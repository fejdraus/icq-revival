//! One direction of one socket as a stream transformer: bytes in, bytes out,
//! FLAP frames rewritten in place.
//!
//! A FLAP frame is `0x2A | channel:u8 | sequence:u16 BE | payload_len:u16 BE |
//! payload` (wire/frames.go). Complete frames are emitted in order, one out for
//! each one in: a SNAC frame [`crate::rewrite`] changes goes out with its new
//! payload and length and the sender's own sequence number, every other frame
//! byte for byte. A partial frame is held until the rest arrives. So the frame
//! count and the sequence numbering on the connection never change (DESIGN.md
//! section 6).
//!
//! A stream is taken for FLAP only if its first frame is a channel-1 frame
//! starting with FLAP version `00 00 00 01` - how both sides of an OSCAR
//! connection open - and every later header has the marker and a channel from 1
//! to 5. Anything else (direct connections, file transfer, a proxy) turns the
//! stream raw at once: bytes held so far are released unchanged, and from then
//! on everything passes straight through.

use std::collections::HashMap;

use crate::config::Policy;
use crate::icbm::Direction;
use crate::rewrite;

/// FLAP start-of-frame marker.
pub const FLAP_MARKER: u8 = 0x2A;
/// FLAP channel of the sign-on frame that opens a connection.
pub const FLAP_CHANNEL_SIGNON: u8 = 0x01;
/// FLAP channel carrying SNAC data.
pub const FLAP_CHANNEL_SNAC: u8 = 0x02;
/// The highest FLAP channel (keep-alive).
const FLAP_CHANNEL_MAX: u8 = 0x05;
/// FLAP version at the start of a sign-on frame.
const FLAP_VERSION: [u8; 4] = [0, 0, 0, 1];
const HEADER_LEN: usize = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Nothing complete seen yet; the first frame decides.
    Opening,
    /// A FLAP stream.
    Flap,
    /// Not FLAP: everything passes through.
    Raw,
}

/// One direction of one socket.
pub struct StreamRewriter {
    dir: Direction,
    state: State,
    buf: Vec<u8>,
    /// Contacts last seen announcing the add-on or not, so the log reports
    /// changes only (a contact's user info comes with every status change).
    e2e_contacts: HashMap<String, bool>,
}

impl StreamRewriter {
    pub fn new(dir: Direction) -> Self {
        StreamRewriter {
            dir,
            state: State::Opening,
            buf: Vec::new(),
            e2e_contacts: HashMap::new(),
        }
    }

    /// Whether the stream has been found not to be FLAP.
    pub fn is_raw(&self) -> bool {
        self.state == State::Raw
    }

    /// How many bytes are held waiting for the rest of a frame.
    pub fn held(&self) -> usize {
        self.buf.len()
    }

    /// Feeds bytes; appends what may go on to `out` and returns log lines.
    /// Never fails: anything it cannot make sense of passes through unchanged.
    pub fn push(&mut self, bytes: &[u8], policy: &Policy, out: &mut Vec<u8>) -> Vec<String> {
        let mut lines = Vec::new();
        if self.state == State::Raw {
            out.extend_from_slice(bytes);
            return lines;
        }
        let mut buf = std::mem::take(&mut self.buf);
        buf.extend_from_slice(bytes);
        let mut used = 0;
        loop {
            let rest = &buf[used..];
            match self.check_header(rest) {
                Header::NeedMore => break,
                Header::NotFlap => {
                    self.state = State::Raw;
                    out.extend_from_slice(rest);
                    used = buf.len();
                    break;
                }
                Header::Frame(total) => {
                    if rest.len() < total {
                        break;
                    }
                    self.state = State::Flap;
                    self.emit(&rest[..total], policy, out, &mut lines);
                    used += total;
                }
            }
        }
        buf.drain(..used);
        self.buf = buf;
        lines
    }

    /// Releases held bytes unchanged, for the end of the stream.
    pub fn finish(&mut self, out: &mut Vec<u8>) {
        out.append(&mut self.buf);
    }

    fn check_header(&self, b: &[u8]) -> Header {
        if b.is_empty() {
            return Header::NeedMore;
        }
        if b[0] != FLAP_MARKER {
            return Header::NotFlap;
        }
        let Some(&channel) = b.get(1) else {
            return Header::NeedMore;
        };
        let opening = self.state == State::Opening;
        if !(1..=FLAP_CHANNEL_MAX).contains(&channel) || (opening && channel != FLAP_CHANNEL_SIGNON)
        {
            return Header::NotFlap;
        }
        if b.len() < HEADER_LEN {
            return Header::NeedMore;
        }
        let payload_len = u16::from_be_bytes([b[4], b[5]]) as usize;
        if opening {
            if payload_len < FLAP_VERSION.len() {
                return Header::NotFlap;
            }
            if b.len() < HEADER_LEN + FLAP_VERSION.len() {
                return Header::NeedMore;
            }
            if b[HEADER_LEN..HEADER_LEN + FLAP_VERSION.len()] != FLAP_VERSION {
                return Header::NotFlap;
            }
        }
        Header::Frame(HEADER_LEN + payload_len)
    }

    fn emit(&mut self, frame: &[u8], policy: &Policy, out: &mut Vec<u8>, lines: &mut Vec<String>) {
        if frame[1] != FLAP_CHANNEL_SNAC {
            out.extend_from_slice(frame);
            return;
        }
        let processed = rewrite::process(self.dir, &frame[HEADER_LEN..], policy);
        lines.extend(processed.lines);
        for (contact, has) in processed.e2e_contacts {
            let before = self.e2e_contacts.insert(contact.clone(), has);
            match (before, has) {
                (None | Some(false), true) => {
                    lines.push(format!("contact {contact} announces the E2E add-on"))
                }
                (Some(true), false) => lines.push(format!(
                    "contact {contact} no longer announces the E2E add-on"
                )),
                _ => {}
            }
        }
        match processed.payload {
            Some(p) if p.len() <= u16::MAX as usize => {
                // Marker, channel and the sender's sequence number as they were.
                out.extend_from_slice(&frame[..4]);
                out.extend_from_slice(&(p.len() as u16).to_be_bytes());
                out.extend_from_slice(&p);
            }
            Some(_) => {
                lines.push("frame would exceed 64 KiB; sent unchanged".to_string());
                out.extend_from_slice(frame);
            }
            None => out.extend_from_slice(frame),
        }
    }
}

enum Header {
    NeedMore,
    NotFlap,
    /// A plausible header; the frame is this many bytes long.
    Frame(usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(channel: u8, seq: u16, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![FLAP_MARKER, channel];
        v.extend_from_slice(&seq.to_be_bytes());
        v.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    fn hello() -> Vec<u8> {
        frame(1, 100, &[0, 0, 0, 1])
    }

    fn run(r: &mut StreamRewriter, bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        r.push(bytes, &Policy::harness(), &mut out);
        out
    }

    #[test]
    fn flap_frames_pass_whole() {
        let mut r = StreamRewriter::new(Direction::Outbound);
        let mut s = hello();
        s.extend(frame(2, 101, b"not a snac we touch"));
        s.extend(frame(5, 102, b""));
        assert_eq!(run(&mut r, &s), s);
        assert!(!r.is_raw());
    }

    #[test]
    fn partial_frame_is_held() {
        let mut r = StreamRewriter::new(Direction::Inbound);
        let s = [hello(), frame(2, 7, b"abcdef")].concat();
        let cut = s.len() - 3;
        assert_eq!(run(&mut r, &s[..cut]), hello());
        assert_eq!(r.held(), cut - hello().len());
        assert_eq!(run(&mut r, &s[cut..]), frame(2, 7, b"abcdef"));
        assert_eq!(r.held(), 0);
    }

    #[test]
    fn non_flap_goes_raw_at_once() {
        let mut r = StreamRewriter::new(Direction::Inbound);
        assert_eq!(run(&mut r, b"OFT2 file transfer"), b"OFT2 file transfer");
        assert!(r.is_raw());
        assert_eq!(run(&mut r, &hello()), hello());
    }

    #[test]
    fn a_star_that_is_not_a_signon_goes_raw() {
        // Starts like FLAP but channel 2 first: not an OSCAR connection opening.
        let mut r = StreamRewriter::new(Direction::Outbound);
        let s = frame(2, 1, b"xyz");
        assert_eq!(run(&mut r, &s[..3]), &s[..3]);
        assert!(r.is_raw());
        // Right channel, wrong version.
        let mut r = StreamRewriter::new(Direction::Outbound);
        let s = frame(1, 1, &[0, 0, 0, 9]);
        assert_eq!(run(&mut r, &s), s);
        assert!(r.is_raw());
    }

    #[test]
    fn desync_later_releases_held_bytes() {
        let mut r = StreamRewriter::new(Direction::Inbound);
        let s = [hello(), b"\x2A\x09garbage".to_vec()].concat();
        assert_eq!(run(&mut r, &s), s);
        assert!(r.is_raw());
    }

    #[test]
    fn finish_releases_a_partial_frame() {
        let mut r = StreamRewriter::new(Direction::Inbound);
        let partial = &frame(1, 1, &[0, 0, 0, 1, 9, 9])[..8];
        assert!(run(&mut r, partial).is_empty());
        let mut out = Vec::new();
        r.finish(&mut out);
        assert_eq!(out, partial);
    }
}
