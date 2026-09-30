//! FLAP frame reassembly over a byte stream.
//!
//! The hooked send/recv see a raw TCP byte stream, not framed SNACs. A FLAP
//! frame is `0x2A | channel:u8 | sequence:u16 BE | payload_len:u16 BE |
//! payload` (see wire/frames.go). We buffer bytes per socket per direction and
//! yield complete frames; a frame split across two recv calls is held until the
//! rest arrives. This phase never rewrites frames, so sequence numbers are left
//! exactly as the client and server set them.

/// FLAP start-of-frame marker.
pub const FLAP_MARKER: u8 = 0x2A;
/// FLAP channel carrying SNAC data.
pub const FLAP_CHANNEL_SNAC: u8 = 0x02;

const HEADER_LEN: usize = 6;
/// A sane ceiling so a desynchronised or non-FLAP stream cannot make the buffer
/// grow without bound. FLAP payloads are u16-bounded, so 64 KiB + header covers
/// any real frame.
const MAX_BUFFER: usize = 1 << 20;

/// One complete FLAP frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub channel: u8,
    pub sequence: u16,
    pub payload: Vec<u8>,
}

/// Accumulates one direction of one socket's stream and yields whole frames.
#[derive(Default)]
pub struct Reassembler {
    buf: Vec<u8>,
    /// Once the stream looks like it is not FLAP, stop buffering: this is not a
    /// BOS connection (or it desynchronised). Bytes still pass through the hook
    /// untouched; we simply stop trying to parse.
    desynced: bool,
}

impl Reassembler {
    pub fn new() -> Self {
        Reassembler::default()
    }

    /// Reports whether this stream has been marked as not-FLAP.
    pub fn is_desynced(&self) -> bool {
        self.desynced
    }

    /// Feeds freshly observed bytes and returns every frame that is now
    /// complete. Never panics and never errors: an unparsable stream just stops
    /// yielding frames.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<Frame> {
        let mut frames = Vec::new();
        if self.desynced {
            return frames;
        }
        self.buf.extend_from_slice(bytes);
        loop {
            if self.buf.len() < HEADER_LEN {
                break;
            }
            if self.buf[0] != FLAP_MARKER {
                // The very first byte of a BOS stream is a FLAP marker; anything
                // else means this is not a FLAP socket.
                self.desynced = true;
                self.buf.clear();
                break;
            }
            let channel = self.buf[1];
            let sequence = u16::from_be_bytes([self.buf[2], self.buf[3]]);
            let payload_len = u16::from_be_bytes([self.buf[4], self.buf[5]]) as usize;
            let total = HEADER_LEN + payload_len;
            if self.buf.len() < total {
                // Partial frame; wait for more bytes.
                if self.buf.len() > MAX_BUFFER {
                    self.desynced = true;
                    self.buf.clear();
                }
                break;
            }
            let payload = self.buf[HEADER_LEN..total].to_vec();
            frames.push(Frame {
                channel,
                sequence,
                payload,
            });
            self.buf.drain(..total);
        }
        frames
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame_bytes(channel: u8, seq: u16, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![FLAP_MARKER, channel];
        v.extend_from_slice(&seq.to_be_bytes());
        v.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn one_whole_frame() {
        let mut r = Reassembler::new();
        let f = r.push(&frame_bytes(FLAP_CHANNEL_SNAC, 7, b"abcd"));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].channel, FLAP_CHANNEL_SNAC);
        assert_eq!(f[0].sequence, 7);
        assert_eq!(f[0].payload, b"abcd");
    }

    #[test]
    fn two_frames_in_one_push() {
        let mut r = Reassembler::new();
        let mut bytes = frame_bytes(2, 1, b"one");
        bytes.extend(frame_bytes(2, 2, b"two"));
        let f = r.push(&bytes);
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].payload, b"one");
        assert_eq!(f[1].sequence, 2);
    }

    #[test]
    fn frame_split_across_pushes() {
        let mut r = Reassembler::new();
        let whole = frame_bytes(2, 9, b"hello world");
        let (a, b) = whole.split_at(4);
        assert!(r.push(a).is_empty());
        let f = r.push(b);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].payload, b"hello world");
    }

    #[test]
    fn header_split_across_pushes() {
        let mut r = Reassembler::new();
        let whole = frame_bytes(2, 3, b"xy");
        assert!(r.push(&whole[..2]).is_empty());
        assert!(r.push(&whole[2..5]).is_empty());
        let f = r.push(&whole[5..]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].payload, b"xy");
    }

    #[test]
    fn non_flap_stream_desyncs_and_passes_through() {
        let mut r = Reassembler::new();
        assert!(r.push(b"GET / HTTP/1.1\r\n").is_empty());
        assert!(r.is_desynced());
        // Later bytes are ignored, never buffered.
        assert!(r.push(&frame_bytes(2, 1, b"z")).is_empty());
    }
}
