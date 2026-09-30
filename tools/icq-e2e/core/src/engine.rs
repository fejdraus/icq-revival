//! The observation engine: per-socket FLAP reassembly feeding SNAC/ICBM parsing,
//! producing log lines. Pure logic, no Windows or Winsock types, so it is fully
//! unit-testable and can be driven in-process by the test host.

use std::collections::HashMap;

use crate::flap::Reassembler;
use crate::icbm;
use crate::snac;

/// One tracked socket: a reassembler per direction and the peer address seen at
/// `connect`, if any.
struct SocketState {
    out: Reassembler,
    inb: Reassembler,
    peer: Option<String>,
}

impl SocketState {
    fn new(peer: Option<String>) -> Self {
        SocketState {
            out: Reassembler::new(),
            inb: Reassembler::new(),
            peer,
        }
    }
}

/// Holds all tracked sockets. Not thread-safe by itself; the hook layer guards
/// it with a mutex.
#[derive(Default)]
pub struct Engine {
    sockets: HashMap<u64, SocketState>,
}

impl Engine {
    pub fn new() -> Self {
        Engine::default()
    }

    /// Records the peer address of a socket at connect time (for log context).
    pub fn on_connect(&mut self, socket: u64, peer: Option<String>) {
        self.sockets
            .entry(socket)
            .or_insert_with(|| SocketState::new(peer.clone()));
        if let Some(s) = self.sockets.get_mut(&socket) {
            if s.peer.is_none() {
                s.peer = peer;
            }
        }
    }

    /// Feeds observed outbound bytes (client -> server) and returns log lines.
    pub fn on_send(&mut self, socket: u64, bytes: &[u8]) -> Vec<String> {
        self.feed(socket, bytes, icbm::Direction::Outbound)
    }

    /// Feeds observed inbound bytes (server -> client) and returns log lines.
    pub fn on_recv(&mut self, socket: u64, bytes: &[u8]) -> Vec<String> {
        self.feed(socket, bytes, icbm::Direction::Inbound)
    }

    /// Drops a socket's state at close.
    pub fn on_close(&mut self, socket: u64) {
        self.sockets.remove(&socket);
    }

    fn feed(&mut self, socket: u64, bytes: &[u8], dir: icbm::Direction) -> Vec<String> {
        let state = self
            .sockets
            .entry(socket)
            .or_insert_with(|| SocketState::new(None));
        let peer_ctx = state.peer.clone();
        let frames = match dir {
            icbm::Direction::Outbound => state.out.push(bytes),
            icbm::Direction::Inbound => state.inb.push(bytes),
        };
        let mut lines = Vec::new();
        for frame in frames {
            if frame.channel != crate::flap::FLAP_CHANNEL_SNAC {
                continue;
            }
            if let Some(msg) = decode_frame(dir, &frame.payload) {
                let mut line = msg.log_line();
                if let Some(p) = &peer_ctx {
                    line.push_str(&format!(" via={}", p));
                }
                lines.push(line);
            }
        }
        lines
    }
}

/// Decodes one SNAC payload into a loggable message, or `None` for the many
/// SNACs we pass by (presence, typing, acks, login, ...).
fn decode_frame(dir: icbm::Direction, payload: &[u8]) -> Option<icbm::Message> {
    let s = snac::parse(payload)?;
    match (s.food_group, s.sub_group) {
        (snac::FOOD_ICBM, snac::ICBM_MSG_TO_HOST) => icbm::parse_to_host(s.body),
        (snac::FOOD_ICBM, snac::ICBM_MSG_TO_CLIENT) => icbm::parse_to_client(s.body),
        (snac::FOOD_ICQ, snac::ICQ_DB_QUERY) => {
            // Offline replies arrive server -> client; ignore the request form.
            if dir == icbm::Direction::Inbound {
                icbm::parse_icq_offline(s.body)
            } else {
                None
            }
        }
        _ => None,
    }
}
