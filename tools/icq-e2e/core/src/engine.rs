//! All tracked sockets, each with a [`StreamRewriter`] per direction. Pure logic,
//! no Windows or Winsock types, so it is fully unit-testable and can be driven
//! in-process by the test host. The hook layer keeps its own per-socket state
//! with separate locks; this is the same pipeline behind a simple API.

use std::collections::HashMap;

use crate::config::Policy;
use crate::icbm::Direction;
use crate::stream::StreamRewriter;

/// One tracked socket: a rewriter per direction and the peer address seen at
/// `connect`, if any.
struct SocketState {
    out: StreamRewriter,
    inb: StreamRewriter,
    peer: Option<String>,
}

impl SocketState {
    fn new(peer: Option<String>) -> Self {
        let (out, inb) = StreamRewriter::pair();
        SocketState { out, inb, peer }
    }
}

/// Holds all tracked sockets. Not thread-safe by itself.
pub struct Engine {
    policy: Policy,
    sockets: HashMap<u64, SocketState>,
}

impl Default for Engine {
    fn default() -> Self {
        Engine::new()
    }
}

impl Engine {
    /// An engine that only observes (Phase 0 behaviour).
    pub fn new() -> Self {
        Engine::with_policy(Policy::observe())
    }

    /// An engine with the given policy.
    pub fn with_policy(policy: Policy) -> Self {
        Engine {
            policy,
            sockets: HashMap::new(),
        }
    }

    /// Records the peer address of a socket at connect time (for log context).
    pub fn on_connect(&mut self, socket: u64, peer: Option<String>) {
        let s = self
            .sockets
            .entry(socket)
            .or_insert_with(|| SocketState::new(None));
        if s.peer.is_none() {
            s.peer = peer;
        }
    }

    /// Feeds outbound bytes (client -> server) and returns log lines; the bytes
    /// that would go on the wire are dropped.
    pub fn on_send(&mut self, socket: u64, bytes: &[u8]) -> Vec<String> {
        self.send(socket, bytes, &mut Vec::new())
    }

    /// Feeds inbound bytes (server -> client) and returns log lines; the bytes
    /// the client would get are dropped.
    pub fn on_recv(&mut self, socket: u64, bytes: &[u8]) -> Vec<String> {
        self.recv(socket, bytes, &mut Vec::new())
    }

    /// Feeds outbound bytes, appends what goes on the wire to `out`, and
    /// returns log lines.
    pub fn send(&mut self, socket: u64, bytes: &[u8], out: &mut Vec<u8>) -> Vec<String> {
        self.feed(socket, bytes, Direction::Outbound, out)
    }

    /// Feeds inbound bytes, appends what the client gets to `out`, and returns
    /// log lines.
    pub fn recv(&mut self, socket: u64, bytes: &[u8], out: &mut Vec<u8>) -> Vec<String> {
        self.feed(socket, bytes, Direction::Inbound, out)
    }

    /// Drops a socket's state at close.
    pub fn on_close(&mut self, socket: u64) {
        self.sockets.remove(&socket);
    }

    fn feed(
        &mut self,
        socket: u64,
        bytes: &[u8],
        dir: Direction,
        out: &mut Vec<u8>,
    ) -> Vec<String> {
        let state = self
            .sockets
            .entry(socket)
            .or_insert_with(|| SocketState::new(None));
        let rw = match dir {
            Direction::Outbound => &mut state.out,
            Direction::Inbound => &mut state.inb,
        };
        let mut lines = rw.push(bytes, &self.policy, out);
        if let Some(p) = &state.peer {
            for line in &mut lines {
                line.push_str(&format!(" via={p}"));
            }
        }
        lines
    }
}
