//! What the add-on does, read once from the environment at start.
//!
//! - `ICQE2E_MODE=observe` - Phase 0 behaviour: bytes pass untouched, messages
//!   are only logged. Anything else, or nothing, is the Phase 1 rewrite harness.
//! - `ICQE2E_PEERS=uin1,uin2` - rewrite outbound messages only to these
//!   contacts. Unset or empty: to everybody. Inbound text is restored whoever
//!   sent it, since only text carrying the harness marker is touched.

/// Whether the add-on only watches or also rewrites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Phase 0: log only, every byte unchanged.
    Observe,
    /// Phase 1: rewrite message text with the reversible harness transform.
    Harness,
}

/// The add-on's settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub mode: Mode,
    /// Contacts outbound rewriting is limited to, normalised; `None` for all.
    pub peers: Option<Vec<String>>,
}

impl Policy {
    /// Log-only, as in Phase 0.
    pub fn observe() -> Self {
        Policy {
            mode: Mode::Observe,
            peers: None,
        }
    }

    /// Rewriting for every contact.
    pub fn harness() -> Self {
        Policy {
            mode: Mode::Harness,
            peers: None,
        }
    }

    /// Reads `ICQE2E_MODE` and `ICQE2E_PEERS`.
    pub fn from_env() -> Self {
        Policy::from_values(
            std::env::var("ICQE2E_MODE").ok().as_deref(),
            std::env::var("ICQE2E_PEERS").ok().as_deref(),
        )
    }

    /// Builds the policy from the two variables' values.
    pub fn from_values(mode: Option<&str>, peers: Option<&str>) -> Self {
        let mode = match mode.map(str::trim) {
            Some(m) if m.eq_ignore_ascii_case("observe") => Mode::Observe,
            _ => Mode::Harness,
        };
        let peers: Vec<String> = peers
            .unwrap_or("")
            .split([',', ';'])
            .map(normalise)
            .filter(|p| !p.is_empty())
            .collect();
        Policy {
            mode,
            peers: (!peers.is_empty()).then_some(peers),
        }
    }

    /// Whether a message to `peer` is rewritten.
    pub fn rewrites_to(&self, peer: &str) -> bool {
        match &self.peers {
            None => true,
            Some(list) => {
                let p = normalise(peer);
                list.contains(&p)
            }
        }
    }

    /// One line for the log.
    pub fn describe(&self) -> String {
        match (self.mode, &self.peers) {
            (Mode::Observe, _) => "mode=observe (log only, bytes unchanged)".to_string(),
            (Mode::Harness, None) => {
                "mode=harness (rewriting messages to every contact)".to_string()
            }
            (Mode::Harness, Some(p)) => {
                format!("mode=harness (rewriting messages to {} only)", p.join(", "))
            }
        }
    }
}

/// Screen names compare without case and spaces, as OSCAR does.
fn normalise(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_harness_for_everybody() {
        let p = Policy::from_values(None, None);
        assert_eq!(p, Policy::harness());
        assert!(p.rewrites_to("12345"));
    }

    #[test]
    fn observe_switch() {
        assert_eq!(
            Policy::from_values(Some(" Observe "), None).mode,
            Mode::Observe
        );
        assert_eq!(
            Policy::from_values(Some("harness"), None).mode,
            Mode::Harness
        );
    }

    #[test]
    fn peer_list() {
        let p = Policy::from_values(None, Some("100001, 100002;Some Name"));
        assert!(p.rewrites_to("100001"));
        assert!(p.rewrites_to("100002"));
        assert!(p.rewrites_to("somename"));
        assert!(!p.rewrites_to("100003"));
        assert_eq!(Policy::from_values(None, Some(" , ")).peers, None);
    }
}
