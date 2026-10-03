//! Which of the client's connections go to our server, and where they are sent
//! instead (STAGE-TLS 2.2, 3.3).
//!
//! The client never learns about TLS. A `connect` from the networking module to
//! one of the server's addresses on one of its ports is sent to the server's
//! TLS port instead, with the ALPN the original port stands for:
//!
//! - 5190 (FLAP) and 5194 (the TLS port itself): ALPN `oscar`;
//! - 8082 (HTTP, the 7.2 web sign-in) and 5195: ALPN `http/1.1`.
//!
//! 5194 and 5195 are what the patch writes into the client's own settings when
//! the TLS row is ticked (fail closed, STAGE-TLS 3.5): the sign-in goes there,
//! and without the add-on nothing on those ports speaks the client's plain
//! protocol - 5194 is TLS only, nothing listens on 5195 - so a client whose
//! add-on is missing cannot sign in at all instead of signing in in plaintext.
//! The web sign-in needs a port of its own because the ALPN is picked by the
//! port, before the client has said anything. A client that came in over the
//! TLS port is handed `domain:5194` in every redirect (the BUCP
//! `ReconnectHere`, `startOSCARSession`, every service redirect), so it lands
//! on this map again and its connection settings show the TLS port. 5190 and
//! 8082 stay mapped for installs patched before and for an older server that
//! still hands out the plain host.
//!
//! The server is known only by the name in `icq-e2e.ini` (`server=`): `connect`
//! sees nothing but an IP address, so the name is resolved here, cached, and
//! resolved again when a connect to a server port misses. Nothing is guessed
//! from the traffic of other peers.
//!
//! Plain Rust, no Winsock: the hooks ask [`Route::target`] and act on the
//! answer.

use std::net::{Ipv4Addr, ToSocketAddrs};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::tls::{ALPN_HTTP, ALPN_OSCAR};

/// The server's TLS 1.3 port: the add-on's constant, never asked for.
pub const TLS_PORT: u16 = 5194;
/// Ports where the server speaks FLAP (in plaintext, or TLS on [`TLS_PORT`]).
pub const FLAP_PORTS: [u16; 2] = [5190, TLS_PORT];
/// The port the patch gives the 7.2 web sign-in when the TLS row is ticked.
/// The server never listens on it: only the add-on's mapping makes it work.
pub const TLS_ONLY_HTTP_PORT: u16 = 5195;
/// Ports that stand for the server's WebAPI (the 7.2 web sign-in): its plain
/// port, and the one only the add-on can reach it on.
pub const HTTP_PORTS: [u16; 2] = [8082, TLS_ONLY_HTTP_PORT];
/// The guard ports and the server's plain ports they stand for with
/// `tls=off` (fourth review, finding G). The patch points the client's
/// sign-in at a guard port whenever any protecting row is ticked - the
/// messages row too, not only TLS - so a client whose add-on is missing or
/// broken cannot sign in at all: 5194 speaks only TLS and nothing listens on
/// 5195. With TLS the add-on maps them to the TLS port; with `tls=off` it
/// maps them to the plain ports on the same host, which only it does.
pub const GUARD_PORTS: [(u16, u16); 2] = [(TLS_PORT, 5190), (TLS_ONLY_HTTP_PORT, 8082)];

/// How long a resolution is trusted before it is made again.
const CACHE_FOR: Duration = Duration::from_secs(300);
/// How soon a miss on a server port may resolve again.
const RETRY_AFTER: Duration = Duration::from_secs(1);

/// The ports of the server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ports {
    /// Mapped to [`Ports::tls`] with ALPN `oscar`.
    pub flap: Vec<u16>,
    /// Mapped to [`Ports::tls`] with ALPN `http/1.1`.
    pub http: Vec<u16>,
    /// The TLS port.
    pub tls: u16,
    /// Guard port and the plain port it stands for with `tls=off`.
    pub guard: Vec<(u16, u16)>,
}

impl Ports {
    /// The ports of every server of this project.
    pub fn production() -> Self {
        Ports {
            flap: FLAP_PORTS.to_vec(),
            http: HTTP_PORTS.to_vec(),
            tls: TLS_PORT,
            guard: GUARD_PORTS.to_vec(),
        }
    }

    /// The plain port a guard port stands for, if `port` is one.
    pub fn plain_for_guard(&self, port: u16) -> Option<u16> {
        self.guard.iter().find(|(g, _)| *g == port).map(|(_, p)| *p)
    }

    /// The ALPN a connection to `port` asks for, if the port is one of ours.
    pub fn alpn_for(&self, port: u16) -> Option<&'static [u8]> {
        if self.flap.contains(&port) {
            Some(ALPN_OSCAR)
        } else if self.http.contains(&port) {
            Some(ALPN_HTTP)
        } else {
            None
        }
    }
}

/// Where a connection to the server goes instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapping {
    /// The port the client asked for; `getpeername` reports it back.
    pub original_port: u16,
    /// The port the connection really goes to.
    pub tls_port: u16,
    /// The protocol asked for in the handshake.
    pub alpn: &'static [u8],
}

impl Mapping {
    /// `oscar` or `http/1.1`, for the log.
    pub fn alpn_name(&self) -> &'static str {
        std::str::from_utf8(self.alpn).unwrap_or("?")
    }
}

/// What [`Route::target`] makes of a `connect`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// Not the server: left alone (peers, anything else).
    Elsewhere,
    /// The server on one of its ports: TLS, as the mapping says.
    Server(Mapping),
    /// The server on a port the add-on cannot secure: refused.
    ServerOtherPort,
    /// A server port, and the server's name does not resolve here, so it
    /// cannot be told whether this is the server: refused.
    Unresolved,
}

/// What [`Route::guard`] makes of a `connect` with `tls=off`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Guard {
    /// Not a guard port of the server: left alone.
    NotGuard,
    /// The server on a guard port: to this plain port instead.
    Plain(u16),
    /// A guard port, and the server's name does not resolve: refused.
    Unresolved,
}

/// Turns a name into its IPv4 addresses.
pub type Resolver = Box<dyn Fn(&str) -> Vec<Ipv4Addr> + Send + Sync>;

struct Cache {
    addrs: Vec<Ipv4Addr>,
    at: Option<Instant>,
}

/// The server, its ports and its addresses.
pub struct Route {
    server: String,
    ports: Ports,
    resolver: Resolver,
    cache: Mutex<Cache>,
}

impl Route {
    pub fn new(server: &str, ports: Ports, resolver: Resolver) -> Self {
        Route {
            server: server.to_string(),
            ports,
            resolver,
            cache: Mutex::new(Cache {
                addrs: Vec::new(),
                at: None,
            }),
        }
    }

    /// The production route: the server's ports, resolved with the system's
    /// resolver (`getaddrinfo`), IPv4 only as the clients are.
    pub fn system(server: &str) -> Self {
        Route::new(server, Ports::production(), Box::new(resolve_system))
    }

    /// The server's DNS name: SNI and the name its certificate must carry.
    pub fn server(&self) -> &str {
        &self.server
    }

    pub fn ports(&self) -> &Ports {
        &self.ports
    }

    /// The addresses known for the server now (for the log and the tests).
    pub fn addresses(&self) -> Vec<Ipv4Addr> {
        self.cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .addrs
            .clone()
    }

    /// Whether `ip` is the server. With `refresh` a miss resolves the name
    /// again (at most once a second), which is how a changed DNS answer is
    /// picked up; without it only the cache is asked, except for the very
    /// first time.
    pub fn is_server(&self, ip: Ipv4Addr, refresh: bool) -> bool {
        let mut c = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let stale = c.at.is_none_or(|t| now.duration_since(t) >= CACHE_FOR);
        if stale {
            c.addrs = (self.resolver)(&self.server);
            c.at = Some(now);
        }
        if c.addrs.contains(&ip) {
            return true;
        }
        if refresh && c.at.is_some_and(|t| now.duration_since(t) >= RETRY_AFTER) {
            c.addrs = (self.resolver)(&self.server);
            c.at = Some(now);
            return c.addrs.contains(&ip);
        }
        false
    }

    /// Whether the server's name resolved at all the last time it was tried.
    fn resolved(&self) -> bool {
        !self
            .cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .addrs
            .is_empty()
    }

    /// What to do with a `connect` to `ip:port`.
    pub fn target(&self, ip: Ipv4Addr, port: u16) -> Target {
        match self.ports.alpn_for(port) {
            Some(alpn) => {
                if self.is_server(ip, true) {
                    Target::Server(Mapping {
                        original_port: port,
                        tls_port: self.ports.tls,
                        alpn,
                    })
                } else if !self.resolved() {
                    Target::Unresolved
                } else {
                    Target::Elsewhere
                }
            }
            None if self.is_server(ip, false) => Target::ServerOtherPort,
            None => Target::Elsewhere,
        }
    }

    /// What to do with a `connect` to `ip:port` with `tls=off`: a guard port
    /// of the server goes to the plain port it stands for.
    pub fn guard(&self, ip: Ipv4Addr, port: u16) -> Guard {
        let Some(plain) = self.ports.plain_for_guard(port) else {
            return Guard::NotGuard;
        };
        if self.is_server(ip, true) {
            Guard::Plain(plain)
        } else if !self.resolved() {
            Guard::Unresolved
        } else {
            Guard::NotGuard
        }
    }

    /// Whether a host named in a proxy request is the server: its name, or
    /// one of its addresses.
    pub fn names_server(&self, host: &ProxyHost) -> bool {
        match host {
            ProxyHost::Name(n) => {
                n.eq_ignore_ascii_case(&self.server)
                    || n.parse::<Ipv4Addr>()
                        .is_ok_and(|ip| self.is_server(ip, true))
            }
            ProxyHost::Ip(ip) => self.is_server(*ip, true),
        }
    }
}

/// `getaddrinfo` through the standard library, IPv4 addresses only.
fn resolve_system(name: &str) -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    if let Ok(addrs) = (name, 0u16).to_socket_addrs() {
        for a in addrs {
            if let std::net::SocketAddr::V4(v4) = a {
                if !out.contains(v4.ip()) {
                    out.push(*v4.ip());
                }
            }
        }
    }
    out
}

// --- proxies ----------------------------------------------------------------

/// The host a proxy is asked to connect to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyHost {
    Name(String),
    Ip(Ipv4Addr),
}

/// What the first bytes a client sends to a proxy say (STAGE-TLS 6, the proxy
/// risk). With a proxy configured, `connect` goes to the proxy, not to the
/// server, so the mapping never sees the server: the request inside the first
/// bytes does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyHello {
    /// Not a proxy request.
    None,
    /// An HTTP `CONNECT host:port`, a SOCKS4(a) or a SOCKS5 request.
    Request { host: ProxyHost, port: u16 },
    /// A SOCKS5 greeting: the request follows in the next bytes sent.
    Socks5Greeting,
}

/// Reads a proxy request out of the first bytes sent on a connection.
/// `socks5_request` says the previous bytes were a SOCKS5 greeting.
pub fn proxy_hello(data: &[u8], socks5_request: bool) -> ProxyHello {
    if socks5_request {
        return socks5_request_target(data).map_or(ProxyHello::None, |(host, port)| {
            ProxyHello::Request { host, port }
        });
    }
    if let Some(rest) = data.strip_prefix(b"CONNECT ") {
        let target: Vec<u8> = rest.iter().take_while(|&&b| b != b' ').copied().collect();
        let target = String::from_utf8_lossy(&target).into_owned();
        if let Some((host, port)) = target.rsplit_once(':') {
            if let Ok(port) = port.parse::<u16>() {
                let host = host.trim_matches(['[', ']']).to_string();
                return ProxyHello::Request {
                    host: match host.parse::<Ipv4Addr>() {
                        Ok(ip) => ProxyHost::Ip(ip),
                        Err(_) => ProxyHost::Name(host),
                    },
                    port,
                };
            }
        }
        return ProxyHello::None;
    }
    // SOCKS4: 04 01 port:2 ip:4 userid\0 [host\0 for 4a when ip is 0.0.0.x].
    if data.len() >= 9 && data[0] == 4 && data[1] == 1 {
        let port = u16::from_be_bytes([data[2], data[3]]);
        let ip = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
        let after_user = data[8..].iter().position(|&b| b == 0).map(|i| 8 + i + 1);
        if ip.octets()[..3] == [0, 0, 0] && ip.octets()[3] != 0 {
            if let Some(at) = after_user {
                let name: Vec<u8> = data[at..]
                    .iter()
                    .take_while(|&&b| b != 0)
                    .copied()
                    .collect();
                return ProxyHello::Request {
                    host: ProxyHost::Name(String::from_utf8_lossy(&name).into_owned()),
                    port,
                };
            }
        }
        return ProxyHello::Request {
            host: ProxyHost::Ip(ip),
            port,
        };
    }
    // SOCKS5 greeting: 05 n methods[n].
    if data.len() >= 2 && data[0] == 5 && data.len() == 2 + data[1] as usize {
        return ProxyHello::Socks5Greeting;
    }
    ProxyHello::None
}

/// The target of a SOCKS5 request: 05 01 00 atyp addr port.
fn socks5_request_target(data: &[u8]) -> Option<(ProxyHost, u16)> {
    if data.len() < 4 || data[0] != 5 || data[1] != 1 {
        return None;
    }
    let port_at = |at: usize| -> Option<u16> {
        Some(u16::from_be_bytes([*data.get(at)?, *data.get(at + 1)?]))
    };
    match data[3] {
        1 => {
            let a = data.get(4..8)?;
            Some((
                ProxyHost::Ip(Ipv4Addr::new(a[0], a[1], a[2], a[3])),
                port_at(8)?,
            ))
        }
        3 => {
            let n = *data.get(4)? as usize;
            let name = data.get(5..5 + n)?;
            Some((
                ProxyHost::Name(String::from_utf8_lossy(name).into_owned()),
                port_at(5 + n)?,
            ))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    const SERVER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
    const PEER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);

    fn route_with(answers: Arc<Mutex<Vec<Ipv4Addr>>>, calls: Arc<AtomicUsize>) -> Route {
        Route::new(
            "icq.example.org",
            Ports::production(),
            Box::new(move |name| {
                assert_eq!(name, "icq.example.org");
                calls.fetch_add(1, Ordering::SeqCst);
                answers.lock().unwrap().clone()
            }),
        )
    }

    #[test]
    fn server_ports_are_mapped_with_their_alpn() {
        let r = route_with(
            Arc::new(Mutex::new(vec![SERVER])),
            Arc::new(AtomicUsize::new(0)),
        );
        assert_eq!(
            r.target(SERVER, 5190),
            Target::Server(Mapping {
                original_port: 5190,
                tls_port: 5194,
                alpn: ALPN_OSCAR
            })
        );
        assert_eq!(
            r.target(SERVER, 8082),
            Target::Server(Mapping {
                original_port: 8082,
                tls_port: 5194,
                alpn: ALPN_HTTP
            })
        );
        // The ports the patch writes with the TLS row ticked (fail closed):
        // the TLS port for OSCAR, 5195 for the web sign-in.
        assert_eq!(
            r.target(SERVER, 5194),
            Target::Server(Mapping {
                original_port: 5194,
                tls_port: 5194,
                alpn: ALPN_OSCAR
            })
        );
        assert_eq!(
            r.target(SERVER, 5195),
            Target::Server(Mapping {
                original_port: 5195,
                tls_port: 5194,
                alpn: ALPN_HTTP
            })
        );
        // Peers, on any port, are left alone.
        assert_eq!(r.target(PEER, 5190), Target::Elsewhere);
        assert_eq!(r.target(PEER, 5195), Target::Elsewhere);
        assert_eq!(r.target(PEER, 40000), Target::Elsewhere);
        // The server on a port the add-on cannot secure is refused.
        assert_eq!(r.target(SERVER, 443), Target::ServerOtherPort);
    }

    /// Fourth review, finding G: with `tls=off` the guard ports of the
    /// server go to its plain ports; anything else, and the guard ports of
    /// other hosts, are left alone; an unresolved name is refused.
    #[test]
    fn guard_ports_go_to_the_plain_ports_with_tls_off() {
        let r = route_with(
            Arc::new(Mutex::new(vec![SERVER])),
            Arc::new(AtomicUsize::new(0)),
        );
        assert_eq!(r.guard(SERVER, 5194), Guard::Plain(5190));
        assert_eq!(r.guard(SERVER, 5195), Guard::Plain(8082));
        assert_eq!(r.guard(SERVER, 5190), Guard::NotGuard);
        assert_eq!(r.guard(SERVER, 8082), Guard::NotGuard);
        assert_eq!(r.guard(PEER, 5194), Guard::NotGuard);
        let unresolved = route_with(
            Arc::new(Mutex::new(Vec::new())),
            Arc::new(AtomicUsize::new(0)),
        );
        assert_eq!(unresolved.guard(SERVER, 5194), Guard::Unresolved);
        assert_eq!(unresolved.guard(SERVER, 40000), Guard::NotGuard);
    }

    #[test]
    fn a_miss_on_a_server_port_resolves_again() {
        let answers = Arc::new(Mutex::new(vec![SERVER]));
        let calls = Arc::new(AtomicUsize::new(0));
        let r = route_with(answers.clone(), calls.clone());
        assert!(r.is_server(SERVER, true));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // The DNS answer changes; the first miss is within a second of the
        // last resolution, so the cache answers.
        let moved = Ipv4Addr::new(192, 0, 2, 20);
        *answers.lock().unwrap() = vec![moved];
        assert_eq!(r.target(moved, 5190), Target::Elsewhere);
        // A second later the miss on a server port resolves again.
        r.cache.lock().unwrap().at = Some(Instant::now() - RETRY_AFTER);
        assert!(matches!(r.target(moved, 5190), Target::Server(_)));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        // A miss on another port never resolves.
        r.cache.lock().unwrap().at = Some(Instant::now() - RETRY_AFTER);
        assert_eq!(r.target(PEER, 40000), Target::Elsewhere);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn a_name_that_does_not_resolve_refuses_server_ports() {
        let r = route_with(
            Arc::new(Mutex::new(Vec::new())),
            Arc::new(AtomicUsize::new(0)),
        );
        assert_eq!(r.target(SERVER, 5190), Target::Unresolved);
        assert_eq!(r.target(SERVER, 8082), Target::Unresolved);
        assert_eq!(r.target(SERVER, 5194), Target::Unresolved);
        assert_eq!(r.target(SERVER, 5195), Target::Unresolved);
        assert_eq!(r.target(PEER, 40000), Target::Elsewhere);
    }

    #[test]
    fn the_system_resolver_reads_an_address_literal() {
        let r = Route::system("127.0.0.1");
        assert!(r.is_server(Ipv4Addr::LOCALHOST, false));
        assert_eq!(r.addresses(), vec![Ipv4Addr::LOCALHOST]);
    }

    #[test]
    fn proxy_requests_are_read() {
        assert_eq!(
            proxy_hello(b"CONNECT icq.example.org:5190 HTTP/1.0\r\n\r\n", false),
            ProxyHello::Request {
                host: ProxyHost::Name("icq.example.org".into()),
                port: 5190
            }
        );
        assert_eq!(
            proxy_hello(b"CONNECT 192.0.2.10:8082 HTTP/1.1\r\n", false),
            ProxyHello::Request {
                host: ProxyHost::Ip(SERVER),
                port: 8082
            }
        );
        // SOCKS4 with an address, SOCKS4a with a name.
        assert_eq!(
            proxy_hello(&[4, 1, 0x14, 0x46, 192, 0, 2, 10, b'u', 0], false),
            ProxyHello::Request {
                host: ProxyHost::Ip(SERVER),
                port: 5190
            }
        );
        let mut s4a = vec![4, 1, 0x14, 0x46, 0, 0, 0, 1, 0];
        s4a.extend_from_slice(b"icq.example.org\0");
        assert_eq!(
            proxy_hello(&s4a, false),
            ProxyHello::Request {
                host: ProxyHost::Name("icq.example.org".into()),
                port: 5190
            }
        );
        // SOCKS5: the greeting, then the request.
        assert_eq!(proxy_hello(&[5, 1, 0], false), ProxyHello::Socks5Greeting);
        let mut s5 = vec![5, 1, 0, 3, 15];
        s5.extend_from_slice(b"icq.example.org");
        s5.extend_from_slice(&8082u16.to_be_bytes());
        assert_eq!(
            proxy_hello(&s5, true),
            ProxyHello::Request {
                host: ProxyHost::Name("icq.example.org".into()),
                port: 8082
            }
        );
        // FLAP and HTTP are not proxy requests.
        assert_eq!(proxy_hello(&[0x2A, 1, 0, 1, 0, 4], false), ProxyHello::None);
        assert_eq!(
            proxy_hello(b"POST /auth/clientLogin HTTP/1.0", false),
            ProxyHello::None
        );
    }

    #[test]
    fn a_proxy_request_for_the_server_is_recognised() {
        let r = route_with(
            Arc::new(Mutex::new(vec![SERVER])),
            Arc::new(AtomicUsize::new(0)),
        );
        assert!(r.names_server(&ProxyHost::Name("ICQ.example.org".into())));
        assert!(r.names_server(&ProxyHost::Name("192.0.2.10".into())));
        assert!(r.names_server(&ProxyHost::Ip(SERVER)));
        assert!(!r.names_server(&ProxyHost::Name("other.example.org".into())));
        assert!(!r.names_server(&ProxyHost::Ip(PEER)));
    }
}
