//! TLS 1.3 for the client's connections to our server, as plain byte buffers.
//!
//! [`TlsPipe`] holds one rustls client connection and knows nothing about
//! sockets: the Winsock hooks (STAGE-TLS 3.3) feed it the ciphertext they read,
//! take the plaintext it decrypted, hand it the client's plaintext and send the
//! ciphertext it produced. Everything that is hard about TLS on a byte stream -
//! a record cut anywhere, several records in one read, the client writing
//! before the handshake has finished, a stream that ends without
//! `close_notify` - is handled and tested here, with no socket in sight.
//!
//! The rules (STAGE-TLS 3.1, 3.4, 3.5):
//!
//! - TLS 1.3 only, with ring as the crypto provider; no session resumption, no
//!   0-RTT.
//! - The name sent as SNI and checked against the certificate is the server
//!   name from the add-on's settings, never anything the network supplied.
//! - The certificate is checked against the Windows trust store
//!   (`rustls-platform-verifier`), the same decision WinHTTP makes for the key
//!   directory. Tests give their own roots instead.
//! - An optional pin (`sha256/<base64 of the SPKI>`) is checked on top of a
//!   valid chain, never instead of it.
//! - Fail closed: any error is final for the connection, is kept, and is
//!   reported with a reason a person can act on. A stream that ends without
//!   `close_notify` is [`CloseKind::Truncated`], never a clean end.

use std::io::{Read, Write};
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{Resumption, WebPkiServerVerifier};

use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    AlertDescription, CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct,
    Error, RootCertStore, SignatureScheme,
};

/// ALPN of an OSCAR (FLAP) connection on the server's TLS port.
pub const ALPN_OSCAR: &[u8] = b"oscar";
/// ALPN of an HTTP connection (the 7.2 web sign-in) on the same port.
pub const ALPN_HTTP: &[u8] = b"http/1.1";

/// RFC 9266 `tls-exporter` channel binding: label and length.
const EXPORTER_LABEL: &[u8] = b"EXPORTER-Channel-Binding";
const EXPORTER_LEN: usize = 32;

/// How much plaintext the client may write before the handshake has finished
/// (rustls holds it and sends it after `Finished`), and how much ciphertext may
/// wait to be sent. Far more than a sign-in ever writes ahead.
const BUFFER_LIMIT: usize = 4 * 1024 * 1024;

/// Which certificates are trusted.
#[derive(Clone, Debug)]
pub enum Trust {
    /// The Windows trust store, through `rustls-platform-verifier`.
    System,
    /// Only these roots (tests, or a private deployment).
    Roots(Vec<CertificateDer<'static>>),
}

/// What the add-on's settings say about TLS to the server.
#[derive(Clone, Debug)]
pub struct TlsSettings {
    /// The server's DNS name: SNI, and the name the certificate must carry.
    pub server_name: String,
    pub trust: Trust,
    /// SHA-256 digests of acceptable subject public key infos; empty for no
    /// pin. Checked in addition to the chain.
    pub pins: Vec<[u8; 32]>,
}

impl TlsSettings {
    /// Settings that trust the system store and pin nothing.
    pub fn system(server_name: &str) -> Self {
        TlsSettings {
            server_name: server_name.to_string(),
            trust: Trust::System,
            pins: Vec::new(),
        }
    }
}

/// Why a connection could not be secured. The text of [`TlsFailure::reason`]
/// is meant for the person in front of the client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TlsFailure {
    /// The certificate does not name the server.
    NotValidForName,
    /// The certificate has expired or is not valid yet.
    Expired,
    /// The certificate does not lead to a trusted root.
    UnknownIssuer,
    /// The certificate was revoked.
    Revoked,
    /// Some other problem with the certificate.
    BadCertificate(String),
    /// The chain is valid but the key is not one of the pinned ones.
    PinMismatch,
    /// The server does not speak TLS 1.3.
    NotTls13,
    /// The TLS conversation itself went wrong.
    Protocol(String),
    /// The settings could not be turned into a TLS client.
    Setup(String),
    /// More data was written than the pipe will hold.
    BufferFull,
}

impl TlsFailure {
    /// One line, for the log and the message box.
    pub fn reason(&self) -> String {
        match self {
            TlsFailure::NotValidForName => "the certificate is not valid for this name".to_string(),
            TlsFailure::Expired => "the certificate has expired or is not valid yet".to_string(),
            TlsFailure::UnknownIssuer => {
                "the certificate is not issued by an authority this computer trusts".to_string()
            }
            TlsFailure::Revoked => "the certificate has been revoked".to_string(),
            TlsFailure::BadCertificate(why) => format!("the certificate is not valid ({why})"),
            TlsFailure::PinMismatch => {
                "the server's key is not the pinned one (tls_pin)".to_string()
            }
            TlsFailure::NotTls13 => "the server does not offer TLS 1.3".to_string(),
            TlsFailure::Protocol(why) => format!("TLS error ({why})"),
            TlsFailure::Setup(why) => format!("TLS could not be set up ({why})"),
            TlsFailure::BufferFull => "too much data waiting on the connection".to_string(),
        }
    }
}

impl std::fmt::Display for TlsFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason())
    }
}

/// How a stream ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseKind {
    /// The server sent `close_notify`.
    Clean,
    /// The transport ended without `close_notify`: data may be missing.
    Truncated,
}

/// Where a [`TlsPipe`] is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TlsState {
    Handshaking,
    Ready,
    /// The server's side has ended; plaintext may still be waiting to be taken.
    Closed(CloseKind),
    Failed(TlsFailure),
}

/// A TLS client configuration built once from the settings and shared by every
/// connection: the verifier (the system store is opened once) and the name.
#[derive(Clone)]
pub struct TlsClient {
    config: Arc<ClientConfig>,
    name: ServerName<'static>,
}

impl TlsClient {
    pub fn new(settings: &TlsSettings) -> Result<Self, TlsFailure> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let name = ServerName::try_from(settings.server_name.clone())
            .map_err(|e| TlsFailure::Setup(format!("server name: {e}")))?;
        let chain: Arc<dyn ServerCertVerifier> = match &settings.trust {
            Trust::System => Arc::new(
                rustls_platform_verifier::Verifier::new(provider.clone())
                    .map_err(|e| TlsFailure::Setup(format!("system trust store: {e}")))?,
            ),
            Trust::Roots(roots) => {
                let mut store = RootCertStore::empty();
                for r in roots {
                    store
                        .add(r.clone())
                        .map_err(|e| TlsFailure::Setup(format!("root certificate: {e}")))?;
                }
                WebPkiServerVerifier::builder_with_provider(Arc::new(store), provider.clone())
                    .build()
                    .map_err(|e| TlsFailure::Setup(format!("verifier: {e}")))?
            }
        };
        let verifier: Arc<dyn ServerCertVerifier> = if settings.pins.is_empty() {
            chain
        } else {
            Arc::new(PinnedVerifier {
                inner: chain,
                pins: settings.pins.clone(),
            })
        };
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| TlsFailure::Setup(e.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        config.resumption = Resumption::disabled();
        config.enable_early_data = false;
        Ok(TlsClient {
            config: Arc::new(config),
            name,
        })
    }

    /// A new connection offering `alpn` (e.g. [`ALPN_OSCAR`]); its ClientHello
    /// is ready in [`TlsPipe::take_ciphertext`] at once.
    pub fn connect(&self, alpn: &[u8]) -> Result<TlsPipe, TlsFailure> {
        let mut conn = ClientConnection::new_with_alpn(
            self.config.clone(),
            self.name.clone(),
            vec![alpn.to_vec()],
        )
        .map_err(|e| classify(&e))?;
        conn.set_buffer_limit(Some(BUFFER_LIMIT));
        Ok(TlsPipe {
            conn,
            plaintext: Vec::new(),
            failed: None,
            ended: None,
            local_closed: false,
        })
    }
}

/// One TLS client connection as byte buffers. See the module documentation.
pub struct TlsPipe {
    conn: ClientConnection,
    /// Decrypted bytes not taken yet.
    plaintext: Vec<u8>,
    /// The first error, final for the connection.
    failed: Option<TlsFailure>,
    /// How the server's side ended, once it has.
    ended: Option<CloseKind>,
    /// Whether [`TlsPipe::close`] was called.
    local_closed: bool,
}

impl TlsPipe {
    /// Gives the pipe bytes read from the transport, in any cut: part of a
    /// record, several records, a handshake message split anywhere. All of
    /// `data` is taken. Afterwards the plaintext may have grown, and there may
    /// be ciphertext to send (the client `Finished`, or an alert after a
    /// failure: send it, then close).
    pub fn feed_ciphertext(&mut self, data: &[u8]) -> Result<(), TlsFailure> {
        if let Some(f) = &self.failed {
            return Err(f.clone());
        }
        let mut rest = data;
        while !rest.is_empty() {
            if self.ended.is_some() {
                // Nothing after close_notify counts; rustls reads no more.
                break;
            }
            let n = match self.conn.read_tls(&mut rest) {
                Ok(n) => n,
                Err(e) => return Err(self.fail(TlsFailure::Protocol(e.to_string()))),
            };
            match self.conn.process_new_packets() {
                Ok(state) => {
                    let want = state.plaintext_bytes_to_read();
                    if want > 0 {
                        let at = self.plaintext.len();
                        self.plaintext.resize(at + want, 0);
                        if let Err(e) = self.conn.reader().read_exact(&mut self.plaintext[at..]) {
                            self.plaintext.truncate(at);
                            return Err(self.fail(TlsFailure::Protocol(e.to_string())));
                        }
                    }
                    if state.peer_has_closed() {
                        self.ended = Some(CloseKind::Clean);
                    }
                }
                Err(e) => return Err(self.fail(classify(&e))),
            }
            if n == 0 && self.ended.is_none() {
                // rustls took nothing and is not closed: it cannot progress.
                return Err(self.fail(TlsFailure::Protocol("input not accepted".to_string())));
            }
        }
        Ok(())
    }

    /// The transport has ended (`recv` returned 0). Without a `close_notify`
    /// before it, the stream was cut: data may be missing, and that is never
    /// reported as a clean end.
    pub fn end_of_input(&mut self) -> CloseKind {
        let kind = match self.ended {
            Some(CloseKind::Clean) => CloseKind::Clean,
            _ => CloseKind::Truncated,
        };
        self.ended = Some(kind);
        kind
    }

    /// Decrypted bytes waiting to be taken.
    pub fn plaintext_len(&self) -> usize {
        self.plaintext.len()
    }

    /// Moves up to `buf.len()` bytes of plaintext into `buf`.
    pub fn take_plaintext(&mut self, buf: &mut [u8]) -> usize {
        let k = self.peek_plaintext(buf);
        self.plaintext.drain(..k);
        k
    }

    /// Copies up to `buf.len()` bytes of plaintext into `buf` and keeps them
    /// (`MSG_PEEK`).
    pub fn peek_plaintext(&self, buf: &mut [u8]) -> usize {
        let k = buf.len().min(self.plaintext.len());
        buf[..k].copy_from_slice(&self.plaintext[..k]);
        k
    }

    /// Encrypts the client's bytes. Before the handshake has finished they are
    /// held and sent after it, in order.
    pub fn write_plaintext(&mut self, data: &[u8]) -> Result<(), TlsFailure> {
        if let Some(f) = &self.failed {
            return Err(f.clone());
        }
        if self.local_closed {
            return Err(TlsFailure::Protocol("write after close".to_string()));
        }
        let mut rest = data;
        while !rest.is_empty() {
            match self.conn.writer().write(rest) {
                Ok(0) => return Err(self.fail(TlsFailure::BufferFull)),
                Ok(n) => rest = &rest[n..],
                Err(e) => return Err(self.fail(TlsFailure::Protocol(e.to_string()))),
            }
        }
        Ok(())
    }

    /// Whether there is ciphertext to send.
    pub fn wants_write(&self) -> bool {
        self.conn.wants_write()
    }

    /// The ciphertext to send, in order. Empty when there is none.
    pub fn take_ciphertext(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        while self.conn.wants_write() {
            match self.conn.write_tls(&mut out) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        out
    }

    /// Queues a `close_notify` for the server (send it with
    /// [`TlsPipe::take_ciphertext`]). Further writes fail.
    pub fn close(&mut self) {
        if !self.local_closed {
            self.local_closed = true;
            self.conn.send_close_notify();
        }
    }

    pub fn state(&self) -> TlsState {
        if let Some(f) = &self.failed {
            return TlsState::Failed(f.clone());
        }
        if let Some(k) = self.ended {
            return TlsState::Closed(k);
        }
        if self.conn.is_handshaking() {
            TlsState::Handshaking
        } else {
            TlsState::Ready
        }
    }

    pub fn is_handshaking(&self) -> bool {
        self.conn.is_handshaking()
    }

    /// The ALPN protocol the server chose.
    pub fn alpn(&self) -> Option<&[u8]> {
        self.conn.alpn_protocol()
    }

    /// The RFC 9266 `tls-exporter` channel binding (32 bytes), for SCRAM-PLUS.
    /// Only after the handshake.
    pub fn exporter(&self) -> Result<[u8; EXPORTER_LEN], TlsFailure> {
        self.conn
            .export_keying_material([0u8; EXPORTER_LEN], EXPORTER_LABEL, None)
            .map_err(|e| TlsFailure::Protocol(e.to_string()))
    }

    /// Records the first failure and returns it.
    fn fail(&mut self, f: TlsFailure) -> TlsFailure {
        self.failed.get_or_insert(f).clone()
    }
}

/// Turns a rustls error into a reason a person can act on.
fn classify(e: &Error) -> TlsFailure {
    match e {
        Error::InvalidCertificate(c) => match c {
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
                TlsFailure::NotValidForName
            }
            CertificateError::Expired
            | CertificateError::ExpiredContext { .. }
            | CertificateError::NotValidYet
            | CertificateError::NotValidYetContext { .. } => TlsFailure::Expired,
            CertificateError::UnknownIssuer => TlsFailure::UnknownIssuer,
            CertificateError::Revoked => TlsFailure::Revoked,
            CertificateError::Other(other) if other.0.downcast_ref::<PinMismatch>().is_some() => {
                TlsFailure::PinMismatch
            }
            other => TlsFailure::BadCertificate(format!("{other:?}")),
        },
        Error::AlertReceived(AlertDescription::ProtocolVersion) | Error::PeerIncompatible(_) => {
            TlsFailure::NotTls13
        }
        other => TlsFailure::Protocol(other.to_string()),
    }
}

// --- pinning ----------------------------------------------------------------

/// The error a pin mismatch is carried in, so [`classify`] can tell it apart.
#[derive(Debug)]
struct PinMismatch;

impl std::fmt::Display for PinMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("server key does not match the pin")
    }
}

impl std::error::Error for PinMismatch {}

/// Checks the chain with `inner`, then the end-entity key against the pins.
#[derive(Debug)]
struct PinnedVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    pins: Vec<[u8; 32]>,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let ok = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        let spki =
            spki_of(end_entity).ok_or(Error::InvalidCertificate(CertificateError::BadEncoding))?;
        let digest = ring::digest::digest(&ring::digest::SHA256, spki);
        if self.pins.iter().any(|p| p.as_slice() == digest.as_ref()) {
            Ok(ok)
        } else {
            Err(Error::InvalidCertificate(CertificateError::Other(
                rustls::OtherError(Arc::new(PinMismatch)),
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Parses `tls_pin` (`sha256/<base64>[,sha256/<base64>...]`).
pub fn parse_pins(text: &str) -> Result<Vec<[u8; 32]>, String> {
    use base64::Engine;
    let mut out = Vec::new();
    for part in text.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let b64 = part
            .strip_prefix("sha256/")
            .ok_or_else(|| format!("pin {part:?} does not start with sha256/"))?;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| format!("pin {part:?}: {e}"))?;
        let pin: [u8; 32] = raw
            .try_into()
            .map_err(|_| format!("pin {part:?} is not 32 bytes"))?;
        out.push(pin);
    }
    Ok(out)
}

/// The pin of a certificate: `sha256/` and the base64 SHA-256 of its subject
/// public key info.
pub fn pin_of(cert_der: &[u8]) -> Option<String> {
    use base64::Engine;
    let spki = spki_of(cert_der)?;
    let digest = ring::digest::digest(&ring::digest::SHA256, spki);
    Some(format!(
        "sha256/{}",
        base64::engine::general_purpose::STANDARD.encode(digest.as_ref())
    ))
}

/// The DER of the subject public key info inside an X.509 certificate.
fn spki_of(cert: &[u8]) -> Option<&[u8]> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    let (_, cert_body, _) = der_tlv(cert, 0x30)?;
    let (_, mut tbs, _) = der_tlv(cert_body, 0x30)?;
    // tbsCertificate ::= SEQUENCE { [0] version OPTIONAL, serialNumber,
    //   signature, issuer, validity, subject, subjectPublicKeyInfo, ... }
    if tbs.first() == Some(&0xA0) {
        tbs = der_tlv(tbs, 0xA0)?.2;
    }
    for tag in [0x02, 0x30, 0x30, 0x30, 0x30] {
        tbs = der_tlv(tbs, tag)?.2;
    }
    let (whole, _, _) = der_tlv(tbs, 0x30)?;
    Some(whole)
}

/// One DER element with tag `tag` at the start of `data`: (the whole element,
/// its contents, what follows it).
fn der_tlv(data: &[u8], tag: u8) -> Option<(&[u8], &[u8], &[u8])> {
    if *data.first()? != tag {
        return None;
    }
    let first = *data.get(1)? as usize;
    let (len, header) = if first < 0x80 {
        (first, 2)
    } else {
        let n = first & 0x7F;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *data.get(2 + i)? as usize;
        }
        (len, 2 + n)
    };
    let end = header.checked_add(len)?;
    if end > data.len() {
        return None;
    }
    Some((&data[..end], &data[header..end], &data[end..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, KeyUsagePurpose,
    };
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::{ServerConfig, ServerConnection};

    /// A test CA and a server certificate it issued.
    struct Pki {
        ca: CertificateDer<'static>,
        cert: CertificateDer<'static>,
        key: PrivateKeyDer<'static>,
    }

    /// A CA with a name of its own: two CAs of one name would make the
    /// verifier try the wrong one and report a bad signature.
    fn ca() -> CertifiedIssuer<'static, KeyPair> {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, format!("ICQ E2E test CA {n}"));
        CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap()
    }

    fn pki_with(names: &[&str], expired: bool) -> Pki {
        let ca = ca();
        let mut params =
            CertificateParams::new(names.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                .unwrap();
        if expired {
            params.not_before = rcgen::date_time_ymd(2001, 1, 1);
            params.not_after = rcgen::date_time_ymd(2002, 1, 1);
        }
        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &ca).unwrap();
        Pki {
            ca: ca.der().clone(),
            cert: cert.der().clone(),
            key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        }
    }

    fn pki() -> Pki {
        pki_with(&["icq.example.org"], false)
    }

    fn provider() -> Arc<rustls::crypto::CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    /// The in-process server, and the plaintext it has received so far
    /// (rustls holds only a little before it must be read).
    struct TestServer {
        conn: ServerConnection,
        got: Vec<u8>,
    }

    impl std::ops::Deref for TestServer {
        type Target = ServerConnection;
        fn deref(&self) -> &ServerConnection {
            &self.conn
        }
    }

    impl std::ops::DerefMut for TestServer {
        fn deref_mut(&mut self) -> &mut ServerConnection {
            &mut self.conn
        }
    }

    fn server_with(
        pki: &Pki,
        versions: &[&'static rustls::SupportedProtocolVersion],
    ) -> TestServer {
        let mut cfg = ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(versions)
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![pki.cert.clone()], pki.key.clone_key())
            .unwrap();
        cfg.alpn_protocols = vec![ALPN_OSCAR.to_vec(), ALPN_HTTP.to_vec()];
        let mut conn = ServerConnection::new(Arc::new(cfg)).unwrap();
        conn.set_buffer_limit(None);
        TestServer {
            conn,
            got: Vec::new(),
        }
    }

    fn server(pki: &Pki) -> TestServer {
        server_with(pki, &[&rustls::version::TLS13])
    }

    fn client_for(pki: &Pki, name: &str) -> TlsClient {
        TlsClient::new(&TlsSettings {
            server_name: name.to_string(),
            trust: Trust::Roots(vec![pki.ca.clone()]),
            pins: Vec::new(),
        })
        .unwrap()
    }

    /// A tiny deterministic generator for the random cuts.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    /// How the client's ciphertext is cut before it is fed.
    #[derive(Clone, Copy)]
    enum Cut {
        Whole,
        OneByte,
        Random(u64),
    }

    /// Feeds `data` to the pipe in pieces as `cut` says.
    fn feed(pipe: &mut TlsPipe, data: &[u8], cut: Cut) -> Result<(), TlsFailure> {
        match cut {
            Cut::Whole => pipe.feed_ciphertext(data),
            Cut::OneByte => {
                for b in data.chunks(1) {
                    pipe.feed_ciphertext(b)?;
                }
                Ok(())
            }
            Cut::Random(seed) => {
                let mut rng = Rng(seed);
                let mut rest = data;
                while !rest.is_empty() {
                    let n = (rng.next() % 40) as usize + 1;
                    let n = n.min(rest.len());
                    pipe.feed_ciphertext(&rest[..n])?;
                    rest = &rest[n..];
                }
                Ok(())
            }
        }
    }

    /// Everything the server has to send.
    fn server_out(server: &mut TestServer) -> Vec<u8> {
        let mut out = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut out).unwrap();
        }
        out
    }

    /// Gives the server what the client produced.
    fn server_in(server: &mut TestServer, data: &[u8]) -> Result<(), Error> {
        let mut rest = data;
        while !rest.is_empty() {
            server.conn.read_tls(&mut rest).unwrap();
            server.conn.process_new_packets()?;
            let mut chunk = [0u8; 4096];
            while let Ok(n) = server.conn.reader().read(&mut chunk) {
                if n == 0 {
                    break;
                }
                server.got.extend_from_slice(&chunk[..n]);
            }
        }
        Ok(())
    }

    fn server_plaintext(server: &mut TestServer) -> Vec<u8> {
        std::mem::take(&mut server.got)
    }

    /// Runs the conversation until neither side has anything to send. Server
    /// to client bytes are cut as `cut` says.
    fn pump(pipe: &mut TlsPipe, server: &mut TestServer, cut: Cut) -> Result<(), TlsFailure> {
        for _ in 0..20 {
            let c = pipe.take_ciphertext();
            if !c.is_empty() {
                if let Err(e) = server_in(server, &c) {
                    // Let the server's alert reach the client.
                    let alert = server_out(server);
                    let _ = feed(pipe, &alert, cut);
                    return Err(match pipe.state() {
                        TlsState::Failed(f) => f,
                        _ => TlsFailure::Protocol(format!("server: {e}")),
                    });
                }
            }
            let s = server_out(server);
            if !s.is_empty() {
                feed(pipe, &s, cut)?;
            }
            if c.is_empty() && s.is_empty() {
                return Ok(());
            }
        }
        Ok(())
    }

    fn handshake_and_echo(cut: Cut) {
        let pki = pki();
        let client = client_for(&pki, "icq.example.org");
        let mut pipe = client.connect(ALPN_OSCAR).unwrap();
        let mut server = server(&pki);
        assert_eq!(pipe.state(), TlsState::Handshaking);
        pump(&mut pipe, &mut server, cut).unwrap();
        assert_eq!(pipe.state(), TlsState::Ready);
        assert_eq!(pipe.alpn(), Some(ALPN_OSCAR));
        assert_eq!(
            server.server_name(),
            Some("icq.example.org"),
            "SNI is the configured name"
        );

        // Server speaks first (the FLAP hello), then the client answers.
        let hello = [0x2A, 1, 0, 1, 0, 4, 0, 0, 0, 1];
        server.writer().write_all(&hello).unwrap();
        pump(&mut pipe, &mut server, cut).unwrap();
        assert_eq!(pipe.plaintext_len(), hello.len());
        let mut got = [0u8; 64];
        let n = pipe.take_plaintext(&mut got);
        assert_eq!(&got[..n], &hello);

        // Large data both ways: several records, cut anywhere.
        let big: Vec<u8> = (0..70_000u32).map(|i| (i * 7 + 3) as u8).collect();
        pipe.write_plaintext(&big).unwrap();
        pump(&mut pipe, &mut server, cut).unwrap();
        assert_eq!(server_plaintext(&mut server), big);
        server.writer().write_all(&big).unwrap();
        pump(&mut pipe, &mut server, cut).unwrap();
        let mut back = vec![0u8; big.len() + 10];
        let mut taken = 0;
        // Small takes, as a client with a small buffer would.
        while pipe.plaintext_len() > 0 {
            let end = (taken + 1000).min(back.len());
            taken += pipe.take_plaintext(&mut back[taken..end]);
        }
        assert_eq!(&back[..taken], &big[..]);
    }

    #[test]
    fn handshake_and_echo_whole_records() {
        handshake_and_echo(Cut::Whole);
    }

    #[test]
    fn handshake_and_echo_one_byte_at_a_time() {
        handshake_and_echo(Cut::OneByte);
    }

    #[test]
    fn handshake_and_echo_random_cuts() {
        for seed in [1, 7, 0xDEAD_BEEF, 12345] {
            handshake_and_echo(Cut::Random(seed));
        }
    }

    /// Several of the server's flights coalesced into one read.
    #[test]
    fn coalesced_records_are_all_decrypted() {
        let pki = pki();
        let mut pipe = client_for(&pki, "icq.example.org")
            .connect(ALPN_OSCAR)
            .unwrap();
        let mut server = server(&pki);
        server_in(&mut server, &pipe.take_ciphertext()).unwrap();
        // The whole server flight, and the data the server wrote right away
        // (sent with it as 0.5-RTT data, or after the client's Finished), in
        // one buffer.
        server.writer().write_all(b"first").unwrap();
        let mut all = server_out(&mut server);
        pipe.feed_ciphertext(&all).unwrap();
        server_in(&mut server, &pipe.take_ciphertext()).unwrap();
        server.writer().write_all(b"second").unwrap();
        server.writer().write_all(b"third").unwrap();
        all = server_out(&mut server);
        pipe.feed_ciphertext(&all).unwrap();
        let mut buf = [0u8; 64];
        let n = pipe.take_plaintext(&mut buf);
        assert_eq!(&buf[..n], b"firstsecondthird");
    }

    /// The client writes before the handshake has finished (the 7.2 HTTP
    /// request right after connect): the bytes arrive after it, in order.
    #[test]
    fn plaintext_written_early_arrives_after_the_handshake_in_order() {
        let pki = pki();
        let mut pipe = client_for(&pki, "icq.example.org")
            .connect(ALPN_HTTP)
            .unwrap();
        let mut server = server(&pki);
        pipe.write_plaintext(b"POST /auth/getChallenge HTTP/1.0\r\n")
            .unwrap();
        pipe.write_plaintext(b"\r\n").unwrap();
        assert!(pipe.is_handshaking());
        pump(&mut pipe, &mut server, Cut::Random(99)).unwrap();
        assert_eq!(pipe.alpn(), Some(ALPN_HTTP));
        assert_eq!(
            server_plaintext(&mut server),
            b"POST /auth/getChallenge HTTP/1.0\r\n\r\n"
        );
    }

    /// MSG_PEEK: a peek leaves the bytes for the next take.
    #[test]
    fn peek_keeps_the_plaintext() {
        let pki = pki();
        let mut pipe = client_for(&pki, "icq.example.org")
            .connect(ALPN_OSCAR)
            .unwrap();
        let mut server = server(&pki);
        pump(&mut pipe, &mut server, Cut::Whole).unwrap();
        server.writer().write_all(b"abcdef").unwrap();
        pump(&mut pipe, &mut server, Cut::Whole).unwrap();
        let mut b = [0u8; 3];
        assert_eq!(pipe.peek_plaintext(&mut b), 3);
        assert_eq!(&b, b"abc");
        assert_eq!(pipe.plaintext_len(), 6);
        assert_eq!(pipe.take_plaintext(&mut b), 3);
        assert_eq!(&b, b"abc");
        assert_eq!(pipe.take_plaintext(&mut b), 3);
        assert_eq!(&b, b"def");
    }

    /// close_notify from the server is a clean end, after the data before it.
    #[test]
    fn close_notify_is_a_clean_end() {
        let pki = pki();
        let mut pipe = client_for(&pki, "icq.example.org")
            .connect(ALPN_OSCAR)
            .unwrap();
        let mut server = server(&pki);
        pump(&mut pipe, &mut server, Cut::Whole).unwrap();
        server.writer().write_all(b"bye").unwrap();
        server.send_close_notify();
        let wire = server_out(&mut server);
        feed(&mut pipe, &wire, Cut::OneByte).unwrap();
        assert_eq!(pipe.state(), TlsState::Closed(CloseKind::Clean));
        assert_eq!(pipe.plaintext_len(), 3, "the data before the close is kept");
        assert_eq!(pipe.end_of_input(), CloseKind::Clean);
    }

    /// A transport that ends without close_notify - also in the middle of a
    /// record - is truncated, never a clean end.
    #[test]
    fn a_cut_without_close_notify_is_truncated() {
        let pki = pki();
        let mut pipe = client_for(&pki, "icq.example.org")
            .connect(ALPN_OSCAR)
            .unwrap();
        let mut server = server(&pki);
        pump(&mut pipe, &mut server, Cut::Whole).unwrap();
        server.writer().write_all(b"complete").unwrap();
        server.writer().write_all(b"cut short").unwrap();
        let wire = server_out(&mut server);
        // Everything but the last few bytes of the second record.
        feed(&mut pipe, &wire[..wire.len() - 5], Cut::Whole).unwrap();
        let mut buf = [0u8; 64];
        let n = pipe.take_plaintext(&mut buf);
        assert_eq!(&buf[..n], b"complete");
        assert_eq!(pipe.end_of_input(), CloseKind::Truncated);
        assert_eq!(pipe.state(), TlsState::Closed(CloseKind::Truncated));
    }

    /// The client's own close: a close_notify the server sees as one.
    #[test]
    fn close_sends_close_notify() {
        let pki = pki();
        let mut pipe = client_for(&pki, "icq.example.org")
            .connect(ALPN_OSCAR)
            .unwrap();
        let mut server = server(&pki);
        pump(&mut pipe, &mut server, Cut::Whole).unwrap();
        pipe.close();
        let wire = pipe.take_ciphertext();
        server_in(&mut server, &wire).unwrap();
        let mut buf = [0u8; 4];
        assert_eq!(server.conn.reader().read(&mut buf).unwrap(), 0, "clean end");
        assert!(pipe.write_plaintext(b"late").is_err());
    }

    fn expect_failure(pipe: &mut TlsPipe, server: &mut TestServer) -> TlsFailure {
        let err = pump(pipe, server, Cut::Whole).expect_err("the handshake must fail");
        assert_eq!(pipe.state(), TlsState::Failed(err.clone()));
        assert!(
            pipe.write_plaintext(b"x").is_err(),
            "nothing is accepted after a failure"
        );
        assert!(
            pipe.feed_ciphertext(b"\x17\x03\x03").is_err(),
            "the failure is final"
        );
        err
    }

    #[test]
    fn wrong_name_fails() {
        let pki = pki();
        let mut pipe = client_for(&pki, "other.example.org")
            .connect(ALPN_OSCAR)
            .unwrap();
        let mut server = server(&pki);
        assert_eq!(
            expect_failure(&mut pipe, &mut server),
            TlsFailure::NotValidForName
        );
    }

    #[test]
    fn expired_certificate_fails() {
        let pki = pki_with(&["icq.example.org"], true);
        let mut pipe = client_for(&pki, "icq.example.org")
            .connect(ALPN_OSCAR)
            .unwrap();
        let mut server = server(&pki);
        assert_eq!(expect_failure(&mut pipe, &mut server), TlsFailure::Expired);
    }

    #[test]
    fn unknown_ca_fails() {
        let other = pki();
        let pki = pki();
        // The client trusts another CA.
        let mut pipe = client_for(&other, "icq.example.org")
            .connect(ALPN_OSCAR)
            .unwrap();
        let mut server = server(&pki);
        assert_eq!(
            expect_failure(&mut pipe, &mut server),
            TlsFailure::UnknownIssuer
        );
    }

    /// The Windows trust store does not know the test CA either.
    #[test]
    fn system_trust_rejects_an_unknown_ca() {
        let pki = pki();
        let client = TlsClient::new(&TlsSettings::system("icq.example.org")).unwrap();
        let mut pipe = client.connect(ALPN_OSCAR).unwrap();
        let mut server = server(&pki);
        let err = expect_failure(&mut pipe, &mut server);
        assert!(
            matches!(
                err,
                TlsFailure::UnknownIssuer | TlsFailure::BadCertificate(_)
            ),
            "{err:?}"
        );
    }

    #[test]
    fn tls12_only_server_fails() {
        let pki = pki();
        let mut pipe = client_for(&pki, "icq.example.org")
            .connect(ALPN_OSCAR)
            .unwrap();
        let mut server = server_with(&pki, &[&rustls::version::TLS12]);
        assert_eq!(expect_failure(&mut pipe, &mut server), TlsFailure::NotTls13);
    }

    #[test]
    fn pin_matches_and_mismatches() {
        let pki = pki();
        let good = parse_pins(&pin_of(&pki.cert).unwrap()).unwrap();
        let other = parse_pins(&pin_of(&pki.ca).unwrap()).unwrap();
        let with = |pins: Vec<[u8; 32]>| {
            TlsClient::new(&TlsSettings {
                server_name: "icq.example.org".to_string(),
                trust: Trust::Roots(vec![pki.ca.clone()]),
                pins,
            })
            .unwrap()
            .connect(ALPN_OSCAR)
            .unwrap()
        };

        let mut pipe = with([other.clone(), good].concat());
        pump(&mut pipe, &mut server(&pki), Cut::Whole).unwrap();
        assert_eq!(pipe.state(), TlsState::Ready, "one of the pins matches");

        let mut pipe = with(other);
        assert_eq!(
            expect_failure(&mut pipe, &mut server(&pki)),
            TlsFailure::PinMismatch
        );
    }

    #[test]
    fn pins_are_parsed_strictly() {
        assert!(parse_pins("").unwrap().is_empty());
        let one = format!("sha256/{}", "A".repeat(43) + "=");
        assert_eq!(parse_pins(&one).unwrap().len(), 1);
        assert_eq!(parse_pins(&format!("{one}, {one}")).unwrap().len(), 2);
        assert!(parse_pins("sha1/AAAA").is_err());
        assert!(parse_pins("sha256/AAAA").is_err(), "not 32 bytes");
        assert!(parse_pins("sha256/!!").is_err());
    }

    /// The pin is the hash of the key the certificate carries.
    #[test]
    fn spki_is_found_in_the_certificate() {
        use rcgen::PublicKeyData;
        let key = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec!["a.example".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        assert_eq!(
            spki_of(cert.der()).unwrap(),
            key.subject_public_key_info().as_slice()
        );
        assert!(spki_of(b"\x30\x03\x02\x01").is_none(), "truncated DER");
    }

    /// The exporter is 32 bytes and the same on both ends.
    #[test]
    fn exporter_matches_the_server() {
        let pki = pki();
        let mut pipe = client_for(&pki, "icq.example.org")
            .connect(ALPN_OSCAR)
            .unwrap();
        let mut server = server(&pki);
        pump(&mut pipe, &mut server, Cut::Whole).unwrap();
        let ours = pipe.exporter().unwrap();
        let theirs = server
            .export_keying_material([0u8; 32], EXPORTER_LABEL, None)
            .unwrap();
        assert_eq!(ours.len(), 32);
        assert_eq!(ours, theirs);
        assert_ne!(ours, [0u8; 32]);
    }

    #[test]
    fn a_bad_server_name_is_a_setup_failure() {
        let err = TlsClient::new(&TlsSettings::system("not a name"))
            .err()
            .unwrap();
        assert!(matches!(err, TlsFailure::Setup(_)), "{err:?}");
    }

    /// Garbage from the server is a failure, not plaintext.
    #[test]
    fn garbage_fails() {
        let pki = pki();
        let mut pipe = client_for(&pki, "icq.example.org")
            .connect(ALPN_OSCAR)
            .unwrap();
        let _ = pipe.take_ciphertext();
        let err = pipe
            .feed_ciphertext(&[0x2A, 1, 0, 1, 0, 4, 0, 0, 0, 1])
            .unwrap_err();
        assert!(matches!(err, TlsFailure::Protocol(_)), "{err:?}");
        assert_eq!(pipe.plaintext_len(), 0);
        assert!(!pipe.take_ciphertext().is_empty(), "an alert to send");
    }
}
