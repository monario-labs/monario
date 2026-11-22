//! Mandatory Noise transport. All I/O is explicitly driven; constructors open no sockets.
pub mod persistent;
use super::Connection;
use crate::{Clock, Error, Node, PeerId};
use curve25519_dalek::montgomery::MontgomeryPoint;
use sha2::{Digest, Sha256};
use snow::{HandshakeState, TransportState};
use std::io::{self, Read, Write};
use zeroize::{Zeroize, Zeroizing};

const PROTOCOL: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
const DOMAIN: &[u8] = b"Monario/encrypted-p2p/v1\0";
/// Separate prologue domain for transport-only pool sessions.
pub const POOL_DOMAIN: &[u8] = b"Monario/pool-transport/v1\0";
/// Separate prologue domain for the read-only wallet page transport.
pub const SCAN_DOMAIN: &[u8] = b"Monario/scan-transport/v1\0";
const PLAIN: usize = 16_384;
const CIPHER: usize = PLAIN + 16;
// Close rather than reuse a nonce or indefinitely retain traffic keys (16 GiB/direction).
const RECORD_LIMIT: u64 = 1 << 20;
const HANDSHAKE_MS: u64 = 10_000;
const RECORD_MS: u64 = 10_000;
const SESSION_MS: u64 = 86_400_000;

// Reject every noncontributory X25519 public input, including noncanonical aliases.
// A fixed public scalar suffices to detect low-order inputs; this is not a secret DH.
pub(crate) fn valid_public(key: [u8; 32]) -> bool {
    MontgomeryPoint(key).mul_clamped([42; 32]).to_bytes() != [0; 32]
}

/// Transport-only secret. Never derive this from a wallet key. No Debug/Clone/export.
/// The owner is wiped on drop; upstream Noise internals do not guarantee full erasure.
pub struct Identity(Zeroizing<[u8; 32]>);
impl Identity {
    pub fn generate() -> Result<Self, Error> {
        let mut secret = Zeroizing::new([0; 32]);
        getrandom::fill(secret.as_mut()).map_err(|_| Error::Entropy)?;
        Ok(Self(secret))
    }
    /// The caller must protect and erase any source copies of this secret.
    pub fn from_secret(secret: Zeroizing<[u8; 32]>) -> Self {
        Self(secret)
    }
    pub fn public_key(&self) -> [u8; 32] {
        MontgomeryPoint::mul_base_clamped(*self.0).to_bytes()
    }
    /// Domain-separated key derivation for a non-node protocol. The derived key
    /// is independent of the base identity but is lost with it; this never
    /// exposes or copies the base secret. Used to give the scan transport its own
    /// static key without persisting another secret.
    pub(crate) fn derive(&self, domain: &[u8]) -> Result<Self, Error> {
        if domain.is_empty() || domain.len() > 64 {
            return Err(Error::Configuration);
        }
        let mut hash = Sha256::new();
        hash.update(b"Monario/identity-derive/v1\0");
        hash.update(domain);
        hash.update(self.0.as_ref());
        Ok(Self(Zeroizing::new(hash.finalize().into())))
    }
}

/// Outbound identity pins must come from trusted operator configuration.
#[derive(Clone, Copy)]
pub enum Role {
    Initiator {
        remote_key: [u8; 32],
    },
    /// Public inbound connections prove key possession, not an authorized identity.
    Responder,
}

enum State {
    Handshake(Box<HandshakeState>),
    Active(Box<TransportState>),
    Closed,
}

/// Encrypted adapter with bounded records, absolute deadlines, and terminal errors.
/// The same consensus profile used by Node must be supplied to the constructor.
/// Streams must be nonblocking and unbuffered; the TCP driver configures this.
pub struct SecureConnection<S> {
    inner: Connection<Records<S>>,
}
impl<S> Drop for SecureConnection<S> {
    fn drop(&mut self) {
        self.inner.stream.close();
        self.inner.input.zeroize();
    }
}
fn records<S: Read + Write>(
    stream: S,
    identity: &Identity,
    role: Role,
    profile: [u8; 32],
    domain: &[u8],
    started_ms: u64,
) -> Result<Records<S>, Error> {
    if domain.is_empty() || domain.len() > 64 {
        return Err(Error::Configuration);
    }
    if matches!(role, Role::Initiator { remote_key } if !valid_public(remote_key) || remote_key == identity.public_key())
    {
        return Err(Error::Configuration);
    }
    let mut prologue = domain.to_vec();
    prologue.extend_from_slice(&profile);
    let builder = snow::Builder::new(PROTOCOL.parse().map_err(|_| Error::Configuration)?)
        .local_private_key(identity.0.as_ref())
        .and_then(|b| b.prologue(&prologue))
        .map_err(|_| Error::Configuration)?;
    let handshake = match role {
        Role::Initiator { .. } => builder.build_initiator(),
        Role::Responder => builder.build_responder(),
    }
    .map_err(|_| Error::Entropy)?;
    Ok(Records {
        stream,
        state: State::Handshake(Box::new(handshake)),
        role,
        local_key: identity.public_key(),
        step: 0,
        established: false,
        output: Vec::with_capacity(CIPHER + 2),
        sent: 0,
        header: [0; 2],
        header_at: 0,
        input: vec![0; CIPHER].into_boxed_slice(),
        input_at: 0,
        plain: Zeroizing::new(vec![0; PLAIN]),
        plain_at: 0,
        plain_len: 0,
        started_ms,
        last_ms: started_ms,
        record_started: None,
        output_started: None,
    })
}

impl<S: Read + Write> SecureConnection<S> {
    pub fn new(
        stream: S,
        identity: &Identity,
        role: Role,
        profile: [u8; 32],
        started_ms: u64,
    ) -> Result<Self, Error> {
        Ok(Self {
            inner: Connection::new(records(
                stream, identity, role, profile, DOMAIN, started_ms,
            )?),
        })
    }
    pub fn poll(&mut self, node: &mut Node, id: PeerId, clock: Clock) -> Result<(), Error> {
        let result = if !node.contains_peer(id) {
            Err(Error::Protocol)
        } else {
            self.inner
                .stream
                .advance(clock.monotonic_ms)
                .and_then(|ready| {
                    if ready {
                        self.inner.poll(node, id, clock)
                    } else {
                        Ok(())
                    }
                })
        };
        if result.is_err() {
            self.inner.stream.close();
            self.inner.input.zeroize();
        }
        result
    }
}

/// Transport-only Noise stream for non-node protocols such as the pool.
/// It reuses the same bounded records, deadlines and key pinning as the node link.
pub struct SecureStream<S> {
    inner: Records<S>,
}
impl<S> Drop for SecureStream<S> {
    fn drop(&mut self) {
        self.inner.close();
    }
}
impl<S: Read + Write> SecureStream<S> {
    pub fn new(
        stream: S,
        identity: &Identity,
        role: Role,
        profile: [u8; 32],
        domain: &[u8],
        started_ms: u64,
    ) -> Result<Self, Error> {
        Ok(Self {
            inner: records(stream, identity, role, profile, domain, started_ms)?,
        })
    }
    /// Drive the handshake and pending output. `Ok(true)` means application
    /// data may be read or written; `Ok(false)` means retry after more I/O.
    pub fn advance(&mut self, now: u64) -> Result<bool, Error> {
        self.inner.advance(now)
    }
    pub fn established(&self) -> bool {
        self.inner.established
    }
    pub fn close(&mut self) {
        self.inner.close();
    }
}
impl<S: Read + Write> Read for SecureStream<S> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.inner.read(out)
    }
}
impl<S: Read + Write> Write for SecureStream<S> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.inner.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

struct Records<S> {
    stream: S,
    state: State,
    role: Role,
    local_key: [u8; 32],
    step: usize,
    established: bool,
    output: Vec<u8>,
    sent: usize,
    header: [u8; 2],
    header_at: usize,
    input: Box<[u8]>,
    input_at: usize,
    plain: Zeroizing<Vec<u8>>,
    plain_at: usize,
    plain_len: usize,
    started_ms: u64,
    last_ms: u64,
    record_started: Option<u64>,
    output_started: Option<u64>,
}
fn invalid() -> io::Error {
    io::ErrorKind::InvalidData.into()
}
fn blocked(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}
impl<S> Records<S> {
    fn close(&mut self) {
        self.state = State::Closed;
        self.plain.zeroize();
        self.output.zeroize();
        self.input.zeroize();
    }
}
impl<S: Read + Write> Records<S> {
    fn flush_record(&mut self) -> io::Result<bool> {
        if self.sent < self.output.len() {
            match self.stream.write(&self.output[self.sent..]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => self.sent += n,
                Err(e) if blocked(&e) => return Ok(false),
                Err(e) => return Err(e),
            }
        }
        if self.sent != self.output.len() {
            return Ok(false);
        }
        self.output.zeroize();
        self.output.clear();
        self.sent = 0;
        self.output_started = None;
        Ok(true)
    }
    // One header read and one bounded body read per call. Never allocate from a peer length.
    fn receive_record(&mut self) -> io::Result<bool> {
        if self.header_at < 2 {
            match self.stream.read(&mut self.header[self.header_at..]) {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(n) => {
                    self.record_started.get_or_insert(self.last_ms);
                    self.header_at += n;
                }
                Err(e) if blocked(&e) => return Ok(false),
                Err(e) => return Err(e),
            }
            if self.header_at != 2 {
                return Ok(false);
            }
        }
        let len = usize::from(u16::from_le_bytes(self.header));
        match self.state {
            State::Handshake(_) if len != [32, 96, 64][self.step] => return Err(invalid()),
            State::Active(_) if !(17..=CIPHER).contains(&len) => return Err(invalid()),
            State::Closed => return Err(invalid()),
            _ => {}
        }
        match self.stream.read(&mut self.input[self.input_at..len]) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => self.input_at += n,
            Err(e) if blocked(&e) => return Ok(false),
            Err(e) => return Err(e),
        }
        Ok(self.input_at == len)
    }
    fn consumed(&mut self) {
        self.header_at = 0;
        self.input_at = 0;
        self.record_started = None;
    }
    fn pin(&self, h: &HandshakeState) -> Result<(), Error> {
        if let Some(key) = h.get_remote_static() {
            if !valid_public(key.try_into().map_err(|_| Error::Protocol)?)
                || key == self.local_key
                || matches!(self.role, Role::Initiator { remote_key } if key != remote_key)
            {
                return Err(Error::Protocol);
            }
        } else if h.is_handshake_finished() {
            return Err(Error::Protocol);
        }
        Ok(())
    }
    fn advance(&mut self, now: u64) -> Result<bool, Error> {
        if matches!(self.state, State::Closed) {
            return Err(Error::Protocol);
        }
        if now < self.last_ms {
            return Err(Error::Clock);
        }
        self.last_ms = now;
        if now - self.started_ms >= SESSION_MS
            || (!self.established && now - self.started_ms >= HANDSHAKE_MS)
            || self
                .record_started
                .is_some_and(|start| now - start >= RECORD_MS)
            || self
                .output_started
                .is_some_and(|start| now - start >= RECORD_MS)
        {
            return Err(Error::Protocol);
        }
        if !self.flush_record().map_err(|_| Error::Io)? {
            return Ok(self.established);
        }
        if matches!(self.state, State::Active(_)) {
            self.established = true;
            return Ok(true);
        }
        let writing = matches!(&self.state, State::Handshake(h) if h.is_my_turn());
        if writing {
            self.output.resize(98, 0);
            let State::Handshake(h) = &mut self.state else {
                unreachable!()
            };
            let n = h
                .write_message(&[], &mut self.output[2..])
                .map_err(|_| Error::Protocol)?;
            self.output[..2].copy_from_slice(&(n as u16).to_le_bytes());
            self.output.truncate(n + 2);
            self.output_started = Some(now);
        } else {
            if !self.receive_record().map_err(|_| Error::Protocol)? {
                return Ok(false);
            }
            if self.step < 2
                && !valid_public(self.input[..32].try_into().map_err(|_| Error::Protocol)?)
            {
                return Err(Error::Protocol);
            }
            let State::Handshake(h) = &mut self.state else {
                unreachable!()
            };
            let n = h
                .read_message(&self.input[..self.input_at], &mut [])
                .map_err(|_| Error::Protocol)?;
            if n != 0 {
                return Err(Error::Protocol);
            }
            self.consumed();
        }
        self.step += 1;
        let State::Handshake(h) = &self.state else {
            unreachable!()
        };
        self.pin(h)?;
        if h.is_handshake_finished() {
            let State::Handshake(h) = std::mem::replace(&mut self.state, State::Closed) else {
                unreachable!()
            };
            self.state = State::Active(Box::new(
                h.into_transport_mode().map_err(|_| Error::Protocol)?,
            ));
        }
        // In particular, finish writing XX's final message before releasing any application data.
        Ok(false)
    }
}
impl<S: Read + Write> Read for Records<S> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.plain_at == self.plain_len {
            if !self.receive_record()? {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let State::Active(t) = &mut self.state else {
                return Err(invalid());
            };
            if t.receiving_nonce() >= RECORD_LIMIT {
                return Err(invalid());
            }
            self.plain_len = t
                .read_message(&self.input[..self.input_at], &mut self.plain)
                .map_err(|_| invalid())?;
            self.plain_at = 0;
            self.consumed();
        }
        let n = out.len().min(self.plain_len - self.plain_at);
        out[..n].copy_from_slice(&self.plain[self.plain_at..self.plain_at + n]);
        self.plain[self.plain_at..self.plain_at + n].zeroize();
        self.plain_at += n;
        Ok(n)
    }
}
impl<S: Read + Write> Write for Records<S> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if !self.output.is_empty() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let State::Active(t) = &mut self.state else {
            return Err(invalid());
        };
        if t.sending_nonce() >= RECORD_LIMIT {
            return Err(invalid());
        }
        let n = bytes.len().min(PLAIN);
        self.output.resize(n + 18, 0);
        let len = t
            .write_message(&bytes[..n], &mut self.output[2..])
            .map_err(|_| invalid())?;
        self.output[..2].copy_from_slice(&(len as u16).to_le_bytes());
        self.output_started = Some(self.last_ms);
        // Plaintext ownership transfers only after ciphertext has been retained in this buffer.
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.flush_record()? {
            Ok(())
        } else {
            Err(io::ErrorKind::WouldBlock.into())
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
