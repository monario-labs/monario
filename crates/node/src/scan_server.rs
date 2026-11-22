//! Nonblocking, token-authenticated page server for the node runtime.
//!
//! This is a read-only transport. It never mutates chain, mempool, wallet, mining
//! or peer-trust state and never accepts a wallet query. Requests carry only a
//! start height and a block count. Every accepted connection runs inside the
//! mandatory Noise session, pinned to the node's derived scan identity. There is
//! no plaintext mode. The bind is loopback-only unless the operator explicitly
//! opts into a remote bind.
//!
//! `Server::bind` is explicit activation. Tests use in-memory streams and never
//! bind a listener.

use crate::{
    Error, Node,
    transport::{Identity, Role, SCAN_DOMAIN, SecureStream},
};
use monario_wallet_scan::page::{
    MAX_PAGE_BYTES,
    transport::{self, Request},
};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
};

pub const MAX_CONNECTIONS: usize = 4;
pub const MAX_REQUESTS_PER_CONNECTION: usize = 1_024;
pub const IDLE_MS: u64 = 30_000;
const TOKEN_BYTES: usize = 32;
const REQUEST_BYTES: usize = 10;

pub struct Config {
    pub bind: SocketAddr,
    pub token: [u8; TOKEN_BYTES],
    /// Explicit opt-in for a non-loopback bind. Loopback is the default policy.
    pub allow_remote: bool,
    /// Transport identity published by the node so a wallet can pin it.
    pub identity: Identity,
    /// Consensus profile bound into the Noise prologue.
    pub profile: [u8; 32],
}

impl Config {
    fn validate(&self) -> Result<(), Error> {
        if self.bind.port() == 0
            || self.bind.ip().is_unspecified()
            || self.bind.ip().is_multicast()
            || self.token == [0; TOKEN_BYTES]
            || self.profile == [0; 32]
        {
            return Err(Error::Configuration);
        }
        if !self.allow_remote && !self.bind.ip().is_loopback() {
            return Err(Error::Configuration);
        }
        Ok(())
    }
}

pub struct Server {
    listener: TcpListener,
    token: [u8; TOKEN_BYTES],
    identity: Identity,
    profile: [u8; 32],
    connections: Vec<Connection<SecureStream<TcpStream>>>,
}

impl Server {
    /// EXPLICIT BIND. Never called by library construction or tests.
    pub fn bind(config: Config) -> Result<Self, Error> {
        config.validate()?;
        let listener = TcpListener::bind(config.bind).map_err(|_| Error::Configuration)?;
        listener
            .set_nonblocking(true)
            .map_err(|_| Error::Configuration)?;
        Ok(Self {
            listener,
            token: config.token,
            identity: config.identity,
            profile: config.profile,
            connections: Vec::new(),
        })
    }

    /// One bounded, nonblocking poll. A bad connection is dropped; listener
    /// failure is fatal to the caller's runtime.
    pub fn poll(&mut self, node: &Node, now_ms: u64) -> Result<(), Error> {
        loop {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    if self.connections.len() >= MAX_CONNECTIONS {
                        continue;
                    }
                    if stream.set_nonblocking(true).is_err() {
                        continue;
                    }
                    let Ok(secure) = SecureStream::new(
                        stream,
                        &self.identity,
                        Role::Responder,
                        self.profile,
                        SCAN_DOMAIN,
                        now_ms,
                    ) else {
                        continue;
                    };
                    self.connections.push(Connection::new(secure, now_ms));
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => return Err(Error::Io),
            }
        }
        let token = self.token;
        self.connections
            .retain_mut(|connection| connection.poll(node, &token, now_ms).is_ok());
        Ok(())
    }
}

/// The minimal transport a page connection needs. `SecureStream` drives a Noise
/// handshake; the in-memory test transport is already plaintext and ready.
trait Transport: Read + Write {
    /// `Ok(false)` means the encrypted session is not ready for application data.
    fn advance(&mut self, now: u64) -> Result<bool, ()>;
}

impl<S: Read + Write> Transport for SecureStream<S> {
    fn advance(&mut self, now: u64) -> Result<bool, ()> {
        SecureStream::advance(self, now).map_err(|_| ())
    }
}

struct Connection<S> {
    stream: S,
    token: [u8; TOKEN_BYTES],
    token_have: usize,
    authenticated: bool,
    request: [u8; REQUEST_BYTES],
    request_have: usize,
    write: Vec<u8>,
    write_at: usize,
    requests: usize,
    last: u64,
}

impl<S: Transport> Connection<S> {
    fn new(stream: S, now: u64) -> Self {
        Self {
            stream,
            token: [0; TOKEN_BYTES],
            token_have: 0,
            authenticated: false,
            request: [0; REQUEST_BYTES],
            request_have: 0,
            write: Vec::new(),
            write_at: 0,
            requests: 0,
            last: now,
        }
    }

    fn poll(&mut self, node: &Node, expected: &[u8; TOKEN_BYTES], now: u64) -> Result<(), ()> {
        if now.saturating_sub(self.last) > IDLE_MS || self.requests >= MAX_REQUESTS_PER_CONNECTION {
            return Err(());
        }
        // Fail closed until the handshake completes and pending ciphertext drains.
        if !self.stream.advance(now)? {
            return Ok(());
        }
        // Bound work per poll: drain a pending response before reading more.
        if self.write_at < self.write.len() {
            match self.stream.write(&self.write[self.write_at..]) {
                Ok(0) => return Err(()),
                Ok(written) => {
                    self.write_at += written;
                    self.last = now;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => return Err(()),
            }
            if self.write_at == self.write.len() {
                self.write.clear();
                self.write_at = 0;
            }
            let _ = self.stream.advance(now)?;
            return Ok(());
        }
        if !self.authenticated {
            match self
                .stream
                .read(&mut self.token[self.token_have..TOKEN_BYTES])
            {
                Ok(0) => return Err(()),
                Ok(read) => {
                    self.token_have += read;
                    self.last = now;
                    if self.token_have == TOKEN_BYTES {
                        if !constant_time_eq(&self.token, expected) {
                            return Err(());
                        }
                        self.authenticated = true;
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => return Err(()),
            }
            return Ok(());
        }
        match self.stream.read(&mut self.request[self.request_have..]) {
            Ok(0) => return Err(()),
            Ok(read) => {
                self.request_have += read;
                self.last = now;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) => {}
            Err(_) => return Err(()),
        }
        if self.request_have == REQUEST_BYTES {
            let request = Request::decode(self.request).map_err(|_| ())?;
            let response = transport::handle_page_request(node.source(), request, MAX_PAGE_BYTES);
            let mut out = Vec::new();
            transport::write_response(&mut out, &response, MAX_PAGE_BYTES).map_err(|_| ())?;
            self.write = out;
            self.write_at = 0;
            self.request = [0; REQUEST_BYTES];
            self.request_have = 0;
            self.requests = self.requests.saturating_add(1);
            let _ = self.stream.advance(now)?;
        }
        Ok(())
    }
}

fn constant_time_eq(a: &[u8; TOKEN_BYTES], b: &[u8; TOKEN_BYTES]) -> bool {
    let mut difference = 0u8;
    for index in 0..TOKEN_BYTES {
        difference |= a[index] ^ b[index];
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use monario_wallet_scan::page::transport::{
        Status, TOKEN_BYTES as CLIENT_TOKEN_BYTES, read_response, write_request,
    };
    use std::io::Cursor;

    struct Mock {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl Mock {
        fn new(input: Vec<u8>) -> Self {
            Self {
                input: Cursor::new(input),
                output: Vec::new(),
            }
        }
    }

    impl Read for Mock {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(out)
        }
    }

    impl Write for Mock {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.output.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Plaintext in-memory framing transport; the cryptographic session is
    /// exercised by `transport::encrypted` and the isolated in-memory pair tests.
    struct Plain<S>(S);

    impl<S: Read + Write> Read for Plain<S> {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            self.0.read(out)
        }
    }

    impl<S: Read + Write> Write for Plain<S> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.write(bytes)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.0.flush()
        }
    }

    impl<S: Read + Write> Transport for Plain<S> {
        fn advance(&mut self, _now: u64) -> Result<bool, ()> {
            Ok(true)
        }
    }

    fn token() -> [u8; TOKEN_BYTES] {
        [7; TOKEN_BYTES]
    }

    fn request(start: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        write_request(
            &mut bytes,
            &token(),
            Request::new(start, 1).expect("valid request"),
        )
        .expect("frame");
        bytes
    }

    fn poll_until_response(
        connection: &mut Connection<Plain<Mock>>,
        node: &Node,
    ) -> Result<(), ()> {
        for now in 0..8 {
            connection.poll(node, &token(), now)?;
            if !connection.write.is_empty() || connection.write_at > 0 {
                return Ok(());
            }
        }
        Err(())
    }

    #[test]
    fn authenticated_request_gets_a_generic_tip_response() {
        let (_dir, node) = crate::tests::node();
        let mut connection = Connection::new(Plain(Mock::new(request(1))), 0);
        poll_until_response(&mut connection, &node).unwrap();
        // One more poll drains the queued response.
        connection.poll(&node, &token(), 1).unwrap();
        let response = read_response(
            &mut Cursor::new(connection.stream.0.output.clone()),
            MAX_PAGE_BYTES,
        )
        .unwrap();
        assert_eq!(response.status, Status::AtTip);
        assert!(response.page.is_empty());
    }

    fn send<S: Read + Write>(client: &mut SecureStream<S>, bytes: &[u8], now: &mut u64) {
        let mut at = 0;
        while at < bytes.len() {
            *now += 1;
            client.advance(*now).unwrap();
            match client.write(&bytes[at..]) {
                Ok(written) => at += written,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => panic!("encrypted write failed"),
            }
            client.advance(*now).unwrap();
        }
    }

    #[test]
    fn encrypted_in_memory_session_serves_a_page() {
        let (_dir, node) = crate::tests::node();
        let server_key = Identity::from_secret(zeroize::Zeroizing::new([11; 32]));
        let client_key = Identity::from_secret(zeroize::Zeroizing::new([7; 32]));
        let profile = [2u8; 32];
        let (client_io, server_io) = crate::transport::isolated_memory_pair();
        let mut client = SecureStream::new(
            client_io,
            &client_key,
            Role::Initiator {
                remote_key: server_key.public_key(),
            },
            profile,
            SCAN_DOMAIN,
            0,
        )
        .unwrap();
        let server_stream = SecureStream::new(
            server_io,
            &server_key,
            Role::Responder,
            profile,
            SCAN_DOMAIN,
            0,
        )
        .unwrap();
        let mut connection = Connection::new(server_stream, 0);
        let frame = request(1);
        let mut now = 0u64;
        let mut sent = false;
        let mut response = Vec::new();
        for _ in 0..2_000 {
            now += 1;
            client.advance(now).unwrap();
            connection.poll(&node, &token(), now).unwrap();
            if client.established() && !sent {
                send(&mut client, &frame[..TOKEN_BYTES], &mut now);
                send(&mut client, &frame[TOKEN_BYTES..], &mut now);
                sent = true;
            }
            let mut buffer = [0u8; 64];
            if !sent || !client.established() {
                continue;
            }
            match client.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => response.extend_from_slice(&buffer[..read]),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => panic!("encrypted read failed"),
            }
            if response.len() >= 5 {
                break;
            }
        }
        assert_eq!(response, vec![1, 0, 0, 0, 0]);
    }

    #[test]
    fn bad_tokens_truncation_and_bounds_fail_closed() {
        let (_dir, node) = crate::tests::node();

        let mut wrong = request(1);
        wrong[0] ^= 1;
        let mut connection = Connection::new(Plain(Mock::new(wrong)), 0);
        let mut failed = false;
        for now in 0..4 {
            if connection.poll(&node, &token(), now).is_err() {
                failed = true;
                break;
            }
        }
        assert!(failed);

        let mut connection = Connection::new(Plain(Mock::new(request(1)[..10].to_vec())), 0);
        let mut failed = false;
        for now in 0..4 {
            if connection.poll(&node, &token(), now).is_err() {
                failed = true;
                break;
            }
        }
        assert!(failed);

        let mut connection = Connection::new(Plain(Mock::new(request(1))), 0);
        assert!(connection.poll(&node, &token(), IDLE_MS + 1).is_err());

        let mut connection = Connection::new(Plain(Mock::new(Vec::new())), 0);
        connection.requests = MAX_REQUESTS_PER_CONNECTION + 1;
        assert!(connection.poll(&node, &token(), 0).is_err());
    }

    #[test]
    fn config_validation_rejects_unsafe_binds_and_zero_tokens() {
        let identity = Identity::generate().unwrap();
        let valid = Config {
            bind: "127.0.0.1:19445".parse().unwrap(),
            token: [1; TOKEN_BYTES],
            allow_remote: false,
            identity: Identity::generate().unwrap(),
            profile: [2; 32],
        };
        assert!(valid.validate().is_ok());
        assert!(
            Config {
                bind: "0.0.0.0:19445".parse().unwrap(),
                token: [1; TOKEN_BYTES],
                allow_remote: true,
                identity,
                profile: [2; 32],
            }
            .validate()
            .is_err()
        );
        assert!(
            Config {
                bind: "127.0.0.1:0".parse().unwrap(),
                token: [1; TOKEN_BYTES],
                allow_remote: false,
                identity: Identity::generate().unwrap(),
                profile: [2; 32],
            }
            .validate()
            .is_err()
        );
        assert!(
            Config {
                bind: "192.0.2.1:19445".parse().unwrap(),
                token: [1; TOKEN_BYTES],
                allow_remote: false,
                identity: Identity::generate().unwrap(),
                profile: [2; 32],
            }
            .validate()
            .is_err()
        );
        assert!(
            Config {
                bind: "127.0.0.1:19445".parse().unwrap(),
                token: [0; TOKEN_BYTES],
                allow_remote: false,
                identity: Identity::generate().unwrap(),
                profile: [2; 32],
            }
            .validate()
            .is_err()
        );
        assert!(
            Config {
                bind: "127.0.0.1:19445".parse().unwrap(),
                token: [1; TOKEN_BYTES],
                allow_remote: false,
                identity: Identity::generate().unwrap(),
                profile: [0; 32],
            }
            .validate()
            .is_err()
        );
        assert_eq!(CLIENT_TOKEN_BYTES, TOKEN_BYTES);
    }
}
