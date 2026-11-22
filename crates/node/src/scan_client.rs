//! Key-pinned, encrypted client for the node's read-only scan page server.
//!
//! The wallet still validates and durably commits every block locally. This
//! module owns only the transport: it connects explicitly, pins the operator's
//! scan public key, and drives the mandatory Noise session on a blocking socket
//! with bounded per-operation deadlines. It opens no listener and accepts no
//! page without the pin.

use crate::transport::{Identity, Role, SCAN_DOMAIN, SecureStream};
use monario_wallet_scan::Error as ScanError;
use monario_wallet_scan::page::{
    MAX_PAGE_BYTES, PageSource,
    transport::{Client, Request},
};
use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    time::{Duration, Instant},
};

/// Blocking socket adapter that drives `SecureStream::advance` before each
/// operation. Every call has an absolute deadline, so a stalled handshake or a
/// partial record cannot hang the caller indefinitely.
struct Driven {
    stream: SecureStream<TcpStream>,
    started: Instant,
    timeout: Duration,
}

fn blocked(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

impl Driven {
    fn now_ms(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn check(&self, deadline: Instant) -> io::Result<()> {
        if Instant::now() >= deadline {
            Err(io::ErrorKind::TimedOut.into())
        } else {
            Ok(())
        }
    }

    fn pump(&mut self, deadline: Instant) -> io::Result<()> {
        loop {
            self.check(deadline)?;
            match self.stream.advance(self.now_ms()) {
                Ok(true) => return Ok(()),
                Ok(false) => self.check(deadline)?,
                Err(_) => return Err(io::ErrorKind::InvalidData.into()),
            }
        }
    }
}

impl Read for Driven {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let deadline = Instant::now() + self.timeout;
        loop {
            self.check(deadline)?;
            self.pump(deadline)?;
            match self.stream.read(out) {
                Ok(read) => return Ok(read),
                Err(error) if blocked(&error) => self.check(deadline)?,
                Err(error) => return Err(error),
            }
        }
    }
}

impl Write for Driven {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let deadline = Instant::now() + self.timeout;
        loop {
            self.check(deadline)?;
            self.pump(deadline)?;
            match self.stream.write(bytes) {
                Ok(written) => return Ok(written),
                Err(error) if blocked(&error) => self.check(deadline)?,
                Err(error) => return Err(error),
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        let deadline = Instant::now() + self.timeout;
        loop {
            match self.stream.flush() {
                Ok(()) => return Ok(()),
                Err(error) if blocked(&error) => self.pump(deadline)?,
                Err(error) => return Err(error),
            }
        }
    }
}

impl Drop for Driven {
    fn drop(&mut self) {
        self.stream.close();
    }
}

/// A pinned, encrypted page source for one numeric endpoint.
pub struct SecurePageSource {
    client: Client<Driven>,
}

impl SecurePageSource {
    /// EXPLICIT NETWORK ACTIVATION. The caller supplies the trusted scan public
    /// key and the consensus profile; neither is learned from the peer.
    pub fn connect(
        address: SocketAddr,
        token: [u8; 32],
        timeout: Duration,
        remote_key: [u8; 32],
        profile: [u8; 32],
    ) -> Result<Self, ScanError> {
        if address.port() == 0
            || address.ip().is_unspecified()
            || address.ip().is_multicast()
            || token == [0; 32]
            || timeout.is_zero()
            || profile == [0; 32]
        {
            return Err(ScanError::Configuration);
        }
        let stream =
            TcpStream::connect_timeout(&address, timeout).map_err(|_| ScanError::Transport)?;
        // Individual reads and writes must not outlive the transport's 10-second
        // record/handshake deadlines; the overall operation keeps the caller bound.
        let io_timeout = timeout.min(Duration::from_millis(10_000));
        stream
            .set_read_timeout(Some(io_timeout))
            .and_then(|()| stream.set_write_timeout(Some(io_timeout)))
            .and_then(|()| stream.set_nodelay(true))
            .map_err(|_| ScanError::Transport)?;
        let identity = Identity::generate().map_err(|_| ScanError::Transport)?;
        let secure = SecureStream::new(
            stream,
            &identity,
            Role::Initiator { remote_key },
            profile,
            SCAN_DOMAIN,
            0,
        )
        .map_err(|_| ScanError::Transport)?;
        let driven = Driven {
            stream: secure,
            started: Instant::now(),
            timeout,
        };
        Ok(Self {
            client: Client::new(driven, token)?,
        })
    }
}

impl PageSource for SecurePageSource {
    fn page(
        &mut self,
        start_height: u64,
        max_blocks: usize,
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, ScanError> {
        if max_bytes == 0 || max_bytes > MAX_PAGE_BYTES {
            return Err(ScanError::Configuration);
        }
        let request = Request::new(start_height, max_blocks)?;
        self.client.request(request, max_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsafe_endpoints_and_parameters_fail_closed() {
        let key = [3; 32];
        let profile = [2; 32];
        for address in ["0.0.0.0:19445", "127.0.0.1:0", "224.0.0.1:19445"] {
            assert!(
                SecurePageSource::connect(
                    address.parse().unwrap(),
                    [1; 32],
                    Duration::from_secs(1),
                    key,
                    profile,
                )
                .is_err(),
                "{address}"
            );
        }
        assert!(
            SecurePageSource::connect(
                "127.0.0.1:19445".parse().unwrap(),
                [0; 32],
                Duration::from_secs(1),
                key,
                profile,
            )
            .is_err()
        );
        assert!(
            SecurePageSource::connect(
                "127.0.0.1:19445".parse().unwrap(),
                [1; 32],
                Duration::ZERO,
                key,
                profile,
            )
            .is_err()
        );
        assert!(
            SecurePageSource::connect(
                "127.0.0.1:19445".parse().unwrap(),
                [1; 32],
                Duration::from_secs(1),
                [0; 32],
                [0; 32],
            )
            .is_err()
        );
    }
}
