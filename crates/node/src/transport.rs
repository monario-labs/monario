//! Opt-in nonblocking TCP driver. Tests use in-memory Read/Write implementations.
mod encrypted;
mod policy;
use crate::{Clock, Error, Node, PeerId, wire::CHUNK};
pub use encrypted::persistent;
pub(crate) use encrypted::valid_public;
pub use encrypted::{Identity, POOL_DOMAIN, Role, SCAN_DOMAIN, SecureConnection, SecureStream};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

struct Connection<S> {
    stream: S,
    input: Box<[u8; CHUNK]>,
    start: usize,
    end: usize,
}
impl<S: Read + Write> Connection<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            input: Box::new([0; CHUNK]),
            start: 0,
            end: 0,
        }
    }
    /// At most one bounded read and one partial write. Interrupted/WouldBlock
    /// never discard bytes; EOF and zero-length writes close the connection.
    pub fn poll(&mut self, node: &mut Node, id: PeerId, clock: Clock) -> Result<(), Error> {
        if !node.contains_peer(id) {
            return Err(Error::Protocol);
        }
        if node.can_receive(id) {
            if self.start == self.end {
                self.start = 0;
                self.end = 0;
                match self.stream.read(self.input.as_mut_slice()) {
                    Ok(0) => return Err(Error::Io),
                    Ok(n) => self.end = n,
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) => {}
                    Err(_) => return Err(Error::Io),
                }
            }
            if self.start < self.end {
                self.start += node.receive(id, &self.input[self.start..self.end], clock)?;
            }
        }
        if let Some(bytes) = node.outbound(id) {
            match self.stream.write(bytes) {
                Ok(0) => return Err(Error::Io),
                Ok(n) => node.consume_outbound(id, n)?,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => return Err(Error::Io),
            }
        }
        Ok(())
    }
}
/// Trusted numeric socket addresses only. Peers cannot supply dial targets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerTarget {
    pub address: SocketAddr,
    pub public_key: [u8; 32],
}
pub struct TcpConfig {
    pub identity: Identity,
    pub listen: Option<SocketAddr>,
    pub connect: Vec<PeerTarget>,
}
/// Construction validates configuration but opens no socket.
pub struct TcpDriver {
    config: TcpConfig,
}
impl TcpDriver {
    pub fn new(config: TcpConfig) -> Result<Self, Error> {
        if config.connect.len() > 32
            || config.connect.iter().any(|p| {
                p.address.port() == 0
                    || p.address.ip().is_unspecified()
                    || p.address.ip().is_multicast()
                    || !encrypted::valid_public(p.public_key)
                    || p.public_key == config.identity.public_key()
            })
            || config
                .connect
                .iter()
                .enumerate()
                .any(|(i, p)| config.connect[..i].iter().any(|q| q.address == p.address))
            || config.listen.is_some_and(|a| a.port() == 0)
        {
            return Err(Error::Configuration);
        }
        Ok(Self { config })
    }
    /// EXPLICIT NETWORK ACTIVATION. Never called by tests or library construction.
    /// All RandomX use and durable mutations stay on this calling thread.
    pub fn run(&self, node: &mut Node, stop: &AtomicBool) -> Result<(), Error> {
        self.run_with(node, stop, |_, _| Ok(()))
    }
    /// Same loop with one bounded caller step per poll iteration. The step runs on
    /// the node-owning thread after `Node::tick`; an error shuts the driver down.
    pub fn run_with(
        &self,
        node: &mut Node,
        stop: &AtomicBool,
        mut tick: impl FnMut(&mut Node, Clock) -> Result<(), Error>,
    ) -> Result<(), Error> {
        drive(node, stop, |node, stop| {
            self.run_inner(node, stop, &mut tick)
        })
    }
    fn run_inner(
        &self,
        node: &mut Node,
        stop: &AtomicBool,
        tick: &mut impl FnMut(&mut Node, Clock) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let listener = if let Some(addr) = self.config.listen {
            let l = TcpListener::bind(addr).map_err(|_| Error::Io)?;
            l.set_nonblocking(true).map_err(|_| Error::Io)?;
            Some(l)
        } else {
            None
        };
        let mut connections: BTreeMap<PeerId, (SocketAddr, SecureConnection<TcpStream>)> =
            BTreeMap::new();
        let mut retry = policy::RetryPolicy::new();
        let mut credited = BTreeSet::new();
        let began = Instant::now();
        let base_ms = node.last_ms;
        let reserved_outbound = self.config.connect.len().min(node.limits.peers);
        while !stop.load(Ordering::Acquire) && !node.stopped() {
            let clock = Clock {
                monotonic_ms: base_ms
                    .saturating_add(u64::try_from(began.elapsed().as_millis()).unwrap_or(u64::MAX)),
                unix_seconds: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| Error::Clock)?
                    .as_secs(),
            };
            if let Some(listener) = &listener {
                for _ in 0..4 {
                    match listener.accept() {
                        Ok((stream, addr)) => {
                            // Kernel-supplied address only; peer wire data never selects a ban key.
                            if !retry.allows(addr.ip(), clock.monotonic_ms) {
                                continue;
                            }
                            if node.peer_count() >= node.limits.peers - reserved_outbound {
                                continue;
                            }
                            if connections
                                .values()
                                .filter(|(other, _)| other.ip() == addr.ip())
                                .count()
                                >= 2
                            {
                                continue;
                            }
                            stream.set_nonblocking(true).map_err(|_| Error::Io)?;
                            match node.add_peer(clock) {
                                Ok(id) => {
                                    let connection = SecureConnection::new(
                                        stream,
                                        &self.config.identity,
                                        Role::Responder,
                                        node.profile,
                                        clock.monotonic_ms,
                                    )?;
                                    connections.insert(id, (addr, connection));
                                }
                                Err(Error::Capacity) => {}
                                Err(e) => return Err(e),
                            }
                        }
                        Err(e)
                            if matches!(
                                e.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                            ) =>
                        {
                            break;
                        }
                        Err(_) => return Err(Error::Io),
                    }
                }
            }
            // One bounded dial attempt per iteration; no DNS or advertised-address dialing.
            if node.peer_count() < node.limits.peers
                && let Some(target) = self.config.connect.iter().find(|target| {
                    !connections.values().any(|(a, _)| *a == target.address)
                        && retry.allows(target.address.ip(), clock.monotonic_ms)
                })
            {
                let addr = target.address;
                match TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
                    Ok(stream) => {
                        stream.set_nonblocking(true).map_err(|_| Error::Io)?;
                        match node.add_outbound_peer(clock) {
                            Ok(id) => {
                                let connection = SecureConnection::new(
                                    stream,
                                    &self.config.identity,
                                    Role::Initiator {
                                        remote_key: target.public_key,
                                    },
                                    node.profile,
                                    clock.monotonic_ms,
                                )?;
                                connections.insert(id, (addr, connection));
                            }
                            Err(Error::Capacity) => {}
                            Err(e) => return Err(e),
                        }
                    }
                    Err(_) => {
                        retry.failure(addr.ip(), clock.monotonic_ms);
                    }
                }
            }
            let ids: Vec<_> = connections.keys().copied().collect();
            for id in ids {
                let result = if node.contains_peer(id) {
                    connections
                        .get_mut(&id)
                        .expect("listed connection")
                        .1
                        .poll(node, id, clock)
                } else {
                    Err(Error::Protocol)
                };
                if matches!(result, Err(Error::Io | Error::Protocol)) {
                    if let Some((addr, _)) = connections.remove(&id) {
                        retry.failure(addr.ip(), clock.monotonic_ms);
                    }
                    credited.remove(&id);
                    node.disconnect(id);
                } else {
                    result?;
                    if node.peer_ready(id)
                        && credited.insert(id)
                        && let Some((addr, _)) = connections.get(&id)
                    {
                        retry.success(addr.ip());
                    }
                }
            }
            node.tick(clock)?;
            tick(node, clock)?;
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }
}

// Shared lifecycle; tests supply a memory-only loop, never a socket factory.
pub(crate) fn drive(
    node: &mut Node,
    stop: &AtomicBool,
    run: impl FnOnce(&mut Node, &AtomicBool) -> Result<(), Error>,
) -> Result<(), Error> {
    if stop.load(Ordering::Acquire) {
        return node.shutdown();
    }
    if node.stopped() {
        return Err(Error::Stopped);
    }
    let result = run(node, stop);
    let shutdown = node.shutdown();
    result.and(shutdown)
}

#[cfg(test)]
pub(crate) use encrypted::tests::memory_pair as isolated_memory_pair;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    struct Mock {
        read: Vec<u8>,
        at: usize,
        written: Vec<u8>,
        calls: usize,
    }
    impl Read for Mock {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            if self.at == self.read.len() {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let n = (self.read.len() - self.at).min(out.len()).min(7);
            out[..n].copy_from_slice(&self.read[self.at..self.at + n]);
            self.at += n;
            Ok(n)
        }
    }
    impl Write for Mock {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.calls += 1;
            if self.calls.is_multiple_of(2) {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let n = bytes.len().min(3);
            self.written.extend(&bytes[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn partial_io_and_wouldblock_preserve_exact_stream_bytes() {
        let (_dir, mut node) = crate::tests::node();
        let id = node.add_peer(crate::tests::clock(0)).unwrap();
        let hello = crate::tests::hello(&node, [9; 16]);
        let mut expected = node.outbound(id).unwrap().to_vec();
        expected.extend(
            crate::wire::encode(
                node.magic,
                crate::wire::ACK,
                &[],
                node.block_limit,
                node.tx_limit,
            )
            .unwrap(),
        );
        let mut conn = Connection::new(Mock {
            read: hello,
            at: 0,
            written: Vec::new(),
            calls: 0,
        });
        for ms in 0..100 {
            conn.poll(&mut node, id, crate::tests::clock(ms)).unwrap();
            node.tick(crate::tests::clock(ms)).unwrap();
        }
        assert_eq!(conn.stream.written, expected);
        assert!(node.peers[&id].hello);
        assert!(!node.peers[&id].ready);
    }
    #[test]
    fn pre_stopped_driver_opens_no_socket() {
        let (_dir, mut node) = crate::tests::node();
        let driver = TcpDriver::new(TcpConfig {
            identity: Identity::generate().unwrap(),
            listen: Some("127.0.0.1:1".parse().unwrap()),
            connect: vec![],
        })
        .unwrap();
        driver.run(&mut node, &AtomicBool::new(true)).unwrap();
        assert!(node.stopped());
        assert_eq!(node.peer_count(), 0);
    }
    #[test]
    fn bounded_caller_step_runs_inside_the_owning_loop_and_stops_cleanly() {
        let (_dir, mut node) = crate::tests::node();
        let driver = TcpDriver::new(TcpConfig {
            identity: Identity::generate().unwrap(),
            listen: None,
            connect: vec![],
        })
        .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let signal = stop.clone();
        let mut ticks = 0;
        driver
            .run_with(&mut node, &stop, |_, _| {
                ticks += 1;
                if ticks >= 3 {
                    signal.store(true, Ordering::Release);
                }
                Ok(())
            })
            .unwrap();
        assert_eq!(ticks, 3);
        assert!(node.stopped());
        assert_eq!(node.peer_count(), 0);
        assert_eq!(node.buffered_bytes(), (0, 0));
    }
    #[test]
    fn caller_step_error_requests_shutdown_without_reopening_sockets() {
        let (_dir, mut node) = crate::tests::node();
        let driver = TcpDriver::new(TcpConfig {
            identity: Identity::generate().unwrap(),
            listen: None,
            connect: vec![],
        })
        .unwrap();
        assert_eq!(
            driver.run_with(&mut node, &AtomicBool::new(false), |_, _| Err(
                Error::Protocol
            )),
            Err(Error::Protocol)
        );
        assert!(node.stopped());
        assert_eq!(node.peer_count(), 0);
    }
}
