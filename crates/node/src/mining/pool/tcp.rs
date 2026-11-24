//! Explicit TCP pool server/client drivers. Construction opens no socket; only
//! `run`/`connect` activate networking. Tests only exercise pre-stopped paths.
use super::session::{
    self, CheckerFactory, Client, ClientPolicy, Event, Limits, RandomXFactory, Server,
};
use super::{Error as PoolError, Policy, ledger, link, wire};
use crate::{
    Clock, Node,
    mining::{Work, refresh::Manager},
    transport::{Identity, POOL_DOMAIN, Role, SecureStream},
};
use std::{
    io,
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

#[derive(Debug)]
pub enum Error {
    Configuration,
    Clock,
    Io,
    Handshake,
    NoWork,
    Refresh(crate::mining::Error),
    Pool(PoolError),
    Session(session::Error),
    Link(link::Error),
    Wire(wire::Error),
    Node(crate::Error),
}

const MAX_CONNECTIONS: usize = 16;
const MAX_PER_IP: usize = 4;
const MIN_POLL_MS: u64 = 100;
const MAX_POLL_MS: u64 = 60_000;
const MAX_TIMESTAMP_SECONDS: u32 = 3_600;
const MAX_CONNECT_TIMEOUT_MS: u64 = 30_000;

/// Client-side connection lifecycle. A transport connection is not an
/// authenticated session, and a rejected credential is not a later share
/// rejection. No phase carries any secret.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Phase {
    #[default]
    Offline,
    Handshake,
    Authenticating,
    Authenticated,
    Rejected,
}

impl Phase {
    /// Fixed lowercase label for the public status snapshot.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Offline => "offline",
            Self::Handshake => "handshake",
            Self::Authenticating => "authenticating",
            Self::Authenticated => "authenticated",
            Self::Rejected => "rejected",
        }
    }
}

pub struct ServerConfig {
    pub identity: Identity,
    pub listen: SocketAddr,
    pub profile: [u8; 32],
    pub clients: Vec<Arc<ClientPolicy>>,
    pub policy: Policy,
    pub limits: Limits,
    pub mode: monario_randomx::Mode,
    pub max_connections: usize,
    pub poll_ms: u64,
    pub timestamp_seconds: u32,
}

pub struct TcpPool {
    config: ServerConfig,
    timestamp: Option<u64>,
    last_poll: Option<u64>,
    listener: Option<Arc<TcpListener>>,
    began: Option<Instant>,
    base_ms: u64,
    connections: Vec<Connection>,
    current: Option<Arc<Work>>,
    factory: Arc<dyn CheckerFactory>,
}

impl TcpPool {
    /// Validates bounded configuration but opens no listener.
    pub fn new(config: ServerConfig) -> Result<Self, Error> {
        if config.listen.port() == 0
            || config.max_connections == 0
            || config.max_connections > MAX_CONNECTIONS
            || !(MIN_POLL_MS..=MAX_POLL_MS).contains(&config.poll_ms)
            || config.timestamp_seconds == 0
            || config.timestamp_seconds > MAX_TIMESTAMP_SECONDS
            || config.clients.is_empty()
            || config.clients.len() > session::MAX_CLIENTS
        {
            return Err(Error::Configuration);
        }
        let factory: Arc<dyn CheckerFactory> = Arc::new(RandomXFactory::new(config.mode));
        Ok(Self {
            config,
            timestamp: None,
            last_poll: None,
            listener: None,
            began: None,
            base_ms: 0,
            connections: Vec::new(),
            current: None,
            factory,
        })
    }

    /// EXPLICIT NETWORK ACTIVATION. An already-set stop flag binds no listener.
    /// The caller owns node shutdown; this ticks until the stop flag is set and
    /// then closes every connection. Pacing is a fixed 10 ms sleep.
    pub fn run(
        &mut self,
        node: &mut Node,
        manager: &mut Manager,
        ledger: &mut ledger::Ledger,
        stop: &AtomicBool,
    ) -> Result<(), Error> {
        while self.tick(node, manager, ledger, stop)? {
            std::thread::sleep(Duration::from_millis(10));
        }
        self.close();
        Ok(())
    }

    /// One non-blocking step for a caller that owns no other loop: derive a
    /// monotonic clock from the first tick, run `poll`, then tick the node.
    /// `run` uses this; a node runtime uses `poll` with its own clock instead.
    pub fn tick(
        &mut self,
        node: &mut Node,
        manager: &mut Manager,
        ledger: &mut ledger::Ledger,
        stop: &AtomicBool,
    ) -> Result<bool, Error> {
        if stop.load(Ordering::Acquire) || node.stopped() {
            return Ok(false);
        }
        if self.began.is_none() {
            self.began = Some(Instant::now());
            self.base_ms = node.last_ms;
        }
        let began = self.began.ok_or(Error::Clock)?;
        let clock = Clock {
            monotonic_ms: self
                .base_ms
                .saturating_add(u64::try_from(began.elapsed().as_millis()).unwrap_or(u64::MAX)),
            unix_seconds: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| Error::Clock)?
                .as_secs(),
        };
        if !self.poll(node, manager, ledger, stop, clock)? {
            return Ok(false);
        }
        node.tick(clock).map_err(Error::Node)?;
        Ok(true)
    }

    /// One non-blocking server step for a caller that already owns the node clock
    /// (for example `PersistentDriver::run_with`). Binds once, refreshes work,
    /// accepts at most four connections and polls every client once; it never
    /// ticks the node. Returns `false` without binding when the stop flag or the
    /// node reports shutdown, so a runtime can own P2P, RPC and scan beside it.
    pub fn poll(
        &mut self,
        node: &mut Node,
        manager: &mut Manager,
        ledger: &mut ledger::Ledger,
        stop: &AtomicBool,
        clock: Clock,
    ) -> Result<bool, Error> {
        if stop.load(Ordering::Acquire) || node.stopped() {
            return Ok(false);
        }
        if self.listener.is_none() {
            let listener = TcpListener::bind(self.config.listen).map_err(|_| Error::Io)?;
            listener.set_nonblocking(true).map_err(|_| Error::Io)?;
            self.listener = Some(Arc::new(listener));
        }
        let listener = self.listener.as_ref().ok_or(Error::Io)?.clone();
        if self
            .last_poll
            .is_none_or(|at| clock.monotonic_ms.saturating_sub(at) >= self.config.poll_ms)
        {
            self.last_poll = Some(clock.monotonic_ms);
            let timestamp = self.timestamp(node, clock)?;
            let refreshed = match manager.refresh(node, timestamp, clock) {
                Ok(work) => work.clone(),
                Err(error) => {
                    for connection in &mut self.connections {
                        connection.link.close();
                    }
                    return Err(Error::Refresh(error));
                }
            };
            if self
                .current
                .as_ref()
                .is_none_or(|old| old.id() != refreshed.id())
            {
                self.current = Some(Arc::new(refreshed));
            }
            let work = self.current.as_ref().ok_or(Error::NoWork)?.clone();
            for connection in &mut self.connections {
                match connection
                    .server
                    .apply_work(work.as_ref(), clock.monotonic_ms)
                {
                    Ok(true) => connection.sent_job = None,
                    Ok(false) => {}
                    Err(_) => connection.link.close(),
                }
            }
            self.connections
                .retain(|connection| !connection.link.is_closed());
        }
        for _ in 0..4 {
            if self.connections.len() >= self.config.max_connections {
                break;
            }
            match listener.accept() {
                Ok((stream, peer)) => {
                    if stream.set_nonblocking(true).is_err()
                        || self
                            .connections
                            .iter()
                            .filter(|connection| connection.peer.ip() == peer.ip())
                            .count()
                            >= MAX_PER_IP
                    {
                        continue;
                    }
                    let work = self.current.as_ref().ok_or(Error::NoWork)?.clone();
                    let secure = SecureStream::new(
                        stream,
                        &self.config.identity,
                        Role::Responder,
                        self.config.profile,
                        POOL_DOMAIN,
                        clock.monotonic_ms,
                    )
                    .map_err(|_| Error::Handshake)?;
                    let server = Server::shared(
                        work.as_ref(),
                        self.config.policy,
                        self.config.clients.clone(),
                        self.factory.clone(),
                        self.config.limits,
                    )
                    .map_err(Error::Session)?;
                    self.connections.push(Connection {
                        peer,
                        link: link::PoolLink::new_control(secure),
                        server,
                        sent_job: None,
                    });
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    break;
                }
                Err(_) => return Err(Error::Io),
            }
        }
        let mut active = Vec::with_capacity(self.connections.len());
        for mut connection in std::mem::take(&mut self.connections) {
            if connection.tick(node, ledger, clock).is_err() {
                connection.link.close();
            } else {
                active.push(connection);
            }
        }
        self.connections = active;
        Ok(true)
    }

    /// Close every connection and forget the bound listener and cached work.
    pub(crate) fn close(&mut self) {
        for connection in &mut self.connections {
            connection.link.close();
        }
        self.connections.clear();
        self.listener = None;
        self.began = None;
        self.current = None;
        self.last_poll = None;
    }

    fn timestamp(&mut self, node: &Node, clock: Clock) -> Result<u64, Error> {
        let now = clock.unix_seconds;
        let median = node
            .source()
            .chain()
            .map_err(|_| Error::Pool(PoolError::Storage))?
            .median_time_past();
        let minimum = median.saturating_add(1);
        let candidate = now.max(minimum);
        match self.timestamp {
            Some(held)
                if held >= minimum
                    && held <= candidate
                    && candidate.saturating_sub(held)
                        < u64::from(self.config.timestamp_seconds) =>
            {
                Ok(held)
            }
            _ => {
                self.timestamp = Some(candidate);
                Ok(candidate)
            }
        }
    }
}

struct Connection {
    peer: SocketAddr,
    link: link::PoolLink<TcpStream>,
    server: Server,
    sent_job: Option<[u8; 32]>,
}

/// A reply that leaves the peer without a usable current assignment, so the
/// driver must dispatch the live job again. `AuthOk` starts a fresh session;
/// `STALE` means the peer just discarded an assignment (possibly a replacement
/// it had already received), and `job_at` still gates the resend by expiry, so
/// retired or expired work is never revived.
fn needs_dispatch(reply: &wire::Message) -> bool {
    matches!(
        reply,
        wire::Message::AuthOk { .. } | wire::Message::Rejected { code: wire::STALE }
    )
}

impl Connection {
    fn tick(
        &mut self,
        node: &mut Node,
        ledger: &mut ledger::Ledger,
        clock: Clock,
    ) -> Result<(), Error> {
        let messages = self.link.poll(clock.monotonic_ms).map_err(Error::Link)?;
        for message in messages {
            let bytes = wire::encode(&message).map_err(Error::Wire)?.len();
            let reply = self
                .server
                .handle(node, ledger, message, bytes, clock)
                .map_err(Error::Session)?;
            self.link.send(&reply).map_err(Error::Link)?;
            if needs_dispatch(&reply) {
                // Redispatch at most one current unexpired job below, after this
                // rejection, so a late old-assignment Submit cannot leave the
                // client without work until lease expiry.
                self.sent_job = None;
            }
        }
        if self.server.is_authenticated()
            && self.sent_job.is_none()
            && let Some(job) = self.server.job_at(clock.monotonic_ms)
        {
            let id = match &job {
                wire::Message::Job { job, .. } => *job,
                _ => [0; 32],
            };
            self.link.send(&job).map_err(Error::Link)?;
            self.sent_job = Some(id);
        }
        self.link.flush(clock.monotonic_ms).map_err(Error::Link)
    }
}

pub struct ClientConfig {
    pub identity: Identity,
    pub pool: SocketAddr,
    pub pool_key: [u8; 32],
    pub profile: [u8; 32],
    pub client: [u8; 16],
    pub token: Zeroizing<[u8; 32]>,
    pub limits: Limits,
    pub connect_timeout_ms: u64,
}

pub struct TcpClient {
    config: ClientConfig,
    state: Option<ClientState>,
}

struct ClientState {
    link: link::PoolLink<TcpStream>,
    client: Client,
    auth_sent: bool,
}

impl TcpClient {
    /// Validates configuration; opens no socket.
    pub fn new(config: ClientConfig) -> Result<Self, Error> {
        if config.pool.port() == 0
            || config.client == [0; 16]
            || *config.token == [0; 32]
            || config.connect_timeout_ms == 0
            || config.connect_timeout_ms > MAX_CONNECT_TIMEOUT_MS
        {
            return Err(Error::Configuration);
        }
        Ok(Self {
            config,
            state: None,
        })
    }

    /// EXPLICIT NETWORK ACTIVATION. Never called by construction or tests.
    pub fn connect(&mut self, now_ms: u64) -> Result<(), Error> {
        if self.state.is_some() {
            return Err(Error::Configuration);
        }
        let stream = TcpStream::connect_timeout(
            &self.config.pool,
            Duration::from_millis(self.config.connect_timeout_ms),
        )
        .map_err(|_| Error::Io)?;
        stream.set_nonblocking(true).map_err(|_| Error::Io)?;
        let secure = SecureStream::new(
            stream,
            &self.config.identity,
            Role::Initiator {
                remote_key: self.config.pool_key,
            },
            self.config.profile,
            POOL_DOMAIN,
            now_ms,
        )
        .map_err(|_| Error::Handshake)?;
        let client = Client::new(self.config.client, *self.config.token, self.config.limits)
            .map_err(Error::Session)?;
        self.state = Some(ClientState {
            link: link::PoolLink::new(secure),
            client,
            auth_sent: false,
        });
        Ok(())
    }

    pub fn tick(&mut self, node: &Node, clock: Clock) -> Result<Vec<Event>, Error> {
        let state = self.state.as_mut().ok_or(Error::Configuration)?;
        let messages = state.link.poll(clock.monotonic_ms).map_err(Error::Link)?;
        if state.link.is_established() && !state.auth_sent {
            let auth = state.client.auth_message();
            state.link.send(&auth).map_err(Error::Link)?;
            state.auth_sent = true;
        }
        let mut events = Vec::new();
        for message in messages {
            let bytes = wire::encode(&message).map_err(Error::Wire)?.len();
            let event = state
                .client
                .handle(node, message, bytes, clock)
                .map_err(Error::Session)?;
            events.push(event);
            // A credential rejection is terminal: later frames must not be
            // processed against the rejected session.
            if state.client.auth_rejected() {
                break;
            }
        }
        state.link.flush(clock.monotonic_ms).map_err(Error::Link)?;
        if state.client.is_closed() {
            state.link.close();
        }
        Ok(events)
    }

    pub fn submit(&mut self, nonce: [u8; 32], clock: Clock) -> Result<(), Error> {
        let state = self.state.as_mut().ok_or(Error::Configuration)?;
        let message = state.client.submit(nonce, clock).map_err(Error::Session)?;
        state.link.send(&message).map_err(Error::Link)
    }

    pub fn work(&self) -> Option<&Work> {
        self.state.as_ref()?.client.work()
    }

    pub fn assignment(&self) -> Option<&session::ClientAssignment> {
        self.state.as_ref()?.client.assignment()
    }

    pub fn is_connected(&self) -> bool {
        self.state
            .as_ref()
            .is_some_and(|state| !state.link.is_closed())
    }

    /// Distinguish an open transport/handshake from a usable authenticated
    /// session and from a credential the server explicitly rejected.
    pub fn phase(&self) -> Phase {
        let Some(state) = self.state.as_ref() else {
            return Phase::Offline;
        };
        // A peer may close immediately after rejecting the credential. Keep the
        // explicit rejection visible instead of degrading to "offline".
        if state.client.auth_rejected() {
            return Phase::Rejected;
        }
        if state.link.is_closed() {
            return Phase::Offline;
        }
        if state.client.is_authenticated() {
            Phase::Authenticated
        } else if state.link.is_established() {
            Phase::Authenticating
        } else {
            Phase::Handshake
        }
    }

    pub fn close(&mut self) {
        if let Some(state) = &mut self.state {
            state.link.close();
        }
        self.state = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mining::pool::session::ClientPolicy;
    use crate::tests::{clock, node, private_tempdir};
    use monario_address::{Address, Network, Receiver, TransparentReceiver};

    fn address() -> String {
        Address::new(
            Network::Regtest,
            Receiver::Transparent(TransparentReceiver::PublicKeyHash([7; 20])),
        )
        .encode()
    }

    fn ledger_limits() -> ledger::Limits {
        ledger::Limits {
            max_shares: 64,
            max_clients: 8,
            max_units_per_share: 100,
            max_units_per_client: 10_000,
        }
    }

    #[test]
    fn pre_stopped_pool_binds_no_listener_and_construction_opens_nothing() {
        let (_dir, mut n) = node();
        let dir = private_tempdir();
        let mut ledger =
            ledger::Ledger::create(&dir.path().join("pool.sqlite"), [9; 32], ledger_limits())
                .unwrap();
        let clients = vec![Arc::new(
            ClientPolicy::new([7; 16], [9; 32], [3; 24], 1, 4, [255; 32]).unwrap(),
        )];
        let pool = TcpPool::new(ServerConfig {
            identity: Identity::generate().unwrap(),
            listen: "127.0.0.1:1".parse().unwrap(),
            profile: [2; 32],
            clients,
            policy: Policy {
                units_per_share: 1,
                units_per_block_candidate: 4,
            },
            limits: Limits::default(),
            mode: monario_randomx::Mode::Interpreter,
            max_connections: 2,
            poll_ms: 1_000,
            timestamp_seconds: 60,
        })
        .unwrap();
        let mut client = TcpClient::new(ClientConfig {
            identity: Identity::generate().unwrap(),
            pool: "127.0.0.1:1".parse().unwrap(),
            pool_key: Identity::generate().unwrap().public_key(),
            profile: [2; 32],
            client: [7; 16],
            token: Zeroizing::new([9; 32]),
            limits: Limits::default(),
            connect_timeout_ms: 200,
        })
        .unwrap();
        assert!(!client.is_connected());
        assert_eq!(client.phase(), Phase::Offline);
        assert!(client.tick(&n, clock(10)).is_err());
        let mut manager = Manager::new(address(), Network::Regtest, vec![]);
        let stop = AtomicBool::new(true);
        let mut pool = pool;
        pool.run(&mut n, &mut manager, &mut ledger, &stop).unwrap();
        assert_eq!(n.peer_count(), 0);
        assert_eq!(ledger.share_count().unwrap(), 0);
    }

    #[test]
    fn stale_and_auth_ok_redispatch_but_busy_and_invalid_do_not() {
        assert!(needs_dispatch(&wire::Message::AuthOk { session: [1; 16] }));
        assert!(needs_dispatch(&wire::Message::Rejected { code: wire::STALE }));
        for code in [wire::BUSY, wire::INVALID, wire::DUPLICATE, wire::QUOTA] {
            assert!(!needs_dispatch(&wire::Message::Rejected { code }));
        }
        assert!(!needs_dispatch(&wire::Message::Accepted {
            units: 1,
            block_candidate: false,
        }));
        assert!(!needs_dispatch(&wire::Message::Job {
            assignment: [1; 32],
            parent: [2; 32],
            job: [3; 32],
            prefix: [4; 24],
            start: 0,
            end: 1,
            target: [5; 32],
            packet: vec![],
        }));
    }

    #[test]
    fn phase_labels_are_fixed_and_ordered() {
        assert_eq!(Phase::default(), Phase::Offline);
        let labels = [
            Phase::Offline,
            Phase::Handshake,
            Phase::Authenticating,
            Phase::Authenticated,
            Phase::Rejected,
        ]
        .map(Phase::label);
        assert_eq!(
            labels,
            [
                "offline",
                "handshake",
                "authenticating",
                "authenticated",
                "rejected"
            ]
        );
    }

    #[test]
    fn invalid_pool_configuration_fails_closed() {
        let (_dir, _) = node();
        assert!(
            TcpPool::new(ServerConfig {
                identity: Identity::generate().unwrap(),
                listen: "127.0.0.1:0".parse().unwrap(),
                profile: [2; 32],
                clients: vec![Arc::new(
                    ClientPolicy::new([7; 16], [9; 32], [3; 24], 1, 4, [255; 32]).unwrap(),
                )],
                policy: Policy {
                    units_per_share: 1,
                    units_per_block_candidate: 4,
                },
                limits: Limits::default(),
                mode: monario_randomx::Mode::Interpreter,
                max_connections: 0,
                poll_ms: 1_000,
                timestamp_seconds: 60,
            })
            .is_err()
        );
        assert!(
            TcpClient::new(ClientConfig {
                identity: Identity::generate().unwrap(),
                pool: "127.0.0.1:1".parse().unwrap(),
                pool_key: Identity::generate().unwrap().public_key(),
                profile: [2; 32],
                client: [7; 16],
                token: Zeroizing::new([0; 32]),
                limits: Limits::default(),
                connect_timeout_ms: 200,
            })
            .is_err()
        );
    }
}
