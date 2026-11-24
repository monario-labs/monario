//! Explicitly activated operator loop over `refresh::Manager` and `cpu::Miner`.
//! Construction starts no thread, search or transport. The caller drives `tick`
//! (from the existing node loop) or `run` (local-only loop).
use super::{
    Clock, Error as MiningError, Node, Submitted, Work, cpu,
    pool::link::Error as LinkError, pool::session::Error as SessionError,
    pool::session::Event as SessionEvent, pool::session::Limits as SessionLimits,
    pool::tcp::ClientConfig, pool::tcp::Error as PoolTransportError, pool::tcp::Phase,
    pool::tcp::TcpClient, pool::wire::Error as WireError, refresh,
};
use crate::transport::Identity;
use monario_address::{Address, Network, Receiver};
use monario_chain::Hash;
use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver as WorkReceiver, TryRecvError},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

pub use monario_randomx::MAX_WORKERS;
const MIN_POLL_MS: u64 = 10;
const MAX_POLL_MS: u64 = 60_000;
const MAX_TIMESTAMP_SECONDS: u32 = 3_600;
const MAX_ADDRESS_BYTES: usize = 128;
/// Coinbase extra data is public; the consensus encoder accepts at most 98 bytes.
const MAX_EXTRA_DATA: usize = 98;
/// One bounded slot per assignment-specific worker channel. A full slot applies
/// backpressure to that worker only; it never blocks or stops its peers.
const POOL_EVENT_CAPACITY: usize = 1;
/// Bound the retry cadence after quota or link-buffer pressure.
const POOL_RETRY_MS: u64 = 250;

#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub network: Network,
    /// Local CPU worker count. Workers share the light cache for the active seed.
    pub workers: u8,
    /// Minimum monotonic interval between validated job refreshes.
    pub poll_ms: u64,
    /// Work timestamp is held steady for this long to avoid per-tick rebuilds.
    pub timestamp_seconds: u32,
    pub mode: monario_randomx::Mode,
}

#[derive(Debug)]
pub enum Error {
    Configuration,
    Clock,
    Refresh(MiningError),
    Worker(cpu::Error),
    Submit(cpu::Error),
    Node(crate::Error),
    Spawn,
    Pool(super::pool::tcp::Error),
    /// The pool server explicitly rejected the configured client credential.
    PoolAuth,
    /// A worker stopped without reporting exhaustion or a fatal error.
    WorkerExit,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Status {
    pub refreshed: bool,
    pub accepted: Option<Hash>,
    pub workers: usize,
    pub job: Option<Hash>,
}

/// Blocking search primitive executed in a dedicated worker thread.
trait Search: Send + Sync {
    /// Return at most one candidate. `Ok(None)` means cancellation; an exhausted
    /// range or hashing failure is an error rather than silent progress loss.
    fn search(
        &self,
        work: &Work,
        start: u64,
        end: u64,
        cancel: &AtomicBool,
    ) -> Result<Option<cpu::Solution>, cpu::Error>;
}

struct CpuSearch {
    mode: monario_randomx::Mode,
    cache: Mutex<Option<monario_randomx::SharedCache>>,
}

impl CpuSearch {
    fn new(mode: monario_randomx::Mode) -> Self {
        Self {
            mode,
            cache: Mutex::new(None),
        }
    }

    fn verifier(&self, work: &Work) -> Result<monario_randomx::Verifier, cpu::Error> {
        let cache = {
            let mut slot = self
                .cache
                .lock()
                .map_err(|_| cpu::Error::CacheUnavailable)?;
            let seed = work.seed();
            if slot.as_ref().is_none_or(|cache| cache.seed() != seed) {
                // The operator joins the previous workers before changing jobs.
                *slot = None;
                *slot = Some(monario_randomx::SharedCache::new(&seed).map_err(cpu::Error::Hash)?);
            }
            slot.as_ref().expect("cache initialized").clone()
        };
        cache.verifier(self.mode).map_err(cpu::Error::Hash)
    }
}

impl Search for CpuSearch {
    fn search(
        &self,
        work: &Work,
        start: u64,
        end: u64,
        cancel: &AtomicBool,
    ) -> Result<Option<cpu::Solution>, cpu::Error> {
        if cancel.load(Ordering::Acquire) {
            return Ok(None);
        }
        let mut miner = cpu::Miner::with_verifier(work, start, end, self.verifier(work)?)?;
        loop {
            match miner.search_batch(cpu::MAX_BATCH, cancel)? {
                cpu::Batch::Found(solution) => return Ok(Some(solution)),
                cpu::Batch::Pending => {}
                cpu::Batch::Cancelled => return Ok(None),
                cpu::Batch::Exhausted => return Err(cpu::Error::Exhausted),
            }
        }
    }
}

struct Worker {
    cancel: Arc<AtomicBool>,
    handle: JoinHandle<()>,
}

/// Job refresh, worker replacement and submission share one calling thread.
/// Workers only search; only this struct mutates the node.
pub struct Operator {
    manager: refresh::Manager,
    config: Config,
    timestamp: Option<u64>,
    last_poll: Option<u64>,
    job: Option<Arc<Work>>,
    workers: Vec<Worker>,
    events: Option<WorkReceiver<Result<Option<cpu::Solution>, cpu::Error>>>,
    backend: Arc<dyn Search>,
}

/// Validate a solo payout destination before a node is spawned or activated:
/// real `monario-address` decoding against the intended network, with a
/// transparent receiver only. No prefix or shape heuristics.
pub fn validate_solo_address(address: &str, network: Network) -> Result<(), Error> {
    if address.is_empty() || address.len() > MAX_ADDRESS_BYTES {
        return Err(Error::Configuration);
    }
    match Address::decode(address, network)
        .map_err(|_| Error::Configuration)?
        .receiver()
    {
        Receiver::Transparent(_) => Ok(()),
        Receiver::Private(_) => Err(Error::Configuration),
    }
}

impl Operator {
    /// Validates configuration and payout destination; opens no thread or network.
    pub fn new(config: Config, address: String, extra_data: Vec<u8>) -> Result<Self, Error> {
        if config.workers == 0
            || config.workers > MAX_WORKERS
            || !(MIN_POLL_MS..=MAX_POLL_MS).contains(&config.poll_ms)
            || config.timestamp_seconds == 0
            || config.timestamp_seconds > MAX_TIMESTAMP_SECONDS
            || extra_data.len() > MAX_EXTRA_DATA
        {
            return Err(Error::Configuration);
        }
        validate_solo_address(&address, config.network)?;
        Ok(Self::with_backend(
            config,
            refresh::Manager::new(address, config.network, extra_data),
            Arc::new(CpuSearch::new(config.mode)),
        ))
    }

    fn with_backend(config: Config, manager: refresh::Manager, backend: Arc<dyn Search>) -> Self {
        Self {
            manager,
            config,
            timestamp: None,
            last_poll: None,
            job: None,
            workers: Vec::new(),
            events: None,
            backend,
        }
    }

    /// One bounded, non-blocking step: rate-limited refresh, worker replacement
    /// on a changed job, and at most one submission drain per worker slot.
    pub fn tick(&mut self, node: &mut Node, clock: Clock) -> Result<Status, Error> {
        let mut status = Status::default();
        if self
            .last_poll
            .is_none_or(|at| clock.monotonic_ms.saturating_sub(at) >= self.config.poll_ms)
        {
            self.last_poll = Some(clock.monotonic_ms);
            let timestamp = self.timestamp(node, clock)?;
            let work = match self.manager.refresh(node, timestamp, clock) {
                Ok(work) => work.clone(),
                Err(error) => {
                    self.stop_workers();
                    self.job = None;
                    return Err(Error::Refresh(error));
                }
            };
            if self.job.as_ref().is_none_or(|job| job.id() != work.id()) {
                self.stop_workers();
                self.job = Some(Arc::new(work));
                self.start_workers()?;
                status.refreshed = true;
            }
        }
        self.reap();
        status.accepted = self.collect(node, clock)?;
        if status.accepted.is_some() {
            // The accepted block changes the validated tip; rebuild immediately.
            self.last_poll = None;
        }
        status.workers = self.workers.len();
        status.job = self.job.as_ref().map(|job| job.id());
        Ok(status)
    }

    fn timestamp(&mut self, node: &Node, clock: Clock) -> Result<u64, Error> {
        let now = clock.unix_seconds;
        // A block accepted within the same second raises the median-time floor.
        let median = node
            .source()
            .chain()
            .map_err(|_| Error::Refresh(MiningError::Storage))?
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

    fn start_workers(&mut self) -> Result<(), Error> {
        let work = self.job.clone().ok_or(Error::Configuration)?;
        if !self.workers.is_empty() {
            return Err(Error::Configuration);
        }
        let (sender, receiver) = mpsc::channel();
        let mut workers = Vec::<Worker>::with_capacity(usize::from(self.config.workers));
        for index in 0..self.config.workers {
            let (start, end) = partition(index, self.config.workers);
            let cancel = Arc::new(AtomicBool::new(false));
            let signal = cancel.clone();
            let job = work.clone();
            let events = sender.clone();
            let backend = self.backend.clone();
            let handle = match thread::Builder::new()
                .name(format!("monar-miner-{index}"))
                .spawn(move || {
                    let event = backend.search(&job, start, end, &signal);
                    let _ = events.send(event);
                }) {
                Ok(handle) => handle,
                Err(_) => {
                    for worker in workers {
                        worker.cancel.store(true, Ordering::Release);
                        let _ = worker.handle.join();
                    }
                    return Err(Error::Spawn);
                }
            };
            workers.push(Worker { cancel, handle });
        }
        drop(sender);
        self.workers = workers;
        self.events = Some(receiver);
        Ok(())
    }

    fn collect(&mut self, node: &mut Node, clock: Clock) -> Result<Option<Hash>, Error> {
        let mut events = Vec::new();
        if let Some(receiver) = &self.events {
            for _ in 0..self.config.workers {
                match receiver.try_recv() {
                    Ok(event) => events.push(event),
                    Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
                }
            }
        }
        for event in events {
            let solution = match event {
                Ok(Some(solution)) => solution,
                Ok(None) => continue,
                Err(error) => {
                    self.stop_workers();
                    return Err(Error::Worker(error));
                }
            };
            let Some(work) = self.job.clone() else {
                continue;
            };
            if solution.job_id != work.id() {
                continue;
            }
            match node.submit_solution(&work, &solution, clock) {
                Ok(Submitted::Accepted(accepted)) => {
                    self.stop_workers();
                    return Ok(Some(accepted.id));
                }
                Ok(Submitted::AlreadyKnown(id)) => {
                    self.stop_workers();
                    return Ok(Some(id));
                }
                Err(cpu::Error::Submit(MiningError::Stale)) => {}
                Err(error) => {
                    self.stop_workers();
                    return Err(Error::Submit(error));
                }
            }
        }
        Ok(None)
    }

    fn reap(&mut self) {
        let mut active = Vec::with_capacity(self.workers.len());
        for worker in self.workers.drain(..) {
            if worker.handle.is_finished() {
                let _ = worker.handle.join();
            } else {
                active.push(worker);
            }
        }
        self.workers = active;
    }

    fn stop_workers(&mut self) {
        for worker in &self.workers {
            worker.cancel.store(true, Ordering::Release);
        }
        for worker in self.workers.drain(..) {
            let _ = worker.handle.join();
        }
        self.events = None;
    }

    /// Cancel and join every worker; safe to call repeatedly and from `Drop`.
    pub fn shutdown(&mut self) {
        self.stop_workers();
        self.job = None;
        self.last_poll = None;
    }

    pub fn active_workers(&self) -> usize {
        self.workers.len()
    }

    /// Local-only loop. Opens no socket and never creates a chain; the caller
    /// must still supply an existing validated node. Stops on `stop` or node stop.
    pub fn run(&mut self, node: &mut Node, stop: &AtomicBool) -> Result<(), Error> {
        self.run_with(node, stop, |_, _, _| Ok(()))
    }

    /// Local loop with one caller step per poll, matching the network driver hook.
    pub fn run_with(
        &mut self,
        node: &mut Node,
        stop: &AtomicBool,
        mut step: impl FnMut(&Node, Clock, Status) -> Result<(), Error>,
    ) -> Result<(), Error> {
        if stop.load(Ordering::Acquire) {
            return Ok(());
        }
        let base = node.last_ms;
        let began = Instant::now();
        while !stop.load(Ordering::Acquire) && !node.stopped() {
            let clock = Clock {
                monotonic_ms: base
                    .saturating_add(u64::try_from(began.elapsed().as_millis()).unwrap_or(u64::MAX)),
                unix_seconds: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| Error::Clock)?
                    .as_secs(),
            };
            let status = self.tick(node, clock)?;
            step(node, clock, status)?;
            node.tick(clock).map_err(Error::Node)?;
            thread::sleep(Duration::from_millis(10));
        }
        self.stop_workers();
        Ok(())
    }
}

impl Drop for Operator {
    fn drop(&mut self) {
        self.stop_workers();
    }
}

// ---------------------------------------------------------------------------
// Explicit pool-mode operator
// ---------------------------------------------------------------------------

/// Blocking search primitive for pool-assigned work, executed in a worker thread.
/// Implementations must keep one cursor for the whole assigned partition, report
/// every candidate through `share` (returning `false` stops the search), and must
/// never submit. `Ok(())` means the assigned range is exhausted or cancelled.
trait PoolSearch: Send + Sync {
    #[expect(
        clippy::too_many_arguments,
        reason = "Explicit job, partition, target, cancellation and share boundaries"
    )]
    fn search(
        &self,
        work: &Work,
        prefix: [u8; 24],
        start: u64,
        end: u64,
        target: [u8; 32],
        cancel: &AtomicBool,
        share: &mut dyn FnMut([u8; 32]) -> bool,
    ) -> Result<(), cpu::Error>;
}

impl PoolSearch for CpuSearch {
    #[expect(
        clippy::too_many_arguments,
        reason = "Explicit job, partition, target, cancellation and share boundaries"
    )]
    fn search(
        &self,
        work: &Work,
        prefix: [u8; 24],
        start: u64,
        end: u64,
        target: [u8; 32],
        cancel: &AtomicBool,
        share: &mut dyn FnMut([u8; 32]) -> bool,
    ) -> Result<(), cpu::Error> {
        if cancel.load(Ordering::Acquire) {
            return Ok(());
        }
        // Build one miner for the assignment so every reported share continues
        // from the existing cursor instead of restarting the partition.
        let mut miner =
            cpu::Miner::with_pool_verifier(work, start, end, prefix, target, self.verifier(work)?)?;
        loop {
            match miner.search_batch(cpu::MAX_BATCH, cancel)? {
                cpu::Batch::Found(solution) => {
                    if !share(solution.nonce) {
                        return Ok(());
                    }
                }
                cpu::Batch::Pending => {}
                cpu::Batch::Cancelled | cpu::Batch::Exhausted => return Ok(()),
            }
        }
    }
}

/// Explicitly activated pool configuration. The token is a transport secret; it
/// is moved into the session and zeroized there. No `Debug` implementation exists.
pub struct PoolOperatorConfig {
    pub identity: Identity,
    pub pool: SocketAddr,
    pub pool_key: [u8; 32],
    pub profile: [u8; 32],
    pub client: [u8; 16],
    pub token: Zeroizing<[u8; 32]>,
    /// Local CPU worker count. Workers share the light cache for the active seed.
    pub workers: u8,
    /// Minimum monotonic interval between pool polls.
    pub poll_ms: u64,
    pub connect_timeout_ms: u64,
    pub mode: monario_randomx::Mode,
}

/// Snapshot of one pool tick. Shares are client-side observations submitted to
/// the pool; they are not block receipts, durable credits or payouts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PoolStatus {
    /// True only for an authenticated session, never for a bare transport
    /// connection or a rejected credential.
    pub connected: bool,
    pub phase: Phase,
    pub assigned: bool,
    pub workers: usize,
    pub submitted: u64,
    pub block_candidates: u64,
}

/// One candidate produced by a worker, bound to the exact assignment and job
/// that produced it so a replaced assignment can never submit stale work.
struct PoolShare {
    assignment: [u8; 32],
    job: [u8; 32],
    nonce: [u8; 32],
}

enum PoolEvent {
    /// The worker searched its whole partition and is stopping normally.
    Exhausted,
    /// The worker stopped because hashing/cache setup failed.
    Fatal(cpu::Error),
}

struct PoolWorker {
    cancel: Arc<AtomicBool>,
    handle: JoinHandle<()>,
    /// Bounded, assignment-specific share queue. Dropping it unblocks a worker
    /// that is waiting on a full queue during shutdown.
    shares: WorkReceiver<PoolShare>,
    /// Bounded terminal report, separate from shares so fatal errors surface
    /// even while share backpressure is pausing the worker.
    outcome: WorkReceiver<PoolEvent>,
    /// A terminal event was observed for this worker.
    terminated: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SubmitDisposition {
    Submitted,
    Retry,
    Stale,
}

/// Pool-mode operator. Construction opens no socket; `run`/`run_with` is the
/// explicit network activation point. Workers are cancelled when the pool
/// assignment changes, the session closes, or the caller stops. The local node
/// validates each assigned job before it is hashed; shares go to the pool.
pub struct PoolOperator {
    client: TcpClient,
    workers_limit: u8,
    poll_ms: u64,
    assignment: Option<[u8; 32]>,
    job: Option<Arc<Work>>,
    workers: Vec<PoolWorker>,
    /// Bounded retry queue for shares the client quota temporarily refused.
    pending: VecDeque<PoolShare>,
    /// Monotonic time before which quota/link pressure is not retried.
    retry_at: Option<u64>,
    backend: Arc<dyn PoolSearch>,
    submitted: u64,
    block_candidates: u64,
    last_poll: Option<u64>,
}

/// Quota and a full link writer buffer are retryable backpressure; a replaced
/// assignment is stale, not fatal. Closed/IO/wire-format failures stay fatal.
fn classify_submit(
    result: Result<(), PoolTransportError>,
) -> Result<SubmitDisposition, PoolTransportError> {
    match result {
        Ok(()) => Ok(SubmitDisposition::Submitted),
        Err(PoolTransportError::Session(SessionError::Quota)) => Ok(SubmitDisposition::Retry),
        Err(PoolTransportError::Link(LinkError::Wire(WireError::Oversized))) => {
            Ok(SubmitDisposition::Retry)
        }
        Err(PoolTransportError::Session(SessionError::Assignment)) => Ok(SubmitDisposition::Stale),
        Err(error) => Err(error),
    }
}

/// Spawn one worker for one assignment-specific, bounded event queue. The worker
/// keeps its cursor across every reported share and only exits on exhaustion,
/// cancellation, channel closure or a fatal hashing error.
#[expect(
    clippy::too_many_arguments,
    reason = "Explicit job, partition, target, assignment and backend boundaries"
)]
fn spawn_pool_worker(
    index: u8,
    work: Arc<Work>,
    assignment: [u8; 32],
    prefix: [u8; 24],
    start: u64,
    end: u64,
    target: [u8; 32],
    backend: Arc<dyn PoolSearch>,
) -> std::io::Result<PoolWorker> {
    let (share_sender, shares) = mpsc::sync_channel(POOL_EVENT_CAPACITY);
    let (outcome_sender, outcome) = mpsc::sync_channel(POOL_EVENT_CAPACITY);
    let cancel = Arc::new(AtomicBool::new(false));
    let signal = cancel.clone();
    let job = work.id();
    let handle = thread::Builder::new()
        .name(format!("monar-pool-miner-{index}"))
        .spawn(move || {
            let query = backend.search(
                &work,
                prefix,
                start,
                end,
                target,
                &signal,
                &mut |nonce| {
                    share_sender
                        .send(PoolShare {
                            assignment,
                            job,
                            nonce,
                        })
                        .is_ok()
                },
            );
            let terminal = match query {
                Ok(()) => PoolEvent::Exhausted,
                Err(error) => PoolEvent::Fatal(error),
            };
            let _ = outcome_sender.send(terminal);
        })?;
    Ok(PoolWorker {
        cancel,
        handle,
        shares,
        outcome,
        terminated: false,
    })
}

/// Set cancellation, unblock a possible full-queue send by dropping both
/// receivers, then join. This keeps shutdown bounded even under backpressure.
fn stop_pool_worker(worker: PoolWorker) {
    worker.cancel.store(true, Ordering::Release);
    drop(worker.shares);
    drop(worker.outcome);
    let _ = worker.handle.join();
}

impl PoolOperator {
    /// Validates bounded configuration and moves the identity/token into the
    /// session. Opens no socket.
    pub fn new(config: PoolOperatorConfig) -> Result<Self, Error> {
        if config.workers == 0
            || config.workers > MAX_WORKERS
            || !(MIN_POLL_MS..=MAX_POLL_MS).contains(&config.poll_ms)
            || config.connect_timeout_ms == 0
            || config.pool.port() == 0
            || config.client == [0; 16]
            || *config.token == [0; 32]
            || config.pool_key == [0; 32]
        {
            return Err(Error::Configuration);
        }
        let client = TcpClient::new(ClientConfig {
            identity: config.identity,
            pool: config.pool,
            pool_key: config.pool_key,
            profile: config.profile,
            client: config.client,
            token: config.token,
            limits: SessionLimits::default(),
            connect_timeout_ms: config.connect_timeout_ms,
        })
        .map_err(|_| Error::Configuration)?;
        Ok(Self {
            client,
            workers_limit: config.workers,
            poll_ms: config.poll_ms,
            assignment: None,
            job: None,
            workers: Vec::new(),
            pending: VecDeque::new(),
            retry_at: None,
            backend: Arc::new(CpuSearch::new(config.mode)),
            submitted: 0,
            block_candidates: 0,
            last_poll: None,
        })
    }

    /// EXPLICIT NETWORK ACTIVATION. Never called by construction or tests.
    pub fn connect(&mut self, now_ms: u64) -> Result<(), Error> {
        self.client.connect(now_ms).map_err(Error::Pool)
    }

    /// One bounded step: rate-limited pool poll, assignment-driven worker restart,
    /// then at most one drain of worker submissions.
    pub fn tick(&mut self, node: &mut Node, clock: Clock) -> Result<PoolStatus, Error> {
        if self
            .last_poll
            .is_none_or(|at| clock.monotonic_ms.saturating_sub(at) >= self.poll_ms)
        {
            self.last_poll = Some(clock.monotonic_ms);
            let events = match self.client.tick(node, clock) {
                Ok(events) => events,
                Err(error) => {
                    // A transport/session failure makes the assignment unusable;
                    // never keep hashing or submitting against it.
                    self.stop_workers();
                    self.assignment = None;
                    self.job = None;
                    return Err(Error::Pool(error));
                }
            };
            for event in events {
                if let SessionEvent::Accepted {
                    block_candidate: true,
                    ..
                } = event
                {
                    self.block_candidates = self.block_candidates.saturating_add(1);
                }
            }
            // A server credential rejection is terminal for this connection: do
            // not retry the secret and do not keep reporting "connected".
            if self.client.phase() == Phase::Rejected {
                self.stop_workers();
                self.assignment = None;
                self.job = None;
                return Err(Error::PoolAuth);
            }
            self.refresh_assignment()?;
        }
        self.collect(clock)?;
        Ok(self.status())
    }

    /// Current public snapshot, available after a failed tick for a terminal
    /// status write. Shares are observations, not payouts.
    pub fn status(&self) -> PoolStatus {
        let phase = self.client.phase();
        PoolStatus {
            connected: phase == Phase::Authenticated,
            phase,
            assigned: self.assignment.is_some(),
            workers: self.active_workers(),
            submitted: self.submitted,
            block_candidates: self.block_candidates,
        }
    }

    fn refresh_assignment(&mut self) -> Result<(), Error> {
        let current = self
            .client
            .assignment()
            .map(|a| (a.id, a.start, a.end, a.prefix, a.target));
        match current {
            Some((id, start, end, prefix, target)) => {
                if self.assignment != Some(id) {
                    self.stop_workers();
                    let work = self.client.work().cloned().ok_or(Error::Configuration)?;
                    self.job = Some(Arc::new(work));
                    self.assignment = Some(id);
                    self.start_workers(start, end, prefix, target)?;
                }
            }
            None => {
                if self.assignment.is_some()
                    || !self.workers.is_empty()
                    || !self.pending.is_empty()
                {
                    self.stop_workers();
                    self.assignment = None;
                    self.job = None;
                }
            }
        }
        Ok(())
    }

    fn start_workers(
        &mut self,
        start: u64,
        end: u64,
        prefix: [u8; 24],
        target: [u8; 32],
    ) -> Result<(), Error> {
        let work = self.job.clone().ok_or(Error::Configuration)?;
        let assignment = self.assignment.ok_or(Error::Configuration)?;
        if !self.workers.is_empty() {
            return Err(Error::Configuration);
        }
        let mut workers: Vec<PoolWorker> = Vec::new();
        for index in 0..self.workers_limit {
            let (lo, hi) = partition_range(start, end, index, self.workers_limit);
            if lo > hi {
                continue;
            }
            match spawn_pool_worker(
                index,
                work.clone(),
                assignment,
                prefix,
                lo,
                hi,
                target,
                self.backend.clone(),
            ) {
                Ok(worker) => workers.push(worker),
                Err(_) => {
                    for worker in workers {
                        stop_pool_worker(worker);
                    }
                    return Err(Error::Spawn);
                }
            }
        }
        self.workers = workers;
        Ok(())
    }

    fn pending_capacity(&self) -> usize {
        usize::from(self.workers_limit).max(1)
    }

    fn collect(&mut self, clock: Clock) -> Result<(), Error> {
        // Terminal reports get at most one bounded check per worker each tick,
        // independent of share backpressure, so fatal errors are never hidden.
        let mut outcomes = Vec::new();
        for worker in &mut self.workers {
            if let Ok(event) = worker.outcome.try_recv() {
                worker.terminated = true;
                outcomes.push(event);
            }
        }

        let blocked = self.retry_pending(clock)?;
        let capacity = self.pending_capacity();
        let mut shares = Vec::new();
        // At most one share per worker per tick. Stop pulling as soon as the
        // bounded retry queue is full; full channels then pause producers.
        let mut pulled_all = !blocked && self.pending.len() < capacity;
        if pulled_all {
            for worker in &mut self.workers {
                if self.pending.len() + shares.len() >= capacity {
                    pulled_all = false;
                    break;
                }
                if let Ok(share) = worker.shares.try_recv() {
                    shares.push(share);
                }
            }
        }

        // Reap only when the bounded budget has room for a possible final
        // share, then remove and join. After the join, the receiver is
        // definitive: either one buffered share or `Disconnected`.
        if pulled_all {
            let mut index = 0;
            while index < self.workers.len() {
                if !self.workers[index].handle.is_finished() {
                    index += 1;
                    continue;
                }
                if self.pending.len() + shares.len() >= capacity {
                    index += 1;
                    continue;
                }
                let worker = self.workers.remove(index);
                let cancelled = worker.cancel.load(Ordering::Acquire);
                let _ = worker.handle.join();
                let mut terminated = worker.terminated;
                if let Ok(event) = worker.outcome.try_recv() {
                    terminated = true;
                    outcomes.push(event);
                }
                if !cancelled && !terminated {
                    self.stop_workers();
                    return Err(Error::WorkerExit);
                }
                match worker.shares.try_recv() {
                    Ok(share) => {
                        shares.push(share);
                        // Capacity is one and no sender remains after join.
                        debug_assert!(matches!(
                            worker.shares.try_recv(),
                            Err(TryRecvError::Disconnected)
                        ));
                    }
                    Err(TryRecvError::Disconnected) => {}
                    // Unreachable after join, but keep the candidate safe by
                    // leaving the worker's receiver dropped only once budgeted.
                    Err(TryRecvError::Empty) => {}
                }
            }
        }

        for event in outcomes {
            if let PoolEvent::Fatal(error) = event {
                self.stop_workers();
                return Err(Error::Worker(error));
            }
        }
        for share in shares {
            // A candidate from a replaced assignment or job is stale.
            if self.assignment != Some(share.assignment) {
                continue;
            }
            let Some(work) = &self.job else {
                continue;
            };
            if work.id() != share.job {
                continue;
            }
            self.submit_share(share, clock)?;
        }
        Ok(())
    }

    /// Retry quota/link-delayed shares on a bounded cadence. Returns true while
    /// pressure persists, which pauses new pulls and lets channels backpressure
    /// workers without evicting valid candidates.
    fn retry_pending(&mut self, clock: Clock) -> Result<bool, Error> {
        if self.pending.is_empty() {
            self.retry_at = None;
            return Ok(false);
        }
        if self
            .retry_at
            .is_some_and(|at| clock.monotonic_ms < at)
        {
            return Ok(true);
        }
        let capacity = self.pending_capacity();
        for _ in 0..capacity {
            let Some(share) = self.pending.pop_front() else {
                self.retry_at = None;
                return Ok(false);
            };
            if self.assignment != Some(share.assignment) {
                continue;
            }
            if self.job.as_ref().is_none_or(|work| work.id() != share.job) {
                continue;
            }
            match classify_submit(self.client.submit(share.nonce, clock)) {
                Ok(SubmitDisposition::Submitted) => {
                    self.submitted = self.submitted.saturating_add(1);
                }
                Ok(SubmitDisposition::Retry) => {
                    self.pending.push_front(share);
                    self.retry_at =
                        Some(clock.monotonic_ms.saturating_add(POOL_RETRY_MS));
                    return Ok(true);
                }
                Ok(SubmitDisposition::Stale) => {}
                Err(error) => {
                    self.stop_workers();
                    return Err(Error::Pool(error));
                }
            }
        }
        if self.pending.is_empty() {
            self.retry_at = None;
            Ok(false)
        } else {
            self.retry_at = Some(clock.monotonic_ms.saturating_add(POOL_RETRY_MS));
            Ok(true)
        }
    }

    fn submit_share(&mut self, share: PoolShare, clock: Clock) -> Result<(), Error> {
        match classify_submit(self.client.submit(share.nonce, clock)) {
            Ok(SubmitDisposition::Submitted) => {
                self.submitted = self.submitted.saturating_add(1);
                Ok(())
            }
            Ok(SubmitDisposition::Retry) => {
                // The pull budget above guarantees room for every accepted
                // candidate; valid shares are queued, never evicted.
                debug_assert!(self.pending.len() < self.pending_capacity());
                self.pending.push_back(share);
                if self.retry_at.is_none() {
                    self.retry_at =
                        Some(clock.monotonic_ms.saturating_add(POOL_RETRY_MS));
                }
                Ok(())
            }
            // The assignment/job was replaced between hashing and submission.
            Ok(SubmitDisposition::Stale) => Ok(()),
            Err(error) => {
                self.stop_workers();
                Err(Error::Pool(error))
            }
        }
    }

    fn stop_workers(&mut self) {
        for worker in &self.workers {
            worker.cancel.store(true, Ordering::Release);
        }
        for worker in self.workers.drain(..) {
            stop_pool_worker(worker);
        }
        self.pending.clear();
        self.retry_at = None;
    }

    /// Cancel and join every worker, close the session; safe to call repeatedly.
    pub fn shutdown(&mut self) {
        self.stop_workers();
        self.client.close();
        self.assignment = None;
        self.job = None;
        self.last_poll = None;
    }

    pub fn active_workers(&self) -> usize {
        self.workers
            .iter()
            .filter(|worker| !worker.handle.is_finished())
            .count()
    }

    /// Explicit network activation. Opens one authenticated, encrypted pool
    /// connection and ticks the local node. Stops on `stop` or node stop.
    pub fn run(&mut self, node: &mut Node, stop: &AtomicBool) -> Result<(), Error> {
        self.run_with(node, stop, |_, _, _| Ok(()))
    }

    /// Network loop with one caller step per tick, matching the network driver hook.
    pub fn run_with(
        &mut self,
        node: &mut Node,
        stop: &AtomicBool,
        mut step: impl FnMut(&Node, Clock, PoolStatus) -> Result<(), Error>,
    ) -> Result<(), Error> {
        if stop.load(Ordering::Acquire) {
            return Ok(());
        }
        let base = node.last_ms;
        if !self.client.is_connected() {
            self.connect(base)?;
        }
        let began = Instant::now();
        while !stop.load(Ordering::Acquire) && !node.stopped() {
            let clock = Clock {
                monotonic_ms: base
                    .saturating_add(u64::try_from(began.elapsed().as_millis()).unwrap_or(u64::MAX)),
                unix_seconds: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| Error::Clock)?
                    .as_secs(),
            };
            let status = self.tick(node, clock)?;
            step(node, clock, status)?;
            node.tick(clock).map_err(Error::Node)?;
            thread::sleep(Duration::from_millis(10));
        }
        self.shutdown();
        Ok(())
    }
}

impl Drop for PoolOperator {
    fn drop(&mut self) {
        self.stop_workers();
    }
}

/// Split an inclusive `[start, end]` range into `count` contiguous chunks.
/// Returns `(1, 0)` for an empty chunk so callers can skip it.
fn partition_range(start: u64, end: u64, index: u8, count: u8) -> (u64, u64) {
    if start > end || count == 0 || index >= count {
        return (1, 0);
    }
    let span = u128::from(end) - u128::from(start) + 1;
    let count = u128::from(count);
    let index = u128::from(index);
    let lo = span * index / count;
    let hi = span * (index + 1) / count;
    if lo >= hi {
        return (1, 0);
    }
    (
        (u128::from(start) + lo) as u64,
        (u128::from(start) + hi - 1) as u64,
    )
}

/// Disjoint inclusive 64-bit partitions covering the whole low-order nonce space.
fn partition(index: u8, count: u8) -> (u64, u64) {
    let total = u64::MAX as u128 + 1;
    let count = u128::from(count);
    let index = u128::from(index);
    let start = (total * index / count) as u64;
    let end = (total * (index + 1) / count - 1) as u64;
    (start, end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::clock;
    use monario_address::TransparentReceiver;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicUsize;

    fn address() -> String {
        Address::new(
            Network::Regtest,
            Receiver::Transparent(TransparentReceiver::PublicKeyHash([7; 20])),
        )
        .encode()
    }

    fn config(workers: u8) -> Config {
        Config {
            network: Network::Regtest,
            workers,
            poll_ms: 10,
            timestamp_seconds: 60,
            mode: monario_randomx::Mode::Interpreter,
        }
    }

    fn at(ms: u64) -> Clock {
        clock(ms)
    }

    struct Immediate {
        nonce: [u8; 32],
        job: Option<[u8; 32]>,
        fail: bool,
    }

    impl Search for Immediate {
        fn search(
            &self,
            work: &Work,
            _start: u64,
            _end: u64,
            _cancel: &AtomicBool,
        ) -> Result<Option<cpu::Solution>, cpu::Error> {
            if self.fail {
                return Err(cpu::Error::Exhausted);
            }
            Ok(Some(cpu::Solution {
                job_id: self.job.unwrap_or_else(|| work.id()),
                nonce: self.nonce,
            }))
        }
    }

    struct Waiting {
        parents: Arc<Mutex<Vec<Hash>>>,
        cancelled: Arc<AtomicUsize>,
    }

    impl Search for Waiting {
        fn search(
            &self,
            work: &Work,
            _start: u64,
            _end: u64,
            cancel: &AtomicBool,
        ) -> Result<Option<cpu::Solution>, cpu::Error> {
            self.parents.lock().unwrap().push(work.parent());
            while !cancel.load(Ordering::Acquire) {
                thread::sleep(Duration::from_millis(1));
            }
            self.cancelled.fetch_add(1, Ordering::Release);
            Ok(None)
        }
    }

    fn wait_for(condition: impl Fn() -> bool) {
        for _ in 0..2_000 {
            if condition() {
                return;
            }
            thread::sleep(Duration::from_millis(1));
        }
        panic!("condition was not reached");
    }

    #[test]
    fn accepted_fake_block_triggers_refresh_and_clean_shutdown() {
        let _serial = crate::tests::REAL.lock().unwrap();
        let (_dir, mut node) = crate::tests::node();
        let tip = node.source().chain().unwrap().tip();
        let backend = Arc::new(Immediate {
            nonce: [0; 32],
            job: None,
            fail: false,
        });
        let mut operator = Operator::with_backend(
            config(2),
            refresh::Manager::new(address(), Network::Regtest, vec![]),
            backend,
        );
        let mut accepted = None;
        for step in 1..=1_000 {
            let status = operator.tick(&mut node, at(step * 10)).unwrap();
            assert!(status.workers <= 2);
            if let Some(id) = status.accepted {
                accepted = Some(id);
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        let accepted = accepted.expect("fake backend must produce an easy fixed-nonce block");
        let chain = node.source().chain().unwrap();
        assert_eq!(chain.tip(), accepted);
        assert_ne!(chain.tip(), tip);
        assert_eq!(operator.active_workers(), 0);
        let status = operator.tick(&mut node, at(20_000)).unwrap();
        assert!(status.refreshed);
        assert_eq!(
            operator.job.as_ref().unwrap().parent(),
            accepted,
            "refresh must build on the newly accepted tip"
        );
        operator.shutdown();
        assert_eq!(operator.active_workers(), 0);
    }

    #[test]
    fn changed_tip_cancels_and_joins_every_old_worker_before_replacement() {
        let count = 6;
        let _serial = crate::tests::REAL.lock().unwrap();
        let (_dir, mut node) = crate::tests::node();
        let parents = Arc::new(Mutex::new(Vec::new()));
        let cancelled = Arc::new(AtomicUsize::new(0));
        let backend = Arc::new(Waiting {
            parents: parents.clone(),
            cancelled: cancelled.clone(),
        });
        let mut operator = Operator::with_backend(
            config(count),
            refresh::Manager::new(address(), Network::Regtest, vec![]),
            backend,
        );
        let count = usize::from(count);
        let first = operator.tick(&mut node, at(10)).unwrap();
        assert!(first.refreshed);
        wait_for(|| parents.lock().unwrap().len() >= count);
        let old_tip = node.source().chain().unwrap().tip();
        let new_tip = crate::tests::append(&mut node, old_tip, vec![], 10);
        assert_ne!(old_tip, new_tip);
        let second = operator.tick(&mut node, at(20)).unwrap();
        assert!(second.refreshed);
        assert_eq!(cancelled.load(Ordering::Acquire), count);
        wait_for(|| parents.lock().unwrap().len() >= count * 2);
        let seen = parents.lock().unwrap().clone();
        assert_eq!(&seen[..count], &[old_tip; 6]);
        assert_eq!(&seen[count..], &[new_tip; 6]);
        assert_eq!(operator.active_workers(), count);
        operator.shutdown();
        assert_eq!(cancelled.load(Ordering::Acquire), count * 2);
        assert_eq!(operator.active_workers(), 0);
    }

    #[test]
    fn pre_stopped_local_run_spawns_no_worker() {
        let (_dir, mut node) = crate::tests::node();
        let backend = Arc::new(Waiting {
            parents: Arc::new(Mutex::new(Vec::new())),
            cancelled: Arc::new(AtomicUsize::new(0)),
        });
        let mut operator = Operator::with_backend(
            config(1),
            refresh::Manager::new(address(), Network::Regtest, vec![]),
            backend,
        );
        let stop = AtomicBool::new(true);
        operator.run(&mut node, &stop).unwrap();
        assert_eq!(operator.active_workers(), 0);
    }

    #[test]
    fn solo_payout_address_requires_matching_network_and_transparent_receiver() {
        const REGTEST: &str = "rmont1qyqqqqgzqvzq2ps8pqys5zcvp58q7yq3zgfs7grwe7";
        const TEST: &str = "testmont1qyqqqqgzqvzq2ps8pqys5zcvp58q7yq3zgfsxp6xum";
        const REGTEST_PRIVATE: &str =
            "rmonz1qypgluecd9cuke9cuaufjzxa367hm6f2drjcdg6dhrl2nx006gqkltnkw5904elwjstyd09ey8n3q4";
        assert!(validate_solo_address(REGTEST, Network::Regtest).is_ok());
        assert!(validate_solo_address(REGTEST, Network::Test).is_err());
        assert!(validate_solo_address(REGTEST, Network::Main).is_err());
        assert!(validate_solo_address(TEST, Network::Regtest).is_err());
        assert!(validate_solo_address(REGTEST_PRIVATE, Network::Regtest).is_err());
        assert!(validate_solo_address("rmont1fixture", Network::Regtest).is_err());
        assert!(validate_solo_address("", Network::Regtest).is_err());
        assert!(matches!(
            Operator::new(config(1), REGTEST_PRIVATE.into(), vec![]),
            Err(Error::Configuration)
        ));
        assert!(matches!(
            Operator::new(config(1), TEST.into(), vec![]),
            Err(Error::Configuration)
        ));
    }

    #[test]
    fn configuration_and_backend_errors_fail_closed() {
        assert!(matches!(
            Operator::new(config(0), address(), vec![]),
            Err(Error::Configuration)
        ));
        assert!(matches!(
            Operator::new(config(MAX_WORKERS + 1), address(), vec![]),
            Err(Error::Configuration)
        ));
        assert!(matches!(
            Operator::new(config(1), "not-an-address".into(), vec![]),
            Err(Error::Configuration)
        ));
        assert!(matches!(
            Operator::new(config(1), address(), vec![0; MAX_EXTRA_DATA + 1]),
            Err(Error::Configuration)
        ));
        let _serial = crate::tests::REAL.lock().unwrap();
        let (_dir, mut node) = crate::tests::node();
        let backend = Arc::new(Immediate {
            nonce: [0; 32],
            job: None,
            fail: true,
        });
        let mut operator = Operator::with_backend(
            config(1),
            refresh::Manager::new(address(), Network::Regtest, vec![]),
            backend,
        );
        let mut failed = false;
        for step in 1..=200 {
            match operator.tick(&mut node, at(step * 10)) {
                Err(Error::Worker(cpu::Error::Exhausted)) => {
                    failed = true;
                    break;
                }
                Ok(_) => thread::sleep(Duration::from_millis(1)),
                Err(other) => panic!("unexpected error: {other:?}"),
            }
        }
        assert!(failed);
        assert_eq!(operator.active_workers(), 0);
    }

    #[test]
    fn partition_is_disjoint_and_covers_the_low_order_space() {
        for count in 1..=MAX_WORKERS {
            let mut next = 0u128;
            for index in 0..count {
                let (start, end) = partition(index, count);
                assert_eq!(u128::from(start), next);
                assert!(start <= end);
                next = u128::from(end) + 1;
            }
            assert_eq!(next, u64::MAX as u128 + 1);
        }
    }

    fn pool_config(workers: u8) -> PoolOperatorConfig {
        PoolOperatorConfig {
            identity: Identity::generate().unwrap(),
            pool: "127.0.0.1:1".parse().unwrap(),
            pool_key: [3; 32],
            profile: [2; 32],
            client: [7; 16],
            token: Zeroizing::new([9; 32]),
            workers,
            poll_ms: 10,
            connect_timeout_ms: 200,
            mode: monario_randomx::Mode::Interpreter,
        }
    }

    #[test]
    fn pool_partition_range_is_disjoint_and_bounded() {
        for count in 1..=MAX_WORKERS {
            let mut seen = 0u64;
            for index in 0..count {
                let (lo, hi) = partition_range(10, 99, index, count);
                if lo > hi {
                    continue;
                }
                assert!(lo >= 10 && hi <= 99 && lo <= hi);
                seen += hi - lo + 1;
            }
            assert_eq!(seen, 90);
        }
        let mut total = 0;
        for index in 0..4 {
            let (lo, hi) = partition_range(7, 8, index, 4);
            if lo <= hi {
                total += hi - lo + 1;
            }
        }
        assert_eq!(total, 2);
    }

    #[test]
    fn pool_operator_construction_opens_nothing_and_rejects_bad_configuration() {
        // Construction only validates; it never connects or spawns workers.
        let operator = PoolOperator::new(pool_config(1)).unwrap();
        assert_eq!(operator.active_workers(), 0);
        drop(operator);

        let bad = pool_config(0);
        assert!(matches!(PoolOperator::new(bad), Err(Error::Configuration)));
        let mut bad = pool_config(1);
        bad.workers = MAX_WORKERS + 1;
        assert!(matches!(PoolOperator::new(bad), Err(Error::Configuration)));
        let mut bad = pool_config(1);
        bad.client = [0; 16];
        assert!(matches!(PoolOperator::new(bad), Err(Error::Configuration)));
        let mut bad = pool_config(1);
        bad.token = Zeroizing::new([0; 32]);
        assert!(matches!(PoolOperator::new(bad), Err(Error::Configuration)));
        let mut bad = pool_config(1);
        bad.pool_key = [0; 32];
        assert!(matches!(PoolOperator::new(bad), Err(Error::Configuration)));
    }

    fn prepared_work(node: &mut Node) -> Work {
        let address = address();
        node.prepare_work(
            super::super::Request {
                address: &address,
                network: Network::Regtest,
                timestamp: 1_105,
                extra_data: b"",
            },
            clock(0),
        )
        .unwrap()
        .work
    }

    /// Offline fake: reports `shares` candidates, then stays live until cancelled.
    struct RepeatingPoolSearch {
        shares: usize,
        starts: Arc<Mutex<Vec<(u64, u64)>>>,
        reported: Arc<AtomicUsize>,
    }

    impl PoolSearch for RepeatingPoolSearch {
        #[expect(
            clippy::too_many_arguments,
            reason = "Matches the explicit worker search boundary"
        )]
        fn search(
            &self,
            _work: &Work,
            prefix: [u8; 24],
            start: u64,
            end: u64,
            _target: [u8; 32],
            cancel: &AtomicBool,
            share: &mut dyn FnMut([u8; 32]) -> bool,
        ) -> Result<(), cpu::Error> {
            self.starts.lock().unwrap().push((start, end));
            for offset in 0..self.shares {
                if cancel.load(Ordering::Acquire) {
                    return Ok(());
                }
                let mut nonce = [0u8; 32];
                nonce[..8].copy_from_slice(&start.saturating_add(offset as u64).to_le_bytes());
                nonce[8..].copy_from_slice(&prefix);
                if !share(nonce) {
                    return Ok(());
                }
                self.reported.fetch_add(1, Ordering::Release);
            }
            while !cancel.load(Ordering::Acquire) {
                thread::sleep(Duration::from_millis(1));
            }
            Ok(())
        }
    }

    #[test]
    fn pool_workers_keep_searching_after_candidates_and_report_live_count() {
        let (_dir, mut node) = crate::tests::node();
        let work = Arc::new(prepared_work(&mut node));
        let starts = Arc::new(Mutex::new(Vec::new()));
        let mut operator = PoolOperator::new(pool_config(2)).unwrap();
        operator.backend = Arc::new(RepeatingPoolSearch {
            shares: 2,
            starts: starts.clone(),
            reported: Arc::new(AtomicUsize::new(0)),
        });
        operator.assignment = Some([4; 32]);
        operator.job = Some(work.clone());
        operator
            .start_workers(100, 199, [7; 24], [255; 32])
            .unwrap();

        let mut received = Vec::new();
        for _ in 0..2_000 {
            for worker in &mut operator.workers {
                if let Ok(share) = worker.shares.try_recv() {
                    received.push(share);
                }
            }
            if received.len() >= 4 {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(received.len(), 4);
        assert!(
            received
                .iter()
                .all(|share| share.assignment == [4; 32] && share.job == work.id())
        );
        assert_eq!(operator.active_workers(), 2);
        assert!(
            operator
                .workers
                .iter()
                .all(|worker| !worker.handle.is_finished()),
            "a share candidate must not retire its worker"
        );
        let mut starts = starts.lock().unwrap().clone();
        starts.sort_unstable();
        assert_eq!(starts, vec![(100, 149), (150, 199)]);
        operator.shutdown();
        assert_eq!(operator.active_workers(), 0);
    }

    #[test]
    fn full_pool_queue_is_bounded_and_shutdown_still_joins() {
        let (_dir, mut node) = crate::tests::node();
        let work = Arc::new(prepared_work(&mut node));
        let starts = Arc::new(Mutex::new(Vec::new()));
        let reported = Arc::new(AtomicUsize::new(0));
        let mut operator = PoolOperator::new(pool_config(1)).unwrap();
        operator.backend = Arc::new(RepeatingPoolSearch {
            shares: 2,
            starts: starts.clone(),
            reported: reported.clone(),
        });
        operator.assignment = Some([5; 32]);
        operator.job = Some(work);
        operator
            .start_workers(0, 999, [8; 24], [255; 32])
            .unwrap();

        // Consume the first candidate so the second fills the only queue slot.
        wait_for(|| operator.workers[0].shares.try_recv().is_ok());
        wait_for(|| reported.load(Ordering::Acquire) >= 2);
        assert_eq!(operator.workers.len(), 1);
        // The queue is full; cancellation must drop the receiver to unblock and
        // join the worker instead of hanging forever.
        operator.shutdown();
        assert_eq!(operator.active_workers(), 0);
    }

    /// Offline fake: reports exactly one candidate and exits normally.
    struct ExitingPoolSearch;

    impl PoolSearch for ExitingPoolSearch {
        #[expect(
            clippy::too_many_arguments,
            reason = "Matches the explicit worker search boundary"
        )]
        fn search(
            &self,
            _work: &Work,
            prefix: [u8; 24],
            start: u64,
            _end: u64,
            _target: [u8; 32],
            _cancel: &AtomicBool,
            share: &mut dyn FnMut([u8; 32]) -> bool,
        ) -> Result<(), cpu::Error> {
            let mut nonce = [0u8; 32];
            nonce[..8].copy_from_slice(&start.to_le_bytes());
            nonce[8..].copy_from_slice(&prefix);
            let _ = share(nonce);
            Ok(())
        }
    }

    #[test]
    fn final_share_is_not_lost_when_a_worker_exits() {
        let (_dir, mut node) = crate::tests::node();
        let work = Arc::new(prepared_work(&mut node));
        let worker = spawn_pool_worker(
            0,
            work,
            [9; 32],
            [3; 24],
            42,
            42,
            [255; 32],
            Arc::new(ExitingPoolSearch),
        )
        .unwrap();
        wait_for(|| worker.handle.is_finished());
        let share = worker.shares.try_recv().unwrap();
        assert_eq!(
            u64::from_le_bytes(share.nonce[..8].try_into().unwrap()),
            42
        );
        assert_eq!(&share.nonce[8..], &[3; 24]);
        assert_eq!(share.assignment, [9; 32]);
        assert!(matches!(
            worker.shares.try_recv(),
            Err(TryRecvError::Disconnected)
        ));
        assert!(matches!(worker.outcome.try_recv(), Ok(PoolEvent::Exhausted)));

        let mut operator = PoolOperator::new(pool_config(1)).unwrap();
        operator.workers.push(worker);
        operator.stop_workers();
        assert_eq!(operator.active_workers(), 0);
    }

    #[test]
    fn pool_submit_dispositions_separate_retry_stale_and_fatal() {
        assert_eq!(
            classify_submit(Ok(())).unwrap(),
            SubmitDisposition::Submitted
        );
        assert_eq!(
            classify_submit(Err(PoolTransportError::Session(SessionError::Quota))).unwrap(),
            SubmitDisposition::Retry
        );
        assert_eq!(
            classify_submit(Err(PoolTransportError::Link(LinkError::Wire(
                WireError::Oversized
            ))))
            .unwrap(),
            SubmitDisposition::Retry
        );
        assert_eq!(
            classify_submit(Err(PoolTransportError::Session(
                SessionError::Assignment
            )))
            .unwrap(),
            SubmitDisposition::Stale
        );
        assert!(matches!(
            classify_submit(Err(PoolTransportError::Io)),
            Err(PoolTransportError::Io)
        ));
        assert!(matches!(
            classify_submit(Err(PoolTransportError::Session(SessionError::Closed))),
            Err(PoolTransportError::Session(SessionError::Closed))
        ));
        assert!(matches!(
            classify_submit(Err(PoolTransportError::Link(LinkError::Closed))),
            Err(PoolTransportError::Link(LinkError::Closed))
        ));
    }
}
