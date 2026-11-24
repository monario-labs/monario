//! Explicitly activated operator loop over `refresh::Manager` and `cpu::Miner`.
//! Construction starts no thread, search or transport. The caller drives `tick`
//! (from the existing node loop) or `run` (local-only loop).
use super::{
    Clock, Error as MiningError, Node, Submitted, Work, cpu, pool::session::Event as SessionEvent,
    pool::session::Limits as SessionLimits, pool::tcp::ClientConfig, pool::tcp::TcpClient, refresh,
};
use crate::transport::Identity;
use monario_address::{Address, Network, Receiver};
use monario_chain::Hash;
use std::{
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

/// Process-wide worker bound. Workers share a single 256 MiB RandomX cache.
pub use monario_randomx::MAX_WORKERS;
/// Published default for the official pool. Provisional: it is a name default,
/// authenticated by the configured pool key. It is not an implicit trust anchor
/// and this constant asserts no live service.
pub const OFFICIAL_POOL_ADDRESS: &str = "pool.monario.org:19444";
const MIN_POLL_MS: u64 = 10;
const MAX_POLL_MS: u64 = 60_000;
const MAX_TIMESTAMP_SECONDS: u32 = 3_600;
const MAX_ADDRESS_BYTES: usize = 128;
/// Coinbase extra data is public; the consensus encoder accepts at most 98 bytes.
const MAX_EXTRA_DATA: usize = 98;

#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub network: Network,
    /// Inclusive 1..=MAX_WORKERS. Workers share one RandomX cache.
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
        let seed = work.seed();
        let cache = {
            let mut slot = self.cache.lock().map_err(|_| cpu::Error::CacheUnavailable)?;
            let current = slot
                .as_ref()
                .map(|cache| cache.seed() == seed)
                .unwrap_or(false);
            if !current {
                *slot = None;
                *slot =
                    Some(monario_randomx::SharedCache::new(&seed).map_err(cpu::Error::Hash)?);
            }
            slot.clone().ok_or(cpu::Error::CacheUnavailable)?
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

impl Operator {
    /// Validates configuration and payout destination; opens no thread or network.
    pub fn new(config: Config, address: String, extra_data: Vec<u8>) -> Result<Self, Error> {
        if config.workers == 0
            || config.workers > MAX_WORKERS
            || !(MIN_POLL_MS..=MAX_POLL_MS).contains(&config.poll_ms)
            || config.timestamp_seconds == 0
            || config.timestamp_seconds > MAX_TIMESTAMP_SECONDS
            || address.is_empty()
            || address.len() > MAX_ADDRESS_BYTES
            || extra_data.len() > MAX_EXTRA_DATA
        {
            return Err(Error::Configuration);
        }
        match Address::decode(&address, config.network)
            .map_err(|_| Error::Configuration)?
            .receiver()
        {
            Receiver::Transparent(_) => {}
            Receiver::Private(_) => return Err(Error::Configuration),
        }
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
            for _ in 0..=usize::from(MAX_WORKERS) {
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
/// Implementations must return `Ok(None)` when cancelled and must never submit.
trait PoolSearch: Send + Sync {
    fn search(
        &self,
        work: &Work,
        prefix: [u8; 24],
        start: u64,
        end: u64,
        target: [u8; 32],
        cancel: &AtomicBool,
    ) -> Result<Option<[u8; 32]>, cpu::Error>;
}

impl PoolSearch for CpuSearch {
    fn search(
        &self,
        work: &Work,
        prefix: [u8; 24],
        start: u64,
        end: u64,
        target: [u8; 32],
        cancel: &AtomicBool,
    ) -> Result<Option<[u8; 32]>, cpu::Error> {
        if cancel.load(Ordering::Acquire) {
            return Ok(None);
        }
        let mut miner = cpu::Miner::with_pool_verifier(
            work,
            start,
            end,
            prefix,
            target,
            self.verifier(work)?,
        )?;
        loop {
            match miner.search_batch(cpu::MAX_BATCH, cancel)? {
                cpu::Batch::Found(solution) => return Ok(Some(solution.nonce)),
                cpu::Batch::Pending => {}
                cpu::Batch::Cancelled => return Ok(None),
                // An exhausted assigned partition is not an error; wait for a new job.
                cpu::Batch::Exhausted => return Ok(None),
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
    /// Inclusive 1..=MAX_WORKERS. Workers share one 256 MiB RandomX cache.
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
    pub connected: bool,
    pub assigned: bool,
    pub workers: usize,
    pub submitted: u64,
    pub block_candidates: u64,
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
    workers: Vec<Worker>,
    events: Option<WorkReceiver<Result<Option<[u8; 32]>, cpu::Error>>>,
    backend: Arc<dyn PoolSearch>,
    submitted: u64,
    block_candidates: u64,
    last_poll: Option<u64>,
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
            events: None,
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
            let events = self.client.tick(node, clock).map_err(Error::Pool)?;
            for event in events {
                if let SessionEvent::Accepted {
                    block_candidate: true,
                    ..
                } = event
                {
                    self.block_candidates = self.block_candidates.saturating_add(1);
                }
            }
            self.refresh_assignment()?;
        }
        self.collect(clock)?;
        Ok(PoolStatus {
            connected: self.client.is_connected(),
            assigned: self.assignment.is_some(),
            workers: self.workers.len(),
            submitted: self.submitted,
            block_candidates: self.block_candidates,
        })
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
                if self.assignment.is_some() || !self.workers.is_empty() {
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
        if !self.workers.is_empty() {
            return Err(Error::Configuration);
        }
        let (sender, receiver) = mpsc::channel();
        let mut workers: Vec<Worker> = Vec::new();
        for index in 0..self.workers_limit {
            let (lo, hi) = partition_range(start, end, index, self.workers_limit);
            if lo > hi {
                continue;
            }
            let cancel = Arc::new(AtomicBool::new(false));
            let signal = cancel.clone();
            let job = work.clone();
            let events = sender.clone();
            let backend = self.backend.clone();
            let handle = match thread::Builder::new()
                .name(format!("monar-pool-miner-{index}"))
                .spawn(move || {
                    let event = backend.search(&job, prefix, lo, hi, target, &signal);
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

    fn collect(&mut self, clock: Clock) -> Result<(), Error> {
        let mut events = Vec::new();
        if let Some(receiver) = &self.events {
            for _ in 0..=usize::from(MAX_WORKERS) {
                match receiver.try_recv() {
                    Ok(event) => events.push(event),
                    Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
                }
            }
        }
        for event in events {
            match event {
                Ok(Some(nonce)) => {
                    if self.client.submit(nonce, clock).is_ok() {
                        self.submitted = self.submitted.saturating_add(1);
                    } else {
                        // A rejected assignment (stale or replaced) cancels search.
                        self.stop_workers();
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    self.stop_workers();
                    return Err(Error::Worker(error));
                }
            }
        }
        Ok(())
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

    /// Cancel and join every worker, close the session; safe to call repeatedly.
    pub fn shutdown(&mut self) {
        self.stop_workers();
        self.client.close();
        self.assignment = None;
        self.job = None;
        self.last_poll = None;
    }

    pub fn active_workers(&self) -> usize {
        self.workers.len()
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
        let _serial = crate::tests::REAL.lock().unwrap();
        let (_dir, mut node) = crate::tests::node();
        let parents = Arc::new(Mutex::new(Vec::new()));
        let cancelled = Arc::new(AtomicUsize::new(0));
        let backend = Arc::new(Waiting {
            parents: parents.clone(),
            cancelled: cancelled.clone(),
        });
        let mut operator = Operator::with_backend(
            config(2),
            refresh::Manager::new(address(), Network::Regtest, vec![]),
            backend,
        );
        let first = operator.tick(&mut node, at(10)).unwrap();
        assert!(first.refreshed);
        wait_for(|| parents.lock().unwrap().len() >= 2);
        let old_tip = node.source().chain().unwrap().tip();
        let new_tip = crate::tests::append(&mut node, old_tip, vec![], 10);
        assert_ne!(old_tip, new_tip);
        let second = operator.tick(&mut node, at(20)).unwrap();
        assert!(second.refreshed);
        assert_eq!(cancelled.load(Ordering::Acquire), 2);
        wait_for(|| parents.lock().unwrap().len() >= 4);
        let seen = parents.lock().unwrap().clone();
        assert_eq!(&seen[..2], &[old_tip, old_tip]);
        assert_eq!(&seen[2..], &[new_tip, new_tip]);
        assert_eq!(operator.active_workers(), 2);
        operator.shutdown();
        assert_eq!(cancelled.load(Ordering::Acquire), 4);
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
}
