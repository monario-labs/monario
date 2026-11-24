//! Authenticated pool session state machines. Messages are framed by `wire` and
//! must be carried inside an encrypted, key-pinned `SecureStream`; this module
//! never opens a socket. A server instance owns one client session; a real pool
//! creates one instance per authenticated connection.
use super::{Error as PoolError, Policy, Share, ledger, wire};
use crate::mining::cpu;
use crate::mining::{Error as MiningError, Work};
use crate::{Clock, Node};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
};
use zeroize::{Zeroize, Zeroizing};

pub const MAX_CLIENTS: usize = 1_024;

/// Trusted server-side client policy. Tokens are transport secrets, are compared
/// in constant time and are zeroized on drop. No `Debug` implementation exists.
pub struct ClientPolicy {
    client: [u8; 16],
    token: Zeroizing<[u8; 32]>,
    prefix: [u8; 24],
    start: u64,
    end: u64,
    share_target: [u8; 32],
}

impl ClientPolicy {
    pub fn new(
        client: [u8; 16],
        token: [u8; 32],
        prefix: [u8; 24],
        start: u64,
        end: u64,
        share_target: [u8; 32],
    ) -> Result<Self, Error> {
        if client == [0; 16] || token == [0; 32] || start > end {
            return Err(Error::Configuration);
        }
        Ok(Self {
            client,
            token: Zeroizing::new(token),
            prefix,
            start,
            end,
            share_target,
        })
    }

    pub fn client(&self) -> [u8; 16] {
        self.client
    }

    pub fn prefix(&self) -> [u8; 24] {
        self.prefix
    }

    pub fn start(&self) -> u64 {
        self.start
    }

    pub fn end(&self) -> u64 {
        self.end
    }

    pub fn share_target(&self) -> [u8; 32] {
        self.share_target
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub window_ms: u64,
    pub messages: u32,
    pub bytes: usize,
    pub submits: u32,
    pub auth_failures: u32,
    pub job_ttl_ms: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            window_ms: 10_000,
            messages: 128,
            bytes: 8 * 1024 * 1024,
            submits: 256,
            auth_failures: 8,
            job_ttl_ms: 60_000,
        }
    }
}

impl Limits {
    fn valid(self) -> bool {
        (1..=600_000).contains(&self.window_ms)
            && (1..=4_096).contains(&self.messages)
            && (1..=64 * 1024 * 1024).contains(&self.bytes)
            && (1..=4_096).contains(&self.submits)
            && (1..=1_024).contains(&self.auth_failures)
            && (1..=600_000).contains(&self.job_ttl_ms)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Configuration,
    Clock,
    Closed,
    Quota,
    Assignment,
    Pool(PoolError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    Authenticated,
    Assigned,
    Accepted { units: u64, block_candidate: bool },
    Rejected { code: u8 },
    Closed,
}

/// Blocking verification boundary. The production implementation uses an
/// independent RandomX VM and the durable ledger; tests inject a fixed digest.
pub trait Checker {
    /// Cheap tip/assignment checks, a pre-hash durable duplicate lookup, and an
    /// independent hash/target check. Crediting is a separate authoritative call.
    fn check(
        &mut self,
        node: &Node,
        solution: &cpu::Solution,
        ledger: &ledger::Ledger,
    ) -> Result<Share, PoolError>;
}

pub struct RandomXChecker {
    verifier: super::Verifier,
}

impl RandomXChecker {
    pub fn new(
        work: &Work,
        client: &ClientPolicy,
        mode: monario_randomx::Mode,
        cache: monario_randomx::SharedCache,
    ) -> Result<Self, PoolError> {
        if cache.seed() != work.seed().as_slice() {
            return Err(PoolError::Hash(monario_randomx::Error::InvalidSeed));
        }
        let verifier = cache.verifier(mode).map_err(PoolError::Hash)?;
        // The cache and the VM must both report the seed this job was built for.
        if verifier.seed() != work.seed().as_slice() {
            return Err(PoolError::Hash(monario_randomx::Error::InvalidSeed));
        }
        Ok(Self {
            verifier: super::Verifier::new_with_verifier(
                work,
                client.prefix,
                client.start,
                client.end,
                client.share_target,
                verifier,
            )?,
        })
    }
}

impl Checker for RandomXChecker {
    fn check(
        &mut self,
        node: &Node,
        solution: &cpu::Solution,
        ledger: &ledger::Ledger,
    ) -> Result<Share, PoolError> {
        self.verifier.verify_share_durable(node, solution, ledger)
    }
}

pub trait CheckerFactory {
    fn create(&self, work: &Work, client: &ClientPolicy) -> Result<Box<dyn Checker>, PoolError>;
}

/// One immutable initialized cache per active seed. A seed change drops the
/// previous registry reference; checkers that still own a clone keep their VM
/// valid until the old assignment is retired.
struct SeedSlot<C> {
    active: Mutex<Option<(Vec<u8>, C)>>,
}

impl<C: Clone> SeedSlot<C> {
    fn new() -> Self {
        Self {
            active: Mutex::new(None),
        }
    }

    fn acquire(
        &self,
        seed: &[u8],
        create: impl FnOnce(&[u8]) -> Result<C, PoolError>,
    ) -> Result<C, PoolError> {
        let mut slot = self.active.lock().map_err(|_| PoolError::Storage)?;
        if let Some((held, cache)) = slot.as_ref()
            && held.as_slice() == seed
        {
            return Ok(cache.clone());
        }
        *slot = None;
        let cache = create(seed)?;
        *slot = Some((seed.to_vec(), cache.clone()));
        Ok(cache)
    }
}

pub struct RandomXFactory {
    pub mode: monario_randomx::Mode,
    cache: SeedSlot<monario_randomx::SharedCache>,
}

impl RandomXFactory {
    pub fn new(mode: monario_randomx::Mode) -> Self {
        Self {
            mode,
            cache: SeedSlot::new(),
        }
    }
}

impl CheckerFactory for RandomXFactory {
    fn create(&self, work: &Work, client: &ClientPolicy) -> Result<Box<dyn Checker>, PoolError> {
        let cache = self.cache.acquire(&work.seed(), |seed| {
            monario_randomx::SharedCache::new(seed).map_err(PoolError::Hash)
        })?;
        Ok(Box::new(RandomXChecker::new(
            work, client, self.mode, cache,
        )?))
    }
}

#[derive(Clone, Copy)]
struct Assignment {
    id: [u8; 32],
    job: [u8; 32],
    expires_ms: u64,
}

struct Quota {
    window: u64,
    messages: u32,
    bytes: usize,
    submits: u32,
}

impl Quota {
    fn new() -> Self {
        Self {
            window: 0,
            messages: 0,
            bytes: 0,
            submits: 0,
        }
    }

    fn admit(&mut self, now: u64, bytes: usize, submit: bool, limits: Limits) -> Result<(), Error> {
        if bytes > wire::MAX_BUFFER {
            return Err(Error::Quota);
        }
        if now.saturating_sub(self.window) >= limits.window_ms {
            self.window = now;
            self.messages = 0;
            self.bytes = 0;
            self.submits = 0;
        }
        let messages = self.messages.checked_add(1).ok_or(Error::Quota)?;
        let total_bytes = self.bytes.checked_add(bytes).ok_or(Error::Quota)?;
        let submits = if submit {
            self.submits.checked_add(1).ok_or(Error::Quota)?
        } else {
            self.submits
        };
        if messages > limits.messages || total_bytes > limits.bytes || submits > limits.submits {
            return Err(Error::Quota);
        }
        self.messages = messages;
        self.bytes = total_bytes;
        self.submits = submits;
        Ok(())
    }
}

pub struct Server {
    work: Work,
    policy: Policy,
    clients: Vec<Arc<ClientPolicy>>,
    factory: Arc<dyn CheckerFactory>,
    limits: Limits,
    session: Option<[u8; 16]>,
    client_index: Option<usize>,
    checker: Option<Box<dyn Checker>>,
    assignment: Option<Assignment>,
    epoch: u64,
    failures: u32,
    quota: Quota,
    last_ms: Option<u64>,
    closed: bool,
}

impl Server {
    pub fn new(
        work: &Work,
        policy: Policy,
        clients: Vec<ClientPolicy>,
        factory: Box<dyn CheckerFactory>,
        limits: Limits,
    ) -> Result<Self, Error> {
        Self::shared(
            work,
            policy,
            clients.into_iter().map(Arc::new).collect(),
            Arc::from(factory),
            limits,
        )
    }

    /// Multiple connections can share the same non-secret policy objects. Tokens
    /// remain owned by the caller's `Arc<ClientPolicy>` and are zeroized on drop.
    /// The checker factory is shared so one initialized RandomX cache serves every
    /// authenticated connection on the active seed.
    pub fn shared(
        work: &Work,
        policy: Policy,
        clients: Vec<Arc<ClientPolicy>>,
        factory: Arc<dyn CheckerFactory>,
        limits: Limits,
    ) -> Result<Self, Error> {
        if clients.is_empty() || clients.len() > MAX_CLIENTS || !limits.valid() {
            return Err(Error::Configuration);
        }
        if !partitions(clients.as_slice()) {
            return Err(Error::Configuration);
        }
        for client in &clients {
            super::Rules::new(
                work,
                client.prefix,
                client.start,
                client.end,
                client.share_target,
            )
            .map_err(Error::Pool)?;
        }
        policy.units(false).map_err(Error::Pool)?;
        policy.units(true).map_err(Error::Pool)?;
        Ok(Self {
            work: work.clone(),
            policy,
            clients,
            factory,
            limits,
            session: None,
            client_index: None,
            checker: None,
            assignment: None,
            epoch: 0,
            failures: 0,
            quota: Quota::new(),
            last_ms: None,
            closed: false,
        })
    }

    /// One bounded server step. Fatal clock/quota/closed errors are returned;
    /// authentication and share rejections are returned as `Rejected` messages.
    pub fn handle(
        &mut self,
        node: &mut Node,
        ledger: &mut ledger::Ledger,
        message: wire::Message,
        frame_bytes: usize,
        clock: Clock,
    ) -> Result<wire::Message, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        if self.last_ms.is_some_and(|last| clock.monotonic_ms < last) {
            return Err(Error::Clock);
        }
        self.last_ms = Some(clock.monotonic_ms);
        let submit = matches!(message, wire::Message::Submit { .. });
        self.quota
            .admit(clock.monotonic_ms, frame_bytes, submit, self.limits)?;
        match message {
            wire::Message::Auth { client, token } => self.authenticate(&client, &token, clock),
            wire::Message::Submit {
                assignment,
                job,
                nonce,
            } => self.submit(node, ledger, assignment, job, nonce, clock),
            _ => Ok(rejected(wire::INVALID)),
        }
    }

    fn authenticate(
        &mut self,
        client: &[u8; 16],
        token: &[u8; 32],
        clock: Clock,
    ) -> Result<wire::Message, Error> {
        if self.session.is_some() {
            return Ok(rejected(wire::INVALID));
        }
        let index = self.clients.iter().position(|p| equal(&p.client, client));
        let zero = Zeroizing::new([0u8; 32]);
        let expected = index.map_or(&*zero, |index| &*self.clients[index].token);
        let accepted = equal(expected, token) && index.is_some();
        if !accepted {
            self.failures = self.failures.saturating_add(1);
            if self.failures >= self.limits.auth_failures {
                self.closed = true;
            }
            return Ok(rejected(wire::UNAUTHORIZED));
        }
        let index = index.expect("authenticated client index");
        let session = session_id(self.work.id(), *client, self.epoch);
        self.session = Some(session);
        self.client_index = Some(index);
        self.checker = Some(
            self.factory
                .create(&self.work, &self.clients[index])
                .map_err(Error::Pool)?,
        );
        self.assignment = Some(self.assignment(index, clock.monotonic_ms));
        Ok(wire::Message::AuthOk { session })
    }

    fn submit(
        &mut self,
        node: &mut Node,
        ledger: &mut ledger::Ledger,
        assignment: [u8; 32],
        job: [u8; 32],
        nonce: [u8; 32],
        clock: Clock,
    ) -> Result<wire::Message, Error> {
        let (Some(_), Some(index)) = (self.session, self.client_index) else {
            return Ok(rejected(wire::UNAUTHENTICATED));
        };
        let Some(current) = self.assignment else {
            return Ok(rejected(wire::STALE));
        };
        if current.id != assignment || current.job != job {
            return Ok(rejected(wire::STALE));
        }
        if clock.monotonic_ms > current.expires_ms {
            // Keep the assignment so `apply_work` can rotate its ID and resend
            // the job. The client may already have discarded it after STALE.
            return Ok(rejected(wire::STALE));
        }
        let client = self.clients[index].client;
        let solution = cpu::Solution { job_id: job, nonce };
        let checker = self.checker.as_mut().ok_or(Error::Configuration)?;
        let share = match checker.check(node, &solution, ledger) {
            Ok(share) => share,
            Err(PoolError::Duplicate) => return Ok(rejected(wire::DUPLICATE)),
            Err(PoolError::Stale) => {
                self.assignment = None;
                return Ok(rejected(wire::STALE));
            }
            Err(PoolError::Assignment | PoolError::InvalidShare) => {
                return Ok(rejected(wire::INVALID));
            }
            Err(_) => return Ok(rejected(wire::BUSY)),
        };
        let units = self
            .policy
            .units(share.block_candidate)
            .map_err(Error::Pool)?;
        // A block candidate is journaled durably before the node call, then
        // finalized only from the node's verified durable block index. A crash
        // before acceptance leaves an unresolved row; a crash after acceptance
        // is reconciled idempotently.
        if share.block_candidate {
            let block_id = self
                .work
                .block_id(node.source(), nonce)
                .map_err(|_| Error::Pool(PoolError::Storage))?;
            let parent = self.work.parent();
            // Reserve the exact candidate and its credit before any chain
            // mutation. Capacity is refused here, before the node sees a block.
            let pending = match ledger.reserve(
                block_id,
                parent,
                &solution.job_id,
                &solution.nonce,
                client,
                units,
                true,
            ) {
                Ok(pending) => pending,
                Err(ledger::Error::Duplicate) => return Ok(rejected(wire::DUPLICATE)),
                Err(_) => return Ok(rejected(wire::BUSY)),
            };
            let result = node.submit_solution(&self.work, &solution, clock);
            match result {
                Ok(crate::mining::Submitted::Accepted(accepted)) if accepted.id == block_id => {}
                Ok(crate::mining::Submitted::AlreadyKnown(id)) if id == block_id => {}
                Ok(_) => {
                    // The node reported a different block; keep the reservation
                    // unresolved rather than crediting unproven work.
                    return Ok(rejected(wire::BUSY));
                }
                Err(cpu::Error::Submit(MiningError::Stale)) => {
                    if cancel_reservation(ledger, &block_id).is_err() {
                        return Ok(rejected(wire::BUSY));
                    }
                    self.assignment = None;
                    return Ok(rejected(wire::STALE));
                }
                Err(cpu::Error::Submit(
                    MiningError::Address | MiningError::Encoding | MiningError::Consensus(_),
                )) => {
                    if cancel_reservation(ledger, &block_id).is_err() {
                        return Ok(rejected(wire::BUSY));
                    }
                    return Ok(rejected(wire::INVALID));
                }
                Err(cpu::Error::Submit(MiningError::Node(
                    crate::Error::Protocol | crate::Error::Clock | crate::Error::Configuration,
                ))) => {
                    if cancel_reservation(ledger, &block_id).is_err() {
                        return Ok(rejected(wire::BUSY));
                    }
                    return Ok(rejected(wire::INVALID));
                }
                // I/O, storage, pruned, selection and unknown failures may hide a
                // committed block. Preserve the reservation for reconciliation.
                Err(_) => return Ok(rejected(wire::BUSY)),
            }
            let Some(acceptance) = confirmed_acceptance(node, &pending)? else {
                return Ok(rejected(wire::BUSY));
            };
            // The node has durably accepted this exact candidate. Retire the
            // solved assignment immediately, even if the separate credit still
            // needs runtime reconciliation.
            self.assignment = None;
            if ledger.finalize(&acceptance).is_err() {
                // The block is durable but the credit is not. Keep the journal row
                // for reconciliation and fail closed for this submission.
                return Ok(rejected(wire::BUSY));
            }
            return Ok(wire::Message::Accepted {
                units,
                block_candidate: true,
            });
        }
        match ledger.credit(
            &solution.job_id,
            &solution.nonce,
            client,
            units,
            share.block_candidate,
        ) {
            Ok(_) => {}
            Err(ledger::Error::Duplicate) => return Ok(rejected(wire::DUPLICATE)),
            Err(_) => return Ok(rejected(wire::BUSY)),
        }
        Ok(wire::Message::Accepted {
            units,
            block_candidate: share.block_candidate,
        })
    }

    fn assignment(&self, index: usize, now: u64) -> Assignment {
        let client = self.clients[index].client;
        Assignment {
            id: derive(
                b"Monario/pool-assignment/v1\0",
                &[&self.work.id(), &client, &self.epoch.to_le_bytes()],
            ),
            job: self.work.id(),
            expires_ms: now.saturating_add(self.limits.job_ttl_ms),
        }
    }

    /// The current job for the authenticated client, ignoring lease expiry.
    /// Diagnostics/tests only: the TCP driver uses [`Server::job_at`] so expired
    /// work is never sent.
    pub fn job(&self) -> Option<wire::Message> {
        self.job_message()
    }

    /// Current job only while its assignment is unexpired. An expired lease must
    /// be rotated by [`Server::apply_work`] before it is dispatched again.
    pub fn job_at(&self, now_ms: u64) -> Option<wire::Message> {
        let assignment = self.assignment?;
        if now_ms > assignment.expires_ms {
            return None;
        }
        self.job_message()
    }

    fn job_message(&self) -> Option<wire::Message> {
        let index = self.client_index?;
        let assignment = self.assignment?;
        let client = &self.clients[index];
        Some(wire::Message::Job {
            assignment: assignment.id,
            parent: self.work.parent(),
            job: assignment.job,
            prefix: client.prefix,
            start: client.start,
            end: client.end,
            target: client.share_target,
            packet: self.work.encode().to_vec(),
        })
    }

    /// Reconcile one validated refresh with this connection. An unchanged, live
    /// job keeps its work and assignment IDs and its checker. An expired
    /// assignment is rotated to a fresh ID and must be redispatched, but it
    /// reuses the checker and its initialized cache. A retired assignment (for
    /// example after an accepted candidate) is never revived for the same work.
    /// A genuinely different job retires the old assignment and builds a fresh
    /// checker. Returns `true` only when the peer needs a new job message.
    pub fn apply_work(&mut self, work: &Work, now_ms: u64) -> Result<bool, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        if work.id() != self.work.id() {
            self.replace_work(work, now_ms)?;
            return Ok(true);
        }
        let Some(index) = self.client_index else {
            return Ok(false);
        };
        let Some(assignment) = self.assignment else {
            // Solved and retired: same-work refresh must not resurrect it.
            return Ok(false);
        };
        if now_ms < assignment.expires_ms {
            return Ok(false);
        }
        // Expired outstanding lease: rotate the assignment ID so a client that
        // discarded it after STALE can accept the resent job, but keep the
        // checker and its cache because the work itself is unchanged.
        self.epoch = self.epoch.checked_add(1).ok_or(Error::Configuration)?;
        self.session = Some(session_id(
            self.work.id(),
            self.clients[index].client,
            self.epoch,
        ));
        self.assignment = Some(self.assignment(index, now_ms));
        Ok(true)
    }

    /// Replace the validated work on a tip/mempool change. The old assignment is
    /// retired; an authenticated client receives a new assignment on `job()`.
    pub fn replace_work(&mut self, work: &Work, now_ms: u64) -> Result<(), Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        for client in &self.clients {
            super::Rules::new(
                work,
                client.prefix,
                client.start,
                client.end,
                client.share_target,
            )
            .map_err(Error::Pool)?;
        }
        self.checker = None;
        self.assignment = None;
        self.work = work.clone();
        self.epoch = self.epoch.checked_add(1).ok_or(Error::Configuration)?;
        if let (Some(session), Some(index)) = (self.session, self.client_index) {
            self.session = Some(session_id(
                work.id(),
                self.clients[index].client,
                self.epoch,
            ));
            self.checker = Some(
                self.factory
                    .create(&self.work, &self.clients[index])
                    .map_err(Error::Pool)?,
            );
            self.assignment = Some(self.assignment(index, now_ms));
            let _ = session;
        }
        Ok(())
    }

    pub fn is_authenticated(&self) -> bool {
        self.session.is_some()
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Drop session state and zeroize the in-memory client tokens.
    pub fn close(&mut self) {
        self.closed = true;
        self.session = None;
        self.client_index = None;
        self.checker = None;
        self.assignment = None;
        self.clients.clear();
    }
}

pub struct Client {
    client: [u8; 16],
    token: Zeroizing<[u8; 32]>,
    limits: Limits,
    session: Option<[u8; 16]>,
    assignment: Option<ClientAssignment>,
    work: Option<Work>,
    quota: Quota,
    last_ms: Option<u64>,
    closed: bool,
    /// Set only by a server credential rejection before any session existed. A
    /// later job/share rejection never marks the credential invalid.
    auth_rejected: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientAssignment {
    pub id: [u8; 32],
    pub job: [u8; 32],
    pub prefix: [u8; 24],
    pub start: u64,
    pub end: u64,
    pub target: [u8; 32],
}

impl Client {
    pub fn new(client: [u8; 16], token: [u8; 32], limits: Limits) -> Result<Self, Error> {
        if client == [0; 16] || token == [0; 32] || !limits.valid() {
            return Err(Error::Configuration);
        }
        Ok(Self {
            client,
            token: Zeroizing::new(token),
            limits,
            session: None,
            assignment: None,
            work: None,
            quota: Quota::new(),
            last_ms: None,
            closed: false,
            auth_rejected: false,
        })
    }

    pub fn auth_message(&self) -> wire::Message {
        wire::Message::Auth {
            client: self.client,
            token: *self.token,
        }
    }

    pub fn handle(
        &mut self,
        node: &Node,
        message: wire::Message,
        frame_bytes: usize,
        clock: Clock,
    ) -> Result<Event, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        if self.last_ms.is_some_and(|last| clock.monotonic_ms < last) {
            return Err(Error::Clock);
        }
        self.last_ms = Some(clock.monotonic_ms);
        self.quota
            .admit(clock.monotonic_ms, frame_bytes, false, self.limits)?;
        match message {
            wire::Message::AuthOk { session } => {
                if self.session.is_some() {
                    return Ok(rejected_event(wire::INVALID));
                }
                self.session = Some(session);
                Ok(Event::Authenticated)
            }
            wire::Message::Job {
                assignment,
                parent,
                job,
                prefix,
                start,
                end,
                target,
                packet,
            } => self.assign(
                node,
                assignment,
                parent,
                job,
                prefix,
                start,
                end,
                target,
                packet,
                clock.unix_seconds,
            ),
            wire::Message::Accepted {
                units,
                block_candidate,
            } => {
                if self.session.is_none() {
                    return Ok(rejected_event(wire::UNAUTHENTICATED));
                }
                if block_candidate {
                    self.assignment = None;
                    self.work = None;
                }
                Ok(Event::Accepted {
                    units,
                    block_candidate,
                })
            }
            wire::Message::Rejected { code } => {
                if matches!(code, wire::STALE | wire::UNAUTHORIZED) {
                    self.assignment = None;
                    self.work = None;
                }
                // Only a rejection that arrives while no session exists can be a
                // credential rejection; later share/job codes must not reset it.
                if code == wire::UNAUTHORIZED && self.session.is_none() {
                    self.auth_rejected = true;
                }
                Ok(Event::Rejected { code })
            }
            wire::Message::Error { .. } => {
                self.close();
                Ok(Event::Closed)
            }
            _ => Ok(rejected_event(wire::INVALID)),
        }
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Exact decoded job fields from one bounded message"
    )]
    fn assign(
        &mut self,
        node: &Node,
        assignment: [u8; 32],
        parent: [u8; 32],
        job: [u8; 32],
        prefix: [u8; 24],
        start: u64,
        end: u64,
        target: [u8; 32],
        packet: Vec<u8>,
        now_unix: u64,
    ) -> Result<Event, Error> {
        if self.session.is_none() {
            return Ok(rejected_event(wire::INVALID));
        }
        let work = match Work::decode(node.source(), &packet, now_unix) {
            Ok(work) => work,
            Err(_) => return Ok(rejected_event(wire::INVALID)),
        };
        if work.id() != job || work.parent() != parent {
            return Ok(rejected_event(wire::INVALID));
        }
        if super::Rules::new(&work, prefix, start, end, target).is_err() {
            return Ok(rejected_event(wire::INVALID));
        }
        self.assignment = Some(ClientAssignment {
            id: assignment,
            job,
            prefix,
            start,
            end,
            target,
        });
        self.work = Some(work);
        Ok(Event::Assigned)
    }

    /// Build a share submission for an assigned nonce. The server independently
    /// checks the job, partition, target and durable replay state.
    pub fn submit(&mut self, nonce: [u8; 32], clock: Clock) -> Result<wire::Message, Error> {
        let session = self.session.ok_or(Error::Assignment)?;
        let assignment = self.assignment.ok_or(Error::Assignment)?;
        let value = u64::from_le_bytes(nonce[..8].try_into().expect("fixed nonce"));
        if nonce[8..] != assignment.prefix || value < assignment.start || value > assignment.end {
            return Err(Error::Assignment);
        }
        self.quota
            .admit(clock.monotonic_ms, wire::HEADER + 96, true, self.limits)?;
        let _ = session;
        Ok(wire::Message::Submit {
            assignment: assignment.id,
            job: assignment.job,
            nonce,
        })
    }

    pub fn work(&self) -> Option<&Work> {
        self.work.as_ref()
    }

    pub fn assignment(&self) -> Option<&ClientAssignment> {
        self.assignment.as_ref()
    }

    pub fn session(&self) -> Option<[u8; 16]> {
        self.session
    }

    pub fn is_authenticated(&self) -> bool {
        self.session.is_some()
    }

    /// The server explicitly rejected this client credential.
    pub fn auth_rejected(&self) -> bool {
        self.auth_rejected
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    pub fn close(&mut self) {
        self.closed = true;
        self.session = None;
        self.assignment = None;
        self.work = None;
        self.token.zeroize();
    }
}

fn partitions(clients: &[Arc<ClientPolicy>]) -> bool {
    let mut ids = BTreeSet::new();
    for (index, client) in clients.iter().enumerate() {
        if !ids.insert(client.client) {
            return false;
        }
        for other in &clients[..index] {
            if client.prefix == other.prefix
                && !(client.end < other.start || other.end < client.start)
            {
                return false;
            }
        }
    }
    true
}

fn equal<const N: usize>(left: &[u8; N], right: &[u8; N]) -> bool {
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        difference |= a ^ b;
    }
    difference == 0 && left.len() == right.len()
}

fn session_id(job: [u8; 32], client: [u8; 16], epoch: u64) -> [u8; 16] {
    let digest = derive(
        b"Monario/pool-session/v1\0",
        &[&job, &client, &epoch.to_le_bytes()],
    );
    let mut session = [0u8; 16];
    session.copy_from_slice(&digest[..16]);
    session
}

fn derive(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    for part in parts {
        digest.update((part.len() as u64).to_le_bytes());
        digest.update(part);
    }
    digest.finalize().into()
}

fn rejected(code: u8) -> wire::Message {
    wire::Message::Rejected { code }
}

fn rejected_event(code: u8) -> Event {
    Event::Rejected { code }
}

/// A definite rejection may drop its journal row. Missing means there is nothing
/// left to cancel; any other failure stays unresolved and fails closed upstream.
fn cancel_reservation(
    ledger: &mut ledger::Ledger,
    block: &[u8; 32],
) -> Result<(), ledger::Error> {
    match ledger.cancel(block) {
        Ok(()) | Err(ledger::Error::Missing) => Ok(()),
        Err(error) => Err(error),
    }
}

/// Accept a candidate only from the node's durable block index: exact ID, exact
/// parent and the parent's contextual height plus one. No proof returns `None`
/// and must leave the reservation unresolved and uncredited.
fn confirmed_acceptance(
    node: &Node,
    pending: &ledger::Pending,
) -> Result<Option<ledger::Acceptance>, Error> {
    let Some(info) = node
        .source()
        .block_info(&pending.block)
        .map_err(|_| Error::Pool(PoolError::Storage))?
    else {
        return Ok(None);
    };
    if info.parent != Some(pending.parent) {
        return Ok(None);
    }
    let Some(parent) = node
        .source()
        .block_info(&pending.parent)
        .map_err(|_| Error::Pool(PoolError::Storage))?
    else {
        return Ok(None);
    };
    let Some(height) = parent.height.checked_add(1) else {
        return Ok(None);
    };
    if info.height != height {
        return Ok(None);
    }
    Ok(Some(ledger::Acceptance {
        block: pending.block,
        parent: pending.parent,
        height,
        commitment: info.commitment,
    }))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reconciliation {
    pub finalized: usize,
    pub remaining: usize,
}

/// Reconcile every unresolved block-candidate reservation against the durable
/// node block index before a pool accepts connections. Each exact, contextually
/// valid acceptance is finalized idempotently. Any finalize failure fails closed
/// so startup cannot silently drop or double-credit reserved work.
pub fn reconcile_pending(
    node: &Node,
    ledger: &mut ledger::Ledger,
) -> Result<Reconciliation, Error> {
    let pending = ledger
        .pending()
        .map_err(|error| Error::Pool(PoolError::Ledger(error)))?;
    let total = pending.len();
    let mut finalized = 0usize;
    for entry in pending {
        let Some(acceptance) = confirmed_acceptance(node, &entry)? else {
            continue;
        };
        ledger
            .finalize(&acceptance)
            .map_err(|error| Error::Pool(PoolError::Ledger(error)))?;
        finalized += 1;
    }
    Ok(Reconciliation {
        finalized,
        remaining: total - finalized,
    })
}

/// Fixed-digest checker for tests. It still applies the real partition, target,
/// tip and durable-ledger checks; only RandomX hashing is replaced.
#[cfg(test)]
struct FixedChecker {
    rules: super::Rules,
    digest: [u8; 32],
}

#[cfg(test)]
impl Checker for FixedChecker {
    fn check(
        &mut self,
        node: &Node,
        solution: &cpu::Solution,
        ledger: &ledger::Ledger,
    ) -> Result<Share, PoolError> {
        super::durable_check(&self.rules, node, solution, ledger, |_| Ok(self.digest))
    }
}

#[cfg(test)]
struct FixedFactory {
    digest: [u8; 32],
}

#[cfg(test)]
impl CheckerFactory for FixedFactory {
    fn create(&self, work: &Work, client: &ClientPolicy) -> Result<Box<dyn Checker>, PoolError> {
        Ok(Box::new(FixedChecker {
            rules: super::Rules::new(
                work,
                client.prefix,
                client.start,
                client.end,
                client.share_target,
            )?,
            digest: self.digest,
        }))
    }
}

#[cfg(test)]
struct CountingFactory {
    digest: [u8; 32],
    creates: Arc<std::sync::atomic::AtomicUsize>,
}

#[cfg(test)]
impl CheckerFactory for CountingFactory {
    fn create(&self, work: &Work, client: &ClientPolicy) -> Result<Box<dyn Checker>, PoolError> {
        self.creates
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        FixedFactory { digest: self.digest }.create(work, client)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{REAL, append, clock, node, private_tempdir, root};
    use monario_address::{Address, Network, Receiver, TransparentReceiver};

    fn limits() -> Limits {
        Limits {
            messages: 8,
            ..Limits::default()
        }
    }

    fn ledger_limits() -> ledger::Limits {
        ledger::Limits {
            max_shares: 64,
            max_clients: 8,
            max_units_per_share: 100,
            max_units_per_client: 10_000,
        }
    }

    fn policy() -> Policy {
        Policy {
            units_per_share: 1,
            units_per_block_candidate: 4,
        }
    }

    fn address() -> String {
        Address::new(
            Network::Regtest,
            Receiver::Transparent(TransparentReceiver::PublicKeyHash([7; 20])),
        )
        .encode()
    }

    fn prepare(n: &mut Node, timestamp: u32) -> Work {
        prepare_at(n, timestamp, 0)
    }

    fn prepare_at(n: &mut Node, timestamp: u32, ms: u64) -> Work {
        n.prepare_work(
            crate::mining::Request {
                address: &address(),
                network: Network::Regtest,
                timestamp: u64::from(timestamp),
                extra_data: b"",
            },
            clock(ms),
        )
        .unwrap()
        .work
    }

    fn setup(n: &mut Node, timestamp: u32) -> (Work, ClientPolicy) {
        let work = prepare(n, timestamp);
        let client = ClientPolicy::new([7; 16], [9; 32], [3; 24], 1, 4, work.target_le()).unwrap();
        (work, client)
    }

    fn frame(message: &wire::Message) -> (wire::Message, usize) {
        (message.clone(), wire::encode(message).unwrap().len())
    }

    #[test]
    fn seed_slot_reuses_one_allocation_per_seed_and_keeps_old_clone() {
        let slot: SeedSlot<Arc<u8>> = SeedSlot::new();
        let creates = std::sync::atomic::AtomicUsize::new(0);
        let acquire = |seed: &[u8]| {
            slot.acquire(seed, |_| {
                let allocation =
                    creates.fetch_add(1, std::sync::atomic::Ordering::SeqCst) as u8;
                Ok::<_, PoolError>(Arc::new(allocation))
            })
        };
        let first = acquire(b"first").unwrap();
        let same = acquire(b"first").unwrap();
        assert!(Arc::ptr_eq(&first, &same));
        assert_eq!(creates.load(std::sync::atomic::Ordering::SeqCst), 1);
        let second = acquire(b"second").unwrap();
        assert_eq!(creates.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert!(!Arc::ptr_eq(&first, &second));
        // The superseded clone remains valid and still refers to its allocation.
        assert_eq!(*first, 0);
        assert_eq!(*second, 1);
    }

    #[test]
    fn authenticated_client_receives_validated_job_and_durably_credits_a_share() {
        let _serial = REAL.lock().unwrap();
        let dir = private_tempdir();
        let (_node_dir, mut n) = node();
        let mut ledger =
            ledger::Ledger::create(&dir.path().join("pool.sqlite"), [9; 32], ledger_limits())
                .unwrap();
        let (work, client) = setup(&mut n, 1105);
        let mut server = Server::new(
            &work,
            policy(),
            vec![client],
            Box::new(FixedFactory { digest: [0; 32] }),
            limits(),
        )
        .unwrap();
        let mut client = Client::new([7; 16], [9; 32], limits()).unwrap();
        let (auth, bytes) = frame(&client.auth_message());
        let reply = server
            .handle(&mut n, &mut ledger, auth, bytes, clock(10))
            .unwrap();
        assert!(matches!(reply, wire::Message::AuthOk { .. }));
        assert_eq!(
            client.handle(&n, reply, 18, clock(10)).unwrap(),
            Event::Authenticated
        );
        let job = server.job().unwrap();
        let bytes = wire::encode(&job).unwrap().len();
        assert_eq!(
            client.handle(&n, job, bytes, clock(10)).unwrap(),
            Event::Assigned
        );
        assert_eq!(client.work().unwrap().id(), work.id());
        let mut nonce = [0u8; 32];
        nonce[..8].copy_from_slice(&1u64.to_le_bytes());
        nonce[8..].copy_from_slice(&[3; 24]);
        let submit = client.submit(nonce, clock(11)).unwrap();
        let bytes = wire::encode(&submit).unwrap().len();
        let reply = server
            .handle(&mut n, &mut ledger, submit, bytes, clock(11))
            .unwrap();
        assert_eq!(
            reply,
            wire::Message::Accepted {
                units: 5,
                block_candidate: true
            }
        );
        drop(server);
        assert_eq!(ledger.total([7; 16]).unwrap(), 5);
        assert_eq!(ledger.share_count().unwrap(), 1);
        assert_eq!(n.source().chain().unwrap().height(), 1);
        assert_eq!(
            client.handle(&n, reply, 19, clock(11)).unwrap(),
            Event::Accepted {
                units: 5,
                block_candidate: true
            }
        );
        assert!(client.assignment().is_none());
    }

    #[test]
    fn auth_failures_are_indistinguishable_and_bounded() {
        let _serial = REAL.lock().unwrap();
        let dir = private_tempdir();
        let (_node_dir, mut n) = node();
        let mut ledger =
            ledger::Ledger::create(&dir.path().join("pool.sqlite"), [9; 32], ledger_limits())
                .unwrap();
        let (work, client) = setup(&mut n, 1105);
        let mut server = Server::new(
            &work,
            policy(),
            vec![client],
            Box::new(FixedFactory { digest: [0; 32] }),
            Limits {
                auth_failures: 2,
                ..limits()
            },
        )
        .unwrap();
        let bad = wire::Message::Auth {
            client: [7; 16],
            token: [8; 32],
        };
        let bytes = wire::encode(&bad).unwrap().len();
        assert_eq!(
            server
                .handle(&mut n, &mut ledger, bad.clone(), bytes, clock(1))
                .unwrap(),
            wire::Message::Rejected {
                code: wire::UNAUTHORIZED
            }
        );
        assert_eq!(
            server
                .handle(&mut n, &mut ledger, bad.clone(), bytes, clock(2))
                .unwrap(),
            wire::Message::Rejected {
                code: wire::UNAUTHORIZED
            }
        );
        assert!(server.is_closed());
        assert_eq!(
            server.handle(&mut n, &mut ledger, bad, bytes, clock(3)),
            Err(Error::Closed)
        );
        let unknown = wire::Message::Auth {
            client: [6; 16],
            token: [9; 32],
        };
        drop(server);
        let mut server = Server::new(
            &work,
            policy(),
            vec![ClientPolicy::new([7; 16], [9; 32], [3; 24], 1, 4, work.target_le()).unwrap()],
            Box::new(FixedFactory { digest: [0; 32] }),
            limits(),
        )
        .unwrap();
        let bytes = wire::encode(&unknown).unwrap().len();
        assert_eq!(
            server
                .handle(&mut n, &mut ledger, unknown, bytes, clock(10))
                .unwrap(),
            wire::Message::Rejected {
                code: wire::UNAUTHORIZED
            }
        );
    }

    #[test]
    fn client_distinguishes_credential_rejection_from_later_share_rejection() {
        let (_node_dir, n) = node();
        let mut rejected = Client::new([7; 16], [9; 32], limits()).unwrap();
        assert!(!rejected.is_authenticated());
        assert!(!rejected.auth_rejected());
        let reply = wire::Message::Rejected {
            code: wire::UNAUTHORIZED,
        };
        let bytes = wire::encode(&reply).unwrap().len();
        assert_eq!(
            rejected.handle(&n, reply, bytes, clock(1)).unwrap(),
            Event::Rejected {
                code: wire::UNAUTHORIZED
            }
        );
        assert!(rejected.auth_rejected());
        assert!(!rejected.is_authenticated());

        let mut client = Client::new([7; 16], [9; 32], limits()).unwrap();
        let reply = wire::Message::AuthOk { session: [1; 16] };
        let bytes = wire::encode(&reply).unwrap().len();
        assert_eq!(
            client.handle(&n, reply, bytes, clock(1)).unwrap(),
            Event::Authenticated
        );
        assert!(client.is_authenticated());
        for (tick, code) in [
            wire::INVALID,
            wire::STALE,
            wire::DUPLICATE,
            wire::BUSY,
            wire::UNAUTHORIZED,
        ]
        .into_iter()
        .enumerate()
        {
            let reply = wire::Message::Rejected { code };
            let bytes = wire::encode(&reply).unwrap().len();
            assert_eq!(
                client
                    .handle(&n, reply, bytes, clock(2 + tick as u64))
                    .unwrap(),
                Event::Rejected { code }
            );
            // A rejection after a live session is a job/share rejection, never
            // an invalid credential, even for the UNAUTHORIZED code.
            assert!(!client.auth_rejected());
        }
        assert!(client.is_authenticated());
    }

    #[test]
    fn duplicate_across_restart_and_stale_jobs_fail_closed() {
        let _serial = REAL.lock().unwrap();
        let dir = private_tempdir();
        let (_node_dir, mut n) = node();
        let path = dir.path().join("pool.sqlite");
        let mut ledger = ledger::Ledger::create(&path, [9; 32], ledger_limits()).unwrap();
        let (work, _) = setup(&mut n, 1105);
        let policy = ClientPolicy::new([7; 16], [9; 32], [3; 24], 1, 4, [255; 32]).unwrap();
        let mut server = Server::new(
            &work,
            super::Policy {
                units_per_share: 1,
                units_per_block_candidate: 4,
            },
            vec![policy],
            Box::new(FixedFactory { digest: [255; 32] }),
            limits(),
        )
        .unwrap();
        let mut client = Client::new([7; 16], [9; 32], limits()).unwrap();
        let (auth, bytes) = frame(&client.auth_message());
        let reply = server
            .handle(&mut n, &mut ledger, auth, bytes, clock(10))
            .unwrap();
        assert!(matches!(reply, wire::Message::AuthOk { .. }));
        client.handle(&n, reply, 18, clock(10)).unwrap();
        let job = server.job().unwrap();
        let bytes = wire::encode(&job).unwrap().len();
        assert_eq!(
            client.handle(&n, job, bytes, clock(10)).unwrap(),
            Event::Assigned
        );
        let mut nonce = [0u8; 32];
        nonce[..8].copy_from_slice(&1u64.to_le_bytes());
        nonce[8..].copy_from_slice(&[3; 24]);
        let submit = client.submit(nonce, clock(11)).unwrap();
        let bytes = wire::encode(&submit).unwrap().len();
        assert!(matches!(
            server
                .handle(&mut n, &mut ledger, submit, bytes, clock(11))
                .unwrap(),
            wire::Message::Accepted { .. }
        ));
        let submit = client.submit(nonce, clock(12)).unwrap();
        let bytes = wire::encode(&submit).unwrap().len();
        assert_eq!(
            server
                .handle(&mut n, &mut ledger, submit, bytes, clock(12))
                .unwrap(),
            wire::Message::Rejected {
                code: wire::DUPLICATE
            }
        );
        assert_eq!(ledger.share_count().unwrap(), 1);
        drop(server);

        // A new connection to the same durable ledger must still see the replay.
        let mut reopened = ledger::Ledger::open(&path, [9; 32], ledger_limits()).unwrap();
        let (work, _) = setup(&mut n, 1105);
        let policy = ClientPolicy::new([7; 16], [9; 32], [3; 24], 1, 4, [255; 32]).unwrap();
        let mut server = Server::new(
            &work,
            super::Policy {
                units_per_share: 1,
                units_per_block_candidate: 4,
            },
            vec![policy],
            Box::new(FixedFactory { digest: [255; 32] }),
            limits(),
        )
        .unwrap();
        let mut client = Client::new([7; 16], [9; 32], limits()).unwrap();
        let (auth, bytes) = frame(&client.auth_message());
        let reply = server
            .handle(&mut n, &mut reopened, auth, bytes, clock(20))
            .unwrap();
        assert!(matches!(reply, wire::Message::AuthOk { .. }));
        client.handle(&n, reply, 18, clock(20)).unwrap();
        let job = server.job().unwrap();
        let bytes = wire::encode(&job).unwrap().len();
        client.handle(&n, job, bytes, clock(20)).unwrap();
        let submit = client.submit(nonce, clock(21)).unwrap();
        let bytes = wire::encode(&submit).unwrap().len();
        assert_eq!(
            server
                .handle(&mut n, &mut reopened, submit, bytes, clock(21))
                .unwrap(),
            wire::Message::Rejected {
                code: wire::DUPLICATE
            }
        );
        drop(server);
        assert_eq!(reopened.share_count().unwrap(), 1);
    }

    #[test]
    fn job_replacement_retires_old_assignments_and_reorgs_are_rejected() {
        let _serial = REAL.lock().unwrap();
        let dir = private_tempdir();
        let (_node_dir, mut n) = node();
        let mut ledger =
            ledger::Ledger::create(&dir.path().join("pool.sqlite"), [9; 32], ledger_limits())
                .unwrap();
        let (work, client) = setup(&mut n, 1105);
        let mut server = Server::new(
            &work,
            policy(),
            vec![client],
            Box::new(FixedFactory { digest: [0; 32] }),
            limits(),
        )
        .unwrap();
        let mut client = Client::new([7; 16], [9; 32], limits()).unwrap();
        let (auth, bytes) = frame(&client.auth_message());
        let reply = server
            .handle(&mut n, &mut ledger, auth, bytes, clock(10))
            .unwrap();
        client.handle(&n, reply, 18, clock(10)).unwrap();
        let first_job = server.job().unwrap();
        let first_assignment = match &first_job {
            wire::Message::Job { assignment, .. } => *assignment,
            _ => panic!("expected job"),
        };
        let bytes = wire::encode(&first_job).unwrap().len();
        client.handle(&n, first_job, bytes, clock(10)).unwrap();

        let tip = n.source().chain().unwrap().tip();
        let new_tip = append(&mut n, tip, vec![], 10);
        let next_work = prepare_at(&mut n, 1210, 20);
        server.replace_work(&next_work, 20).unwrap();
        let mut nonce = [0u8; 32];
        nonce[..8].copy_from_slice(&1u64.to_le_bytes());
        nonce[8..].copy_from_slice(&[3; 24]);
        let stale = wire::Message::Submit {
            assignment: first_assignment,
            job: work.id(),
            nonce,
        };
        let bytes = wire::encode(&stale).unwrap().len();
        assert_eq!(
            server
                .handle(&mut n, &mut ledger, stale, bytes, clock(21))
                .unwrap(),
            wire::Message::Rejected { code: wire::STALE }
        );
        assert_eq!(n.source().chain().unwrap().tip(), new_tip);
        assert_eq!(ledger.share_count().unwrap(), 0);
        let replacement = server.job().unwrap();
        let bytes = wire::encode(&replacement).unwrap().len();
        match &replacement {
            wire::Message::Job { job, parent, .. } => {
                assert_eq!(*job, next_work.id());
                assert_eq!(*parent, new_tip);
            }
            _ => panic!("expected replacement job"),
        }
        assert_eq!(
            client.handle(&n, replacement, bytes, clock(21)).unwrap(),
            Event::Assigned
        );
        assert_eq!(client.work().unwrap().id(), next_work.id());
        drop(server);
    }

    #[test]
    fn quota_and_clock_regressions_fail_closed_without_verification() {
        let _serial = REAL.lock().unwrap();
        let dir = private_tempdir();
        let (_node_dir, mut n) = node();
        let mut ledger =
            ledger::Ledger::create(&dir.path().join("pool.sqlite"), [9; 32], ledger_limits())
                .unwrap();
        let (work, client) = setup(&mut n, 1105);
        let mut server = Server::new(
            &work,
            policy(),
            vec![client],
            Box::new(FixedFactory { digest: [0; 32] }),
            Limits {
                messages: 1,
                ..limits()
            },
        )
        .unwrap();
        let client = Client::new([7; 16], [9; 32], limits()).unwrap();
        let (auth, bytes) = frame(&client.auth_message());
        server
            .handle(&mut n, &mut ledger, auth, bytes, clock(10))
            .unwrap();
        assert_eq!(
            server.handle(
                &mut n,
                &mut ledger,
                wire::Message::Rejected { code: wire::STALE },
                10,
                clock(11)
            ),
            Err(Error::Quota)
        );
        assert_eq!(
            server.handle(
                &mut n,
                &mut ledger,
                wire::Message::Rejected { code: wire::STALE },
                10,
                clock(5)
            ),
            Err(Error::Clock)
        );
    }

    #[test]
    fn client_rejects_tampered_jobs_and_duplicate_partitions() {
        let _serial = REAL.lock().unwrap();
        let dir = private_tempdir();
        let (_node_dir, mut n) = node();
        let mut ledger =
            ledger::Ledger::create(&dir.path().join("pool.sqlite"), [9; 32], ledger_limits())
                .unwrap();
        let work = prepare(&mut n, 1105);
        assert!(matches!(
            Server::new(
                &work,
                policy(),
                vec![
                    ClientPolicy::new([7; 16], [9; 32], [3; 24], 1, 4, work.target_le()).unwrap(),
                    ClientPolicy::new([8; 16], [10; 32], [3; 24], 4, 8, work.target_le()).unwrap(),
                ],
                Box::new(FixedFactory { digest: [0; 32] }),
                limits()
            ),
            Err(Error::Configuration)
        ));
        let mut client = Client::new([7; 16], [9; 32], limits()).unwrap();
        let (auth, bytes) = frame(&client.auth_message());
        let mut server = Server::new(
            &work,
            policy(),
            vec![ClientPolicy::new([7; 16], [9; 32], [3; 24], 1, 4, work.target_le()).unwrap()],
            Box::new(FixedFactory { digest: [0; 32] }),
            limits(),
        )
        .unwrap();
        let reply = server
            .handle(&mut n, &mut ledger, auth, bytes, clock(10))
            .unwrap();
        client.handle(&n, reply, 18, clock(10)).unwrap();
        let mut job = server.job().unwrap();
        if let wire::Message::Job { job, .. } = &mut job {
            job[0] ^= 1;
        }
        let bytes = wire::encode(&job).unwrap().len();
        assert_eq!(
            client.handle(&n, job, bytes, clock(10)).unwrap(),
            Event::Rejected {
                code: wire::INVALID
            }
        );
        assert!(client.work().is_none());
    }

    #[test]
    fn independent_sessions_share_one_ledger_with_disjoint_partitions() {
        let _serial = REAL.lock().unwrap();
        let dir = private_tempdir();
        let (_node_dir, mut n) = node();
        let mut ledger =
            ledger::Ledger::create(&dir.path().join("pool.sqlite"), [9; 32], ledger_limits())
                .unwrap();
        let work = prepare(&mut n, 1105);
        let first = ClientPolicy::new([7; 16], [9; 32], [3; 24], 1, 4, [255; 32]).unwrap();
        let second = ClientPolicy::new([8; 16], [10; 32], [4; 24], 1, 4, [255; 32]).unwrap();
        let share_policy = Policy {
            units_per_share: 1,
            units_per_block_candidate: 4,
        };
        let mut first_server = Server::new(
            &work,
            share_policy,
            vec![first],
            Box::new(FixedFactory { digest: [255; 32] }),
            limits(),
        )
        .unwrap();
        let mut second_server = Server::new(
            &work,
            share_policy,
            vec![second],
            Box::new(FixedFactory { digest: [255; 32] }),
            limits(),
        )
        .unwrap();
        let mut first_client = Client::new([7; 16], [9; 32], limits()).unwrap();
        let mut second_client = Client::new([8; 16], [10; 32], limits()).unwrap();
        for (server, client, clock_ms) in [
            (&mut first_server, &mut first_client, 10),
            (&mut second_server, &mut second_client, 20),
        ] {
            let (auth, bytes) = frame(&client.auth_message());
            let reply = server
                .handle(&mut n, &mut ledger, auth, bytes, clock(clock_ms))
                .unwrap();
            assert!(matches!(reply, wire::Message::AuthOk { .. }));
            client.handle(&n, reply, 18, clock(clock_ms)).unwrap();
            let job = server.job().unwrap();
            let bytes = wire::encode(&job).unwrap().len();
            assert_eq!(
                client.handle(&n, job, bytes, clock(clock_ms)).unwrap(),
                Event::Assigned
            );
        }
        for (server, client, prefix, clock_ms) in [
            (&mut first_server, &mut first_client, [3u8; 24], 11),
            (&mut second_server, &mut second_client, [4u8; 24], 21),
        ] {
            let mut nonce = [0u8; 32];
            nonce[..8].copy_from_slice(&1u64.to_le_bytes());
            nonce[8..].copy_from_slice(&prefix);
            let submit = client.submit(nonce, clock(clock_ms)).unwrap();
            let bytes = wire::encode(&submit).unwrap().len();
            assert!(matches!(
                server
                    .handle(&mut n, &mut ledger, submit, bytes, clock(clock_ms))
                    .unwrap(),
                wire::Message::Accepted {
                    units: 1,
                    block_candidate: false
                }
            ));
        }
        assert_eq!(ledger.total([7; 16]).unwrap(), 1);
        assert_eq!(ledger.total([8; 16]).unwrap(), 1);
        assert_eq!(ledger.share_count().unwrap(), 2);
        let mut nonce = [0u8; 32];
        nonce[..8].copy_from_slice(&1u64.to_le_bytes());
        nonce[8..].copy_from_slice(&[3; 24]);
        let duplicate = first_client.submit(nonce, clock(12)).unwrap();
        let bytes = wire::encode(&duplicate).unwrap().len();
        assert_eq!(
            first_server
                .handle(&mut n, &mut ledger, duplicate, bytes, clock(12))
                .unwrap(),
            wire::Message::Rejected {
                code: wire::DUPLICATE
            }
        );
        assert_eq!(ledger.share_count().unwrap(), 2);
    }

    #[test]
    fn capacity_refusal_precedes_block_submission() {
        let _serial = REAL.lock().unwrap();
        let dir = private_tempdir();
        let (_node_dir, mut n) = node();
        let capacity = ledger::Limits {
            max_shares: 1,
            ..ledger_limits()
        };
        let mut ledger =
            ledger::Ledger::create(&dir.path().join("pool.sqlite"), [9; 32], capacity).unwrap();
        ledger
            .credit(&[1; 32], &[1; 32], [9; 16], 1, false)
            .unwrap();
        let (work, client) = setup(&mut n, 1105);
        let mut server = Server::new(
            &work,
            policy(),
            vec![client],
            Box::new(FixedFactory { digest: [0; 32] }),
            limits(),
        )
        .unwrap();
        let mut client = Client::new([7; 16], [9; 32], limits()).unwrap();
        let (auth, bytes) = frame(&client.auth_message());
        let reply = server
            .handle(&mut n, &mut ledger, auth, bytes, clock(10))
            .unwrap();
        client.handle(&n, reply, 18, clock(10)).unwrap();
        let job = server.job().unwrap();
        let bytes = wire::encode(&job).unwrap().len();
        client.handle(&n, job, bytes, clock(10)).unwrap();
        let mut nonce = [0u8; 32];
        nonce[..8].copy_from_slice(&1u64.to_le_bytes());
        nonce[8..].copy_from_slice(&[3; 24]);
        let submit = client.submit(nonce, clock(11)).unwrap();
        let bytes = wire::encode(&submit).unwrap().len();
        assert_eq!(
            server
                .handle(&mut n, &mut ledger, submit, bytes, clock(11))
                .unwrap(),
            wire::Message::Rejected { code: wire::BUSY }
        );
        assert_eq!(
            n.source().chain().unwrap().height(),
            0,
            "a failed durable reservation must not reach the node"
        );
        assert_eq!(ledger.share_count().unwrap(), 1);
        assert_eq!(
            ledger.pending_count().unwrap(),
            0,
            "capacity refused the reservation without leaving a journal row"
        );
        drop(server);
        assert_eq!(ledger.share_count().unwrap(), 1);
    }

    #[test]
    fn pending_reservation_without_acceptance_survives_reopen_uncredited() {
        let _serial = REAL.lock().unwrap();
        let dir = private_tempdir();
        let (_node_dir, n) = node();
        let path = dir.path().join("pool.sqlite");
        let mut ledger = ledger::Ledger::create(&path, [9; 32], ledger_limits()).unwrap();
        ledger
            .reserve([3; 32], root().id, &[1; 32], &[2; 32], [7; 16], 1, true)
            .unwrap();
        drop(ledger);
        let mut reopened = ledger::Ledger::open(&path, [9; 32], ledger_limits()).unwrap();
        assert_eq!(
            reconcile_pending(&n, &mut reopened).unwrap(),
            Reconciliation {
                finalized: 0,
                remaining: 1
            }
        );
        assert_eq!(reopened.share_count().unwrap(), 0);
        assert_eq!(reopened.total([7; 16]).unwrap(), 0);
        assert_eq!(reopened.pending_count().unwrap(), 1);
    }

    #[test]
    fn reconcile_finalizes_one_exact_durable_acceptance_once() {
        let _serial = REAL.lock().unwrap();
        let dir = private_tempdir();
        let (_node_dir, mut n) = node();
        let accepted = append(&mut n, root().id, vec![], 0);
        let info = n.source().block_info(&accepted).unwrap().unwrap();
        let parent = info.parent.unwrap();
        assert_eq!(info.height, 1);
        let path = dir.path().join("pool.sqlite");
        let mut ledger = ledger::Ledger::create(&path, [9; 32], ledger_limits()).unwrap();
        ledger
            .reserve(accepted, parent, &[1; 32], &[2; 32], [7; 16], 1, true)
            .unwrap();
        assert_eq!(ledger.share_count().unwrap(), 0);
        drop(ledger);
        let mut reopened = ledger::Ledger::open(&path, [9; 32], ledger_limits()).unwrap();
        assert_eq!(
            reconcile_pending(&n, &mut reopened).unwrap(),
            Reconciliation {
                finalized: 1,
                remaining: 0
            }
        );
        assert_eq!(reopened.total([7; 16]).unwrap(), 1);
        assert_eq!(reopened.share_count().unwrap(), 1);
        assert_eq!(reopened.pending_count().unwrap(), 0);
        assert_eq!(
            reconcile_pending(&n, &mut reopened).unwrap(),
            Reconciliation {
                finalized: 0,
                remaining: 0
            }
        );
        assert_eq!(reopened.total([7; 16]).unwrap(), 1);
        assert_eq!(reopened.share_count().unwrap(), 1);
    }

    #[test]
    fn stale_or_unproven_pending_stays_uncredited() {
        let _serial = REAL.lock().unwrap();
        let dir = private_tempdir();
        let (_node_dir, mut n) = node();
        let accepted = append(&mut n, root().id, vec![], 0);
        let path = dir.path().join("pool.sqlite");
        let mut ledger = ledger::Ledger::create(&path, [9; 32], ledger_limits()).unwrap();
        // Correct block ID, impossible parent.
        ledger
            .reserve(accepted, [9; 32], &[1; 32], &[2; 32], [7; 16], 1, true)
            .unwrap();
        // No durable block index entry at all.
        ledger
            .reserve([4; 32], root().id, &[3; 32], &[4; 32], [7; 16], 1, true)
            .unwrap();
        drop(ledger);
        let mut reopened = ledger::Ledger::open(&path, [9; 32], ledger_limits()).unwrap();
        assert_eq!(
            reconcile_pending(&n, &mut reopened).unwrap(),
            Reconciliation {
                finalized: 0,
                remaining: 2
            }
        );
        assert_eq!(reopened.share_count().unwrap(), 0);
        assert_eq!(reopened.total([7; 16]).unwrap(), 0);
        assert_eq!(reopened.pending_count().unwrap(), 2);
    }

    fn assignment_of(job: &wire::Message) -> ([u8; 32], [u8; 32]) {
        match job {
            wire::Message::Job { assignment, job, .. } => (*assignment, *job),
            _ => panic!("expected job"),
        }
    }

    #[test]
    fn unchanged_work_keeps_ids_and_checkers_and_renews_an_expired_lease() {
        let _serial = REAL.lock().unwrap();
        let dir = private_tempdir();
        let (_node_dir, mut n) = node();
        let mut ledger =
            ledger::Ledger::create(&dir.path().join("pool.sqlite"), [9; 32], ledger_limits())
                .unwrap();
        let work = prepare(&mut n, 1105);
        let client = ClientPolicy::new([7; 16], [9; 32], [3; 24], 1, 4, [255; 32]).unwrap();
        let creates = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut server = Server::new(
            &work,
            policy(),
            vec![client],
            Box::new(CountingFactory {
                digest: [255; 32],
                creates: creates.clone(),
            }),
            Limits {
                job_ttl_ms: 100,
                ..limits()
            },
        )
        .unwrap();
        let auth = wire::Message::Auth {
            client: [7; 16],
            token: [9; 32],
        };
        let bytes = wire::encode(&auth).unwrap().len();
        assert!(matches!(
            server
                .handle(&mut n, &mut ledger, auth, bytes, clock(10))
                .unwrap(),
            wire::Message::AuthOk { .. }
        ));
        assert_eq!(creates.load(std::sync::atomic::Ordering::SeqCst), 1);
        let (assignment, _) = assignment_of(&server.job().unwrap());

        // Live unchanged work neither replaces the job nor builds another checker.
        assert!(!server.apply_work(&work, 20).unwrap());
        assert_eq!(creates.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(assignment_of(&server.job().unwrap()).0, assignment);

        // The lease expires at 110; rotate the assignment ID and redispatch the
        // same work, reusing the checker and its cache.
        assert!(server.apply_work(&work, 110).unwrap());
        assert_eq!(creates.load(std::sync::atomic::Ordering::SeqCst), 1);
        let (renewed, renewed_job) = assignment_of(&server.job().unwrap());
        assert_ne!(renewed, assignment);
        assert_eq!(renewed_job, work.id());

        let mut nonce = [0u8; 32];
        nonce[..8].copy_from_slice(&1u64.to_le_bytes());
        nonce[8..].copy_from_slice(&[3; 24]);
        let submit = wire::Message::Submit {
            assignment: renewed,
            job: work.id(),
            nonce,
        };
        let bytes = wire::encode(&submit).unwrap().len();
        assert_eq!(
            server
                .handle(&mut n, &mut ledger, submit, bytes, clock(150))
                .unwrap(),
            wire::Message::Accepted {
                units: 1,
                block_candidate: false
            },
            "the rotated lease accepts work after the original expiry"
        );
    }

    #[test]
    fn actual_work_change_replaces_assignment_and_checker_once() {
        let _serial = REAL.lock().unwrap();
        let dir = private_tempdir();
        let (_node_dir, mut n) = node();
        let mut ledger =
            ledger::Ledger::create(&dir.path().join("pool.sqlite"), [9; 32], ledger_limits())
                .unwrap();
        let work = prepare(&mut n, 1105);
        let client = ClientPolicy::new([7; 16], [9; 32], [3; 24], 1, 4, [255; 32]).unwrap();
        let creates = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut server = Server::new(
            &work,
            policy(),
            vec![client],
            Box::new(CountingFactory {
                digest: [255; 32],
                creates: creates.clone(),
            }),
            limits(),
        )
        .unwrap();
        let auth = wire::Message::Auth {
            client: [7; 16],
            token: [9; 32],
        };
        let bytes = wire::encode(&auth).unwrap().len();
        assert!(matches!(
            server
                .handle(&mut n, &mut ledger, auth, bytes, clock(10))
                .unwrap(),
            wire::Message::AuthOk { .. }
        ));
        let (first_assignment, first_job) = assignment_of(&server.job().unwrap());
        assert_eq!(first_job, work.id());

        let next = prepare_at(&mut n, 1210, 20);
        assert_ne!(next.id(), work.id());
        assert!(server.apply_work(&next, 20).unwrap());
        assert_eq!(creates.load(std::sync::atomic::Ordering::SeqCst), 2);
        let (next_assignment, next_job) = assignment_of(&server.job().unwrap());
        assert_ne!(next_assignment, first_assignment);
        assert_eq!(next_job, next.id());

        // The replacement is stable across later unchanged polls.
        assert!(!server.apply_work(&next, 30).unwrap());
        assert_eq!(creates.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(assignment_of(&server.job().unwrap()).0, next_assignment);
    }

    #[test]
    fn accepted_candidate_does_not_revive_a_same_work_assignment() {
        let _serial = REAL.lock().unwrap();
        let dir = private_tempdir();
        let (_node_dir, mut n) = node();
        let mut ledger =
            ledger::Ledger::create(&dir.path().join("pool.sqlite"), [9; 32], ledger_limits())
                .unwrap();
        let work = prepare(&mut n, 1105);
        let client = ClientPolicy::new([7; 16], [9; 32], [3; 24], 1, 4, [255; 32]).unwrap();
        let creates = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut server = Server::new(
            &work,
            policy(),
            vec![client],
            Box::new(CountingFactory {
                digest: [0; 32],
                creates: creates.clone(),
            }),
            limits(),
        )
        .unwrap();
        let auth = wire::Message::Auth {
            client: [7; 16],
            token: [9; 32],
        };
        let bytes = wire::encode(&auth).unwrap().len();
        assert!(matches!(
            server
                .handle(&mut n, &mut ledger, auth, bytes, clock(10))
                .unwrap(),
            wire::Message::AuthOk { .. }
        ));
        let (assignment, _) = assignment_of(&server.job().unwrap());
        let mut nonce = [0u8; 32];
        nonce[..8].copy_from_slice(&1u64.to_le_bytes());
        nonce[8..].copy_from_slice(&[3; 24]);
        let submit = wire::Message::Submit {
            assignment,
            job: work.id(),
            nonce,
        };
        let bytes = wire::encode(&submit).unwrap().len();
        assert_eq!(
            server
                .handle(&mut n, &mut ledger, submit, bytes, clock(11))
                .unwrap(),
            wire::Message::Accepted {
                units: 5,
                block_candidate: true
            }
        );
        assert!(server.job().is_none());
        assert!(!server.apply_work(&work, 500).unwrap());
        assert_eq!(creates.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(
            server.job().is_none(),
            "an accepted candidate must not resurrect the same-work assignment"
        );
    }

    #[test]
    fn pool_frames_traverse_the_noise_stream() {
        use crate::transport::{Identity, POOL_DOMAIN, Role, SecureStream};
        use std::io::{Read, Write};
        use zeroize::Zeroizing;

        let (client_io, server_io) = crate::transport::isolated_memory_pair();
        let client_key = Identity::from_secret(Zeroizing::new([7; 32]));
        let server_key = Identity::from_secret(Zeroizing::new([11; 32]));
        let mut client = SecureStream::new(
            client_io,
            &client_key,
            Role::Initiator {
                remote_key: server_key.public_key(),
            },
            [2; 32],
            POOL_DOMAIN,
            0,
        )
        .unwrap();
        let mut server = SecureStream::new(
            server_io,
            &server_key,
            Role::Responder,
            [2; 32],
            POOL_DOMAIN,
            0,
        )
        .unwrap();
        for ms in 0..100 {
            client.advance(ms).unwrap();
            server.advance(ms).unwrap();
        }
        assert!(client.established() && server.established());

        let message = wire::Message::Auth {
            client: [1; 16],
            token: [2; 32],
        };
        let frame = wire::encode(&message).unwrap();
        let mut sent = 0;
        for ms in 100..2_000 {
            if sent < frame.len() {
                match client.write(&frame[sent..]) {
                    Ok(0) => panic!("zero write"),
                    Ok(n) => sent += n,
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                        ) => {}
                    Err(_) => panic!("write failed"),
                }
            }
            client.advance(ms).unwrap();
            server.advance(ms).unwrap();
            if sent == frame.len() {
                break;
            }
        }
        assert_eq!(sent, frame.len());
        let mut received = Vec::new();
        let mut buffer = [0u8; 64];
        for ms in 2_000..10_000 {
            match server.read(&mut buffer) {
                Ok(0) => panic!("zero read"),
                Ok(n) => received.extend_from_slice(&buffer[..n]),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => panic!("read failed"),
            }
            client.advance(ms).unwrap();
            server.advance(ms).unwrap();
            if received.len() >= frame.len() {
                break;
            }
        }
        assert_eq!(received, frame);
        assert_eq!(wire::decode(&received).unwrap(), message);
    }
}
