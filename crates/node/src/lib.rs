//! Explicitly driven node runtime. Construction opens no sockets and generates no root.
pub mod cli;
pub mod lookup;
pub mod mining;
mod orphans;
mod relay;
pub mod rpc;
pub mod scan_client;
pub mod scan_server;
pub mod submission;
pub mod transport;
pub mod wire;
use monario_chain::{
    Accepted, Hash,
    header::{HEADER_LEN, Header},
    mempool::{self, Mempool},
    storage::{DurableChain, StorageError},
};
use monario_v6::V6Verifier;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::SocketAddr;
pub type PeerId = [u8; 16];

/// A peer-supplied discovery candidate. Candidates are untrusted, are never
/// dialed automatically and are never added to the pinned peer configuration by
/// this type. An operator must review and promote them explicitly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerCandidate {
    pub address: SocketAddr,
    pub public_key: [u8; 32],
}

/// Hard cap on retained untrusted candidates.
pub const MAX_CANDIDATES: usize = 128;
#[derive(Clone, Copy)]
pub struct Clock {
    pub monotonic_ms: u64,
    pub unix_seconds: u64,
}
#[derive(Clone, Copy)]
pub struct Limits {
    pub peers: usize,
    pub receive_bytes: usize,
    pub send_bytes: usize,
    pub messages_per_window: u32,
    pub bytes_per_window: usize,
    pub tx_checks_per_window: u32,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Configuration,
    Clock,
    Stopped,
    Capacity,
    Protocol,
    Storage,
    Entropy,
    Io,
    Transaction,
    Mining,
    Pruned,
}
const WINDOW: u64 = 10_000;
const HANDSHAKE: u64 = 10_000;
const FRAME_TIMEOUT: u64 = 30_000;
const REQUEST_TIMEOUT: u64 = 30_000;
const IDLE: u64 = 120_000;
struct Send {
    bytes: Vec<u8>,
    offset: usize,
    at: u64,
}
struct Peer {
    outbound: bool,
    nonce: [u8; 16],
    remote_nonce: Option<[u8; 16]>,
    hello: bool,
    ready: bool,
    tip: Hash,
    decoder: wire::Decoder,
    inbox: Option<wire::Frame>,
    out: VecDeque<Send>,
    born: u64,
    last_rx: u64,
    frame_started: Option<u64>,
    window: u64,
    bytes: usize,
    messages: u32,
    tx_checks: u32,
    next_sync: u64,
    ping: Option<([u8; 8], u64)>,
    announced_tip: Hash,
    relayed: BTreeMap<Hash, u64>,
    relay_window: u64,
    relay_count: u32,
    relay_next: u64,
    parent_requests: u32,
    parent_served: u32,
}
impl Peer {
    fn window(&mut self, now: u64) {
        if now.saturating_sub(self.window) >= WINDOW {
            self.window = now;
            self.bytes = 0;
            self.messages = 0;
            self.tx_checks = 0;
            self.parent_requests = 0;
            self.parent_served = 0;
        }
    }
    fn held(&self) -> usize {
        self.decoder.reserved() + self.inbox.as_ref().map_or(0, |f| f.payload.len())
    }
}
struct Sync {
    started: u64,
    peer: PeerId,
    locator: Vec<Hash>,
    cursor: Hash,
    ids: VecDeque<Hash>,
    awaiting: bool,
    requested: Option<Hash>,
    deadline: u64,
}
pub struct Node {
    store: DurableChain<V6Verifier>,
    pool: Mempool,
    limits: Limits,
    profile: Hash,
    magic: [u8; 4],
    chain_id: Hash,
    block_limit: usize,
    tx_limit: usize,
    peers: BTreeMap<PeerId, Peer>,
    sync: Option<Sync>,
    receive_bytes: usize,
    send_bytes: usize,
    last_ms: u64,
    window: u64,
    tx_checks: u32,
    parent_requests: u32,
    parent_served: u32,
    round: Option<PeerId>,
    relay_round: Option<PeerId>,
    bulk_bytes: usize,
    replay_bytes: usize,
    stopped: bool,
    submission: Option<submission::Active>,
    orphans: orphans::Orphans,
    candidates: Vec<PeerCandidate>,
    local_public_key: Option<[u8; 32]>,
    local_candidates: Vec<PeerCandidate>,
}
fn random<const N: usize>() -> Result<[u8; N], Error> {
    let mut b = [0; N];
    getrandom::fill(&mut b).map_err(|_| Error::Entropy)?;
    Ok(b)
}

/// Discovery candidates must be numeric IP:port targets. DNS names are not
/// accepted, matching the pinned-peer configuration contract.
fn valid_candidate_address(address: SocketAddr) -> bool {
    address.port() != 0 && !address.ip().is_unspecified() && !address.ip().is_multicast()
}
impl Node {
    pub fn new(
        store: DurableChain<V6Verifier>,
        limits: Limits,
        pool_limits: mempool::Limits,
    ) -> Result<Self, Error> {
        let c = store.chain().map_err(|_| Error::Storage)?;
        let block_limit = c.limits().block_bytes;
        let tx_limit = c.limits().transaction_bytes.min(2_000_000);
        if limits.peers == 0
            || limits.peers > 32
            || limits.receive_bytes < 2 * (block_limit + 32) + 65536
            || limits.receive_bytes > 64 * 1024 * 1024
            || limits.send_bytes < block_limit + 65536
            || limits.send_bytes > 64 * 1024 * 1024
            || limits.messages_per_window < 8
            || limits.messages_per_window > 1024
            || limits.bytes_per_window < block_limit + wire::HEADER + 32
            || limits.bytes_per_window > 64 * 1024 * 1024
            || limits.tx_checks_per_window == 0
            || limits.tx_checks_per_window > 1024
            || pool_limits.transactions > 1024
            || pool_limits.bytes > 8 * 1024 * 1024
        {
            return Err(Error::Configuration);
        }
        let profile = c.validation_profile();
        let magic = wire::magic(profile);
        let chain_id = c.chain_id();
        let pool = Mempool::new(c, pool_limits).map_err(|_| Error::Configuration)?;
        Ok(Self {
            store,
            pool,
            limits,
            profile,
            magic,
            chain_id,
            block_limit,
            tx_limit,
            peers: BTreeMap::new(),
            sync: None,
            receive_bytes: 0,
            send_bytes: 0,
            last_ms: 0,
            window: 0,
            tx_checks: 0,
            parent_requests: 0,
            parent_served: 0,
            round: None,
            relay_round: None,
            bulk_bytes: 0,
            replay_bytes: 0,
            stopped: false,
            submission: None,
            orphans: orphans::Orphans::default(),
            candidates: Vec::new(),
            local_public_key: None,
            local_candidates: Vec::new(),
        })
    }
    pub fn source(&self) -> &DurableChain<V6Verifier> {
        &self.store
    }
    /// Publish this node's explicitly pinned peers for one-hop advertisement.
    /// The list is never extended with untrusted candidates. No connection is
    /// opened or scheduled here.
    pub fn set_local_candidates(
        &mut self,
        public_key: [u8; 32],
        candidates: Vec<PeerCandidate>,
    ) -> Result<(), Error> {
        if !crate::transport::valid_public(public_key) || candidates.len() > 32 {
            return Err(Error::Configuration);
        }
        let mut seen = BTreeSet::new();
        for candidate in &candidates {
            if !valid_candidate_address(candidate.address)
                || !crate::transport::valid_public(candidate.public_key)
                || candidate.public_key == public_key
                || !seen.insert((candidate.address, candidate.public_key))
            {
                return Err(Error::Configuration);
            }
        }
        self.local_public_key = Some(public_key);
        self.local_candidates = candidates;
        Ok(())
    }
    /// Untrusted candidates received from ready peers, in first-seen order.
    pub fn candidates(&self) -> &[PeerCandidate] {
        &self.candidates
    }
    pub fn mempool(&self) -> &Mempool {
        &self.pool
    }
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }
    pub fn contains_peer(&self, id: PeerId) -> bool {
        self.peers.contains_key(&id)
    }
    /// Whether a peer completed the application handshake. Used by the transport
    /// driver to credit a successful endpoint only after authentication.
    pub fn peer_ready(&self, id: PeerId) -> bool {
        self.peers.get(&id).is_some_and(|peer| peer.ready)
    }
    pub fn buffered_bytes(&self) -> (usize, usize) {
        (self.receive_bytes, self.send_bytes)
    }
    pub fn stopped(&self) -> bool {
        self.stopped
    }
    fn clock(&mut self, clock: Clock) -> Result<(), Error> {
        if self.stopped {
            return Err(Error::Stopped);
        }
        if clock.monotonic_ms < self.last_ms {
            return Err(Error::Clock);
        }
        self.last_ms = clock.monotonic_ms;
        if self.last_ms.saturating_sub(self.window) >= WINDOW {
            self.window = self.last_ms;
            self.tx_checks = 0;
            self.parent_requests = 0;
            self.parent_served = 0;
            self.bulk_bytes = 0;
            self.replay_bytes = 0;
        }
        Ok(())
    }
    fn reserve_replay_lookup(&mut self, bytes: usize) -> bool {
        if self.pool.is_empty() {
            return true;
        }
        let limit = self.limits.bytes_per_window.max(self.tx_limit);
        let Some(next) = self.replay_bytes.checked_add(bytes).filter(|n| *n <= limit) else {
            return false;
        };
        self.replay_bytes = next;
        true
    }
    fn queue(&mut self, p: &mut Peer, kind: u8, payload: &[u8], now: u64) -> Result<bool, Error> {
        let len = wire::HEADER + payload.len();
        let bulk = matches!(
            kind,
            wire::BLOCK | wire::TRANSACTION | wire::PARENT_TRANSACTION
        );
        if p.out.len() >= 32
            || self
                .send_bytes
                .checked_add(len)
                .is_none_or(|n| n > self.limits.send_bytes)
            || (bulk
                && self
                    .bulk_bytes
                    .checked_add(len)
                    .is_none_or(|n| n > self.limits.bytes_per_window))
        {
            return Ok(false);
        }
        let bytes = wire::encode(self.magic, kind, payload, self.block_limit, self.tx_limit)
            .map_err(|_| Error::Protocol)?;
        self.send_bytes += bytes.len();
        if bulk {
            self.bulk_bytes += bytes.len();
        }
        let send = Send {
            bytes,
            offset: 0,
            at: now,
        };
        // Keep the current stream frame intact, but prioritize requested bodies
        // over queued transaction gossip to avoid starving synchronization.
        if kind == wire::BLOCK && !p.out.is_empty() {
            p.out.insert(1, send);
        } else {
            p.out.push_back(send);
        }
        Ok(true)
    }
    pub fn add_peer(&mut self, clock: Clock) -> Result<PeerId, Error> {
        self.clock(clock)?;
        if self.peers.len() >= self.limits.peers {
            return Err(Error::Capacity);
        }
        let id = random()?;
        if self.peers.contains_key(&id) {
            return Err(Error::Entropy);
        }
        let now = clock.monotonic_ms;
        let mut p = Peer {
            outbound: false,
            nonce: random()?,
            remote_nonce: None,
            hello: false,
            ready: false,
            tip: [0; 32],
            decoder: wire::Decoder::new(),
            inbox: None,
            out: VecDeque::new(),
            born: now,
            last_rx: now,
            frame_started: None,
            window: now,
            bytes: 0,
            messages: 0,
            tx_checks: 0,
            next_sync: now,
            ping: None,
            announced_tip: self.store.chain().map_err(|_| Error::Storage)?.tip(),
            relayed: BTreeMap::new(),
            relay_window: now,
            relay_count: 0,
            relay_next: now,
            parent_requests: 0,
            parent_served: 0,
        };
        let c = self.store.chain().map_err(|_| Error::Storage)?;
        let mut payload = self.profile.to_vec();
        payload.extend(p.nonce);
        payload.extend(c.tip());
        payload.extend(c.height().to_le_bytes());
        if !self.queue(&mut p, wire::HELLO, &payload, now)? {
            return Err(Error::Capacity);
        }
        self.peers.insert(id, p);
        Ok(id)
    }
    /// Local transport direction only; no peer-supplied role grants priority.
    pub fn add_outbound_peer(&mut self, clock: Clock) -> Result<PeerId, Error> {
        let id = self.add_peer(clock)?;
        self.peers.get_mut(&id).expect("inserted peer").outbound = true;
        Ok(id)
    }
    fn release(&mut self, id: PeerId, p: Peer) {
        self.orphans.disconnect(id);
        self.receive_bytes -= p.held();
        self.send_bytes -= p.out.iter().map(|s| s.bytes.len()).sum::<usize>();
        if self.sync.as_ref().is_some_and(|s| s.peer == id) {
            self.sync = None;
        }
    }
    pub fn disconnect(&mut self, id: PeerId) {
        if let Some(p) = self.peers.remove(&id) {
            self.release(id, p);
        }
    }
    pub fn can_receive(&self, id: PeerId) -> bool {
        self.peers.get(&id).is_some_and(|p| p.inbox.is_none()) && !self.stopped
    }
    /// Feed at most one bounded transport chunk. Return the consumed byte count;
    /// zero means backpressure. Unconsumed bytes must be retained by the transport.
    pub fn receive(&mut self, id: PeerId, data: &[u8], clock: Clock) -> Result<usize, Error> {
        self.clock(clock)?;
        if data.len() > wire::CHUNK {
            return Err(Error::Capacity);
        }
        let mut p = self.peers.remove(&id).ok_or(Error::Protocol)?;
        if p.inbox.is_some() {
            self.peers.insert(id, p);
            return Ok(0);
        }
        p.window(clock.monotonic_ms);
        if p.bytes >= self.limits.bytes_per_window || p.messages >= self.limits.messages_per_window
        {
            self.peers.insert(id, p);
            return Ok(0);
        }
        let data = &data[..data.len().min(self.limits.bytes_per_window - p.bytes)];
        let block_expected = self
            .sync
            .as_ref()
            .is_some_and(|s| s.peer == id && s.requested.is_some());
        let inv_expected = self
            .sync
            .as_ref()
            .is_some_and(|s| s.peer == id && s.awaiting);
        let parent_expected = self.orphans.expected(id, clock.monotonic_ms);
        let old = p.decoder.reserved();
        let reserve = if p.decoder.kind() == Some(wire::BLOCK) {
            0
        } else {
            self.block_limit + 32
        };
        let budget = self
            .limits
            .receive_bytes
            .saturating_sub(self.receive_bytes)
            .saturating_sub(reserve);
        let result = p.decoder.feed(
            data,
            self.magic,
            self.block_limit,
            self.tx_limit,
            budget,
            |kind| {
                if !p.hello {
                    kind == wire::HELLO
                } else if !p.ready {
                    kind == wire::ACK
                } else {
                    match kind {
                        wire::HELLO | wire::ACK => false,
                        wire::BLOCK => block_expected,
                        wire::INVENTORY => inv_expected,
                        wire::PARENT_TRANSACTION | wire::TRANSACTION_NOT_FOUND => parent_expected,
                        _ => true,
                    }
                }
            },
        );
        match result {
            Ok((n, frame)) => {
                let new = p.decoder.reserved() + frame.as_ref().map_or(0, |f| f.payload.len());
                self.receive_bytes = self.receive_bytes - old + new;
                if n > 0 {
                    p.last_rx = clock.monotonic_ms;
                    p.frame_started.get_or_insert(clock.monotonic_ms);
                }
                p.bytes = p.bytes.saturating_add(n);
                if frame.is_some() {
                    p.messages += 1;
                    p.frame_started = None;
                }
                if p.bytes > self.limits.bytes_per_window
                    || p.messages > self.limits.messages_per_window
                {
                    self.release(id, p);
                    self.receive_bytes -= frame.as_ref().map_or(0, |f| f.payload.len());
                    return Err(Error::Protocol);
                }
                p.inbox = frame;
                self.peers.insert(id, p);
                Ok(n)
            }
            Err(_) => {
                self.receive_bytes = self.receive_bytes - old + p.decoder.reserved();
                self.release(id, p);
                Err(Error::Protocol)
            }
        }
    }
    pub fn outbound(&self, id: PeerId) -> Option<&[u8]> {
        if self.stopped {
            return None;
        }
        let s = self.peers.get(&id)?.out.front()?;
        Some(&s.bytes[s.offset..s.bytes.len().min(s.offset + wire::CHUNK)])
    }
    pub fn consume_outbound(&mut self, id: PeerId, n: usize) -> Result<(), Error> {
        let p = self.peers.get_mut(&id).ok_or(Error::Protocol)?;
        let s = p.out.front_mut().ok_or(Error::Protocol)?;
        if n > s.bytes.len() - s.offset {
            return Err(Error::Protocol);
        }
        s.offset += n;
        if s.offset == s.bytes.len() {
            self.send_bytes -= p.out.pop_front().expect("front checked").bytes.len();
        }
        Ok(())
    }
    pub fn import_block(&mut self, bytes: &[u8], clock: Clock) -> Result<Accepted, Error> {
        self.clock(clock)?;
        let accepted = match self.store.submit_encoded(bytes, clock.unix_seconds) {
            Ok(a) => a,
            Err(StorageError::Consensus(_)) => return Err(Error::Protocol),
            Err(_) => {
                self.stopped = true;
                return Err(Error::Storage);
            }
        };
        if accepted.became_best {
            if self.pool.synchronize(&self.store).is_err() {
                self.stopped = true;
                return Err(Error::Storage);
            }
            self.reconcile_relay()?;
            self.orphans.wake();
        }
        Ok(accepted)
    }
    /// Local application submission, fully validated before relay. No signing keys
    /// or wallet files are held by this runtime. The opt-in local inbox uses private
    /// filesystem authority; remote RPC would require separate authorization.
    pub fn submit_transaction(&mut self, bytes: Vec<u8>, clock: Clock) -> Result<Hash, Error> {
        self.clock(clock)?;
        let id = self
            .pool
            .admit(self.store.chain().map_err(|_| Error::Storage)?, bytes)
            .map_err(|_| Error::Transaction)?;
        self.orphans.wake();
        Ok(id)
    }
    fn message(
        &mut self,
        id: PeerId,
        p: &mut Peer,
        f: &wire::Frame,
        clock: Clock,
    ) -> Result<bool, Error> {
        let now = clock.monotonic_ms;
        let b = f.payload.as_slice();
        match f.kind {
            wire::HELLO => {
                if p.hello || b[..32] != self.profile {
                    return Err(Error::Protocol);
                }
                let nonce: [u8; 16] = b[32..48].try_into().map_err(|_| Error::Protocol)?;
                if nonce == p.nonce
                    || self
                        .peers
                        .values()
                        .any(|other| other.nonce == nonce || other.remote_nonce == Some(nonce))
                {
                    return Err(Error::Protocol);
                }
                if !self.queue(p, wire::ACK, &[], now)? {
                    return Ok(false);
                }
                p.remote_nonce = Some(nonce);
                p.hello = true;
                p.tip = b[48..80].try_into().map_err(|_| Error::Protocol)?;
                // The advertised height is deliberately never used for fork choice.
            }
            wire::ACK => {
                if !p.hello || p.ready {
                    return Err(Error::Protocol);
                }
                p.ready = true;
                if let Some(local_key) = self.local_public_key {
                    let advertise: Vec<_> = self
                        .local_candidates
                        .iter()
                        .filter(|candidate| candidate.public_key != local_key)
                        .map(|candidate| (candidate.address, candidate.public_key))
                        .collect();
                    for chunk in advertise.chunks(wire::MAX_CANDIDATES_PER_FRAME) {
                        let Ok(payload) = wire::encode_candidates(chunk) else {
                            break;
                        };
                        if !self.queue(p, wire::CANDIDATES, &payload, now)? {
                            break;
                        }
                    }
                }
            }
            _ if !p.ready => return Err(Error::Protocol),
            wire::GET_BLOCKS => {
                let n = usize::from(b[0]);
                if n == 0 || n > 32 || b.len() != 1 + n * 32 {
                    return Err(Error::Protocol);
                }
                let locator: Vec<Hash> = b[1..]
                    .chunks_exact(32)
                    .map(|h| h.try_into().expect("fixed hash"))
                    .collect();
                if locator.iter().collect::<BTreeSet<_>>().len() != locator.len() {
                    return Err(Error::Protocol);
                }
                let (anchor, ids) = self
                    .store
                    .chain()
                    .map_err(|_| Error::Storage)?
                    .synchronization_inventory(&locator)
                    .map_err(|_| Error::Protocol)?;
                let mut payload = anchor.to_vec();
                payload.extend((ids.len() as u16).to_le_bytes());
                for id in ids {
                    payload.extend(id);
                }
                if !self.queue(p, wire::INVENTORY, &payload, now)? {
                    return Ok(false);
                }
            }
            wire::INVENTORY => {
                let anchor: Hash = b[..32].try_into().map_err(|_| Error::Protocol)?;
                let n = u16::from_le_bytes(b[32..34].try_into().expect("fixed count")) as usize;
                if n > 128 || b.len() != 34 + n * 32 {
                    return Err(Error::Protocol);
                }
                let s = self
                    .sync
                    .as_mut()
                    .filter(|s| s.peer == id && s.awaiting)
                    .ok_or(Error::Protocol)?;
                if !s.locator.contains(&anchor) {
                    return Err(Error::Protocol);
                }
                let ids: VecDeque<Hash> = b[34..]
                    .chunks_exact(32)
                    .map(|h| h.try_into().expect("fixed hash"))
                    .collect();
                if ids.contains(&anchor) || ids.iter().collect::<BTreeSet<_>>().len() != ids.len() {
                    return Err(Error::Protocol);
                }
                s.cursor = anchor;
                s.ids = ids;
                s.awaiting = false;
                s.deadline = now.saturating_add(REQUEST_TIMEOUT);
                if n == 0 {
                    p.next_sync = now.saturating_add(30_000);
                    self.sync = None;
                }
            }
            wire::GET_BLOCK => {
                let block: Hash = b.try_into().map_err(|_| Error::Protocol)?;
                let c = self.store.chain().map_err(|_| Error::Storage)?;
                if let Some(summary) = c.block_summary(block) {
                    if self
                        .send_bytes
                        .checked_add(wire::HEADER + 32 + summary.bytes as usize)
                        .is_none_or(|n| n > self.limits.send_bytes)
                        || p.out.len() >= 32
                        || self
                            .bulk_bytes
                            .checked_add(wire::HEADER + 32 + summary.bytes as usize)
                            .is_none_or(|n| n > self.limits.bytes_per_window)
                    {
                        return Ok(false);
                    }
                    let bytes = self
                        .store
                        .authenticated_block_bytes(block)
                        .map_err(|_| Error::Storage)?;
                    let mut payload = block.to_vec();
                    payload.extend(bytes);
                    if !self.queue(p, wire::BLOCK, &payload, now)? {
                        return Ok(false);
                    }
                } else if !self.queue(p, wire::NOT_FOUND, b, now)? {
                    return Ok(false);
                }
            }
            wire::BLOCK => {
                let block: Hash = b[..32].try_into().map_err(|_| Error::Protocol)?;
                let s = self
                    .sync
                    .as_ref()
                    .filter(|s| s.peer == id && s.requested == Some(block))
                    .ok_or(Error::Protocol)?;
                let h = Header::decode(&b[32..32 + HEADER_LEN]).map_err(|_| Error::Protocol)?;
                if h.id(&self.chain_id) != block || h.parent != s.cursor {
                    return Err(Error::Protocol);
                }
                if self
                    .store
                    .chain()
                    .map_err(|_| Error::Storage)?
                    .contains(&block)
                {
                    if self
                        .store
                        .authenticated_block_bytes(block)
                        .map_err(|_| Error::Storage)?
                        != b[32..]
                    {
                        return Err(Error::Protocol);
                    }
                } else {
                    self.import_block(&b[32..], clock)?;
                }
                let live: BTreeSet<_> = self
                    .pool
                    .relay_transactions(self.store.chain().map_err(|_| Error::Storage)?)
                    .map_err(|_| Error::Storage)?
                    .map(|(tx, _)| tx)
                    .collect();
                p.relayed.retain(|tx, _| live.contains(tx));
                let s = self.sync.as_mut().ok_or(Error::Protocol)?;
                s.cursor = block;
                s.requested = None;
            }
            wire::TRANSACTION => {
                p.window(now);
                if !self.reserve_replay_lookup(b.len()) {
                    return Ok(false);
                }
                if let Some(tx) = self
                    .pool
                    .known_transaction(self.store.chain().map_err(|_| Error::Storage)?, b)
                    .map_err(|_| Error::Storage)?
                {
                    p.relayed.insert(tx, now);
                    return Ok(true);
                }
                let per_peer = self
                    .limits
                    .tx_checks_per_window
                    .div_ceil(self.limits.peers as u32)
                    .max(1);
                if self.tx_checks < self.limits.tx_checks_per_window && p.tx_checks < per_peer {
                    self.tx_checks += 1;
                    p.tx_checks += 1;
                    match self
                        .pool
                        .admit(self.store.chain().map_err(|_| Error::Storage)?, b.to_vec())
                    {
                        Ok(tx) => {
                            self.orphans.wake();
                            p.relayed.insert(tx, now);
                        }
                        Err(mempool::Error::Stale) => return Err(Error::Storage),
                        Err(e) if orphans::missing(&e) => self.cache_orphan(id, b, now, now, 0)?,
                        Err(_) => {} // Local policy/orphan/conflict rejection is not peer guilt.
                    }
                }
            }
            wire::GET_TRANSACTION => return self.serve_parent(p, b, now),
            wire::PARENT_TRANSACTION | wire::TRANSACTION_NOT_FOUND => {
                return self.parent_response(id, p, f.kind, b, now);
            }
            wire::TIP => {
                let tip = b.try_into().map_err(|_| Error::Protocol)?;
                if p.tip != tip {
                    p.tip = tip;
                    p.next_sync = now;
                }
            }
            wire::PING => {
                if !self.queue(p, wire::PONG, b, now)? {
                    return Ok(false);
                }
            }
            wire::PONG => {
                if p.ping.as_ref().is_none_or(|(nonce, _)| b != nonce) {
                    return Err(Error::Protocol);
                }
                p.ping = None;
            }
            wire::NOT_FOUND => {
                if self
                    .sync
                    .as_ref()
                    .is_none_or(|s| s.peer != id || s.requested.as_ref().is_none_or(|h| b != h))
                {
                    return Err(Error::Protocol);
                }
                p.next_sync = now.saturating_add(30_000);
                self.sync = None;
            }
            wire::CANDIDATES => {
                let parsed = wire::parse_candidates(b).map_err(|_| Error::Protocol)?;
                for (address, public_key) in parsed {
                    if !valid_candidate_address(address)
                        || !crate::transport::valid_public(public_key)
                    {
                        return Err(Error::Protocol);
                    }
                    let candidate = PeerCandidate {
                        address,
                        public_key,
                    };
                    if self.local_public_key == Some(public_key)
                        || self.local_candidates.contains(&candidate)
                        || self.candidates.contains(&candidate)
                    {
                        continue;
                    }
                    if self.candidates.len() >= MAX_CANDIDATES {
                        break;
                    }
                    self.candidates.push(candidate);
                }
            }
            _ => return Err(Error::Protocol),
        }
        Ok(true)
    }
    fn schedule(&mut self, clock: Clock) -> Result<(), Error> {
        let now = clock.monotonic_ms;
        if self.sync.is_none() {
            let c = self.store.chain().map_err(|_| Error::Storage)?;
            if let Some(id) = self
                .peers
                .iter()
                .filter(|(_, p)| p.ready && p.next_sync <= now)
                .min_by_key(|(id, p)| (!p.outbound, p.next_sync, **id))
                .map(|(id, _)| *id)
            {
                let cursor = c.tip();
                let locator = c
                    .synchronization_locator(cursor)
                    .map_err(|_| Error::Storage)?;
                let mut payload = vec![locator.len() as u8];
                for h in &locator {
                    payload.extend(h);
                }
                let mut p = self.peers.remove(&id).expect("selected peer");
                if self.queue(&mut p, wire::GET_BLOCKS, &payload, now)? {
                    self.sync = Some(Sync {
                        started: now,
                        peer: id,
                        locator,
                        cursor,
                        ids: VecDeque::new(),
                        awaiting: true,
                        requested: None,
                        deadline: now.saturating_add(REQUEST_TIMEOUT),
                    });
                }
                self.peers.insert(id, p);
            }
        }
        let Some(mut s) = self.sync.take() else {
            return Ok(());
        };
        // Yield between requests even when a peer keeps supplying known blocks.
        // Periodic probing also repairs lost best-tip announcements.
        if !s.awaiting && s.requested.is_none() && now.saturating_sub(s.started) >= 120_000 {
            if let Some(p) = self.peers.get_mut(&s.peer) {
                p.next_sync = now.saturating_add(30_000);
            }
            return Ok(());
        }
        if !s.awaiting && s.requested.is_none() {
            while let Some(id) = s.ids.front().copied() {
                // A bounded-history node may have evicted this header from memory;
                // the durable index still proves the peer supplied known blocks.
                let known = self.store.block_info(&id).map_err(|_| Error::Storage)?;
                if let Some(info) = known {
                    if info.parent != Some(s.cursor) {
                        self.disconnect(s.peer);
                        return Ok(());
                    }
                    s.cursor = id;
                    s.ids.pop_front();
                } else {
                    break;
                }
            }
            let mut p = self.peers.remove(&s.peer).ok_or(Error::Protocol)?;
            if let Some(id) = s.ids.front().copied() {
                if self.queue(&mut p, wire::GET_BLOCK, &id, now)? {
                    s.ids.pop_front();
                    s.requested = Some(id);
                    s.deadline = now.saturating_add(REQUEST_TIMEOUT);
                }
            } else {
                let c = self.store.chain().map_err(|_| Error::Storage)?;
                s.locator = c
                    .synchronization_locator(s.cursor)
                    .map_err(|_| Error::Storage)?;
                let mut payload = vec![s.locator.len() as u8];
                for h in &s.locator {
                    payload.extend(h);
                }
                if self.queue(&mut p, wire::GET_BLOCKS, &payload, now)? {
                    s.awaiting = true;
                    s.deadline = now.saturating_add(REQUEST_TIMEOUT);
                }
            }
            self.peers.insert(s.peer, p);
        }
        self.sync = Some(s);
        Ok(())
    }
    /// Bounded maintenance: at most eight control frames and one proof-bearing
    /// frame per call. All validation stays on this owner thread.
    pub fn tick(&mut self, clock: Clock) -> Result<(), Error> {
        self.clock(clock)?;
        let now = clock.monotonic_ms;
        self.orphans.expire(now);
        let expired: Vec<_> = self
            .peers
            .iter()
            .filter_map(|(id, p)| {
                ((!p.ready && now.saturating_sub(p.born) >= HANDSHAKE)
                    || now.saturating_sub(p.last_rx) >= IDLE
                    || p.frame_started
                        .is_some_and(|t| now.saturating_sub(t) >= FRAME_TIMEOUT)
                    || p.out
                        .front()
                        .is_some_and(|s| now.saturating_sub(s.at) >= FRAME_TIMEOUT)
                    || p.ping
                        .is_some_and(|(_, at)| now.saturating_sub(at) >= REQUEST_TIMEOUT)
                    || self
                        .sync
                        .as_ref()
                        .is_some_and(|s| s.peer == *id && now >= s.deadline))
                .then_some(*id)
            })
            .collect();
        for id in expired {
            self.disconnect(id);
        }
        let mut ids: Vec<_> = self.peers.keys().copied().collect();
        if let Some(last) = self.round {
            let split = ids.partition_point(|id| *id <= last);
            ids.rotate_left(split);
        }
        // Requested blocks cannot be starved by a transaction flood.
        ids.sort_by_key(|id| {
            self.peers[id]
                .inbox
                .as_ref()
                .is_none_or(|f| f.kind != wire::BLOCK)
        });
        let block_waiting = ids.iter().any(|id| {
            self.peers[id]
                .inbox
                .as_ref()
                .is_some_and(|f| matches!(f.kind, wire::BLOCK | wire::GET_BLOCK))
        });
        let mut heavy = if block_waiting {
            false
        } else {
            self.poll_submission(clock)?
        };
        let mut controls = 0;
        for id in ids {
            let kind = self.peers[&id].inbox.as_ref().map(|f| f.kind);
            let Some(kind) = kind else {
                continue;
            };
            let work = matches!(
                kind,
                wire::BLOCK
                    | wire::TRANSACTION
                    | wire::GET_BLOCK
                    | wire::GET_TRANSACTION
                    | wire::PARENT_TRANSACTION
            );
            if (work && heavy) || (!work && controls >= 8) {
                continue;
            }
            if work {
                heavy = true;
            } else {
                controls += 1;
            }
            let mut p = self.peers.remove(&id).expect("listed peer");
            let f = p.inbox.take().expect("checked inbox");
            self.receive_bytes -= f.payload.len();
            match self.message(id, &mut p, &f, clock) {
                Ok(true) => {
                    self.round = Some(id);
                    self.peers.insert(id, p);
                }
                Ok(false) => {
                    if work {
                        heavy = false;
                    }
                    self.receive_bytes += f.payload.len();
                    p.inbox = Some(f);
                    self.peers.insert(id, p);
                }
                Err(Error::Protocol) => self.release(id, p),
                Err(e) => {
                    self.release(id, p);
                    self.stopped = true;
                    return Err(e);
                }
            }
        }
        self.schedule(clock)?;
        if !heavy
            && !block_waiting
            && self.sync.is_none()
            && let Err(e) = self.retry_orphan(clock)
        {
            self.stopped = true;
            return Err(e);
        }
        if !block_waiting && self.sync.is_none() {
            self.fetch_parent(clock)?;
        }
        self.relay(clock)?;
        let ids: Vec<_> = self.peers.keys().copied().collect();
        for id in ids {
            let mut p = self.peers.remove(&id).expect("listed peer");
            if p.ready && p.ping.is_none() && now.saturating_sub(p.last_rx) >= 30_000 {
                let nonce = random()?;
                if self.queue(&mut p, wire::PING, &nonce, now)? {
                    p.ping = Some((nonce, now));
                }
            }
            self.peers.insert(id, p);
        }
        Ok(())
    }
    /// Finish between validation jobs. SQLite commits are never interrupted here.
    pub fn shutdown(&mut self) -> Result<(), Error> {
        self.stopped = true;
        let ids: Vec<_> = self.peers.keys().copied().collect();
        for id in ids {
            self.disconnect(id);
        }
        self.store.checkpoint().map_err(|_| Error::Storage)
    }
}

#[cfg(test)]
mod tests;
