//! Untrusted, session-local bytes awaiting transparent inputs. Never relay as valid.
use super::*;
#[path = "parents.rs"]
mod parents;
use monario_chain::{Error as ChainError, transactions::TransactionError};
use sha2::{Digest, Sha256};

const COUNT: usize = 64;
const BYTES: usize = 1_048_576;
const PER_PEER: usize = 2;
const LIFETIME: u64 = 60_000;
struct Item {
    peer: PeerId,
    digest: Hash,
    raw: Vec<u8>,
    born: u64,
    pending: bool,
    parents: Vec<Hash>,
    tried: BTreeSet<Hash>,
    depth: u8,
}
struct Request {
    id: Hash,
    token: [u8; 16],
    deadline: u64,
    born: u64,
    depth: u8,
}
#[derive(Default)]
pub(super) struct Orphans {
    items: VecDeque<Item>,
    bytes: usize,
    requests: BTreeMap<PeerId, Request>,
}
pub(super) fn missing(error: &mempool::Error) -> bool {
    matches!(
        error,
        mempool::Error::Invalid(
            ChainError::MissingInput | ChainError::Transaction(TransactionError::MissingInput)
        )
    )
}
impl Orphans {
    pub(super) fn expire(&mut self, now: u64) {
        self.items.retain(|i| now.saturating_sub(i.born) < LIFETIME);
        self.requests.retain(|_, r| now < r.deadline);
        self.bytes = self.items.iter().map(|i| i.raw.len()).sum();
    }
    pub(super) fn disconnect(&mut self, peer: PeerId) {
        self.requests.remove(&peer);
        self.items.retain(|i| i.peer != peer);
        self.bytes = self.items.iter().map(|i| i.raw.len()).sum();
    }
    pub(super) fn wake(&mut self) {
        for item in &mut self.items {
            item.pending = true;
        }
    }
    pub(super) fn expected(&self, peer: PeerId, now: u64) -> bool {
        self.requests.get(&peer).is_some_and(|r| now < r.deadline)
    }
    fn room(&self, peer: PeerId, len: usize) -> bool {
        len != 0
            && self.items.len() < COUNT
            && self.bytes.checked_add(len).is_some_and(|n| n <= BYTES)
            && self.items.iter().filter(|i| i.peer == peer).count() < PER_PEER
    }
    #[cfg(test)]
    fn remember(&mut self, peer: PeerId, raw: &[u8], now: u64) {
        self.insert(peer, raw, now, now, 0, Vec::new());
    }
    fn insert(
        &mut self,
        peer: PeerId,
        raw: &[u8],
        now: u64,
        born: u64,
        depth: u8,
        parents: Vec<Hash>,
    ) {
        self.expire(now);
        if !self.room(peer, raw.len()) || now.saturating_sub(born) >= LIFETIME {
            return;
        }
        let mut h = Sha256::new();
        h.update(b"Monario/orphan-payload/v1\0");
        h.update(raw);
        let digest = h.finalize().into();
        if self.items.iter().any(|i| i.digest == digest) {
            return;
        }
        self.bytes += raw.len();
        self.items.push_back(Item {
            peer,
            digest,
            raw: raw.to_vec(),
            born,
            pending: false,
            parents,
            tried: BTreeSet::new(),
            depth,
        });
    }
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.items.len()
    }
}
impl Node {
    pub(super) fn retry_orphan(&mut self, clock: Clock) -> Result<(), Error> {
        let now = clock.monotonic_ms;
        if self.tx_checks >= self.limits.tx_checks_per_window {
            return Ok(());
        }
        let quota = self
            .limits
            .tx_checks_per_window
            .div_ceil(self.limits.peers as u32)
            .max(1);
        for peer in self.peers.values_mut() {
            peer.window(now);
        }
        let Some(index) = self.orphans.items.iter().position(|i| {
            i.pending
                && self
                    .peers
                    .get(&i.peer)
                    .is_some_and(|p| p.ready && p.tx_checks < quota)
        }) else {
            return Ok(());
        };
        let mut item = self.orphans.items.remove(index).expect("selected orphan");
        self.orphans.bytes -= item.raw.len();
        self.tx_checks += 1;
        self.peers
            .get_mut(&item.peer)
            .expect("checked peer")
            .tx_checks += 1;
        match self.pool.admit(
            self.store.chain().map_err(|_| Error::Storage)?,
            item.raw.clone(),
        ) {
            Ok(id) => {
                self.orphans.wake();
                self.peers
                    .get_mut(&item.peer)
                    .expect("owner thread")
                    .relayed
                    .insert(id, now);
            }
            Err(mempool::Error::Stale | mempool::Error::Storage) => return Err(Error::Storage),
            Err(e) if missing(&e) || e == mempool::Error::Capacity => {
                if missing(&e) {
                    item.parents = self.missing_parent_ids(&item.raw)?;
                }
                item.pending = false;
                self.orphans.bytes += item.raw.len();
                self.orphans.items.push_back(item);
            }
            Err(_) => {} // Context/signature/policy rejection drops untrusted quarantine bytes.
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn count_bytes_peer_limits_duplicates_expiry_and_disconnect_are_bounded() {
        let mut q = Orphans::default();
        for p in 0..32 {
            for n in 0..3 {
                q.remember([p; 16], &[p, n], 0);
            }
        }
        assert_eq!(q.len(), 64);
        assert_eq!(q.bytes, 128);
        q.remember([99; 16], &[99], 1);
        assert_eq!(q.len(), 64);
        q.disconnect([0; 16]);
        assert_eq!(q.len(), 62);
        q.expire(LIFETIME);
        assert_eq!(q.len(), 0);
        assert_eq!(q.bytes, 0);
        q.remember([1; 16], &vec![1; BYTES], 0);
        q.remember([2; 16], &[2], 1);
        assert_eq!(q.len(), 1);
        assert_eq!(q.bytes, BYTES);
        q.expire(LIFETIME);
        q.remember([1; 16], &[7], LIFETIME);
        q.remember([2; 16], &[7], LIFETIME + 1);
        assert_eq!(q.len(), 1);
        assert_eq!(q.items[0].born, LIFETIME);
        q.remember([1; 16], &[7], 2 * LIFETIME - 1);
        q.expire(2 * LIFETIME);
        assert_eq!(q.len(), 0);
        q.remember([1; 16], &[], 2 * LIFETIME);
        q.remember([1; 16], &vec![0; BYTES + 1], 2 * LIFETIME);
        assert_eq!(q.len(), 0);
    }
}
