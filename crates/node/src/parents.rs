//! Requested parent bytes are untrusted until normal current-state admission.
use super::*;
const PARENTS: usize = 8;
const IN_FLIGHT: usize = 4;
const REQUESTS: u32 = 8;
const PER_SESSION: u32 = 2;
const DEPTH: u8 = 4;

impl Node {
    fn pending_parent_ids(&self) -> Result<BTreeSet<Hash>, Error> {
        Ok(self
            .pool
            .relay_transactions(self.store.chain().map_err(|_| Error::Storage)?)
            .map_err(|_| Error::Storage)?
            .map(|(id, _)| id)
            .collect())
    }
    pub(crate) fn missing_parent_ids(&self, raw: &[u8]) -> Result<Vec<Hash>, Error> {
        let (_, inputs) = monario_v6::transaction_references(raw).map_err(|_| Error::Protocol)?;
        let known = self.pending_parent_ids()?;
        let chain = self.store.chain().map_err(|_| Error::Storage)?;
        let mut parents = BTreeSet::new();
        for input in inputs {
            if !known.contains(&input.transaction)
                && !chain.ledger().contains_transaction(&input.transaction)
            {
                parents.insert(input.transaction);
                if parents.len() == PARENTS {
                    break;
                }
            }
        }
        Ok(parents.into_iter().collect())
    }
    pub(crate) fn cache_orphan(
        &mut self,
        peer: PeerId,
        raw: &[u8],
        now: u64,
        born: u64,
        depth: u8,
    ) -> Result<(), Error> {
        self.orphans.expire(now);
        if !self.orphans.room(peer, raw.len()) {
            return Ok(());
        }
        let parents = self.missing_parent_ids(raw)?;
        self.orphans.insert(peer, raw, now, born, depth, parents);
        Ok(())
    }
    pub(crate) fn fetch_parent(&mut self, clock: Clock) -> Result<(), Error> {
        let now = clock.monotonic_ms;
        if self.orphans.requests.len() >= IN_FLIGHT
            || self.parent_requests >= REQUESTS
            || self.tx_checks >= self.limits.tx_checks_per_window
        {
            return Ok(());
        }
        let quota = self
            .limits
            .tx_checks_per_window
            .div_ceil(self.limits.peers as u32)
            .max(1);
        for p in self.peers.values_mut() {
            p.window(now);
        }
        let known = self.pending_parent_ids()?;
        let chain = self.store.chain().map_err(|_| Error::Storage)?;
        let candidate = self.orphans.items.iter().find_map(|i| {
            if i.depth >= DEPTH
                || i.tried.len() >= PARENTS
                || self.orphans.requests.contains_key(&i.peer)
                || !self.peers.get(&i.peer).is_some_and(|p| {
                    p.ready && p.tx_checks < quota && p.parent_requests < PER_SESSION
                })
            {
                return None;
            }
            i.parents
                .iter()
                .find(|id| {
                    !i.tried.contains(*id)
                        && !known.contains(*id)
                        && !chain.ledger().contains_transaction(id)
                        && !self.orphans.requests.values().any(|r| r.id == **id)
                })
                .map(|id| (i.peer, *id, i.born, i.depth + 1))
        });
        let Some((peer, id, mut born, mut depth)) = candidate else {
            return Ok(());
        };
        // A shared request inherits the earliest root expiry; it cannot prolong
        // any original dependency by manufacturing fresh quarantine lifetimes.
        for i in &self.orphans.items {
            if i.peer == peer && i.parents.contains(&id) {
                born = born.min(i.born);
                depth = depth.min(i.depth.saturating_add(1));
            }
        }
        let mut p = self.peers.remove(&peer).expect("selected origin");
        let result = (|| {
            if p.out.len() >= 32
                || self
                    .send_bytes
                    .checked_add(wire::HEADER + 48)
                    .is_none_or(|n| n > self.limits.send_bytes)
            {
                return Ok(());
            }
            let token: [u8; 16] = random()?;
            let mut payload = token.to_vec();
            payload.extend(id);
            if self.queue(&mut p, wire::GET_TRANSACTION, &payload, now)? {
                for i in &mut self.orphans.items {
                    if i.peer == peer && i.parents.contains(&id) && i.tried.len() < PARENTS {
                        i.tried.insert(id);
                    }
                }
                self.orphans.requests.insert(
                    peer,
                    Request {
                        id,
                        token,
                        deadline: now.saturating_add(REQUEST_TIMEOUT),
                        born,
                        depth,
                    },
                );
                self.parent_requests += 1;
                p.parent_requests += 1;
            }
            Ok(())
        })();
        self.peers.insert(peer, p);
        result
    }
    pub(crate) fn serve_parent(
        &mut self,
        p: &mut Peer,
        request: &[u8],
        now: u64,
    ) -> Result<bool, Error> {
        p.window(now);
        if p.parent_served >= PER_SESSION || self.parent_served >= REQUESTS {
            return Ok(false);
        }
        let id: Hash = request[16..].try_into().map_err(|_| Error::Protocol)?;
        let raw = self
            .pool
            .relay_transactions(self.store.chain().map_err(|_| Error::Storage)?)
            .map_err(|_| Error::Storage)?
            .find(|(tx, _)| *tx == id)
            .map(|(_, raw)| raw)
            .filter(|raw| raw.len() <= self.tx_limit);
        let (kind, payload) = if let Some(raw) = raw {
            let len = wire::HEADER + 48 + raw.len();
            if p.out.len() >= 32
                || self
                    .send_bytes
                    .checked_add(len)
                    .is_none_or(|n| n > self.limits.send_bytes)
                || self
                    .bulk_bytes
                    .checked_add(len)
                    .is_none_or(|n| n > self.limits.bytes_per_window)
            {
                return Ok(false);
            }
            let mut payload = request.to_vec();
            payload.extend(raw);
            (wire::PARENT_TRANSACTION, payload)
        } else {
            (wire::TRANSACTION_NOT_FOUND, request.to_vec())
        };
        if !self.queue(p, kind, &payload, now)? {
            return Ok(false);
        }
        p.parent_served += 1;
        self.parent_served += 1;
        Ok(true)
    }
    pub(crate) fn parent_response(
        &mut self,
        peer: PeerId,
        p: &mut Peer,
        kind: u8,
        payload: &[u8],
        now: u64,
    ) -> Result<bool, Error> {
        let request = self
            .orphans
            .requests
            .get(&peer)
            .filter(|r| now < r.deadline)
            .ok_or(Error::Protocol)?;
        if payload[..16] != request.token || payload[16..48] != request.id {
            return Err(Error::Protocol);
        }
        let expected_id = request.id;
        if kind == wire::TRANSACTION_NOT_FOUND {
            self.orphans.requests.remove(&peer);
            return Ok(true);
        }
        if !self.reserve_replay_lookup(payload.len() - 48) {
            return Ok(false);
        }
        if let Some(id) = self
            .pool
            .known_transaction(
                self.store.chain().map_err(|_| Error::Storage)?,
                &payload[48..],
            )
            .map_err(|_| Error::Storage)?
        {
            if id != expected_id {
                return Err(Error::Protocol);
            }
            self.orphans.requests.remove(&peer);
            p.relayed.insert(id, now);
            return Ok(true);
        }
        p.window(now);
        let quota = self
            .limits
            .tx_checks_per_window
            .div_ceil(self.limits.peers as u32)
            .max(1);
        if self.tx_checks >= self.limits.tx_checks_per_window || p.tx_checks >= quota {
            return Ok(false);
        }
        self.tx_checks += 1;
        p.tx_checks += 1;
        let request = self
            .orphans
            .requests
            .remove(&peer)
            .expect("matched request");
        let raw = &payload[48..];
        let (id, _) = monario_v6::transaction_references(raw).map_err(|_| Error::Protocol)?;
        if id != request.id {
            return Err(Error::Protocol);
        }
        let needed = self.orphans.items.iter().any(|i| {
            i.peer == peer && i.parents.contains(&id) && now.saturating_sub(i.born) < LIFETIME
        });
        if !needed
            || self.pending_parent_ids()?.contains(&id)
            || self
                .store
                .chain()
                .map_err(|_| Error::Storage)?
                .ledger()
                .contains_transaction(&id)
        {
            return Ok(true);
        }
        match self.pool.admit(
            self.store.chain().map_err(|_| Error::Storage)?,
            raw.to_vec(),
        ) {
            Ok(id) => {
                self.orphans.wake();
                p.relayed.insert(id, now);
            }
            Err(mempool::Error::Stale | mempool::Error::Storage) => return Err(Error::Storage),
            Err(e) if missing(&e) => {
                self.cache_orphan(peer, raw, now, request.born, request.depth)?
            }
            Err(_) => {} // No admission receipt is inferred from a matching response ID.
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{clock, node};
    #[test]
    fn global_inflight_window_and_session_request_limits_are_hard_bounds() {
        let (_dir, mut n) = node();
        n.limits.peers = 8;
        for i in 0..8 {
            let p = n.add_peer(clock(0)).unwrap();
            n.peers.get_mut(&p).unwrap().ready = true;
            n.orphans.insert(
                p,
                &[i],
                0,
                0,
                0,
                (0..8).map(|k| [i * 8 + k + 1; 32]).collect(),
            );
        }
        for _ in 0..16 {
            n.fetch_parent(clock(0)).unwrap();
        }
        assert_eq!(n.orphans.requests.len(), IN_FLIGHT);
        assert_eq!(n.parent_requests, 4);
        n.orphans.requests.clear();
        for _ in 0..16 {
            n.fetch_parent(clock(0)).unwrap();
        }
        assert_eq!(n.parent_requests, REQUESTS);
        assert_eq!(n.orphans.requests.len(), IN_FLIGHT);
        assert!(n.peers.values().all(|p| p.parent_requests <= PER_SESSION));
    }
    #[test]
    fn depth_attempt_count_and_inherited_root_lifetime_cannot_be_reset_by_responses() {
        let (_dir, mut n) = node();
        let p = n.add_peer(clock(0)).unwrap();
        n.peers.get_mut(&p).unwrap().ready = true;
        n.orphans
            .insert(p, &[1], 0, 0, DEPTH, (1..=8).map(|i| [i; 32]).collect());
        n.fetch_parent(clock(0)).unwrap();
        assert!(n.orphans.requests.is_empty());
        n.orphans.items[0].depth = 0;
        for step in 0..8 {
            let now = (step / 2) * WINDOW;
            n.clock(clock(now)).unwrap();
            n.fetch_parent(clock(now)).unwrap();
            assert_eq!(n.orphans.requests.len(), 1);
            n.orphans.requests.clear();
        }
        assert_eq!(n.orphans.items[0].tried.len(), PARENTS);
        n.orphans.items[0].parents = vec![[99; 32]];
        n.clock(clock(4 * WINDOW)).unwrap();
        n.fetch_parent(clock(4 * WINDOW)).unwrap();
        assert!(n.orphans.requests.is_empty());
        n.orphans
            .insert(p, &[3], 4 * WINDOW, 4 * WINDOW, 0, vec![[99; 32]]);
        n.fetch_parent(clock(4 * WINDOW)).unwrap();
        assert_eq!(n.orphans.items[0].tried.len(), PARENTS);
        assert_eq!(n.orphans.items[1].tried.len(), 1);
        n.orphans.requests.clear();
        n.orphans.items.clear();
        n.orphans.bytes = 0;
        // Even a response arriving much later inherits the original root birth.
        n.orphans.insert(p, &[2], 30_000, 3, 1, Vec::new());
        assert_eq!(n.orphans.items[0].born, 3);
        n.orphans.expire(60_003);
        assert!(n.orphans.items.is_empty());
    }
}
