//! Bounded session-local catch-up; queued bytes are never a delivery receipt.
use super::*;

const REANNOUNCE_MS: u64 = 600_000;

impl Node {
    pub(super) fn reconcile_relay(&mut self) -> Result<(), Error> {
        let live: BTreeSet<_> = self
            .pool
            .relay_transactions(self.store.chain().map_err(|_| Error::Storage)?)
            .map_err(|_| Error::Storage)?
            .map(|(id, _)| id)
            .collect();
        for peer in self.peers.values_mut() {
            peer.relayed.retain(|id, _| live.contains(id));
        }
        Ok(())
    }

    pub(super) fn relay(&mut self, clock: Clock) -> Result<(), Error> {
        let now = clock.monotonic_ms;
        let tip = self.store.chain().map_err(|_| Error::Storage)?.tip();
        let quota = self
            .limits
            .tx_checks_per_window
            .div_ceil(self.limits.peers as u32)
            .max(1);
        let mut ids: Vec<_> = self.peers.keys().copied().collect();
        if let Some(last) = self.relay_round {
            let split = ids.partition_point(|id| *id <= last);
            ids.rotate_left(split);
        }
        let blocks_waiting = self.peers.values().any(|p| {
            p.inbox
                .as_ref()
                .is_some_and(|f| matches!(f.kind, wire::BLOCK | wire::GET_BLOCK))
        });
        let mut sent = false;
        for id in ids {
            let mut p = self.peers.remove(&id).expect("listed peer");
            let result = (|| {
                if !p.ready {
                    return Ok(());
                }
                // Also notify the source peer of downloaded blocks. Import occurs
                // while that peer is removed from the runtime's peer map.
                if p.announced_tip != tip {
                    if !self.queue(&mut p, wire::TIP, &tip, now)? {
                        return Ok(());
                    }
                    p.announced_tip = tip;
                }
                if now.saturating_sub(p.relay_window) >= WINDOW {
                    p.relay_window = now;
                    p.relay_count = 0;
                }
                if sent
                    || p.tip != tip
                    || p.relay_count >= quota
                    || now < p.relay_next
                    || self.sync.is_some()
                    || blocks_waiting
                    || p.out.len() >= 32
                    || self.send_bytes >= self.limits.send_bytes
                    || self.bulk_bytes >= self.limits.bytes_per_window
                {
                    return Ok(());
                }
                let next = self
                    .pool
                    .relay_transactions(self.store.chain().map_err(|_| Error::Storage)?)
                    .map_err(|_| Error::Storage)?
                    .filter(|(tx, _)| {
                        p.relayed
                            .get(tx)
                            .is_none_or(|at| now.saturating_sub(*at) >= REANNOUNCE_MS)
                    })
                    // None sorts before timestamps; equal keys retain pool order.
                    .min_by_key(|(tx, _)| p.relayed.get(tx).copied())
                    .filter(|(_, raw)| {
                        // Do not skip an unrelayable parent to send later entries.
                        raw.len() <= self.tx_limit
                            && p.out.len() < 32
                            && self
                                .send_bytes
                                .checked_add(wire::HEADER + raw.len())
                                .is_some_and(|n| n <= self.limits.send_bytes)
                            && self
                                .bulk_bytes
                                .checked_add(wire::HEADER + raw.len())
                                .is_some_and(|n| n <= self.limits.bytes_per_window)
                    })
                    .map(|(tx, raw)| (tx, raw.to_vec()));
                if let Some((tx, raw)) = next
                    && self.queue(&mut p, wire::TRANSACTION, &raw, now)?
                {
                    p.relayed.insert(tx, now);
                    p.relay_count += 1;
                    // Space frames as well as limiting bursts: remote monotonic
                    // rate windows need not start at the same instant as ours.
                    p.relay_next = now.saturating_add(WINDOW.div_ceil(u64::from(quota)));
                    self.relay_round = Some(id);
                    sent = true;
                }
                Ok(())
            })();
            self.peers.insert(id, p);
            result?;
        }
        Ok(())
    }
}
