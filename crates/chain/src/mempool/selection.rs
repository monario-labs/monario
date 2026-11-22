//! Bounded ancestor-aware fee ordering, with atomic contextual package validation.
use super::*;
#[path = "packages.rs"]
mod packages;
use packages::Packages;

/// Diagnostic selection, not a validity receipt. The block builder verifies it again.
pub struct Selection {
    pub transactions: Vec<Vec<u8>>,
    pub ids: Vec<Hash>,
    pub fees: Amount,
    pub skipped: Vec<(Hash, Error)>,
}
impl Mempool {
    /// Highest marginal ancestor-package fee/byte, then ascending candidate ID.
    /// Packages over 25 entries fall back to dependency-ready individual scoring.
    /// This is bounded local greedy policy, not global fee maximization/consensus.
    pub fn select<V: TransactionVerifier>(
        &self,
        c: &Chain<V>,
        coinbase_reserve: usize,
    ) -> Result<Selection, Error> {
        self.current(c)?;
        let cap = c
            .config
            .limits
            .block_bytes
            .min(crate::archive::MAX_BLOCK_BYTES);
        if coinbase_reserve == 0 || coinbase_reserve > c.config.limits.transaction_bytes {
            return Err(Error::Configuration);
        }
        let height = c
            .height()
            .checked_add(1)
            .ok_or(Error::Invalid(ChainError::HeightOverflow))?;
        let mut size = crate::header::HEADER_LEN
            .checked_add(coinbase_reserve)
            .ok_or(Error::Capacity)?;
        if size.saturating_add(crate::wire::compact_size_len(1)) > cap {
            return Err(Error::Capacity);
        }
        let mut graph = Packages::new(&self.entries)?;
        let mut ready = BTreeSet::new();
        for i in 0..self.len() {
            if !graph.large[i] || graph.pending[i] == 0 {
                ready.insert(graph.scores[i]);
            }
        }
        let mut selected = Overlay::new(c.ledger());
        let mut records = Vec::new();
        let mut actions = 0_u64;
        let mut shield_cost = 0_u64;
        let mut done = vec![false; self.len()];
        let mut rejected: Vec<Option<Error>> = (0..self.len()).map(|_| None).collect();
        let mut checks = 0;
        let work_limit = self.len() * 2;
        let mut out = Selection {
            transactions: Vec::new(),
            ids: Vec::new(),
            fees: Amount::ZERO,
            skipped: Vec::new(),
        };
        while let Some(score) = ready.pop_last() {
            let i = score.index;
            let members: Vec<_> = graph.members[i]
                .iter()
                .copied()
                .filter(|&j| !done[j])
                .collect();
            if members.iter().any(|&j| rejected[j].is_some()) {
                rejected[i] = Some(Error::Conflict);
                continue;
            }
            let count = out.transactions.len() + members.len() + 1;
            if count > c.config.limits.transactions
                || size
                    .saturating_add(score.bytes)
                    .saturating_add(crate::wire::compact_size_len(count))
                    > cap
            {
                rejected[i] = Some(Error::Capacity);
                continue;
            }
            let mut trial = Overlay::new(&selected);
            let mut next_records = records.clone();
            let mut next_fees = out.fees;
            let mut next_actions = actions;
            let mut next_cost = shield_cost;
            let mut failure = None;
            let mut limited = false;
            for &j in &members {
                if checks == work_limit {
                    failure = Some((i, Error::Capacity));
                    limited = true;
                    break;
                }
                checks += 1;
                let e = &self.entries[j];
                let result = c
                    .stage_transaction(
                        &e.raw,
                        TransactionContext {
                            height,
                            median_time_past: c.median_time_past(),
                            state: c.ledger(),
                        },
                        false,
                        &mut trial,
                        &mut next_records,
                    )
                    .and_then(|tx| {
                        if tx.id != e.id || tx.fee != e.fee {
                            return Err(ChainError::StateMismatch);
                        }
                        // Deterministic shielded budget, exactly as block validation
                        // will enforce it. A later smaller package may still fit.
                        next_actions = next_actions
                            .checked_add(tx.shielded_actions)
                            .ok_or(ChainError::ShieldedLimit)?;
                        next_cost = next_cost
                            .checked_add(crate::shielded::cost(tx.shielded_actions))
                            .ok_or(ChainError::ShieldedLimit)?;
                        if next_actions > crate::shielded::MAX_ACTIONS_PER_BLOCK
                            || next_cost > crate::shielded::MAX_COST_PER_BLOCK
                        {
                            return Err(ChainError::ShieldedLimit);
                        }
                        next_fees = next_fees
                            .checked_add(tx.fee)
                            .map_err(|_| ChainError::Amount)?;
                        Ok(())
                    });
                if let Err(error) = result {
                    failure = Some((j, Error::Invalid(error)));
                    break;
                }
            }
            if failure.is_none() {
                let mut services = Overlay::new(&trial);
                let result = c
                    .apply_services(c.tip(), height, c.ledger(), &mut services, &next_records)
                    .and_then(|_| {
                        if services.shielded().balance > c.ledger().supply() {
                            Err(ChainError::Amount)
                        } else {
                            Ok(())
                        }
                    });
                if let Err(error) = result {
                    failure = Some((i, Error::Invalid(error)));
                }
            }
            if let Some((bad, error)) = failure {
                ready.remove(&graph.scores[bad]);
                rejected[bad] = Some(error);
                if bad != i {
                    rejected[i] = Some(Error::Conflict);
                }
                if limited {
                    for j in 0..self.len() {
                        if !done[j] && rejected[j].is_none() {
                            rejected[j] = Some(Error::Capacity);
                        }
                    }
                    break;
                }
                continue;
            }
            selected
                .apply(&trial.finish(), false)
                .map_err(Error::Invalid)?;
            records = next_records;
            out.fees = next_fees;
            actions = next_actions;
            shield_cost = next_cost;
            size += score.bytes;
            for &j in &members {
                ready.remove(&graph.scores[j]);
                done[j] = true;
                out.transactions.push(self.entries[j].raw.clone());
                out.ids.push(self.entries[j].id);
            }
            for &j in &members {
                for &child in &graph.children[j] {
                    graph.pending[child] -= 1;
                    if graph.large[child]
                        && graph.pending[child] == 0
                        && !done[child]
                        && rejected[child].is_none()
                    {
                        ready.insert(graph.scores[child]);
                    }
                }
                for &owner in &graph.owners[j] {
                    if done[owner] || rejected[owner].is_some() {
                        continue;
                    }
                    ready.remove(&graph.scores[owner]);
                    graph.scores[owner].fee -= self.entries[j].fee.atoms();
                    graph.scores[owner].bytes -= self.entries[j].raw.len();
                    ready.insert(graph.scores[owner]);
                }
            }
        }
        for (j, error) in rejected.into_iter().enumerate() {
            if !done[j] {
                out.skipped
                    .push((self.entries[j].id, error.unwrap_or(Error::Conflict)));
            }
        }
        Ok(out)
    }
}
