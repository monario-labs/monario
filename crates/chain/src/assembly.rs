//! Read-only candidate assembly. No PoW search, submission, persistence or network.
use crate::{
    Block, Chain, Error, Hash, LedgerView, Overlay,
    header::{HEADER_LEN, HEADER_VERSION, Header, merkle_root},
    shielded,
    transactions::{TransactionContext, TransactionVerifier},
};
use monario_monetary::{Amount, rewards::miner_reward};

/// Calculated from fully verified ordered transactions and authenticated branch state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoinbasePlan {
    pub parent: Hash,
    pub height: u64,
    pub fees: Amount,
    pub miner_maximum: Amount,
}

/// A candidate is not an acceptance receipt. Its nonce is zero and no PoW is checked.
pub struct BlockTemplate {
    pub block: Block,
    pub coinbase: CoinbasePlan,
    pub pow_seed: Hash,
}

impl<V: TransactionVerifier> Chain<V> {
    /// Assemble against any retained validated parent without modifying this chain.
    /// `now` is the trusted caller's clock, as in submit. The callback only encodes
    /// the coinbase: returned bytes receive the same checks as all block submissions.
    /// This method never invokes RandomX or searches a nonce.
    pub fn build_template(
        &self,
        parent: Hash,
        timestamp: u64,
        now: u64,
        transactions: Vec<Vec<u8>>,
        make_coinbase: impl FnOnce(&CoinbasePlan) -> Result<Vec<u8>, Error>,
    ) -> Result<BlockTemplate, Error> {
        let p = self.nodes.get(&parent).ok_or(Error::UnknownParent)?;
        let height = p.height.checked_add(1).ok_or(Error::HeightOverflow)?;
        if height > crate::consensus::MAX_BLOCK_HEIGHT {
            return Err(Error::HeightOverflow);
        }
        let median = self.median_time(parent);
        if timestamp <= median {
            return Err(Error::MedianTime);
        }
        if timestamp > now.saturating_add(u64::from(self.config.max_future_seconds)) {
            return Err(Error::FutureTime);
        }
        let count = transactions
            .len()
            .checked_add(1)
            .ok_or(Error::ResourceLimit)?;
        if count > self.config.limits.transactions {
            return Err(Error::ResourceLimit);
        }
        let cap = self
            .config
            .limits
            .block_bytes
            .min(crate::archive::MAX_BLOCK_BYTES);
        // Include count/header and reserve at least one byte for the coinbase.
        let mut size = HEADER_LEN + crate::wire::compact_size_len(count) + 1;
        if size > cap {
            return Err(Error::ResourceLimit);
        }
        for raw in &transactions {
            if raw.is_empty() || raw.len() > self.config.limits.transaction_bytes {
                return Err(Error::ResourceLimit);
            }
            size = size.checked_add(raw.len()).ok_or(Error::ResourceLimit)?;
            if size > cap {
                return Err(Error::ResourceLimit);
            }
        }
        let bits = if height == 1 {
            self.config.initial_bits
        } else {
            self.asert
                .next_bits(p.height, p.timestamp)
                .map_err(Error::Pow)?
        };
        let pow_seed = self.seed_for(parent, height)?;
        let (detach, attach) = self.route(self.tip(), parent)?;
        let mut base = Overlay::new(self.ledger());
        for id in detach {
            base.apply(
                self.nodes[&id].delta.as_ref().ok_or(Error::StateMismatch)?,
                true,
            )?;
        }
        for id in attach {
            base.apply(
                self.nodes[&id].delta.as_ref().ok_or(Error::StateMismatch)?,
                false,
            )?;
        }
        let mut staged = Overlay::new(&base);
        let mut records = Vec::new();
        let mut authorizations = Vec::with_capacity(count);
        let mut fees = Amount::ZERO;
        let mut shield_actions = 0_u64;
        let mut shield_cost = 0_u64;
        for raw in &transactions {
            let tx = self.stage_transaction(
                raw,
                TransactionContext {
                    height,
                    median_time_past: median,
                    state: &base,
                },
                false,
                &mut staged,
                &mut records,
            )?;
            shield_actions = shield_actions
                .checked_add(tx.shielded_actions)
                .ok_or(Error::ShieldedLimit)?;
            shield_cost = shield_cost
                .checked_add(shielded::cost(tx.shielded_actions))
                .ok_or(Error::ShieldedLimit)?;
            if shield_actions > shielded::MAX_ACTIONS_PER_BLOCK
                || shield_cost > shielded::MAX_COST_PER_BLOCK
            {
                return Err(Error::ShieldedLimit);
            }
            fees = fees.checked_add(tx.fee).map_err(|_| Error::Amount)?;
            authorizations.push((tx.id, tx.authorization_digest));
        }
        self.apply_services(parent, height, &base, &mut staged, &records)?;
        let coinbase = CoinbasePlan {
            parent,
            height,
            fees,
            miner_maximum: miner_reward(height, fees).map_err(|_| Error::Amount)?,
        };
        let raw = make_coinbase(&coinbase)?;
        // Bound the completed candidate before doing more signature/proof work.
        if raw.is_empty()
            || raw.len() > self.config.limits.transaction_bytes
            || size
                .checked_sub(1)
                .and_then(|n| n.checked_add(raw.len()))
                .is_none_or(|n| n > cap)
        {
            return Err(Error::ResourceLimit);
        }
        let tx = self.stage_transaction(
            &raw,
            TransactionContext {
                height,
                median_time_past: median,
                state: &base,
            },
            true,
            &mut staged,
            &mut records,
        )?;
        authorizations.insert(0, (tx.id, tx.authorization_digest));
        let merkle_root = merkle_root(&authorizations.iter().map(|p| p.0).collect::<Vec<_>>())?;
        let commitment = self
            .verifier
            .block_commitment_with_state(
                p.commitment,
                height,
                &authorizations,
                staged.shielded().root(),
            )
            .map_err(Error::Transaction)?;
        let mut all = Vec::with_capacity(count);
        all.push(raw);
        all.extend(transactions);
        let block = Block {
            header: Header {
                version: HEADER_VERSION,
                parent,
                merkle_root,
                commitment,
                timestamp,
                bits,
                nonce: [0; 32],
            },
            transactions: all,
        };
        self.check_body_limits(&block)?;
        // Re-run the ordinary body path in canonical coinbase-first order. This
        // rejects callback mistakes, collisions, supply errors and invalid coinbase values;
        // planning effects are never trusted as a portable validation receipt.
        self.validate_body(&block, height, median, p.commitment, &base)?;
        Ok(BlockTemplate {
            block,
            coinbase,
            pow_seed,
        })
    }
}

#[cfg(test)]
mod tests;
