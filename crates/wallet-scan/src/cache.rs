//! Versioned authenticated derived state. Never import an unauthenticated projection.
use super::private_cache::PrivateChecks;
use super::*;
use monario_wallet::storage::WalletStore;
use std::io::{Cursor, Read};
use zcash_primitives::merkle_tree::{write_commitment_tree, write_incremental_witness};

pub(super) const MAX: usize = 4 * 1024 * 1024;
const HISTORY_BYTES: usize = 2 * 1024 * 1024;
const HISTORY_BLOCKS: usize = 128;
const HISTORY_MAGIC: &[u8; 8] = b"MONWUD02";
const LEGACY_HISTORY_MAGIC: &[u8; 8] = b"MONWUD01";
pub(super) fn invalid(_: impl std::fmt::Debug) -> Error {
    Error::InvalidBody
}
pub(super) fn bytes<const N: usize>(r: &mut Cursor<&[u8]>) -> Result<[u8; N], Error> {
    let mut b = [0; N];
    r.read_exact(&mut b).map_err(invalid)?;
    Ok(b)
}
pub(super) fn count(r: &mut Cursor<&[u8]>, max: usize) -> Result<usize, Error> {
    let n = u32::from_le_bytes(bytes(r)?) as usize;
    if n > max {
        return Err(Error::Capacity);
    }
    Ok(n)
}
pub(super) fn blob<'a>(r: &mut Cursor<&'a [u8]>, max: usize) -> Result<&'a [u8], Error> {
    let n = count(r, max)?;
    let start = r.position() as usize;
    let end = start.checked_add(n).ok_or(Error::Capacity)?;
    let b = r.get_ref().get(start..end).ok_or(Error::InvalidBody)?;
    r.set_position(end as u64);
    Ok(b)
}
pub(super) fn put(b: &mut Vec<u8>, data: &[u8]) -> Result<(), Error> {
    let n = u32::try_from(data.len()).map_err(invalid)?;
    if b.len().saturating_add(data.len()).saturating_add(4) > MAX {
        return Err(Error::Capacity);
    }
    b.extend(n.to_le_bytes());
    b.extend(data);
    Ok(())
}
impl Scanner {
    /// Last projected block, which may precede the current validated tip.
    pub fn scanned_tip(&self) -> Hash {
        self.state.tip
    }
    /// Whether the last successful restore migrated an older cache format.
    /// Callers can persist the upgrade even when no new block was scanned.
    pub fn cache_was_migrated(&self) -> bool {
        self.cache_migrated
    }
    fn binding(&self) -> Vec<u8> {
        let mut b = b"Monario/wallet-scan/v1\0".to_vec();
        b.extend(self.profile);
        b.extend(self.root);
        for n in [
            self.limits.accounts,
            self.limits.transparent_addresses,
            self.limits.unspent_coins,
            self.limits.unspent_notes,
        ] {
            b.extend((n as u64).to_le_bytes());
        }
        b.extend((self.accounts.len() as u32).to_le_bytes());
        for a in &self.accounts {
            b.extend(a.id.to_le_bytes());
            b.extend(a.viewing.to_bytes());
            b.extend((a.scripts.len() as u32).to_le_bytes());
            for (script, (scope, index)) in &a.scripts {
                b.extend((script.len() as u32).to_le_bytes());
                b.extend(script);
                b.push(u8::from(*scope == Scope::Internal));
                b.extend(index.to_le_bytes());
            }
        }
        b
    }
    pub(super) fn encode_state(&self, s: &State) -> Result<Zeroizing<Vec<u8>>, Error> {
        #[cfg(test)]
        crate::restore_metrics::COUNTERS.with(|c| c.borrow_mut().encodes += 1);
        let mut b = Zeroizing::new(Vec::new());
        let binding = Zeroizing::new(self.binding());
        put(&mut b, &binding)?;
        b.extend(s.tip);
        b.extend(s.height.to_le_bytes());
        let mut tree = Vec::new();
        write_commitment_tree(&s.tree, &mut tree).map_err(invalid)?;
        put(&mut b, &tree)?;
        b.extend((s.coins.len() as u32).to_le_bytes());
        for (op, (account, c)) in &s.coins {
            b.extend(op.transaction);
            b.extend(op.index.to_le_bytes());
            b.extend(account.to_le_bytes());
            b.extend(c.value.atoms().to_le_bytes());
            b.extend(c.created_height.to_le_bytes());
            b.push(u8::from(c.coinbase));
            put(&mut b, &c.script)?;
        }
        b.extend((s.notes.len() as u32).to_le_bytes());
        for (nf, n) in &s.notes {
            b.extend(nf);
            b.extend(n.account.to_le_bytes());
            b.push(u8::from(n.scope == Scope::Internal));
            b.extend(n.index.to_le_bytes());
            b.extend(n.note.recipient().to_raw_address_bytes());
            b.extend(n.note.value().inner().to_le_bytes());
            b.extend(n.note.rho().to_bytes());
            b.extend(n.note.rseed().as_bytes());
            b.push(match n.note.version() {
                orchard::note::NoteVersion::V2 => 2,
                orchard::note::NoteVersion::V3 => 3,
            });
            b.extend_from_slice(n.memo.as_slice());
            let mut witness = Vec::new();
            write_incremental_witness(&n.witness, &mut witness).map_err(invalid)?;
            put(&mut b, &witness)?;
        }
        b.extend((s.observed.len() as u32).to_le_bytes());
        for (id, p) in &s.observed {
            b.extend(id.to_le_bytes());
            b.extend(p.transparent_external.to_le_bytes());
            b.extend(p.transparent_internal.to_le_bytes());
            b.extend(p.private_external.to_le_bytes());
            b.extend(p.private_internal.to_le_bytes());
        }
        if b.len() > MAX {
            return Err(Error::Capacity);
        }
        Ok(b)
    }
    /// Restore only a wallet-authenticated cache. Unknown tips and changed discovery
    /// scopes are cache misses; retained ancestors permit incremental reorg recovery.
    /// Previously authenticated bodies are not read again. This is not an import API.
    pub fn restore_cache(
        &mut self,
        store: &WalletStore,
        source: &DurableChain<V6Verifier>,
        context: Hash,
    ) -> Result<bool, Error> {
        self.check_source(source)?;
        let Some(plain) = store.load_scan_cache(context).map_err(invalid)? else {
            return Ok(false);
        };
        // The canonical projection stays the prefix; the versioned trailer
        // contains either legacy snapshots or compact reverse deltas.
        let mut checks = PrivateChecks::default();
        let mut r = Cursor::new(plain.as_slice());
        let Some(state) = self.read_state(source, &mut r, &mut checks)? else {
            return Ok(false);
        };
        let mut history = VecDeque::new();
        let mut migrated = true;
        if r.position() as usize != plain.len() {
            let magic = bytes::<8>(&mut r)?;
            if &magic != HISTORY_MAGIC && &magic != LEGACY_HISTORY_MAGIC {
                return Err(Error::InvalidBody);
            }
            migrated = &magic == LEGACY_HISTORY_MAGIC;
            let mut total = 0usize;
            let mut records = VecDeque::new();
            for _ in 0..count(&mut r, HISTORY_BLOCKS)? {
                let encoded = blob(&mut r, HISTORY_BYTES)?;
                total = total
                    .checked_add(encoded.len() + 4)
                    .ok_or(Error::Capacity)?;
                if total > HISTORY_BYTES {
                    return Err(Error::Capacity);
                }
                records.push_back(Zeroizing::new(encoded.to_vec()));
            }
            if r.position() as usize != plain.len() {
                return Err(Error::InvalidBody);
            }
            if migrated {
                let mut previous: Option<State> = None;
                for encoded in records {
                    let next = self
                        .decode_state_checked(source, &encoded, &mut checks)?
                        .ok_or(Error::InvalidBody)?;
                    if let Some(old) = previous {
                        if source
                            .block_info(&next.tip)
                            .map_err(Error::Chain)?
                            .and_then(|b| b.parent)
                            != Some(old.tip)
                        {
                            return Err(Error::InvalidBody);
                        }
                        self.remember(&mut history, &old, &next)?;
                    }
                    previous = Some(next);
                }
                if let Some(old) = previous {
                    if source
                        .block_info(&state.tip)
                        .map_err(Error::Chain)?
                        .and_then(|b| b.parent)
                        != Some(old.tip)
                    {
                        return Err(Error::InvalidBody);
                    }
                    self.remember(&mut history, &old, &state)?;
                }
            } else if !records.is_empty() {
                let mut child = self.capture_rollback(&state)?.ok_or(Error::Capacity)?;
                for encoded in records.into_iter().rev() {
                    let (parent, prepared) =
                        self.apply_prepared_delta_checked(source, &child, &encoded, &mut checks)?;
                    history.push_front((parent.tip, encoded));
                    child = prepared;
                }
            }
        }
        self.trim_history(&mut history, &state)?;
        self.state = state;
        self.history = history;
        self.cache_migrated = migrated;
        Ok(true)
    }
    /// Test-only pre-optimization v2 restore oracle. No cached hashes/encodings.
    #[cfg(test)]
    pub(super) fn restore_cache_reference(
        &mut self,
        store: &WalletStore,
        source: &DurableChain<V6Verifier>,
        context: Hash,
    ) -> Result<bool, Error> {
        self.check_source(source)?;
        let Some(plain) = store.load_scan_cache(context).map_err(invalid)? else {
            return Ok(false);
        };
        let mut r = Cursor::new(plain.as_slice());
        let Some(state) = self.read_state(source, &mut r, &mut PrivateChecks::uncached())? else {
            return Ok(false);
        };
        if &bytes::<8>(&mut r)? != HISTORY_MAGIC {
            return Err(Error::InvalidBody);
        }
        let mut records = VecDeque::new();
        let mut total = 0usize;
        for _ in 0..count(&mut r, HISTORY_BLOCKS)? {
            let encoded = blob(&mut r, HISTORY_BYTES)?;
            total += encoded.len() + 4;
            if total > HISTORY_BYTES {
                return Err(Error::Capacity);
            }
            records.push_back(Zeroizing::new(encoded.to_vec()));
        }
        if r.position() as usize != plain.len() {
            return Err(Error::InvalidBody);
        }
        let mut child = state.clone();
        let mut history = VecDeque::new();
        for encoded in records.into_iter().rev() {
            child = self.apply_delta_reference(source, &child, &encoded)?;
            history.push_front((child.tip, encoded));
        }
        self.trim_history(&mut history, &state)?;
        self.state = state;
        self.history = history;
        self.cache_migrated = false;
        Ok(true)
    }
    #[cfg(test)]
    pub(super) fn decode_state(
        &self,
        source: &DurableChain<V6Verifier>,
        plain: &[u8],
    ) -> Result<Option<State>, Error> {
        self.decode_state_checked(source, plain, &mut PrivateChecks::uncached())
    }
    pub(super) fn decode_state_checked(
        &self,
        source: &DurableChain<V6Verifier>,
        plain: &[u8],
        checks: &mut PrivateChecks,
    ) -> Result<Option<State>, Error> {
        let mut r = Cursor::new(plain);
        let state = self.read_state(source, &mut r, checks)?;
        if r.position() as usize != plain.len() {
            return Err(Error::InvalidBody);
        }
        Ok(state)
    }
    fn read_state(
        &self,
        source: &DurableChain<V6Verifier>,
        r: &mut Cursor<&[u8]>,
        checks: &mut PrivateChecks,
    ) -> Result<Option<State>, Error> {
        let start = r.position() as usize;
        let binding = Zeroizing::new(self.binding());
        if blob(r, MAX)? != binding.as_slice() {
            return Ok(None);
        }
        let tip = bytes(r)?;
        let height = u64::from_le_bytes(bytes(r)?);
        let Some(info) = source.block_info(&tip).map_err(Error::Chain)? else {
            return Ok(None);
        };
        if info.height != height {
            return Err(Error::InvalidBody);
        }
        let tree = checks.read_tree(r, self.profile, info.shielded_root)?;
        let mut s = State {
            tip,
            height,
            tree,
            coins: BTreeMap::new(),
            notes: BTreeMap::new(),
            observed: BTreeMap::new(),
        };
        for _ in 0..count(r, self.limits.unspent_coins)? {
            let op = OutPoint {
                transaction: bytes(r)?,
                index: u32::from_le_bytes(bytes(r)?),
            };
            let account = u32::from_le_bytes(bytes(r)?);
            let value = Amount::from_atoms(u64::from_le_bytes(bytes(r)?)).map_err(invalid)?;
            let created_height = u64::from_le_bytes(bytes(r)?);
            let coinbase = match bytes::<1>(r)?[0] {
                0 => false,
                1 => true,
                _ => return Err(Error::InvalidBody),
            };
            let script = blob(r, 10000)?.to_vec();
            if created_height > height
                || self.scripts.get(&script).map(|v| v.0) != Some(account)
                || s.coins
                    .insert(
                        op,
                        (
                            account,
                            Coin {
                                value,
                                script,
                                created_height,
                                coinbase,
                            },
                        ),
                    )
                    .is_some()
            {
                return Err(Error::InvalidBody);
            }
        }
        for _ in 0..count(r, self.limits.unspent_notes)? {
            let (nf, note) =
                checks.read_note(r, self.profile, &self.accounts, info.shielded_root)?;
            #[cfg(test)]
            crate::restore_metrics::COUNTERS.with(|c| c.borrow_mut().witnesses += 1);
            if s.notes.insert(nf, note).is_some() {
                return Err(Error::InvalidBody);
            }
        }
        for _ in 0..count(r, self.limits.accounts)? {
            let id = u32::from_le_bytes(bytes(r)?);
            let p = AccountProgress {
                transparent_external: u64::from_le_bytes(bytes(r)?),
                transparent_internal: u64::from_le_bytes(bytes(r)?),
                private_external: u128::from_le_bytes(bytes(r)?),
                private_internal: u128::from_le_bytes(bytes(r)?),
            };
            if !self.accounts.iter().any(|a| a.id == id)
                || p.transparent_external > 1 << 31
                || p.transparent_internal > 1 << 31
                || p.private_external > 1 << 88
                || p.private_internal > 1 << 88
                || s.observed.insert(id, p).is_some()
            {
                return Err(Error::InvalidBody);
            }
        }
        let end = r.position() as usize;
        if self.encode_state(&s)?.as_slice() != &r.get_ref()[start..end] {
            return Err(Error::InvalidBody);
        }
        #[cfg(test)]
        {
            let exit = crate::restore_metrics::COUNTERS.with(|c| {
                let mut v = c.borrow_mut();
                v.states += 1;
                v.stop_after_state == Some(v.states)
            });
            if exit {
                std::process::exit(84);
            }
        }
        Ok(Some(s))
    }
    pub(super) fn encode_cache(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let mut b = self.encode_state(&self.state)?;
        b.extend(HISTORY_MAGIC);
        b.extend((self.history.len() as u32).to_le_bytes());
        for (_, encoded) in &self.history {
            put(&mut b, encoded)?;
        }
        if b.len() > MAX {
            return Err(Error::Capacity);
        }
        Ok(b)
    }
    pub(super) fn remember(
        &self,
        history: &mut VecDeque<(Hash, Zeroizing<Vec<u8>>)>,
        before: &State,
        after: &State,
    ) -> Result<(), Error> {
        self.remember_prepared(history, self.capture_rollback(before)?, after)
    }
    pub(super) fn remember_prepared(
        &self,
        history: &mut VecDeque<(Hash, Zeroizing<Vec<u8>>)>,
        before: Option<super::rollback::Prepared>,
        after: &State,
    ) -> Result<(), Error> {
        let Some(before) = before else {
            history.clear();
            return Ok(());
        };
        match self.finish_delta(&before, after) {
            Ok(encoded) if encoded.len() + 4 <= HISTORY_BYTES => {
                history.push_back((before.tip, encoded))
            }
            Ok(_) | Err(Error::Capacity) => history.clear(),
            Err(e) => return Err(e),
        }
        while history.len() > HISTORY_BLOCKS
            || history.iter().map(|(_, b)| b.len() + 4).sum::<usize>() > HISTORY_BYTES
        {
            history.pop_front();
        }
        Ok(())
    }
    pub(super) fn trim_history(
        &self,
        history: &mut VecDeque<(Hash, Zeroizing<Vec<u8>>)>,
        state: &State,
    ) -> Result<(), Error> {
        let size = match self.encode_state(state) {
            Ok(encoded) => encoded.len().saturating_add(12),
            Err(Error::Capacity) => {
                history.clear();
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        while !history.is_empty()
            && size.saturating_add(history.iter().map(|(_, b)| b.len() + 4).sum::<usize>()) > MAX
        {
            history.pop_front();
        }
        Ok(())
    }
    /// Persist only a complete current projection. An interrupted write leaves old or
    /// new authenticated state; neither releases wallet claims nor advances counters.
    pub fn save_cache(
        &self,
        store: &WalletStore,
        source: &DurableChain<V6Verifier>,
        context: Hash,
    ) -> Result<(), Error> {
        self.current(source)?;
        store
            .save_scan_cache(context, &self.encode_cache()?)
            .map_err(invalid)
    }
}
