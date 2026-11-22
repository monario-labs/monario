//! Encrypted input claims, committed before signing and retained across reorgs.
use super::*;
use std::collections::BTreeSet;
/// Retained reservation history capacity; exhaustion fails closed.
pub const MAX_RESERVATIONS: usize = 10000;
/// Maximum input claims across all retained records.
pub const MAX_INPUTS: usize = 16384;
/// Maximum retained automatic attempts for one registration/period/profile.
pub const MAX_SERVICE_ATTEMPTS: usize = 3;

/// Authenticated automatic-proof intent; retained even without signed bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ServiceProof {
    /// Registered collateral-node identity.
    pub registration: [u8; 32],
    /// Completed service interval start height.
    pub period_start: u64,
    /// Accepted interval-end block identity on the signing branch.
    pub challenge: [u8; 32],
    /// Registered operator key used to sign the service response.
    pub operator: [u8; 33],
    /// Fixed fee authorized for this attempt, in atoms.
    pub fee_atoms: u64,
}
impl core::fmt::Debug for ServiceProof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ServiceProof([REDACTED])")
    }
}
impl ServiceProof {
    fn valid(self) -> bool {
        self.period_start > 0
            && self.fee_atoms > 0
            && secp256k1::PublicKey::from_byte_array_compressed(self.operator).is_ok()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
/// One transparent outpoint or private spend nullifier.
pub enum Input {
    /// Exact public output identity.
    Transparent {
        /// Creating transaction ID.
        transaction: [u8; 32],
        /// Output index.
        index: u32,
    },
    /// Exact private spend identity.
    Private {
        /// Authenticated note nullifier.
        nullifier: [u8; 32],
    },
}
impl core::fmt::Debug for Input {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ReservedInput([REDACTED])")
    }
}
#[derive(Clone)]
/// Durable spend intent; Debug does not expose wallet linkage metadata.
pub struct Reservation {
    /// Random reservation token.
    pub id: [u8; 16],
    /// Chain validation-profile fingerprint.
    pub profile: [u8; 32],
    /// Validated chain tip at creation.
    pub validated_tip: [u8; 32],
    /// Signed transaction's finite expiry, not permission to release a claim.
    pub expiry_height: u64,
    /// Bound signed transaction ID; None means signing did not finish.
    pub transaction: Option<[u8; 32]>,
    /// All claimed inputs.
    pub inputs: Vec<Input>,
    /// Optional automatic-proof budget identity, committed before signing.
    pub service_proof: Option<ServiceProof>,
    bytes: Option<Zeroizing<Vec<u8>>>,
}
impl Reservation {
    /// Explicit signed-byte export for rebroadcast after reopening. Never log it.
    pub fn expose_transaction(&self) -> Option<&[u8]> {
        self.bytes.as_ref().map(|b| b.as_slice())
    }
}
impl core::fmt::Debug for Reservation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Reservation([REDACTED])")
    }
}
impl WalletStore {
    /// Borrow authenticated claims after unlocking the wallet.
    pub fn reservations(&self) -> Result<&BTreeMap<[u8; 16], Reservation>, StorageError> {
        self.ready()?;
        Ok(&self.state.pending)
    }
    /// Durable before any signature/proof construction. Reservations are not
    /// automatically released by wall time, expiry, confirmation or mempool loss.
    pub fn reserve_inputs(
        &mut self,
        profile: [u8; 32],
        validated_tip: [u8; 32],
        expiry_height: u64,
        inputs: Vec<Input>,
    ) -> Result<[u8; 16], StorageError> {
        self.reserve_claim(profile, validated_tip, expiry_height, inputs, None)
    }
    /// Reserve one transparent proof-fee input atomically with its attempt tag.
    /// Unsigned, compacted and orphaned attempts all consume the same period's
    /// limit/budget. No spending signature or submission may precede this commit.
    pub fn reserve_service_inputs(
        &mut self,
        profile: [u8; 32],
        validated_tip: [u8; 32],
        expiry_height: u64,
        inputs: Vec<Input>,
        proof: ServiceProof,
        period_fee_budget: u64,
    ) -> Result<[u8; 16], StorageError> {
        self.ready()?;
        if !proof.valid() || inputs.len() != 1 || !matches!(inputs[0], Input::Transparent { .. }) {
            return Err(StorageError::Invalid);
        }
        let attempts: Vec<_> = self
            .state
            .pending
            .values()
            .filter(|r| {
                r.profile == profile
                    && r.service_proof.is_some_and(|p| {
                        p.registration == proof.registration && p.period_start == proof.period_start
                    })
            })
            .collect();
        let fees: u128 = attempts
            .iter()
            .filter_map(|r| r.service_proof)
            .map(|p| u128::from(p.fee_atoms))
            .sum();
        if attempts.len() >= MAX_SERVICE_ATTEMPTS
            || fees + u128::from(proof.fee_atoms) > u128::from(period_fee_budget)
        {
            return Err(StorageError::Capacity);
        }
        self.reserve_claim(profile, validated_tip, expiry_height, inputs, Some(proof))
    }
    fn reserve_claim(
        &mut self,
        profile: [u8; 32],
        validated_tip: [u8; 32],
        expiry_height: u64,
        inputs: Vec<Input>,
        service_proof: Option<ServiceProof>,
    ) -> Result<[u8; 16], StorageError> {
        self.ready()?;
        if self.state.recovery {
            return Err(StorageError::RecoveryRequired);
        }
        if expiry_height == 0
            || inputs.is_empty()
            || inputs.len() > 32
            || inputs.iter().copied().collect::<BTreeSet<_>>().len() != inputs.len()
        {
            return Err(StorageError::Invalid);
        }
        if self
            .state
            .pending
            .values()
            .any(|r| r.inputs.iter().any(|i| inputs.contains(i)))
        {
            return Err(StorageError::InputReserved);
        }
        let id = crypto::random()?;
        if self.state.pending.contains_key(&id) {
            return Err(StorageError::Entropy);
        }
        let mut pending = self.state.pending.clone();
        pending.insert(
            id,
            Reservation {
                id,
                profile,
                validated_tip,
                expiry_height,
                transaction: None,
                inputs,
                service_proof,
                bytes: None,
            },
        );
        self.commit_pending(pending, |_| {})?;
        Ok(id)
    }
    /// Commit the exact signed transaction ID before returning signed bytes.
    pub fn bind_reservation(
        &mut self,
        id: [u8; 16],
        transaction: [u8; 32],
        bytes: &[u8],
    ) -> Result<WalletCheckpoint, StorageError> {
        self.ready()?;
        if bytes.is_empty() || bytes.len() > 2_000_000 {
            return Err(StorageError::Capacity);
        }
        let mut pending = self.state.pending.clone();
        let r = pending.get_mut(&id).ok_or(StorageError::Invalid)?;
        if r.transaction.is_some_and(|old| old != transaction) {
            return Err(StorageError::Invalid);
        }
        if r.transaction == Some(transaction) {
            if r.expose_transaction() == Some(bytes) {
                return self.checkpoint();
            }
            return Err(StorageError::Invalid);
        }
        r.transaction = Some(transaction);
        r.bytes = Some(Zeroizing::new(bytes.to_vec()));
        self.commit_pending(pending, |_| {})
    }
    /// Drop only raw bytes already archived by the caller (for example in a
    /// confirmed retained block). Input claims and transaction IDs remain held.
    pub fn compact_reservation_bytes(
        &mut self,
        id: [u8; 16],
    ) -> Result<WalletCheckpoint, StorageError> {
        self.ready()?;
        let mut pending = self.state.pending.clone();
        let r = pending.get_mut(&id).ok_or(StorageError::Invalid)?;
        if r.transaction.is_none() {
            return Err(StorageError::Invalid);
        }
        r.bytes = None;
        self.commit_pending(pending, |_| {})
    }
    /// Only ordinary unsigned claims may be cancelled. Automatic proof attempts
    /// retain their tags/claims to prevent resetting the period budget. A signed claim is retained so a
    /// deep reorg cannot silently expose its inputs for another payment.
    pub fn cancel_unsigned_reservation(
        &mut self,
        id: [u8; 16],
    ) -> Result<WalletCheckpoint, StorageError> {
        self.ready()?;
        if self
            .state
            .pending
            .get(&id)
            .is_none_or(|r| r.transaction.is_some() || r.service_proof.is_some())
        {
            return Err(StorageError::Invalid);
        }
        let mut pending = self.state.pending.clone();
        pending.remove(&id);
        self.commit_pending(pending, |_| {})
    }
    fn commit_pending(
        &mut self,
        pending: BTreeMap<[u8; 16], Reservation>,
        hook: impl FnMut(bool),
    ) -> Result<WalletCheckpoint, StorageError> {
        self.ready()?;
        let mut header = self.header;
        header.checkpoint.revision = header
            .checkpoint
            .revision
            .checked_add(1)
            .ok_or(StorageError::Capacity)?;
        let plain = state::encode_pending(
            &self.state.seed,
            &self.state.accounts,
            self.state.recovery,
            &pending,
        )?;
        let envelope = crypto::seal(header, &self.key, &plain)?;
        if let Err(e) = write_record(&mut self.db, &envelope, false, hook) {
            self.poisoned = true;
            return Err(e);
        }
        self.state.pending = pending;
        self.header = header;
        Ok(header.checkpoint)
    }
}
pub(super) fn encode(
    pending: &BTreeMap<[u8; 16], Reservation>,
    out: &mut Vec<u8>,
) -> Result<(), StorageError> {
    if pending.len() > MAX_RESERVATIONS
        || pending.values().map(|r| r.inputs.len()).sum::<usize>() > MAX_INPUTS
    {
        return Err(StorageError::Capacity);
    }
    let wide = pending
        .values()
        .any(|r| r.expiry_height > u64::from(u32::MAX));
    let tagged = wide || pending.values().any(|r| r.service_proof.is_some());
    let mut budget = out.len() + 12;
    for r in pending.values() {
        budget = budget
            .checked_add(
                122 + (if wide { 4 } else { 0 })
                    + (if tagged { 1 } else { 0 })
                    + r.service_proof.map_or(0, |_| 113)
                    + r.inputs.len() * 37
                    + r.bytes.as_ref().map_or(0, |b| b.len()),
            )
            .ok_or(StorageError::Capacity)?;
        if budget > crypto::PLAIN_LEN
            || r.bytes
                .as_ref()
                .is_some_and(|b| b.is_empty() || b.len() > 2_000_000 || r.transaction.is_none())
        {
            return Err(StorageError::Capacity);
        }
    }
    out.extend(if wide {
        b"MNRPEND3"
    } else if tagged {
        b"MNRPEND2"
    } else {
        b"MNRPEND1"
    });
    out.extend((pending.len() as u32).to_le_bytes());
    let mut all = BTreeSet::new();
    for (id, r) in pending {
        if *id != r.id
            || r.expiry_height == 0
            || r.inputs.is_empty()
            || r.inputs.len() > 32
            || r.inputs.iter().copied().collect::<BTreeSet<_>>().len() != r.inputs.len()
            || (r.service_proof.is_some()
                && (r.inputs.len() != 1 || !matches!(r.inputs[0], Input::Transparent { .. })))
        {
            return Err(StorageError::Invalid);
        }
        out.extend(id);
        out.extend(r.profile);
        out.extend(r.validated_tip);
        if wide {
            out.extend(r.expiry_height.to_le_bytes());
        } else {
            out.extend((r.expiry_height as u32).to_le_bytes());
        }
        if tagged {
            out.push(u8::from(r.service_proof.is_some()));
            if let Some(p) = r.service_proof {
                if !p.valid() {
                    return Err(StorageError::Invalid);
                }
                out.extend(p.registration);
                out.extend(p.period_start.to_le_bytes());
                out.extend(p.challenge);
                out.extend(p.operator);
                out.extend(p.fee_atoms.to_le_bytes());
            }
        }
        out.push(u8::from(r.transaction.is_some()));
        out.extend(r.transaction.unwrap_or([0; 32]));
        let raw = r.expose_transaction().unwrap_or(&[]);
        out.extend((raw.len() as u32).to_le_bytes());
        out.extend(raw);
        out.push(r.inputs.len() as u8);
        for input in &r.inputs {
            if !all.insert(*input) {
                return Err(StorageError::Invalid);
            }
            match input {
                Input::Transparent { transaction, index } => {
                    out.push(0);
                    out.extend(transaction);
                    out.extend(index.to_le_bytes());
                }
                Input::Private { nullifier } => {
                    out.push(1);
                    out.extend(nullifier);
                }
            }
        }
    }
    Ok(())
}
pub(super) fn decode(
    bytes: &[u8],
    offset: &mut usize,
) -> Result<BTreeMap<[u8; 16], Reservation>, StorageError> {
    fn take<'a>(b: &'a [u8], o: &mut usize, n: usize) -> Result<&'a [u8], StorageError> {
        let end = o.checked_add(n).ok_or(StorageError::Invalid)?;
        let v = b.get(*o..end).ok_or(StorageError::Invalid)?;
        *o = end;
        Ok(v)
    }
    fn array<const N: usize>(b: &[u8], o: &mut usize) -> Result<[u8; N], StorageError> {
        take(b, o, N)?.try_into().map_err(|_| StorageError::Invalid)
    }
    let (tagged, wide) = match take(bytes, offset, 8)? {
        b"MNRPEND1" => (false, false),
        b"MNRPEND2" => (true, false),
        b"MNRPEND3" => (true, true),
        _ => return Err(StorageError::Invalid),
    };
    let count = u32::from_le_bytes(array(bytes, offset)?) as usize;
    if count > MAX_RESERVATIONS {
        return Err(StorageError::Capacity);
    }
    let mut pending = BTreeMap::new();
    let mut last = None;
    let mut all = BTreeSet::new();
    let mut total = 0;
    for _ in 0..count {
        let id = array(bytes, offset)?;
        if last.is_some_and(|old| old >= id) {
            return Err(StorageError::Invalid);
        }
        last = Some(id);
        let profile = array(bytes, offset)?;
        let validated_tip = array(bytes, offset)?;
        let expiry_height = if wide {
            u64::from_le_bytes(array(bytes, offset)?)
        } else {
            u64::from(u32::from_le_bytes(array(bytes, offset)?))
        };
        let service_proof = if tagged {
            match take(bytes, offset, 1)?[0] {
                0 => None,
                1 => {
                    let p = ServiceProof {
                        registration: array(bytes, offset)?,
                        period_start: u64::from_le_bytes(array(bytes, offset)?),
                        challenge: array(bytes, offset)?,
                        operator: array(bytes, offset)?,
                        fee_atoms: u64::from_le_bytes(array(bytes, offset)?),
                    };
                    if !p.valid() {
                        return Err(StorageError::Invalid);
                    }
                    Some(p)
                }
                _ => return Err(StorageError::Invalid),
            }
        } else {
            None
        };
        let flag = take(bytes, offset, 1)?[0];
        let tx = array(bytes, offset)?;
        if flag > 1 || (flag == 0 && tx != [0; 32]) || expiry_height == 0 {
            return Err(StorageError::Invalid);
        }
        let len = u32::from_le_bytes(array(bytes, offset)?) as usize;
        if len > 2_000_000 || (flag == 0 && len != 0) {
            return Err(StorageError::Invalid);
        }
        let raw = take(bytes, offset, len)?;
        let body = (!raw.is_empty()).then(|| Zeroizing::new(raw.to_vec()));
        let n = take(bytes, offset, 1)?[0] as usize;
        total += n;
        if n == 0 || n > 32 || total > MAX_INPUTS {
            return Err(StorageError::Capacity);
        }
        let mut inputs = Vec::with_capacity(n);
        for _ in 0..n {
            let input = match take(bytes, offset, 1)?[0] {
                0 => Input::Transparent {
                    transaction: array(bytes, offset)?,
                    index: u32::from_le_bytes(array(bytes, offset)?),
                },
                1 => Input::Private {
                    nullifier: array(bytes, offset)?,
                },
                _ => return Err(StorageError::Invalid),
            };
            if !all.insert(input) {
                return Err(StorageError::Invalid);
            }
            inputs.push(input);
        }
        if service_proof.is_some()
            && (inputs.len() != 1 || !matches!(inputs[0], Input::Transparent { .. }))
        {
            return Err(StorageError::Invalid);
        }
        pending.insert(
            id,
            Reservation {
                id,
                profile,
                validated_tip,
                expiry_height,
                transaction: (flag == 1).then_some(tx),
                inputs,
                bytes: body,
                service_proof,
            },
        );
    }
    if (tagged && !wide && !pending.values().any(|r| r.service_proof.is_some()))
        || (wide
            && !pending
                .values()
                .any(|r| r.expiry_height > u64::from(u32::MAX)))
    {
        return Err(StorageError::Invalid);
    }
    Ok(pending)
}

#[cfg(test)]
mod tests;
