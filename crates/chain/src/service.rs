//! On-chain collateral registration and sampled-history service accounting.
use crate::{
    Chain, Error, Hash, LedgerView, archive,
    header::hash_domain,
    ledger::{OutPoint, Overlay},
    pose::Score,
    transactions::TransactionVerifier,
};
use monario_monetary::ATOMS_PER_COIN;
use secp256k1::{
    Message, PublicKey, SecretKey,
    ecdsa::{self, Signature},
};
use std::collections::BTreeSet;
const MAGIC: &[u8] = b"MONAR-SVC";
/// Magic plus one version and one kind byte precede every record body.
pub(crate) const HEADER: usize = MAGIC.len() + 2;
/// Offset of the record version byte. External parsers must not assume a fixed magic width.
pub const VERSION: usize = MAGIC.len();
/// Canonical signed service-record format version.
pub const RECORD_FORMAT_VERSION: u8 = 2;
/// Offset of the record kind byte (2 rotation, 3 reactivation).
pub const KIND: usize = MAGIC.len() + 1;
/// Fixed proof payload after the header: id (32) + start (8) + challenge (32).
const PROOF_FIELDS: usize = 32 + 8 + 32;
/// Length of the fixed service-record header (magic, version, kind). External
/// callers parsing a record body must start at this offset.
pub const RECORD_HEADER_LEN: usize = HEADER;
mod control;
#[cfg(test)]
use control::reactivation_authorization_with;
pub(crate) use control::valid_control_transition;
pub use control::{control_script, reactivation_authorization, rotation_authorization};
pub const COLLATERAL_ATOMS: u64 = 1000 * ATOMS_PER_COIN;
pub const REGISTRATION_CONFIRMATIONS: u64 = 100;
pub const QUALIFY_SECONDS: u64 = 604800;
pub const PERIOD_BLOCKS: u64 = 1920;
pub const RESPONSE_BLOCKS: u64 = 160;
pub const MAX_REGISTRATIONS: usize = 84000;
pub const SLOT_CAPACITY: u32 = 44;
pub const MAX_RECORDS: usize = 64;
pub const SAMPLES: usize = 4;
pub const MAX_RECORD_BYTES: usize = 8192;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Previous accepted control transaction; zero before the first update.
    pub control_head: Hash,
    pub collateral: OutPoint,
    pub owner: [u8; 33],
    pub operator: [u8; 33],
    pub registered_height: u64,
    pub slot: u16,
    pub next_start: u64,
    pub credited_seconds: u64,
    pub last_proven_end: Option<u64>,
    pub score: Score,
    pub score_height: u64,
}
impl Entry {
    pub fn mature_for_block(&self, height: u64) -> bool {
        self.registered_height
            .checked_add(REGISTRATION_CONFIRMATIONS)
            .is_some_and(|h| height >= h)
    }
    /// Score storage is lazy; obtain its effective decayed value at a branch height.
    pub fn penalty_at(&self, height: u64) -> Option<u32> {
        let mut score = self.score;
        score.decay_blocks(height.checked_sub(self.score_height)?);
        Some(score.penalty())
    }
    pub fn deadline(&self) -> Option<u64> {
        if self.score.banned() {
            None
        } else {
            self.next_start
                .checked_add(PERIOD_BLOCKS)?
                .checked_add(RESPONSE_BLOCKS)
        }
    }
    pub fn qualified(&self, height: u64) -> bool {
        self.mature_for_block(height)
            && height >= self.score_height
            && !self.score.banned()
            && self.credited_seconds == QUALIFY_SECONDS
            && self
                .last_proven_end
                .and_then(|h| h.checked_add(PERIOD_BLOCKS + RESPONSE_BLOCKS))
                .is_some_and(|h| height <= h)
    }
    pub(crate) fn valid(&self) -> bool {
        let Some(earliest) = self
            .registered_height
            .checked_add(REGISTRATION_CONFIRMATIONS - 1)
        else {
            return false;
        };
        let Some(initial) = earliest.checked_add(
            (u64::from(self.slot) + PERIOD_BLOCKS - earliest % PERIOD_BLOCKS) % PERIOD_BLOCKS,
        ) else {
            return false;
        };
        if self.next_start < initial {
            return false;
        }
        let completed = (self.next_start - initial) / PERIOD_BLOCKS;
        PublicKey::from_byte_array_compressed(self.owner).is_ok()
            && PublicKey::from_byte_array_compressed(self.operator).is_ok()
            && self.owner != self.operator
            && u64::from(self.slot) < PERIOD_BLOCKS
            && self.registered_height > 0
            && self
                .registered_height
                .checked_add(REGISTRATION_CONFIRMATIONS - 1)
                .is_some_and(|h| self.next_start >= h)
            && self.next_start % PERIOD_BLOCKS == u64::from(self.slot)
            && self
                .next_start
                .checked_add(PERIOD_BLOCKS + RESPONSE_BLOCKS)
                .is_some()
            && self.credited_seconds <= QUALIFY_SECONDS
            && self.credited_seconds <= completed.min(7) * 86400
            && (completed == 0 || self.next_start <= self.score_height)
            && self.score_height >= self.registered_height
            && self.last_proven_end.is_none_or(|h| {
                h < self.score_height
                    && h >= initial.saturating_add(PERIOD_BLOCKS)
                    && h <= self.next_start
                    && (self.next_start - h).is_multiple_of(PERIOD_BLOCKS)
            })
            && (self.last_proven_end.is_some() || self.credited_seconds == 0)
    }
    fn decay(&mut self, height: u64) -> Result<(), Error> {
        self.score.decay_blocks(
            height
                .checked_sub(self.score_height)
                .ok_or(Error::Service)?,
        );
        self.score_height = height;
        Ok(())
    }
}
pub fn owner_script(owner: &[u8; 33]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let h = <ripemd::Ripemd160 as ripemd::Digest>::digest(Sha256::digest(owner));
    [vec![0x76, 0xa9, 20], h.to_vec(), vec![0x88, 0xac]].concat()
}
fn signed_hash(chain_id: Hash, root: Hash, payload: &[u8]) -> Hash {
    hash_domain(
        b"Monario/service-signature/v1\0",
        &[&chain_id, &root, payload],
    )
}
fn authorize(key: [u8; 33], digest: Hash, bytes: &[u8]) -> Result<(), Error> {
    let key = PublicKey::from_byte_array_compressed(key).map_err(|_| Error::Service)?;
    let sig = Signature::from_compact(bytes).map_err(|_| Error::Service)?;
    let mut normalized = sig;
    normalized.normalize_s();
    if normalized != sig {
        return Err(Error::Service);
    }
    ecdsa::verify(&sig, Message::from_digest(digest), &key).map_err(|_| Error::Service)
}
fn finish_script(
    mut payload: Vec<u8>,
    chain_id: Hash,
    root: Hash,
    key: &SecretKey,
) -> Result<Vec<u8>, Error> {
    let sig = ecdsa::sign(
        Message::from_digest(signed_hash(chain_id, root, &payload)),
        key,
    );
    payload.extend(sig.serialize_compact());
    script(&payload)
}
fn script(payload: &[u8]) -> Result<Vec<u8>, Error> {
    if payload.len() > MAX_RECORD_BYTES {
        return Err(Error::Service);
    }
    let mut out = vec![0x6a];
    match payload.len() {
        0..=75 => out.push(payload.len() as u8),
        76..=255 => out.extend([0x4c, payload.len() as u8]),
        _ => {
            out.push(0x4d);
            out.extend((payload.len() as u16).to_le_bytes());
        }
    }
    out.extend(payload);
    Ok(out)
}
/// Check the reserved namespace and canonical outer encoding, without granting
/// registration, proof validity or transaction acceptance.
pub fn check_encoding(bytes: &[u8]) -> Result<(), Error> {
    payload(bytes)?.ok_or(Error::Service).map(|_| ())
}
/// Create a canonical owner-authorized registration output script. The transaction
/// carrying it must have a zero-valued output and must not spend the collateral.
pub fn registration_script(
    chain_id: Hash,
    root: Hash,
    collateral: OutPoint,
    owner: &SecretKey,
    operator: [u8; 33],
) -> Result<Vec<u8>, Error> {
    PublicKey::from_byte_array_compressed(operator).map_err(|_| Error::Service)?;
    if PublicKey::from_secret_key(owner).serialize() == operator {
        return Err(Error::Service);
    }
    let mut p = MAGIC.to_vec();
    p.extend([RECORD_FORMAT_VERSION, 0]);
    p.extend(collateral.transaction);
    p.extend(collateral.index.to_le_bytes());
    p.extend(PublicKey::from_secret_key(owner).serialize());
    p.extend(operator);
    finish_script(p, chain_id, root, owner)
}
pub(crate) fn payload(script_bytes: &[u8]) -> Result<Option<Vec<u8>>, Error> {
    if script_bytes.first() != Some(&0x6a) {
        return Ok(None);
    }
    let (offset, len) = match script_bytes.get(1).copied() {
        Some(n @ 0..=75) => (2, usize::from(n)),
        Some(0x4c) if script_bytes.len() >= 3 => (3, usize::from(script_bytes[2])),
        Some(0x4d) if script_bytes.len() >= 4 => (
            4,
            u16::from_le_bytes([script_bytes[2], script_bytes[3]]) as usize,
        ),
        Some(0x4e) if script_bytes.len() >= 6 => (
            6,
            u32::from_le_bytes(script_bytes[2..6].try_into().map_err(|_| Error::Service)?) as usize,
        ),
        _ => return Ok(None),
    };
    let p = script_bytes.get(offset..).ok_or(Error::Service)?;
    if !p.starts_with(MAGIC) {
        return Ok(None);
    }
    if p.len() != len
        || script(p)?.as_slice() != script_bytes
        || p.len() < HEADER + 64
        || p[VERSION] != RECORD_FORMAT_VERSION
        || p[KIND] > 4
    {
        return Err(Error::Service);
    }
    Ok(Some(p.to_vec()))
}
struct Reader<'a>(&'a [u8]);
impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], Error> {
        if self.0.len() < n {
            return Err(Error::Service);
        }
        let (v, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(v)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Service)
    }
    fn n(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.array()?))
    }
}

impl<V: TransactionVerifier> Chain<V> {
    /// Current timely response context from validated branch ancestry only.
    /// This query reads no archive bodies and grants no proof/transaction validity.
    pub fn service_challenge(&self, id: Hash) -> Result<(u64, Hash), Error> {
        let e = self.ledger().service_entry(&id).ok_or(Error::Service)?;
        let height = self.height().checked_add(1).ok_or(Error::Service)?;
        let end = e
            .next_start
            .checked_add(PERIOD_BLOCKS)
            .ok_or(Error::Service)?;
        if e.score.banned() || height <= end || height > e.deadline().ok_or(Error::Service)? {
            return Err(Error::Service);
        }
        Ok((e.next_start, self.ancestor(self.tip(), end)?))
    }
    fn targets(
        &self,
        parent: Hash,
        id: Hash,
        start: u64,
    ) -> Result<[(Hash, usize); SAMPLES], Error> {
        let end = start.checked_add(PERIOD_BLOCKS).ok_or(Error::Service)?;
        let challenge = self.ancestor(parent, end)?;
        let mut targets = [([0; 32], 0); SAMPLES];
        for (slot, target) in targets.iter_mut().enumerate() {
            let seed = hash_domain(
                b"Monario/history-challenge/v1\0",
                &[
                    &self.config.chain_id,
                    &self.root.id,
                    &id,
                    &start.to_le_bytes(),
                    &challenge,
                    &[slot as u8],
                ],
            );
            let h = 1 + draw(seed, 0, start)?;
            let block = self.ancestor(parent, h)?;
            let count = self.nodes[&block]
                .archive
                .ok_or(Error::Service)?
                .chunks()
                .ok_or(Error::Service)?;
            *target = (block, draw(seed, 1, count as u64)? as usize);
        }
        Ok(targets)
    }
    pub(crate) fn apply_services(
        &self,
        parent: Hash,
        height: u64,
        base: &dyn LedgerView,
        staged: &mut Overlay<'_>,
        records: &[(Hash, Vec<u8>)],
    ) -> Result<(), Error> {
        if records.len() > MAX_RECORDS {
            return Err(Error::ResourceLimit);
        }
        let population = u32::try_from(base.service_count()).map_err(|_| Error::Service)?;
        for id in base.service_due(height) {
            let Some(mut e) = staged.service_entry(&id).cloned() else {
                continue;
            };
            if e.deadline().is_some_and(|d| d < height) {
                e.decay(height)?;
                e.score.punish_failure(population);
                e.next_start = e
                    .next_start
                    .checked_add(PERIOD_BLOCKS)
                    .ok_or(Error::Service)?;
                staged.set_service(id, Some(e));
            }
        }
        let mut seen = BTreeSet::new();
        let mut updated = BTreeSet::new();
        for (txid, p) in records {
            if p.len() < HEADER + 64
                || p.len() > MAX_RECORD_BYTES
                || !p.starts_with(MAGIC)
                || p[VERSION] != RECORD_FORMAT_VERSION
                || p[KIND] > 3
            {
                return Err(Error::Service);
            }
            if !seen.insert(*txid) {
                return Err(Error::Service);
            }
            let body = p
                .get(..p.len().checked_sub(64).ok_or(Error::Service)?)
                .ok_or(Error::Service)?;
            let sig = &p[body.len()..];
            let mut r = Reader(body.get(HEADER..).ok_or(Error::Service)?);
            if p[KIND] == 0 {
                let collateral = OutPoint {
                    transaction: r.array()?,
                    index: u32::from_le_bytes(r.array()?),
                };
                let owner = r.array()?;
                let operator = r.array()?;
                if !r.0.is_empty()
                    || staged.service_count() >= MAX_REGISTRATIONS
                    || staged.service_entry(txid).is_some()
                    || staged.service_collateral(&collateral).is_some()
                    || staged.service_operator(&operator).is_some()
                {
                    return Err(Error::Service);
                }
                PublicKey::from_byte_array_compressed(operator).map_err(|_| Error::Service)?;
                if owner == operator {
                    return Err(Error::Service);
                }
                let original = base.coin(&collateral).ok_or(Error::Service)?;
                let current = staged.coin(&collateral).ok_or(Error::Service)?;
                if original != current
                    || current.value.atoms() != COLLATERAL_ATOMS
                    || current.script != owner_script(&owner)
                {
                    return Err(Error::Service);
                }
                authorize(
                    owner,
                    signed_hash(self.config.chain_id, self.root.id, body),
                    sig,
                )?;
                let slots = staged.service_slots();
                let (slot, count) = slots
                    .iter()
                    .enumerate()
                    .min_by_key(|(i, n)| (**n, *i))
                    .ok_or(Error::Service)?;
                if *count >= SLOT_CAPACITY {
                    return Err(Error::ResourceLimit);
                }
                let earliest = height
                    .checked_add(REGISTRATION_CONFIRMATIONS - 1)
                    .ok_or(Error::Service)?;
                let next_start = earliest
                    .checked_add(
                        (slot as u64 + PERIOD_BLOCKS - earliest % PERIOD_BLOCKS) % PERIOD_BLOCKS,
                    )
                    .ok_or(Error::Service)?;
                let e = Entry {
                    control_head: [0; 32],
                    collateral,
                    owner,
                    operator,
                    registered_height: height,
                    slot: slot as u16,
                    next_start,
                    credited_seconds: 0,
                    last_proven_end: None,
                    score: Score::default(),
                    score_height: height,
                };
                if !e.valid() {
                    return Err(Error::Service);
                }
                staged.set_service(*txid, Some(e));
            } else if p[KIND] >= 2 {
                let id = Hash::try_from(r.take(32)?).map_err(|_| Error::Service)?;
                if !updated.insert(id) || base.service_entry(&id).is_none() {
                    return Err(Error::Service);
                }
                self.apply_control(parent, height, population, staged, *txid, p)?;
            } else {
                let id = r.array()?;
                if !updated.insert(id) {
                    return Err(Error::Service);
                }
                let start = r.n()?;
                let challenge: Hash = r.array()?;
                let mut e = staged.service_entry(&id).cloned().ok_or(Error::Service)?;
                if e.score.banned() || e.next_start != start || staged.coin(&e.collateral).is_none()
                {
                    return Err(Error::Service);
                }
                let end = start.checked_add(PERIOD_BLOCKS).ok_or(Error::Service)?;
                if height <= end || height > e.deadline().ok_or(Error::Service)? {
                    return Err(Error::Service);
                }
                if self.ancestor(parent, end)? != challenge {
                    return Err(Error::Service);
                }
                authorize(
                    e.operator,
                    signed_hash(self.config.chain_id, self.root.id, body),
                    sig,
                )?;
                for (block, index) in self.targets(parent, id, start)? {
                    let len = usize::from(u16::from_le_bytes(r.array()?));
                    if len == 0 || len > archive::CHUNK_BYTES {
                        return Err(Error::Service);
                    }
                    let data = r.take(len)?.to_vec();
                    let count = usize::from(r.take(1)?[0]);
                    if count > 12 {
                        return Err(Error::Service);
                    }
                    let mut path = Vec::with_capacity(count);
                    for _ in 0..count {
                        path.push(r.array()?);
                    }
                    if !self.nodes[&block]
                        .archive
                        .ok_or(Error::Service)?
                        .verify(index, &archive::Sample { data, path })
                    {
                        return Err(Error::Service);
                    }
                }
                if !r.0.is_empty() {
                    return Err(Error::Service);
                }
                let a = self.median_time(self.ancestor(parent, start)?);
                let b = self.median_time(self.ancestor(parent, end)?);
                let elapsed = b.checked_sub(a).ok_or(Error::Service)?.min(86400);
                e.credited_seconds = e
                    .credited_seconds
                    .saturating_add(elapsed)
                    .min(QUALIFY_SECONDS);
                e.next_start = end;
                e.last_proven_end = Some(end);
                e.decay(height)?;
                staged.set_service(id, Some(e));
            }
        }
        Ok(())
    }
}
fn draw(seed: Hash, kind: u8, bound: u64) -> Result<u64, Error> {
    if bound == 0 {
        return Err(Error::Service);
    }
    let minimum = bound.wrapping_neg() % bound;
    for nonce in 0u32..128 {
        let h = hash_domain(
            b"Monario/history-draw/v1\0",
            &[&seed, &[kind], &nonce.to_le_bytes()],
        );
        let value = u64::from_le_bytes(h[..8].try_into().map_err(|_| Error::Service)?);
        if value >= minimum {
            return Ok(value % bound);
        }
    }
    Err(Error::Service)
}

/// Read the identity of a canonical response record. This is NOT proof validation
/// or transaction acceptance; callers must independently check the full service
/// effects before signing, retaining metadata or submitting any transaction.
pub fn proof_context(script: &[u8]) -> Result<(Hash, u64, Hash), Error> {
    let p = payload(script)?.ok_or(Error::Service)?;
    if p[KIND] != 1 || p.len() < HEADER + PROOF_FIELDS + 64 {
        return Err(Error::Service);
    }
    let mut r = Reader(&p[HEADER..]);
    Ok((r.array()?, r.n()?, r.array()?))
}

/// Produce a response from actual retained canonical block bytes. Pruned/missing
/// bodies fail; the signed response proves sampled access, not exclusive storage.
pub fn proof_script<V: TransactionVerifier>(
    source: &crate::storage::DurableChain<V>,
    id: Hash,
    operator: &SecretKey,
) -> Result<Vec<u8>, Error> {
    let chain = source.chain().map_err(|_| Error::Storage)?;
    proof_script_with(chain, id, operator, |block| {
        let b = source.stored_block(block).map_err(|_| Error::Storage)?;
        crate::wire::encode(&b, &chain.config.limits, &chain.verifier)
    })
}
fn proof_script_with<V: TransactionVerifier>(
    chain: &Chain<V>,
    id: Hash,
    operator: &SecretKey,
    mut read: impl FnMut(Hash) -> Result<Vec<u8>, Error>,
) -> Result<Vec<u8>, Error> {
    let e = chain.ledger().service_entry(&id).ok_or(Error::Service)?;
    if PublicKey::from_secret_key(operator).serialize() != e.operator || e.score.banned() {
        return Err(Error::Service);
    }
    let (start, challenge) = chain.service_challenge(id)?;
    let mut p = MAGIC.to_vec();
    p.extend([RECORD_FORMAT_VERSION, 1]);
    p.extend(id);
    p.extend(start.to_le_bytes());
    p.extend(challenge);
    for (block, index) in chain.targets(chain.tip(), id, start)? {
        let bytes = read(block)?;
        if archive::summarize(&bytes) != chain.nodes[&block].archive {
            return Err(Error::Service);
        }
        let sample = archive::sample(&bytes, index).ok_or(Error::Service)?;
        p.extend((sample.data.len() as u16).to_le_bytes());
        p.extend(sample.data);
        p.push(sample.path.len() as u8);
        for h in sample.path {
            p.extend(h);
        }
    }
    finish_script(p, chain.config.chain_id, chain.root.id, operator)
}

impl<V: TransactionVerifier> Chain<V> {
    /// Read-only preflight for wallet intent. Input IDs here are NOT trusted
    /// transaction effects; final acceptance always validates actual transactions.
    pub fn check_service_intent(&self, script: &[u8], inputs: &[OutPoint]) -> Result<(), Error> {
        let mut staged = Overlay::new(self.ledger());
        for p in inputs {
            staged.spend(*p)?;
        }
        let p = payload(script)?.ok_or(Error::Service)?;
        let id = hash_domain(b"Monario/service-intent/v1\0", &[script]);
        self.apply_services(
            self.tip(),
            self.height().checked_add(1).ok_or(Error::Service)?,
            self.ledger(),
            &mut staged,
            &[(id, p)],
        )
    }
    /// Non-mutating next-block service-record check for an already verified
    /// transaction. This is NOT transaction acceptance or a transferable receipt.
    pub fn check_service_effects(
        &self,
        tx: &crate::transactions::VerifiedTransaction,
    ) -> Result<(), Error> {
        let mut staged = Overlay::new(self.ledger());
        for p in &tx.inputs {
            staged.spend(*p)?;
        }
        let mut records = Vec::new();
        for output in &tx.outputs {
            if let Some(p) = payload(&output.script)? {
                if tx.coinbase_height.is_some() || output.value != monario_monetary::Amount::ZERO {
                    return Err(Error::Service);
                }
                records.push((tx.id, p));
            }
        }
        self.apply_services(
            self.tip(),
            self.height().checked_add(1).ok_or(Error::Service)?,
            self.ledger(),
            &mut staged,
            &records,
        )
    }
}

#[cfg(test)]
pub(crate) mod tests;
