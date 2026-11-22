//! Replay-protected owner controls. Archive verification is unchanged.
use super::*;

// Structural checkpoint checks supplement the independently trusted commitment;
// they never replace signature/archive verification during block acceptance.
pub(crate) fn valid_control_transition(a: &Entry, b: &Entry, height: u64) -> bool {
    if a.collateral != b.collateral
        || a.owner != b.owner
        || a.registered_height != b.registered_height
        || a.slot != b.slot
        || a.credited_seconds != b.credited_seconds
        || b.score_height != height
        || b.control_head == [0; 32]
        || a.control_head == b.control_head
    {
        return false;
    }
    if a.operator != b.operator {
        let mut expected = a.clone();
        if expected.decay(height).is_err() {
            return false;
        }
        expected.operator = b.operator;
        expected.control_head = b.control_head;
        if a.deadline().is_some_and(|d| d < height) {
            // A timeout preceding a key update is still represented.
            if a.next_start.checked_add(PERIOD_BLOCKS) != Some(b.next_start)
                || b.last_proven_end != a.last_proven_end
                || (a.score.banned() && !b.score.banned())
            {
                return false;
            }
            expected.next_start = b.next_start;
            expected.score = b.score;
        }
        expected == *b
    } else {
        let Ok((_, end)) = interval(a, height) else {
            return false;
        };
        !b.score.banned()
            && (50..=MAX_REGISTRATIONS as u32 / 2).contains(&b.score.penalty())
            && b.next_start == end
            && b.last_proven_end == Some(end)
    }
}

fn prefix<V: TransactionVerifier>(chain: &Chain<V>, id: Hash, kind: u8) -> Result<Vec<u8>, Error> {
    let e = chain.ledger().service_entry(&id).ok_or(Error::Service)?;
    let mut p = MAGIC.to_vec();
    p.extend([RECORD_FORMAT_VERSION, kind]);
    p.extend(id);
    p.extend(e.control_head);
    Ok(p)
}
fn sign(mut p: Vec<u8>, chain: Hash, root: Hash, key: &SecretKey) -> Vec<u8> {
    p.extend(
        ecdsa::sign(Message::from_digest(signed_hash(chain, root, &p)), key).serialize_compact(),
    );
    p
}
/// New operator signs an acceptance bound to the registration's last control.
pub fn rotation_authorization<V: TransactionVerifier>(
    chain: &Chain<V>,
    id: Hash,
    new_operator: &SecretKey,
) -> Result<Vec<u8>, Error> {
    let e = chain.ledger().service_entry(&id).ok_or(Error::Service)?;
    let key = PublicKey::from_secret_key(new_operator).serialize();
    if key == e.owner || key == e.operator || chain.ledger().service_operator(&key).is_some() {
        return Err(Error::Service);
    }
    let mut p = prefix(chain, id, 2)?;
    p.extend(key);
    Ok(sign(p, chain.chain_id(), chain.root_id(), new_operator))
}
fn interval(e: &Entry, height: u64) -> Result<(u64, u64), Error> {
    if !e.score.banned() || !e.mature_for_block(height) {
        return Err(Error::Service);
    }
    let parent = height.checked_sub(1).ok_or(Error::Service)?;
    let end = parent
        .checked_sub((parent % PERIOD_BLOCKS + PERIOD_BLOCKS - u64::from(e.slot)) % PERIOD_BLOCKS)
        .ok_or(Error::Service)?;
    let start = end.checked_sub(PERIOD_BLOCKS).ok_or(Error::Service)?;
    if start == 0
        || start < e.next_start
        || end < e.score_height
        || height > end.checked_add(RESPONSE_BLOCKS).ok_or(Error::Service)?
    {
        return Err(Error::Service);
    }
    Ok((start, end))
}
pub fn reactivation_authorization<V: TransactionVerifier>(
    source: &crate::storage::DurableChain<V>,
    id: Hash,
    operator: &SecretKey,
) -> Result<Vec<u8>, Error> {
    let chain = source.chain().map_err(|_| Error::Storage)?;
    reactivation_authorization_with(chain, id, operator, |h| {
        let block = source.stored_block(h).map_err(|_| Error::Storage)?;
        crate::wire::encode(&block, &chain.config.limits, &chain.verifier)
    })
}
pub(super) fn reactivation_authorization_with<V: TransactionVerifier>(
    chain: &Chain<V>,
    id: Hash,
    operator: &SecretKey,
    mut read: impl FnMut(Hash) -> Result<Vec<u8>, Error>,
) -> Result<Vec<u8>, Error> {
    let e = chain.ledger().service_entry(&id).ok_or(Error::Service)?;
    if PublicKey::from_secret_key(operator).serialize() != e.operator {
        return Err(Error::Service);
    }
    let (start, end) = interval(e, chain.height().checked_add(1).ok_or(Error::Service)?)?;
    let mut p = prefix(chain, id, 3)?;
    p.extend(start.to_le_bytes());
    p.extend(chain.ancestor(chain.tip(), end)?);
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
    Ok(sign(p, chain.chain_id(), chain.root_id(), operator))
}
/// The owner reviews public operator authorization, then adds the final signature.
/// Preflight checks the full record; final transaction validation repeats it.
pub fn control_script<V: TransactionVerifier>(
    chain: &Chain<V>,
    authorization: &[u8],
    owner: &SecretKey,
) -> Result<Vec<u8>, Error> {
    if authorization.len() < HEADER + 32 + 32 + 64
        || authorization.len() > MAX_RECORD_BYTES - 64
        || !authorization.starts_with(MAGIC)
        || authorization[VERSION] != RECORD_FORMAT_VERSION
        || !(2..=3).contains(&authorization[KIND])
    {
        return Err(Error::Service);
    }
    let id = Hash::try_from(&authorization[HEADER..HEADER + 32]).map_err(|_| Error::Service)?;
    let e = chain.ledger().service_entry(&id).ok_or(Error::Service)?;
    if PublicKey::from_secret_key(owner).serialize() != e.owner {
        return Err(Error::Service);
    }
    let packet = finish_script(
        authorization.to_vec(),
        chain.chain_id(),
        chain.root_id(),
        owner,
    )?;
    chain.check_service_intent(&packet, &[])?;
    Ok(packet)
}
impl<V: TransactionVerifier> Chain<V> {
    pub(super) fn apply_control(
        &self,
        parent: Hash,
        height: u64,
        population: u32,
        staged: &mut Overlay<'_>,
        txid: Hash,
        p: &[u8],
    ) -> Result<(), Error> {
        let owner_body = p
            .get(..p.len().checked_sub(64).ok_or(Error::Service)?)
            .ok_or(Error::Service)?;
        let operator_body = if p[KIND] == 4 {
            owner_body
        } else {
            owner_body
                .get(..owner_body.len().checked_sub(64).ok_or(Error::Service)?)
                .ok_or(Error::Service)?
        };
        let mut r = Reader(operator_body.get(HEADER..).ok_or(Error::Service)?);
        let id = r.array()?;
        let head: Hash = r.array()?;
        let mut e = staged.service_entry(&id).cloned().ok_or(Error::Service)?;
        if e.control_head != head || staged.coin(&e.collateral).is_none() {
            return Err(Error::Service);
        }
        authorize(
            e.owner,
            signed_hash(self.chain_id(), self.root_id(), owner_body),
            &p[owner_body.len()..],
        )?;
        let key = if p[KIND] == 2 {
            let key = r.array()?;
            PublicKey::from_byte_array_compressed(key).map_err(|_| Error::Service)?;
            if !r.0.is_empty()
                || key == e.owner
                || key == e.operator
                || staged.service_operator(&key).is_some()
            {
                return Err(Error::Service);
            }
            e.operator = key;
            key
        } else {
            let (start, end) = interval(&e, height)?;
            if r.n()? != start || r.array::<32>()? != self.ancestor(parent, end)? {
                return Err(Error::Service);
            }
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
            e.next_start = end;
            e.last_proven_end = Some(end);
            e.operator
        };
        authorize(
            key,
            signed_hash(self.chain_id(), self.root_id(), operator_body),
            &owner_body[operator_body.len()..],
        )?;
        e.decay(height)?;
        // Reactivation starts at half maximum at inclusion, without retroactive decay.
        if p[KIND] == 3 {
            e.score = Score::from_parts(crate::pose::maximum_penalty(population) / 2, false)
                .ok_or(Error::Service)?;
        }
        e.control_head = txid;
        if !e.valid() {
            return Err(Error::Service);
        }
        staged.set_service(id, Some(e));
        Ok(())
    }
}
