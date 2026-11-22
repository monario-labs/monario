//! Operation-local proofs of deterministic private-note predicates, never disk trust flags.
use super::cache::{blob, bytes, invalid};
use super::*;
use sha2::{Digest, Sha256};
use std::io::Cursor;
use zcash_primitives::merkle_tree::{read_commitment_tree, read_incremental_witness};

const KEY_BYTES: usize = 2 * 1024 * 1024;
const ENTRIES: usize = 4096;
#[derive(Clone, Copy)]
struct Identity {
    note: orchard::Note,
    cmx: MerkleHashOrchard,
}
struct KnownIdentity {
    key: Zeroizing<Vec<u8>>,
    identity: Identity,
}
struct KnownWitness {
    key: Zeroizing<Vec<u8>>,
    witness: IncrementalWitness<MerkleHashOrchard, 32>,
}
struct KnownFrontier {
    key: Zeroizing<Vec<u8>>,
    tree: CommitmentTree<MerkleHashOrchard, 32>,
}
#[derive(Default)]
pub(super) struct PrivateChecks {
    identities: BTreeMap<Hash, KnownIdentity>,
    witnesses: BTreeMap<Hash, KnownWitness>,
    frontiers: BTreeMap<Hash, KnownFrontier>,
    key_bytes: usize,
    #[cfg(test)]
    uncached: bool,
}

// Depth-32 witnesses have fewer than 32 parents and at most 32 filled nodes.
// Bound vector counts before the upstream legacy constructor can allocate or panic.
fn optional_node(r: &mut Cursor<&[u8]>) -> Result<bool, Error> {
    match bytes::<1>(r)?[0] {
        0 => return Ok(false),
        1 => {
            bytes::<32>(r)?;
        }
        _ => return Err(Error::InvalidBody),
    }
    Ok(true)
}
fn tree_shape(r: &mut Cursor<&[u8]>, nonempty: bool) -> Result<(), Error> {
    let left = optional_node(r)?;
    let right = optional_node(r)?;
    let n = bytes::<1>(r)?[0];
    if n >= 32 {
        return Err(Error::InvalidBody);
    }
    let mut occupied = false;
    for _ in 0..n {
        occupied |= optional_node(r)?;
    }
    if !left && (nonempty || right || occupied) {
        return Err(Error::InvalidBody);
    }
    Ok(())
}
fn witness_shape(raw: &[u8]) -> Result<(), Error> {
    let mut r = Cursor::new(raw);
    tree_shape(&mut r, true)?;
    let n = bytes::<1>(&mut r)?[0];
    if n > 32 {
        return Err(Error::InvalidBody);
    }
    for _ in 0..n {
        bytes::<32>(&mut r)?;
    }
    match bytes::<1>(&mut r)?[0] {
        0 => {}
        1 => tree_shape(&mut r, true)?,
        _ => return Err(Error::InvalidBody),
    }
    if r.position() as usize != raw.len() {
        return Err(Error::InvalidBody);
    }
    Ok(())
}
impl PrivateChecks {
    pub(super) fn read_tree(
        &mut self,
        r: &mut Cursor<&[u8]>,
        profile: Hash,
        root: Hash,
    ) -> Result<CommitmentTree<MerkleHashOrchard, 32>, Error> {
        let raw = blob(r, 4096)?;
        let mut key = Zeroizing::new(Vec::with_capacity(raw.len() + 64));
        key.extend(profile);
        key.extend(root);
        key.extend_from_slice(raw);
        let hash: Hash = Sha256::digest(key.as_slice()).into();
        if let Some(known) = self
            .frontiers
            .get(&hash)
            .filter(|known| known.key.as_slice() == key.as_slice())
        {
            #[cfg(test)]
            crate::restore_metrics::COUNTERS.with(|c| c.borrow_mut().frontier_reuses += 1);
            return Ok(known.tree.clone());
        }
        let mut shape = Cursor::new(raw);
        tree_shape(&mut shape, false)?;
        if shape.position() as usize != raw.len() {
            return Err(Error::InvalidBody);
        }
        let tree: CommitmentTree<MerkleHashOrchard, 32> =
            read_commitment_tree(raw).map_err(invalid)?;
        #[cfg(test)]
        crate::restore_metrics::COUNTERS.with(|c| c.borrow_mut().private_frontiers += 1);
        if tree.root().to_bytes() != root {
            return Err(Error::InvalidBody);
        }
        if !self.frontiers.contains_key(&hash) && self.room(self.frontiers.len(), key.len()) {
            self.key_bytes += key.len();
            self.frontiers.insert(
                hash,
                KnownFrontier {
                    key,
                    tree: tree.clone(),
                },
            );
        }
        Ok(tree)
    }
    #[cfg(test)]
    pub(super) fn uncached() -> Self {
        Self {
            uncached: true,
            ..Self::default()
        }
    }
    #[cfg(test)]
    pub(super) fn at_capacity() -> Self {
        Self {
            key_bytes: KEY_BYTES,
            ..Self::default()
        }
    }
    fn room(&self, entries: usize, bytes: usize) -> bool {
        #[cfg(test)]
        if self.uncached {
            return false;
        }
        entries < ENTRIES && self.key_bytes.saturating_add(bytes) <= KEY_BYTES
    }
    pub(super) fn read_note(
        &mut self,
        r: &mut Cursor<&[u8]>,
        profile: Hash,
        accounts: &[WatchAccount],
        root: Hash,
    ) -> Result<(Hash, ReceivedNote), Error> {
        let raw = Zeroizing::new(bytes::<169>(r)?);
        let mut fields = Cursor::new(raw.as_slice());
        let nf = bytes(&mut fields)?;
        let account = u32::from_le_bytes(bytes(&mut fields)?);
        let scope = match bytes::<1>(&mut fields)?[0] {
            0 => Scope::External,
            1 => Scope::Internal,
            _ => return Err(Error::InvalidBody),
        };
        let index = u128::from_le_bytes(bytes(&mut fields)?);
        let a = accounts
            .iter()
            .find(|a| a.id == account)
            .ok_or(Error::InvalidBody)?;
        let fvk = Zeroizing::new(a.viewing.to_bytes());
        let mut key = Zeroizing::new(Vec::with_capacity(297));
        key.extend(profile);
        key.extend_from_slice(fvk.as_slice());
        key.extend_from_slice(raw.as_slice());
        let identity = if let Some(known) = self
            .identities
            .get(&nf)
            .filter(|known| known.key.as_slice() == key.as_slice())
        {
            #[cfg(test)]
            crate::restore_metrics::COUNTERS.with(|c| c.borrow_mut().identity_reuses += 1);
            known.identity
        } else {
            #[cfg(test)]
            crate::restore_metrics::COUNTERS.with(|c| c.borrow_mut().private_identities += 1);
            let recipient = Option::from(orchard::Address::from_raw_address_bytes(&bytes(
                &mut fields,
            )?))
            .ok_or(Error::InvalidBody)?;
            let value =
                orchard::value::NoteValue::from_raw(u64::from_le_bytes(bytes(&mut fields)?));
            let rho = Option::from(orchard::note::Rho::from_bytes(&bytes(&mut fields)?))
                .ok_or(Error::InvalidBody)?;
            let seed = Option::from(orchard::note::RandomSeed::from_bytes(
                bytes(&mut fields)?,
                &rho,
            ))
            .ok_or(Error::InvalidBody)?;
            let version = match bytes::<1>(&mut fields)?[0] {
                2 => orchard::note::NoteVersion::V2,
                3 => orchard::note::NoteVersion::V3,
                _ => return Err(Error::InvalidBody),
            };
            let note: orchard::Note = Option::from(orchard::Note::from_parts(
                recipient, value, rho, seed, version,
            ))
            .ok_or(Error::InvalidBody)?;
            let upstream = if scope == Scope::External {
                orchard::keys::Scope::External
            } else {
                orchard::keys::Scope::Internal
            };
            let expected = a
                .viewing
                .to_ivk(upstream)
                .diversifier_index(&recipient)
                .map(u128::from);
            if value.inner() == 0
                || nf != note.nullifier(&a.viewing).to_bytes()
                || expected != Some(index)
            {
                return Err(Error::InvalidBody);
            }
            let identity = Identity {
                cmx: MerkleHashOrchard::from_cmx(&note.commitment().into()),
                note,
            };
            if !self.identities.contains_key(&nf) && self.room(self.identities.len(), key.len()) {
                self.key_bytes += key.len();
                self.identities.insert(nf, KnownIdentity { key, identity });
            }
            identity
        };
        // Memos are untrusted payload, never part of a reused cryptographic predicate.
        let memo = Zeroizing::new(bytes(r)?);
        let raw_witness = blob(r, 8192)?;
        let mut key = Zeroizing::new(Vec::with_capacity(raw_witness.len() + 96));
        key.extend(profile);
        key.extend(root);
        key.extend(identity.cmx.to_bytes());
        key.extend_from_slice(raw_witness);
        let hash: Hash = Sha256::digest(key.as_slice()).into();
        let witness = if let Some(known) = self
            .witnesses
            .get(&hash)
            .filter(|known| known.key.as_slice() == key.as_slice())
        {
            #[cfg(test)]
            crate::restore_metrics::COUNTERS.with(|c| c.borrow_mut().witness_reuses += 1);
            known.witness.clone()
        } else {
            witness_shape(raw_witness)?;
            let witness: IncrementalWitness<MerkleHashOrchard, 32> =
                read_incremental_witness(raw_witness).map_err(invalid)?;
            let position = u64::from(witness.witnessed_position());
            let available = 32 - position.count_ones() as usize;
            if witness.filled().len() > available {
                return Err(Error::InvalidBody);
            }
            if witness.cursor().is_some() {
                let depth = (0..32)
                    .filter(|level| position & (1u64 << level) == 0)
                    .nth(witness.filled().len());
                if depth.is_none_or(|d| d == 0) {
                    return Err(Error::InvalidBody);
                }
            }
            #[cfg(test)]
            crate::restore_metrics::COUNTERS.with(|c| c.borrow_mut().private_roots += 1);
            if witness
                .path()
                .ok_or(Error::InvalidBody)?
                .root(identity.cmx)
                .to_bytes()
                != root
            {
                return Err(Error::InvalidBody);
            }
            if !self.witnesses.contains_key(&hash) && self.room(self.witnesses.len(), key.len()) {
                self.key_bytes += key.len();
                self.witnesses.insert(
                    hash,
                    KnownWitness {
                        key,
                        witness: witness.clone(),
                    },
                );
            }
            witness
        };
        #[cfg(test)]
        {
            let exit = crate::restore_metrics::COUNTERS.with(|c| {
                let v = c.borrow();
                v.stop_after_private_reuse && v.identity_reuses > 0 && v.witness_reuses > 0
            });
            if exit {
                std::process::exit(85);
            }
        }
        Ok((
            nf,
            ReceivedNote {
                account,
                scope,
                index,
                note: identity.note,
                memo,
                witness,
            },
        ))
    }
}
