//! Record-aligned reverse byte edits; canonical state decoding remains authoritative.
use super::cache::{MAX, blob, bytes, count, put};
use super::*;
use sha2::{Digest, Sha256};
use std::{io::Cursor, ops::Range};

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    Header,
    Coins,
    Coin(OutPoint),
    Notes,
    Note(Hash),
    Observed,
    Account(u32),
}
struct Edit {
    offset: usize,
    remove: usize,
    restore: Zeroizing<Vec<u8>>,
}
pub(super) struct Prepared {
    pub(super) tip: Hash,
    height: u64,
    encoded: Zeroizing<Vec<u8>>,
    spans: Vec<(Key, Range<usize>)>,
    hash: Hash,
}

fn digest(b: &[u8]) -> Hash {
    #[cfg(test)]
    crate::restore_metrics::COUNTERS.with(|c| c.borrow_mut().hashes += 1);
    let mut h = Sha256::new();
    h.update(b"Monario/wallet-rollback/v2\0");
    h.update(b);
    h.finalize().into()
}
fn spans(s: &State, encoded: &[u8]) -> Result<Vec<(Key, Range<usize>)>, Error> {
    let mut r = Cursor::new(encoded);
    blob(&mut r, MAX)?;
    bytes::<32>(&mut r)?;
    bytes::<8>(&mut r)?;
    blob(&mut r, 4096)?;
    let mut ranges = vec![(Key::Header, 0..r.position() as usize)];
    let mut start = r.position() as usize;
    bytes::<4>(&mut r)?;
    ranges.push((Key::Coins, start..r.position() as usize));
    for key in s.coins.keys() {
        start = r.position() as usize;
        r.set_position(r.position() + 57);
        blob(&mut r, 10000)?;
        ranges.push((Key::Coin(*key), start..r.position() as usize));
    }
    start = r.position() as usize;
    bytes::<4>(&mut r)?;
    ranges.push((Key::Notes, start..r.position() as usize));
    for key in s.notes.keys() {
        start = r.position() as usize;
        r.set_position(r.position() + 681);
        blob(&mut r, 8192)?;
        ranges.push((Key::Note(*key), start..r.position() as usize));
    }
    start = r.position() as usize;
    bytes::<4>(&mut r)?;
    ranges.push((Key::Observed, start..r.position() as usize));
    for key in s.observed.keys() {
        start = r.position() as usize;
        r.set_position(r.position() + 52);
        ranges.push((Key::Account(*key), start..r.position() as usize));
    }
    if r.position() as usize != encoded.len() {
        return Err(Error::InvalidBody);
    }
    Ok(ranges)
}
fn edit(edits: &mut Vec<Edit>, offset: usize, before: &[u8], after: &[u8]) {
    if before == after {
        return;
    }
    let prefix = before.iter().zip(after).take_while(|(a, b)| a == b).count();
    let suffix = before[prefix..]
        .iter()
        .rev()
        .zip(after[prefix..].iter().rev())
        .take_while(|(a, b)| a == b)
        .count();
    let offset = offset + prefix;
    let remove = after.len() - prefix - suffix;
    let restore = &before[prefix..before.len() - suffix];
    if let Some(last) = edits.last_mut()
        && last.offset + last.remove == offset
    {
        last.remove += remove;
        last.restore.extend_from_slice(restore);
    } else {
        edits.push(Edit {
            offset,
            remove,
            restore: Zeroizing::new(restore.to_vec()),
        });
    }
}
impl Scanner {
    pub(super) fn capture_rollback(&self, state: &State) -> Result<Option<Prepared>, Error> {
        let encoded = match self.encode_state(state) {
            Ok(b) => b,
            Err(Error::Capacity) => return Ok(None),
            Err(e) => return Err(e),
        };
        let spans = spans(state, &encoded)?;
        let hash = digest(&encoded);
        Ok(Some(Prepared {
            tip: state.tip,
            height: state.height,
            encoded,
            spans,
            hash,
        }))
    }
    #[cfg(test)]
    pub(super) fn encode_delta(
        &self,
        before: &State,
        after: &State,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.finish_delta(
            &self.capture_rollback(before)?.ok_or(Error::Capacity)?,
            after,
        )
    }
    pub(super) fn finish_delta(
        &self,
        before: &Prepared,
        after: &State,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.finish_prepared_delta(
            before,
            &self.capture_rollback(after)?.ok_or(Error::Capacity)?,
        )
    }
    fn finish_prepared_delta(
        &self,
        before: &Prepared,
        after: &Prepared,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        if before.height.checked_add(1) != Some(after.height) {
            return Err(Error::InvalidBody);
        }
        let old = &before.encoded;
        let new = &after.encoded;
        let a = &before.spans;
        let b = &after.spans;
        let mut edits = Vec::new();
        let (mut i, mut j, mut cursor) = (0, 0, 0);
        while i < a.len() || j < b.len() {
            match (a.get(i), b.get(j)) {
                (Some((ka, ra)), Some((kb, rb))) if ka == kb => {
                    edit(&mut edits, rb.start, &old[ra.clone()], &new[rb.clone()]);
                    cursor = rb.end;
                    i += 1;
                    j += 1;
                }
                (Some((ka, ra)), next) if next.is_none_or(|(kb, _)| ka < kb) => {
                    edit(&mut edits, cursor, &old[ra.clone()], &[]);
                    i += 1;
                }
                (_, Some((_, rb))) => {
                    edit(&mut edits, rb.start, &[], &new[rb.clone()]);
                    cursor = rb.end;
                    j += 1;
                }
                _ => return Err(Error::InvalidBody),
            }
        }
        let mut out = Zeroizing::new(Vec::new());
        out.extend(before.tip);
        out.extend(after.tip);
        out.extend(before.hash);
        out.extend(after.hash);
        out.extend((old.len() as u32).to_le_bytes());
        out.extend((new.len() as u32).to_le_bytes());
        out.extend((edits.len() as u32).to_le_bytes());
        for e in edits {
            out.extend((e.offset as u32).to_le_bytes());
            out.extend((e.remove as u32).to_le_bytes());
            put(&mut out, &e.restore)?;
        }
        if out.len() > MAX {
            return Err(Error::Capacity);
        }
        Ok(out)
    }
    #[cfg(test)]
    pub(super) fn apply_delta(
        &self,
        source: &DurableChain<V6Verifier>,
        child: &State,
        delta: &[u8],
    ) -> Result<State, Error> {
        let prepared = self.capture_rollback(child)?.ok_or(Error::Capacity)?;
        self.apply_prepared_delta(source, &prepared, delta)
            .map(|(state, _)| state)
    }
    #[cfg(test)]
    pub(super) fn apply_prepared_delta(
        &self,
        source: &DurableChain<V6Verifier>,
        child: &Prepared,
        delta: &[u8],
    ) -> Result<(State, Prepared), Error> {
        self.apply_prepared_delta_checked(
            source,
            child,
            delta,
            &mut super::private_cache::PrivateChecks::default(),
        )
    }
    pub(super) fn apply_prepared_delta_checked(
        &self,
        source: &DurableChain<V6Verifier>,
        child: &Prepared,
        delta: &[u8],
        checks: &mut super::private_cache::PrivateChecks,
    ) -> Result<(State, Prepared), Error> {
        let mut r = Cursor::new(delta);
        let parent_tip = bytes(&mut r)?;
        let child_tip = bytes(&mut r)?;
        let parent_hash: Hash = bytes(&mut r)?;
        let child_hash: Hash = bytes(&mut r)?;
        let parent_len = count(&mut r, MAX)?;
        let child_len = count(&mut r, MAX)?;
        let new = &child.encoded;
        if child_tip != child.tip
            || source
                .block_info(&child_tip)
                .map_err(Error::Chain)?
                .and_then(|b| b.parent)
                != Some(parent_tip)
            || child_len != new.len()
            || child_hash != child.hash
        {
            return Err(Error::InvalidBody);
        }
        let mut old = Zeroizing::new(Vec::new());
        let mut cursor = 0;
        for i in 0..count(&mut r, MAX / 12)? {
            let offset = count(&mut r, child_len)?;
            let remove = count(&mut r, child_len)?;
            let restore = blob(&mut r, MAX)?;
            let end = offset.checked_add(remove).ok_or(Error::Capacity)?;
            if end > child_len
                || offset < cursor
                || (i > 0 && offset == cursor)
                || old
                    .len()
                    .saturating_add(offset - cursor)
                    .saturating_add(restore.len())
                    > parent_len
            {
                return Err(Error::InvalidBody);
            }
            old.extend_from_slice(&new[cursor..offset]);
            old.extend_from_slice(restore);
            cursor = end;
        }
        if r.position() as usize != delta.len()
            || old.len().saturating_add(child_len - cursor) != parent_len
        {
            return Err(Error::InvalidBody);
        }
        old.extend_from_slice(&new[cursor..]);
        let hash = digest(&old);
        if hash != parent_hash {
            return Err(Error::InvalidBody);
        }
        let parent = self
            .decode_state_checked(source, &old, checks)?
            .ok_or(Error::InvalidBody)?;
        let prepared = Prepared {
            tip: parent.tip,
            height: parent.height,
            spans: spans(&parent, &old)?,
            encoded: old,
            hash,
        };
        if parent.tip != parent_tip
            || parent.height.checked_add(1) != Some(child.height)
            || self.finish_prepared_delta(&prepared, child)?.as_slice() != delta
        {
            return Err(Error::InvalidBody);
        }
        Ok((parent, prepared))
    }
    #[cfg(test)]
    pub(super) fn apply_delta_reference(
        &self,
        source: &DurableChain<V6Verifier>,
        child: &State,
        delta: &[u8],
    ) -> Result<State, Error> {
        let mut r = Cursor::new(delta);
        let parent_tip = bytes(&mut r)?;
        let child_tip = bytes(&mut r)?;
        let parent_hash: Hash = bytes(&mut r)?;
        let child_hash: Hash = bytes(&mut r)?;
        let parent_len = count(&mut r, MAX)?;
        let child_len = count(&mut r, MAX)?;
        let new = self.encode_state(child)?;
        if child_tip != child.tip
            || source
                .block_info(&child_tip)
                .map_err(Error::Chain)?
                .and_then(|b| b.parent)
                != Some(parent_tip)
            || child_len != new.len()
            || child_hash != digest(&new)
        {
            return Err(Error::InvalidBody);
        }
        let mut old = Zeroizing::new(Vec::new());
        let mut cursor = 0;
        for i in 0..count(&mut r, MAX / 12)? {
            let offset = count(&mut r, child_len)?;
            let remove = count(&mut r, child_len)?;
            let restore = blob(&mut r, MAX)?;
            let end = offset.checked_add(remove).ok_or(Error::Capacity)?;
            if end > child_len
                || offset < cursor
                || (i > 0 && offset == cursor)
                || old
                    .len()
                    .saturating_add(offset - cursor)
                    .saturating_add(restore.len())
                    > parent_len
            {
                return Err(Error::InvalidBody);
            }
            old.extend_from_slice(&new[cursor..offset]);
            old.extend_from_slice(restore);
            cursor = end;
        }
        if r.position() as usize != delta.len()
            || old.len().saturating_add(child_len - cursor) != parent_len
        {
            return Err(Error::InvalidBody);
        }
        old.extend_from_slice(&new[cursor..]);
        if digest(&old) != parent_hash {
            return Err(Error::InvalidBody);
        }
        let parent = self.decode_state(source, &old)?.ok_or(Error::InvalidBody)?;
        if parent.tip != parent_tip
            || parent.height.checked_add(1) != Some(child.height)
            || self.encode_delta(&parent, child)?.as_slice() != delta
        {
            return Err(Error::InvalidBody);
        }
        Ok(parent)
    }
}
