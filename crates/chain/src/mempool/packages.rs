//! Bounded ancestor sets and exact marginal fee ordering; local policy only.
use super::*;
use std::{cmp::Ordering, collections::BTreeMap};
pub(super) const MAX_PACKAGE: usize = 25;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Score {
    pub fee: u64,
    pub bytes: usize,
    id: Hash,
    pub index: usize,
}
impl Ord for Score {
    fn cmp(&self, other: &Self) -> Ordering {
        // <=25 bounded Amounts and <=64 MiB of admitted bytes fit in u128.
        (u128::from(self.fee) * other.bytes as u128)
            .cmp(&(u128::from(other.fee) * self.bytes as u128))
            .then_with(|| other.id.cmp(&self.id))
            .then_with(|| other.index.cmp(&self.index))
            .then_with(|| self.fee.cmp(&other.fee))
            .then_with(|| self.bytes.cmp(&other.bytes))
    }
}
impl PartialOrd for Score {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
pub(super) struct Packages {
    pub members: Vec<Vec<usize>>,
    pub owners: Vec<Vec<usize>>,
    pub children: Vec<Vec<usize>>,
    pub pending: Vec<usize>,
    pub large: Vec<bool>,
    pub scores: Vec<Score>,
}
impl Packages {
    pub fn new(entries: &[Entry]) -> Result<Self, Error> {
        let positions: BTreeMap<_, _> =
            entries.iter().enumerate().map(|(i, e)| (e.id, i)).collect();
        let mut out = Self {
            members: Vec::new(),
            owners: vec![Vec::new(); entries.len()],
            children: vec![Vec::new(); entries.len()],
            pending: vec![0; entries.len()],
            large: vec![false; entries.len()],
            scores: Vec::new(),
        };
        for (i, e) in entries.iter().enumerate() {
            let mut members = BTreeSet::from([i]);
            for parent in &e.parents {
                let &p = positions.get(parent).ok_or(Error::Stale)?;
                if p >= i {
                    return Err(Error::Stale);
                }
                out.children[p].push(i);
                out.pending[i] += 1;
                if !out.large[i] {
                    members.extend(out.members[p].iter().copied());
                    out.large[i] = out.large[p] || members.len() > MAX_PACKAGE;
                }
            }
            let members: Vec<_> = if out.large[i] {
                vec![i]
            } else {
                members.into_iter().collect()
            };
            let fee = members.iter().map(|&j| entries[j].fee.atoms()).sum();
            let bytes = members.iter().map(|&j| entries[j].raw.len()).sum();
            for &j in &members {
                out.owners[j].push(i);
            }
            out.members.push(members);
            out.scores.push(Score {
                fee,
                bytes,
                id: e.id,
                index: i,
            });
        }
        Ok(out)
    }
}
