//! Local admission bounds, recomputed by ordinary admission during every rebuild.
use super::*;

impl Mempool {
    pub(super) fn check_topology(
        &self,
        parents: &BTreeSet<Hash>,
        entries: &BTreeMap<Hash, usize>,
    ) -> Result<Vec<usize>, Error> {
        if parents.is_empty() {
            return Ok(Vec::new());
        }
        if parents.len() >= MAX_ANCESTORS {
            return Err(Error::Capacity);
        }
        let mut pending = parents.clone();
        let mut ancestors = BTreeSet::new();
        let mut indices = Vec::new();
        while let Some(id) = pending.pop_first() {
            if !ancestors.insert(id) {
                continue;
            }
            // The candidate itself also counts toward the ancestor limit.
            if ancestors.len() >= MAX_ANCESTORS {
                return Err(Error::Capacity);
            }
            let index = *entries.get(&id).ok_or(Error::Stale)?;
            let entry = self
                .entries
                .get(index)
                .filter(|e| e.id == id)
                .ok_or(Error::Stale)?;
            if entry.descendants >= MAX_DESCENDANTS {
                return Err(Error::Capacity);
            }
            pending.extend(
                entry
                    .parents
                    .iter()
                    .filter(|id| !ancestors.contains(*id))
                    .copied(),
            );
            indices.push(index);
        }
        Ok(indices)
    }
}
