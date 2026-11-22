//! Bounded historical-byte Merkle samples, derived only from validated block bodies.
use crate::{Hash, header::hash_domain};
pub const CHUNK_BYTES: usize = 1024;
pub const MAX_BLOCK_BYTES: usize = 5_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Summary {
    pub bytes: u32,
    pub root: Hash,
}
#[derive(Clone, Debug)]
pub struct Sample {
    pub data: Vec<u8>,
    pub path: Vec<Hash>,
}
fn leaf(index: usize, data: &[u8]) -> Hash {
    hash_domain(
        b"Monario/archive-leaf/v1\0",
        &[
            &(index as u32).to_le_bytes(),
            &(data.len() as u32).to_le_bytes(),
            data,
        ],
    )
}
fn parent(a: &Hash, b: &Hash) -> Hash {
    hash_domain(b"Monario/archive-pair/v1\0", &[a, b])
}
fn seal(bytes: u32, root: Hash) -> Summary {
    Summary {
        bytes,
        root: hash_domain(b"Monario/archive-root/v1\0", &[&bytes.to_le_bytes(), &root]),
    }
}
fn leaves(data: &[u8]) -> Option<Vec<Hash>> {
    if data.is_empty() || data.len() > MAX_BLOCK_BYTES {
        return None;
    }
    let mut level: Vec<_> = data
        .chunks(CHUNK_BYTES)
        .enumerate()
        .map(|(i, d)| leaf(i, d))
        .collect();
    level.resize(
        level.len().next_power_of_two(),
        hash_domain(b"Monario/archive-padding/v1\0", &[]),
    );
    Some(level)
}
pub fn summarize(data: &[u8]) -> Option<Summary> {
    let mut level = leaves(data)?;
    while level.len() > 1 {
        level = level
            .chunks_exact(2)
            .map(|p| parent(&p[0], &p[1]))
            .collect();
    }
    Some(seal(data.len() as u32, level[0]))
}
pub fn sample(data: &[u8], index: usize) -> Option<Sample> {
    let mut level = leaves(data)?;
    let start = index.checked_mul(CHUNK_BYTES)?;
    let chunk = data.get(start..data.len().min(start.checked_add(CHUNK_BYTES)?))?;
    if chunk.is_empty() {
        return None;
    }
    let mut path = Vec::new();
    let mut i = index;
    while level.len() > 1 {
        path.push(level[i ^ 1]);
        i /= 2;
        level = level
            .chunks_exact(2)
            .map(|p| parent(&p[0], &p[1]))
            .collect();
    }
    Some(Sample {
        data: chunk.to_vec(),
        path,
    })
}
impl Summary {
    pub fn chunks(self) -> Option<usize> {
        let n = self.bytes as usize;
        (n > 0 && n <= MAX_BLOCK_BYTES).then(|| n.div_ceil(CHUNK_BYTES))
    }
    pub fn verify(self, index: usize, proof: &Sample) -> bool {
        let Some(count) = self.chunks() else {
            return false;
        };
        if index >= count || proof.path.len() != count.next_power_of_two().ilog2() as usize {
            return false;
        }
        let expected = (self.bytes as usize - index * CHUNK_BYTES).min(CHUNK_BYTES);
        if proof.data.len() != expected {
            return false;
        }
        let mut h = leaf(index, &proof.data);
        let mut i = index;
        for sibling in &proof.path {
            h = if i & 1 == 0 {
                parent(&h, sibling)
            } else {
                parent(sibling, &h)
            };
            i /= 2;
        }
        seal(self.bytes, h) == self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_samples_lengths_padding_and_mutations() {
        for n in [1, 1024, 1025, 3073, MAX_BLOCK_BYTES] {
            let data: Vec<_> = (0..n).map(|i| i as u8).collect();
            let summary = summarize(&data).unwrap();
            for i in [0, summary.chunks().unwrap() - 1] {
                let mut proof = sample(&data, i).unwrap();
                assert!(summary.verify(i, &proof));
                proof.data[0] ^= 1;
                assert!(!summary.verify(i, &proof));
                proof.data[0] ^= 1;
                proof.path.push([0; 32]);
                assert!(!summary.verify(i, &proof));
            }
            assert!(sample(&data, summary.chunks().unwrap()).is_none());
        }
        assert!(summarize(&[]).is_none());
        assert!(summarize(&vec![0; MAX_BLOCK_BYTES + 1]).is_none());
    }
}
