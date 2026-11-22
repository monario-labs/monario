//! Synthetic framing tests; no PoW, nonce search or network activity.
use super::*;
use crate::tests::{FixtureVerifier, block, cb, config, root};
use crate::wire::{decode, encode, read_compact_size};

fn fixture() -> (Chain<FixtureVerifier>, Block) {
    let chain = Chain::new(config(), root(), FixtureVerifier::default()).unwrap();
    cb(&chain, 1, 1, 100);
    let b = block(&chain, root().id, 1045, &[1]);
    (chain, b)
}
#[test]
fn canonical_encoding_and_every_truncation() {
    let (chain, b) = fixture();
    let raw = encode(&b, &chain.config.limits, &chain.verifier).unwrap();
    assert_eq!(raw.len(), HEADER_LEN + 1 + 8);
    assert_eq!(&raw[..HEADER_LEN], &b.header.encode());
    assert_eq!(raw[HEADER_LEN], 1);
    assert_eq!(&raw[HEADER_LEN + 1..], &1_u64.to_le_bytes());
    let restored = decode(&raw, &chain.config.limits, &chain.verifier).unwrap();
    assert_eq!(restored.header, b.header);
    assert_eq!(restored.transactions, b.transactions);
    for end in 0..raw.len() {
        assert!(decode(&raw[..end], &chain.config.limits, &chain.verifier).is_err());
    }
    let mut trailing = raw.clone();
    trailing.push(0);
    assert!(matches!(
        decode(&trailing, &chain.config.limits, &chain.verifier),
        Err(Error::BlockEncoding)
    ));
}

#[test]
fn bounded_deterministic_mutations_never_escape_block_framing() {
    let (chain, block) = fixture();
    let valid = encode(&block, &chain.config.limits, &chain.verifier).unwrap();
    let mut state = 0xd9b4_beef_734a_0021_u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    for case in 0..4096 {
        let mut bytes = valid.clone();
        let mutations = 1 + (next() % 8) as usize;
        for _ in 0..mutations {
            let at = next() as usize % bytes.len();
            bytes[at] ^= 1 << (next() % 8);
        }
        if case % 7 == 0 {
            bytes.truncate(next() as usize % (bytes.len() + 1));
        } else if case % 11 == 0 {
            bytes.push(next() as u8);
        }

        if let Ok(decoded) = decode(&bytes, &chain.config.limits, &chain.verifier) {
            assert_eq!(
                encode(&decoded, &chain.config.limits, &chain.verifier).unwrap(),
                bytes
            );
        }
    }
}

#[test]
fn noncanonical_counts_empty_blocks_and_resource_bounds() {
    let (chain, b) = fixture();
    let raw = encode(&b, &chain.config.limits, &chain.verifier).unwrap();
    for count in [
        vec![253, 1, 0],
        vec![254, 1, 0, 0, 0],
        vec![255, 1, 0, 0, 0, 0, 0, 0, 0],
        vec![0],
    ] {
        let changed = [&raw[..HEADER_LEN], &count, &raw[HEADER_LEN + 1..]].concat();
        assert!(decode(&changed, &chain.config.limits, &chain.verifier).is_err());
    }
    let mut tiny = chain.config.limits.clone();
    tiny.block_bytes = raw.len() - 1;
    assert!(matches!(
        decode(&raw, &tiny, &chain.verifier),
        Err(Error::ResourceLimit)
    ));
    assert!(matches!(
        encode(&b, &tiny, &chain.verifier),
        Err(Error::ResourceLimit)
    ));
    tiny = chain.config.limits.clone();
    tiny.transaction_bytes = 7;
    assert!(decode(&raw, &tiny, &chain.verifier).is_err());
    assert!(encode(&b, &tiny, &chain.verifier).is_err());
    let mut permissive = chain.config.limits.clone();
    permissive.block_bytes = usize::MAX;
    permissive.transaction_bytes = usize::MAX;
    let oversized = vec![0; crate::archive::MAX_BLOCK_BYTES + 1];
    assert!(matches!(
        decode(&oversized, &permissive, &chain.verifier),
        Err(Error::ResourceLimit)
    ));
    let oversized_block = Block {
        header: b.header.clone(),
        transactions: vec![vec![0; crate::archive::MAX_BLOCK_BYTES - HEADER_LEN]],
    };
    assert!(matches!(
        encode(&oversized_block, &permissive, &chain.verifier),
        Err(Error::ResourceLimit)
    ));
    let mut changed = raw.clone();
    changed[HEADER_LEN] = 100;
    assert!(decode(&changed, &chain.config.limits, &chain.verifier).is_err());
    assert!(decode(&raw, &chain.config.limits, &transactions::UnavailableV6).is_err());
}
#[test]
fn compact_size_boundaries_and_nonminimal_forms() {
    for (raw, value) in [
        (vec![252], 252),
        (vec![253, 253, 0], 253),
        (vec![253, 255, 255], 65535),
        (vec![254, 0, 0, 1, 0], 65536),
        (vec![254, 255, 255, 255, 255], u32::MAX as u64),
        (vec![255, 0, 0, 0, 0, 1, 0, 0, 0], 1_u64 << 32),
        (vec![255; 9], u64::MAX),
    ] {
        let mut bytes = raw.as_slice();
        assert_eq!(read_compact_size(&mut bytes).unwrap(), value);
        assert!(bytes.is_empty());
        for end in 0..raw.len() {
            assert!(read_compact_size(&mut &raw[..end]).is_err());
        }
    }
    for raw in [
        vec![253, 252, 0],
        vec![254, 255, 255, 0, 0],
        vec![255, 255, 255, 255, 255, 0, 0, 0, 0],
    ] {
        assert!(read_compact_size(&mut raw.as_slice()).is_err());
    }
}
#[test]
fn encoded_submission_rejects_before_pow_and_preserves_state() {
    let (mut chain, b) = fixture();
    let mut raw = encode(&b, &chain.config.limits, &chain.verifier).unwrap();
    raw.push(0);
    assert!(chain.submit_encoded(&raw, 2000).is_err());
    assert_eq!(chain.height(), 0);
    assert_eq!(chain.ledger().supply(), Amount::ZERO);
    raw.pop();
    raw[4..36].copy_from_slice(&[99; 32]);
    assert!(matches!(
        chain.submit_encoded(&raw, 2000),
        Err(Error::UnknownParent)
    ));
    assert_eq!(chain.height(), 0);
}

#[test]
fn count_prefix_boundary_exact_limits_and_transaction_segmentation() {
    let (chain, b) = fixture();
    let mut l = chain.config.limits.clone();
    l.transactions = 253;
    let many = Block {
        header: b.header.clone(),
        transactions: vec![b.transactions[0].clone(); 253],
    };
    let raw = encode(&many, &l, &chain.verifier).unwrap();
    assert_eq!(&raw[HEADER_LEN..HEADER_LEN + 3], &[253, 253, 0]);
    assert_eq!(raw.len(), HEADER_LEN + 3 + 253 * 8);
    l.block_bytes = raw.len();
    assert_eq!(
        decode(&raw, &l, &chain.verifier).unwrap().transactions,
        many.transactions
    );
    l.transactions = 252;
    assert!(decode(&raw, &l, &chain.verifier).is_err());
    let combined = Block {
        header: b.header,
        transactions: vec![[b.transactions[0].as_slice(), b.transactions[0].as_slice()].concat()],
    };
    assert!(encode(&combined, &chain.config.limits, &chain.verifier).is_err());
}

#[test]
fn invalid_framer_boundaries_fail_closed() {
    struct BadFramer(usize);
    impl TransactionVerifier for BadFramer {
        fn transaction_length(&self, _: &[u8]) -> Result<usize, TransactionError> {
            Ok(self.0)
        }
        fn verify(
            &self,
            _: &[u8],
            _: TransactionContext<'_>,
        ) -> Result<transactions::VerifiedTransaction, TransactionError> {
            Err(TransactionError::Invalid)
        }
        fn block_commitment(
            &self,
            _: Hash,
            _: u64,
            _: &[(Hash, Hash)],
        ) -> Result<Hash, TransactionError> {
            Err(TransactionError::Invalid)
        }
    }
    let (chain, b) = fixture();
    let raw = encode(&b, &chain.config.limits, &chain.verifier).unwrap();
    for size in [0, 9, usize::MAX] {
        assert!(matches!(
            decode(&raw, &chain.config.limits, &BadFramer(size)),
            Err(Error::BlockEncoding)
        ));
    }
}
