use super::*;

#[test]
fn canonical_id_includes_coinbase_but_never_authenticates_bytes() {
    for coinbase in [false, true] {
        let raw = fixture(coinbase, 1, 0, vec![0x51, 0]);
        let id = transaction_id(&raw).unwrap();
        let tx = decode(&raw).unwrap();
        assert_eq!(id, *tx.txid().as_ref());
        for end in 0..raw.len() {
            assert!(transaction_id(&raw[..end]).is_err());
        }
        let mut trailing = raw.clone();
        trailing.push(0);
        assert!(transaction_id(&trailing).is_err());
        let mut altered = raw.clone();
        let at = altered.windows(3).position(|w| w == [2, 0x51, 0]).unwrap() + 2;
        altered[at] = 0x51;
        assert_ne!(raw, altered);
        assert_eq!(transaction_id(&altered).unwrap(), id);
    }
}

#[test]
fn bounded_deterministic_mutations_never_escape_transaction_framing() {
    let valid = fixture(false, 0, 0, vec![1, 2, 3, 4]);
    let mut state = 0x8f3d_9a72_41c6_b50d_u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    for case in 0..4096 {
        let mut bytes = if case % 4 == 0 {
            (0..(next() as usize % 512)).map(|_| next() as u8).collect()
        } else {
            valid.clone()
        };
        let mutations = 1 + (next() % 8) as usize;
        for _ in 0..mutations {
            if bytes.is_empty() || case % 4 == 0 {
                break;
            }
            let at = next() as usize % bytes.len();
            bytes[at] ^= 1 << (next() % 8);
        }
        if case % 7 == 0 && !bytes.is_empty() {
            bytes.truncate(next() as usize % (bytes.len() + 1));
        } else if case % 11 == 0 {
            bytes.push(next() as u8);
        }

        if let Ok(length) = V6Verifier.transaction_length(&bytes) {
            assert!(length > 0);
            assert!(length <= bytes.len());
        }
        if transaction_id(&bytes).is_ok() {
            assert_eq!(V6Verifier.transaction_length(&bytes).unwrap(), bytes.len());
        }
    }
}

use monario_chain::{
    LedgerView,
    ledger::{Coin, ShieldedTree},
};

pub(super) struct State {
    tree: ShieldedTree,
    missing: bool,
    pub(super) coin: Coin,
}
impl Default for State {
    fn default() -> Self {
        Self {
            tree: ShieldedTree::default(),
            missing: false,
            coin: Coin {
                value: Amount::from_atoms(100).unwrap(),
                script: vec![0x51],
                created_height: 0,
                coinbase: false,
            },
        }
    }
}
impl LedgerView for State {
    fn coin(&self, point: &OutPoint) -> Option<&Coin> {
        (!self.missing && point.transaction == [7; 32] && point.index == 0).then_some(&self.coin)
    }
    fn contains_transaction(&self, _: &Hash) -> bool {
        false
    }
    fn supply(&self) -> monario_monetary::Supply {
        self.coin.value.into()
    }
    fn shielded(&self) -> &ShieldedTree {
        &self.tree
    }
    fn has_nullifier(&self, _: &Hash) -> bool {
        false
    }
    fn has_anchor(&self, root: &Hash) -> bool {
        *root == self.tree.root()
    }
}
fn fixture(coinbase: bool, expiry: u32, lock: u32, sig: Vec<u8>) -> Vec<u8> {
    let input = tb::TxIn::from_parts(
        tb::OutPoint::new(
            if coinbase { [0; 32] } else { [7; 32] },
            if coinbase { u32::MAX } else { 0 },
        ),
        Script(script::Code(sig)),
        0,
    );
    let data: transaction::TransactionData<transaction::Authorized> =
        transaction::TransactionData::from_parts_v6(
            BranchId::Nu6_3,
            lock,
            expiry.into(),
            Some(tb::Bundle {
                vin: vec![input],
                vout: vec![tb::TxOut::new(
                    Zatoshis::from_u64(90).unwrap(),
                    Script(script::Code(vec![0x51])),
                )],
                authorization: tb::Authorized,
            }),
            None,
            None,
            None,
        );
    let mut raw = Vec::new();
    data.freeze().unwrap().write(&mut raw).unwrap();
    raw
}
fn verify(raw: &[u8], state: &State) -> Result<VerifiedTransaction, Error> {
    V6Verifier.verify(
        raw,
        TransactionContext {
            height: 1,
            median_time_past: 1000,
            state,
        },
    )
}
#[test]
fn canonical_v6_and_public_anyone_can_spend_scripts() {
    let raw = fixture(false, 0, 0, vec![]);
    let state = State::default();
    let tx = verify(&raw, &state).unwrap();
    assert_eq!(tx.inputs.len(), 1);
    assert_eq!(tx.outputs[0].value.atoms(), 90);
    let mut failing = State::default();
    failing.coin.script = vec![0];
    assert!(verify(&raw, &failing).is_err());
    // OP_CHECKSIG cannot be satisfied with an empty or malformed signature.
    failing.coin.script = vec![0xac];
    assert!(verify(&raw, &failing).is_err());
}
#[test]
fn truncated_trailing_cross_network_expiry_and_locktime_fail() {
    let state = State::default();
    let raw = fixture(false, 0, 0, vec![]);
    for n in 0..raw.len() {
        assert!(verify(&raw[..n], &state).is_err());
    }
    let mut extra = raw.clone();
    extra.push(0);
    assert!(verify(&extra, &state).is_err());
    let mut earlier = raw.clone();
    earlier[8..12].copy_from_slice(b"MON6");
    assert!(verify(&earlier, &state).is_err());
    let mut zcash = raw.clone();
    zcash[8..12].copy_from_slice(&0x37a5165b_u32.to_le_bytes());
    assert!(verify(&zcash, &state).is_err());
    let mut future = raw;
    future[8..12].copy_from_slice(&0x77190ad9_u32.to_le_bytes());
    assert!(verify(&future, &state).is_err());
    assert!(verify(&fixture(false, 0, 2, vec![]), &state).is_err());
    assert!(
        V6Verifier
            .verify(
                &fixture(false, 1, 0, vec![]),
                TransactionContext {
                    height: 2,
                    median_time_past: 1000,
                    state: &state
                }
            )
            .is_err()
    );
}
#[test]
fn coinbase_height_and_expiry_are_checked_without_keys() {
    let state = State::default();
    assert_eq!(
        verify(&fixture(true, 1, 0, vec![0x51, 0]), &state)
            .unwrap()
            .coinbase_height,
        Some(1)
    );
    assert!(verify(&fixture(true, 0, 0, vec![0x51, 0]), &state).is_err());
    assert!(verify(&fixture(true, 1, 0, vec![1, 1]), &state).is_err());
}
#[test]
fn branch_identity_is_distinct_and_auth_commitment_is_bound() {
    assert_eq!(u32::from(BranchId::Nu6_3), BRANCH_ID);
    assert!(BranchId::try_from(0x37a5165b).is_err());
    let a = V6Verifier
        .block_commitment_with_state([1; 32], 1, &[([2; 32], [3; 32])], [4; 32])
        .unwrap();
    let b = V6Verifier
        .block_commitment_with_state([1; 32], 1, &[([2; 32], [5; 32])], [4; 32])
        .unwrap();
    assert_ne!(a, b);
}

#[test]
fn canonical_ironwood_with_forged_proof_is_rejected_by_corrected_verifier() {
    // Public ak from Orchard's key-components test vectors. No secret key is
    // generated or used. All-zero proof/signatures deliberately forge no value.
    let ak = [
        0x74, 0x0b, 0xbe, 0x5d, 0x05, 0x80, 0xb2, 0xca, 0xd4, 0x30, 0x18, 0x0d, 0x02, 0xcc, 0x12,
        0x8b, 0x9a, 0x14, 0x0d, 0x5e, 0x07, 0xc1, 0x51, 0x72, 0x1d, 0xc1, 0x6d, 0x25, 0xd4, 0xe2,
        0x0f, 0x15,
    ];
    let state = State::default();
    let mut bundle = vec![1];
    bundle.extend([0; 64]); // cv_net, nullifier
    bundle.extend(ak);
    bundle.extend([0; 32]); // rk, cmx
    bundle.extend(ak); // nonidentity ephemeral public key
    bundle.extend(vec![0; orchard::note_encryption::ENC_CIPHERTEXT_SIZE + 80]);
    bundle.push(7);
    bundle.extend(0_i64.to_le_bytes());
    bundle.extend(state.tree.root());
    let proof_size = orchard::Proof::expected_proof_size(1);
    assert!(proof_size > 252 && proof_size <= 65535);
    bundle.push(253);
    bundle.extend((proof_size as u16).to_le_bytes());
    bundle.extend(vec![0; proof_size]);
    bundle.extend([0; 128]);
    let parsed = transaction::components::orchard::read_v6_bundle(
        bundle.as_slice(),
        BranchId::Nu6_3,
        orchard::ValuePool::Ironwood,
    )
    .unwrap()
    .unwrap();
    assert_eq!(parsed.actions().len(), 1);
    let key = KEY.get_or_init(|| VerifyingKey::build(OrchardCircuitVersion::PostNu6_3));
    assert!(parsed.verify_proof(key).is_err());
    assert!(
        parsed
            .actions()
            .head
            .rk()
            .verify(&[0; 32], parsed.actions().head.authorization())
            .is_err()
    );
    let data: transaction::TransactionData<transaction::Authorized> =
        transaction::TransactionData::from_parts_v6(
            BranchId::Nu6_3,
            0,
            0.into(),
            None,
            None,
            None,
            Some(parsed),
        );
    let mut raw = Vec::new();
    data.freeze().unwrap().write(&mut raw).unwrap();
    assert!(verify(&raw, &state).is_err());
    // Canonical proof length enforcement rejects padding before proof verification.
    let mut padded = bundle;
    let offset = 1 + 32 * 5 + orchard::note_encryption::ENC_CIPHERTEXT_SIZE + 80 + 1 + 8 + 32;
    padded[offset + 1..offset + 3].copy_from_slice(&((proof_size + 1) as u16).to_le_bytes());
    padded.insert(offset + 3, 0);
    assert!(
        transaction::components::orchard::read_v6_bundle(
            padded.as_slice(),
            BranchId::Nu6_3,
            orchard::ValuePool::Ironwood
        )
        .is_err()
    );
}

#[test]
fn public_block_submission_uses_real_v6_and_randomx() {
    // One fixed header and nonce, never a search loop. No root block is created.
    use monario_chain::{Block, Chain, Config, Limits, Root, header::Header};
    let state = State::default();
    let raw = fixture(true, 1, 0, vec![0x51, 0]);
    let effects = verify(&raw, &state).unwrap();
    let root = Root {
        id: [3; 32],
        timestamp: 1000,
        commitment: [4; 32],
    };
    let commitment = V6Verifier
        .block_commitment_with_state(
            root.commitment,
            1,
            &[(effects.id, effects.authorization_digest)],
            state.tree.root(),
        )
        .unwrap();
    let config = Config {
        chain_id: [11; 32],
        initial_bits: 0x2100ffff,
        pow_limit_bits: 0x2100ffff,
        half_life_seconds: 3600,
        asert_from_first_block: false,
        seed_interval: 8,
        seed_lag: 2,
        coinbase_maturity: 2,
        max_future_seconds: 120,
        retained_blocks: 10,
        limits: Limits {
            block_bytes: 100000,
            transaction_bytes: 10000,
            transactions: 100,
            inputs_per_transaction: 100,
            outputs_per_transaction: 100,
            script_bytes: 1000,
        },
    };
    let header = Header {
        version: 1,
        parent: root.id,
        merkle_root: effects.id,
        commitment,
        timestamp: 1045,
        bits: config.initial_bits,
        nonce: [0; 32],
    };
    let payload = monario_chain::wire::encode(
        &Block {
            header,
            transactions: vec![raw],
        },
        &config.limits,
        &V6Verifier,
    )
    .unwrap();
    let mut chain = Chain::new(config.clone(), root, V6Verifier).unwrap();
    let before = chain.tip();
    let mut trailing = payload.clone();
    trailing.push(0);
    assert!(chain.submit_encoded(&trailing, 1045).is_err());
    assert_eq!(chain.tip(), before);
    let mut changed = payload.clone();
    let index = changed.len() - 5;
    changed[index] ^= 1;
    assert!(monario_chain::wire::decode(&changed, &config.limits, &V6Verifier).is_ok());
    assert!(matches!(
        chain.submit_encoded(&changed, 1045),
        Err(monario_chain::Error::MerkleRoot)
    ));
    assert_eq!(chain.tip(), before);
    assert_eq!(chain.ledger().supply(), Amount::ZERO);
    let accepted = chain.submit_encoded(&payload, 1045).unwrap();
    assert!(accepted.became_best);
    assert_eq!(chain.height(), 1);
    assert_eq!(chain.ledger().supply().atoms(), 90);
    let expected = chain.tip();
    drop(chain);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("encoded.sqlite");
    let mut durable =
        monario_chain::storage::DurableChain::open(&path, config.clone(), root, V6Verifier, 1045)
            .unwrap();
    assert!(durable.submit_encoded(&trailing, 1045).is_err());
    assert_eq!(durable.chain().unwrap().height(), 0);
    assert_eq!(durable.submit_encoded(&payload, 1045).unwrap().id, expected);
    drop(durable);
    let durable =
        monario_chain::storage::DurableChain::open(&path, config, root, V6Verifier, 1045).unwrap();
    assert_eq!(durable.chain().unwrap().tip(), expected);
    assert_eq!(durable.chain().unwrap().ledger().supply().atoms(), 90);
}

#[test]
fn bounded_v6_framing_matches_upstream_and_rejects_every_truncation() {
    for raw in [
        fixture(true, 1, 0, vec![0x51, 0]),
        include_bytes!("../tests/fixtures/signed-v6.bin").to_vec(),
        include_bytes!("../tests/fixtures/private-v6.bin").to_vec(),
    ] {
        assert_eq!(V6Verifier.transaction_length(&raw).unwrap(), raw.len());
        let joined = [raw.as_slice(), raw.as_slice()].concat();
        assert_eq!(V6Verifier.transaction_length(&joined).unwrap(), raw.len());
        for end in 0..raw.len() {
            assert!(
                V6Verifier.transaction_length(&raw[..end]).is_err(),
                "truncation {end}"
            );
        }
        let mut cursor = std::io::Cursor::new(&joined);
        let parsed = Transaction::read(&mut cursor, BranchId::Nu6_3).unwrap();
        assert_eq!(cursor.position(), raw.len() as u64);
        let mut canonical = Vec::new();
        parsed.write(&mut canonical).unwrap();
        assert_eq!(canonical, raw);
    }
}

#[test]
fn malformed_v6_counts_scripts_and_pools_fail_preflight() {
    let raw = fixture(false, 0, 0, vec![]);
    // Transparent input count begins at byte 24, its script length at byte 61.
    for (offset, prefix) in [
        (24, vec![253, 1, 0]),
        (24, vec![255; 9]),
        (61, vec![254, 0, 0, 0, 1]),
    ] {
        let changed = [&raw[..offset], &prefix, &raw[offset + 1..]].concat();
        assert!(V6Verifier.transaction_length(&changed).is_err());
        assert!(verify(&changed, &State::default()).is_err());
    }
    for offset in [raw.len() - 4, raw.len() - 3, raw.len() - 2] {
        let mut changed = raw.clone();
        changed[offset] = 1;
        assert!(V6Verifier.transaction_length(&changed).is_err());
    }
    let mut wrong = raw.clone();
    wrong[8..12].copy_from_slice(&0x37a5_165b_u32.to_le_bytes());
    assert!(V6Verifier.transaction_length(&wrong).is_err());
    let mut wrong = raw.clone();
    wrong[0] = 5;
    assert!(V6Verifier.transaction_length(&wrong).is_err());
    let private = include_bytes!("../tests/fixtures/private-v6.bin");
    let proof = orchard::Proof::expected_proof_size(1);
    let prefix_end = private.len() - proof - 128;
    let mut changed = private.to_vec();
    changed[prefix_end - 2..prefix_end].copy_from_slice(&((proof + 1) as u16).to_le_bytes());
    assert!(V6Verifier.transaction_length(&changed).is_err());
}

#[test]
fn signed_and_private_block_payload_roundtrips_and_mutations() {
    use monario_chain::{Block, Limits, header::Header, wire};
    let limits = Limits {
        block_bytes: 20000,
        transaction_bytes: 10000,
        transactions: 10,
        inputs_per_transaction: 100,
        outputs_per_transaction: 100,
        script_bytes: 1000,
    };
    let block = Block {
        header: Header {
            version: 1,
            parent: [3; 32],
            merkle_root: [0; 32],
            commitment: [0; 32],
            timestamp: 1045,
            bits: 0x207fffff,
            nonce: [0; 32],
        },
        transactions: vec![
            include_bytes!("../tests/fixtures/signed-v6.bin").to_vec(),
            include_bytes!("../tests/fixtures/private-v6.bin").to_vec(),
        ],
    };
    let raw = wire::encode(&block, &limits, &V6Verifier).unwrap();
    let parsed = wire::decode(&raw, &limits, &V6Verifier).unwrap();
    assert_eq!(parsed.transactions, block.transactions);
    assert_eq!(wire::encode(&parsed, &limits, &V6Verifier).unwrap(), raw);
    // Deterministic hostile-input property: every successfully framed mutation
    // has exactly one byte-preserving serialization. Framing grants no validity.
    for index in 0..raw.len() {
        let mut changed = raw.clone();
        changed[index] ^= 128;
        if let Ok(decoded) = wire::decode(&changed, &limits, &V6Verifier) {
            assert_eq!(
                wire::encode(&decoded, &limits, &V6Verifier).unwrap(),
                changed
            );
        }
    }
}

#[test]
fn address_receivers_interoperate_with_p2sh_and_ironwood_backends() {
    use monario_address::{Address, Network, Receiver, TransparentReceiver};
    // Public HASH160(OP_TRUE), independently calculated with Python hashlib.
    let hash = [
        0xda, 0x17, 0x45, 0xe9, 0xb5, 0x49, 0xbd, 0x0b, 0xfa, 0x1a, 0x56, 0x99, 0x71, 0xc7, 0x7e,
        0xba, 0x30, 0xcd, 0x5a, 0x4b,
    ];
    let encoded = Address::new(
        Network::Main,
        Receiver::Transparent(TransparentReceiver::ScriptHash(hash)),
    )
    .encode();
    let decoded = Address::decode(&encoded, Network::Main).unwrap();
    let mut state = State::default();
    state.coin.script = decoded.script_pubkey().unwrap();
    let raw = fixture(false, 0, 0, vec![1, 0x51]);
    assert!(verify(&raw, &state).is_ok());
    state.coin.script[2] ^= 1;
    assert!(verify(&raw, &state).is_err());
    // Published raw receiver, no key derivation or random material.
    let vector = include_str!("../../address/tests/vectors.txt")
        .lines()
        .find(|line| line.starts_with("main 2 "))
        .unwrap();
    let encoded = vector.split_whitespace().nth(3).unwrap();
    let decoded = Address::decode(encoded, Network::Main).unwrap();
    assert!(decoded.script_pubkey().is_none());
    let Receiver::Private(receiver) = decoded.receiver() else {
        panic!("private receiver required");
    };
    let version = orchard::bundle::BundleVersion::ironwood_v3();
    let mut builder = orchard::builder::Builder::new(
        orchard::builder::BundleType::Transactional {
            bundle_required: true,
            pad_to_minimum: Some(1),
        },
        version,
        version.default_flags(),
        orchard::Anchor::empty_tree(),
    )
    .unwrap();
    builder
        .add_output(
            None,
            receiver.to_upstream(),
            orchard::value::NoteValue::from_raw(90),
            [0; 512],
        )
        .unwrap();
}

#[test]
fn missing_input_is_a_deferred_failure_never_a_verification_receipt() {
    let raw = fixture(false, 0, 0, vec![]);
    let mut state = State {
        missing: true,
        ..State::default()
    };
    assert!(matches!(verify(&raw, &state), Err(Error::MissingInput)));
    let mut trailing = raw.clone();
    trailing.push(0);
    assert!(matches!(verify(&trailing, &state), Err(Error::Invalid)));
    assert!(matches!(
        verify(&fixture(false, 1, 0, vec![]), &state),
        Err(Error::MissingInput)
    ));
    assert!(matches!(
        V6Verifier.verify(
            &fixture(false, 1, 0, vec![]),
            TransactionContext {
                height: 2,
                median_time_past: 1000,
                state: &state,
            }
        ),
        Err(Error::Invalid)
    ));
    state.missing = false;
    state.coin.script = vec![0xac];
    assert!(matches!(verify(&raw, &state), Err(Error::Invalid)));
}

#[test]
fn canonical_references_are_not_an_authorization_receipt() {
    let raw = fixture(false, 0, 0, vec![]);
    let (id, refs) = transaction_references(&raw).unwrap();
    assert_eq!(
        refs,
        vec![OutPoint {
            transaction: [7; 32],
            index: 0
        }]
    );
    assert_eq!(id, verify(&raw, &State::default()).unwrap().id);
    let mut state = State::default();
    state.coin.script = vec![0xac];
    assert!(verify(&raw, &state).is_err());
    assert!(transaction_references(&raw).is_ok());
    let mut trailing = raw.clone();
    trailing.push(0);
    assert!(transaction_references(&trailing).is_err());
    let mut foreign = raw;
    foreign[8..12].copy_from_slice(&0x37a5165b_u32.to_le_bytes());
    assert!(transaction_references(&foreign).is_err());
    assert!(transaction_references(&fixture(true, 1, 0, vec![0x51, 0])).is_err());
}

#[test]
fn transaction_value_bounds_match_consensus_and_fail_closed() {
    use monario_monetary::MAX_TRANSACTION_VALUE_ATOMS as limit;
    use zcash_protocol::value::{MAX_BALANCE, MAX_MONEY, ZatBalance};

    assert_eq!(MAX_MONEY, limit);
    assert_eq!(MAX_BALANCE, limit as i64);
    assert!(Zatoshis::from_u64(limit).is_ok());
    assert!(Zatoshis::from_u64(limit + 1).is_err());
    assert!(ZatBalance::from_i64(limit as i64).is_ok());
    assert!(ZatBalance::from_i64(-(limit as i64)).is_ok());
    assert!(ZatBalance::from_i64(limit as i64 + 1).is_err());
    assert!(ZatBalance::from_i64(-(limit as i64) - 1).is_err());

    let raw = fixture(true, 1, 0, vec![0x51, 0]);
    let matches: Vec<_> = raw
        .windows(8)
        .enumerate()
        .filter_map(|(i, b)| (b == 90_u64.to_le_bytes()).then_some(i))
        .collect();
    assert_eq!(matches.len(), 1);
    let mut value_at_limit = raw.clone();
    value_at_limit[matches[0]..matches[0] + 8].copy_from_slice(&limit.to_le_bytes());
    assert_eq!(
        verify(&value_at_limit, &State::default()).unwrap().outputs[0]
            .value
            .atoms(),
        limit
    );
    let mut above_limit = value_at_limit;
    above_limit[matches[0]..matches[0] + 8].copy_from_slice(&(limit + 1).to_le_bytes());
    assert!(verify(&above_limit, &State::default()).is_err());
}

#[test]
fn timestamp_locktime_unlocks_after_2106_without_truncation() {
    let raw = fixture(false, 0, u32::MAX, vec![]);
    let state = State::default();
    let verify_at = |median_time_past| {
        V6Verifier.verify(
            &raw,
            TransactionContext {
                height: 1,
                median_time_past,
                state: &state,
            },
        )
    };
    assert!(verify_at(u64::from(u32::MAX)).is_err());
    assert!(verify_at(u64::from(u32::MAX) + 1).is_ok());
}

#[test]
fn transaction_height_boundary_enforces_wide_expiry() {
    let state = State::default();
    let finite = fixture(false, u32::MAX, 0, vec![]);
    let no_expiry = fixture(false, 0, 0, vec![]);
    let verify_at = |raw: &[u8], height| {
        V6Verifier.verify(
            raw,
            TransactionContext {
                height,
                median_time_past: 1000,
                state: &state,
            },
        )
    };
    assert!(verify_at(&finite, u64::from(u32::MAX)).is_ok());
    assert!(verify_at(&finite, u64::from(u32::MAX) + 1).is_err());
    assert!(verify_at(&no_expiry, u64::from(u32::MAX)).is_ok());
    assert!(verify_at(&no_expiry, u64::from(u32::MAX) + 1).is_ok());
    let mut wide = no_expiry.clone();
    let expiry = u64::from(u32::MAX) + 50;
    wide[16..24].copy_from_slice(&expiry.to_le_bytes());
    assert_eq!(decode(&wide).unwrap().expiry_height(), expiry);
    assert!(verify_at(&wide, expiry).is_ok());
    assert!(verify_at(&wide, expiry + 1).is_err());
}

#[test]
fn wide_expiry_header_digest_matches_independent_vector() {
    use zcash_primitives::transaction::txid::TxIdDigester;
    let mut raw = include_bytes!("../tests/fixtures/signed-v6.bin").to_vec();
    raw[16..24].copy_from_slice(&4_294_967_395_u64.to_le_bytes());
    let digest = decode(&raw).unwrap().into_data().digest(TxIdDigester);
    let actual: String = digest
        .header_digest()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        actual,
        "aaba74429b5852096eab338650a86d2657dbade11667d343e2a294445e57272a"
    );
}
