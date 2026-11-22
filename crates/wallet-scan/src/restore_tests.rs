//! Public synthetic restore-cost fixture, not a consensus/UTXO throughput benchmark.
use super::*;
use monario_wallet::storage::{Password, WalletDirectory, WalletStore};

fn large_cache() -> (
    tempfile::TempDir,
    DurableChain<V6Verifier>,
    WalletStore,
    Scanner,
) {
    let dir = tempfile::tempdir().unwrap();
    let mut source = DurableChain::open(
        &dir.path().join("chain.sqlite"),
        config(),
        root(),
        V6Verifier,
        2000,
    )
    .unwrap();
    let store = WalletStore::create(
        &WalletDirectory::open(dir.path()).unwrap(),
        "restore",
        Seed::from_bytes(&[7; 32]).unwrap(),
        Network::Main,
        &Password::from_bytes(b"public restore test password").unwrap(),
    )
    .unwrap();
    let mut capacity = limits();
    capacity.unspent_coins = 100_000;
    let mut s = Scanner::new(&source, Network::Main, vec![watch(7)], capacity).unwrap();
    let script = Seed::from_bytes(&[7; 32])
        .unwrap()
        .transparent_key(Network::Main, 0, Scope::External, 0)
        .unwrap()
        .address()
        .script_pubkey()
        .unwrap();
    let mut state = State::empty(root().id);
    for i in 0..40_000 {
        state.coins.insert(
            OutPoint {
                transaction: [1; 32],
                index: i,
            },
            (
                0,
                Coin {
                    value: Amount::ZERO,
                    script: script.clone(),
                    created_height: 0,
                    coinbase: false,
                },
            ),
        );
    }
    let mut model = Model::new();
    let mut history = VecDeque::new();
    for height in 1..=16 {
        let before = s.capture_rollback(&state).unwrap();
        model.accept(&mut source, height, &[]);
        state.tip = model.parent;
        state.height = height.into();
        s.remember_prepared(&mut history, before, &state).unwrap();
    }
    s.state = state;
    s.history = history;
    s.save_cache(&store, &source, [0; 32]).unwrap();
    (dir, source, store, s)
}

#[test]
fn large_wallet_restore_cost_and_exact_validated_history() {
    let (_dir, source, store, mut s) = large_cache();
    let mut reference = Scanner::new(&source, Network::Main, vec![watch(7)], s.limits).unwrap();
    crate::restore_metrics::COUNTERS.with(|c| *c.borrow_mut() = Default::default());
    let start = std::time::Instant::now();
    assert!(
        reference
            .restore_cache_reference(&store, &source, [0; 32])
            .unwrap()
    );
    let reference_elapsed = start.elapsed();
    let baseline = crate::restore_metrics::COUNTERS.with(|c| *c.borrow());
    let mut restored = Scanner::new(&source, Network::Main, vec![watch(7)], s.limits).unwrap();
    crate::restore_metrics::COUNTERS.with(|c| *c.borrow_mut() = Default::default());
    let start = std::time::Instant::now();
    assert!(restored.restore_cache(&store, &source, [0; 32]).unwrap());
    let elapsed = start.elapsed();
    let optimized = crate::restore_metrics::COUNTERS.with(|c| *c.borrow());
    assert_eq!(baseline.states, 17);
    assert_eq!(optimized.states, baseline.states);
    assert_eq!(optimized.witnesses, baseline.witnesses);
    assert_eq!(baseline.encodes, 66);
    assert_eq!(optimized.encodes, 19);
    assert_eq!(baseline.hashes, 64);
    assert_eq!(optimized.hashes, 17);
    assert_eq!(restored.encode_cache().unwrap(), s.encode_cache().unwrap());
    assert_eq!(restored.history.len(), 16);
    assert_eq!(
        restored.encode_cache().unwrap(),
        reference.encode_cache().unwrap()
    );
    eprintln!(
        "synthetic_restore outputs=40000 history=16 reference_ms={} optimized_ms={} encodes={}->{} hashes={}->{} validated_states={}",
        reference_elapsed.as_millis(),
        elapsed.as_millis(),
        baseline.encodes,
        optimized.encodes,
        baseline.hashes,
        optimized.hashes,
        optimized.states
    );
    s.history.clear();
    s.save_cache(&store, &source, [0; 32]).unwrap();
    let mut no_history = Scanner::new(&source, Network::Main, vec![watch(7)], s.limits).unwrap();
    crate::restore_metrics::COUNTERS.with(|c| *c.borrow_mut() = Default::default());
    assert!(no_history.restore_cache(&store, &source, [0; 32]).unwrap());
    let counts = crate::restore_metrics::COUNTERS.with(|c| *c.borrow());
    assert_eq!(counts.states, 1);
    assert_eq!(counts.encodes, 2);
    assert_eq!(counts.hashes, 0);
    assert_eq!(
        no_history.encode_cache().unwrap(),
        s.encode_cache().unwrap()
    );
}

fn compare_restore(store: &WalletStore, source: &DurableChain<V6Verifier>, valid: bool) {
    let mut reference = scanner(source, 7);
    let mut fast = scanner(source, 7);
    let original = fast.encode_cache().unwrap();
    crate::restore_metrics::COUNTERS.with(|c| *c.borrow_mut() = Default::default());
    let reference_result = reference.restore_cache_reference(store, source, [0; 32]);
    let baseline = crate::restore_metrics::COUNTERS.with(|c| *c.borrow());
    crate::restore_metrics::COUNTERS.with(|c| *c.borrow_mut() = Default::default());
    let fast_result = fast.restore_cache(store, source, [0; 32]);
    let optimized = crate::restore_metrics::COUNTERS.with(|c| *c.borrow());
    if valid {
        assert!(matches!(reference_result, Ok(true)));
        assert!(matches!(fast_result, Ok(true)));
        assert!(optimized.witnesses > 0);
        assert_eq!(
            fast.encode_cache().unwrap(),
            reference.encode_cache().unwrap()
        );
    } else {
        assert!(reference_result.is_err());
        assert!(fast_result.is_err());
        assert_eq!(fast.encode_cache().unwrap(), original);
        assert_eq!(reference.encode_cache().unwrap(), original);
    }
    assert_eq!(optimized.states, baseline.states);
    assert_eq!(optimized.witnesses, baseline.witnesses);
}

#[test]
fn optimized_restore_preserves_private_validation_and_rejects_authenticated_bad_parents() {
    let dir = tempfile::tempdir().unwrap();
    let mut source = DurableChain::open(
        &dir.path().join("chain.sqlite"),
        config(),
        root(),
        V6Verifier,
        2000,
    )
    .unwrap();
    let store = WalletStore::create(
        &WalletDirectory::open(dir.path()).unwrap(),
        "private",
        Seed::from_bytes(&[7; 32]).unwrap(),
        Network::Main,
        &Password::from_bytes(b"public restore test password").unwrap(),
    )
    .unwrap();
    let mut model = Model::new();
    model.accept(&mut source, 1, &[]);
    model.accept(&mut source, 2, &[]);
    model.accept(&mut source, 3, &[fixture("deposit")]);
    let mut s = scanner(&source, 7);
    s.sync(&source, 100).unwrap();
    s.save_cache(&store, &source, [0; 32]).unwrap();
    compare_restore(&store, &source, true);
    model.accept(&mut source, 4, &[fixture("transfer")]);
    s.sync(&source, 1).unwrap();
    s.save_cache(&store, &source, [0; 32]).unwrap();
    compare_restore(&store, &source, true);
    let parent = s
        .apply_delta(&source, &s.state, &s.history.back().unwrap().1)
        .unwrap();
    for variant in 0..7 {
        let mut bad = parent.clone();
        match variant {
            0 => bad.notes.values_mut().next().unwrap().account = 1,
            1 => bad.notes.values_mut().next().unwrap().index += 1,
            2 => {
                let raw = fixture("transfer");
                let tx = Transaction::read(raw.as_slice(), BranchId::Nu6_3).unwrap();
                bad.notes
                    .values_mut()
                    .next()
                    .unwrap()
                    .witness
                    .append(MerkleHashOrchard::from_cmx(
                        tx.ironwood_bundle().unwrap().actions()[0].cmx(),
                    ))
                    .unwrap();
            }
            3 => bad.coins.values_mut().next().unwrap().1.script = vec![0x6a],
            4 => bad.observed.get_mut(&0).unwrap().private_external = 1 << 89,
            5 => {
                let (_, note) = bad.notes.pop_first().unwrap();
                bad.notes.insert([99; 32], note);
            }
            _ => {
                let raw = fixture("transfer");
                let tx = Transaction::read(raw.as_slice(), BranchId::Nu6_3).unwrap();
                bad.tree
                    .append(MerkleHashOrchard::from_cmx(
                        tx.ironwood_bundle().unwrap().actions()[0].cmx(),
                    ))
                    .unwrap();
            }
        }
        // Hashes and AEAD are valid. Semantic checks must still reject the parent.
        let delta = s.encode_delta(&bad, &s.state).unwrap();
        let mut encoded = s.encode_state(&s.state).unwrap();
        encoded.extend(b"MONWUD02");
        encoded.extend(1u32.to_le_bytes());
        encoded.extend((delta.len() as u32).to_le_bytes());
        encoded.extend_from_slice(&delta);
        store.save_scan_cache([0; 32], &encoded).unwrap();
        compare_restore(&store, &source, false);
    }
    // Semantically valid reconstruction with an extra no-op edit is noncanonical.
    let delta = s.encode_delta(&parent, &s.state).unwrap();
    let count = u32::from_le_bytes(delta[136..140].try_into().unwrap());
    let mut bad = delta[..136].to_vec();
    bad.extend((count + 1).to_le_bytes());
    bad.extend([0; 12]);
    bad.extend_from_slice(&delta[140..]);
    let mut encoded = s.encode_state(&s.state).unwrap();
    encoded.extend(b"MONWUD02");
    encoded.extend(1u32.to_le_bytes());
    encoded.extend((bad.len() as u32).to_le_bytes());
    encoded.extend(bad);
    store.save_scan_cache([0; 32], &encoded).unwrap();
    compare_restore(&store, &source, false);
}
