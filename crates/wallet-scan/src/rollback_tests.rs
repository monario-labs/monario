//! Public fixtures. Synthetic codec/retention cases never become imported wallet state.
use super::*;
use rand::{RngExt, SeedableRng, rngs::StdRng};
fn open(dir: &std::path::Path) -> DurableChain<V6Verifier> {
    DurableChain::open(
        &dir.join("chain.sqlite"),
        config(),
        root(),
        V6Verifier,
        2000,
    )
    .unwrap()
}
fn script() -> Vec<u8> {
    Seed::from_bytes(&[7; 32])
        .unwrap()
        .transparent_key(Network::Main, 0, Scope::External, 0)
        .unwrap()
        .address()
        .script_pubkey()
        .unwrap()
}

#[test]
fn compact_delta_roundtrips_record_insert_delete_edit_and_descriptor_binding() {
    let dir = tempfile::tempdir().unwrap();
    let mut source = open(dir.path());
    let mut model = Model::new();
    model.accept(&mut source, 1, &[]);
    let s = scanner(&source, 7);
    let script = script();
    let mut rng = StdRng::from_seed([18; 32]);
    // Exercise the canonical byte codec, not consensus acceptance of synthetic coins.
    for _ in 0..300 {
        let mut before = State::empty(root().id);
        let mut after = State::empty(model.parent);
        after.height = 1;
        for i in 0..16 {
            let key = OutPoint {
                transaction: [i; 32],
                index: u32::from(i),
            };
            for state in [&mut before, &mut after] {
                if rng.random::<bool>() {
                    state.coins.insert(
                        key,
                        (
                            0,
                            Coin {
                                value: Amount::from_atoms(rng.random_range(0..100)).unwrap(),
                                script: script.clone(),
                                created_height: 0,
                                coinbase: rng.random(),
                            },
                        ),
                    );
                }
            }
        }
        for state in [&mut before, &mut after] {
            if rng.random::<bool>() {
                state.observed.insert(
                    0,
                    AccountProgress {
                        transparent_external: rng.random_range(0..4),
                        ..AccountProgress::default()
                    },
                );
            }
        }
        let delta = s.encode_delta(&before, &after).unwrap();
        let old = s.apply_delta(&source, &after, &delta).unwrap();
        assert_eq!(
            s.encode_state(&old).unwrap(),
            s.encode_state(&before).unwrap()
        );
        assert_eq!(s.encode_delta(&old, &after).unwrap(), delta);
    }
    let before = State::empty(root().id);
    let mut after = before.clone();
    after.tip = model.parent;
    after.height = 1;
    let delta = s.encode_delta(&before, &after).unwrap();
    let other = Scanner::new(
        &source,
        Network::Main,
        vec![
            WatchAccount::from_seed(&Seed::from_bytes(&[7; 32]).unwrap(), Network::Main, 0, 3, 2)
                .unwrap(),
        ],
        limits(),
    )
    .unwrap();
    assert!(other.apply_delta(&source, &after, &delta).is_err());
}

#[test]
fn delta_rejects_wrong_child_hash_parent_offsets_lengths_counts_and_trailing_data() {
    let dir = tempfile::tempdir().unwrap();
    let mut source = open(dir.path());
    let mut model = Model::new();
    model.accept(&mut source, 1, &[]);
    let mut s = scanner(&source, 7);
    let before = s.state.clone();
    s.sync(&source, 1).unwrap();
    let after = s.state.clone();
    let delta = s.encode_delta(&before, &after).unwrap();
    // A no-op edit preserves both projection hashes, but is not canonical.
    let edits = u32::from_le_bytes(delta[136..140].try_into().unwrap());
    let mut noncanonical = delta[..136].to_vec();
    noncanonical.extend((edits + 1).to_le_bytes());
    noncanonical.extend([0; 12]);
    noncanonical.extend_from_slice(&delta[140..]);
    assert!(s.apply_delta(&source, &after, &noncanonical).is_err());
    for length in [0, 31, 64, 128, 139, delta.len() - 1] {
        assert!(s.apply_delta(&source, &after, &delta[..length]).is_err());
    }
    for offset in [0, 32, 64, 96, 128, 132, 136, 140, 144, 148, delta.len() - 1] {
        let mut bad = delta.to_vec();
        bad[offset] ^= 0xff;
        assert!(
            s.apply_delta(&source, &after, &bad).is_err(),
            "offset {offset}"
        );
    }
    let mut bad = delta.to_vec();
    bad.extend([0]);
    assert!(s.apply_delta(&source, &after, &bad).is_err());
    for offset in [128, 132, 136, 140, 144, 148] {
        let mut bad = delta.to_vec();
        bad[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(s.apply_delta(&source, &after, &bad).is_err());
    }
    let mut changed = after.clone();
    changed.coins.values_mut().next().unwrap().1.value = Amount::ZERO;
    assert!(s.apply_delta(&source, &changed, &delta).is_err());
    model.accept(&mut source, 2, &[]);
    s.sync(&source, 1).unwrap();
    assert!(s.apply_delta(&source, &s.state, &delta).is_err());
}

#[test]
fn witness_only_delta_reuses_note_plaintext_memo_and_unchanged_coins() {
    let dir = tempfile::tempdir().unwrap();
    let mut source = open(dir.path());
    let mut model = Model::new();
    model.accept(&mut source, 1, &[]);
    model.accept(&mut source, 2, &[]);
    model.accept(&mut source, 3, &[fixture("deposit")]);
    let mut s = scanner(&source, 7);
    s.sync(&source, 100).unwrap();
    let mut before = s.state.clone();
    let nf = *before.notes.keys().next().unwrap();
    before.notes.get_mut(&nf).unwrap().memo.fill(0x5a);
    let mut after = before.clone();
    // Projection-kernel witness mutation; the real spend/reorg tests exercise admission.
    let raw = fixture("transfer");
    let tx = Transaction::read(raw.as_slice(), BranchId::Nu6_3).unwrap();
    for a in tx.ironwood_bundle().unwrap().actions() {
        let leaf = MerkleHashOrchard::from_cmx(a.cmx());
        after.tree.append(leaf).unwrap();
        after
            .notes
            .get_mut(&nf)
            .unwrap()
            .witness
            .append(leaf)
            .unwrap();
    }
    model.accept(&mut source, 4, &[raw]);
    after.tip = model.parent;
    after.height = 4;
    let delta = s.encode_delta(&before, &after).unwrap();
    assert!(delta.len() < s.encode_state(&before).unwrap().len());
    assert!(!delta.windows(512).any(|v| v == [0x5a; 512]));
    assert!(
        !delta
            .windows(32)
            .any(|v| v == before.notes[&nf].note.rseed().as_bytes())
    );
    let old = s.apply_delta(&source, &after, &delta).unwrap();
    assert_eq!(
        s.encode_state(&old).unwrap(),
        s.encode_state(&before).unwrap()
    );
}

#[test]
fn large_projection_retains_128_compact_deltas_with_existing_byte_limits() {
    let dir = tempfile::tempdir().unwrap();
    let source = open(dir.path());
    let mut capacity = limits();
    capacity.unspent_coins = 100_000;
    let mut s = Scanner::new(&source, Network::Main, vec![watch(7)], capacity).unwrap();
    let script = script();
    // Retention-only synthetic map. No cache import, block or balance claim is made.
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
    assert!(s.encode_state(&state).unwrap().len() > 2 * 1024 * 1024);
    let mut history = VecDeque::new();
    for i in 1..=128 {
        let old = s.capture_rollback(&state).unwrap();
        state.height = i;
        state.tip = [i as u8; 32];
        s.remember_prepared(&mut history, old, &state).unwrap();
    }
    s.trim_history(&mut history, &state).unwrap();
    assert_eq!(history.len(), 128);
    assert!(history.iter().map(|(_, b)| b.len() + 4).sum::<usize>() < 128 * 512);
    s.state = state;
    s.history = history;
    assert!(s.encode_cache().unwrap().len() <= 4 * 1024 * 1024);
}

#[test]
fn legacy_snapshot_history_migrates_to_deltas_without_losing_reorg_coverage() {
    let dir = tempfile::tempdir().unwrap();
    let mut source = open(dir.path());
    let mut model = Model::new();
    model.accept(&mut source, 1, &[]);
    model.accept(&mut source, 2, &[]);
    model.accept(&mut source, 3, &[fixture("deposit")]);
    let funding = model.clone();
    model.accept(&mut source, 4, &[fixture("transfer")]);
    model.accept(&mut source, 5, &[fixture("withdrawal")]);
    let mut s = scanner(&source, 7);
    s.sync(&source, 100).unwrap();
    let mut child = s.state.clone();
    let mut snapshots = VecDeque::new();
    for (_, delta) in s.history.iter().rev() {
        child = s.apply_delta(&source, &child, delta).unwrap();
        snapshots.push_front(s.encode_state(&child).unwrap());
    }
    let mut old = s.encode_state(&s.state).unwrap();
    old.extend(b"MONWUD01");
    old.extend((snapshots.len() as u32).to_le_bytes());
    for b in snapshots {
        old.extend((b.len() as u32).to_le_bytes());
        old.extend_from_slice(&b);
    }
    let store = monario_wallet::storage::WalletStore::create(
        &monario_wallet::storage::WalletDirectory::open(dir.path()).unwrap(),
        "legacy",
        Seed::from_bytes(&[7; 32]).unwrap(),
        Network::Main,
        &monario_wallet::storage::Password::from_bytes(b"public delta test password").unwrap(),
    )
    .unwrap();
    let cp = store.checkpoint().unwrap();
    store.save_scan_cache([0; 32], &old).unwrap();
    let mut restored = scanner(&source, 7);
    assert!(restored.restore_cache(&store, &source, [0; 32]).unwrap());
    assert!(restored.cache_was_migrated());
    assert_eq!(restored.encode_cache().unwrap(), s.encode_cache().unwrap());
    restored.save_cache(&store, &source, [0; 32]).unwrap();
    let mut reload = scanner(&source, 7);
    assert!(reload.restore_cache(&store, &source, [0; 32]).unwrap());
    assert!(!reload.cache_was_migrated());
    let mut side = funding;
    side.accept(&mut source, 4, &[]);
    side.accept(&mut source, 5, &[]);
    side.accept(&mut source, 6, &[]);
    let p = reload.sync(&source, 3).unwrap();
    assert!(p.complete);
    assert_eq!(p.rolled_back, 2);
    assert!(!p.restarted);
    assert_balance(&reload, &source, 0, 0, 90);
    assert_eq!(store.checkpoint().unwrap(), cp);
    assert!(store.reservations().unwrap().is_empty());
}
