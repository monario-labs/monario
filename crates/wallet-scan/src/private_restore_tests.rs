//! Public cryptographic microbenchmarks plus real-v6 restore integration.
use super::*;
use crate::private_cache::PrivateChecks;
use std::io::Cursor;

fn records(s: &Scanner, state: &State) -> Vec<Zeroizing<Vec<u8>>> {
    let encoded = s.encode_state(state).unwrap();
    let mut r = Cursor::new(encoded.as_slice());
    crate::cache::blob(&mut r, crate::cache::MAX).unwrap();
    crate::cache::bytes::<32>(&mut r).unwrap();
    crate::cache::bytes::<8>(&mut r).unwrap();
    crate::cache::blob(&mut r, 4096).unwrap();
    assert_eq!(crate::cache::count(&mut r, 100_000).unwrap(), 0);
    let n = crate::cache::count(&mut r, 100_000).unwrap();
    let mut out = Vec::new();
    for _ in 0..n {
        let start = r.position() as usize;
        r.set_position(r.position() + 681);
        crate::cache::blob(&mut r, 8192).unwrap();
        out.push(Zeroizing::new(
            encoded[start..r.position() as usize].to_vec(),
        ));
    }
    out
}
fn fixture_notes(n: u32) -> (tempfile::TempDir, Scanner, State) {
    let dir = tempfile::tempdir().unwrap();
    let source = DurableChain::open(
        &dir.path().join("chain.sqlite"),
        config(),
        root(),
        V6Verifier,
        2000,
    )
    .unwrap();
    let mut capacity = limits();
    capacity.unspent_notes = 1000;
    let s = Scanner::new(&source, Network::Main, vec![watch(7)], capacity).unwrap();
    let mut state = State::empty(root().id);
    let a = &s.accounts[0];
    for i in 0..n {
        let mut rho = [0; 32];
        rho[..4].copy_from_slice(&(i + 1).to_le_bytes());
        let rho = Option::from(orchard::note::Rho::from_bytes(&rho)).unwrap();
        let seed = Option::from(orchard::note::RandomSeed::from_bytes([42; 32], &rho)).unwrap();
        let note: orchard::Note = Option::from(orchard::Note::from_parts(
            a.viewing.address_at(i, orchard::keys::Scope::External),
            orchard::value::NoteValue::from_raw(1),
            rho,
            seed,
            orchard::note::NoteVersion::V3,
        ))
        .unwrap();
        let leaf = MerkleHashOrchard::from_cmx(&note.commitment().into());
        for old in state.notes.values_mut() {
            old.witness.append(leaf).unwrap();
        }
        state.tree.append(leaf).unwrap();
        state.notes.insert(
            note.nullifier(&a.viewing).to_bytes(),
            ReceivedNote {
                account: 0,
                scope: Scope::External,
                index: u128::from(i),
                note,
                memo: Zeroizing::new([i as u8; 512]),
                witness: IncrementalWitness::from_tree(state.tree.clone()).unwrap(),
            },
        );
    }
    (dir, s, state)
}
fn reset() {
    crate::restore_metrics::COUNTERS.with(|c| *c.borrow_mut() = Default::default());
}
fn counters() -> crate::restore_metrics::Counts {
    crate::restore_metrics::COUNTERS.with(|c| *c.borrow())
}

#[test]
fn private_predicates_reuse_exact_bytes_with_identical_results() {
    let (_dir, s, state) = fixture_notes(128);
    let raw = records(&s, &state);
    let root = state.tree.root().to_bytes();
    let mut reference = PrivateChecks::uncached();
    reset();
    let start = std::time::Instant::now();
    for _ in 0..16 {
        for r in &raw {
            let result = reference
                .read_note(&mut Cursor::new(r.as_slice()), s.profile, &s.accounts, root)
                .unwrap();
            std::hint::black_box(result);
        }
    }
    let reference_time = start.elapsed();
    let baseline = counters();
    let mut checks = PrivateChecks::default();
    reset();
    let start = std::time::Instant::now();
    for _ in 0..16 {
        for r in &raw {
            let result = checks
                .read_note(&mut Cursor::new(r.as_slice()), s.profile, &s.accounts, root)
                .unwrap();
            std::hint::black_box(result);
        }
    }
    let optimized_time = start.elapsed();
    let optimized = counters();
    assert_eq!(baseline.private_identities, 2048);
    assert_eq!(baseline.private_roots, 2048);
    assert_eq!(optimized.private_identities, 128);
    assert_eq!(optimized.private_roots, 128);
    assert_eq!(optimized.identity_reuses, 1920);
    assert_eq!(optimized.witness_reuses, 1920);
    for r in &raw {
        let (nf, n) = checks
            .read_note(&mut Cursor::new(r.as_slice()), s.profile, &s.accounts, root)
            .unwrap();
        assert_eq!(n.note.nullifier(&s.accounts[0].viewing).to_bytes(), nf);
        assert_eq!(n.witness.root().to_bytes(), root);
        assert_eq!(n.memo.as_slice(), state.notes[&nf].memo.as_slice());
    }
    eprintln!(
        "private_predicates notes=128 passes=16 reference_ms={} optimized_ms={} identities={}->{} witness_roots={}->{}",
        reference_time.as_millis(),
        optimized_time.as_millis(),
        baseline.private_identities,
        optimized.private_identities,
        baseline.private_roots,
        optimized.private_roots
    );
}

#[test]
fn warm_private_checks_reject_changed_context_identity_or_witness_and_preserve_memos() {
    let (_dir, s, state) = fixture_notes(2);
    let raw = records(&s, &state);
    let original = &raw[0];
    let root = state.tree.root().to_bytes();
    let mut checks = PrivateChecks::default();
    checks
        .read_note(
            &mut Cursor::new(original.as_slice()),
            s.profile,
            &s.accounts,
            root,
        )
        .unwrap();
    for offset in [0, 32, 36, 37, 53, 96, 104, 136, 168] {
        let mut bad = original.to_vec();
        bad[offset] ^= 0xff;
        assert!(
            checks
                .read_note(
                    &mut Cursor::new(bad.as_slice()),
                    s.profile,
                    &s.accounts,
                    root
                )
                .is_err(),
            "identity offset {offset}"
        );
    }
    let mut bad_root = root;
    bad_root[0] ^= 1;
    assert!(
        checks
            .read_note(
                &mut Cursor::new(original.as_slice()),
                s.profile,
                &s.accounts,
                bad_root
            )
            .is_err()
    );
    let foreign = watch(8);
    assert!(
        checks
            .read_note(
                &mut Cursor::new(original.as_slice()),
                s.profile,
                &[foreign],
                root
            )
            .is_err()
    );
    let mut changed_memo = original.to_vec();
    changed_memo[169] ^= 1;
    let (_, note) = checks
        .read_note(
            &mut Cursor::new(changed_memo.as_slice()),
            s.profile,
            &s.accounts,
            root,
        )
        .unwrap();
    assert_eq!(note.memo[0], changed_memo[169]);
    // A different profile must recompute both predicates, even with identical keys/bytes.
    reset();
    checks
        .read_note(
            &mut Cursor::new(original.as_slice()),
            [99; 32],
            &s.accounts,
            root,
        )
        .unwrap();
    assert_eq!(counters().private_identities, 1);
    assert_eq!(counters().private_roots, 1);
    for len in [0, 32, 168, 680, original.len() - 1] {
        assert!(
            checks
                .read_note(
                    &mut Cursor::new(&original[..len]),
                    s.profile,
                    &s.accounts,
                    root
                )
                .is_err()
        );
    }
    let other = &raw[1];
    let mut changed = original.to_vec();
    changed.truncate(681);
    changed.extend_from_slice(&other[681..]);
    assert!(
        checks
            .read_note(
                &mut Cursor::new(changed.as_slice()),
                s.profile,
                &s.accounts,
                root
            )
            .is_err()
    );
}

#[test]
fn private_check_capacity_falls_back_and_oversized_witness_vectors_are_errors() {
    let (_dir, s, state) = fixture_notes(2);
    let raw = records(&s, &state);
    let root = state.tree.root().to_bytes();
    let mut checks = PrivateChecks::at_capacity();
    reset();
    for _ in 0..2 {
        for r in &raw {
            checks
                .read_note(&mut Cursor::new(r.as_slice()), s.profile, &s.accounts, root)
                .unwrap();
        }
    }
    assert_eq!(counters().private_identities, 4);
    assert_eq!(counters().private_roots, 4);
    assert_eq!(counters().identity_reuses, 0);
    assert_eq!(counters().witness_reuses, 0);
    // A syntactically oversized filled vector used to reach the legacy constructor.
    let witness = &raw[0][685..];
    let mut r = Cursor::new(witness);
    zcash_primitives::merkle_tree::read_commitment_tree::<MerkleHashOrchard, _, 32>(&mut r)
        .unwrap();
    let filled = r.position() as usize;
    for bad_count in [33u8, 255] {
        let mut bad = raw[0][..681].to_vec();
        let mut malformed = witness.to_vec();
        malformed[filled] = bad_count;
        bad.extend((malformed.len() as u32).to_le_bytes());
        bad.extend(malformed);
        assert!(
            checks
                .read_note(
                    &mut Cursor::new(bad.as_slice()),
                    s.profile,
                    &s.accounts,
                    root
                )
                .is_err()
        );
    }
    let mut one = CommitmentTree::<MerkleHashOrchard, 32>::empty();
    one.append(MerkleHashOrchard::from_cmx(
        &state
            .notes
            .values()
            .next()
            .unwrap()
            .note
            .commitment()
            .into(),
    ))
    .unwrap();
    let mut encoded = Vec::new();
    zcash_primitives::merkle_tree::write_commitment_tree(&one, &mut encoded).unwrap();
    let mut zero_depth_cursor = encoded.clone();
    zero_depth_cursor.extend([0, 1]);
    zero_depth_cursor.extend(encoded);
    for malformed in [vec![0, 0, 0, 1, 0, 0, 0], zero_depth_cursor] {
        let mut bad = raw[0][..681].to_vec();
        bad.extend((malformed.len() as u32).to_le_bytes());
        bad.extend(malformed);
        assert!(
            checks
                .read_note(
                    &mut Cursor::new(bad.as_slice()),
                    s.profile,
                    &s.accounts,
                    root
                )
                .is_err()
        );
    }
}

#[test]
fn private_frontier_reuse_binds_exact_tree_profile_and_root_and_falls_back_at_capacity() {
    let (_dir, s, state) = fixture_notes(2);
    let mut raw = Vec::new();
    zcash_primitives::merkle_tree::write_commitment_tree(&state.tree, &mut raw).unwrap();
    let root = state.tree.root().to_bytes();
    let encoded = |raw: &[u8]| {
        let mut out = (raw.len() as u32).to_le_bytes().to_vec();
        out.extend_from_slice(raw);
        out
    };
    let data = encoded(&raw);
    let mut checks = PrivateChecks::default();
    reset();
    for _ in 0..2 {
        assert_eq!(
            checks
                .read_tree(&mut Cursor::new(data.as_slice()), s.profile, root)
                .unwrap(),
            state.tree
        );
    }
    assert_eq!(counters().private_frontiers, 1);
    assert_eq!(counters().frontier_reuses, 1);
    checks
        .read_tree(&mut Cursor::new(data.as_slice()), [99; 32], root)
        .unwrap();
    assert_eq!(counters().private_frontiers, 2);
    let mut wrong_root = root;
    wrong_root[0] ^= 1;
    assert!(
        checks
            .read_tree(&mut Cursor::new(data.as_slice()), s.profile, wrong_root)
            .is_err()
    );
    let mut changed = raw.clone();
    changed[1] ^= 1;
    let mut invalid_field = raw.clone();
    invalid_field[1..33].fill(255);
    for malformed in [
        vec![],
        vec![2, 0, 0],
        vec![0, 0, 32],
        vec![0, 0, 255],
        vec![0, 1],
        raw[..raw.len() - 1].to_vec(),
        [raw.as_slice(), &[0]].concat(),
        changed,
        invalid_field,
    ] {
        let bad = encoded(&malformed);
        assert!(
            checks
                .read_tree(&mut Cursor::new(bad.as_slice()), s.profile, root)
                .is_err()
        );
    }
    let mut full = PrivateChecks::at_capacity();
    reset();
    for _ in 0..2 {
        full.read_tree(&mut Cursor::new(data.as_slice()), s.profile, root)
            .unwrap();
    }
    assert_eq!(counters().private_frontiers, 2);
    assert_eq!(counters().frontier_reuses, 0);
}

#[test]
fn real_private_cache_restore_reuses_predicates_and_rechecks_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let mut source = DurableChain::open(
        &dir.path().join("chain.sqlite"),
        config(),
        root(),
        V6Verifier,
        2000,
    )
    .unwrap();
    let mut model = Model::new();
    for height in 1..=16 {
        let extra = if height == 3 {
            vec![fixture("deposit")]
        } else {
            vec![]
        };
        model.accept(&mut source, height, &extra);
    }
    let store = monario_wallet::storage::WalletStore::create(
        &monario_wallet::storage::WalletDirectory::open(dir.path()).unwrap(),
        "private",
        Seed::from_bytes(&[7; 32]).unwrap(),
        Network::Main,
        &monario_wallet::storage::Password::from_bytes(b"public private restore password").unwrap(),
    )
    .unwrap();
    let cp = store.checkpoint().unwrap();
    let mut s = scanner(&source, 7);
    s.sync(&source, 100).unwrap();
    s.save_cache(&store, &source, [0; 32]).unwrap();
    let mut reference = scanner(&source, 7);
    reset();
    let start = std::time::Instant::now();
    assert!(
        reference
            .restore_cache_reference(&store, &source, [0; 32])
            .unwrap()
    );
    let before = start.elapsed();
    let baseline = counters();
    let mut restored = scanner(&source, 7);
    reset();
    let start = std::time::Instant::now();
    assert!(restored.restore_cache(&store, &source, [0; 32]).unwrap());
    let after = start.elapsed();
    let optimized = counters();
    assert_eq!(baseline.states, 17);
    assert_eq!(optimized.states, 17);
    assert_eq!(baseline.witnesses, 14);
    assert_eq!(optimized.witnesses, 14);
    assert_eq!(baseline.private_identities, 14);
    assert_eq!(optimized.private_identities, 1);
    assert_eq!(baseline.private_roots, 14);
    assert_eq!(optimized.private_roots, 1);
    assert_eq!(baseline.private_frontiers, 17);
    assert_eq!(optimized.private_frontiers, 2);
    assert_eq!(
        reference.encode_cache().unwrap(),
        restored.encode_cache().unwrap()
    );
    assert_balance(&restored, &source, 0, 0, 90);
    let nf = *restored
        .unspent_notes(&source)
        .unwrap()
        .keys()
        .next()
        .unwrap();
    restored.witness(&source, nf).unwrap();
    let mut reopened = scanner(&source, 7);
    reset();
    assert!(reopened.restore_cache(&store, &source, [0; 32]).unwrap());
    assert_eq!(counters().private_identities, 1);
    assert_eq!(counters().private_roots, 1);
    assert_eq!(store.checkpoint().unwrap(), cp);
    assert!(store.reservations().unwrap().is_empty());
    eprintln!(
        "real_private_restore notes=1 history=16 reference_ms={} optimized_ms={} identities={}->{} witness_roots={}->{} frontiers={}->{}",
        before.as_millis(),
        after.as_millis(),
        baseline.private_identities,
        optimized.private_identities,
        baseline.private_roots,
        optimized.private_roots,
        baseline.private_frontiers,
        optimized.private_frontiers
    );
}
