//! Real signed/private fixture transactions and fixed-nonce headers only.
use super::*;
use monario_wallet::storage::{Password, WalletDirectory, WalletStore};
fn wallet(dir: &std::path::Path) -> WalletStore {
    WalletStore::create(
        &WalletDirectory::open(dir).unwrap(),
        "cache",
        Seed::from_bytes(&[7; 32]).unwrap(),
        Network::Main,
        &Password::from_bytes(b"public cache test password").unwrap(),
    )
    .unwrap()
}
pub(super) fn legacy_cache(s: &Scanner, source: &DurableChain<V6Verifier>) -> Zeroizing<Vec<u8>> {
    let mut child = s.state.clone();
    let mut snapshots = VecDeque::new();
    for (_, delta) in s.history.iter().rev() {
        child = s.apply_delta(source, &child, delta).unwrap();
        snapshots.push_front(s.encode_state(&child).unwrap());
    }
    let mut old = s.encode_state(&s.state).unwrap();
    old.extend(b"MONWUD01");
    old.extend((snapshots.len() as u32).to_le_bytes());
    for b in snapshots {
        old.extend((b.len() as u32).to_le_bytes());
        old.extend_from_slice(&b);
    }
    old
}
#[test]
fn incremental_cache_restores_private_witnesses_appends_and_replays_reorgs() {
    let dir = tempfile::tempdir().unwrap();
    let store = wallet(dir.path());
    let cp = store.checkpoint().unwrap();
    let mut source = DurableChain::open(
        &dir.path().join("chain.sqlite"),
        config(),
        root(),
        V6Verifier,
        2000,
    )
    .unwrap();
    let mut model = Model::new();
    model.accept(&mut source, 1, &[]);
    model.accept(&mut source, 2, &[]);
    model.accept(&mut source, 3, &[fixture("deposit")]);
    let funding = model.clone();
    let mut first = scanner(&source, 7);
    first.sync(&source, 100).unwrap();
    first.save_cache(&store, &source, [0; 32]).unwrap();
    let saved = store.load_scan_cache([0; 32]).unwrap().unwrap();
    let mut cached = scanner(&source, 7);
    assert!(cached.restore_cache(&store, &source, [0; 32]).unwrap());
    assert!(cached.sync(&source, 1).unwrap().complete);
    assert_balance(&cached, &source, 0, 0, 90);
    let nf = *cached
        .unspent_notes(&source)
        .unwrap()
        .keys()
        .next()
        .unwrap();
    cached.witness(&source, nf).unwrap();
    model.accept(&mut source, 4, &[fixture("transfer")]);
    assert!(cached.sync(&source, 1).unwrap().complete);
    cached.save_cache(&store, &source, [0; 32]).unwrap();
    model.accept(&mut source, 5, &[fixture("withdrawal")]);
    let mut reopened = scanner(&source, 7);
    assert!(reopened.restore_cache(&store, &source, [0; 32]).unwrap());
    assert!(reopened.sync(&source, 1).unwrap().complete);
    assert_balance(&reopened, &source, 70, 0, 0);
    // Rollback to an older authentic cache merely replays the missing tail.
    store.save_scan_cache([0; 32], &saved).unwrap();
    let mut rolled = scanner(&source, 7);
    assert!(rolled.restore_cache(&store, &source, [0; 32]).unwrap());
    assert!(!rolled.sync(&source, 1).unwrap().complete);
    assert!(rolled.save_cache(&store, &source, [0; 32]).is_err());
    rolled.sync(&source, 100).unwrap();
    assert_balance(&rolled, &source, 70, 0, 0);
    rolled.save_cache(&store, &source, [0; 32]).unwrap();
    let mut side = funding;
    side.accept(&mut source, 4, &[fixture("conflict")]);
    side.accept(&mut source, 5, &[]);
    side.accept(&mut source, 6, &[]);
    let mut orphan = scanner(&source, 7);
    assert!(orphan.restore_cache(&store, &source, [0; 32]).unwrap());
    let progress = orphan.sync(&source, 1).unwrap();
    assert!(!progress.restarted);
    assert_eq!(progress.rolled_back, 2);
    assert!(!progress.complete);
    orphan.sync(&source, 100).unwrap();
    assert_balance(&orphan, &source, 0, 0, 0);
    let mut full = scanner(&source, 7);
    full.sync(&source, 100).unwrap();
    assert_eq!(orphan.encode_cache().unwrap(), full.encode_cache().unwrap());
    assert_eq!(store.checkpoint().unwrap(), cp);
    assert!(store.reservations().unwrap().is_empty());
}
#[test]
fn cache_scope_limits_unknown_tips_and_malformed_state_fail_safely() {
    let dir = tempfile::tempdir().unwrap();
    let store = wallet(dir.path());
    let mut source = DurableChain::open(
        &dir.path().join("chain.sqlite"),
        config(),
        root(),
        V6Verifier,
        2000,
    )
    .unwrap();
    let mut model = Model::new();
    model.accept(&mut source, 1, &[]);
    let mut s = scanner(&source, 7);
    s.sync(&source, 10).unwrap();
    s.save_cache(&store, &source, [0; 32]).unwrap();
    assert!(
        !scanner(&source, 8)
            .restore_cache(&store, &source, [0; 32])
            .unwrap()
    );
    assert!(
        !scanner(&source, 7)
            .restore_cache(&store, &source, [1; 32])
            .unwrap()
    );
    let mut changed = Scanner::new(
        &source,
        Network::Main,
        vec![
            WatchAccount::from_seed(store.expose_seed().unwrap(), Network::Main, 0, 3, 2).unwrap(),
        ],
        limits(),
    )
    .unwrap();
    assert!(!changed.restore_cache(&store, &source, [0; 32]).unwrap());
    let original = s.encode_cache().unwrap();
    let binding_len = u32::from_le_bytes(original[..4].try_into().unwrap()) as usize;
    let mut unknown = original.to_vec();
    unknown[4 + binding_len..4 + binding_len + 32].fill(99);
    store.save_scan_cache([0; 32], &unknown).unwrap();
    assert!(
        !scanner(&source, 7)
            .restore_cache(&store, &source, [0; 32])
            .unwrap()
    );
    for n in [0, 1, 4, original.len() - 1] {
        store.save_scan_cache([0; 32], &original[..n]).unwrap();
        let mut fresh = scanner(&source, 7);
        assert!(fresh.restore_cache(&store, &source, [0; 32]).is_err());
        assert_eq!(fresh.scanned_tip(), root().id);
    }
    let mut trailing = original.to_vec();
    trailing.push(0);
    store.save_scan_cache([0; 32], &trailing).unwrap();
    assert!(
        scanner(&source, 7)
            .restore_cache(&store, &source, [0; 32])
            .is_err()
    );
    // Inconsistent height/root cannot be accepted even under a valid envelope.
    for offset in [4 + binding_len + 32, 4 + binding_len + 40] {
        let mut bad = original.to_vec();
        bad[offset] ^= 1;
        store.save_scan_cache([0; 32], &bad).unwrap();
        assert!(
            scanner(&source, 7)
                .restore_cache(&store, &source, [0; 32])
                .is_err()
        );
    }
}

#[test]
fn retained_reorg_restores_private_witness_and_scans_only_replacement_branch() {
    let dir = tempfile::tempdir().unwrap();
    let store = wallet(dir.path());
    let mut source = DurableChain::open(
        &dir.path().join("chain.sqlite"),
        config(),
        root(),
        V6Verifier,
        2000,
    )
    .unwrap();
    let mut model = Model::new();
    model.accept(&mut source, 1, &[]);
    model.accept(&mut source, 2, &[]);
    model.accept(&mut source, 3, &[fixture("deposit")]);
    let funding = model.clone();
    model.accept(&mut source, 4, &[fixture("transfer")]);
    model.accept(&mut source, 5, &[fixture("withdrawal")]);
    let mut s = scanner(&source, 7);
    s.sync(&source, 100).unwrap();
    s.save_cache(&store, &source, [0; 32]).unwrap();
    let mut side = funding;
    side.accept(&mut source, 4, &[]);
    side.accept(&mut source, 5, &[]);
    side.accept(&mut source, 6, &[]);
    let mut restored = scanner(&source, 7);
    assert!(restored.restore_cache(&store, &source, [0; 32]).unwrap());
    // Three replacement blocks, not six historical bodies.
    let progress = restored.sync(&source, 3).unwrap();
    assert!(progress.complete);
    assert!(!progress.restarted);
    assert_eq!(progress.rolled_back, 2);
    assert_balance(&restored, &source, 0, 0, 90);
    let nf = *restored
        .unspent_notes(&source)
        .unwrap()
        .keys()
        .next()
        .unwrap();
    restored.witness(&source, nf).unwrap();
    let mut full = scanner(&source, 7);
    full.sync(&source, 100).unwrap();
    assert_eq!(
        restored.encode_state(&restored.state).unwrap(),
        full.encode_state(&full.state).unwrap()
    );
    restored.save_cache(&store, &source, [0; 32]).unwrap();
    let mut again = scanner(&source, 7);
    assert!(again.restore_cache(&store, &source, [0; 32]).unwrap());
    assert!(again.sync(&source, 1).unwrap().complete);
    again.witness(&source, nf).unwrap();
    // A second reorg back to the original branch must not reuse orphaned states.
    model.accept(&mut source, 6, &[]);
    model.accept(&mut source, 7, &[]);
    let progress = again.sync(&source, 4).unwrap();
    assert!(progress.complete);
    assert!(!progress.restarted);
    assert_eq!(progress.rolled_back, 3);
    assert_balance(&again, &source, 70, 0, 0);
    assert!(matches!(
        again.witness(&source, nf),
        Err(Error::UnknownNote)
    ));
    let mut full = scanner(&source, 7);
    full.sync(&source, 100).unwrap();
    assert_eq!(
        again.encode_state(&again.state).unwrap(),
        full.encode_state(&full.state).unwrap()
    );
}

#[test]
fn history_authentication_contiguity_and_legacy_fallback_fail_safely() {
    let dir = tempfile::tempdir().unwrap();
    let store = wallet(dir.path());
    let mut source = DurableChain::open(
        &dir.path().join("chain.sqlite"),
        config(),
        root(),
        V6Verifier,
        2000,
    )
    .unwrap();
    let mut model = Model::new();
    model.accept(&mut source, 1, &[]);
    model.accept(&mut source, 2, &[]);
    model.accept(&mut source, 3, &[fixture("deposit")]);
    let funding = model.clone();
    model.accept(&mut source, 4, &[fixture("transfer")]);
    model.accept(&mut source, 5, &[fixture("withdrawal")]);
    let mut s = scanner(&source, 7);
    s.sync(&source, 100).unwrap();
    let history = s.history.clone();
    // Even a correctly encrypted cache must not accept reordered, duplicated,
    // missing, non-parent or semantically malformed rollback records.
    for kind in 0..6 {
        s.history = history.clone();
        match kind {
            0 => s.history.swap(0, 1),
            1 => {
                let entry = s.history.back().unwrap().clone();
                s.history.push_back(entry);
            }
            2 => {
                s.history.remove(1);
            }
            3 => {
                s.history.pop_back();
            }
            4 => {
                let b = &mut s.history[3].1;
                b[64] ^= 1;
            }
            _ => {
                let b = &mut s.history[3].1;
                b.push(0);
            }
        }
        store
            .save_scan_cache([0; 32], &s.encode_cache().unwrap())
            .unwrap();
        let mut fresh = scanner(&source, 7);
        let before = fresh.encode_cache().unwrap();
        assert!(fresh.restore_cache(&store, &source, [0; 32]).is_err());
        assert_eq!(fresh.encode_cache().unwrap(), before);
    }
    s.history = history;
    let core = s.encode_state(&s.state).unwrap();
    for count in [129u32, u32::MAX] {
        let mut bad = core.to_vec();
        bad.extend(b"MONWUD01");
        bad.extend(count.to_le_bytes());
        store.save_scan_cache([0; 32], &bad).unwrap();
        assert!(
            scanner(&source, 7)
                .restore_cache(&store, &source, [0; 32])
                .is_err()
        );
    }
    // An actual legacy cache has no history trailer; it remains readable and
    // safely falls back to a full scan when the ancestor was not retained.
    store.save_scan_cache([0; 32], &core).unwrap();
    let mut legacy = scanner(&source, 7);
    assert!(legacy.restore_cache(&store, &source, [0; 32]).unwrap());
    assert!(legacy.history.is_empty());
    let mut side = funding;
    side.accept(&mut source, 4, &[]);
    side.accept(&mut source, 5, &[]);
    side.accept(&mut source, 6, &[]);
    let progress = legacy.sync(&source, 3).unwrap();
    assert!(progress.restarted);
    assert_eq!(progress.rolled_back, 0);
    assert!(!progress.complete);
    assert_eq!(progress.height, 3);
    legacy.sync(&source, 100).unwrap();
    assert_balance(&legacy, &source, 0, 0, 90);
    legacy.save_cache(&store, &source, [0; 32]).unwrap();
    assert!(!legacy.history.is_empty());
}

#[test]
fn replacement_body_failure_preserves_orphan_projection_and_rollback_history() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("chain.sqlite");
    let mut source = DurableChain::open(&path, config(), root(), V6Verifier, u64::MAX / 2).unwrap();
    let mut model = Model::new();
    model.accept(&mut source, 1, &[]);
    model.accept(&mut source, 2, &[]);
    model.accept(&mut source, 3, &[fixture("deposit")]);
    let funding = model.clone();
    model.accept(&mut source, 4, &[fixture("transfer")]);
    model.accept(&mut source, 5, &[fixture("withdrawal")]);
    let mut s = scanner(&source, 7);
    s.sync(&source, 100).unwrap();
    let before = s.encode_cache().unwrap();
    let mut side = funding;
    side.accept(&mut source, 4, &[]);
    side.accept(&mut source, 5, &[]);
    side.accept(&mut source, 6, &[]);
    let limits = SnapshotLimits {
        max_entries: 10000,
        max_row_bytes: 1 << 20,
        max_bytes: 16 << 20,
    };
    let trusted = source.create_state_checkpoint(limits).unwrap();
    drop(source);
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute(
        "UPDATE blocks SET data=zeroblob(length(data)) WHERE seq=7",
        [],
    )
    .unwrap();
    drop(db);
    let source = DurableChain::open_with_checkpoint(
        &path,
        config(),
        root(),
        V6Verifier,
        2000,
        trusted,
        limits,
    )
    .unwrap();
    // First replacement body succeeds; the second fails after rollback staging.
    assert!(s.sync(&source, 3).is_err());
    assert_eq!(s.encode_cache().unwrap(), before);
    assert!(matches!(s.balance(&source, 0), Err(Error::NotSynced)));
}

#[test]
fn rollback_retention_kernel_bounds_count_bytes_and_total_cache_size() {
    let dir = tempfile::tempdir().unwrap();
    let source = DurableChain::open(
        &dir.path().join("chain.sqlite"),
        config(),
        root(),
        V6Verifier,
        2000,
    )
    .unwrap();
    let s = scanner(&source, 7);
    let mut after = s.state.clone();
    after.height = 1;
    after.tip = [7; 32];
    // Synthetic retention-only buffers do not enter restore or consensus.
    let mut history: VecDeque<_> = (0..128)
        .map(|i| ([i; 32], Zeroizing::new(vec![0; 16])))
        .collect();
    s.remember(&mut history, &s.state, &after).unwrap();
    assert_eq!(history.len(), 128);
    assert_eq!(history.front().unwrap().0, [1; 32]);
    history = (0..4)
        .map(|i| ([i; 32], Zeroizing::new(vec![0; 600_000])))
        .collect();
    s.remember(&mut history, &s.state, &after).unwrap();
    assert!(history.iter().map(|(_, b)| b.len() + 4).sum::<usize>() <= 2 * 1024 * 1024);
    let mut large = State::empty(root().id);
    for i in 0..40_000 {
        large.coins.insert(
            OutPoint {
                transaction: [1; 32],
                index: i,
            },
            (
                0,
                Coin {
                    value: Amount::ZERO,
                    script: vec![0; 25],
                    created_height: 0,
                    coinbase: false,
                },
            ),
        );
    }
    s.trim_history(&mut history, &large).unwrap();
    assert!(
        s.encode_state(&large).unwrap().len()
            + 12
            + history.iter().map(|(_, b)| b.len() + 4).sum::<usize>()
            <= 4 * 1024 * 1024
    );
    assert!(history.len() < 4);
}

fn cache_password() -> Password {
    Password::from_bytes(b"public cache test password").unwrap()
}
fn reopen(dir: &std::path::Path, id: [u8; 16]) -> WalletStore {
    WalletStore::open(
        &WalletDirectory::open(dir).unwrap(),
        "cache",
        &cache_password(),
        monario_wallet::storage::WalletCheckpoint {
            wallet_id: id,
            network: Network::Main,
            revision: 0,
        },
    )
    .unwrap()
}
#[test]
fn reorg_crash_worker() {
    let Some(dir) = std::env::var_os("MONAR_REORG_CACHE_TEST_DIR") else {
        return;
    };
    let dir = std::path::Path::new(&dir);
    let id = std::env::var("MONAR_REORG_CACHE_TEST_ID").unwrap();
    assert_eq!(id.len(), 32);
    let mut wallet_id = [0; 16];
    for (i, b) in wallet_id.iter_mut().enumerate() {
        *b = u8::from_str_radix(&id[i * 2..i * 2 + 2], 16).unwrap();
    }
    let source = DurableChain::open(
        &dir.join("chain.sqlite"),
        config(),
        root(),
        V6Verifier,
        2000,
    )
    .unwrap();
    let store = reopen(dir, wallet_id);
    let mut s = scanner(&source, 7);
    let phase = std::env::var("MONAR_REORG_CACHE_TEST_PHASE").unwrap();
    if phase == "restoring" {
        crate::restore_metrics::COUNTERS.with(|c| {
            *c.borrow_mut() = crate::restore_metrics::Counts {
                stop_after_state: Some(2),
                ..Default::default()
            };
        });
    }
    if phase == "private-restoring" {
        crate::restore_metrics::COUNTERS.with(|c| {
            *c.borrow_mut() = crate::restore_metrics::Counts {
                stop_after_private_reuse: true,
                ..Default::default()
            };
        });
    }
    assert!(s.restore_cache(&store, &source, [0; 32]).unwrap());
    match phase.as_str() {
        "restoring" | "private-restoring" => panic!("restore crash hook did not execute"),
        "before" => std::process::exit(81),
        "partial" => {
            let p = s.sync(&source, 1).unwrap();
            assert_eq!(p.rolled_back, 2);
            assert!(!p.complete);
            std::process::exit(82);
        }
        "committed" => {
            let p = s.sync(&source, 3).unwrap();
            assert!(p.complete);
            assert_eq!(p.rolled_back, 2);
            s.save_cache(&store, &source, [0; 32]).unwrap();
            std::process::exit(83);
        }
        _ => panic!("unknown public test phase"),
    }
}

#[test]
fn reorg_process_death_recovers_old_or_new_cache_without_releasing_signed_claims() {
    for (phase, code, legacy) in [
        ("before", 81, false),
        ("restoring", 84, false),
        ("private-restoring", 85, false),
        ("partial", 82, false),
        ("committed", 83, false),
        ("before", 81, true),
        ("restoring", 84, true),
        ("private-restoring", 85, true),
        ("committed", 83, true),
    ] {
        let private_restore = phase == "private-restoring";
        let dir = tempfile::tempdir().unwrap();
        let mut store = wallet(dir.path());
        let mut source = DurableChain::open(
            &dir.path().join("chain.sqlite"),
            config(),
            root(),
            V6Verifier,
            2000,
        )
        .unwrap();
        let mut model = Model::new();
        model.accept(&mut source, 1, &[]);
        model.accept(&mut source, 2, &[]);
        model.accept(&mut source, 3, &[fixture("deposit")]);
        let funding = model.clone();
        if private_restore {
            model.accept(&mut source, 4, &[]);
            model.accept(&mut source, 5, &[]);
        } else {
            model.accept(&mut source, 4, &[fixture("transfer")]);
            model.accept(&mut source, 5, &[fixture("withdrawal")]);
        }
        let token = store
            .reserve_inputs(
                source.profile_id().unwrap(),
                source.chain().unwrap().tip(),
                20,
                vec![monario_wallet::storage::pending::Input::Transparent {
                    transaction: [8; 32],
                    index: 0,
                }],
            )
            .unwrap();
        store
            .bind_reservation(token, [9; 32], &fixture("withdrawal"))
            .unwrap();
        let cp = store.checkpoint().unwrap();
        let mut s = scanner(&source, 7);
        s.sync(&source, 100).unwrap();
        let private_seed = s
            .state
            .notes
            .values()
            .next()
            .map(|n| *n.note.rseed().as_bytes());
        if legacy {
            store
                .save_scan_cache([0; 32], &legacy_cache(&s, &source))
                .unwrap();
        } else {
            s.save_cache(&store, &source, [0; 32]).unwrap();
        }
        let old = store.load_scan_cache([0; 32]).unwrap().unwrap();
        let mut side = funding;
        if private_restore {
            side.accept(&mut source, 4, &[fixture("transfer")]);
            side.accept(&mut source, 5, &[fixture("withdrawal")]);
        } else {
            side.accept(&mut source, 4, &[]);
            side.accept(&mut source, 5, &[]);
        }
        side.accept(&mut source, 6, &[]);
        drop(source);
        drop(store);
        let id: String = cp.wallet_id.iter().map(|b| format!("{b:02x}")).collect();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "tests::cache::reorg_crash_worker"])
            .env("MONAR_REORG_CACHE_TEST_DIR", dir.path())
            .env("MONAR_REORG_CACHE_TEST_ID", id)
            .env("MONAR_REORG_CACHE_TEST_PHASE", phase)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(code));
        let source = DurableChain::open(
            &dir.path().join("chain.sqlite"),
            config(),
            root(),
            V6Verifier,
            2000,
        )
        .unwrap();
        let store = reopen(dir.path(), cp.wallet_id);
        let mut s = scanner(&source, 7);
        assert!(s.restore_cache(&store, &source, [0; 32]).unwrap());
        let p = s.sync(&source, 3).unwrap();
        assert!(p.complete);
        assert!(!p.restarted);
        assert_eq!(p.rolled_back, if phase == "committed" { 0 } else { 2 });
        if phase != "committed" {
            assert_eq!(store.load_scan_cache([0; 32]).unwrap().unwrap(), old);
        }
        let note_seed = if private_restore {
            assert_balance(&s, &source, 70, 0, 0);
            private_seed.unwrap()
        } else {
            assert_balance(&s, &source, 0, 0, 90);
            let nf = *s.unspent_notes(&source).unwrap().keys().next().unwrap();
            s.witness(&source, nf).unwrap();
            *s.unspent_notes(&source).unwrap()[&nf]
                .note
                .rseed()
                .as_bytes()
        };
        assert_eq!(store.checkpoint().unwrap(), cp);
        assert_eq!(store.reservations().unwrap().len(), 1);
        assert_eq!(
            store.reservations().unwrap()[&token].expose_transaction(),
            Some(fixture("withdrawal").as_slice())
        );
        s.save_cache(&store, &source, [0; 32]).unwrap();
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            if entry
                .as_ref()
                .unwrap()
                .file_name()
                .to_str()
                .unwrap()
                .starts_with("cache.monw")
            {
                let b = std::fs::read(entry.unwrap().path()).unwrap();
                for secret in [
                    b"public cache test password".as_slice(),
                    [7; 32].as_slice(),
                    note_seed.as_slice(),
                ] {
                    assert!(!b.windows(secret.len()).any(|v| v == secret));
                }
            }
        }
    }
}
