//! Replay filtering uses current verified bytes, never an unverified effects ID.
use super::*;

#[test]
fn verified_replays_do_not_consume_validation_budget_or_fill_orphan_slots() {
    let _serial = REAL.lock().unwrap();
    let (_dir, mut n) = node();
    let (coin, _) = funded(&mut n);
    let raw = raw(0, Some((coin, 0)), 90);
    let id = n.submit_transaction(raw.clone(), clock(0)).unwrap();
    let p = peer(&mut n);
    let checks = n.tx_checks;
    for ms in 3..10 {
        send(&mut n, p, wire::TRANSACTION, &raw, ms);
    }
    assert_eq!(n.tx_checks, checks);
    assert_eq!(n.peers[&p].tx_checks, 0);
    assert_eq!(n.orphans.len(), 0);
    assert_eq!(n.pool.len(), 1);
    assert!(n.peers[&p].relayed.contains_key(&id));
    assert!(n.peers[&p].messages >= 9); // Handshake and ingress quotas still apply.
}

#[test]
fn changed_authorization_same_id_is_not_recognized_or_substituted() {
    let _serial = REAL.lock().unwrap();
    let (_dir, mut n) = node();
    let (coin, _) = funded(&mut n);
    let original = raw(0, Some((coin, 0)), 90);
    let id = n.submit_transaction(original.clone(), clock(0)).unwrap();
    let parsed = transaction::Transaction::read(original.as_slice(), BranchId::Nu6_3).unwrap();
    let mut bundle = parsed.transparent_bundle().unwrap().clone();
    bundle.vin[0] = tb::TxIn::from_parts(
        tb::OutPoint::new(coin, 0),
        Script(script::Code(vec![0x6a])),
        u32::MAX,
    );
    let data: TransactionData<transaction::Authorized> = TransactionData::from_parts_v6(
        BranchId::Nu6_3,
        0,
        16.into(),
        Some(bundle),
        None,
        None,
        None,
    );
    let mut bad = Vec::new();
    data.freeze().unwrap().write(&mut bad).unwrap();
    assert_eq!(monario_v6::transaction_references(&bad).unwrap().0, id);
    assert_eq!(
        n.pool
            .known_transaction(n.source().chain().unwrap(), &bad)
            .unwrap(),
        None
    );
    let p = peer(&mut n);
    send(&mut n, p, wire::TRANSACTION, &bad, 3);
    assert_eq!(n.tx_checks, 1);
    assert!(!n.peers[&p].relayed.contains_key(&id));
    assert_eq!(n.pool.len(), 1);
    assert_eq!(
        n.pool
            .relay_transactions(n.source().chain().unwrap())
            .unwrap()
            .next()
            .unwrap()
            .1,
        original
    );
}

#[test]
fn requested_parent_already_known_completes_at_exhausted_budget_but_wrong_id_cannot() {
    let _serial = REAL.lock().unwrap();
    for wrong in [false, true] {
        let (_dir, mut n) = node();
        let (coin, _) = funded(&mut n);
        let parent = raw(0, Some((coin, 0)), 90);
        let child = raw(0, Some((id(&parent), 0)), 80);
        let p = peer(&mut n);
        send(&mut n, p, wire::TRANSACTION, &child, 3);
        let mut response = request(&mut n, p);
        let cached = if wrong {
            raw(0, Some((coin, 0)), 89)
        } else {
            parent.clone()
        };
        n.submit_transaction(cached.clone(), clock(4)).unwrap();
        response.extend(cached);
        n.tx_checks = n.limits.tx_checks_per_window;
        n.peers.get_mut(&p).unwrap().tx_checks = 4;
        send(&mut n, p, wire::PARENT_TRANSACTION, &response, 5);
        assert_eq!(n.tx_checks, n.limits.tx_checks_per_window);
        assert_eq!(n.pool.len(), 1);
        assert!(!n.orphans.expected(p, 5));
        assert_eq!(n.contains_peer(p), !wrong);
        if !wrong {
            assert!(n.peers[&p].inbox.is_none());
            assert_eq!(n.peers[&p].tx_checks, 4);
        }
    }
}

#[test]
fn confirmation_removes_recognition_and_reorg_resurrection_revalidates_before_replay_filtering() {
    let _serial = REAL.lock().unwrap();
    let (_dir, mut n) = node();
    let (coin, tip) = funded(&mut n);
    let raw = raw(0, Some((coin, 0)), 90);
    let id = n.submit_transaction(raw.clone(), clock(0)).unwrap();
    let p = peer(&mut n);
    send(&mut n, p, wire::TRANSACTION, &raw, 3);
    assert_eq!(n.tx_checks, 0);
    append(&mut n, tip, vec![raw.clone()], 4);
    assert_eq!(
        n.pool
            .known_transaction(n.source().chain().unwrap(), &raw)
            .unwrap(),
        None
    );
    assert!(!n.peers[&p].relayed.contains_key(&id));
    let side = append(&mut n, tip, vec![], 5);
    append(&mut n, side, vec![], 6);
    assert_eq!(
        n.pool
            .known_transaction(n.source().chain().unwrap(), &raw)
            .unwrap(),
        Some(id)
    );
    send(&mut n, p, wire::TRANSACTION, &raw, 7);
    assert_eq!(n.tx_checks, 0);
    assert_eq!(n.orphans.len(), 0);
    assert_eq!(n.pool.len(), 1);
}

#[test]
fn replay_cache_crash_worker() {
    let Some(path) = std::env::var_os("MONAR_REPLAY_CACHE_TEST_DB") else {
        return;
    };
    let mut n = open(std::path::Path::new(&path));
    let tip = n.source().chain().unwrap().tip();
    let first = n
        .source()
        .chain()
        .unwrap()
        .block_info(&tip)
        .unwrap()
        .parent
        .unwrap();
    let block = n.source().stored_block(first).unwrap();
    let coin = *transaction::Transaction::read(block.transactions[0].as_slice(), BranchId::Nu6_3)
        .unwrap()
        .txid()
        .as_ref();
    let body = raw(0, Some((coin, 0)), 90);
    n.submit_transaction(body.clone(), clock(0)).unwrap();
    let p = peer(&mut n);
    send(&mut n, p, wire::TRANSACTION, &body, 3);
    assert_eq!(n.tx_checks, 0);
    std::process::exit(97);
}

#[test]
fn fingerprint_budget_applies_global_backpressure_and_resets_without_spending_proof_slots() {
    let _serial = REAL.lock().unwrap();
    let (_dir, mut n) = node();
    let (coin, _) = funded(&mut n);
    let body = raw(0, Some((coin, 0)), 90);
    let id = n.submit_transaction(body.clone(), clock(0)).unwrap();
    let p = peer(&mut n);
    n.replay_bytes = n.limits.bytes_per_window.max(n.tx_limit);
    send(&mut n, p, wire::TRANSACTION, &body, 3);
    assert!(n.peers[&p].inbox.is_some());
    assert_eq!(n.tx_checks, 0);
    assert_eq!(n.orphans.len(), 0);
    n.tick(clock(4)).unwrap();
    assert!(n.peers[&p].inbox.is_some());
    assert_eq!(n.tx_checks, 0);
    n.tick(clock(10_003)).unwrap();
    assert!(n.peers[&p].inbox.is_none());
    assert_eq!(n.tx_checks, 0);
    assert_eq!(n.replay_bytes, body.len());
    assert!(n.peers[&p].relayed.contains_key(&id));
}

#[test]
fn crash_discards_recognition_and_resubmission_requires_fresh_full_admission() {
    let _serial = REAL.lock().unwrap();
    let (dir, mut n) = node();
    let (coin, tip) = funded(&mut n);
    n.shutdown().unwrap();
    drop(n);
    let path = dir.path().join("node.sqlite");
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "tests::parents::duplicates::replay_cache_crash_worker",
        ])
        .env("MONAR_REPLAY_CACHE_TEST_DB", &path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(97));
    let mut n = open(&path);
    let body = raw(0, Some((coin, 0)), 90);
    assert_eq!(n.source().chain().unwrap().tip(), tip);
    assert_eq!(
        n.pool
            .known_transaction(n.source().chain().unwrap(), &body)
            .unwrap(),
        None
    );
    let p = peer(&mut n);
    send(&mut n, p, wire::TRANSACTION, &body, 3);
    assert_eq!(n.tx_checks, 1);
    assert_eq!(n.pool.len(), 1);
    assert_eq!(n.orphans.len(), 0);
}
