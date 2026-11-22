//! No sockets: retry timers use trusted fixture clocks and memory-only frames.
use super::*;
const RETRY: u64 = 600_000;
fn at(n: &mut Node, ms: u64) {
    n.clock(clock(ms)).unwrap();
    n.relay(clock(ms)).unwrap();
}

#[test]
fn exact_bytes_are_reoffered_only_after_the_per_transaction_interval() {
    let _serial = REAL.lock().unwrap();
    let (_dir, mut n) = node();
    let (coin, _) = funded(&mut n);
    let txs = package(&mut n, coin, 1, 0);
    let p = synchronized_peer(&mut n);
    at(&mut n, 3);
    assert_eq!(&n.outbound(p).unwrap()[wire::HEADER..], txs[0].1);
    drain(&mut n, p);
    at(&mut n, RETRY + 2);
    assert!(n.outbound(p).is_none());
    at(&mut n, RETRY + 3);
    assert_eq!(n.outbound(p).unwrap()[4], wire::TRANSACTION);
    assert_eq!(&n.outbound(p).unwrap()[wire::HEADER..], txs[0].1);
    assert_eq!(n.pool.len(), 1);
}

#[test]
fn oldest_hint_order_prevents_earlier_entries_from_starving_later_retries() {
    let _serial = REAL.lock().unwrap();
    let (_dir, mut n) = node();
    let (coin, _) = funded(&mut n);
    let txs = package(&mut n, coin, 3, 0);
    let p = synchronized_peer(&mut n);
    for ms in [3, 2503, 5003] {
        at(&mut n, ms);
        drain(&mut n, p);
    }
    for (i, (_, raw)) in txs.iter().enumerate() {
        at(&mut n, (i as u64 + 1) * RETRY + 5003);
        assert_eq!(&n.outbound(p).unwrap()[wire::HEADER..], raw);
        drain(&mut n, p);
    }
}

fn keepalive(n: &mut Node, p: PeerId, ms: u64) {
    let tip = n.source().chain().unwrap().tip();
    let bytes = wire::encode(n.magic, wire::TIP, &tip, n.block_limit, n.tx_limit).unwrap();
    deliver(n, p, &bytes, ms);
}

#[test]
fn recent_valid_receipt_delays_only_that_transactions_next_echo() {
    let _serial = REAL.lock().unwrap();
    let (_dir, mut n) = node();
    let (coin, _) = funded(&mut n);
    let txs = package(&mut n, coin, 1, 0);
    let p = synchronized_peer(&mut n);
    at(&mut n, 3);
    drain(&mut n, p);
    let frame = wire::encode(
        n.magic,
        wire::TRANSACTION,
        &txs[0].1,
        n.block_limit,
        n.tx_limit,
    )
    .unwrap();
    deliver(&mut n, p, &frame, RETRY + 2);
    assert_eq!(n.tx_checks, 0); // Exact live bytes do not spend another proof slot.
    at(&mut n, RETRY + 3);
    assert!(n.outbound(p).is_none());
    at(&mut n, 2 * RETRY + 1);
    assert!(n.outbound(p).is_none());
    at(&mut n, 2 * RETRY + 2);
    assert_eq!(&n.outbound(p).unwrap()[wire::HEADER..], txs[0].1);
}

#[test]
fn changed_authorization_same_id_cannot_refresh_timer_or_replace_reoffered_bytes() {
    let _serial = REAL.lock().unwrap();
    let (_dir, mut n) = node();
    let (coin, _) = funded(&mut n);
    let txs = package(&mut n, coin, 1, 0);
    let p = synchronized_peer(&mut n);
    at(&mut n, 3);
    drain(&mut n, p);
    let parsed = transaction::Transaction::read(txs[0].1.as_slice(), BranchId::Nu6_3).unwrap();
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
    assert_eq!(
        monario_v6::transaction_references(&bad).unwrap().0,
        txs[0].0
    );
    assert_ne!(bad, txs[0].1);
    let frame = wire::encode(n.magic, wire::TRANSACTION, &bad, n.block_limit, n.tx_limit).unwrap();
    deliver(&mut n, p, &frame, RETRY + 2);
    assert_eq!(n.peers[&p].relayed[&txs[0].0], 3);
    drain(&mut n, p);
    at(&mut n, RETRY + 3);
    assert_eq!(&n.outbound(p).unwrap()[wire::HEADER..], txs[0].1);
    assert_eq!(n.pool.len(), 1);
}

#[test]
fn retries_share_backpressure_pacing_and_global_peer_turns_without_advancing_unsent_hints() {
    let _serial = REAL.lock().unwrap();
    let (_dir, mut n) = node();
    let (coin, _) = funded(&mut n);
    let txs = package(&mut n, coin, 1, 0);
    let a = synchronized_peer(&mut n);
    let b = synchronized_peer(&mut n);
    at(&mut n, 5);
    at(&mut n, 6);
    drain(&mut n, a);
    drain(&mut n, b);
    let original_a = n.peers[&a].relayed[&txs[0].0];
    let original_b = n.peers[&b].relayed[&txs[0].0];
    n.clock(clock(RETRY + 6)).unwrap();
    n.bulk_bytes = n.limits.bytes_per_window;
    n.relay(clock(RETRY + 6)).unwrap();
    assert!(n.outbound(a).is_none() && n.outbound(b).is_none());
    assert_eq!(n.peers[&a].relayed[&txs[0].0], original_a);
    assert_eq!(n.peers[&b].relayed[&txs[0].0], original_b);
    n.bulk_bytes = 0;
    let request = wire::encode(
        n.magic,
        wire::GET_BLOCK,
        &root().id,
        n.block_limit,
        n.tx_limit,
    )
    .unwrap();
    n.receive(a, &request, clock(RETRY + 7)).unwrap();
    let tip = n.source().chain().unwrap().tip();
    let alive = wire::encode(n.magic, wire::TIP, &tip, n.block_limit, n.tx_limit).unwrap();
    n.receive(b, &alive, clock(RETRY + 7)).unwrap();
    n.relay(clock(RETRY + 7)).unwrap();
    assert!(n.outbound(a).is_none() && n.outbound(b).is_none());
    n.tick(clock(RETRY + 8)).unwrap();
    assert_eq!(n.peers.values().map(|p| p.relay_count).sum::<u32>(), 1);
    n.tick(clock(RETRY + 9)).unwrap();
    assert_eq!(n.peers[&a].relay_count, 1);
    assert_eq!(n.peers[&b].relay_count, 1);
    drain(&mut n, a);
    drain(&mut n, b);
    at(&mut n, RETRY + 10);
    assert!(n.outbound(a).is_none() && n.outbound(b).is_none());
    assert!(n.send_bytes <= n.limits.send_bytes);
}

#[test]
fn receiver_quota_drop_recovers_on_same_session_and_known_retry_uses_no_proof_slot() {
    let _serial = REAL.lock().unwrap();
    let (_ad, mut a) = node();
    let (_bd, mut b) = node();
    let (coin, tip) = funded(&mut a);
    assert_eq!(funded(&mut b).1, tip);
    let txs = package(&mut a, coin, 1, 0);
    let ap = synchronized_peer(&mut a);
    let bp = synchronized_peer(&mut b);
    b.tx_checks = b.limits.tx_checks_per_window;
    b.peers.get_mut(&bp).unwrap().tx_checks = 4;
    at(&mut a, 3);
    transfer(&mut a, ap, &mut b, bp, 3);
    b.tick(clock(3)).unwrap();
    assert!(b.pool.is_empty());
    keepalive(&mut b, bp, RETRY + 2);
    keepalive(&mut a, ap, RETRY + 3);
    transfer(&mut a, ap, &mut b, bp, RETRY + 4);
    b.tick(clock(RETRY + 4)).unwrap();
    assert_eq!(b.pool.len(), 1);
    assert_eq!(b.tx_checks, 1);
    assert!(b.outbound(bp).is_none());
    keepalive(&mut b, bp, 2 * RETRY + 2);
    keepalive(&mut a, ap, 2 * RETRY + 3);
    transfer(&mut a, ap, &mut b, bp, 2 * RETRY + 4);
    b.tick(clock(2 * RETRY + 4)).unwrap();
    assert_eq!(b.pool.len(), 1);
    assert_eq!(b.tx_checks, 0);
    assert_eq!(
        b.pool
            .known_transaction(b.source().chain().unwrap(), &txs[0].1)
            .unwrap(),
        Some(txs[0].0)
    );
}

#[test]
fn confirmation_discards_retry_time_and_reorg_resurrection_gets_fresh_admission_relay() {
    let _serial = REAL.lock().unwrap();
    let (_dir, mut n) = node();
    let (coin, fork) = funded(&mut n);
    let txs = package(&mut n, coin, 1, 0);
    let p = synchronized_peer(&mut n);
    at(&mut n, 3);
    drain(&mut n, p);
    append(&mut n, fork, vec![txs[0].1.clone()], 4);
    assert!(!n.peers[&p].relayed.contains_key(&txs[0].0));
    let side = append(&mut n, fork, vec![], 5);
    let tip = append(&mut n, side, vec![], 6);
    n.peers.get_mut(&p).unwrap().tip = tip;
    at(&mut n, 4000);
    assert_eq!(n.peers[&p].relayed[&txs[0].0], 4000);
    assert_eq!(n.pool.len(), 1);
}

#[test]
fn process_death_mid_retry_discards_hints_and_requires_fresh_pool_admission() {
    let _serial = REAL.lock().unwrap();
    let (dir, mut n) = node();
    let (coin, tip) = funded(&mut n);
    n.shutdown().unwrap();
    drop(n);
    let path = dir.path().join("node.sqlite");
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "tests::relay::relay_crash_worker"])
        .env("MONAR_RELAY_CRASH_DB", &path)
        .env("MONAR_RELAY_CRASH_REANNOUNCE", "yes")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(94));
    let mut n = open(&path);
    assert_eq!(n.source().chain().unwrap().tip(), tip);
    assert!(n.pool.is_empty() && n.peers.is_empty());
    assert_eq!(n.buffered_bytes(), (0, 0));
    let txs = package(&mut n, coin, 1, 0);
    let p = synchronized_peer(&mut n);
    at(&mut n, 3);
    assert_eq!(n.peers[&p].relayed[&txs[0].0], 3);
}
