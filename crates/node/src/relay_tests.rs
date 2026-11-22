//! In-memory transport and public anyone-can-spend fixtures only.
use super::*;
#[path = "reannouncement_tests.rs"]
mod reannouncement;

fn funded(n: &mut Node) -> (Hash, Hash) {
    let first = append(n, root().id, vec![], 0);
    let tip = append(n, first, vec![], 0);
    let block = n.source().stored_block(first).unwrap();
    let tx =
        transaction::Transaction::read(block.transactions[0].as_slice(), BranchId::Nu6_3).unwrap();
    (*tx.txid().as_ref(), tip)
}
fn package(n: &mut Node, mut parent: Hash, count: usize, ms: u64) -> Vec<(Hash, Vec<u8>)> {
    (0..count)
        .map(|i| {
            let bytes = raw(0, Some((parent, 0)), 90 - i as u64 * 10);
            parent = n.submit_transaction(bytes.clone(), clock(ms)).unwrap();
            (parent, bytes)
        })
        .collect()
}
fn drain(n: &mut Node, p: PeerId) {
    while let Some(bytes) = n.outbound(p) {
        let len = bytes.len();
        n.consume_outbound(p, len).unwrap();
    }
}
fn synchronized_peer(n: &mut Node) -> PeerId {
    let born = n.last_ms;
    let p = n.add_peer(clock(born)).unwrap();
    let h = hello(n, p);
    deliver(n, p, &h, born + 1);
    let ack = wire::encode(n.magic, wire::ACK, &[], n.block_limit, n.tx_limit).unwrap();
    deliver(n, p, &ack, born + 2);
    drain(n, p);
    n.peers.get_mut(&p).unwrap().tip = n.store.chain().unwrap().tip();
    n.peers.get_mut(&p).unwrap().next_sync = u64::MAX;
    n.sync = None;
    p
}
#[test]
fn late_peer_catches_up_after_chain_sync_in_dependency_order_without_echoes() {
    let _serial = REAL.lock().unwrap();
    let (_a, mut a) = node();
    let (_b, mut b) = node();
    let (coin, tip) = funded(&mut a);
    let txs = package(&mut a, coin, 2, 0);
    let ap = a.add_peer(clock(0)).unwrap();
    let bp = b.add_peer(clock(0)).unwrap();
    drive(&mut a, ap, &mut b, bp, 1, 3000);
    assert_eq!(b.source().chain().unwrap().tip(), tip);
    assert_eq!(a.peers[&ap].tip, tip); // Download source receives the new tip too.
    assert_eq!(b.mempool().len(), 2);
    let delivered: Vec<_> = b
        .pool
        .relay_transactions(b.store.chain().unwrap())
        .unwrap()
        .map(|(id, _)| id)
        .collect();
    assert_eq!(delivered, txs.iter().map(|(id, _)| *id).collect::<Vec<_>>());
    let sent = a.peers[&ap].relay_count;
    drive(&mut a, ap, &mut b, bp, 3000, 3100);
    assert_eq!(a.peers[&ap].relay_count, sent);
    assert_eq!(b.peers[&bp].relay_count, 0);
}

#[test]
fn backpressure_and_window_limits_retry_without_marking_unsent_transactions() {
    let _serial = REAL.lock().unwrap();
    let (_dir, mut n) = node();
    let (coin, _) = funded(&mut n);
    let txs = package(&mut n, coin, 6, 0);
    let p = synchronized_peer(&mut n);
    n.bulk_bytes = n.limits.bytes_per_window;
    n.relay(clock(3)).unwrap();
    assert!(n.peers[&p].relayed.is_empty());
    n.bulk_bytes = 0;
    n.send_bytes = n.limits.send_bytes;
    n.relay(clock(3)).unwrap();
    assert!(n.peers[&p].relayed.is_empty());
    n.send_bytes = 0;
    for _ in 0..32 {
        let mut peer = n.peers.remove(&p).unwrap();
        assert!(n.queue(&mut peer, wire::PONG, &[0; 8], 3).unwrap());
        n.peers.insert(p, peer);
    }
    let tip = n.peers[&p].announced_tip;
    n.peers.get_mut(&p).unwrap().announced_tip = root().id;
    n.relay(clock(3)).unwrap();
    assert!(n.peers[&p].relayed.is_empty());
    assert_eq!(n.peers[&p].announced_tip, root().id);
    drain(&mut n, p);
    n.relay(clock(3)).unwrap();
    assert_eq!(n.peers[&p].announced_tip, tip);
    drain(&mut n, p);
    for ms in [3, 2503, 5003, 7503] {
        n.relay(clock(ms)).unwrap();
        drain(&mut n, p);
    }
    assert_eq!(n.peers[&p].relayed.len(), 4); // 16 checks / four configured slots.
    assert_eq!(n.peers[&p].relay_count, 4);
    assert!(
        txs[..4]
            .iter()
            .all(|(id, _)| n.peers[&p].relayed.contains_key(id))
    );
    assert!(!n.peers[&p].relayed.contains_key(&txs[4].0));
    n.relay(clock(10_003)).unwrap();
    drain(&mut n, p);
    n.relay(clock(12_503)).unwrap();
    assert_eq!(n.peers[&p].relayed.len(), 6);
    n.disconnect(p);
    assert_eq!(n.buffered_bytes(), (0, 0));
}

#[test]
fn unready_wrong_tip_and_active_block_sync_do_not_receive_catchup() {
    let _serial = REAL.lock().unwrap();
    let (_dir, mut n) = node();
    let (coin, _) = funded(&mut n);
    package(&mut n, coin, 1, 0);
    let p = n.add_peer(clock(0)).unwrap();
    n.relay(clock(1)).unwrap();
    assert!(n.peers[&p].relayed.is_empty());
    ready(&mut n, p);
    drain(&mut n, p);
    n.relay(clock(3)).unwrap();
    assert!(n.peers[&p].relayed.is_empty());
    n.peers.get_mut(&p).unwrap().tip = n.store.chain().unwrap().tip();
    n.sync = Some(Sync {
        started: 3,
        peer: p,
        locator: vec![root().id],
        cursor: root().id,
        ids: VecDeque::new(),
        awaiting: true,
        requested: None,
        deadline: 30_003,
    });
    n.relay(clock(4)).unwrap();
    assert!(n.peers[&p].relayed.is_empty());
    n.sync = None;
    n.relay(clock(5)).unwrap();
    assert_eq!(n.peers[&p].relayed.len(), 1);
}

#[test]
fn confirmed_transactions_are_forgotten_and_reorg_resurrection_can_relay_again() {
    let _serial = REAL.lock().unwrap();
    let (_dir, mut n) = node();
    let (coin, parent) = funded(&mut n);
    let txs = package(&mut n, coin, 1, 0);
    let p = synchronized_peer(&mut n);
    n.relay(clock(3)).unwrap();
    drain(&mut n, p);
    assert!(n.peers[&p].relayed.contains_key(&txs[0].0));
    append(&mut n, parent, vec![txs[0].1.clone()], 4);
    assert!(n.pool.is_empty());
    assert!(n.peers[&p].relayed.is_empty());
    let side = append(&mut n, parent, vec![], 5);
    let tip = append(&mut n, side, vec![], 6);
    assert_eq!(n.pool.len(), 1);
    n.peers.get_mut(&p).unwrap().tip = tip;
    n.relay(clock(2503)).unwrap();
    assert!(n.peers[&p].relayed.contains_key(&txs[0].0));
}

#[test]
fn peers_share_relay_turns_and_pending_block_requests_take_priority() {
    let _serial = REAL.lock().unwrap();
    let (_dir, mut n) = node();
    let (coin, _) = funded(&mut n);
    let a = synchronized_peer(&mut n);
    let b = synchronized_peer(&mut n);
    package(&mut n, coin, 1, 4);
    let request = wire::encode(
        n.magic,
        wire::GET_BLOCK,
        &root().id,
        n.block_limit,
        n.tx_limit,
    )
    .unwrap();
    assert_eq!(n.receive(a, &request, clock(5)).unwrap(), request.len());
    n.relay(clock(5)).unwrap();
    assert!(n.peers[&a].relayed.is_empty());
    assert!(n.peers[&b].relayed.is_empty());
    n.tick(clock(6)).unwrap();
    assert_eq!(n.peers.values().map(|p| p.relay_count).sum::<u32>(), 1);
    n.tick(clock(7)).unwrap();
    assert_eq!(n.peers[&a].relay_count, 1);
    assert_eq!(n.peers[&b].relay_count, 1);
    assert!(n.buffered_bytes().1 <= n.limits.send_bytes);
}

#[test]
fn relay_crash_worker() {
    let Some(path) = std::env::var_os("MONAR_RELAY_CRASH_DB") else {
        return;
    };
    let mut n = open(std::path::Path::new(&path));
    let block = n
        .source()
        .stored_block(
            n.source()
                .chain()
                .unwrap()
                .block_info(&n.source().chain().unwrap().tip())
                .unwrap()
                .parent
                .unwrap(),
        )
        .unwrap();
    let tx =
        transaction::Transaction::read(block.transactions[0].as_slice(), BranchId::Nu6_3).unwrap();
    package(&mut n, *tx.txid().as_ref(), 1, 0);
    let p = synchronized_peer(&mut n);
    n.relay(clock(3)).unwrap();
    if std::env::var_os("MONAR_RELAY_CRASH_REANNOUNCE").is_some() {
        drain(&mut n, p);
        let tip = n.source().chain().unwrap().tip();
        let frame = wire::encode(n.magic, wire::TIP, &tip, n.block_limit, n.tx_limit).unwrap();
        deliver(&mut n, p, &frame, 600_003);
    }
    let len = n.outbound(p).unwrap().len();
    n.consume_outbound(p, len / 2).unwrap();
    std::process::exit(94);
}

#[test]
fn oversized_parent_waits_for_confirmation_without_failing_relay_or_sending_child() {
    let _serial = REAL.lock().unwrap();
    let (_dir, mut n) = node();
    let (coin, tip) = funded(&mut n);
    let base =
        transaction::Transaction::read(raw(0, Some((coin, 0)), 90).as_slice(), BranchId::Nu6_3)
            .unwrap();
    let mut bundle = base.transparent_bundle().unwrap().clone();
    let mut script_bytes = vec![0x61; 200]; // NOPs, then a true stack value.
    script_bytes.push(0x51);
    bundle.vout[0] = tb::TxOut::new(
        Zatoshis::from_u64(90).unwrap(),
        Script(script::Code(script_bytes)),
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
    let mut parent = Vec::new();
    data.freeze().unwrap().write(&mut parent).unwrap();
    let id = n.submit_transaction(parent.clone(), clock(0)).unwrap();
    let child = raw(0, Some((id, 0)), 80);
    let child_id = n.submit_transaction(child.clone(), clock(0)).unwrap();
    n.tx_limit = child.len(); // Exercise the same mismatch as profiles above the wire cap.
    let p = synchronized_peer(&mut n);
    assert!(parent.len() > n.tx_limit);
    assert!(n.relay(clock(3)).is_ok());
    assert!(n.peers[&p].relayed.is_empty());
    let best = append(&mut n, tip, vec![parent], 4);
    n.peers.get_mut(&p).unwrap().tip = best;
    assert!(n.relay(clock(5)).is_ok());
    assert!(n.peers[&p].relayed.contains_key(&child_id));
}
#[test]
fn partial_send_process_death_discards_session_hints_and_allows_explicit_resubmission() {
    let _serial = REAL.lock().unwrap();
    let (dir, mut n) = node();
    let (coin, tip) = funded(&mut n);
    n.shutdown().unwrap();
    drop(n);
    let path = dir.path().join("node.sqlite");
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "tests::relay::relay_crash_worker"])
        .env("MONAR_RELAY_CRASH_DB", &path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(94));
    let mut n = open(&path);
    assert_eq!(n.source().chain().unwrap().tip(), tip);
    assert!(n.pool.is_empty());
    assert!(n.peers.is_empty());
    assert_eq!(n.buffered_bytes(), (0, 0));
    package(&mut n, coin, 1, 0);
    let p = synchronized_peer(&mut n);
    n.relay(clock(3)).unwrap();
    assert_eq!(n.peers[&p].relayed.len(), 1);
}
