//! Real v6 validation and memory-only transports; fixed public nonce fixtures.
use super::*;
fn funded(n: &mut Node) -> (Hash, Hash) {
    let first = append(n, root().id, vec![], 0);
    let tip = append(n, first, vec![], 0);
    let block = n.source().stored_block(first).unwrap();
    let tx =
        transaction::Transaction::read(block.transactions[0].as_slice(), BranchId::Nu6_3).unwrap();
    (*tx.txid().as_ref(), tip)
}
fn id(bytes: &[u8]) -> Hash {
    *transaction::Transaction::read(bytes, BranchId::Nu6_3)
        .unwrap()
        .txid()
        .as_ref()
}
fn peer(n: &mut Node) -> PeerId {
    let p = n.add_peer(clock(0)).unwrap();
    ready(n, p);
    while let Some(bytes) = n.outbound(p) {
        let len = bytes.len();
        n.consume_outbound(p, len).unwrap();
    }
    n.sync = None;
    n.peers.get_mut(&p).unwrap().next_sync = u64::MAX;
    p
}
fn send(n: &mut Node, p: PeerId, bytes: &[u8], ms: u64) {
    let frame = wire::encode(n.magic, wire::TRANSACTION, bytes, n.block_limit, n.tx_limit).unwrap();
    deliver(n, p, &frame, ms);
}
#[test]
fn child_before_parent_waits_for_state_change_then_passes_full_admission_without_echo() {
    let _serial = REAL.lock().unwrap();
    let (_dir, mut n) = node();
    let (coin, _) = funded(&mut n);
    let parent = raw(0, Some((coin, 0)), 90);
    let child = raw(0, Some((id(&parent), 0)), 80);
    assert_eq!(
        n.submit_transaction(child.clone(), clock(0)),
        Err(Error::Transaction)
    );
    assert_eq!(n.orphans.len(), 0);
    let p = peer(&mut n);
    send(&mut n, p, &child, 3);
    assert_eq!(n.orphans.len(), 1);
    assert!(n.pool.is_empty());
    let checks = n.tx_checks;
    for ms in 4..10 {
        n.tick(clock(ms)).unwrap();
    }
    assert_eq!(n.tx_checks, checks); // No state change: never retry in a busy loop.
    send(&mut n, p, &parent, 10);
    assert_eq!(n.pool.len(), 1);
    assert_eq!(n.orphans.len(), 1);
    n.tick(clock(11)).unwrap();
    assert_eq!(n.pool.len(), 2);
    assert_eq!(n.orphans.len(), 0);
    assert!(n.peers[&p].relayed.contains_key(&id(&child)));
}

#[test]
fn retry_obeys_origin_and_global_budgets_and_one_heavy_job_per_tick() {
    let _serial = REAL.lock().unwrap();
    let (_dir, mut n) = node();
    let (coin, _) = funded(&mut n);
    let parent = raw(0, Some((coin, 0)), 90);
    let child = raw(0, Some((id(&parent), 0)), 80);
    let p = peer(&mut n);
    send(&mut n, p, &child, 3);
    n.submit_transaction(parent, clock(4)).unwrap();
    n.tx_checks = n.limits.tx_checks_per_window;
    n.tick(clock(5)).unwrap();
    assert_eq!(n.orphans.len(), 1);
    n.tx_checks = 0;
    n.peers.get_mut(&p).unwrap().tx_checks = 4;
    n.tick(clock(6)).unwrap();
    assert_eq!(n.orphans.len(), 1);
    n.tick(clock(10_003)).unwrap();
    assert_eq!(n.orphans.len(), 0);
    assert_eq!(n.pool.len(), 2);
    assert_eq!(n.tx_checks, 1);
    assert_eq!(n.peers[&p].tx_checks, 1);
}

#[test]
fn deferred_invalid_signature_is_dropped_without_receipt_or_relay() {
    let _serial = REAL.lock().unwrap();
    let (_dir, mut n) = node();
    let (coin, _) = funded(&mut n);
    let base =
        transaction::Transaction::read(raw(0, Some((coin, 0)), 90).as_slice(), BranchId::Nu6_3)
            .unwrap();
    let mut bundle = base.transparent_bundle().unwrap().clone();
    bundle.vout[0] = tb::TxOut::new(
        Zatoshis::from_u64(90).unwrap(),
        Script(script::Code(vec![0xac])),
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
    let child = raw(0, Some((id(&parent), 0)), 80);
    let p = peer(&mut n);
    send(&mut n, p, &child, 3);
    assert_eq!(n.orphans.len(), 1);
    n.submit_transaction(parent, clock(4)).unwrap();
    n.tick(clock(5)).unwrap();
    assert_eq!(n.orphans.len(), 0);
    assert_eq!(n.pool.len(), 1);
    assert!(!n.peers[&p].relayed.contains_key(&id(&child)));
    assert!(n.contains_peer(p));
    send(&mut n, p, &[0], 6);
    assert_eq!(n.orphans.len(), 0);
}

#[test]
fn reorg_wakes_unknown_input_but_never_trusts_old_context_or_partial_state() {
    let _serial = REAL.lock().unwrap();
    let (_dir, mut n) = node();
    let (coin, tip) = funded(&mut n);
    let parent = raw(0, Some((coin, 0)), 90);
    let child = raw(0, Some((id(&parent), 0)), 80);
    let p = peer(&mut n);
    send(&mut n, p, &child, 3);
    assert_eq!(n.orphans.len(), 1);
    let main = append(&mut n, tip, vec![], 4);
    n.tick(clock(5)).unwrap();
    assert_eq!(n.orphans.len(), 1);
    assert!(n.pool.is_empty());
    let side = append(&mut n, tip, vec![parent], 6);
    assert_eq!(n.source().chain().unwrap().tip(), main);
    let best = append(&mut n, side, vec![], 7);
    n.tick(clock(8)).unwrap();
    assert_eq!(n.source().chain().unwrap().tip(), best);
    assert_eq!(n.orphans.len(), 0);
    assert_eq!(n.pool.len(), 1);
    assert!(
        n.pool
            .fee(n.source().chain().unwrap(), id(&child))
            .unwrap()
            .is_some()
    );
}

#[test]
fn disconnect_and_absolute_expiry_discard_quarantine_without_admission() {
    let _serial = REAL.lock().unwrap();
    let (_dir, mut n) = node();
    funded(&mut n);
    let p = peer(&mut n);
    let child = raw(0, Some(([99; 32], 0)), 1);
    send(&mut n, p, &child, 3);
    assert_eq!(n.orphans.len(), 1);
    send(&mut n, p, &child, 4);
    assert_eq!(n.orphans.len(), 1);
    while let Some(bytes) = n.outbound(p) {
        let len = bytes.len();
        n.consume_outbound(p, len).unwrap();
    }
    n.tick(clock(60_003)).unwrap();
    assert!(n.contains_peer(p));
    assert_eq!(n.orphans.len(), 0);
    assert!(n.pool.is_empty());
    // A fresh session owns its own quarantine and loses it on disconnect.
    n.disconnect(p);
    let (_dir, mut n) = node();
    let p = peer(&mut n);
    send(&mut n, p, &child, 3);
    assert_eq!(n.orphans.len(), 1);
    n.disconnect(p);
    assert_eq!(n.orphans.len(), 0);
    assert_eq!(n.buffered_bytes(), (0, 0));
}

#[test]
fn orphan_crash_worker() {
    let Some(path) = std::env::var_os("MONAR_ORPHAN_CRASH_DB") else {
        return;
    };
    let mut n = open(std::path::Path::new(&path));
    let p = peer(&mut n);
    send(&mut n, p, &raw(0, Some(([99; 32], 0)), 1), 3);
    assert_eq!(n.orphans.len(), 1);
    std::process::exit(95);
}
#[test]
fn process_death_never_persists_unverified_orphans_or_grants_admission() {
    let _serial = REAL.lock().unwrap();
    let (dir, mut n) = node();
    let (_, tip) = funded(&mut n);
    n.shutdown().unwrap();
    drop(n);
    let path = dir.path().join("node.sqlite");
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "tests::orphans::orphan_crash_worker"])
        .env("MONAR_ORPHAN_CRASH_DB", &path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(95));
    let n = open(&path);
    assert_eq!(n.source().chain().unwrap().tip(), tip);
    assert_eq!(n.orphans.len(), 0);
    assert!(n.pool.is_empty());
    assert_eq!(n.peer_count(), 0);
    assert_eq!(n.buffered_bytes(), (0, 0));
}
