//! No sockets: protocol requests/responses through memory-only transport.
use super::*;
#[path = "duplicate_tests.rs"]
mod duplicates;
#[path = "reorg_pool_tests.rs"]
mod reorg_pool;
fn funded(n: &mut Node) -> (Hash, Hash) {
    let first = append(n, root().id, vec![], 0);
    let tip = append(n, first, vec![], 0);
    let block = n.source().stored_block(first).unwrap();
    let tx =
        transaction::Transaction::read(block.transactions[0].as_slice(), BranchId::Nu6_3).unwrap();
    (*tx.txid().as_ref(), tip)
}
fn id(raw: &[u8]) -> Hash {
    monario_v6::transaction_references(raw).unwrap().0
}
fn drain(n: &mut Node, p: PeerId) {
    while let Some(b) = n.outbound(p) {
        let len = b.len();
        n.consume_outbound(p, len).unwrap();
    }
}
fn peer(n: &mut Node) -> PeerId {
    let now = n.last_ms;
    let p = n.add_peer(clock(now)).unwrap();
    let h = hello(n, p);
    deliver(n, p, &h, now + 1);
    let ack = wire::encode(n.magic, wire::ACK, &[], n.block_limit, n.tx_limit).unwrap();
    deliver(n, p, &ack, now + 2);
    drain(n, p);
    n.sync = None;
    n.peers.get_mut(&p).unwrap().next_sync = u64::MAX;
    p
}
fn send(n: &mut Node, p: PeerId, kind: u8, bytes: &[u8], ms: u64) {
    let frame = wire::encode(n.magic, kind, bytes, n.block_limit, n.tx_limit).unwrap();
    deliver(n, p, &frame, ms);
}
fn request(n: &mut Node, p: PeerId) -> Vec<u8> {
    let bytes = n.outbound(p).unwrap().to_vec();
    assert_eq!(bytes[4], wire::GET_TRANSACTION);
    n.consume_outbound(p, bytes.len()).unwrap();
    bytes[wire::HEADER..].to_vec()
}
#[test]
fn missing_parent_is_fetched_from_origin_validated_then_child_is_retried() {
    let _serial = REAL.lock().unwrap();
    let (_a, mut a) = node();
    let (_b, mut b) = node();
    let (coin, tip) = funded(&mut a);
    let (_, other) = funded(&mut b);
    assert_eq!(tip, other);
    let parent = raw(0, Some((coin, 0)), 90);
    let child = raw(0, Some((id(&parent), 0)), 80);
    b.submit_transaction(parent.clone(), clock(0)).unwrap();
    let ap = peer(&mut a);
    let bp = peer(&mut b);
    send(&mut a, ap, wire::TRANSACTION, &child, 3);
    assert_eq!(a.orphans.len(), 1);
    assert!(a.orphans.expected(ap, 3));
    assert!(a.pool.is_empty());
    transfer(&mut a, ap, &mut b, bp, 4);
    b.tick(clock(4)).unwrap();
    assert_eq!(b.outbound(bp).unwrap()[4], wire::PARENT_TRANSACTION);
    transfer(&mut b, bp, &mut a, ap, 5);
    a.tick(clock(5)).unwrap();
    assert_eq!(a.pool.len(), 1);
    a.tick(clock(6)).unwrap();
    assert_eq!(a.pool.len(), 2);
    assert_eq!(a.orphans.len(), 0);
    assert!(!a.orphans.expected(ap, 6));
}
#[test]
fn unsolicited_wrong_tokens_hashes_and_replays_cannot_grant_admission() {
    let _serial = REAL.lock().unwrap();
    for mode in ["unsolicited", "token", "id", "bytes", "replay"] {
        let (_dir, mut n) = node();
        let (coin, _) = funded(&mut n);
        let parent = raw(0, Some((coin, 0)), 90);
        let child = raw(0, Some((id(&parent), 0)), 80);
        let p = peer(&mut n);
        let mut payload = if mode == "unsolicited" {
            vec![0; 48]
        } else {
            send(&mut n, p, wire::TRANSACTION, &child, 3);
            request(&mut n, p)
        };
        if mode == "token" {
            payload[0] ^= 1;
        }
        if mode == "id" {
            payload[16] ^= 1;
        }
        payload.extend(if mode == "bytes" {
            raw(0, Some((coin, 0)), 89)
        } else {
            parent
        });
        let frame = wire::encode(
            n.magic,
            wire::PARENT_TRANSACTION,
            &payload,
            n.block_limit,
            n.tx_limit,
        )
        .unwrap();
        if mode == "unsolicited" {
            assert_eq!(
                n.receive(p, &frame[..wire::HEADER], clock(3)),
                Err(Error::Protocol)
            );
        } else {
            deliver(&mut n, p, &frame, 4);
            if mode == "replay" {
                assert_eq!(n.pool.len(), 1);
                assert_eq!(
                    n.receive(p, &frame[..wire::HEADER], clock(5)),
                    Err(Error::Protocol)
                );
            }
        }
        assert!(!n.contains_peer(p));
        assert_eq!(n.orphans.len(), 0);
        assert_eq!(n.pool.len(), usize::from(mode == "replay"));
        assert_eq!(n.buffered_bytes(), (0, 0));
    }
}
#[test]
fn not_found_timeout_and_queue_pressure_do_not_repeat_or_refresh_requests() {
    let _serial = REAL.lock().unwrap();
    let (_dir, mut n) = node();
    funded(&mut n);
    let p = peer(&mut n);
    n.send_bytes = n.limits.send_bytes;
    send(
        &mut n,
        p,
        wire::TRANSACTION,
        &raw(0, Some(([99; 32], 0)), 1),
        3,
    );
    assert!(!n.orphans.expected(p, 3));
    assert_eq!(n.parent_requests, 0);
    n.send_bytes = 0;
    n.tick(clock(4)).unwrap();
    let query = request(&mut n, p);
    send(&mut n, p, wire::TRANSACTION_NOT_FOUND, &query, 5);
    for ms in 6..10 {
        n.tick(clock(ms)).unwrap();
    }
    assert_eq!(n.parent_requests, 1);
    assert!(!n.orphans.expected(p, 9));
    // A different missing parent gets its own nonce and absolute deadline.
    send(
        &mut n,
        p,
        wire::TRANSACTION,
        &raw(0, Some(([98; 32], 0)), 1),
        10,
    );
    let query2 = request(&mut n, p);
    assert_ne!(&query[..16], &query2[..16]);
    let frame = wire::encode(
        n.magic,
        wire::TRANSACTION_NOT_FOUND,
        &query2,
        n.block_limit,
        n.tx_limit,
    )
    .unwrap();
    assert_eq!(
        n.receive(p, &frame[..wire::HEADER], clock(30_010)),
        Err(Error::Protocol)
    );
    assert!(n.pool.is_empty());
    assert_eq!(n.buffered_bytes(), (0, 0));
}
#[test]
fn delayed_parent_after_reorg_is_checked_against_new_inputs_and_drops_invalid_spends() {
    let _serial = REAL.lock().unwrap();
    let (_dir, mut n) = node();
    let (coin, tip) = funded(&mut n);
    let parent = raw(0, Some((coin, 0)), 90);
    let child = raw(0, Some((id(&parent), 0)), 80);
    let p = peer(&mut n);
    send(&mut n, p, wire::TRANSACTION, &child, 3);
    let mut payload = request(&mut n, p);
    payload.extend(parent);
    let side = append(&mut n, tip, vec![raw(0, Some((coin, 0)), 70)], 4);
    assert_eq!(n.source().chain().unwrap().tip(), side);
    send(&mut n, p, wire::PARENT_TRANSACTION, &payload, 5);
    assert!(n.pool.is_empty()); // Missing/spent input cannot be authorized by a response token.
    assert_eq!(n.orphans.len(), 2); // Both remain unverified, with inherited expiry.
    drain(&mut n, p);
    n.tick(clock(60_003)).unwrap();
    assert_eq!(n.orphans.len(), 0);
}
#[test]
fn responses_obey_proof_budgets_and_serving_uses_only_current_mempool_bytes() {
    let _serial = REAL.lock().unwrap();
    let (_dir, mut n) = node();
    let (coin, tip) = funded(&mut n);
    let parent = raw(0, Some((coin, 0)), 90);
    let child = raw(0, Some((id(&parent), 0)), 80);
    let p = peer(&mut n);
    send(&mut n, p, wire::TRANSACTION, &child, 3);
    let mut payload = request(&mut n, p);
    payload.extend(&parent);
    n.tx_checks = n.limits.tx_checks_per_window;
    send(&mut n, p, wire::PARENT_TRANSACTION, &payload, 4);
    assert!(n.peers[&p].inbox.is_some());
    assert!(n.pool.is_empty());
    assert!(n.orphans.expected(p, 4));
    n.tick(clock(10_003)).unwrap();
    assert_eq!(n.pool.len(), 1);
    assert!(!n.orphans.expected(p, 10_003));
    n.tick(clock(10_004)).unwrap();
    assert_eq!(n.pool.len(), 2);
    append(&mut n, tip, vec![parent.clone()], 10_005);
    drain(&mut n, p);
    let mut query = vec![7; 16];
    query.extend(id(&parent));
    send(&mut n, p, wire::GET_TRANSACTION, &query, 10_006);
    assert_eq!(n.outbound(p).unwrap()[4], wire::TRANSACTION_NOT_FOUND);
    drain(&mut n, p);
    let mut child_query = vec![8; 16];
    child_query.extend(id(&child));
    n.bulk_bytes = n.limits.bytes_per_window;
    send(&mut n, p, wire::GET_TRANSACTION, &child_query, 10_007);
    assert!(n.peers[&p].inbox.is_some());
    assert_eq!(n.peers[&p].parent_served, 1);
    assert!(n.outbound(p).is_none());
    n.bulk_bytes = 0;
    n.tick(clock(10_008)).unwrap();
    assert_eq!(n.outbound(p).unwrap()[4], wire::PARENT_TRANSACTION);
    assert_eq!(n.peers[&p].parent_served, 2);
    drain(&mut n, p);
    send(&mut n, p, wire::GET_TRANSACTION, &child_query, 10_009);
    assert!(n.peers[&p].inbox.is_some());
    assert!(n.outbound(p).is_none());
    n.tick(clock(20_003)).unwrap();
    assert_eq!(n.peers[&p].parent_served, 1);
    assert_eq!(n.outbound(p).unwrap()[4], wire::PARENT_TRANSACTION);
}

#[test]
fn fetched_parent_can_fetch_its_parent_within_original_lifetime_and_budgets() {
    let _serial = REAL.lock().unwrap();
    let (_dir, mut n) = node();
    let (coin, _) = funded(&mut n);
    let grandparent = raw(0, Some((coin, 0)), 90);
    let parent = raw(0, Some((id(&grandparent), 0)), 80);
    let child = raw(0, Some((id(&parent), 0)), 70);
    let p = peer(&mut n);
    send(&mut n, p, wire::TRANSACTION, &child, 3);
    let mut response = request(&mut n, p);
    response.extend(parent);
    send(&mut n, p, wire::PARENT_TRANSACTION, &response, 4);
    assert_eq!(n.orphans.len(), 2);
    assert!(n.pool.is_empty());
    let mut response = request(&mut n, p);
    assert_eq!(&response[16..], id(&grandparent));
    response.extend(grandparent);
    send(&mut n, p, wire::PARENT_TRANSACTION, &response, 5);
    assert_eq!(n.pool.len(), 1);
    n.tick(clock(6)).unwrap(); // Child still lacks its parent; consumes the last peer check.
    assert_eq!(n.pool.len(), 1);
    n.tick(clock(10_003)).unwrap();
    n.tick(clock(10_004)).unwrap();
    assert_eq!(n.pool.len(), 3);
    assert_eq!(n.orphans.len(), 0);
}
#[test]
fn parent_fetch_crash_worker() {
    let Some(path) = std::env::var_os("MONAR_PARENT_CRASH_DB") else {
        return;
    };
    let mut n = open(std::path::Path::new(&path));
    let p = peer(&mut n);
    send(
        &mut n,
        p,
        wire::TRANSACTION,
        &raw(0, Some(([99; 32], 0)), 1),
        3,
    );
    assert!(n.orphans.expected(p, 3));
    let len = n.outbound(p).unwrap().len();
    n.consume_outbound(p, len / 2).unwrap();
    std::process::exit(96);
}

#[test]
fn matching_effects_id_with_invalid_authorization_is_not_admission() {
    let _serial = REAL.lock().unwrap();
    let (_dir, mut n) = node();
    let (coin, _) = funded(&mut n);
    let parent = raw(0, Some((coin, 0)), 90);
    let child = raw(0, Some((id(&parent), 0)), 80);
    let p = peer(&mut n);
    send(&mut n, p, wire::TRANSACTION, &child, 3);
    let mut response = request(&mut n, p);
    let parsed = transaction::Transaction::read(parent.as_slice(), BranchId::Nu6_3).unwrap();
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
    assert_eq!(id(&bad), id(&parent));
    assert_ne!(bad, parent);
    response.extend(bad);
    send(&mut n, p, wire::PARENT_TRANSACTION, &response, 4);
    assert!(n.pool.is_empty());
    assert_eq!(n.orphans.len(), 1);
    assert!(n.contains_peer(p));
    assert!(!n.peers[&p].relayed.contains_key(&id(&parent)));
    assert!(!n.orphans.expected(p, 4));
}

#[test]
fn parent_response_cannot_consume_reserved_block_capacity_while_sync_is_pending() {
    let _serial = REAL.lock().unwrap();
    let (_dir, mut n) = node();
    let (coin, _) = funded(&mut n);
    let parent = raw(0, Some((coin, 0)), 90);
    let child = raw(0, Some((id(&parent), 0)), 80);
    let p = peer(&mut n);
    send(&mut n, p, wire::TRANSACTION, &child, 3);
    let mut response = request(&mut n, p);
    response.extend(parent);
    let frame = wire::encode(
        n.magic,
        wire::PARENT_TRANSACTION,
        &response,
        n.block_limit,
        n.tx_limit,
    )
    .unwrap();
    n.sync = Some(Sync {
        started: 3,
        peer: p,
        locator: vec![root().id],
        cursor: root().id,
        ids: VecDeque::new(),
        awaiting: false,
        requested: Some([44; 32]),
        deadline: 30_003,
    });
    n.receive_bytes = n.limits.receive_bytes - (n.block_limit + 32) - response.len() / 2;
    let held = n.receive_bytes;
    assert_eq!(n.receive(p, &frame, clock(4)).unwrap(), wire::HEADER);
    assert_eq!(n.receive_bytes, held);
    assert_eq!(n.peers[&p].decoder.reserved(), 0);
    assert!(n.peers[&p].inbox.is_none());
    assert!(n.orphans.expected(p, 4));
    // Free the simulated other buffers, then resume the exact held response.
    n.receive_bytes = 0;
    n.sync = None;
    assert_eq!(
        n.receive(p, &frame[wire::HEADER..], clock(5)).unwrap(),
        response.len()
    );
    n.tick(clock(5)).unwrap();
    assert_eq!(n.pool.len(), 1);
}
#[test]
fn crash_discards_requests_and_partial_stream_without_accepting_unverified_bytes() {
    let _serial = REAL.lock().unwrap();
    let (dir, mut n) = node();
    let (_, tip) = funded(&mut n);
    n.shutdown().unwrap();
    drop(n);
    let path = dir.path().join("node.sqlite");
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "tests::parents::parent_fetch_crash_worker"])
        .env("MONAR_PARENT_CRASH_DB", &path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(96));
    let n = open(&path);
    assert_eq!(n.source().chain().unwrap().tip(), tip);
    assert!(n.pool.is_empty());
    assert_eq!(n.orphans.len(), 0);
    assert_eq!(n.peer_count(), 0);
    assert_eq!(n.buffered_bytes(), (0, 0));
}
