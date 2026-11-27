//! Memory-only networking. Real fixed-nonce PoW is verified; no nonce is searched.
use super::*;
#[path = "audit_tests.rs"]
mod audit;
#[path = "known_block_tests.rs"]
mod known_blocks;
#[path = "orphan_tests.rs"]
mod orphans;
#[path = "package_selection_tests.rs"]
mod package_selection;
#[path = "parent_tests.rs"]
mod parents;
#[path = "relay_tests.rs"]
mod relay;
#[path = "mempool_topology_tests.rs"]
mod topology;
#[path = "transfer_tests.rs"]
mod transfer;
use monario_chain::{Config, Root};
use zcash_primitives::transaction::{self, TransactionData};
use zcash_protocol::{consensus::BranchId, value::Zatoshis};
use zcash_script::script;
use zcash_transparent::{address::Script, bundle as tb};
pub(crate) static REAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
pub(crate) fn private_tempdir() -> tempfile::TempDir {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }
    #[cfg(not(unix))]
    {
        tempfile::tempdir().unwrap()
    }
}
pub(crate) fn config() -> Config {
    Config {
        chain_id: [2; 32],
        initial_bits: 0x2100ffff,
        pow_limit_bits: 0x2100ffff,
        half_life_seconds: 3600,
        asert_from_first_block: false,
        seed_interval: 1 << 20,
        seed_lag: 2,
        coinbase_maturity: 2,
        max_future_seconds: 120,
        retained_blocks: 1000,
        limits: monario_chain::Limits {
            block_bytes: 100000,
            transaction_bytes: 100000,
            transactions: 100,
            inputs_per_transaction: 100,
            outputs_per_transaction: 100,
            script_bytes: 1000,
        },
    }
}
pub(crate) fn root() -> Root {
    Root {
        id: [3; 32],
        timestamp: 1000,
        commitment: [4; 32],
    }
}
pub(crate) fn clock(ms: u64) -> Clock {
    Clock {
        monotonic_ms: ms,
        unix_seconds: 1_000_000,
    }
}
fn limits() -> Limits {
    Limits {
        peers: 4,
        receive_bytes: 1_000_000,
        send_bytes: 1_000_000,
        messages_per_window: 128,
        bytes_per_window: 2_000_000,
        tx_checks_per_window: 16,
    }
}
pub(crate) fn open(path: &std::path::Path) -> Node {
    let store = DurableChain::open(path, config(), root(), V6Verifier, 1_000_000).unwrap();
    Node::new(
        store,
        limits(),
        mempool::Limits {
            transactions: 100,
            bytes: 1_000_000,
            inputs: 1000,
            minimum_fee: monario_monetary::Amount::ZERO,
        },
    )
    .unwrap()
}
pub(crate) fn node() -> (tempfile::TempDir, Node) {
    let dir = tempfile::tempdir().unwrap();
    let n = open(&dir.path().join("node.sqlite"));
    (dir, n)
}
pub(crate) fn hello(n: &Node, nonce: [u8; 16]) -> Vec<u8> {
    let mut body = n.profile.to_vec();
    body.extend(nonce);
    body.extend(root().id);
    body.extend(u64::MAX.to_le_bytes());
    wire::encode(n.magic, wire::HELLO, &body, n.block_limit, n.tx_limit).unwrap()
}
fn deliver(n: &mut Node, id: PeerId, bytes: &[u8], ms: u64) {
    let mut at = 0;
    while at < bytes.len() {
        let end = (at + wire::CHUNK).min(bytes.len());
        let used = n.receive(id, &bytes[at..end], clock(ms)).unwrap();
        assert!(used > 0);
        at += used;
        if n.peers[&id].inbox.is_some() {
            n.tick(clock(ms)).unwrap();
        }
    }
}
fn ready(n: &mut Node, id: PeerId) {
    let h = hello(n, [9; 16]);
    deliver(n, id, &h, 1);
    let ack = wire::encode(n.magic, wire::ACK, &[], n.block_limit, n.tx_limit).unwrap();
    deliver(n, id, &ack, 2);
    assert!(n.peers[&id].ready);
}
fn transfer(a: &mut Node, ap: PeerId, b: &mut Node, bp: PeerId, ms: u64) {
    for _ in 0..8 {
        let Some(bytes) = a.outbound(ap).map(|b| b.to_vec()) else {
            break;
        };
        let n = b.receive(bp, &bytes, clock(ms)).unwrap();
        if n == 0 {
            break;
        }
        a.consume_outbound(ap, n).unwrap();
    }
}
fn drive(a: &mut Node, ap: PeerId, b: &mut Node, bp: PeerId, start: u64, end: u64) {
    for ms in start..end {
        transfer(a, ap, b, bp, ms);
        transfer(b, bp, a, ap, ms);
        a.tick(clock(ms)).unwrap();
        b.tick(clock(ms)).unwrap();
    }
}
pub(crate) fn raw(height: u32, input: Option<(Hash, u32)>, value: u64) -> Vec<u8> {
    raw_outputs(height, input, vec![(value, vec![0x51])])
}
fn raw_outputs(height: u32, input: Option<(Hash, u32)>, outputs: Vec<(u64, Vec<u8>)>) -> Vec<u8> {
    let input = if let Some((id, index)) = input {
        tb::TxIn::from_parts(tb::OutPoint::new(id, index), Script::default(), u32::MAX)
    } else {
        tb::TxIn::from_parts(
            tb::OutPoint::new([0; 32], u32::MAX),
            Script(script::Code(vec![0x50 + height as u8, 0])),
            u32::MAX,
        )
    };
    let tx: TransactionData<transaction::Authorized> = TransactionData::from_parts_v6(
        BranchId::Nu6_3,
        0,
        if height == 0 { 16 } else { height }.into(),
        Some(tb::Bundle {
            vin: vec![input],
            vout: outputs
                .into_iter()
                .map(|(value, script_bytes)| {
                    tb::TxOut::new(
                        Zatoshis::from_u64(value).unwrap(),
                        Script(script::Code(script_bytes)),
                    )
                })
                .collect(),
            authorization: tb::Authorized,
        }),
        None,
        None,
        None,
    );
    let mut out = Vec::new();
    tx.freeze().unwrap().write(&mut out).unwrap();
    out
}
pub(crate) fn coinbase(plan: &monario_chain::assembly::CoinbasePlan, miner_value: u64) -> Vec<u8> {
    coinbase_with_script(plan, miner_value, vec![0x51])
}
pub(crate) fn coinbase_with_script(
    plan: &monario_chain::assembly::CoinbasePlan,
    miner_value: u64,
    miner_script: Vec<u8>,
) -> Vec<u8> {
    let outputs = vec![(miner_value, miner_script)];
    raw_outputs(plan.height as u32, None, outputs)
}
pub(crate) fn append(n: &mut Node, parent: Hash, extra: Vec<Vec<u8>>, ms: u64) -> Hash {
    let c = n.source().chain().unwrap();
    let height = c.block_info(&parent).unwrap().height + 1;
    let template = c
        .build_template(parent, 1000 + 105 * height, 1_000_000, extra, |p| {
            Ok(coinbase(p, if p.height == 1 { 100 } else { 0 }))
        })
        .unwrap();
    let bytes = monario_chain::wire::encode(&template.block, c.limits(), &V6Verifier).unwrap();
    n.import_block(&bytes, clock(ms)).unwrap().id
}
#[test]
fn handshake_profile_sequence_self_connections_and_bad_checksum_release_memory() {
    let (_dir, mut n) = node();
    let p = n.add_peer(clock(0)).unwrap();
    let ack = wire::encode(n.magic, wire::ACK, &[], n.block_limit, n.tx_limit).unwrap();
    assert_eq!(n.receive(p, &ack, clock(0)), Err(Error::Protocol));
    assert_eq!(n.buffered_bytes(), (0, 0));
    let p = n.add_peer(clock(1)).unwrap();
    let mut h = hello(&n, [9; 16]);
    h[wire::HEADER] ^= 1;
    assert_eq!(n.receive(p, &h, clock(1)), Err(Error::Protocol));
    assert_eq!(n.buffered_bytes(), (0, 0));
    let p = n.add_peer(clock(2)).unwrap();
    let h = hello(&n, n.peers[&p].nonce);
    deliver(&mut n, p, &h, 2);
    assert!(!n.contains_peer(p));
    let p = n.add_peer(clock(3)).unwrap();
    let mut body = n.profile.to_vec();
    body[0] ^= 1;
    body.extend([9; 16]);
    body.extend(root().id);
    body.extend(0u64.to_le_bytes());
    let h = wire::encode(n.magic, wire::HELLO, &body, n.block_limit, n.tx_limit).unwrap();
    deliver(&mut n, p, &h, 3);
    assert!(!n.contains_peer(p));
    assert_eq!(n.source().chain().unwrap().height(), 0);
}
#[test]
fn unsolicited_blocks_and_absolute_timeouts_are_bounded() {
    let (_dir, mut n) = node();
    let p = n.add_peer(clock(0)).unwrap();
    ready(&mut n, p);
    let payload = vec![0; 32 + HEADER_LEN + 1];
    let frame = wire::encode(n.magic, wire::BLOCK, &payload, n.block_limit, n.tx_limit).unwrap();
    assert_eq!(n.receive(p, &frame, clock(3)), Err(Error::Protocol));
    assert_eq!(n.buffered_bytes(), (0, 0));
    let p = n.add_peer(clock(4)).unwrap();
    let h = hello(&n, [9; 16]);
    n.receive(p, &h[..1], clock(5)).unwrap();
    n.receive(p, &h[1..2], clock(10_003)).unwrap();
    n.tick(clock(10_004)).unwrap();
    assert!(!n.contains_peer(p));
    assert_eq!(n.peer_count(), 0);
    assert_eq!(n.buffered_bytes(), (0, 0));
}
#[test]
fn requested_but_invalid_blocks_cannot_enter_the_chain() {
    let (_dir, mut n) = node();
    let p = n.add_peer(clock(0)).unwrap();
    ready(&mut n, p);
    assert!(n.sync.as_ref().unwrap().awaiting);
    let c = n.source().chain().unwrap();
    let mut template = c
        .build_template(root().id, 1105, 1_000_000, vec![], |plan| {
            Ok(coinbase(plan, 100))
        })
        .unwrap();
    template.block.header.bits = 0x1d00ffff; // Canonical target, wrong initial difficulty.
    let id = template.block.header.id(&n.chain_id);
    let body = monario_chain::wire::encode(&template.block, c.limits(), &V6Verifier).unwrap();
    let mut inv = root().id.to_vec();
    inv.extend(1u16.to_le_bytes());
    inv.extend(id);
    let frame = wire::encode(n.magic, wire::INVENTORY, &inv, n.block_limit, n.tx_limit).unwrap();
    deliver(&mut n, p, &frame, 3);
    assert_eq!(n.sync.as_ref().unwrap().requested, Some(id));
    let mut payload = id.to_vec();
    payload.extend(body);
    let frame = wire::encode(n.magic, wire::BLOCK, &payload, n.block_limit, n.tx_limit).unwrap();
    deliver(&mut n, p, &frame, 4);
    assert_eq!(n.source().chain().unwrap().height(), 0);
    assert!(!n.source().chain().unwrap().contains(&id));
    assert!(!n.contains_peer(p));
    assert_eq!(n.buffered_bytes(), (0, 0));
}
#[test]
fn malformed_inventory_and_periodic_session_limits_do_not_grant_peer_authority() {
    let (_dir, mut n) = node();
    let p = n.add_peer(clock(0)).unwrap();
    ready(&mut n, p);
    let mut inv = root().id.to_vec();
    inv.extend(2u16.to_le_bytes());
    inv.extend([7; 32]);
    inv.extend([7; 32]);
    let frame = wire::encode(n.magic, wire::INVENTORY, &inv, n.block_limit, n.tx_limit).unwrap();
    deliver(&mut n, p, &frame, 3);
    assert!(!n.contains_peer(p));
    let (_dir, mut n) = node();
    let p = n.add_peer(clock(0)).unwrap();
    ready(&mut n, p);
    while let Some(bytes) = n.outbound(p) {
        let count = bytes.len();
        n.consume_outbound(p, count).unwrap();
    }
    let peer = n.peers.get_mut(&p).unwrap();
    peer.last_rx = 120_000;
    let sync = n.sync.as_mut().unwrap();
    sync.awaiting = false;
    sync.started = 0;
    sync.deadline = 150_000;
    n.tick(clock(120_000)).unwrap();
    assert!(n.contains_peer(p));
    assert!(n.sync.is_none());
    assert!(n.peers[&p].next_sync > 120_000);
}
#[test]
fn message_quotas_and_receive_backpressure_do_not_grow_buffers() {
    let (_dir, mut n) = node();
    n.limits.messages_per_window = 8;
    let p = n.add_peer(clock(0)).unwrap();
    ready(&mut n, p);
    let ping = wire::encode(n.magic, wire::PING, &[7; 8], n.block_limit, n.tx_limit).unwrap();
    for ms in 3..10 {
        if n.receive(p, &ping, clock(ms)).unwrap() == 0 {
            break;
        }
        n.tick(clock(ms)).unwrap();
    }
    assert!(n.contains_peer(p));
    assert_eq!(n.peers[&p].messages, 8);
    assert_eq!(n.receive(p, &ping, clock(10_002)).unwrap(), ping.len());
    n.tick(clock(10_002)).unwrap();
    assert_eq!(n.peers[&p].messages, 1);
    n.disconnect(p);
    assert_eq!(n.buffered_bytes(), (0, 0));
    let (_dir, mut n) = node();
    n.limits.receive_bytes = 2 * (n.block_limit + 32) + 65536;
    for i in 0..4 {
        let born = u64::from(i) * 3;
        let p = n.add_peer(clock(born)).unwrap();
        let h = hello(&n, [i + 1; 16]);
        deliver(&mut n, p, &h, born + 1);
        let ack = wire::encode(n.magic, wire::ACK, &[], n.block_limit, n.tx_limit).unwrap();
        deliver(&mut n, p, &ack, born + 2);
        let frame = wire::encode(
            n.magic,
            wire::TRANSACTION,
            &vec![0; n.tx_limit],
            n.block_limit,
            n.tx_limit,
        )
        .unwrap();
        assert_eq!(
            n.receive(p, &frame[..wire::HEADER], clock(born + 2))
                .unwrap(),
            wire::HEADER
        );
        assert!(n.buffered_bytes().0 <= n.limits.receive_bytes - (n.block_limit + 32));
    }
    n.tick(clock(30_011)).unwrap();
    assert_eq!(n.buffered_bytes(), (0, 0));
}
#[test]
fn real_two_node_sync_transaction_relay_reorg_and_restart() {
    let _serial = REAL.lock().unwrap();
    let (dir_a, mut a) = node();
    let (_dir_b, mut b) = node();
    let first = append(&mut a, root().id, vec![], 0);
    let parent = append(&mut a, first, vec![], 0);
    let ap = a.add_peer(clock(0)).unwrap();
    let bp = b.add_peer(clock(0)).unwrap();
    drive(&mut a, ap, &mut b, bp, 1, 100);
    assert_eq!(b.source().chain().unwrap().tip(), parent);
    let block = a.source().stored_block(first).unwrap();
    let tx =
        transaction::Transaction::read(block.transactions[0].as_slice(), BranchId::Nu6_3).unwrap();
    let input = (*tx.txid().as_ref(), 0);
    let spend = raw(0, Some(input), 90);
    a.submit_transaction(spend.clone(), clock(100)).unwrap();
    drive(&mut a, ap, &mut b, bp, 100, 140);
    assert_eq!(b.mempool().len(), 1);
    let main = append(&mut a, parent, vec![spend.clone()], 140);
    drive(&mut a, ap, &mut b, bp, 140, 200);
    assert_eq!(b.source().chain().unwrap().tip(), main);
    assert!(b.mempool().is_empty());
    let side = append(&mut b, parent, vec![], 200);
    let best = append(&mut b, side, vec![], 200);
    drive(&mut a, ap, &mut b, bp, 200, 300);
    assert_eq!(a.source().chain().unwrap().tip(), best);
    assert_eq!(a.mempool().len(), 1);
    assert_eq!(b.mempool().len(), 1);
    a.shutdown().unwrap();
    drop(a);
    let mut a = open(&dir_a.path().join("node.sqlite"));
    assert_eq!(a.source().chain().unwrap().tip(), best);
    assert_eq!(a.peer_count(), 0);
    assert!(a.mempool().is_empty());
    a.submit_transaction(spend, clock(0)).unwrap();
    assert_eq!(a.mempool().len(), 1);
}
#[test]
fn runtime_crash_worker() {
    let Some(path) = std::env::var_os("MONAR_NODE_CRASH_DB") else {
        return;
    };
    let mut n = open(std::path::Path::new(&path));
    if std::env::var("MONAR_NODE_CRASH_PHASE").unwrap() == "partial" {
        let p = n.add_peer(clock(0)).unwrap();
        let h = hello(&n, [9; 16]);
        n.receive(p, &h[..8], clock(0)).unwrap();
        std::process::exit(92);
    }
    append(&mut n, root().id, vec![], 0);
    std::process::exit(93);
}
#[test]
fn runtime_abrupt_exit_recovers_commits_and_discards_peer_state() {
    let _serial = REAL.lock().unwrap();
    for (phase, code, height) in [("partial", 92, 0), ("committed", 93, 1)] {
        let (dir, mut n) = node();
        n.shutdown().unwrap();
        drop(n);
        let path = dir.path().join("node.sqlite");
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "tests::runtime_crash_worker", "--nocapture"])
            .env("MONAR_NODE_CRASH_DB", &path)
            .env("MONAR_NODE_CRASH_PHASE", phase)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(code));
        let n = open(&path);
        assert_eq!(n.source().chain().unwrap().height(), height);
        assert_eq!(n.peer_count(), 0);
        assert_eq!(n.buffered_bytes(), (0, 0));
    }
}

#[test]
fn candidates_are_advertised_bounded_deduplicated_and_never_dialed() {
    let (_dir, mut n) = node();
    let id = n.add_peer(clock(0)).unwrap();
    let local = crate::transport::Identity::generate().unwrap().public_key();
    let address: std::net::SocketAddr = "127.0.0.1:9000".parse().unwrap();
    let key = crate::transport::Identity::generate().unwrap().public_key();
    let candidate = PeerCandidate {
        address,
        public_key: key,
    };
    n.set_local_candidates(local, vec![candidate]).unwrap();
    ready(&mut n, id);
    let payload = wire::encode_candidates(&[(address, key)]).unwrap();
    let expected = wire::encode(
        n.magic,
        wire::CANDIDATES,
        &payload,
        n.block_limit,
        n.tx_limit,
    )
    .unwrap();
    let mut advertised = false;
    for _ in 0..4 {
        let Some(bytes) = n.outbound(id).map(|bytes| bytes.to_vec()) else {
            break;
        };
        if bytes
            .windows(expected.len())
            .any(|window| window == expected)
        {
            advertised = true;
            break;
        }
        n.consume_outbound(id, bytes.len()).unwrap();
    }
    assert!(
        advertised,
        "the ready peer must receive a candidate advertisement"
    );

    let peer_count = n.peer_count();
    let received_address: std::net::SocketAddr = "127.0.0.1:9001".parse().unwrap();
    let received_key = crate::transport::Identity::generate().unwrap().public_key();
    let received = PeerCandidate {
        address: received_address,
        public_key: received_key,
    };
    let received_payload = wire::encode_candidates(&[(received_address, received_key)]).unwrap();
    let received_frame = wire::encode(
        n.magic,
        wire::CANDIDATES,
        &received_payload,
        n.block_limit,
        n.tx_limit,
    )
    .unwrap();
    deliver(&mut n, id, &received_frame, 3);
    assert_eq!(n.candidates(), &[received]);
    deliver(&mut n, id, &received_frame, 4);
    assert_eq!(n.candidates(), &[received]);
    assert_eq!(n.peer_count(), peer_count);

    let (_dir2, mut self_node) = node();
    let self_id = self_node.add_peer(clock(0)).unwrap();
    self_node
        .set_local_candidates(received_key, vec![])
        .unwrap();
    ready(&mut self_node, self_id);
    deliver(&mut self_node, self_id, &received_frame, 3);
    assert!(self_node.candidates().is_empty());

    let bad = wire::encode_candidates(&[(received_address, [0; 32])]).unwrap();
    let bad_frame =
        wire::encode(n.magic, wire::CANDIDATES, &bad, n.block_limit, n.tx_limit).unwrap();
    // Frames are parsed on receive, then handled on tick. A protocol violation
    // releases the peer; it is not a process-wide tick failure.
    n.receive(id, &bad_frame, clock(6)).unwrap();
    n.tick(clock(6)).unwrap();
    assert!(!n.contains_peer(id));
}
