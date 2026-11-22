//! A requested block can become known through local submission before its reply.
use super::*;

fn request(n: &mut Node, id: Hash) -> PeerId {
    let p = n.add_peer(clock(0)).unwrap();
    ready(n, p);
    let mut inventory = root().id.to_vec();
    inventory.extend(1u16.to_le_bytes());
    inventory.extend(id);
    let frame = wire::encode(
        n.magic,
        wire::INVENTORY,
        &inventory,
        n.block_limit,
        n.tx_limit,
    )
    .unwrap();
    deliver(n, p, &frame, 3);
    assert_eq!(n.sync.as_ref().unwrap().requested, Some(id));
    p
}

fn response(n: &Node, id: Hash, raw: &[u8]) -> Vec<u8> {
    let mut payload = id.to_vec();
    payload.extend(raw);
    wire::encode(n.magic, wire::BLOCK, &payload, n.block_limit, n.tx_limit).unwrap()
}

#[test]
fn known_header_cannot_authenticate_changed_truncated_or_extended_bodies() {
    let _serial = REAL.lock().unwrap();
    let (_source, mut source) = node();
    let id = append(&mut source, root().id, vec![], 0);
    let raw = source.source().authenticated_block_bytes(id).unwrap();
    let mut changed = raw.clone();
    *changed.last_mut().unwrap() ^= 1;
    let mut extended = raw.clone();
    extended.push(0);
    for bad in [changed, raw[..HEADER_LEN + 1].to_vec(), extended] {
        let (_dir, mut n) = node();
        let p = request(&mut n, id);
        n.import_block(&raw, clock(3)).unwrap();
        let supply = n.source().chain().unwrap().ledger().supply();
        let frame = response(&n, id, &bad); // Valid frame checksum, identical header ID.
        deliver(&mut n, p, &frame, 4);
        assert!(!n.contains_peer(p));
        assert!(n.sync.is_none());
        assert_eq!(n.buffered_bytes(), (0, 0));
        assert_eq!(n.source().chain().unwrap().tip(), id);
        assert_eq!(n.source().chain().unwrap().ledger().supply(), supply);
        assert_eq!(n.source().authenticated_block_bytes(id).unwrap(), raw);
    }
}

#[test]
fn exact_known_reply_advances_without_reapplying_ledger_state() {
    let _serial = REAL.lock().unwrap();
    let (_source, mut source) = node();
    let id = append(&mut source, root().id, vec![], 0);
    let raw = source.source().authenticated_block_bytes(id).unwrap();
    let (_dir, mut n) = node();
    let p = request(&mut n, id);
    n.import_block(&raw, clock(3)).unwrap();
    let supply = n.source().chain().unwrap().ledger().supply();
    let frame = response(&n, id, &raw);
    deliver(&mut n, p, &frame, 4);
    assert!(n.contains_peer(p));
    let sync = n.sync.as_ref().unwrap();
    assert_eq!(sync.cursor, id);
    assert_eq!(sync.requested, None);
    assert_eq!(n.source().chain().unwrap().height(), 1);
    assert_eq!(n.source().chain().unwrap().ledger().supply(), supply);
}

#[test]
fn known_detached_block_reply_cannot_reverse_a_heavier_chain() {
    let _serial = REAL.lock().unwrap();
    let (_source, mut source) = node();
    let old = append(&mut source, root().id, vec![], 0);
    let raw = source.source().authenticated_block_bytes(old).unwrap();
    let (_dir, mut n) = node();
    let p = request(&mut n, old);
    n.import_block(&raw, clock(3)).unwrap();
    // Different timestamp produces a sibling without changing the trusted root.
    let template = n
        .source()
        .chain()
        .unwrap()
        .build_template(root().id, 1046, 1_000_000, vec![], |plan| {
            Ok(super::coinbase(plan, 100))
        })
        .unwrap();
    let side_raw =
        monario_chain::wire::encode(&template.block, &config().limits, &V6Verifier).unwrap();
    let side = n.import_block(&side_raw, clock(3)).unwrap().id;
    let best = append(&mut n, side, vec![], 3);
    assert_ne!(best, old);
    let supply = n.source().chain().unwrap().ledger().supply();
    let frame = response(&n, old, &raw);
    deliver(&mut n, p, &frame, 4);
    assert!(n.contains_peer(p));
    assert_eq!(n.sync.as_ref().unwrap().cursor, old);
    assert_eq!(n.source().chain().unwrap().tip(), best);
    assert_eq!(n.source().chain().unwrap().ledger().supply(), supply);
}

#[test]
fn known_reply_crash_worker() {
    let Some(directory) = std::env::var_os("MONAR_KNOWN_BLOCK_CRASH_DIR") else {
        return;
    };
    let directory = std::path::Path::new(&directory);
    let bytes = std::fs::read(directory.join("reply.bin")).unwrap();
    let id = Header::decode(&bytes[..HEADER_LEN])
        .unwrap()
        .id(&config().chain_id);
    let mut n = open(&directory.join("node.sqlite"));
    let p = request(&mut n, id);
    n.import_block(&bytes, clock(3)).unwrap();
    let frame = response(&n, id, &bytes);
    if std::env::var("MONAR_KNOWN_BLOCK_CRASH_PHASE").unwrap() == "partial" {
        assert_eq!(
            n.receive(p, &frame[..frame.len() - 1], clock(4)).unwrap(),
            frame.len() - 1
        );
    } else {
        deliver(&mut n, p, &frame, 4);
        assert_eq!(n.sync.as_ref().unwrap().cursor, id);
    }
    std::process::exit(96);
}

#[test]
fn process_death_during_or_after_known_reply_preserves_only_validated_commits() {
    let _serial = REAL.lock().unwrap();
    let (_source, mut source) = node();
    let id = append(&mut source, root().id, vec![], 0);
    let bytes = source.source().authenticated_block_bytes(id).unwrap();
    for phase in ["partial", "complete"] {
        let dir = private_tempdir();
        std::fs::write(dir.path().join("reply.bin"), &bytes).unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::known_blocks::known_reply_crash_worker",
                "--nocapture",
            ])
            .env("MONAR_KNOWN_BLOCK_CRASH_DIR", dir.path())
            .env("MONAR_KNOWN_BLOCK_CRASH_PHASE", phase)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(96));
        let n = open(&dir.path().join("node.sqlite"));
        assert_eq!(n.source().chain().unwrap().tip(), id);
        assert_eq!(n.source().chain().unwrap().height(), 1);
        assert_eq!(n.source().authenticated_block_bytes(id).unwrap(), bytes);
        assert_eq!(n.peer_count(), 0);
        assert!(n.sync.is_none());
        assert_eq!(n.buffered_bytes(), (0, 0));
    }
}
