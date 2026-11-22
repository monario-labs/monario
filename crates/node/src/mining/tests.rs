//! Public seeds/addresses, fixed zero nonces and synthetic external root metadata.
//! No listener, network activation or nonce search occurs.
use super::*;
use crate::tests::{REAL, append, clock, node, open, raw, root};
use monario_address::TransparentReceiver;

fn address() -> String {
    Address::new(
        Network::Regtest,
        Receiver::Transparent(TransparentReceiver::PublicKeyHash([7; 20])),
    )
    .encode()
}
fn prepare(n: &mut Node, timestamp: u32) -> Prepared {
    n.prepare_work(
        Request {
            address: &address(),
            network: Network::Regtest,
            timestamp: u64::from(timestamp),
            extra_data: b"public offline fixture",
        },
        clock(0),
    )
    .unwrap()
}
#[test]
fn fixed_nonce_insufficient_work_does_not_change_chain_or_mempool() {
    let _guard = REAL.lock().unwrap();
    let (dir, n) = node();
    let limits = n.limits;
    drop(n);
    let mut cfg = crate::tests::config();
    cfg.initial_bits = 0x1d00ffff;
    cfg.pow_limit_bits = 0x1d00ffff;
    let source = DurableChain::open(
        &dir.path().join("hard.sqlite"),
        cfg,
        root(),
        V6Verifier,
        1_000_000,
    )
    .unwrap();
    let mut n = Node::new(
        source,
        limits,
        mempool::Limits {
            transactions: 100,
            bytes: 1_000_000,
            inputs: 1000,
            minimum_fee: monario_monetary::Amount::ZERO,
        },
    )
    .unwrap();
    let work = prepare(&mut n, 1105).work;
    assert!(matches!(
        n.submit_work(&work, [0; 32], clock(0)),
        Err(Error::Node(crate::Error::Protocol))
    ));
    assert_eq!(n.source().chain().unwrap().tip(), root().id);
    assert!(n.mempool().is_empty());
    assert_eq!(n.peer_count(), 0);
}
#[test]
fn real_private_payments_are_selected_reverified_and_committed_without_pow_search() {
    let _guard = REAL.lock().unwrap();
    let (_dir, mut n) = node();
    let key = monario_wallet::Seed::from_bytes(&[7; 32])
        .unwrap()
        .transparent_key(Network::Main, 0, monario_wallet::Scope::External, 0)
        .unwrap();
    let c = n.source().chain().unwrap();
    let template = c
        .build_template(root().id, 1105, 1_000_000, vec![], |plan| {
            Ok(crate::tests::coinbase_with_script(
                plan,
                100,
                key.address().script_pubkey().unwrap(),
            ))
        })
        .unwrap();
    let bytes = wire::encode(&template.block, c.limits(), &V6Verifier).unwrap();
    let first = n.import_block(&bytes, clock(0)).unwrap().id;
    append(&mut n, first, vec![], 0);
    let copy_dir = crate::tests::private_tempdir();
    let mut copy = DurableChain::open(
        &copy_dir.path().join("copy.sqlite"),
        crate::tests::config(),
        root(),
        V6Verifier,
        1_000_000,
    )
    .unwrap();
    let mut cursor = root().id;
    for (height, raw) in [
        (
            3,
            include_bytes!("../../../v6/tests/fixtures/spend-deposit-v6.bin").as_slice(),
        ),
        (
            4,
            include_bytes!("../../../v6/tests/fixtures/spend-transfer-v6.bin").as_slice(),
        ),
        (
            5,
            include_bytes!("../../../v6/tests/fixtures/spend-withdrawal-v6.bin").as_slice(),
        ),
    ] {
        n.submit_transaction(raw.to_vec(), clock(0)).unwrap();
        let cached = n
            .pool
            .known_transaction(n.source().chain().unwrap(), raw)
            .unwrap()
            .unwrap();
        let mut altered = raw.to_vec();
        let last = altered.len() - 1;
        altered[last] ^= 1;
        assert_eq!(
            n.pool
                .known_transaction(n.source().chain().unwrap(), &altered)
                .unwrap(),
            None
        );
        assert_eq!(cached, monario_v6::transaction_references(raw).unwrap().0);

        let prepared = prepare(&mut n, 1000 + 105 * height);
        assert_eq!(prepared.selection.transactions, vec![raw]);
        assert_eq!(prepared.selection.fees.atoms(), 10);
        let mut bad = prepared.work.encode().to_vec();
        let pos = bad.windows(raw.len()).position(|w| w == raw).unwrap();
        bad[pos + raw.len() - 1] ^= 1;
        assert!(Work::decode(n.source(), &bad, 2000).is_err());
        assert_eq!(n.mempool().len(), 1);
        let work = Work::decode(n.source(), prepared.work.encode(), 2000).unwrap();
        assert!(matches!(
            n.submit_work(&work, [0; 32], clock(0)),
            Ok(Submitted::Accepted(_))
        ));
        assert!(n.mempool().is_empty());
        // Offline copies must independently validate real signatures and private
        // proofs, not inherit the producer's mining-work or mempool receipts.
        let mut page = Vec::new();
        cursor = monario_chain::transfer::export(n.source(), cursor, &mut page)
            .unwrap()
            .end;
        let imported =
            monario_chain::transfer::import(&mut copy, &mut page.as_slice(), 2000).unwrap();
        assert_eq!(imported.known, 0);
        assert_eq!(imported.accepted, if height == 3 { 3 } else { 1 });
        let original = n.source().chain().unwrap();
        let copied = copy.chain().unwrap();
        assert_eq!(copied.tip(), original.tip());
        let retrieved = crate::lookup::confirmed(n.source(), cached)
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.bytes, raw);
        assert_eq!(retrieved.validated_tip, original.tip());
        let retrieved_copy = crate::lookup::confirmed(&copy, cached).unwrap().unwrap();
        assert_eq!(retrieved_copy.bytes, raw);
        assert_eq!(retrieved_copy.confirmation, retrieved.confirmation);
        let audit = monario_chain::audit::page(&copy, crate::tests::root().id).unwrap();
        assert!(audit.at_tip);
        assert_eq!(audit.end, copied.tip());
        assert_eq!(u64::from(audit.blocks), copied.height());
        assert_eq!(copied.ledger().supply(), original.ledger().supply());
        assert_eq!(
            copied.ledger().shielded().root(),
            original.ledger().shielded().root()
        );
        assert_eq!(
            copied.ledger().shielded().balance,
            original.ledger().shielded().balance
        );
    }
    assert_eq!(
        n.source()
            .chain()
            .unwrap()
            .ledger()
            .shielded()
            .balance
            .atoms(),
        0
    );
}
#[test]
fn offline_work_is_canonical_read_only_and_validates_fixed_nonce_submission() {
    let _guard = REAL.lock().unwrap();
    let (_dir, mut n) = node();
    let before = n.source().chain().unwrap().tip();
    let prepared = prepare(&mut n, 1105);
    assert_eq!(prepared.work.parent(), before);
    assert_eq!(n.source().chain().unwrap().tip(), before);
    assert_eq!(n.peer_count(), 0);
    assert!(prepared.selection.transactions.is_empty());
    let work = Work::decode(n.source(), prepared.work.encode(), 2000).unwrap();
    assert_eq!(work.id(), prepared.work.id());
    assert_eq!(work.pow_preimage(), prepared.work.pow_preimage());
    assert_eq!(
        &work.pow_preimage()[work.pow_preimage().len() - 32..],
        &[0; 32]
    );
    assert_eq!(
        work.target_le(),
        monario_pow::Target::from_compact(crate::tests::config().initial_bits)
            .unwrap()
            .to_le_bytes()
    );
    assert!(matches!(
        n.submit_work(&work, [0; 32], clock(0)),
        Ok(Submitted::Accepted(_))
    ));
    assert!(matches!(
        n.submit_work(&work, [0; 32], clock(0)),
        Ok(Submitted::AlreadyKnown(_))
    ));
    n.shutdown().unwrap();
    assert!(matches!(
        n.submit_work(&work, [0; 32], clock(0)),
        Err(Error::Node(crate::Error::Stopped))
    ));
}
#[test]
fn work_decode_rejects_changed_context_bytes_counts_and_authorizations() {
    let _guard = REAL.lock().unwrap();
    let (_dir, mut n) = node();
    let prepared = prepare(&mut n, 1105);
    let packet = prepared.work.encode();
    for offset in [0, 8, 40, 72, 76, 108, 140, 176, 180, packet.len() - 1] {
        let mut bad = packet.to_vec();
        bad[offset] ^= 255;
        assert!(
            Work::decode(n.source(), &bad, 2000).is_err(),
            "offset {offset}"
        );
    }
    for len in [0, 7, 71, 72, packet.len() - 1] {
        assert!(Work::decode(n.source(), &packet[..len], 2000).is_err());
    }
    let mut trailing = packet.to_vec();
    trailing.push(0);
    assert!(Work::decode(n.source(), &trailing, 2000).is_err());
    // A different valid timestamp describes a distinct valid job, not corruption.
    let mut retimed = packet.to_vec();
    retimed[172..180].copy_from_slice(&1106u64.to_le_bytes());
    let different = Work::decode(n.source(), &retimed, 2000).unwrap();
    assert_ne!(different.id(), prepared.work.id());
    retimed[172..180].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(Work::decode(n.source(), &retimed, 2000).is_err());
    assert!(Work::decode(n.source(), &vec![0; 100_073], 2000).is_err());
    let bad = Address::new(
        Network::Main,
        Receiver::Transparent(TransparentReceiver::PublicKeyHash([7; 20])),
    )
    .encode();
    assert!(matches!(
        n.prepare_work(
            Request {
                address: &bad,
                network: Network::Regtest,
                timestamp: 1105,
                extra_data: b""
            },
            clock(0)
        ),
        Err(Error::Address)
    ));
    assert!(
        n.prepare_work(
            Request {
                address: &address(),
                network: Network::Regtest,
                timestamp: 1000,
                extra_data: b""
            },
            clock(0)
        )
        .is_err()
    );
    assert!(
        n.prepare_work(
            Request {
                address: &address(),
                network: Network::Regtest,
                timestamp: 1105,
                extra_data: &[0; 99]
            },
            clock(0)
        )
        .is_err()
    );
    assert_eq!(n.source().chain().unwrap().tip(), root().id);
    assert_eq!(n.peer_count(), 0);
}
#[test]
fn work_selection_dependencies_tip_changes_reorg_and_restart() {
    let _guard = REAL.lock().unwrap();
    let (dir, mut n) = node();
    let first = append(&mut n, root().id, vec![], 0);
    let second = append(&mut n, first, vec![], 0);
    let funding = n.source().stored_block(first).unwrap();
    let tx = zcash_primitives::transaction::Transaction::read(
        funding.transactions[0].as_slice(),
        zcash_protocol::consensus::BranchId::Nu6_3,
    )
    .unwrap();
    let parent = raw(0, Some((*tx.txid().as_ref(), 0)), 90);
    let parent_tx = zcash_primitives::transaction::Transaction::read(
        parent.as_slice(),
        zcash_protocol::consensus::BranchId::Nu6_3,
    )
    .unwrap();
    let child = raw(0, Some((*parent_tx.txid().as_ref(), 0)), 70);
    n.submit_transaction(parent.clone(), clock(0)).unwrap();
    n.submit_transaction(child.clone(), clock(0)).unwrap();
    let prepared = prepare(&mut n, 1315);
    assert_eq!(prepared.selection.transactions, vec![parent, child]);
    assert_eq!(prepared.selection.fees.atoms(), 30);
    let old_packet = prepared.work.encode().to_vec();
    let accepted = match n.submit_work(&prepared.work, [0; 32], clock(0)).unwrap() {
        Submitted::Accepted(a) => a,
        _ => panic!("new block"),
    };
    assert!(accepted.became_best);
    assert!(n.mempool().is_empty());
    assert!(
        matches!(n.submit_work(&prepared.work,[0;32],clock(0)),Ok(Submitted::AlreadyKnown(id)) if id==accepted.id)
    );
    let stale = prepare(&mut n, 1420);
    let side = append(&mut n, second, vec![], 0);
    append(&mut n, side, vec![], 0);
    assert!(matches!(
        n.submit_work(&stale.work, [0; 32], clock(0)),
        Err(Error::Stale)
    ));
    assert_eq!(n.mempool().len(), 2);
    assert_eq!(prepare(&mut n, 1525).selection.transactions.len(), 2);
    drop(n);
    let mut n = open(&dir.path().join("node.sqlite"));
    let known = Work::decode(n.source(), &old_packet, 2000).unwrap();
    assert!(matches!(
        n.submit_work(&known, [0; 32], clock(0)),
        Ok(Submitted::AlreadyKnown(_))
    ));
    assert!(n.mempool().is_empty()); // Ephemeral: transactions require replay/resubmission.
    assert!(prepare(&mut n, 1525).selection.transactions.is_empty());
}

#[test]
fn mining_crash_worker() {
    let Some(dir) = std::env::var_os("MONAR_MINING_TEST_DIR") else {
        return;
    };
    let dir = std::path::Path::new(&dir);
    let phase = std::env::var("MONAR_MINING_TEST_PHASE").unwrap();
    let mut n = open(&dir.join("node.sqlite"));
    let work = prepare(&mut n, 1105).work;
    let bytes = work.encode();
    std::fs::write(
        dir.join("work.bin"),
        if phase == "partial" {
            &bytes[..bytes.len() / 2]
        } else {
            bytes
        },
    )
    .unwrap();
    if phase == "partial" {
        std::process::exit(81);
    }
    if phase == "prepared" {
        std::process::exit(82);
    }
    n.submit_work(&work, [0; 32], clock(0)).unwrap();
    std::process::exit(83);
}
#[test]
fn process_death_preserves_old_or_committed_chain_and_retry_has_no_double_reward() {
    let _guard = REAL.lock().unwrap();
    for (phase, code) in [("partial", 81), ("prepared", 82), ("committed", 83)] {
        let (dir, n) = node();
        drop(n);
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "mining::tests::mining_crash_worker"])
            .env("MONAR_MINING_TEST_DIR", dir.path())
            .env("MONAR_MINING_TEST_PHASE", phase)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(code));
        let mut n = open(&dir.path().join("node.sqlite"));
        assert_eq!(
            n.source().chain().unwrap().height(),
            u64::from(phase == "committed")
        );
        let bytes = std::fs::read(dir.path().join("work.bin")).unwrap();
        if phase == "partial" {
            assert!(Work::decode(n.source(), &bytes, 2000).is_err());
            continue;
        }
        let work = Work::decode(n.source(), &bytes, 2000).unwrap();
        let supply = n.source().chain().unwrap().ledger().supply();
        let result = n.submit_work(&work, [0; 32], clock(0)).unwrap();
        if phase == "committed" {
            assert!(matches!(result, Submitted::AlreadyKnown(_)));
            assert_eq!(n.source().chain().unwrap().ledger().supply(), supply);
        } else {
            assert!(matches!(result, Submitted::Accepted(_)));
        }
        assert_eq!(n.source().chain().unwrap().height(), 1);
        assert_eq!(n.peer_count(), 0);
    }
}
