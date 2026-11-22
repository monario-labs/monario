//! Real-v6 package selection; fixed nonces and no socket or mining loop.
use super::*;
use monario_address::{Address, Network, Receiver, TransparentReceiver};

fn open_package(path: &std::path::Path) -> Node {
    let mut cfg = config();
    cfg.limits.transactions = 3;
    let store = DurableChain::open(path, cfg, root(), V6Verifier, 1_000_000).unwrap();
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
fn funded(n: &mut Node) -> Hash {
    let first = append(n, root().id, vec![], 0);
    let second = append(n, first, vec![], 0);
    let coin = *transaction::Transaction::read(
        n.source().stored_block(first).unwrap().transactions[0].as_slice(),
        BranchId::Nu6_3,
    )
    .unwrap()
    .txid()
    .as_ref();
    let mut bundle =
        transaction::Transaction::read(raw(0, Some((coin, 0)), 60).as_slice(), BranchId::Nu6_3)
            .unwrap()
            .transparent_bundle()
            .unwrap()
            .clone();
    bundle.vout.push(tb::TxOut::new(
        Zatoshis::from_u64(30).unwrap(),
        Script(script::Code(vec![0x51])),
    ));
    let data: TransactionData<transaction::Authorized> = TransactionData::from_parts_v6(
        BranchId::Nu6_3,
        0,
        16.into(),
        Some(bundle),
        None,
        None,
        None,
    );
    let mut funding = Vec::new();
    data.freeze().unwrap().write(&mut funding).unwrap();
    append(n, second, vec![funding], 0)
}
fn package(n: &Node, fork: Hash) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let block = n.source().stored_block(fork).unwrap();
    let id = monario_v6::transaction_references(&block.transactions[1])
        .unwrap()
        .0;
    let parent = raw(0, Some((id, 0)), 59);
    let pid = monario_v6::transaction_references(&parent).unwrap().0;
    (parent, raw(0, Some((pid, 0)), 0), raw(0, Some((id, 1)), 5))
}
fn prepare(n: &mut Node) -> crate::mining::Prepared {
    let address = Address::new(
        Network::Regtest,
        Receiver::Transparent(TransparentReceiver::PublicKeyHash([11; 20])),
    )
    .encode();
    let timestamp = 1000 + 105 * (n.source().chain().unwrap().height() + 1) as u32;
    n.prepare_work(
        crate::mining::Request {
            address: &address,
            network: Network::Regtest,
            timestamp: u64::from(timestamp),
            extra_data: b"public package fixture",
        },
        clock(0),
    )
    .unwrap()
}

#[test]
fn real_fee_package_selection_rebuilds_after_reorg_and_never_uses_stale_work() {
    let _serial = REAL.lock().unwrap();
    let dir = private_tempdir();
    let mut n = open_package(&dir.path().join("node.sqlite"));
    let fork = funded(&mut n);
    let (parent, child, other) = package(&n, fork);
    for raw in [&parent, &child, &other] {
        n.submit_transaction(raw.clone(), clock(0)).unwrap();
    }
    let old = prepare(&mut n);
    assert_eq!(old.selection.transactions, [parent.clone(), child.clone()]);
    assert_eq!(old.selection.fees.atoms(), 60);
    assert_eq!(n.source().chain().unwrap().tip(), fork);
    assert_eq!(n.pool.len(), 3);
    append(&mut n, fork, vec![parent.clone()], 0);
    assert!(matches!(
        n.submit_work(&old.work, [0; 32], clock(0)),
        Err(crate::mining::Error::Stale)
    ));
    let side = append(&mut n, fork, vec![], 0);
    append(&mut n, side, vec![], 0);
    let new = prepare(&mut n);
    assert_eq!(new.selection.transactions, [parent, child]);
    assert_eq!(new.selection.fees.atoms(), 60);
    assert!(matches!(
        n.submit_work(&new.work, [0; 32], clock(0)),
        Ok(crate::mining::Submitted::Accepted(_))
    ));
    assert_eq!(n.pool.len(), 1);
    assert_eq!(
        n.pool
            .transactions(n.source().chain().unwrap())
            .unwrap()
            .next()
            .unwrap(),
        other
    );
}

#[test]
fn package_selection_crash_worker() {
    let Some(path) = std::env::var_os("MONAR_PACKAGE_SELECTION_DB") else {
        return;
    };
    let mut n = open_package(std::path::Path::new(&path));
    let tip = n.source().chain().unwrap().tip();
    let (parent, child, other) = package(&n, tip);
    for raw in [&parent, &child, &other] {
        n.submit_transaction(raw.clone(), clock(0)).unwrap();
    }
    assert_eq!(prepare(&mut n).selection.transactions, [parent, child]);
    std::process::exit(97);
}

#[test]
fn crash_discards_package_scores_and_selection_without_changing_durable_chain() {
    let _serial = REAL.lock().unwrap();
    let dir = private_tempdir();
    let path = dir.path().join("node.sqlite");
    let mut n = open_package(&path);
    let tip = funded(&mut n);
    let (parent, child, other) = package(&n, tip);
    n.shutdown().unwrap();
    drop(n);
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "tests::package_selection::package_selection_crash_worker",
        ])
        .env("MONAR_PACKAGE_SELECTION_DB", &path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(97));
    let mut n = open_package(&path);
    assert_eq!(n.source().chain().unwrap().tip(), tip);
    assert!(n.pool.is_empty());
    assert!(prepare(&mut n).selection.transactions.is_empty());
    for raw in [&parent, &child, &other] {
        n.submit_transaction(raw.clone(), clock(0)).unwrap();
    }
    let prepared = prepare(&mut n);
    assert_eq!(prepared.selection.transactions, [parent, child]);
    assert!(matches!(
        n.submit_work(&prepared.work, [0; 32], clock(0)),
        Ok(crate::mining::Submitted::Accepted(_))
    ));
}
