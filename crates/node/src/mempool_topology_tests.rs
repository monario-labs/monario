//! Real v6 family limits and durable-chain recovery, with no network or nonce search.
use super::*;

fn funded(n: &mut Node) -> Hash {
    let first = append(n, root().id, vec![], 0);
    append(n, first, vec![], 0)
}
fn package(n: &Node) -> Vec<Vec<u8>> {
    let (_, ids) = n
        .source()
        .chain()
        .unwrap()
        .synchronization_inventory(&[root().id])
        .unwrap();
    let mut parent =
        monario_v6::transaction_id(&n.source().stored_block(ids[0]).unwrap().transactions[0])
            .unwrap();
    let mut out = Vec::new();
    for _ in 0..65 {
        let bytes = raw(0, Some((parent, 0)), 100);
        parent = monario_v6::transaction_id(&bytes).unwrap();
        out.push(bytes);
    }
    out
}

#[test]
fn real_v6_confirmation_and_reorg_rebuild_limits_without_rejecting_valid_blocks() {
    let _serial = REAL.lock().unwrap();
    let (_dir, mut n) = node();
    let base = funded(&mut n);
    let bytes = package(&n);
    for raw in &bytes[..64] {
        n.submit_transaction(raw.clone(), clock(0)).unwrap();
    }
    assert_eq!(
        n.submit_transaction(bytes[64].clone(), clock(0)),
        Err(Error::Transaction)
    );
    assert_eq!(n.mempool().len(), 64);
    append(&mut n, base, vec![bytes[0].clone()], 0);
    assert_eq!(n.mempool().len(), 63);
    n.submit_transaction(bytes[64].clone(), clock(0)).unwrap();
    assert_eq!(n.mempool().len(), 64);
    let side = append(&mut n, base, vec![], 0);
    let side = append(&mut n, side, vec![], 0);
    assert_eq!(n.source().chain().unwrap().tip(), side);
    assert_eq!(n.mempool().len(), 64);
    assert!(
        n.mempool()
            .known_transaction(n.source().chain().unwrap(), &bytes[64])
            .unwrap()
            .is_none()
    );
    assert_eq!(
        n.submit_transaction(bytes[64].clone(), clock(0)),
        Err(Error::Transaction)
    );
    // Admission policy is never a consensus limit on a fully valid block.
    let best = append(&mut n, side, bytes.clone(), 0);
    assert_eq!(n.source().chain().unwrap().tip(), best);
    assert!(n.mempool().is_empty());
    assert!(
        n.source()
            .chain()
            .unwrap()
            .ledger()
            .contains_transaction(&monario_v6::transaction_id(&bytes[64]).unwrap())
    );
}

#[test]
fn topology_crash_worker() {
    let Some(path) = std::env::var_os("MONAR_TOPOLOGY_CRASH_DB") else {
        return;
    };
    let mut n = open(std::path::Path::new(&path));
    let bytes = package(&n);
    for raw in &bytes[..64] {
        n.submit_transaction(raw.clone(), clock(0)).unwrap();
    }
    assert_eq!(
        n.submit_transaction(bytes[64].clone(), clock(0)),
        Err(Error::Transaction)
    );
    if std::env::var("MONAR_TOPOLOGY_CRASH_PHASE").unwrap() == "rejected" {
        std::process::exit(90);
    }
    let tip = n.source().chain().unwrap().tip();
    append(&mut n, tip, vec![bytes[0].clone()], 0);
    n.submit_transaction(bytes[64].clone(), clock(0)).unwrap();
    std::process::exit(91);
}

#[test]
fn abrupt_exit_discards_family_counts_and_fresh_admission_revalidates_after_committed_confirmation()
{
    let _serial = REAL.lock().unwrap();
    for (phase, code, height, skip) in [("rejected", 90, 2, 0), ("confirmed", 91, 3, 1)] {
        let (dir, mut n) = node();
        funded(&mut n);
        let bytes = package(&n);
        n.shutdown().unwrap();
        drop(n);
        let path = dir.path().join("node.sqlite");
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::topology::topology_crash_worker",
                "--nocapture",
            ])
            .env("MONAR_TOPOLOGY_CRASH_DB", &path)
            .env("MONAR_TOPOLOGY_CRASH_PHASE", phase)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(code));
        let mut n = open(&path);
        assert_eq!(n.source().chain().unwrap().height(), height);
        assert!(n.mempool().is_empty());
        assert_eq!(n.peer_count(), 0);
        let mut bad = bytes[skip].clone();
        bad[0] ^= 1;
        assert_eq!(n.submit_transaction(bad, clock(0)), Err(Error::Transaction));
        for raw in bytes.iter().skip(skip).take(64) {
            n.submit_transaction(raw.clone(), clock(0)).unwrap();
        }
        let next = if skip == 0 {
            bytes[64].clone()
        } else {
            raw(
                0,
                Some((monario_v6::transaction_id(&bytes[64]).unwrap(), 0)),
                100,
            )
        };
        assert_eq!(
            n.submit_transaction(next, clock(0)),
            Err(Error::Transaction)
        );
        assert_eq!(n.mempool().len(), 64);
    }
}
