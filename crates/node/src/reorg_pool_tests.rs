//! Reconcile real v6 bytes without sockets, nonce search or persistent validity receipts.
use super::*;

#[test]
fn restored_parent_preserves_pending_descendants_and_rejects_new_branch_conflicts() {
    let _serial = REAL.lock().unwrap();
    for conflict in [false, true] {
        let (_dir, mut n) = node();
        let (coin, fork) = funded(&mut n);
        let parent = raw(0, Some((coin, 0)), 90);
        append(&mut n, fork, vec![parent.clone()], 0);
        let child = raw(0, Some((id(&parent), 0)), 80);
        let grandchild = raw(0, Some((id(&child), 0)), 70);
        n.submit_transaction(child.clone(), clock(0)).unwrap();
        n.submit_transaction(grandchild.clone(), clock(0)).unwrap();
        let extra = if conflict {
            vec![raw(0, Some((coin, 0)), 85)]
        } else {
            vec![]
        };
        let side = append(&mut n, fork, extra, 1);
        let tip = append(&mut n, side, vec![], 2);
        assert_eq!(n.source().chain().unwrap().tip(), tip);
        let c = n.source().chain().unwrap();
        if conflict {
            assert!(n.pool.is_empty());
            assert!(n.submit_transaction(child, clock(3)).is_err());
        } else {
            assert_eq!(
                n.pool
                    .transactions(c)
                    .unwrap()
                    .map(<[u8]>::to_vec)
                    .collect::<Vec<_>>(),
                [parent, child, grandchild]
            );
            let selected = n.pool.select(c, 200).unwrap();
            assert_eq!(selected.transactions.len(), 3);
            assert_eq!(selected.fees.atoms(), 30);
            // Full block validation, not pool membership, authorizes effects.
            append(&mut n, tip, selected.transactions, 3);
            assert!(n.pool.is_empty());
        }
    }
}

#[test]
fn package_reorg_crash_worker() {
    let Some(path) = std::env::var_os("MONAR_PACKAGE_REORG_DB") else {
        return;
    };
    let mut n = open(std::path::Path::new(&path));
    let old = n.source().chain().unwrap().tip();
    let fork = n
        .source()
        .chain()
        .unwrap()
        .block_info(&old)
        .unwrap()
        .parent
        .unwrap();
    let parent = n.source().stored_block(old).unwrap().transactions[1].clone();
    let child = raw(0, Some((id(&parent), 0)), 80);
    let grandchild = raw(0, Some((id(&child), 0)), 70);
    n.submit_transaction(child, clock(0)).unwrap();
    n.submit_transaction(grandchild, clock(0)).unwrap();
    let side = append(&mut n, fork, vec![], 1);
    if std::env::var("MONAR_PACKAGE_REORG_PHASE").unwrap() == "after" {
        append(&mut n, side, vec![], 2);
        assert_eq!(n.pool.len(), 3);
    }
    std::process::exit(97);
}

#[test]
fn process_death_around_winning_reorg_retains_chain_but_no_package_receipts() {
    let _serial = REAL.lock().unwrap();
    for phase in ["before", "after"] {
        let (dir, mut n) = node();
        let (coin, fork) = funded(&mut n);
        let parent = raw(0, Some((coin, 0)), 90);
        append(&mut n, fork, vec![parent.clone()], 0);
        n.shutdown().unwrap();
        drop(n);
        let path = dir.path().join("node.sqlite");
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::parents::reorg_pool::package_reorg_crash_worker",
            ])
            .env("MONAR_PACKAGE_REORG_DB", &path)
            .env("MONAR_PACKAGE_REORG_PHASE", phase)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(97));
        let mut n = open(&path);
        assert_eq!(
            n.source().chain().unwrap().height(),
            if phase == "after" { 4 } else { 3 }
        );
        assert!(n.pool.is_empty());
        assert_eq!(n.peer_count(), 0);
        let child = raw(0, Some((id(&parent), 0)), 80);
        let grandchild = raw(0, Some((id(&child), 0)), 70);
        if !n
            .source()
            .chain()
            .unwrap()
            .ledger()
            .contains_transaction(&id(&parent))
        {
            assert!(n.submit_transaction(child.clone(), clock(0)).is_err());
            n.submit_transaction(parent.clone(), clock(0)).unwrap();
        }
        n.submit_transaction(child, clock(0)).unwrap();
        n.submit_transaction(grandchild, clock(0)).unwrap();
        let selected = n.pool.select(n.source().chain().unwrap(), 200).unwrap();
        let tip = n.source().chain().unwrap().tip();
        append(&mut n, tip, selected.transactions, 1);
        assert!(n.pool.is_empty());
    }
}
