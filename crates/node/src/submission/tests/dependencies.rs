use super::*;
use crate::tests as nt;

fn setup() -> (tempfile::TempDir, Node, Inbox) {
    let dir = private_tempdir();
    let mut n = nt::open(&dir.path().join("node.sqlite"));
    let q = Inbox::create(dir.path(), "local", n.profile, key()).unwrap();
    attach(&mut n, dir.path());
    (dir, n, q)
}
fn attach(n: &mut Node, dir: &Path) {
    n.attach_submission_inbox(Inbox::open(dir, "local", n.profile, key()).unwrap())
        .unwrap();
}
fn package(n: &mut Node) -> (Vec<u8>, Vec<u8>) {
    let first = nt::append(n, nt::root().id, vec![], 0);
    nt::append(n, first, vec![], 0);
    let b = n.source().stored_block(first).unwrap();
    let tx = zcash_primitives::transaction::Transaction::read(
        b.transactions[0].as_slice(),
        zcash_protocol::consensus::BranchId::Nu6_3,
    )
    .unwrap();
    let coin = *tx.txid().as_ref();
    let parent = nt::raw(0, Some((coin, 0)), 90);
    let child = nt::raw(0, Some((txid(&parent), 0)), 80);
    (parent, child)
}
fn txid(raw: &[u8]) -> Hash {
    monario_v6::transaction_references(raw).unwrap().0
}
fn poll(n: &mut Node, ms: u64) {
    n.poll_submission(nt::clock(ms)).unwrap();
}

#[test]
fn child_before_parent_recovers_at_same_tip_without_republication() {
    let _serial = nt::REAL.lock().unwrap();
    let (_dir, mut n, mut q) = setup();
    let (parent, child) = package(&mut n);
    let tip = n.source().chain().unwrap().tip();
    let child_token = q.enqueue(&child).unwrap();
    let parent_token = q.enqueue(&parent).unwrap();
    n.tx_checks = n.limits.tx_checks_per_window;
    assert!(!n.poll_submission(nt::clock(0)).unwrap());
    assert_eq!(q.status(child_token).unwrap().unwrap().state, 0);
    n.tx_checks = 0;
    poll(&mut n, 0);
    assert_eq!(q.status(child_token).unwrap().unwrap().state, 2);
    poll(&mut n, 1000);
    assert_eq!(q.status(parent_token).unwrap().unwrap().state, 1);
    poll(&mut n, 2000);
    assert_eq!(q.status(child_token).unwrap().unwrap().state, 1);
    assert_eq!(n.source().chain().unwrap().tip(), tip);
    assert_eq!(n.pool.len(), 2);
    assert_eq!(n.tx_checks, 3);
    poll(&mut n, 3000);
    assert_eq!(n.tx_checks, 3);
    assert_eq!(q.enqueue(&child).unwrap(), child_token);
}

#[test]
fn cleanup_republication_discards_old_retry_generation() {
    let _serial = nt::REAL.lock().unwrap();
    let (_dir, mut n, mut q) = setup();
    package(&mut n);
    let raw = nt::raw(0, Some(([99; 32], 0)), 1);
    let token = q.enqueue(&raw).unwrap();
    poll(&mut n, 0);
    let old = *n
        .submission
        .as_ref()
        .unwrap()
        .missing
        .keys()
        .next()
        .unwrap();
    assert!(q.forget(token).unwrap());
    assert_eq!(q.enqueue(&raw).unwrap(), token);
    poll(&mut n, 1000);
    let missing = &n.submission.as_ref().unwrap().missing;
    assert_eq!(missing.len(), 1);
    let (new, count) = missing.iter().next().unwrap();
    assert!(new.0 > old.0);
    assert_eq!(new.1, old.1);
    assert_eq!(*count, 1);
}

#[test]
fn missing_retries_require_growth_and_remain_capped_even_with_busy_observation_writer() {
    let _serial = nt::REAL.lock().unwrap();
    for busy in [false, true] {
        let (_dir, mut n, mut q) = setup();
        let (mut previous, _) = package(&mut n);
        let missing = nt::raw(0, Some(([99; 32], 0)), 1);
        let token = q.enqueue(&missing).unwrap();
        if busy {
            q.db.execute_batch("BEGIN IMMEDIATE").unwrap();
        }
        poll(&mut n, 0);
        if !busy {
            poll(&mut n, 1000);
            assert_eq!(n.tx_checks, 1); // Passage of time alone earns no retry.
        }
        for i in 1..=9 {
            if !busy {
                n.submit_transaction(previous.clone(), nt::clock(i * 1000))
                    .unwrap();
                previous = nt::raw(0, Some((txid(&previous), 0)), 90 - i);
            }
            poll(&mut n, i * 1000);
        }
        let active = n.submission.as_ref().unwrap();
        assert_eq!(
            active.missing.values().copied().collect::<Vec<_>>(),
            vec![MISSING_ATTEMPTS]
        );
        if busy {
            assert_eq!(q.status(token).unwrap().unwrap().state, 0);
            q.db.execute_batch("ROLLBACK").unwrap();
            poll(&mut n, 10_000);
        } else {
            assert_eq!(n.tx_checks, u32::from(MISSING_ATTEMPTS));
        }
        assert_eq!(q.status(token).unwrap().unwrap().state, 2);
    }
}

#[test]
fn deferred_authorization_is_fully_verified_and_invalid_bytes_stop_retrying() {
    use zcash_primitives::transaction::{self, TransactionData};
    use zcash_protocol::consensus::BranchId;
    use zcash_transparent::{address::Script, bundle as tb};
    let _serial = nt::REAL.lock().unwrap();
    for busy in [false, true] {
        let (_dir, mut n, mut q) = setup();
        let (parent, child) = package(&mut n);
        let tx = transaction::Transaction::read(child.as_slice(), BranchId::Nu6_3).unwrap();
        let mut bundle = tx.transparent_bundle().unwrap().clone();
        bundle.vin[0] = tb::TxIn::from_parts(
            bundle.vin[0].prevout().clone(),
            Script(zcash_script::script::Code(vec![0x6a])),
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
        assert_eq!(txid(&bad), txid(&child));
        let token = q.enqueue(&bad).unwrap();
        q.enqueue(&parent).unwrap();
        poll(&mut n, 0);
        assert_eq!(n.submission.as_ref().unwrap().missing.len(), 1);
        poll(&mut n, 1000);
        if busy {
            q.db.execute_batch("BEGIN IMMEDIATE").unwrap();
        }
        poll(&mut n, 2000);
        assert_eq!(q.status(token).unwrap().unwrap().state, 2);
        assert_eq!(n.pool.len(), 1);
        let missing = &n.submission.as_ref().unwrap().missing;
        assert_eq!(missing.len(), 1);
        assert_eq!(*missing.values().next().unwrap(), MISSING_ATTEMPTS);
        let checks = n.tx_checks;
        n.submit_transaction(child, nt::clock(3000)).unwrap();
        poll(&mut n, 3000);
        assert_eq!(n.tx_checks, checks + u32::from(busy));
        assert_eq!(
            *n.submission
                .as_ref()
                .unwrap()
                .missing
                .values()
                .next()
                .unwrap(),
            MISSING_ATTEMPTS
        );
        if busy {
            q.db.execute_batch("ROLLBACK").unwrap();
            poll(&mut n, 4000);
        }
        let stored: Vec<u8> =
            q.db.query_row(
                "SELECT raw FROM requests WHERE token=?1",
                [token.as_slice()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(stored, bad);
    }
}

#[test]
fn new_branch_rechecks_exact_requests_and_never_trusts_old_admission_observations() {
    let _serial = nt::REAL.lock().unwrap();
    let (_dir, mut n, mut q) = setup();
    let (parent, child) = package(&mut n);
    let fork = n.source().chain().unwrap().tip();
    let coin = monario_v6::transaction_references(&parent).unwrap().1[0].transaction;
    let ct = q.enqueue(&child).unwrap();
    let pt = q.enqueue(&parent).unwrap();
    for ms in [0, 1000, 2000] {
        poll(&mut n, ms);
    }
    assert_eq!(q.status(ct).unwrap().unwrap().state, 1);
    nt::append(&mut n, fork, vec![parent, child], 2000);
    for ms in [3000, 4000] {
        poll(&mut n, ms);
    }
    assert!(n.pool.is_empty());
    let side = nt::append(&mut n, fork, vec![nt::raw(0, Some((coin, 0)), 85)], 4000);
    let tip = nt::append(&mut n, side, vec![], 4000);
    for ms in [5000, 6000] {
        poll(&mut n, ms);
    }
    for token in [ct, pt] {
        let status = q.status(token).unwrap().unwrap();
        assert_eq!(status.state, 2);
        assert_eq!(status.checked_tip, Some(tip));
    }
    assert!(n.pool.is_empty());
}

#[test]
fn dependency_crash_worker() {
    let Some(dir) = std::env::var_os("MONAR_INBOX_DEPENDENCY_DIR") else {
        return;
    };
    let dir = Path::new(&dir);
    let mut n = nt::open(&dir.join("node.sqlite"));
    attach(&mut n, dir);
    poll(&mut n, 0);
    assert!(n.pool.is_empty());
    if std::env::var("MONAR_INBOX_DEPENDENCY_PHASE").unwrap() == "after" {
        poll(&mut n, 1000);
        poll(&mut n, 2000);
        assert_eq!(n.pool.len(), 2);
    }
    std::process::exit(97);
}

#[test]
fn process_death_discards_retry_state_and_revalidates_retained_exact_bytes() {
    let _serial = nt::REAL.lock().unwrap();
    for phase in ["before", "after"] {
        let (dir, mut n, mut q) = setup();
        let (parent, child) = package(&mut n);
        let tip = n.source().chain().unwrap().tip();
        let token = q.enqueue(&child).unwrap();
        q.enqueue(&parent).unwrap();
        n.shutdown().unwrap();
        drop(n);
        drop(q);
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "submission::tests::dependencies::dependency_crash_worker",
            ])
            .env("MONAR_INBOX_DEPENDENCY_DIR", dir.path())
            .env("MONAR_INBOX_DEPENDENCY_PHASE", phase)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(97));
        let mut n = nt::open(&dir.path().join("node.sqlite"));
        attach(&mut n, dir.path());
        let q = Inbox::open(dir.path(), "local", n.profile, key()).unwrap();
        assert_eq!(
            q.status(token).unwrap().unwrap().state,
            if phase == "after" { 1 } else { 2 }
        );
        assert_eq!(n.source().chain().unwrap().tip(), tip);
        assert!(n.pool.is_empty());
        assert!(n.submission.as_ref().unwrap().missing.is_empty());
        poll(&mut n, 0);
        assert!(n.pool.is_empty());
        assert_eq!(q.status(token).unwrap().unwrap().state, 2);
        poll(&mut n, 1000);
        poll(&mut n, 2000);
        assert_eq!(n.pool.len(), 2);
        assert_eq!(q.status(token).unwrap().unwrap().state, 1);
        assert_eq!(n.tx_checks, 3);
    }
}
