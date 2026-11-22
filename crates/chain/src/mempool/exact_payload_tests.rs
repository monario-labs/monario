use super::*;

#[test]
fn exact_recognition_and_duplicate_admission_never_call_verifier_again() {
    let c = selection_fixture();
    let mut p = Mempool::new(&c, limits()).unwrap();
    let raw = 10u64.to_le_bytes().to_vec();
    let id = p.admit(&c, raw.clone()).unwrap();
    let calls = c.verifier.calls.get();
    for _ in 0..100 {
        assert_eq!(p.known_transaction(&c, &raw).unwrap(), Some(id));
        assert_eq!(p.admit(&c, raw.clone()), Err(Error::Conflict));
    }
    assert_eq!(c.verifier.calls.get(), calls);
    assert_eq!(p.len(), 1);
    assert_eq!(p.known_transaction(&c, &[]).unwrap(), None);
    assert_eq!(
        p.known_transaction(&c, &vec![0; limits().bytes + 1])
            .unwrap(),
        None
    );
    let changed = 11u64.to_le_bytes().to_vec();
    assert_eq!(p.known_transaction(&c, &changed).unwrap(), None);
    // Even a forced digest collision does not turn different bytes into a hit.
    let original = p.entries[0].payload;
    p.entries[0].payload = payload_digest(&changed);
    assert_eq!(p.known_transaction(&c, &changed).unwrap(), None);
    p.entries[0].payload = original;
    p.admit(&c, changed).unwrap();
    assert!(c.verifier.calls.get() > calls);
}

#[test]
fn full_capacity_still_recognizes_current_exact_bytes_without_admitting_again() {
    let c = selection_fixture();
    let mut policy = limits();
    policy.transactions = 1;
    policy.bytes = 8;
    let mut p = Mempool::new(&c, policy).unwrap();
    let raw = 10u64.to_le_bytes().to_vec();
    let id = p.admit(&c, raw.clone()).unwrap();
    let calls = c.verifier.calls.get();
    assert_eq!(p.known_transaction(&c, &raw).unwrap(), Some(id));
    assert_eq!(p.admit(&c, raw), Err(Error::Capacity));
    assert_eq!(c.verifier.calls.get(), calls);
}

#[test]
fn profile_tip_poison_and_removal_bound_recognition_to_current_revalidated_entries() {
    let mut c = selection_fixture();
    let mut p = Mempool::new(&c, limits()).unwrap();
    let parent = 10u64.to_le_bytes().to_vec();
    let child = 11u64.to_le_bytes().to_vec();
    let id = p.admit(&c, parent.clone()).unwrap();
    let child_id = p.admit(&c, child.clone()).unwrap();
    let script = c.config.limits.script_bytes;
    c.config.limits.script_bytes += 1;
    assert_eq!(p.known_transaction(&c, &parent), Err(Error::Stale));
    c.config.limits.script_bytes = script;
    p.poisoned = true;
    assert_eq!(p.known_transaction(&c, &parent), Err(Error::Stale));
    p.poisoned = false;
    cb(&c, 20, 4, 0);
    let b = block(&c, c.tip(), 1180, &[20, 10]);
    c.submit_checked(b, 2000, &mut FixturePow::default())
        .unwrap();
    assert_eq!(p.known_transaction(&c, &parent), Err(Error::Stale));
    let calls = c.verifier.calls.get();
    p.rebuild(&c, Vec::new(), None).unwrap();
    assert!(c.verifier.calls.get() > calls);
    assert_eq!(p.known_transaction(&c, &parent).unwrap(), None);
    assert_eq!(p.known_transaction(&c, &child).unwrap(), Some(child_id));
    assert!(c.ledger().contains_transaction(&id));
    p.remove(&c, child_id).unwrap();
    assert_eq!(p.known_transaction(&c, &child).unwrap(), None);
}
