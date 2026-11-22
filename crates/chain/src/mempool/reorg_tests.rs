use super::*;

fn detached_parent(conflict: bool) -> (Chain<FixtureVerifier>, Mempool) {
    let mut c = selection_fixture();
    let fork = c.tip();
    cb(&c, 20, 4, 0);
    let b = block(&c, fork, 1180, &[20, 10]);
    c.submit_checked(b, 2000, &mut FixturePow::default())
        .unwrap();
    spend(&c, 13, &[11], &[39]);
    let mut p = Mempool::new(&c, limits()).unwrap();
    for id in [11u64, 13] {
        p.admit(&c, id.to_le_bytes().to_vec()).unwrap();
    }
    cb(&c, 21, 4, 0);
    spend(&c, 14, &[1], &[70]);
    let ids = if conflict { vec![21, 14] } else { vec![21] };
    let side = block(&c, fork, 1180, &ids);
    let side = c
        .submit_checked(side, 2000, &mut FixturePow::default())
        .unwrap()
        .id;
    cb(&c, 22, 5, 0);
    let b = block(&c, side, 1225, &[22]);
    c.submit_checked(b, 2000, &mut FixturePow::default())
        .unwrap();
    (c, p)
}

#[test]
fn detached_parents_restore_pending_descendants_with_only_one_retry_pass() {
    let (c, mut p) = detached_parent(false);
    let calls = c.verifier.calls.get();
    let report = p
        .rebuild(&c, vec![10u64.to_le_bytes().to_vec()], None)
        .unwrap();
    assert_eq!(report.retained, 3);
    assert!(report.rejected.is_empty());
    assert_eq!(c.verifier.calls.get() - calls, 5);
    assert_eq!(
        p.transactions(&c)
            .unwrap()
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>(),
        [10u64, 11, 13].map(|id| id.to_le_bytes().to_vec())
    );
    assert_eq!(p.select(&c, 8).unwrap().transactions.len(), 3);
}

#[test]
fn winning_branch_conflicts_cannot_be_resurrected_or_retry_forever() {
    let (c, mut p) = detached_parent(true);
    let calls = c.verifier.calls.get();
    let report = p
        .rebuild(&c, vec![10u64.to_le_bytes().to_vec()], None)
        .unwrap();
    assert_eq!(report.retained, 0);
    assert_eq!(report.rejected.len(), 3);
    assert_eq!(c.verifier.calls.get() - calls, 5);
    assert!(p.is_empty());
}

#[test]
fn invalid_existing_bytes_never_gain_validity_from_parent_resurrection() {
    let (c, mut p) = detached_parent(false);
    c.verifier.transactions.borrow_mut().remove(&11);
    let calls = c.verifier.calls.get();
    let report = p
        .rebuild(&c, vec![10u64.to_le_bytes().to_vec()], None)
        .unwrap();
    assert_eq!(report.retained, 1);
    assert_eq!(report.rejected.len(), 2);
    assert_eq!(c.verifier.calls.get() - calls, 4);
    assert_eq!(
        p.transactions(&c).unwrap().next().unwrap(),
        10u64.to_le_bytes()
    );
}
