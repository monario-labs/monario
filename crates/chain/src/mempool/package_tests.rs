use super::*;

#[test]
fn high_fee_child_pulls_its_parent_ahead_of_lower_value_independent_work() {
    let mut c = selection_fixture();
    c.config.limits.transactions = 3; // Coinbase plus two selected transactions.
    let mut p = Mempool::new(&c, limits()).unwrap();
    for id in [10u64, 11, 12] {
        p.admit(&c, id.to_le_bytes().to_vec()).unwrap();
    }
    let out = p.select(&c, 8).unwrap();
    assert_eq!(
        out.transactions,
        [10u64, 11].map(|n| n.to_le_bytes().to_vec())
    );
    assert_eq!(out.fees.atoms(), 51);
    assert_eq!(p.len(), 3);
}

#[test]
fn shared_ancestor_fees_are_removed_from_remaining_package_scores() {
    let mut c = selection_fixture();
    c.config.limits.transactions = 3;
    spend(&c, 10, &[1], &[50]);
    spend(&c, 11, &[10], &[49]);
    let mut p = Mempool::new(&c, limits()).unwrap();
    for id in [10u64, 11, 12] {
        p.admit(&c, id.to_le_bytes().to_vec()).unwrap();
    }
    let out = p.select(&c, 8).unwrap();
    assert_eq!(
        out.transactions,
        [10u64, 12].map(|n| n.to_le_bytes().to_vec())
    );
    assert_eq!(out.fees.atoms(), 70);
}

#[test]
fn failed_child_rolls_back_package_before_competing_work_is_selected() {
    let mut c = selection_fixture();
    c.config.limits.transactions = 3;
    let mut p = Mempool::new(&c, limits()).unwrap();
    for id in [10u64, 11, 12] {
        p.admit(&c, id.to_le_bytes().to_vec()).unwrap();
    }
    c.verifier.transactions.borrow_mut().remove(&11);
    let out = p.select(&c, 8).unwrap();
    assert_eq!(
        out.transactions,
        [12u64, 10].map(|n| n.to_le_bytes().to_vec())
    );
    assert!(
        out.skipped
            .iter()
            .any(|(_, e)| matches!(e, Error::Invalid(_)))
    );
    assert_eq!(out.fees.atoms(), 21);
    assert_eq!(p.len(), 3);
}

#[test]
fn multi_parent_packages_deduplicate_ancestors_and_equal_rates_use_id_order() {
    let mut c = selection_fixture();
    c.config.limits.transactions = 4;
    cb(&c, 20, 4, 0);
    let b = block(&c, c.tip(), 1180, &[20]);
    c.submit_checked(b, 2000, &mut FixturePow::default())
        .unwrap();
    spend(&c, 13, &[10, 12], &[1]);
    spend(&c, 14, &[3], &[50]);
    let mut p = Mempool::new(&c, limits()).unwrap();
    for id in [10u64, 12, 13, 14] {
        p.admit(&c, id.to_le_bytes().to_vec()).unwrap();
    }
    let out = p.select(&c, 8).unwrap();
    assert_eq!(
        out.transactions,
        [10u64, 12, 13].map(|n| n.to_le_bytes().to_vec())
    );
    assert_eq!(out.fees.atoms(), 199);
    let c = selection_fixture();
    spend(&c, 13, &[2], &[99]);
    let mut p = Mempool::new(&c, limits()).unwrap();
    for id in [10u64, 13] {
        p.admit(&c, id.to_le_bytes().to_vec()).unwrap();
    }
    let mut ids: Vec<_> = p.entries.iter().map(|e| e.id).collect();
    ids.sort();
    assert_eq!(p.select(&c, 8).unwrap().ids, ids);
}

#[test]
fn diamond_dependency_counts_shared_parent_once_in_bytes_fees_and_verification() {
    let mut c = selection_fixture();
    c.config.limits.transactions = 5;
    spend(&c, 10, &[1], &[49, 49]);
    spend(&c, 11, &[10], &[48]);
    spend(&c, 12, &[10], &[48]);
    c.verifier
        .transactions
        .borrow_mut()
        .get_mut(&12)
        .unwrap()
        .inputs[0]
        .index = 1;
    spend(&c, 13, &[11, 12], &[1]);
    spend(&c, 14, &[2], &[80]);
    let mut p = Mempool::new(&c, limits()).unwrap();
    for id in [10u64, 11, 12, 13, 14] {
        p.admit(&c, id.to_le_bytes().to_vec()).unwrap();
    }
    let calls = c.verifier.calls.get();
    let out = p.select(&c, 8).unwrap();
    assert_eq!(
        out.transactions,
        [10u64, 11, 12, 13].map(|n| n.to_le_bytes().to_vec())
    );
    assert_eq!(out.fees.atoms(), 99);
    assert_eq!(c.verifier.calls.get() - calls, 4);
}

#[test]
fn long_dependency_chains_keep_individual_fallback_without_extra_verification() {
    let c = selection_fixture();
    let mut p = Mempool::new(&c, limits()).unwrap();
    for i in 0..30 {
        spend(&c, 1000 + i, &[if i == 0 { 1 } else { 999 + i }], &[99 - i]);
        p.admit(&c, (1000u64 + i).to_le_bytes().to_vec()).unwrap();
    }
    let calls = c.verifier.calls.get();
    let out = p.select(&c, 8).unwrap();
    assert_eq!(
        out.transactions,
        (1000u64..1030)
            .map(|n| n.to_le_bytes().to_vec())
            .collect::<Vec<_>>()
    );
    assert_eq!(c.verifier.calls.get() - calls, 30);
    assert!(out.skipped.is_empty());
}

#[test]
fn adversarial_failed_packages_stop_at_linear_verification_budget_without_partial_effects() {
    let c = selection_fixture();
    let mut p = Mempool::new(&c, limits()).unwrap();
    for i in 0..24 {
        let outputs = if i == 23 { vec![10; 6] } else { vec![99 - i] };
        spend(&c, 1000 + i, &[if i == 0 { 1 } else { 999 + i }], &outputs);
        p.admit(&c, (1000u64 + i).to_le_bytes().to_vec()).unwrap();
    }
    for i in 0..6 {
        spend(&c, 2000 + i, &[1023], &[0]);
        c.verifier
            .transactions
            .borrow_mut()
            .get_mut(&(2000 + i))
            .unwrap()
            .inputs[0]
            .index = i as u32;
        p.admit(&c, (2000u64 + i).to_le_bytes().to_vec()).unwrap();
    }
    for i in 0..6 {
        c.verifier.transactions.borrow_mut().remove(&(2000 + i));
    }
    let calls = c.verifier.calls.get();
    let supply = c.ledger().supply();
    let out = p.select(&c, 8).unwrap();
    assert_eq!(c.verifier.calls.get() - calls, 2 * p.len());
    assert!(out.transactions.is_empty());
    assert_eq!(out.fees, Amount::ZERO);
    assert!(
        out.skipped
            .iter()
            .any(|(_, e)| matches!(e, Error::Capacity))
    );
    assert_eq!(c.ledger().supply(), supply);
    assert_eq!(p.len(), 30);
}
