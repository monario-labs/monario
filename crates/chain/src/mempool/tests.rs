#[path = "exact_payload_tests.rs"]
mod exact_payload;
#[path = "package_tests.rs"]
mod packages;
#[path = "reorg_tests.rs"]
mod reorg;
use super::*;
#[path = "topology_tests.rs"]
mod topology;
use crate::tests::{FixturePow, FixtureVerifier, block, cb, config, root, spend};
fn limits() -> Limits {
    Limits {
        transactions: 100,
        bytes: 100000,
        inputs: 100,
        minimum_fee: Amount::ZERO,
    }
}

fn selection_fixture() -> Chain<FixtureVerifier> {
    let mut c = Chain::new(config(), root(), FixtureVerifier::default()).unwrap();
    for h in 1..=3 {
        cb(&c, h, h, 100);
        let b = block(&c, c.tip(), 1000 + 45 * h as u32, &[h]);
        c.submit_checked(b, 2000, &mut FixturePow::default())
            .unwrap();
    }
    spend(&c, 10, &[1], &[99]); // Low-fee parent.
    spend(&c, 11, &[10], &[49]); // High-fee child, cannot precede parent.
    spend(&c, 12, &[2], &[80]);
    c
}
#[test]
fn selection_orders_package_fees_and_dependencies_without_mutating_pool_or_chain() {
    let c = selection_fixture();
    let mut pool = Mempool::new(&c, limits()).unwrap();
    for id in [10u64, 11, 12] {
        pool.admit(&c, id.to_le_bytes().to_vec()).unwrap();
    }
    let tip = c.tip();
    let out = pool.select(&c, 8).unwrap();
    assert_eq!(
        out.transactions,
        [10u64, 11, 12].map(|id| id.to_le_bytes().to_vec())
    );
    assert_eq!(out.fees.atoms(), 71);
    assert!(out.skipped.is_empty());
    assert_eq!(pool.len(), 3);
    assert_eq!(c.tip(), tip);
    let again = pool.select(&c, 8).unwrap();
    assert_eq!(out.ids, again.ids);
    // The selected bytes must still pass ordinary full template validation.
    c.build_template(tip, 1180, 2000, out.transactions, |p| {
        assert_eq!(p.fees.atoms(), 71);
        cb(&c, 20, 4, p.miner_maximum.atoms());
        Ok(20u64.to_le_bytes().to_vec())
    })
    .unwrap();
}
#[test]
fn selection_capacity_invalid_parent_and_stale_state_fail_safely() {
    let mut c = selection_fixture();
    spend(&c, 13, &[2], &[99]);
    let mut pool = Mempool::new(&c, limits()).unwrap();
    for id in [10u64, 11, 13] {
        pool.admit(&c, id.to_le_bytes().to_vec()).unwrap();
    }
    let out = pool.select(&c, 8).unwrap();
    assert_eq!(out.ids[0], pool.entries[0].id);
    assert!(
        out.ids
            .iter()
            .position(|id| *id == pool.entries[0].id)
            .unwrap()
            < out
                .ids
                .iter()
                .position(|id| *id == pool.entries[1].id)
                .unwrap()
    );
    c.config.limits.block_bytes = crate::header::HEADER_LEN + 8 + 8 + 1;
    // Profile changes require a fresh pool, never a trusted old admission.
    assert!(matches!(pool.select(&c, 8), Err(Error::Stale)));
    let mut pool = Mempool::new(&c, limits()).unwrap();
    for id in [10u64, 11] {
        pool.admit(&c, id.to_le_bytes().to_vec()).unwrap();
    }
    let out = pool.select(&c, 8).unwrap();
    assert_eq!(out.transactions.len(), 1);
    assert_eq!(out.skipped.len(), 1);
    assert!(matches!(pool.select(&c, 0), Err(Error::Configuration)));
    assert!(matches!(pool.select(&c, 10000), Err(Error::Capacity)));
    c.verifier.transactions.borrow_mut().remove(&10);
    let out = pool.select(&c, 8).unwrap();
    assert!(out.transactions.is_empty());
    assert_eq!(out.skipped.len(), 2);
    assert!(
        out.skipped
            .iter()
            .any(|(_, e)| matches!(e, Error::Invalid(_)))
    );
    assert!(
        out.skipped
            .iter()
            .any(|(_, e)| matches!(e, Error::Conflict | Error::Capacity))
    );
    assert_eq!(pool.len(), 2);
}
#[test]
fn service_collateral_claims_cannot_be_withdrawn_inside_pending_package() {
    use crate::service::{
        self,
        tests::{Model, operator, owner, raw},
    };
    let mut model = Model::new();
    let (collateral, fee) = model.prepare_collateral();
    let script =
        service::owner_script(&secp256k1::PublicKey::from_secret_key(&owner()).serialize());
    let record = service::registration_script(
        model.chain.config.chain_id,
        model.chain.root.id,
        collateral,
        &owner(),
        secp256k1::PublicKey::from_secret_key(&operator()).serialize(),
    )
    .unwrap();
    let reg = raw(
        0,
        &[fee],
        &[
            (3 * monario_monetary::ATOMS_PER_COIN, script.clone()),
            (0, record),
        ],
    );
    let withdrawal = raw(0, &[collateral], &[(service::COLLATERAL_ATOMS, script)]);
    let mut pool = Mempool::new(&model.chain, limits()).unwrap();
    let id = pool.admit(&model.chain, reg.clone()).unwrap();
    assert_eq!(pool.select(&model.chain, 256).unwrap().ids, vec![id]);
    assert!(pool.admit(&model.chain, withdrawal.clone()).is_err());
    assert_eq!(pool.len(), 1);
    pool.remove(&model.chain, id).unwrap();
    pool.admit(&model.chain, withdrawal).unwrap();
    assert!(pool.admit(&model.chain, reg).is_err());
    assert_eq!(pool.len(), 1);
}

#[test]
fn selection_accounts_for_compact_count_growth_and_exact_byte_budget() {
    let mut cfg = config();
    cfg.limits.transactions = 300;
    cfg.limits.block_bytes = crate::header::HEADER_LEN + 8 + 252 * 8 + 3;
    cfg.limits.transaction_bytes = cfg.limits.block_bytes;
    let mut c = Chain::new(cfg, root(), FixtureVerifier::default()).unwrap();
    for h in 1..=255 {
        cb(&c, h, h, 100);
        let b = block(&c, c.tip(), 1000 + 45 * h as u32, &[h]);
        c.submit_checked(b, 20000, &mut FixturePow::default())
            .unwrap();
    }
    let mut policy = limits();
    policy.transactions = 300;
    policy.inputs = 1000;
    let mut pool = Mempool::new(&c, policy).unwrap();
    for i in 1..=253 {
        spend(&c, 1000 + i, &[i], &[99]);
        pool.admit(&c, (1000 + i).to_le_bytes().to_vec()).unwrap();
    }
    assert_eq!(pool.select(&c, 8).unwrap().transactions.len(), 252);
    assert_eq!(pool.select(&c, 10).unwrap().transactions.len(), 251);
    assert_eq!(pool.len(), 253);
}
#[test]
fn conflicts_packages_removal_capacity_and_atomic_failure() {
    let mut c = Chain::new(config(), root(), FixtureVerifier::default()).unwrap();
    cb(&c, 1, 1, 100);
    let first = c
        .submit_checked(
            block(&c, root().id, 1045, &[1]),
            2000,
            &mut FixturePow::default(),
        )
        .unwrap()
        .id;
    cb(&c, 2, 2, 0);
    c.submit_checked(
        block(&c, first, 1090, &[2]),
        2000,
        &mut FixturePow::default(),
    )
    .unwrap();
    spend(&c, 3, &[1], &[90]);
    spend(&c, 4, &[3], &[80]);
    spend(&c, 5, &[1], &[70]);
    let mut pool = Mempool::new(&c, limits()).unwrap();
    let id = pool.admit(&c, 3u64.to_le_bytes().to_vec()).unwrap();
    assert_eq!(pool.fee(&c, id).unwrap().unwrap().atoms(), 10);
    pool.admit(&c, 4u64.to_le_bytes().to_vec()).unwrap();
    assert!(pool.admit(&c, 5u64.to_le_bytes().to_vec()).is_err());
    assert!(pool.admit(&c, 3u64.to_le_bytes().to_vec()).is_err());
    assert!(pool.admit(&c, vec![0; 10001]).is_err());
    assert_eq!(pool.len(), 2);
    assert_eq!(pool.transactions(&c).unwrap().count(), 2);
    let report = pool.remove(&c, id).unwrap();
    assert_eq!(report.retained, 0);
    assert_eq!(report.rejected.len(), 1);
    let mut policy = limits();
    policy.minimum_fee = Amount::from_atoms(11).unwrap();
    let mut pool = Mempool::new(&c, policy).unwrap();
    assert_eq!(pool.admit(&c, 3u64.to_le_bytes().to_vec()), Err(Error::Fee));
    assert!(pool.is_empty());
}
#[test]
fn tip_changes_require_revalidation_and_confirmed_parents_preserve_children() {
    let mut c = Chain::new(config(), root(), FixtureVerifier::default()).unwrap();
    cb(&c, 1, 1, 100);
    let first = c
        .submit_checked(
            block(&c, root().id, 1045, &[1]),
            2000,
            &mut FixturePow::default(),
        )
        .unwrap()
        .id;
    cb(&c, 2, 2, 0);
    let second = c
        .submit_checked(
            block(&c, first, 1090, &[2]),
            2000,
            &mut FixturePow::default(),
        )
        .unwrap()
        .id;
    spend(&c, 3, &[1], &[90]);
    spend(&c, 4, &[3], &[80]);
    cb(&c, 6, 3, 0);
    let mut pool = Mempool::new(&c, limits()).unwrap();
    pool.admit(&c, 3u64.to_le_bytes().to_vec()).unwrap();
    pool.admit(&c, 4u64.to_le_bytes().to_vec()).unwrap();
    c.submit_checked(
        block(&c, second, 1135, &[6, 3]),
        2000,
        &mut FixturePow::default(),
    )
    .unwrap();
    assert!(matches!(pool.transactions(&c), Err(Error::Stale)));
    assert_eq!(pool.rebuild(&c, Vec::new(), None).unwrap().retained, 1);
    assert_eq!(
        pool.transactions(&c).unwrap().next().unwrap(),
        4u64.to_le_bytes()
    );
}
