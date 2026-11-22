//! Test-only transaction/PoW fixtures; no nonce search or network activity.
use super::*;
use crate::{
    service,
    service::tests::{candidate, owner, qualified_model, raw},
    tests::{FixturePow, FixtureVerifier, block, cb, cb_with_fees, config, root, spend},
};
use std::cell::Cell;

#[test]
fn transparent_dependencies_fees_branch_state_and_callback_validation() {
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
    let txs = vec![3u64.to_le_bytes().to_vec(), 4u64.to_le_bytes().to_vec()];
    let before = c.ledger().supply();
    let template = c
        .build_template(second, 1135, 2000, txs.clone(), |plan| {
            assert_eq!(plan.fees.atoms(), 20);
            assert_eq!(
                plan.miner_maximum,
                monario_monetary::subsidy(3).checked_add(plan.fees).unwrap()
            );
            cb_with_fees(&c, 5, 3, plan.miner_maximum.atoms(), plan.fees.atoms());
            Ok(5u64.to_le_bytes().to_vec())
        })
        .unwrap();
    assert_eq!(c.tip(), second);
    assert_eq!(c.ledger().supply(), before);
    assert_eq!(template.block.header.nonce, [0; 32]);
    assert_eq!(template.pow_seed, c.seed_for(second, 3).unwrap());
    let expected = block(&c, second, 1135, &[5, 3, 4]);
    assert_eq!(template.block.header, expected.header);
    let tip = c
        .submit_checked(template.block, 2000, &mut FixturePow::default())
        .unwrap()
        .id;
    assert!(
        c.build_template(tip, 1180, 2000, txs.clone(), |_| unreachable!())
            .is_err()
    );
    // The confirmed spend on the active branch must not leak into a side template.
    cb(&c, 6, 3, 0);
    let side = c
        .build_template(second, 1136, 2000, txs, |_| Ok(6u64.to_le_bytes().to_vec()))
        .unwrap();
    assert_eq!(side.coinbase.fees.atoms(), 20);
    assert_eq!(c.tip(), tip);
    cb(&c, 7, 4, monario_monetary::subsidy(4).atoms() + 1);
    assert!(matches!(
        c.build_template(tip, 1180, 2000, vec![], |_| Ok(7u64.to_le_bytes().to_vec())),
        Err(Error::OverclaimedReward)
    ));
    assert!(matches!(
        c.build_template(tip, 1180, 2000, vec![], |_| Ok(6u64.to_le_bytes().to_vec())),
        Err(Error::Coinbase)
    ));
    assert_eq!(c.tip(), tip);
}

#[test]
fn malformed_context_and_resource_bounds_precede_coinbase_callback() {
    let c = Chain::new(config(), root(), FixtureVerifier::default()).unwrap();
    let called = Cell::new(false);
    for (parent, time, txs) in [
        ([9; 32], 1045, vec![]),
        (root().id, 1000, vec![]),
        (root().id, 3000, vec![]),
        (root().id, 1045, vec![vec![]]),
        (root().id, 1045, vec![vec![0; 10001]]),
        (root().id, 1045, vec![vec![0; 8]; 100]),
        (root().id, 1045, vec![vec![0; 8]]),
    ] {
        assert!(
            c.build_template(parent, time, 2000, txs, |_| {
                called.set(true);
                Ok(vec![])
            })
            .is_err()
        );
        assert!(!called.get());
    }
    assert!(matches!(
        c.build_template(root().id, 1045, 2000, vec![], |_| Ok(vec![0; 10001])),
        Err(Error::ResourceLimit)
    ));
    assert!(matches!(
        c.build_template(root().id, 1045, 2000, vec![], |_| Err(Error::Coinbase)),
        Err(Error::Coinbase)
    ));
    assert_eq!(c.height(), 0);
    for cap in [152, 153] {
        let mut limits = config();
        limits.limits.block_bytes = cap;
        limits.limits.transaction_bytes = cap;
        limits.limits.script_bytes = cap;
        let c = Chain::new(limits.clone(), root(), FixtureVerifier::default()).unwrap();
        cb(&c, 1, 1, 0);
        let result = c.build_template(root().id, 1045, 2000, vec![], |_| {
            Ok(1u64.to_le_bytes().to_vec())
        });
        if cap == 152 {
            assert!(matches!(result, Err(Error::ResourceLimit)));
        } else {
            assert_eq!(
                crate::wire::encode(&result.unwrap().block, &limits.limits, &c.verifier)
                    .unwrap()
                    .len(),
                cap
            );
        }
    }
}

#[test]
fn service_registration_does_not_divert_coinbase_from_miners() {
    let (mut m, id, collateral, fee) = qualified_model();
    let tip = m.chain.tip();
    let height = m.chain.height() + 1;
    let timestamp = candidate(&m.chain, tip, &[]).header.timestamp;
    let before = m.chain.ledger().service_entry(&id).unwrap().clone();
    let value = m.chain.ledger().coin(&fee).unwrap().value.atoms();
    let spend = raw(0, &[fee], &[(value - 39, vec![0x51])]);
    let template = m
        .chain
        .build_template(tip, timestamp, 2_000_000, vec![spend], |p| {
            assert_eq!(p.fees.atoms(), 39);
            assert_eq!(
                p.miner_maximum.atoms(),
                monario_monetary::subsidy(height).atoms() + 39
            );
            Ok(raw(height, &[], &[(p.miner_maximum.atoms(), vec![0x51])]))
        })
        .unwrap();
    assert_eq!(m.chain.ledger().service_entry(&id), Some(&before));
    let paid = m
        .chain
        .submit_checked(template.block, 2_000_000, &mut FixturePow::default())
        .unwrap()
        .id;
    assert_eq!(m.chain.ledger().service_entry(&id), Some(&before));
    let withdrawal = raw(
        0,
        &[collateral],
        &[(
            service::COLLATERAL_ATOMS,
            service::owner_script(&secp256k1::PublicKey::from_secret_key(&owner()).serialize()),
        )],
    );
    let timestamp = candidate(&m.chain, paid, &[]).header.timestamp;
    let template = m
        .chain
        .build_template(paid, timestamp, 2_000_000, vec![withdrawal], |p| {
            Ok(raw(p.height, &[], &[(p.miner_maximum.atoms(), vec![0x51])]))
        })
        .unwrap();
    m.chain
        .submit_checked(template.block, 2_000_000, &mut FixturePow::default())
        .unwrap();
    assert!(m.chain.ledger().service_entry(&id).is_none());
}
