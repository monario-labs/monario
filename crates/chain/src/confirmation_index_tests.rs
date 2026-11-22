//! Locator correctness, bounded work and atomicity; no PoW nonce search.
use super::*;

#[test]
fn locator_hints_and_malformed_skip_links_cannot_invent_confirmation() {
    let mut c = chain();
    let mut blocks = vec![root().id];
    for h in 1..=8 {
        cb(&c, h, h, 100);
        blocks.push(add(&mut c, blocks[h as usize - 1], 1000 + 45 * h as u32, &[h]).id);
    }
    for bad in [0, 2, 9, u64::MAX] {
        c.ledger.transactions.insert(tx_id(1), bad);
        assert_eq!(
            c.transaction_confirmation(&tx_id(1)),
            Err(Error::StateMismatch)
        );
    }
    c.ledger.transactions.insert(tx_id(1), 1);
    let saved = c.nodes[&blocks[8]].skip;
    for bad in [blocks[8], blocks[7], [99; 32]] {
        c.nodes.get_mut(&blocks[8]).unwrap().skip = Some(bad);
        assert_eq!(
            c.transaction_confirmation(&tx_id(1)),
            Err(Error::StateMismatch)
        );
    }
    c.nodes.get_mut(&blocks[8]).unwrap().skip = saved;
    cb(&c, 60, 6, 100);
    let orphan = add(&mut c, blocks[5], 1271, &[60]).id;
    let saved = c.nodes[&blocks[7]].skip;
    c.nodes.get_mut(&blocks[7]).unwrap().skip = Some(orphan);
    assert_eq!(
        c.transaction_confirmation(&tx_id(1)),
        Err(Error::StateMismatch)
    );
    c.nodes.get_mut(&blocks[7]).unwrap().skip = saved;
    assert_eq!(
        c.transaction_confirmation(&tx_id(1))
            .unwrap()
            .unwrap()
            .depth,
        8
    );
    assert!(c.transaction_confirmation(&tx_id(60)).unwrap().is_none());
}

#[test]
fn restoring_locators_requires_exact_active_membership_and_unique_inclusion() {
    for defect in 0..3 {
        let mut c = chain();
        cb(&c, 1, 1, 100);
        cb(&c, 2, 2, 100);
        let one = add(&mut c, root().id, 1045, &[1]).id;
        let two = add(&mut c, one, 1090, &[2]).id;
        match defect {
            0 => {
                c.ledger.transactions.remove(&tx_id(1));
            }
            1 => {
                c.ledger.transactions.insert([99; 32], 999);
            }
            _ => {
                c.nodes
                    .get_mut(&two)
                    .unwrap()
                    .delta
                    .as_mut()
                    .unwrap()
                    .transactions
                    .insert(tx_id(1), (false, true));
            }
        }
        assert_eq!(
            Chain::<FixtureVerifier>::rebuild_confirmation_heights(&c.ledger, &c.nodes, c.tip),
            Err(Error::StateMismatch)
        );
    }
    let mut c = chain();
    cb(&c, 1, 1, 100);
    let one = add(&mut c, root().id, 1045, &[1]).id;
    c.ledger.transactions.insert(tx_id(1), 999);
    assert_eq!(
        Chain::<FixtureVerifier>::rebuild_confirmation_heights(&c.ledger, &c.nodes, c.tip),
        Err(Error::StateMismatch)
    );
    c.ledger.transactions.insert(tx_id(1), 1);
    Chain::<FixtureVerifier>::rebuild_confirmation_heights(&c.ledger, &c.nodes, c.tip).unwrap();
    assert_eq!(
        c.transaction_confirmation(&tx_id(1)).unwrap(),
        Some(Confirmation {
            block: one,
            height: 1,
            depth: 1
        })
    );
}

#[test]
fn same_height_reinclusion_resolves_the_new_active_block() {
    let mut c = chain();
    for (id, h) in [
        (1, 1),
        (2, 2),
        (3, 3),
        (4, 4),
        (20, 2),
        (30, 3),
        (40, 4),
        (50, 5),
    ] {
        cb(&c, id, h, 100);
    }
    let one = add(&mut c, root().id, 1045, &[1]).id;
    let two = add(&mut c, one, 1090, &[2]).id;
    spend(&c, 10, &[1], &[90]);
    let old = add(&mut c, two, 1135, &[3, 10]).id;
    add(&mut c, old, 1180, &[4]);
    let side = add(&mut c, one, 1090, &[20]).id;
    let included = add(&mut c, side, 1135, &[30, 10]).id;
    let side = add(&mut c, included, 1180, &[40]).id;
    add(&mut c, side, 1225, &[50]);
    assert_ne!(old, included);
    assert_eq!(
        c.transaction_confirmation(&tx_id(10)).unwrap(),
        Some(Confirmation {
            block: included,
            height: 3,
            depth: 3
        })
    );
}

#[test]
fn failed_durable_record_leaves_locator_membership_and_positions_unchanged() {
    let mut c = chain();
    for (id, h) in [(1, 1), (2, 2), (3, 3), (4, 4), (30, 3), (40, 4), (50, 5)] {
        cb(&c, id, h, 100);
    }
    let one = add(&mut c, root().id, 1045, &[1]).id;
    let two = add(&mut c, one, 1090, &[2]).id;
    spend(&c, 10, &[1], &[90]);
    let old = add(&mut c, two, 1135, &[3, 10]).id;
    let tip = add(&mut c, old, 1180, &[4]).id;
    let side = add(&mut c, two, 1135, &[30]).id;
    let side = add(&mut c, side, 1180, &[40]).id;
    let saved = c.ledger.transactions.clone();
    let count = c.nodes.len();
    let candidate = block(&c, side, 1225, &[50, 10]);
    assert_eq!(
        c.submit_recorded(
            candidate,
            2000,
            &mut FixturePow::default(),
            |_, _, _, _, _| Err(Error::Storage)
        ),
        Err(Error::Storage)
    );
    assert_eq!(c.tip(), tip);
    assert_eq!(c.nodes.len(), count);
    assert_eq!(c.ledger.transactions, saved);
    assert_eq!(
        c.transaction_confirmation(&tx_id(10))
            .unwrap()
            .unwrap()
            .height,
        3
    );
    add(&mut c, side, 1225, &[50, 10]);
    assert_eq!(
        c.transaction_confirmation(&tx_id(10))
            .unwrap()
            .unwrap()
            .height,
        5
    );
}
