//! Opt-in finality enforcement tests. Synthetic fixtures only; no real mining.
use super::finality::{Mode, Pin, Policy};
use super::tests::{FixturePow, FixtureVerifier, block, cb, config, root};
use super::*;

fn chain() -> Chain<FixtureVerifier> {
    Chain::new(config(), root(), FixtureVerifier::default()).unwrap()
}

fn build(c: &mut Chain<FixtureVerifier>, height: u64, tx: u64) -> Hash {
    cb(c, tx, height, 0);
    let b = block(
        c,
        c.tip(),
        1000 + 45 * u32::try_from(height).unwrap(),
        &[tx],
    );
    c.submit_checked(b, 2_000_000, &mut FixturePow::default())
        .unwrap()
        .id
}

/// Canonical branch of `canonical` blocks, returning ids indexed by height.
fn canonical(c: &mut Chain<FixtureVerifier>, height: u64) -> Vec<Hash> {
    let mut ids = vec![root().id];
    for h in 1..=height {
        ids.push(build(c, h, h));
    }
    ids
}

/// Submit a competing branch that forks at `fork_at` with different transactions.
/// Returns `true` if a finality refusal stopped it.
fn compete(c: &mut Chain<FixtureVerifier>, ids: &[Hash], fork_at: u64, fork_to: u64) -> bool {
    let mut parent = ids[usize::try_from(fork_at).unwrap()];
    for h in (fork_at + 1)..=fork_to {
        cb(c, 100_000 + h, h, 0);
        let b = block(
            c,
            parent,
            1000 + 45 * u32::try_from(h).unwrap(),
            &[100_000 + h],
        );
        match c.submit_checked(b, 2_000_000, &mut FixturePow::default()) {
            Ok(accepted) => parent = accepted.id,
            Err(Error::Finality) => return true,
            Err(other) => panic!("unexpected competing-branch error: {other:?}"),
        }
    }
    false
}

#[test]
fn anchor_refuses_a_heavier_branch_that_drops_it() {
    let mut c = chain();
    let ids = canonical(&mut c, 20);
    let canonical_tip = c.tip();
    c.finality = Some(Policy {
        anchor: Some(Pin {
            height: 10,
            hash: ids[10],
        }),
        pin: None,
        mode: Mode::Refuse,
        anchor_bypass: false,
    });
    assert!(compete(&mut c, &ids, 9, 24));
    assert_eq!(c.tip(), canonical_tip);
    assert!(!c.finality_warning());
}

#[test]
fn bypass_allows_the_same_heavier_branch() {
    let mut c = chain();
    let ids = canonical(&mut c, 20);
    c.finality = Some(Policy {
        anchor: Some(Pin {
            height: 10,
            hash: ids[10],
        }),
        pin: None,
        mode: Mode::Refuse,
        anchor_bypass: true,
    });
    assert!(!compete(&mut c, &ids, 9, 24));
    assert_ne!(c.tip(), ids[20]);
    assert!(!c.finality_warning());
}

#[test]
fn warn_pin_records_conflict_and_allows_the_heavier_branch() {
    let mut c = chain();
    let ids = canonical(&mut c, 20);
    c.finality = Some(Policy {
        anchor: None,
        pin: Some(Pin {
            height: 10,
            hash: ids[10],
        }),
        mode: Mode::Warn,
        anchor_bypass: false,
    });
    assert!(!compete(&mut c, &ids, 9, 24));
    assert_ne!(c.tip(), ids[20]);
    assert!(c.finality_warning());
}

#[test]
fn refuse_pin_rejects_a_heavier_branch() {
    let mut c = chain();
    let ids = canonical(&mut c, 20);
    let canonical_tip = c.tip();
    c.finality = Some(Policy {
        anchor: None,
        pin: Some(Pin {
            height: 10,
            hash: ids[10],
        }),
        mode: Mode::Refuse,
        anchor_bypass: false,
    });
    assert!(compete(&mut c, &ids, 9, 24));
    assert_eq!(c.tip(), canonical_tip);
}

#[test]
fn set_finality_fails_closed_for_shallow_or_unknown_pins() {
    let mut c = chain();
    let ids = canonical(&mut c, 1001);
    assert!(
        c.set_finality(Policy {
            anchor: None,
            pin: Some(Pin {
                height: 1,
                hash: ids[1],
            }),
            mode: Mode::Refuse,
            anchor_bypass: false,
        })
        .is_ok()
    );
    assert!(!c.finality_warning());
    c.clear_finality();
    assert!(
        c.set_finality(Policy {
            anchor: None,
            pin: Some(Pin {
                height: 1000,
                hash: ids[1000],
            }),
            mode: Mode::Refuse,
            anchor_bypass: false,
        })
        .is_err()
    );
    assert!(
        c.set_finality(Policy {
            anchor: None,
            pin: Some(Pin {
                height: 1,
                hash: [0; 32],
            }),
            mode: Mode::Refuse,
            anchor_bypass: false,
        })
        .is_err()
    );
}
