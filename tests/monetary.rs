//! Independent monetary boundary and arithmetic property checks.

use monario_monetary::{
    ATOMS_PER_COIN, Amount, AmountError, EMISSION_CURVE_BONUS_ATOMS, EMISSION_CURVE_SEGMENTS,
    EMISSION_ROUNDING_BLOCKS, INITIAL_SUBSIDY_ATOMS, MAIN_EMISSION_ATOMS, MAIN_EMISSION_BLOCKS,
    TAIL_EMISSION_ATOMS, TARGET_BLOCK_SECONDS, cumulative_subsidy, subsidy,
};

#[test]
fn approved_parameters() {
    assert_eq!(TARGET_BLOCK_SECONDS, 90);
    assert_eq!(ATOMS_PER_COIN, 100_000_000);
    assert_eq!(INITIAL_SUBSIDY_ATOMS, 770_000_000);
    // 15 years of 90-second blocks: 365 * 960 * 15 = 5,256,000.
    assert_eq!(MAIN_EMISSION_BLOCKS, 5_256_000);
    assert_eq!(15 * 365 * 960, MAIN_EMISSION_BLOCKS);
    assert_eq!(TAIL_EMISSION_ATOMS, 20_000_000);
    assert_eq!(MAIN_EMISSION_ATOMS, 2_100_000_000_000_000);
    assert_eq!(EMISSION_CURVE_SEGMENTS, 16);
    assert_eq!(EMISSION_CURVE_BONUS_ATOMS, 6_841_796);
    assert_eq!(EMISSION_ROUNDING_BLOCKS, 516_988);
}

#[test]
fn amounts_span_the_atomic_range_with_overflow_checks() {
    let max = Amount::from_atoms(u64::MAX).unwrap();
    let one = Amount::from_atoms(1).unwrap();
    assert_eq!(max.atoms(), u64::MAX);
    assert_eq!(max.checked_add(one), Err(AmountError::OutOfRange));
    assert_eq!(Amount::ZERO.checked_sub(one), Err(AmountError::Underflow));
    assert_eq!(max.checked_sub(max), Ok(Amount::ZERO));
    assert_eq!(one.checked_add(Amount::ZERO), Ok(one));
}

#[test]
fn decimal_conversion_is_exact() {
    for (input, atoms, displayed) in [
        ("0", 0, "0.00000000"),
        ("0.00000001", 1, "0.00000001"),
        ("7.7", 770_000_000, "7.70000000"),
        ("21000000", 2_100_000_000_000_000, "21000000.00000000"),
        ("184467440737.09551615", u64::MAX, "184467440737.09551615"),
    ] {
        let amount: Amount = input.parse().unwrap();
        assert_eq!(amount.atoms(), atoms);
        assert_eq!(amount.to_string(), displayed);
        assert_eq!(displayed.parse::<Amount>(), Ok(amount));
    }
    for input in [
        "",
        " 1",
        "1 ",
        "+1",
        "-1",
        "1e2",
        "NaN",
        "1.",
        ".1",
        "01",
        "00.1",
        "1.000000000",
        "1.2.3",
        "１",
        "1\n",
        "184467440737.09551616",
        "999999999999999999999999999999",
    ] {
        assert!(input.parse::<Amount>().is_err(), "accepted {input:?}");
    }
}

#[test]
fn curved_schedule_is_monotonic_and_reaches_the_perpetual_tail() {
    const N: u64 = MAIN_EMISSION_BLOCKS;
    assert_eq!(subsidy(0), Amount::ZERO);
    assert_eq!(subsidy(1).atoms(), INITIAL_SUBSIDY_ATOMS);
    assert_eq!(subsidy(2).atoms(), 769_999_864);
    assert_eq!(subsidy(3).atoms(), 769_999_726);
    assert_eq!(subsidy(N / 4).atoms(), 587_631_452);
    assert_eq!(subsidy(N / 2).atoms(), 401_841_866);
    assert_eq!(subsidy(3 * N / 4).atoms(), 212_631_382);
    assert_eq!(subsidy(N - 2).atoms(), 20_000_296);
    assert_eq!(subsidy(N - 1).atoms(), 20_000_148);
    for height in [N, N + 1, N * 2, u64::MAX] {
        assert_eq!(subsidy(height).atoms(), TAIL_EMISSION_ATOMS);
    }

    // No increase or abrupt drop is possible within the calibrated schedule.
    let mut previous = subsidy(1).atoms();
    let mut largest_drop = 0;
    for height in 2..=N {
        let reward = subsidy(height).atoms();
        assert!(reward <= previous, "reward rose at height {height}");
        let drop = previous - reward;
        assert!(drop <= 148, "drop too steep at height {height}");
        largest_drop = largest_drop.max(drop);
        previous = reward;
    }
    assert_eq!(largest_drop, 148);
    assert_eq!(previous, TAIL_EMISSION_ATOMS);
}

#[test]
fn main_emission_and_tail_decade_match_the_chosen_model() {
    // The curved schedule's one-atom distributed correction makes the main-era
    // total exact, without assigning the rounding residue to a special block.
    let issued = cumulative_subsidy(MAIN_EMISSION_BLOCKS);
    assert_eq!(issued, MAIN_EMISSION_ATOMS);
    assert_eq!(issued / u128::from(ATOMS_PER_COIN), 21_000_000);

    // 0.2 MONAR across ten years of 90-second blocks.
    let decade_blocks: u64 = 10 * 365 * 960;
    assert_eq!(
        u128::from(TAIL_EMISSION_ATOMS) * u128::from(decade_blocks),
        70_080_000_000_000
    );
    assert_eq!(
        u128::from(TAIL_EMISSION_ATOMS) * u128::from(decade_blocks) / u128::from(ATOMS_PER_COIN),
        700_800
    );
}

#[test]
fn cumulative_issuance_matches_independent_accumulator() {
    const N: u64 = MAIN_EMISSION_BLOCKS;
    assert_eq!(cumulative_subsidy(0), 0);
    assert_eq!(cumulative_subsidy(1), u128::from(INITIAL_SUBSIDY_ATOMS));

    let mut expected: u128 = 0;
    for height in 1..=N {
        expected += u128::from(subsidy(height).atoms());
        if [1, 2, 3, 1_000_000, 2_628_000, N - 1, N].contains(&height) {
            assert_eq!(cumulative_subsidy(height), expected, "height {height}");
        }
    }
    assert_eq!(cumulative_subsidy(N), expected);

    // The tail adds exactly 0.2 MONAR per block and never stops.
    for extra in [1_u64, 2, 10, 3_504_000, u64::MAX - N] {
        let height = N + extra;
        assert_eq!(
            cumulative_subsidy(height),
            expected + u128::from(extra) * u128::from(TAIL_EMISSION_ATOMS)
        );
    }
    assert_eq!(
        cumulative_subsidy(N + 1),
        MAIN_EMISSION_ATOMS + u128::from(TAIL_EMISSION_ATOMS)
    );
    assert!(cumulative_subsidy(u64::MAX) > cumulative_subsidy(42_000_000));

    // Every sampled increment is exactly the per-block subsidy.
    for height in [1, 2, 3, N / 2, N - 1, N, N + 1, N + 10, 42_000_000] {
        assert_eq!(
            cumulative_subsidy(height) - cumulative_subsidy(height - 1),
            u128::from(subsidy(height).atoms()),
            "height {height}"
        );
    }
}

#[test]
fn deterministic_amount_properties() {
    const BOUND: u64 = 1 << 62;
    // Fixed public arithmetic samples, never used as randomness or identifiers.
    for i in 0..10_000_u64 {
        let atoms = (i * 209_999_999_983) % (BOUND + 1);
        let amount = Amount::from_atoms(atoms).unwrap();
        assert_eq!(amount.to_string().parse::<Amount>(), Ok(amount));
        let complement = Amount::from_atoms(BOUND - atoms).unwrap();
        assert_eq!(amount.checked_add(complement).unwrap().atoms(), BOUND);
        assert_eq!(
            amount
                .checked_add(complement)
                .unwrap()
                .checked_sub(complement),
            Ok(amount)
        );
    }
}

#[test]
fn transaction_value_bound_is_not_a_supply_cap() {
    let later = MAIN_EMISSION_BLOCKS + 1_000_000;
    assert!(cumulative_subsidy(later) > u128::from(monario_monetary::MAX_TRANSACTION_VALUE_ATOMS));
    assert_eq!(subsidy(later).atoms(), TAIL_EMISSION_ATOMS);
}

#[test]
fn aggregate_supply_exceeds_u64_without_wrapping() {
    use monario_monetary::{Amount, Supply};
    let amount = Supply::from_atoms(u128::from(u64::MAX)).unwrap();
    let one = Amount::from_atoms(1).unwrap();
    let increased = amount.checked_add(one).unwrap();
    assert_eq!(increased.atoms(), u128::from(u64::MAX) + 1);
    assert_eq!(increased.checked_sub(one).unwrap(), amount);
    assert!(Supply::ZERO.checked_sub(one).is_err());
    assert!(Supply::from_atoms(u128::MAX).is_err());
}
