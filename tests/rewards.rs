//! Consensus tests for complete miner coinbase allocation.
use monario_monetary::{
    Amount, AmountError, MAIN_EMISSION_BLOCKS, TAIL_EMISSION_ATOMS, rewards::miner_reward, subsidy,
};

fn amount(atoms: u64) -> Amount {
    Amount::from_atoms(atoms).unwrap()
}

#[test]
fn miners_receive_all_subsidy_and_fees_across_emission_boundaries() {
    for height in [0, 1, MAIN_EMISSION_BLOCKS - 1, MAIN_EMISSION_BLOCKS] {
        let fees = amount(101);
        assert_eq!(
            miner_reward(height, fees).unwrap(),
            subsidy(height).checked_add(fees).unwrap()
        );
    }
    assert_eq!(
        miner_reward(MAIN_EMISSION_BLOCKS, amount(101))
            .unwrap()
            .atoms(),
        TAIL_EMISSION_ATOMS + 101
    );
}

#[test]
fn reward_addition_is_checked() {
    assert_eq!(
        miner_reward(1, amount(u64::MAX)),
        Err(AmountError::OutOfRange)
    );
}
