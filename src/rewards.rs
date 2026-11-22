//! Checked coinbase reward arithmetic.
use crate::{Amount, AmountError, subsidy};

/// Maximum coinbase value: the scheduled subsidy plus all validated transaction fees.
pub fn miner_reward(height: u64, fees: Amount) -> Result<Amount, AmountError> {
    subsidy(height).checked_add(fees)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MAIN_EMISSION_BLOCKS, TAIL_EMISSION_ATOMS};

    fn amount(atoms: u64) -> Amount {
        Amount::from_atoms(atoms).unwrap()
    }

    #[test]
    fn all_subsidy_and_fees_are_miner_coinbase_value_in_each_emission_era() {
        for height in [0, 1, MAIN_EMISSION_BLOCKS - 1, MAIN_EMISSION_BLOCKS] {
            let fees = amount(101);
            let reward = miner_reward(height, fees).unwrap();
            let expected_subsidy = if height >= MAIN_EMISSION_BLOCKS {
                TAIL_EMISSION_ATOMS
            } else {
                subsidy(height).atoms()
            };
            assert_eq!(reward.atoms(), expected_subsidy + 101);
        }
    }

    #[test]
    fn reward_addition_rejects_overflow() {
        assert_eq!(
            miner_reward(1, amount(u64::MAX)),
            Err(AmountError::OutOfRange)
        );
    }
}
