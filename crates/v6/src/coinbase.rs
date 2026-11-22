//! Canonical transparent v6 coinbases for an assembled payment plan.
use crate::{Error, Script, invalid, script, tb, transaction};
use monario_chain::assembly::CoinbasePlan;
use monario_monetary::rewards::miner_reward;
use zcash_protocol::{consensus::BranchId, value::Zatoshis};
pub use zcash_transparent::address::TransparentAddress as CoinbaseReceiver;

/// Encode the full coinbase value to the miner's transparent receiver.
/// `miner` is a raw typed receiver: callers must validate the address's network
/// before extracting it. `extra_data` is public coinbase data, never a secret.
/// Plans are not acceptance receipts; full block validation remains mandatory.
pub fn encode(
    plan: &CoinbasePlan,
    miner: CoinbaseReceiver,
    extra_data: &[u8],
) -> Result<Vec<u8>, Error> {
    let height = plan.height;
    if height == 0 || height > monario_chain::consensus::MAX_BLOCK_HEIGHT || extra_data.len() > 98 {
        return Err(Error::Invalid);
    }
    let maximum = miner_reward(plan.height, plan.fees).map_err(invalid)?;
    if plan.miner_maximum != maximum {
        return Err(Error::Invalid);
    }
    let mut sig = if height <= 16 {
        vec![0x50 + height as u8]
    } else {
        let mut number = height.to_le_bytes().to_vec();
        while number.last() == Some(&0) {
            number.pop();
        }
        if number.last().is_some_and(|b| b & 0x80 != 0) {
            number.push(0);
        }
        let mut sig = vec![number.len() as u8];
        sig.extend(number);
        sig
    };
    sig.push(0); // Preserve the minimum two-byte coinbase script at small heights.
    sig.extend_from_slice(extra_data);
    if sig.len() > 100 {
        return Err(Error::Invalid);
    }
    let vout = vec![tb::TxOut::new(
        Zatoshis::from_u64(maximum.atoms()).map_err(invalid)?,
        miner.script().into(),
    )];
    let tx: transaction::TransactionData<transaction::Authorized> =
        transaction::TransactionData::from_parts_v6(
            BranchId::Nu6_3,
            0,
            0u32.into(),
            Some(tb::Bundle {
                vin: vec![tb::TxIn::from_parts(
                    tb::OutPoint::new([0; 32], u32::MAX),
                    Script(script::Code(sig)),
                    u32::MAX,
                )],
                vout,
                authorization: tb::Authorized,
            }),
            None,
            None,
            None,
        )
        .with_monario_expiry(height);
    let mut raw = Vec::new();
    tx.freeze()
        .map_err(invalid)?
        .write(&mut raw)
        .map_err(invalid)?;
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{V6Verifier, tests::State};
    use monario_chain::transactions::{TransactionContext, TransactionVerifier};
    use monario_monetary::Amount;

    fn plan(height: u64) -> CoinbasePlan {
        let fees = Amount::from_atoms(39).unwrap();
        CoinbasePlan {
            parent: [1; 32],
            height,
            fees,
            miner_maximum: miner_reward(height, fees).unwrap(),
        }
    }
    #[test]
    fn canonical_height_boundaries_payments_and_both_miner_receiver_types() {
        for height in [
            1,
            16,
            17,
            127,
            128,
            255,
            256,
            32767,
            32768,
            u64::from(u32::MAX),
            u64::from(u32::MAX) + 1,
            monario_chain::consensus::MAX_BLOCK_HEIGHT,
        ] {
            for miner in [
                CoinbaseReceiver::PublicKeyHash([8; 20]),
                CoinbaseReceiver::ScriptHash([8; 20]),
            ] {
                let p = plan(height);
                let raw = encode(&p, miner, b"MONAR").unwrap();
                let tx = V6Verifier
                    .verify(
                        &raw,
                        TransactionContext {
                            height,
                            median_time_past: 1000,
                            state: &State::default(),
                        },
                    )
                    .unwrap();
                assert_eq!(tx.coinbase_height, Some(height));
                assert_eq!(tx.outputs[0].value, p.miner_maximum);
                let expected: Script = miner.script().into();
                assert_eq!(tx.outputs[0].script, expected.0.0);
                assert_eq!(tx.outputs.len(), 1);
            }
        }
    }
    #[test]
    fn rejects_genesis_overflow_inconsistent_plans_and_excess_script_data() {
        let miner = CoinbaseReceiver::PublicKeyHash([8; 20]);
        for height in [0, u64::MAX] {
            assert!(encode(&plan(height), miner, b"").is_err());
        }
        assert!(encode(&plan(1), miner, &[0; 98]).is_ok());
        assert!(encode(&plan(1), miner, &[0; 99]).is_err());
        assert!(encode(&plan(128), miner, &[0; 98]).is_err());
        let mut p = plan(1);
        p.miner_maximum = Amount::ZERO;
        assert!(encode(&p, miner, b"").is_err());
    }
}
