//! Upstream producer -> serialized fixture -> Monario verifier. All test keys and
//! randomness are fixed public fixtures and must NEVER be used for real funds.
use super::tests::State;
use super::*;
use orchard::{
    builder::{Builder, BundleType, InProgress, Unauthorized},
    bundle::BundleVersion,
    keys::{FullViewingKey, Scope, SpendingKey},
    value::NoteValue,
};
use rand::{SeedableRng, rngs::StdRng};

struct Producer;
impl transaction::Authorization for Producer {
    type TransparentAuth = Inputs;
    type SaplingAuth = <transaction::Authorized as transaction::Authorization>::SaplingAuth;
    type OrchardAuth = InProgress<orchard::Proof, Unauthorized>;
}
fn public_script() -> (secp256k1::SecretKey, Script) {
    // Public constant test scalar. No entropy, account, wallet, or secret file.
    let sk = secp256k1::SecretKey::from_secret_bytes([1; 32]).unwrap();
    let pk = secp256k1::PublicKey::from_secret_key(&sk).serialize();
    let mut script = vec![33];
    script.extend(pk);
    script.push(0xac);
    (sk, Script(script::Code(script)))
}
fn produce(private: bool) -> Vec<u8> {
    produce_at(private, 0)
}
fn produce_at(private: bool, expiry: u64) -> Vec<u8> {
    let mut rng = StdRng::from_seed([42; 32]);
    let (sk, script) = public_script();
    let coin = tb::TxOut::new(Zatoshis::from_u64(100).unwrap(), script.clone());
    let ironwood = if private {
        let version = BundleVersion::ironwood_v3();
        let mut b = Builder::new(
            BundleType::Transactional {
                bundle_required: true,
                pad_to_minimum: Some(1),
            },
            version,
            version.default_flags(),
            orchard::Anchor::empty_tree(),
        )
        .unwrap();
        let public_fixture = Option::<SpendingKey>::from(SpendingKey::from_bytes([7; 32])).unwrap();
        let recipient = FullViewingKey::from(&public_fixture).address_at(0_u32, Scope::External);
        b.add_output(None, recipient, NoteValue::from_raw(90), [0; 512])
            .unwrap();
        let (bundle, _) = b
            .build::<zcash_protocol::value::ZatBalance>(&mut rng)
            .unwrap()
            .unwrap();
        let key = orchard::circuit::ProvingKey::build(OrchardCircuitVersion::PostNu6_3);
        Some(bundle.create_proof(&key, &mut rng).unwrap())
    } else {
        None
    };
    let vin = vec![tb::TxIn::<Inputs>::from_parts(
        tb::OutPoint::new([7; 32], 0),
        Script::default(),
        u32::MAX,
    )];
    let vout = if private {
        vec![]
    } else {
        vec![tb::TxOut::new(
            Zatoshis::from_u64(90).unwrap(),
            script.clone(),
        )]
    };
    let data: transaction::TransactionData<Producer> = transaction::TransactionData::from_parts_v6(
        BranchId::Nu6_3,
        0,
        0.into(),
        Some(tb::Bundle {
            vin,
            vout,
            authorization: Inputs(vec![coin.clone()]),
        }),
        None,
        None,
        ironwood,
    )
    .with_monario_expiry(expiry);
    let pre =
        PrecomputedSighashData::new_zip244(data).unwrap_or_else(|_| panic!("v6 precomputation"));
    let b = pre.tx().transparent_bundle().unwrap();
    let input = zcash_transparent::sighash::SignableInput::from_parts(
        b,
        SighashType::ALL,
        0,
        &script,
        &script,
        coin.value(),
    )
    .unwrap();
    let digest = *pre
        .signature_hash(&SignableInput::Transparent(input))
        .as_ref();
    let shielded_hash = *pre.signature_hash(&SignableInput::Shielded).as_ref();
    let sig = secp256k1::ecdsa::sign(secp256k1::Message::from_digest(digest), &sk).serialize_der();
    let mut der = sig.as_ref().to_vec();
    der.push(1);
    let mut ss = vec![u8::try_from(der.len()).unwrap()];
    ss.extend(der);
    let signed = pre.into_tx().map_bundles::<transaction::Authorized>(
        |b| {
            b.map(|b| tb::Bundle {
                vin: b
                    .vin
                    .into_iter()
                    .map(|i| {
                        tb::TxIn::from_parts(
                            i.prevout().clone(),
                            Script(script::Code(ss.clone())),
                            i.sequence(),
                        )
                    })
                    .collect(),
                vout: b.vout,
                authorization: tb::Authorized,
            })
        },
        |b| b,
        |b| b.map(|b| b.apply_signatures(&mut rng, shielded_hash, &[]).unwrap()),
    );
    let mut raw = Vec::new();
    signed.freeze().unwrap().write(&mut raw).unwrap();
    raw
}

#[test]
#[ignore = "expensive deterministic fixture regeneration; run explicitly in release mode"]
fn generate_public_interoperability_fixtures() {
    std::fs::create_dir_all("tests/fixtures").unwrap();
    std::fs::write("tests/fixtures/signed-v6.bin", produce(false)).unwrap();
    std::fs::write("tests/fixtures/private-v6.bin", produce(true)).unwrap();
}

#[test]
#[ignore = "hardware benchmark; run explicitly in release mode"]
fn transparent_transaction_validation_benchmark() {
    use std::time::Instant;
    let state = State::default();
    let verify = |bytes: &[u8]| {
        V6Verifier.verify(
            bytes,
            TransactionContext {
                height: 1,
                median_time_past: 1000,
                state: &state,
            },
        )
    };
    let signed: &[u8] = include_bytes!("../tests/fixtures/signed-v6.bin");
    verify(signed).unwrap();
    let rounds = 50u32;
    let start = Instant::now();
    for _ in 0..rounds {
        verify(signed).unwrap();
    }
    let signed_ms = start.elapsed().as_secs_f64() / f64::from(rounds) * 1000.0;
    let by_count = 10_000usize;
    let by_size = 5_000_000 / signed.len();
    eprintln!(
        "signed_tx_bytes={} signed_verify_ms={signed_ms:.3} by_5mb={by_size} by_count={by_count}",
        signed.len()
    );
    eprintln!(
        "10k_signed_estimate_s={:.2}",
        signed_ms * by_count as f64 / 1000.0
    );
    eprintln!(
        "5mb_signed_estimate_s={:.2}",
        signed_ms * by_size as f64 / 1000.0
    );
}

#[test]
fn signed_and_private_serialized_fixtures_interoperate() {
    use monario_chain::LedgerView;
    let (_, script) = public_script();
    let mut state = State::default();
    state.coin.script = script.0.0;
    for private in [false, true] {
        let raw = std::fs::read(if private {
            "tests/fixtures/private-v6.bin"
        } else {
            "tests/fixtures/signed-v6.bin"
        })
        .expect("committed public fixture");
        let verify = |bytes: &[u8], s: &State| {
            V6Verifier.verify(
                bytes,
                TransactionContext {
                    height: 1,
                    median_time_past: 1000,
                    state: s,
                },
            )
        };
        let effects = verify(&raw, &state).expect("upstream-produced signed fixture verifies");
        assert_eq!(effects.inputs.len(), 1);
        if private {
            let shielded = effects.ironwood.unwrap();
            assert_eq!(shielded.value_balance, -90);
            assert_eq!(shielded.commitments.len(), 1);
        } else {
            assert_eq!(effects.outputs[0].value.atoms(), 90);
        }
        let mut changed = raw.clone();
        changed[12] ^= 1;
        assert!(verify(&changed, &state).is_err());
        if private {
            for offset in [1, 65, 129] {
                let mut damaged = raw.clone();
                let index = damaged.len() - offset;
                damaged[index] ^= 1;
                assert!(
                    verify(&damaged, &state).is_err(),
                    "accepted changed proof/authorization at tail offset {offset}"
                );
            }
        }
        state.coin.value = Amount::from_atoms(101).unwrap();
        assert!(verify(&raw, &state).is_err());
        state.coin.value = Amount::from_atoms(100).unwrap();
        assert_eq!(state.supply().atoms(), 100);
    }
}

#[test]
fn derived_wallet_p2pkh_signatures_interoperate() {
    use monario_wallet::{Network, Scope, Seed};
    // Public test seed only. The derived key is not saved or used for funds.
    let seed = Seed::from_bytes(&[7; 32]).unwrap();
    let key = seed
        .transparent_key(Network::Main, 0, Scope::External, 0)
        .unwrap();
    let encoded = key.address().encode();
    let address = monario_address::Address::decode(&encoded, Network::Main).unwrap();
    let script = Script(script::Code(address.script_pubkey().unwrap()));
    let coin = tb::TxOut::new(Zatoshis::from_u64(100).unwrap(), script.clone());
    let data: transaction::TransactionData<Auth> = transaction::TransactionData::from_parts_v6(
        BranchId::Nu6_3,
        0,
        0.into(),
        Some(tb::Bundle {
            vin: vec![tb::TxIn::<Inputs>::from_parts(
                tb::OutPoint::new([7; 32], 0),
                Script::default(),
                u32::MAX,
            )],
            vout: vec![tb::TxOut::new(
                Zatoshis::from_u64(90).unwrap(),
                script.clone(),
            )],
            authorization: Inputs(vec![coin.clone()]),
        }),
        None,
        None,
        None,
    );
    let pre = PrecomputedSighashData::new_zip244(data).unwrap();
    let signable = zcash_transparent::sighash::SignableInput::from_parts(
        pre.tx().transparent_bundle().unwrap(),
        SighashType::ALL,
        0,
        &script,
        &script,
        coin.value(),
    )
    .unwrap();
    let hash = *pre
        .signature_hash(&SignableInput::Transparent(signable))
        .as_ref();
    let mut secret = secp256k1::SecretKey::from_secret_bytes(*key.expose_secret()).unwrap();
    let signature =
        secp256k1::ecdsa::sign(secp256k1::Message::from_digest(hash), &secret).serialize_der();
    secret.non_secure_erase();
    let mut der = signature.as_ref().to_vec();
    der.push(1);
    let mut script_sig = vec![u8::try_from(der.len()).unwrap()];
    script_sig.extend(der);
    script_sig.push(33);
    script_sig.extend(key.public_key());
    let signed = pre.into_tx().map_bundles::<transaction::Authorized>(
        |bundle| {
            bundle.map(|b| tb::Bundle {
                vin: b
                    .vin
                    .into_iter()
                    .map(|i| {
                        tb::TxIn::from_parts(
                            i.prevout().clone(),
                            Script(script::Code(script_sig.clone())),
                            i.sequence(),
                        )
                    })
                    .collect(),
                vout: b.vout,
                authorization: tb::Authorized,
            })
        },
        |b| b,
        |b| b,
    );
    let mut raw = Vec::new();
    signed.freeze().unwrap().write(&mut raw).unwrap();
    let mut state = State::default();
    state.coin.script = script.0.0;
    let verify = |state: &State| {
        V6Verifier.verify(
            &raw,
            TransactionContext {
                height: 1,
                median_time_past: 1000,
                state,
            },
        )
    };
    let tx = verify(&state).unwrap();
    assert_eq!(tx.outputs[0].value.atoms(), 90);
    state.coin.value = Amount::from_atoms(99).unwrap();
    assert!(verify(&state).is_err());
}

#[test]
fn wide_expiry_is_signed_for_transparent_and_private_transactions() {
    let (_, script) = public_script();
    let mut state = State::default();
    state.coin.script = script.0.0;
    let expiry = u64::from(u32::MAX) + 100;
    for private in [false, true] {
        let raw = produce_at(private, expiry);
        let verify = |bytes: &[u8], height| {
            V6Verifier.verify(
                bytes,
                TransactionContext {
                    height,
                    median_time_past: 1000,
                    state: &state,
                },
            )
        };
        assert!(verify(&raw, expiry).is_ok());
        assert!(verify(&raw, expiry + 1).is_err());
        let mut changed = raw.clone();
        changed[20] ^= 2; // Keep the mutated expiry after the validation height.
        assert_ne!(
            transaction_id(&raw).unwrap(),
            transaction_id(&changed).unwrap()
        );
        assert!(verify(&changed, expiry).is_err());
    }
}
