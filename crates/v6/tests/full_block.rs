//! End-to-end 5,000,000-byte block validation harness.
//!
//! Ignored by default: it builds a real durable chain and signs real v6
//! transactions. Run it explicitly in release mode:
//!
//! ```text
//! cargo test -p monario-v6 --release --offline --test full_block -- --ignored --nocapture
//! ```
//!
//! It performs no nonce search, mining, listener or network activity. Every block
//! uses a fixed zero nonce against the easiest supported target; a fixed nonce
//! that misses that target aborts the harness instead of being searched. The root
//! identity is synthetic and supplied here, so no genesis is created.

use monario_address::Receiver;
use monario_chain::{
    Root,
    assembly::CoinbasePlan,
    consensus::{CANDIDATE_INITIAL_BITS, CANDIDATE_POW_LIMIT_BITS, candidate_config},
    ledger::OutPoint,
    storage::DurableChain,
    wire,
};
use monario_monetary::Amount;
use monario_v6::{V6Verifier, coinbase, transaction_id};
use monario_wallet::{Network, Scope, Seed};
use secp256k1::{Message, SecretKey};
use std::time::Instant;
use zcash_primitives::transaction::{
    self,
    sighash::{PrecomputedSighashData, SignableInput},
};
use zcash_protocol::{consensus::BranchId, value::Zatoshis};
use zcash_script::script;
use zcash_transparent::{address::Script, bundle as tb, sighash::SighashType};

/// Consensus maximum serialized block, including the header.
const BLOCK_BYTES: usize = 5_000_000;
/// Payment slots: the coinbase occupies the last of the 10,000 transaction slots.
const PAYMENTS: usize = 10_000 - 1;
/// Value of every coin the funded block spends.
const COIN: u64 = 75_000;
/// Fee paid by every transaction in the measured block.
const FEE: u64 = 100;
/// Outputs per transaction before the exact-size padding pass.
const NARROW: usize = 9;
/// Outputs per transaction for padded entries, one more output per entry.
const WIDE: usize = NARROW + 1;
/// Largest coinbase `extra_data` that keeps the script at the 100-byte cap here.
const MAX_COINBASE_PADDING: usize = 96;

#[derive(Clone, Debug)]
struct Inputs(Vec<tb::TxOut>);

impl tb::Authorization for Inputs {
    type ScriptSig = Script;
}

impl zcash_transparent::sighash::TransparentAuthorizingContext for Inputs {
    fn input_amounts(&self) -> Vec<Zatoshis> {
        self.0.iter().map(|o| o.value()).collect()
    }
    fn input_scriptpubkeys(&self) -> Vec<Script> {
        self.0.iter().map(|o| o.script_pubkey().clone()).collect()
    }
}

struct Producer;

impl transaction::Authorization for Producer {
    type TransparentAuth = Inputs;
    type SaplingAuth = <transaction::Authorized as transaction::Authorization>::SaplingAuth;
    type OrchardAuth = <transaction::Authorized as transaction::Authorization>::OrchardAuth;
}

struct TestKey {
    secret: SecretKey,
    public: [u8; 33],
    script: Script,
    receiver: coinbase::CoinbaseReceiver,
}

/// Public constant test seed. The derived key is never used for real funds.
fn test_key() -> TestKey {
    let seed = Seed::from_bytes(&[7; 32]).unwrap();
    let key = seed
        .transparent_key(Network::Main, 0, Scope::External, 0)
        .unwrap();
    let address = key.address();
    let receiver = match address.receiver() {
        Receiver::Transparent(receiver) => receiver,
        Receiver::Private(_) => panic!("transparent key produced a private address"),
    };
    TestKey {
        secret: SecretKey::from_secret_bytes(*key.expose_secret()).unwrap(),
        public: key.public_key(),
        script: Script(script::Code(address.script_pubkey().unwrap())),
        receiver,
    }
}

fn zat(atoms: u64) -> Zatoshis {
    Zatoshis::from_u64(atoms).unwrap()
}

/// Deterministic split of `total` into `parts` nonzero shares, remainder last.
fn split_value(total: u64, parts: usize) -> Vec<u64> {
    let count = u64::try_from(parts).unwrap();
    let mut values = vec![total / count; parts];
    if let Some(last) = values.last_mut() {
        *last += total % count;
    }
    values
}

/// Sign every transparent input with the same fixed test key. No entropy is used.
fn signed_transaction(
    inputs: &[(OutPoint, u64)],
    outputs: &[(u64, Script)],
    key: &TestKey,
) -> Vec<u8> {
    let coins: Vec<tb::TxOut> = inputs
        .iter()
        .map(|(_, value)| tb::TxOut::new(zat(*value), key.script.clone()))
        .collect();
    let vin: Vec<tb::TxIn<Inputs>> = inputs
        .iter()
        .map(|(point, _)| {
            tb::TxIn::<Inputs>::from_parts(
                tb::OutPoint::new(point.transaction, point.index),
                Script::default(),
                u32::MAX,
            )
        })
        .collect();
    let vout: Vec<tb::TxOut> = outputs
        .iter()
        .map(|(value, script)| tb::TxOut::new(zat(*value), script.clone()))
        .collect();
    let data: transaction::TransactionData<Producer> = transaction::TransactionData::from_parts_v6(
        BranchId::Nu6_3,
        0,
        0.into(),
        Some(tb::Bundle {
            vin,
            vout,
            authorization: Inputs(coins),
        }),
        None,
        None,
        None,
    );
    let precomputed = PrecomputedSighashData::new_zip244(data).unwrap();
    let mut script_sigs = Vec::with_capacity(inputs.len());
    for (index, (_, value)) in inputs.iter().enumerate() {
        let bundle = precomputed.tx().transparent_bundle().unwrap();
        let signable = zcash_transparent::sighash::SignableInput::from_parts(
            bundle,
            SighashType::ALL,
            index,
            &key.script,
            &key.script,
            zat(*value),
        )
        .unwrap();
        let digest = *precomputed
            .signature_hash(&SignableInput::Transparent(signable))
            .as_ref();
        let signature =
            secp256k1::ecdsa::sign(Message::from_digest(digest), &key.secret).serialize_der();
        let mut der = signature.as_ref().to_vec();
        der.push(1);
        let mut script_sig = vec![u8::try_from(der.len()).unwrap()];
        script_sig.extend(der);
        script_sig.push(33);
        script_sig.extend(key.public);
        script_sigs.push(Script(script::Code(script_sig)));
    }
    let signed = precomputed
        .into_tx()
        .map_bundles::<transaction::Authorized>(
            |bundle| {
                bundle.map(|bundle| tb::Bundle {
                    vin: bundle
                        .vin
                        .into_iter()
                        .zip(script_sigs)
                        .map(|(input, script_sig)| {
                            tb::TxIn::from_parts(
                                input.prevout().clone(),
                                script_sig,
                                input.sequence(),
                            )
                        })
                        .collect(),
                    vout: bundle.vout,
                    authorization: tb::Authorized,
                })
            },
            |bundle| bundle,
            |bundle| bundle,
        );
    let mut raw = Vec::new();
    signed.freeze().unwrap().write(&mut raw).unwrap();
    raw
}

/// Assemble one candidate against the current validated tip and encode it.
/// `build_template` performs full body validation; nothing here searches a nonce.
fn assemble(
    chain: &monario_chain::Chain<V6Verifier>,
    timestamp: u32,
    transactions: Vec<Vec<u8>>,
    extra_data: &[u8],
    miner: coinbase::CoinbaseReceiver,
) -> Vec<u8> {
    let template = chain
        .build_template(
            chain.tip(),
            u64::from(timestamp),
            u64::from(timestamp),
            transactions,
            |plan| {
                coinbase::encode(plan, miner, extra_data)
                    .map_err(|_| monario_chain::Error::Coinbase)
            },
        )
        .unwrap_or_else(|e| panic!("candidate at height {} rejected: {e:?}", chain.height() + 1));
    wire::encode(&template.block, chain.limits(), &V6Verifier).unwrap()
}

/// Canonical coinbase length for this height, fee total and padding length.
fn coinbase_length(
    height: u64,
    fees: Amount,
    extra_len: usize,
    miner: coinbase::CoinbaseReceiver,
) -> usize {
    let plan = CoinbasePlan {
        parent: [0; 32],
        height,
        fees,
        miner_maximum: monario_monetary::rewards::miner_reward(height, fees).unwrap(),
    };
    let extra = vec![0u8; extra_len];
    coinbase::encode(&plan, miner, &extra).unwrap().len()
}

/// Effects ID of the last transaction in a block. Funding blocks hold only a
/// coinbase; the fan-out block holds that coinbase followed by the fan-out.
fn last_transaction_id(
    raw: &[u8],
    chain: &monario_chain::Chain<V6Verifier>,
) -> monario_chain::Hash {
    let block = wire::decode(raw, chain.limits(), &V6Verifier).unwrap();
    transaction_id(block.transactions.last().unwrap()).unwrap()
}

#[test]
#[ignore = "end-to-end 5 MB block benchmark; run explicitly in release mode"]
fn full_capacity_block_validates_and_commits() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("chain.sqlite");
    let config = candidate_config([5; 32], CANDIDATE_INITIAL_BITS, CANDIDATE_POW_LIMIT_BITS);
    let fanout_height = 1 + config.coinbase_maturity;
    let root = Root {
        id: [3; 32],
        timestamp: 1_000,
        commitment: [4; 32],
    };
    let mut chain = DurableChain::open(&path, config, root, V6Verifier, 1_000).unwrap();
    let key = test_key();
    let timestamp = |height: u64| u32::try_from(1_000 + 90 * height).unwrap();

    // Height 1 funds the harness with the whole first subsidy.
    let first = assemble(
        chain.chain().unwrap(),
        timestamp(1),
        Vec::new(),
        b"MONAR",
        key.receiver,
    );
    chain
        .submit_encoded(&first, u64::from(timestamp(1)))
        .unwrap();
    let funding = last_transaction_id(&first, chain.chain().unwrap());

    // The first coinbase becomes spendable at its height plus the maturity.
    for height in 2..fanout_height {
        let raw = assemble(
            chain.chain().unwrap(),
            timestamp(height),
            Vec::new(),
            b"MONAR",
            key.receiver,
        );
        chain
            .submit_encoded(&raw, u64::from(timestamp(height)))
            .unwrap();
    }

    // Fan out the mature subsidy into one coin per payment slot. The remainder is
    // the transaction fee, so no change output is needed.
    let subsidy = monario_monetary::subsidy(1).atoms();
    assert!(subsidy > COIN * u64::try_from(PAYMENTS).unwrap());
    let fanout_outputs: Vec<(u64, Script)> = vec![(COIN, key.script.clone()); PAYMENTS];
    let fanout_tx = signed_transaction(
        &[(
            OutPoint {
                transaction: funding,
                index: 0,
            },
            subsidy,
        )],
        &fanout_outputs,
        &key,
    );
    let fanout_block = assemble(
        chain.chain().unwrap(),
        timestamp(fanout_height),
        vec![fanout_tx],
        b"MONAR",
        key.receiver,
    );
    chain
        .submit_encoded(&fanout_block, u64::from(timestamp(fanout_height)))
        .unwrap();
    let fanout = last_transaction_id(&fanout_block, chain.chain().unwrap());

    // One distinct signed transaction per payment slot, spending a distinct coin.
    let height = fanout_height + 1;
    let fees = Amount::from_atoms(FEE * u64::try_from(PAYMENTS).unwrap()).unwrap();
    let build_payment = |index: usize, outputs: usize| {
        let outpoint = OutPoint {
            transaction: fanout,
            index: u32::try_from(index).unwrap(),
        };
        let values = split_value(COIN - FEE, outputs);
        let destinations: Vec<(u64, Script)> = values
            .into_iter()
            .map(|value| (value, key.script.clone()))
            .collect();
        signed_transaction(&[(outpoint, COIN)], &destinations, &key)
    };
    let construction = Instant::now();
    let narrow: Vec<Vec<u8>> = (0..PAYMENTS).map(|i| build_payment(i, NARROW)).collect();
    let wide: Vec<Vec<u8>> = (0..PAYMENTS).map(|i| build_payment(i, WIDE)).collect();
    let construction = construction.elapsed();

    // Exact size: header, three-byte count, coinbase and every transaction. Each
    // widened transaction adds one fixed-size output; the residual is absorbed by
    // the coinbase's public extra data, which does not affect any signature.
    let frame = monario_chain::header::HEADER_LEN + 3;
    let coinbase = coinbase_length(height, fees, 0, key.receiver);
    let narrow_total: usize = narrow.iter().map(Vec::len).sum();
    let mut gained = Vec::with_capacity(PAYMENTS + 1);
    gained.push(0usize);
    for index in 0..PAYMENTS {
        gained.push(gained[index] + wide[index].len() - narrow[index].len());
    }
    let total = |pad: usize| frame + coinbase + narrow_total + gained[pad];
    assert!(total(0) <= BLOCK_BYTES);
    let mut pad = 0usize;
    while total(pad) < BLOCK_BYTES - MAX_COINBASE_PADDING {
        pad += 1;
        assert!(pad <= PAYMENTS, "no exact-size split exists");
    }
    assert!(total(pad) <= BLOCK_BYTES);
    let padding = BLOCK_BYTES - total(pad);
    let mut transactions = Vec::with_capacity(PAYMENTS);
    for index in 0..PAYMENTS {
        transactions.push(if index < pad {
            wide[index].clone()
        } else {
            narrow[index].clone()
        });
    }
    let extra = vec![0u8; padding];

    let assembly = Instant::now();
    let raw = assemble(
        chain.chain().unwrap(),
        timestamp(height),
        transactions,
        &extra,
        key.receiver,
    );
    let assembly = assembly.elapsed();

    let submission = Instant::now();
    let accepted = chain
        .submit_encoded(&raw, u64::from(timestamp(height)))
        .unwrap();
    let submission = submission.elapsed();

    assert!(accepted.became_best);
    assert_eq!(raw.len(), BLOCK_BYTES);
    assert_eq!(chain.chain().unwrap().height(), height);

    // Reopen the database: a durable commit must replay the full block.
    let reopening = Instant::now();
    drop(chain);
    let reopened = DurableChain::open(
        &path,
        candidate_config([5; 32], CANDIDATE_INITIAL_BITS, CANDIDATE_POW_LIMIT_BITS),
        root,
        V6Verifier,
        u64::from(timestamp(height)),
    )
    .unwrap();
    let reopening = reopening.elapsed();
    assert_eq!(reopened.chain().unwrap().height(), height);
    assert_eq!(
        reopened
            .authenticated_block_bytes(accepted.id)
            .unwrap()
            .len(),
        BLOCK_BYTES
    );

    eprintln!(
        "block_bytes={BLOCK_BYTES} transactions={} construction_ms={} assembly_ms={} \
         submit_ms={} reopen_ms={} padded_transactions={pad} coinbase_padding={padding}",
        PAYMENTS + 1,
        construction.as_millis(),
        assembly.as_millis(),
        submission.as_millis(),
        reopening.as_millis(),
    );
}
