//! Complete offline private-input interoperability. All keys, seeds and RNG are
//! public test fixtures; no nonce search, genesis block or network is created.
use super::*;
use incrementalmerkletree::{Hashable, Level};
use monario_address::Receiver;
use monario_wallet::{Network, PrivateAccount, Scope, Seed, TransparentKey};
use orchard::{
    builder::{Builder, BundleType, InProgress, Unauthorized},
    bundle::BundleVersion,
    keys::{FullViewingKey, SpendAuthorizingKey},
    tree::{MerkleHashOrchard, MerklePath},
    value::NoteValue,
};
use rand::{SeedableRng, rngs::StdRng};

struct Producer;
impl transaction::Authorization for Producer {
    type TransparentAuth = Inputs;
    type SaplingAuth = <transaction::Authorized as transaction::Authorization>::SaplingAuth;
    type OrchardAuth = InProgress<orchard::Proof, Unauthorized>;
}
fn sender() -> TransparentKey {
    Seed::from_bytes(&[7; 32])
        .unwrap()
        .transparent_key(Network::Main, 0, Scope::External, 0)
        .unwrap()
}
fn private(seed: u8) -> PrivateAccount {
    Seed::from_bytes(&[seed; 32])
        .unwrap()
        .private_account(Network::Main, 0)
        .unwrap()
}
fn recipient(account: &PrivateAccount) -> orchard::Address {
    let address = account.address(Scope::External, 0).unwrap();
    let decoded = monario_address::Address::decode(&address.encode(), Network::Main).unwrap();
    let Receiver::Private(receiver) = decoded.receiver() else {
        panic!("private receiver required");
    };
    receiver.to_upstream()
}
fn parse(raw: &[u8]) -> Transaction {
    Transaction::read(raw, BranchId::Nu6_3).unwrap()
}
fn coinbase(height: u32) -> Vec<u8> {
    assert!((1..=16).contains(&height));
    let data: transaction::TransactionData<transaction::Authorized> =
        transaction::TransactionData::from_parts_v6(
            BranchId::Nu6_3,
            0,
            height.into(),
            Some(tb::Bundle {
                vin: vec![tb::TxIn::from_parts(
                    tb::OutPoint::new([0; 32], u32::MAX),
                    Script(script::Code(vec![0x50 + height as u8, 0])),
                    u32::MAX,
                )],
                vout: vec![tb::TxOut::new(
                    Zatoshis::from_u64(if height == 1 { 100 } else { 0 }).unwrap(),
                    Script(script::Code(sender().address().script_pubkey().unwrap())),
                )],
                authorization: tb::Authorized,
            }),
            None,
            None,
            None,
        );
    let mut raw = Vec::new();
    data.freeze().unwrap().write(&mut raw).unwrap();
    raw
}
fn builder(anchor: orchard::Anchor) -> Builder {
    let v = BundleVersion::ironwood_v3();
    Builder::new(
        BundleType::Transactional {
            bundle_required: true,
            pad_to_minimum: Some(1),
        },
        v,
        v.default_flags(),
        anchor,
    )
    .unwrap()
}
fn prove(
    b: Builder,
    input: Option<(Hash, &TransparentKey)>,
    outputs: Vec<tb::TxOut>,
    spending_keys: &[SpendAuthorizingKey],
    rng: &mut StdRng,
    pk: &orchard::circuit::ProvingKey,
) -> Vec<u8> {
    let bundle = b
        .build::<zcash_protocol::value::ZatBalance>(&mut *rng)
        .unwrap()
        .unwrap()
        .0
        .create_proof(pk, &mut *rng)
        .unwrap();
    let transparent = if let Some((id, key)) = input {
        let coin = tb::TxOut::new(
            Zatoshis::from_u64(100).unwrap(),
            Script(script::Code(key.address().script_pubkey().unwrap())),
        );
        Some(tb::Bundle {
            vin: vec![tb::TxIn::from_parts(
                tb::OutPoint::new(id, 0),
                Script::default(),
                u32::MAX,
            )],
            vout: outputs,
            authorization: Inputs(vec![coin]),
        })
    } else if outputs.is_empty() {
        None
    } else {
        Some(tb::Bundle {
            vin: vec![],
            vout: outputs,
            authorization: Inputs(vec![]),
        })
    };
    let data: transaction::TransactionData<Producer> = transaction::TransactionData::from_parts_v6(
        BranchId::Nu6_3,
        0,
        0.into(),
        transparent,
        None,
        None,
        Some(bundle),
    );
    let pre = PrecomputedSighashData::new_zip244(data).unwrap();
    let shielded_hash = *pre.signature_hash(&SignableInput::Shielded).as_ref();
    let script_sig = input.map(|(_, key)| {
        let script = Script(script::Code(key.address().script_pubkey().unwrap()));
        let signable = zcash_transparent::sighash::SignableInput::from_parts(
            pre.tx().transparent_bundle().unwrap(),
            SighashType::ALL,
            0,
            &script,
            &script,
            Zatoshis::from_u64(100).unwrap(),
        )
        .unwrap();
        let hash = *pre
            .signature_hash(&SignableInput::Transparent(signable))
            .as_ref();
        let mut secret = secp256k1::SecretKey::from_secret_bytes(*key.expose_secret()).unwrap();
        let sig =
            secp256k1::ecdsa::sign(secp256k1::Message::from_digest(hash), &secret).serialize_der();
        secret.non_secure_erase();
        let mut der = sig.as_ref().to_vec();
        der.push(1);
        let mut ss = vec![u8::try_from(der.len()).unwrap()];
        ss.extend(der);
        ss.push(33);
        ss.extend(key.public_key());
        ss
    });
    let signed = pre.into_tx().map_bundles::<transaction::Authorized>(
        |b| {
            b.map(|b| tb::Bundle {
                vin: b
                    .vin
                    .into_iter()
                    .map(|i| {
                        tb::TxIn::from_parts(
                            i.prevout().clone(),
                            Script(script::Code(script_sig.clone().unwrap())),
                            i.sequence(),
                        )
                    })
                    .collect(),
                vout: b.vout,
                authorization: tb::Authorized,
            })
        },
        |b| b,
        |b| {
            b.map(|b| {
                b.apply_signatures(&mut *rng, shielded_hash, spending_keys)
                    .unwrap()
            })
        },
    );
    let mut raw = Vec::new();
    signed.freeze().unwrap().write(&mut raw).unwrap();
    raw
}
fn leaves(raw: &[u8]) -> Vec<MerkleHashOrchard> {
    parse(raw).ironwood_bundle().map_or(vec![], |b| {
        b.actions()
            .iter()
            .map(|a| MerkleHashOrchard::from_cmx(a.cmx()))
            .collect()
    })
}
fn note(raw: &[u8], account: &PrivateAccount) -> (usize, orchard::Note) {
    let tx = parse(raw);
    let b = tx.ironwood_bundle().unwrap();
    let fvk = FullViewingKey::from(account.expose_spending_key());
    b.actions()
        .iter()
        .enumerate()
        .find_map(|(index, _)| {
            b.decrypt_output_with_key(index, &fvk.to_ivk(orchard::keys::Scope::External))
                .map(|(note, _, _)| (index, note))
        })
        .expect("wallet decrypts real output")
}
fn witness(leaves: &[MerkleHashOrchard], position: usize) -> MerklePath {
    assert!(position < leaves.len());
    let mut nodes = leaves.to_vec();
    let mut index = position;
    let mut path = [MerkleHashOrchard::empty_root(Level::from(0)); 32];
    for (level, sibling) in path.iter_mut().enumerate() {
        let level = Level::from(level as u8);
        let empty = MerkleHashOrchard::empty_root(level);
        *sibling = *nodes.get(index ^ 1).unwrap_or(&empty);
        nodes = nodes
            .chunks(2)
            .map(|pair| MerkleHashOrchard::combine(level, &pair[0], pair.get(1).unwrap_or(&empty)))
            .collect();
        index /= 2;
    }
    MerklePath::from_parts(position as u32, path)
}
#[test]
#[ignore = "expensive deterministic private-input proof generation; run explicitly in release mode"]
fn generate_public_private_spend_fixtures() {
    let mut rng = StdRng::from_seed([43; 32]);
    let pk = orchard::circuit::ProvingKey::build(OrchardCircuitVersion::PostNu6_3);
    let first = private(7);
    let second = private(8);
    let key = sender();
    let mut b = builder(orchard::Anchor::empty_tree());
    b.add_output(None, recipient(&first), NoteValue::from_raw(90), [0; 512])
        .unwrap();
    let deposit = prove(
        b,
        Some((*parse(&coinbase(1)).txid().as_ref(), &key)),
        vec![],
        &[],
        &mut rng,
        &pk,
    );
    let (position, input) = note(&deposit, &first);
    assert_eq!(input.value().inner(), 90);
    let funding_leaves = leaves(&deposit);
    let path = witness(&funding_leaves, position);
    let anchor = path.root(input.commitment().into());
    let mut b = builder(anchor);
    b.add_spend(
        FullViewingKey::from(first.expose_spending_key()),
        input,
        path,
    )
    .unwrap();
    b.add_output(None, recipient(&second), NoteValue::from_raw(80), [0; 512])
        .unwrap();
    let transfer = prove(
        b,
        None,
        vec![],
        &[SpendAuthorizingKey::from(first.expose_spending_key())],
        &mut rng,
        &pk,
    );
    let (position, input) = note(&transfer, &second);
    assert_eq!(input.value().inner(), 80);
    let mut history = funding_leaves.clone();
    let offset = history.len();
    history.extend(leaves(&transfer));
    let path = witness(&history, offset + position);
    let mut b = builder(path.root(input.commitment().into()));
    b.add_spend(
        FullViewingKey::from(second.expose_spending_key()),
        input,
        path,
    )
    .unwrap();
    let withdrawal = prove(
        b,
        None,
        vec![tb::TxOut::new(
            Zatoshis::from_u64(70).unwrap(),
            Script(script::Code(key.address().script_pubkey().unwrap())),
        )],
        &[SpendAuthorizingKey::from(second.expose_spending_key())],
        &mut rng,
        &pk,
    );
    // A distinct, fully authorized competing spend of the FIRST note.
    let (position, input) = note(&deposit, &first);
    let path = witness(&funding_leaves, position);
    let mut b = builder(path.root(input.commitment().into()));
    b.add_spend(
        FullViewingKey::from(first.expose_spending_key()),
        input,
        path,
    )
    .unwrap();
    b.add_output(None, recipient(&second), NoteValue::from_raw(79), [0; 512])
        .unwrap();
    let conflict = prove(
        b,
        None,
        vec![],
        &[SpendAuthorizingKey::from(first.expose_spending_key())],
        &mut rng,
        &pk,
    );
    for (name, raw) in [
        ("deposit", deposit),
        ("transfer", transfer),
        ("withdrawal", withdrawal),
        ("conflict", conflict),
    ] {
        std::fs::write(format!("tests/fixtures/spend-{name}-v6.bin"), raw).unwrap();
    }
}

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("tests/fixtures/spend-{name}-v6.bin"))
        .expect("committed public private-input fixture")
}
fn config() -> monario_chain::Config {
    monario_chain::Config {
        chain_id: [11; 32],
        initial_bits: 0x2100ffff,
        pow_limit_bits: 0x2100ffff,
        half_life_seconds: 3600,
        seed_interval: 8,
        seed_lag: 2,
        coinbase_maturity: 2,
        max_future_seconds: 120,
        retained_blocks: 1000,
        limits: monario_chain::Limits {
            block_bytes: 100000,
            transaction_bytes: 20000,
            transactions: 100,
            inputs_per_transaction: 100,
            outputs_per_transaction: 100,
            script_bytes: 1000,
        },
    }
}
fn root() -> monario_chain::Root {
    monario_chain::Root {
        id: [3; 32],
        timestamp: 1000,
        commitment: [4; 32],
    }
}
#[derive(Clone)]
struct Model {
    parent: Hash,
    commitment: Hash,
    leaves: Vec<MerkleHashOrchard>,
}
impl Model {
    fn new() -> Self {
        Self {
            parent: root().id,
            commitment: root().commitment,
            leaves: vec![],
        }
    }
    fn candidate(&self, height: u32, extra: &[Vec<u8>]) -> (monario_chain::Block, Self) {
        let mut transactions = vec![coinbase(height)];
        transactions.extend(extra.iter().cloned());
        let mut next = self.clone();
        let mut ids = Vec::new();
        let mut tree = monario_chain::ledger::ShieldedTree::default();
        for raw in &transactions {
            let tx = parse(raw);
            let id = *tx.txid().as_ref();
            let auth = tx.auth_commitment().as_bytes().try_into().unwrap();
            ids.push((id, auth));
            next.leaves.extend(leaves(raw));
        }
        for leaf in &next.leaves {
            assert!(tree.frontier.append(*leaf));
        }
        let commitment = V6Verifier
            .block_commitment_with_state(self.commitment, u64::from(height), &ids, tree.root())
            .unwrap();
        let header = monario_chain::header::Header {
            version: 1,
            parent: self.parent,
            merkle_root: monario_chain::header::merkle_root(
                &ids.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
            )
            .unwrap(),
            commitment,
            timestamp: 1000 + 105 * u64::from(height),
            bits: config().initial_bits,
            nonce: [0; 32],
        };
        next.parent = header.id(&config().chain_id);
        next.commitment = commitment;
        (
            monario_chain::Block {
                header,
                transactions,
            },
            next,
        )
    }
    fn accept(
        &mut self,
        store: &mut monario_chain::storage::DurableChain<V6Verifier>,
        height: u32,
        extra: &[Vec<u8>],
    ) -> monario_chain::Accepted {
        let (block, next) = self.candidate(height, extra);
        let encoded = monario_chain::wire::encode(&block, &config().limits, &V6Verifier).unwrap();
        let accepted = store.submit_encoded(&encoded, 2000).unwrap();
        *self = next;
        accepted
    }
}

#[test]
fn real_private_flow_conserves_value_rejects_conflicts_and_reorgs_after_checkpoint() {
    use monario_chain::{
        ledger::OutPoint,
        storage::{DurableChain, SnapshotLimits},
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("private-flow.sqlite");
    let mut store = DurableChain::open(&path, config(), root(), V6Verifier, 2000).unwrap();
    let mut model = Model::new();
    let deposit = fixture("deposit");
    let transfer = fixture("transfer");
    let withdrawal = fixture("withdrawal");
    let conflict = fixture("conflict");
    model.accept(&mut store, 1, &[]);
    model.accept(&mut store, 2, &[]);
    model.accept(&mut store, 3, std::slice::from_ref(&deposit));
    assert_eq!(store.chain().unwrap().ledger().supply().atoms(), 90);
    assert_eq!(
        store.chain().unwrap().ledger().shielded().balance.atoms(),
        90
    );
    let funding = model.clone();
    let funding_root = store.chain().unwrap().ledger().shielded().root();
    let (position, funding_note) = note(&deposit, &private(7));
    let path_to_note = witness(&model.leaves, position);
    assert_eq!(
        path_to_note
            .root(funding_note.commitment().into())
            .to_bytes(),
        funding_root
    );
    let first_nf = funding_note
        .nullifier(&FullViewingKey::from(private(7).expose_spending_key()))
        .to_bytes();
    model.accept(&mut store, 4, std::slice::from_ref(&transfer));
    let transfer_root = store.chain().unwrap().ledger().shielded().root();
    assert_eq!(store.chain().unwrap().ledger().supply().atoms(), 80);
    assert_eq!(
        store.chain().unwrap().ledger().shielded().balance.atoms(),
        80
    );
    assert!(store.chain().unwrap().ledger().has_nullifier(&first_nf));
    assert_ne!(parse(&transfer).txid(), parse(&conflict).txid());
    let (bad, _) = model.candidate(5, std::slice::from_ref(&conflict));
    assert!(matches!(
        store.submit(bad, 2000),
        Err(monario_chain::storage::StorageError::Consensus(
            monario_chain::Error::DuplicateNullifier
        ))
    ));
    assert_eq!(store.chain().unwrap().tip(), model.parent);
    assert_eq!(
        store.chain().unwrap().ledger().shielded().root(),
        transfer_root
    );
    let (_, second_note) = note(&transfer, &private(8));
    let second_nf = second_note
        .nullifier(&FullViewingKey::from(private(8).expose_spending_key()))
        .to_bytes();
    model.accept(&mut store, 5, std::slice::from_ref(&withdrawal));
    let withdrawal_id = *parse(&withdrawal).txid().as_ref();
    let payout = OutPoint {
        transaction: withdrawal_id,
        index: 0,
    };
    let ledger = store.chain().unwrap().ledger();
    assert_eq!(ledger.supply().atoms(), 70);
    assert_eq!(ledger.shielded().balance, Amount::ZERO);
    assert_eq!(ledger.coin(&payout).unwrap().value.atoms(), 70);
    assert!(ledger.has_nullifier(&second_nf));
    let main_tip = model.parent;
    let limits = SnapshotLimits {
        max_entries: 10000,
        max_row_bytes: 1 << 20,
        max_bytes: 16 << 20,
    };
    let trusted = store.create_state_checkpoint(limits).unwrap();
    drop(store);
    let mut store = DurableChain::open_with_checkpoint(
        &path,
        config(),
        root(),
        V6Verifier,
        2000,
        trusted,
        limits,
    )
    .unwrap();
    assert_eq!(store.chain().unwrap().tip(), main_tip);
    let mut side = funding;
    side.accept(&mut store, 4, std::slice::from_ref(&conflict));
    side.accept(&mut store, 5, &[]);
    assert_eq!(store.chain().unwrap().tip(), main_tip);
    let reorg = side.accept(&mut store, 6, &[]);
    assert!(reorg.became_best);
    assert_eq!(reorg.disconnected.len(), 2);
    let ledger = store.chain().unwrap().ledger();
    assert_eq!(ledger.supply().atoms(), 79);
    assert_eq!(ledger.shielded().balance.atoms(), 79);
    assert!(ledger.coin(&payout).is_none());
    assert!(ledger.has_nullifier(&first_nf));
    assert!(!ledger.has_nullifier(&second_nf));
    assert!(!ledger.has_anchor(&transfer_root));
    let final_root = ledger.shielded().root();
    let work = store.chain().unwrap().chainwork().clone();
    drop(store);
    let store = DurableChain::open(&path, config(), root(), V6Verifier, 2000).unwrap();
    assert_eq!(store.chain().unwrap().tip(), side.parent);
    assert_eq!(store.chain().unwrap().chainwork(), &work);
    assert_eq!(
        store.chain().unwrap().ledger().shielded().root(),
        final_root
    );
    assert_eq!(store.chain().unwrap().ledger().supply().atoms(), 79);
}

#[test]
fn real_private_spend_authorizations_binding_and_context_tampering_fail() {
    use monario_chain::storage::DurableChain;
    let dir = tempfile::tempdir().unwrap();
    let mut store = DurableChain::open(
        &dir.path().join("tamper.sqlite"),
        config(),
        root(),
        V6Verifier,
        2000,
    )
    .unwrap();
    let mut model = Model::new();
    let deposit = fixture("deposit");
    let transfer = fixture("transfer");
    let withdrawal = fixture("withdrawal");
    model.accept(&mut store, 1, &[]);
    model.accept(&mut store, 2, &[]);
    model.accept(&mut store, 3, std::slice::from_ref(&deposit));
    model.accept(&mut store, 4, std::slice::from_ref(&transfer));
    let context = || TransactionContext {
        height: 5,
        median_time_past: 1100,
        state: store.chain().unwrap().ledger(),
    };
    let effects = V6Verifier.verify(&withdrawal, context()).unwrap();
    assert_eq!(effects.ironwood.unwrap().value_balance, 80);
    assert_eq!(effects.outputs[0].value.atoms(), 70);
    let tx = parse(&withdrawal);
    let b = tx.ironwood_bundle().unwrap();
    let actions = b.actions().len();
    let anchor = b.anchor().to_bytes();
    let anchor_offset = withdrawal
        .windows(32)
        .position(|bytes| bytes == anchor)
        .unwrap();
    let cmx = b.actions().first().cmx().to_bytes();
    let ciphertext_offset = withdrawal
        .windows(32)
        .position(|bytes| bytes == cmx)
        .unwrap()
        + 64;
    assert_eq!(
        u64::from_le_bytes(withdrawal[26..34].try_into().unwrap()),
        70
    );
    for offset in [
        8,
        12,
        20, // The high expiry bits are covered by shielded signatures.
        26, // Altered transparent payout remains in range but is unauthorized.
        ciphertext_offset,
        anchor_offset - 8,
        anchor_offset,
        withdrawal.len() - 1,
        withdrawal.len() - 65,
        withdrawal.len() - 64 - 64 * actions - 1,
    ] {
        let mut changed = withdrawal.clone();
        changed[offset] ^= 1;
        assert!(
            V6Verifier.verify(&changed, context()).is_err(),
            "accepted mutation at {offset}"
        );
    }
    let first = private(7);
    let fvk = FullViewingKey::from(first.expose_spending_key());
    let b = parse(&transfer);
    let b = b.ironwood_bundle().unwrap();
    assert!(b.actions().iter().enumerate().all(|(i, _)| {
        b.decrypt_output_with_key(i, &fvk.to_ivk(orchard::keys::Scope::External))
            .is_none()
    }));
    let (_, note) = note(&transfer, &private(8));
    assert_eq!(note.value().inner(), 80);
    assert_eq!(note.recipient(), recipient(&private(8)));
}

#[test]
#[ignore = "hardware benchmark; run explicitly in release mode"]
fn shielded_verification_cost_benchmark() {
    use std::time::Instant;
    let mut rng = StdRng::from_seed([97; 32]);
    let start = Instant::now();
    let pk = orchard::circuit::ProvingKey::build(OrchardCircuitVersion::PostNu6_3);
    eprintln!("proving key build: {:?}", start.elapsed());
    let vk = orchard::circuit::VerifyingKey::build(OrchardCircuitVersion::PostNu6_3);
    let address = recipient(&private(9));
    let mut points: Vec<(f64, f64)> = Vec::new();
    for actions in [1u8, 2, 4, 8, 16, 32, 64] {
        let v = BundleVersion::ironwood_v3();
        let mut b = Builder::new(
            BundleType::Transactional {
                bundle_required: true,
                pad_to_minimum: Some(actions),
            },
            v,
            v.default_flags(),
            orchard::Anchor::empty_tree(),
        )
        .unwrap();
        b.add_output(None, address, NoteValue::from_raw(0), [0; 512])
            .unwrap();
        let prove_start = Instant::now();
        let bundle = b
            .build::<zcash_protocol::value::ZatBalance>(&mut rng)
            .unwrap()
            .unwrap()
            .0
            .create_proof(&pk, &mut rng)
            .unwrap()
            .apply_signatures(&mut rng, [0u8; 32], &[])
            .unwrap();
        let prove = prove_start.elapsed();
        let n = bundle.actions().len();
        let rounds: u32 = if n <= 4 { 10 } else { 3 };
        bundle.verify_proof(&vk).unwrap();
        let t = Instant::now();
        for _ in 0..rounds {
            bundle.verify_proof(&vk).unwrap();
        }
        let proof = t.elapsed().as_secs_f64() / f64::from(rounds) * 1_000.0;
        // Authorization checks are part of consensus verification and scale with
        // actions. A fixed message is enough to time the scalar multiplication.
        let message = [7u8; 32];
        let t = Instant::now();
        for _ in 0..rounds {
            for action in bundle.actions() {
                let _ = action.rk().verify(&message, action.authorization());
            }
        }
        let auth_total = t.elapsed().as_secs_f64() / f64::from(rounds) * 1_000.0;
        let auth = auth_total / n as f64;
        let total = proof + auth_total;
        eprintln!(
            "actions={n} prove={prove:?} proof_verify_ms={proof:.2} action_auth_ms={auth:.3} total_ms={total:.2}"
        );
        points.push((n as f64, total));
    }
    let count = points.len() as f64;
    let mean_x = points.iter().map(|p| p.0).sum::<f64>() / count;
    let mean_y = points.iter().map(|p| p.1).sum::<f64>() / count;
    let sxx = points.iter().map(|p| (p.0 - mean_x).powi(2)).sum::<f64>();
    let sxy = points
        .iter()
        .map(|p| (p.0 - mean_x) * (p.1 - mean_y))
        .sum::<f64>();
    let slope = sxy / sxx;
    let base = mean_y - slope * mean_x;
    eprintln!("least_squares_base_ms={base:.2} slope_ms_per_action={slope:.2}");
    eprintln!("estimated_70_action_block_ms={:.2}", base + slope * 70.0);
}
