//! Synthetic transaction/PoW fixtures; real owner/operator signatures and archival
//! Merkle verification. No nonce search or network. Real v6 interop is separate.
use super::*;
use crate::{
    Block, Config, Root,
    header::{Header, merkle_root},
    transactions::{Output, TransactionContext, TransactionError, VerifiedTransaction},
};
use monario_monetary::{Amount, subsidy};
use std::collections::BTreeMap;

pub(crate) struct Verifier;
fn tx(raw: &[u8]) -> Result<(VerifiedTransaction, usize), TransactionError> {
    let mut r = Reader(raw);
    let height = r.n().map_err(|_| TransactionError::Invalid)?;
    let mut inputs = Vec::new();
    let n = u16::from_le_bytes(r.array().map_err(|_| TransactionError::Invalid)?) as usize;
    if n > 1000 {
        return Err(TransactionError::Invalid);
    }
    for _ in 0..n {
        inputs.push(OutPoint {
            transaction: r.array().map_err(|_| TransactionError::Invalid)?,
            index: u32::from_le_bytes(r.array().map_err(|_| TransactionError::Invalid)?),
        });
    }
    let mut outputs = Vec::new();
    let n = u16::from_le_bytes(r.array().map_err(|_| TransactionError::Invalid)?) as usize;
    if n > 100 {
        return Err(TransactionError::Invalid);
    }
    for _ in 0..n {
        let value = Amount::from_atoms(r.n().map_err(|_| TransactionError::Invalid)?)
            .map_err(|_| TransactionError::Invalid)?;
        let len = u16::from_le_bytes(r.array().map_err(|_| TransactionError::Invalid)?) as usize;
        outputs.push(Output {
            value,
            script: r.take(len).map_err(|_| TransactionError::Invalid)?.to_vec(),
        });
    }
    let len = raw.len() - r.0.len();
    let raw = &raw[..len];
    Ok((
        VerifiedTransaction {
            id: hash_domain(b"service-test-tx", &[raw]),
            authorization_digest: hash_domain(b"service-test-auth", &[raw]),
            coinbase_height: (height != 0).then_some(height),
            inputs,
            outputs,
            has_shielded_bundle: false,
            ironwood: None,
        },
        len,
    ))
}
impl TransactionVerifier for Verifier {
    fn transaction_length(&self, raw: &[u8]) -> Result<usize, TransactionError> {
        tx(raw).map(|(_, n)| n)
    }
    fn verify(
        &self,
        raw: &[u8],
        _: TransactionContext<'_>,
    ) -> Result<VerifiedTransaction, TransactionError> {
        let (tx, n) = tx(raw)?;
        if n != raw.len() {
            return Err(TransactionError::Invalid);
        }
        Ok(tx)
    }
    fn block_commitment(
        &self,
        parent: Hash,
        height: u64,
        ids: &[(Hash, Hash)],
    ) -> Result<Hash, TransactionError> {
        let bytes: Vec<_> = ids
            .iter()
            .flat_map(|(id, auth)| [*id, *auth])
            .flatten()
            .collect();
        Ok(hash_domain(
            b"service-test-commit",
            &[&parent, &height.to_le_bytes(), &bytes],
        ))
    }
}
pub(crate) fn raw(height: u64, inputs: &[OutPoint], outputs: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut b = height.to_le_bytes().to_vec();
    b.extend((inputs.len() as u16).to_le_bytes());
    for p in inputs {
        b.extend(p.transaction);
        b.extend(p.index.to_le_bytes());
    }
    b.extend((outputs.len() as u16).to_le_bytes());
    for (value, script) in outputs {
        b.extend(value.to_le_bytes());
        b.extend((script.len() as u16).to_le_bytes());
        b.extend(script);
    }
    b
}
pub(crate) fn owner() -> SecretKey {
    SecretKey::from_secret_bytes([1; 32]).unwrap()
}

pub(crate) fn recommit(c: &Chain<Verifier>, b: &mut Block) {
    let effects: Vec<_> = b
        .transactions
        .iter()
        .map(|r| {
            let t = tx(r).unwrap().0;
            (t.id, t.authorization_digest)
        })
        .collect();
    b.header.merkle_root = merkle_root(&effects.iter().map(|p| p.0).collect::<Vec<_>>()).unwrap();
    b.header.commitment = Verifier
        .block_commitment(
            c.nodes[&b.header.parent].commitment,
            c.nodes[&b.header.parent].height + 1,
            &effects,
        )
        .unwrap();
}

pub(crate) fn qualified_model() -> (Model, Hash, OutPoint, OutPoint) {
    let mut m = Model::new();
    let (id, collateral, mut fee) = m.register();
    for _ in 0..7 {
        let end = m.chain.ledger().service_entry(&id).unwrap().next_start + PERIOD_BLOCKS;
        m.to(end);
        let record = m.proof_tx(fee, m.proof(id));
        fee = OutPoint {
            transaction: tx(&record).unwrap().0.id,
            index: 0,
        };
        m.add(m.chain.tip(), &[record]);
    }
    (m, id, collateral, fee)
}

#[test]
fn qualified_registration_does_not_divert_coinbase_and_reorg_restores_service_state() {
    let (mut m, id, collateral, fee) = qualified_model();
    let parent = m.chain.tip();
    let entry = m.chain.ledger().service_entry(&id).unwrap().clone();
    let mut b = candidate(&m.chain, parent, &[]);
    b.transactions[0] = raw(
        m.chain.height() + 1,
        &[],
        &[(subsidy(m.chain.height() + 1).atoms() + 1, vec![0x51])],
    );
    recommit(&m.chain, &mut b);
    assert!(
        m.chain
            .submit_checked(b, 2_000_000, &mut crate::tests::FixturePow::default())
            .is_err()
    );
    assert_eq!(m.chain.tip(), parent);
    assert_eq!(m.chain.ledger().service_entry(&id), Some(&entry));
    let height = m.chain.height() + 1;
    let remaining = m.chain.ledger().coin(&fee).unwrap().value.atoms() - 39;
    let spend = raw(0, &[fee], &[(remaining, vec![0x51])]);
    let valid = candidate(&m.chain, parent, &[spend]);
    let cb = tx(&valid.transactions[0]).unwrap().0;
    assert_eq!(cb.outputs.len(), 1);
    assert_eq!(cb.outputs[0].value.atoms(), subsidy(height).atoms() + 39);
    let expected = cb.outputs[0].value.atoms();
    let cbid = tx(&valid.transactions[0]).unwrap().0.id;
    let paid = m.accept_block(valid);
    let payment = OutPoint {
        transaction: cbid,
        index: 0,
    };
    assert!(m.chain.ledger().coin(&payment).unwrap().coinbase);
    let immature = raw(0, &[payment], &[(expected, vec![0x51])]);
    let b = candidate(&m.chain, paid, &[immature]);
    assert!(matches!(
        m.chain
            .submit_checked(b, 2_000_000, &mut crate::tests::FixturePow::default()),
        Err(Error::ImmatureCoinbase)
    ));
    // Spending collateral removes the registration before later service checks.
    let withdrawal = raw(0, &[collateral], &[(COLLATERAL_ATOMS, vec![0x51])]);
    let b = candidate(&m.chain, paid, &[withdrawal]);
    m.accept_block(b);
    assert!(m.chain.ledger().service_entry(&id).is_none());
    let mut side = candidate(&m.chain, parent, &[]);
    side.header.nonce[0] = 3;
    let side = m.accept_block(side);
    let side = m.add(side, &[]);
    m.add(side, &[]);
    assert!(m.chain.ledger().coin(&collateral).is_some());
    assert!(m.chain.ledger().coin(&payment).is_none());
    assert!(m.chain.ledger().service_entry(&id).is_some());
}

fn queue_entry(index: u8) -> Entry {
    Entry {
        control_head: [0; 32],
        collateral: OutPoint {
            transaction: [index; 32],
            index: 0,
        },
        owner: PublicKey::from_secret_key(&owner()).serialize(),
        operator: PublicKey::from_secret_key(
            &SecretKey::from_secret_bytes([index + 2; 32]).unwrap(),
        )
        .serialize(),
        registered_height: 1,
        slot: 0,
        next_start: 15360,
        credited_seconds: QUALIFY_SECONDS,
        last_proven_end: Some(15360),
        score: Score::default(),
        score_height: 15361,
    }
}

#[test]
fn indexed_service_schedule_preserves_full_miner_claim() {
    let mut ledger = crate::ledger::Ledger::default();
    for index in (1..=3).rev() {
        let entry = queue_entry(index);
        assert!(entry.valid());
        ledger.set_service([index; 32], Some(entry));
    }
    assert_eq!(ledger.services.len(), 3);
    let mut staged = Overlay::new(&ledger);
    let mut banned = staged.service_entry(&[1; 32]).unwrap().clone();
    banned.score.punish_failure(100);
    banned.score.punish_failure(100);
    staged.set_service([1; 32], Some(banned));
    staged.set_service([2; 32], None);
    assert_eq!(staged.service_count(), 2);
    ledger.commit(staged.finish());
}

#[test]
fn tail_era_coinbase_assigns_full_subsidy_and_fees_to_miners() {
    let c = Chain::new(config(), root(), Verifier).unwrap();
    // Unit-level body validation in the perpetual tail era; no fake multi-million
    // block chain is accepted or persisted by this test.
    let height = monario_monetary::MAIN_EMISSION_BLOCKS + 1;
    let tail = subsidy(height);
    assert_eq!(tail.atoms(), monario_monetary::TAIL_EMISSION_ATOMS);
    for fee in [0, 19, 20, 39, 40] {
        let mut base = crate::ledger::Ledger::default();
        let mut e = queue_entry(1);
        e.next_start = height - 1;
        e.slot = (e.next_start % PERIOD_BLOCKS) as u16;
        e.last_proven_end = Some(e.next_start);
        e.score_height = height;
        base.set_service([1; 32], Some(e.clone()));
        let p = OutPoint {
            transaction: [8; 32],
            index: 0,
        };
        base.coins.insert(
            p,
            crate::ledger::Coin {
                value: Amount::from_atoms(100).unwrap(),
                script: vec![0x51],
                created_height: 1,
                coinbase: false,
            },
        );
        base.supply = Amount::from_atoms(100).unwrap().into();
        let miner = tail.atoms() + fee;
        let outputs = vec![(miner, vec![0x51])];
        let mut b = candidate(&c, root().id, &[]);
        b.transactions = vec![
            raw(height, &[], &outputs),
            raw(0, &[p], &[(100 - fee, vec![0x51])]),
        ];
        let effects: Vec<_> = b
            .transactions
            .iter()
            .map(|r| {
                let t = tx(r).unwrap().0;
                (t.id, t.authorization_digest)
            })
            .collect();
        b.header.merkle_root =
            merkle_root(&effects.iter().map(|p| p.0).collect::<Vec<_>>()).unwrap();
        b.header.commitment = Verifier
            .block_commitment(root().commitment, height, &effects)
            .unwrap();
        let delta = c
            .validate_body(&b, height, root().timestamp, root().commitment, &base)
            .unwrap();
        assert_eq!(
            delta.supply.1.atoms(),
            delta.supply.0.atoms() + u128::from(tail.atoms())
        );
    }
}
pub(crate) fn operator() -> SecretKey {
    SecretKey::from_secret_bytes([2; 32]).unwrap()
}
pub(crate) fn config() -> Config {
    let mut c = crate::tests::config();
    c.coinbase_maturity = crate::consensus::COINBASE_MATURITY;
    c.limits.inputs_per_transaction = 1000;
    c.limits.block_bytes = archive::MAX_BLOCK_BYTES;
    c.limits.transaction_bytes = 100000;
    c.limits.script_bytes = MAX_RECORD_BYTES + 4;
    c.retained_blocks = 40000;
    c
}
pub(crate) fn root() -> Root {
    crate::tests::root()
}
pub(crate) fn candidate(c: &Chain<Verifier>, parent: Hash, extra: &[Vec<u8>]) -> Block {
    let p = &c.nodes[&parent];
    let height = p.height + 1;
    let script = owner_script(&PublicKey::from_secret_key(&owner()).serialize());
    let payout = fixture_payment(c, parent, extra).expect("test candidate inputs validate");
    let reward =
        monario_monetary::rewards::miner_reward(height, Amount::from_atoms(payout.fees).unwrap())
            .unwrap();
    let outputs = vec![(reward.atoms(), script)];
    let mut transactions = vec![raw(height, &[], &outputs)];
    transactions.extend_from_slice(extra);
    let effects: Vec<_> = transactions
        .iter()
        .map(|r| {
            let t = tx(r).unwrap().0;
            (t.id, t.authorization_digest)
        })
        .collect();
    let commitment = Verifier
        .block_commitment(p.commitment, height, &effects)
        .unwrap();
    Block {
        header: Header {
            version: 1,
            parent,
            merkle_root: merkle_root(&effects.iter().map(|p| p.0).collect::<Vec<_>>()).unwrap(),
            commitment,
            timestamp: root().timestamp + height * 45,
            bits: if height == 1 {
                c.config.initial_bits
            } else {
                c.asert.next_bits(p.height, p.timestamp).unwrap()
            },
            nonce: [0; 32],
        },
        transactions,
    }
}
pub(crate) struct FixturePayout {
    pub(crate) fees: u64,
}

pub(crate) fn fixture_payment(
    c: &Chain<Verifier>,
    parent: Hash,
    extra: &[Vec<u8>],
) -> Option<FixturePayout> {
    let height = c.nodes[&parent].height + 1;
    let (detach, attach) = c.route(c.tip(), parent).ok()?;
    let mut base = Overlay::new(c.ledger());
    for id in detach {
        base.apply(c.nodes[&id].delta.as_ref()?, true).ok()?;
    }
    for id in attach {
        base.apply(c.nodes[&id].delta.as_ref()?, false).ok()?;
    }
    let mut staged = Overlay::new(&base);
    let mut records = Vec::new();
    let mut fees = 0u64;
    for bytes in extra {
        let t = tx(bytes).ok()?.0;
        let mut input = 0u64;
        let mut output = 0u64;
        for p in t.inputs {
            input = input.checked_add(staged.spend(p).ok()?.value.atoms())?;
        }
        for (i, o) in t.outputs.into_iter().enumerate() {
            output = output.checked_add(o.value.atoms())?;
            if let Some(p) = payload(&o.script).ok()? {
                records.push((t.id, p));
            } else {
                staged
                    .create(
                        OutPoint {
                            transaction: t.id,
                            index: i as u32,
                        },
                        crate::ledger::Coin {
                            value: o.value,
                            script: o.script,
                            created_height: height,
                            coinbase: false,
                        },
                    )
                    .ok()?;
            }
        }
        fees = fees.checked_add(input.checked_sub(output)?)?;
    }
    let _ = c.apply_services(parent, height, &base, &mut staged, &records);
    Some(FixturePayout { fees })
}
pub(crate) struct Model {
    pub(crate) chain: Chain<Verifier>,
    pub(crate) bodies: BTreeMap<Hash, Vec<u8>>,
}
impl Model {
    pub(crate) fn new() -> Self {
        Self {
            chain: Chain::new(config(), root(), Verifier).unwrap(),
            bodies: BTreeMap::new(),
        }
    }
    pub(crate) fn add(&mut self, parent: Hash, extra: &[Vec<u8>]) -> Hash {
        let b = candidate(&self.chain, parent, extra);
        self.accept_block(b)
    }
    fn accept_block(&mut self, b: Block) -> Hash {
        let bytes = crate::wire::encode(&b, &config().limits, &Verifier).unwrap();
        let id = self
            .chain
            .submit_checked(b, 2_000_000, &mut crate::tests::FixturePow::default())
            .unwrap()
            .id;
        self.bodies.insert(id, bytes);
        id
    }
    pub(crate) fn to(&mut self, height: u64) {
        while self.chain.height() < height {
            self.add(self.chain.tip(), &[]);
        }
    }
    pub(crate) fn proof(&self, id: Hash) -> Vec<u8> {
        proof_script_with(&self.chain, id, &operator(), |h| {
            self.bodies.get(&h).cloned().ok_or(Error::Storage)
        })
        .unwrap()
    }
    pub(crate) fn prepare_collateral(&mut self) -> (OutPoint, OutPoint) {
        self.to(500);
        let inputs: Vec<_> = self
            .chain
            .ledger
            .coins
            .iter()
            .filter(|(_, c)| {
                c.value != Amount::ZERO
                    && (!c.coinbase
                        || (self.chain.height() + 1).saturating_sub(c.created_height)
                            >= config().coinbase_maturity)
            })
            .map(|(p, _)| *p)
            .collect();
        assert!(inputs.len() >= 100);
        let script = owner_script(&PublicKey::from_secret_key(&owner()).serialize());
        let funding = raw(
            0,
            &inputs,
            &[
                (COLLATERAL_ATOMS, script.clone()),
                (4 * ATOMS_PER_COIN, script.clone()),
                (0, script),
            ],
        );
        let funding_id = tx(&funding).unwrap().0.id;
        self.add(self.chain.tip(), &[funding]);
        let collateral = OutPoint {
            transaction: funding_id,
            index: 0,
        };
        let fee = OutPoint {
            transaction: funding_id,
            index: 1,
        };
        (collateral, fee)
    }
    pub(crate) fn register(&mut self) -> (Hash, OutPoint, OutPoint) {
        let (collateral, fee) = self.prepare_collateral();
        let script = owner_script(&PublicKey::from_secret_key(&owner()).serialize());
        let packet = registration_script(
            config().chain_id,
            root().id,
            collateral,
            &owner(),
            PublicKey::from_secret_key(&operator()).serialize(),
        )
        .unwrap();
        let reg = raw(0, &[fee], &[(3 * ATOMS_PER_COIN, script), (0, packet)]);
        let id = tx(&reg).unwrap().0.id;
        self.add(self.chain.tip(), &[reg]);
        (
            id,
            collateral,
            OutPoint {
                transaction: id,
                index: 0,
            },
        )
    }
    pub(crate) fn proof_tx(&self, fee: OutPoint, packet: Vec<u8>) -> Vec<u8> {
        let coin = self.chain.ledger().coin(&fee).unwrap();
        raw(
            0,
            &[fee],
            &[(coin.value.atoms(), coin.script.clone()), (0, packet)],
        )
    }
}

#[test]
fn accumulated_service_pauses_on_miss_rejects_replay_and_reorgs() {
    let mut m = Model::new();
    let (id, collateral, mut fee) = m.register();
    let e = m.chain.ledger().service_entry(&id).unwrap();
    assert!(e.next_start >= e.registered_height + 99);
    assert_eq!(e.credited_seconds, 0);
    assert!(!e.mature_for_block(e.registered_height + 99));
    assert!(e.mature_for_block(e.registered_height + 100));
    assert!(
        m.chain
            .ledger()
            .coin(&OutPoint {
                transaction: id,
                index: 1
            })
            .is_none()
    );
    let mut inflated = e.clone();
    inflated.credited_seconds = 1;
    assert!(!inflated.valid());
    assert!(proof_script_with(&m.chain, id, &operator(), |_| Err(Error::Storage)).is_err());
    for period in 0..8 {
        let e = m.chain.ledger().service_entry(&id).unwrap().clone();
        let end = e.next_start + PERIOD_BLOCKS;
        if period == 2 {
            let before = e.credited_seconds;
            m.to(end);
            let late = m.proof(id);
            m.to(end + RESPONSE_BLOCKS);
            let late = m.proof_tx(fee, late);
            let b = candidate(&m.chain, m.chain.tip(), &[late]);
            assert!(
                m.chain
                    .submit_checked(b, 2_000_000, &mut crate::tests::FixturePow::default())
                    .is_err()
            );
            m.to(end + RESPONSE_BLOCKS + 1);
            let e = m.chain.ledger().service_entry(&id).unwrap();
            assert_eq!(e.credited_seconds, before);
            assert_eq!(e.score.penalty(), 66);
            continue;
        }
        m.to(end);
        if period == 1 {
            m.to(end + RESPONSE_BLOCKS - 1);
        }
        if period == 0 {
            // Identical pre-fork sample bytes must not permit challenge replay.
            let old = m.proof(id);
            let parent = m.chain.ancestor(m.chain.tip(), end - 1).unwrap();
            let mut fork = candidate(&m.chain, parent, &[]);
            fork.header.nonce[0] = 1;
            let side = m.accept_block(fork);
            m.add(side, &[]);
            let old = m.proof_tx(fee, old);
            let b = candidate(&m.chain, m.chain.tip(), &[old]);
            assert!(
                m.chain
                    .submit_checked(b, 2_000_000, &mut crate::tests::FixturePow::default())
                    .is_err()
            );
        }
        let before = m.chain.tip();
        let packet = m.proof(id);
        let reg_before = m.chain.ledger().service_entry(&id).unwrap().clone();
        let mut bad = packet.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        let bad = m.proof_tx(fee, bad);
        let block = candidate(&m.chain, before, &[bad]);
        assert!(
            m.chain
                .submit_checked(block, 2_000_000, &mut crate::tests::FixturePow::default())
                .is_err()
        );
        assert_eq!(m.chain.ledger().service_entry(&id), Some(&reg_before));
        let zero = *m
            .chain
            .ledger
            .coins
            .iter()
            .find(|(_, c)| {
                c.value == Amount::ZERO && m.chain.height() + 1 - c.created_height >= 100
            })
            .unwrap()
            .0;
        let duplicate = raw(
            0,
            &[zero],
            &[(0, owner_script(&reg_before.owner)), (0, packet.clone())],
        );
        let original = m.proof_tx(fee, packet.clone());
        let block = candidate(&m.chain, before, &[original, duplicate]);
        assert!(
            m.chain
                .submit_checked(block, 2_000_000, &mut crate::tests::FixturePow::default())
                .is_err()
        );
        assert_eq!(m.chain.ledger().service_entry(&id), Some(&reg_before));
        let mut forged = payload(&packet).unwrap().unwrap();
        forged.truncate(forged.len() - 64);
        forged[83] ^= 1;
        let forged = finish_script(forged, config().chain_id, root().id, &operator()).unwrap();
        let forged = m.proof_tx(fee, forged);
        let block = candidate(&m.chain, before, &[forged]);
        assert!(
            m.chain
                .submit_checked(block, 2_000_000, &mut crate::tests::FixturePow::default())
                .is_err()
        );
        assert_eq!(m.chain.ledger().service_entry(&id), Some(&reg_before));
        let record = m.proof_tx(fee, packet.clone());
        let txid = tx(&record).unwrap().0.id;
        m.add(before, &[record]);
        fee = OutPoint {
            transaction: txid,
            index: 0,
        };
        let credited = m
            .chain
            .ledger()
            .service_entry(&id)
            .unwrap()
            .credited_seconds;
        assert_eq!(
            credited,
            ((period + 1 - u64::from(period > 2)) * 86400).min(QUALIFY_SECONDS)
        );
        let replay = m.proof_tx(fee, packet);
        let block = candidate(&m.chain, m.chain.tip(), &[replay]);
        assert!(
            m.chain
                .submit_checked(block, 2_000_000, &mut crate::tests::FixturePow::default())
                .is_err()
        );
    }
    assert!(
        m.chain
            .ledger()
            .service_entry(&id)
            .unwrap()
            .qualified(m.chain.height())
    );
    assert!(!m.chain.ledger().service_entry(&id).unwrap().qualified(0));
    let common = m.chain.tip();
    let previous = m.chain.ledger().service_entry(&id).unwrap().clone();
    let spend = raw(
        0,
        &[collateral],
        &[(COLLATERAL_ATOMS, owner_script(&previous.owner))],
    );
    m.add(common, &[spend]);
    assert!(m.chain.ledger().service_entry(&id).is_none());
    let side = m.add(common, &[]);
    m.add(side, &[]);
    assert_eq!(m.chain.ledger().service_entry(&id), Some(&previous));
    assert!(m.chain.ledger().coin(&collateral).is_some());
    // Current proof expiry prevents stale service records from remaining qualified.
    let deadline = previous.last_proven_end.unwrap() + PERIOD_BLOCKS + RESPONSE_BLOCKS;
    m.to(deadline + 1);
    assert!(
        !m.chain
            .ledger()
            .service_entry(&id)
            .unwrap()
            .qualified(m.chain.height())
    );
}

#[test]
fn registration_owner_domain_collateral_and_encoding_are_fail_closed() {
    let mut m = Model::new();
    let (collateral, fee) = m.prepare_collateral();
    let operator_key = PublicKey::from_secret_key(&operator()).serialize();
    for packet in [
        registration_script([99; 32], root().id, collateral, &owner(), operator_key).unwrap(),
        registration_script(
            config().chain_id,
            [99; 32],
            collateral,
            &owner(),
            operator_key,
        )
        .unwrap(),
        registration_script(
            config().chain_id,
            root().id,
            collateral,
            &operator(),
            PublicKey::from_secret_key(&owner()).serialize(),
        )
        .unwrap(),
        registration_script(config().chain_id, root().id, fee, &owner(), operator_key).unwrap(),
    ] {
        let record = m.proof_tx(fee, packet);
        let block = candidate(&m.chain, m.chain.tip(), &[record]);
        assert!(
            m.chain
                .submit_checked(block, 2_000_000, &mut crate::tests::FixturePow::default())
                .is_err()
        );
        assert_eq!(m.chain.ledger().service_count(), 0);
    }
    let script = registration_script(
        config().chain_id,
        root().id,
        collateral,
        &owner(),
        operator_key,
    )
    .unwrap();
    let valid = m.proof_tx(fee, script.clone());
    let id = tx(&valid).unwrap().0.id;
    m.add(m.chain.tip(), &[valid]);
    let next_fee = OutPoint {
        transaction: id,
        index: 0,
    };
    let duplicate = m.proof_tx(next_fee, script.clone());
    let block = candidate(&m.chain, m.chain.tip(), &[duplicate]);
    assert!(
        m.chain
            .submit_checked(block, 2_000_000, &mut crate::tests::FixturePow::default())
            .is_err()
    );
    let simultaneous = raw(
        0,
        &[collateral, next_fee],
        &[
            (
                COLLATERAL_ATOMS + 4 * ATOMS_PER_COIN,
                owner_script(&PublicKey::from_secret_key(&owner()).serialize()),
            ),
            (0, script.clone()),
        ],
    );
    let block = candidate(&m.chain, m.chain.tip(), &[simultaneous]);
    assert!(
        m.chain
            .submit_checked(block, 2_000_000, &mut crate::tests::FixturePow::default())
            .is_err()
    );
    for n in 3..script.len() {
        assert!(payload(&script[..n]).is_err() || payload(&script[..n]).unwrap().is_none());
    }
    let mut changed = script.clone();
    changed.push(0);
    assert!(payload(&changed).is_err());
    let p = payload(&script).unwrap().unwrap();
    let mut nonminimal = vec![0x6a, 0x4d];
    nonminimal.extend((p.len() as u16).to_le_bytes());
    nonminimal.extend(p);
    assert!(payload(&nonminimal).is_err());
    assert!(payload(&[0x6a, 1, 0x51]).unwrap().is_none());
}

#[test]
fn owner_controls_rotation_replay_and_reorg_restore_operator() {
    let mut m = Model::new();
    let (id, _, fee) = m.register();
    let before = m.chain.ledger().service_entry(&id).unwrap().clone();
    let new_key = SecretKey::from_secret_bytes([9; 32]).unwrap();
    let acceptance = rotation_authorization(&m.chain, id, &new_key).unwrap();
    assert!(control_script(&m.chain, &acceptance, &operator()).is_err());
    let packet = control_script(&m.chain, &acceptance, &owner()).unwrap();
    let mut bad = packet.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert!(m.chain.check_service_intent(&bad, &[]).is_err());
    let parent = m.chain.tip();
    let raw = m.proof_tx(fee, packet.clone());
    m.add(parent, &[raw]);
    let after = m.chain.ledger().service_entry(&id).unwrap();
    assert_eq!(
        after.operator,
        PublicKey::from_secret_key(&new_key).serialize()
    );
    assert_eq!(after.credited_seconds, before.credited_seconds);
    assert_eq!(after.next_start, before.next_start);
    assert!(m.chain.check_service_intent(&packet, &[]).is_err());
    assert!(control_script(&m.chain, &acceptance, &owner()).is_err());
    let fork = m.add(parent, &[]);
    m.add(fork, &[]);
    assert_eq!(m.chain.ledger().service_entry(&id), Some(&before));
    assert!(m.chain.check_service_intent(&packet, &[]).is_ok());
}

#[test]
fn reactivation_requires_owner_fresh_archive_and_preserves_credit() {
    let mut m = Model::new();
    let (id, _, fee) = m.register();
    let end = m.chain.ledger().service_entry(&id).unwrap().next_start + PERIOD_BLOCKS;
    m.to(end);
    let packet = m.proof(id);
    let raw = m.proof_tx(fee, packet);
    let fee = OutPoint {
        transaction: tx(&raw).unwrap().0.id,
        index: 0,
    };
    m.add(m.chain.tip(), &[raw]);
    // Fixture establishes a genuine sticky ban using population-based failures;
    // all reactivation signatures, archive paths and branch checks remain real.
    let mut banned = m.chain.ledger().service_entry(&id).unwrap().clone();
    banned.score.punish_failure(1);
    banned.score.punish_failure(1);
    assert!(banned.score.banned());
    m.chain.ledger.set_service(id, Some(banned.clone()));
    assert!(
        reactivation_authorization_with(&m.chain, id, &operator(), |_| Err(Error::Storage))
            .is_err()
    );
    let next_end = banned.next_start + PERIOD_BLOCKS;
    m.to(next_end);
    let acceptance = reactivation_authorization_with(&m.chain, id, &operator(), |h| {
        m.bodies.get(&h).cloned().ok_or(Error::Storage)
    })
    .unwrap();
    assert!(control_script(&m.chain, &acceptance, &operator()).is_err());
    assert!(
        reactivation_authorization_with(
            &m.chain,
            id,
            &SecretKey::from_secret_bytes([9; 32]).unwrap(),
            |_| Err(Error::Storage)
        )
        .is_err()
    );
    assert!(
        reactivation_authorization_with(&m.chain, id, &operator(), |h| {
            let mut b = m.bodies[&h].clone();
            b[0] ^= 1;
            Ok(b)
        })
        .is_err()
    );
    for index in [81, 115] {
        let mut forged = acceptance[..acceptance.len() - 64].to_vec();
        forged[index] ^= 1;
        let signature = ecdsa::sign(
            Message::from_digest(signed_hash(config().chain_id, root().id, &forged)),
            &operator(),
        );
        forged.extend(signature.serialize_compact());
        let forged = finish_script(forged, config().chain_id, root().id, &owner()).unwrap();
        assert!(m.chain.check_service_intent(&forged, &[]).is_err());
    }
    let packet = control_script(&m.chain, &acceptance, &owner()).unwrap();
    let before = m.chain.ledger().service_entry(&id).unwrap().clone();
    let parent = m.chain.tip();
    let raw = m.proof_tx(fee, packet.clone());
    m.add(parent, &[raw]);
    let after = m.chain.ledger().service_entry(&id).unwrap();
    assert!(!after.score.banned());
    assert_eq!(after.score.penalty(), 50);
    assert_eq!(after.credited_seconds, before.credited_seconds);
    assert!(!after.qualified(m.chain.height()));
    assert!(m.chain.check_service_intent(&packet, &[]).is_err());
    let fork = m.add(parent, &[]);
    m.add(fork, &[]);
    assert_eq!(m.chain.ledger().service_entry(&id), Some(&before));
    assert!(m.chain.check_service_intent(&packet, &[]).is_ok());
}

#[test]
fn controls_reject_bad_possession_domains_conflicts_spent_collateral_and_truncation() {
    let mut m = Model::new();
    let (id, collateral, fee) = m.register();
    let key = SecretKey::from_secret_bytes([9; 32]).unwrap();
    assert!(rotation_authorization(&m.chain, id, &owner()).is_err());
    assert!(rotation_authorization(&m.chain, id, &operator()).is_err());
    let auth = rotation_authorization(&m.chain, id, &key).unwrap();
    let packet = control_script(&m.chain, &auth, &owner()).unwrap();
    for end in 0..auth.len() {
        assert!(control_script(&m.chain, &auth[..end], &owner()).is_err());
    }
    for i in [0, 7, 8, 9, 41, 73, 106, 169] {
        let mut forged = auth.clone();
        forged[i] ^= 1;
        let packet = finish_script(forged, config().chain_id, root().id, &owner()).unwrap();
        assert!(m.chain.check_service_intent(&packet, &[]).is_err());
    }
    for (chain, root) in [([99; 32], root().id), (config().chain_id, [99; 32])] {
        let foreign = finish_script(auth.clone(), chain, root, &owner()).unwrap();
        assert!(m.chain.check_service_intent(&foreign, &[]).is_err());
    }
    assert!(
        m.chain
            .check_service_intent(&packet, &[collateral])
            .is_err()
    );
    let before = m.chain.ledger().service_entry(&id).unwrap().clone();
    let raw = m.proof_tx(fee, packet.clone());
    let next = OutPoint {
        transaction: tx(&raw).unwrap().0.id,
        index: 0,
    };
    let second = raw_for_fee(next, packet);
    let block = candidate(&m.chain, m.chain.tip(), &[raw, second]);
    assert!(
        m.chain
            .submit_checked(block, 2_000_000, &mut crate::tests::FixturePow::default())
            .is_err()
    );
    assert_eq!(m.chain.ledger().service_entry(&id), Some(&before));
}
fn raw_for_fee(fee: OutPoint, packet: Vec<u8>) -> Vec<u8> {
    raw(
        0,
        &[fee],
        &[
            (
                3 * ATOMS_PER_COIN,
                owner_script(&PublicKey::from_secret_key(&owner()).serialize()),
            ),
            (0, packet),
        ],
    )
}

#[test]
fn banned_rotation_does_not_heal_penalty_or_refresh_proof_schedule() {
    let mut m = Model::new();
    let (id, _, fee) = m.register();
    let mut e = m.chain.ledger().service_entry(&id).unwrap().clone();
    e.score.punish_failure(1);
    e.score.punish_failure(1);
    m.chain.ledger.set_service(id, Some(e.clone()));
    let key = SecretKey::from_secret_bytes([9; 32]).unwrap();
    let auth = rotation_authorization(&m.chain, id, &key).unwrap();
    let packet = control_script(&m.chain, &auth, &owner()).unwrap();
    let raw = m.proof_tx(fee, packet);
    m.add(m.chain.tip(), &[raw]);
    let after = m.chain.ledger().service_entry(&id).unwrap();
    assert!(after.score.banned());
    assert_eq!(after.score.penalty(), e.score.penalty());
    assert_eq!(after.next_start, e.next_start);
    assert_eq!(after.last_proven_end, e.last_proven_end);
    assert_eq!(after.credited_seconds, e.credited_seconds);
}
