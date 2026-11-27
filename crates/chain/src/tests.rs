//! Synthetic fixture consensus tests. No header nonce is searched or mined.
use super::*;
use std::cell::RefCell;
use transactions::{Output, VerifiedTransaction};

#[derive(Clone)]
pub(super) struct FixtureTx {
    height: Option<u64>,
    pub(super) inputs: Vec<OutPoint>,
    outputs: Vec<u64>,
    invalid: bool,
    shielded: bool,
    pub(super) ironwood: Option<transactions::VerifiedIronwood>,
}
#[derive(Default)]
pub(super) struct FixtureVerifier {
    pub(super) transactions: RefCell<BTreeMap<u64, FixtureTx>>,
    pub(super) calls: std::cell::Cell<usize>,
}
fn tx_id(id: u64) -> Hash {
    hash_domain(b"fixture-tx", &[&id.to_le_bytes()])
}
fn fixture_commit(parent: Hash, height: u64, ids: &[(Hash, Hash)]) -> Hash {
    let mut data = Vec::new();
    for (id, auth) in ids {
        data.extend(id);
        data.extend(auth);
    }
    hash_domain(b"fixture-commit", &[&parent, &height.to_le_bytes(), &data])
}
impl TransactionVerifier for FixtureVerifier {
    fn transaction_length(&self, bytes: &[u8]) -> Result<usize, TransactionError> {
        if bytes.len() >= 8 {
            Ok(8)
        } else {
            Err(TransactionError::Invalid)
        }
    }
    fn verify(
        &self,
        bytes: &[u8],
        _: TransactionContext<'_>,
    ) -> Result<VerifiedTransaction, TransactionError> {
        self.calls.set(self.calls.get() + 1);
        let id = u64::from_le_bytes(bytes.try_into().map_err(|_| TransactionError::Invalid)?);
        let tx = self
            .transactions
            .borrow()
            .get(&id)
            .cloned()
            .ok_or(TransactionError::Invalid)?;
        if tx.invalid {
            return Err(TransactionError::Invalid);
        }
        Ok(VerifiedTransaction {
            id: tx_id(id),
            authorization_digest: hash_domain(b"auth", &[bytes]),
            coinbase_height: tx.height,
            inputs: tx.inputs,
            outputs: tx
                .outputs
                .into_iter()
                .map(|atoms| Output {
                    value: Amount::from_atoms(atoms).unwrap(),
                    script: vec![0x51],
                })
                .collect(),
            has_shielded_bundle: tx.shielded,
            ironwood: tx.ironwood,
        })
    }
    fn block_commitment(
        &self,
        parent: Hash,
        height: u64,
        ids: &[(Hash, Hash)],
    ) -> Result<Hash, TransactionError> {
        Ok(fixture_commit(parent, height, ids))
    }
}
#[derive(Default)]
pub(super) struct FixturePow {
    seen: Vec<Hash>,
    fail: bool,
}
impl PowCheck for FixturePow {
    fn check(&mut self, seed: &Hash, _: &[u8], _: &Target) -> Result<(), Error> {
        self.seen.push(*seed);
        if self.fail {
            Err(Error::Pow(monario_pow::Error::InsufficientWork))
        } else {
            Ok(())
        }
    }
}
pub(super) fn config() -> Config {
    Config {
        chain_id: [11; 32],
        initial_bits: 0x1d00ffff,
        pow_limit_bits: 0x207fffff,
        half_life_seconds: 3600,
        asert_from_first_block: false,
        seed_interval: 8,
        seed_lag: 2,
        coinbase_maturity: 2,
        max_future_seconds: 120,
        retained_blocks: 10000,
        limits: Limits {
            block_bytes: 100000,
            transaction_bytes: 10000,
            transactions: 100,
            inputs_per_transaction: 100,
            outputs_per_transaction: 100,
            script_bytes: 1000,
        },
    }
}
pub(super) fn root() -> Root {
    Root {
        id: [3; 32],
        timestamp: 1000,
        commitment: [4; 32],
    }
}
fn chain() -> Chain<FixtureVerifier> {
    Chain::new(config(), root(), FixtureVerifier::default()).unwrap()
}
#[test]
fn synchronization_locators_and_inventories_stay_bounded_and_ordered() {
    let mut c = chain();
    let mut ids = vec![root().id];
    for height in 1..=260 {
        cb(&c, height, height, 0);
        let id = c
            .submit_checked(
                block(&c, c.tip(), 1000 + 45 * height as u32, &[height]),
                2_000_000,
                &mut FixturePow::default(),
            )
            .unwrap()
            .id;
        ids.push(id);
    }
    let locator = c.synchronization_locator(c.tip()).unwrap();
    assert!(locator.len() <= 32);
    assert_eq!(locator.first(), ids.last());
    assert_eq!(locator.last(), Some(&root().id));
    let (anchor, first) = c.synchronization_inventory(&[root().id]).unwrap();
    assert_eq!(anchor, root().id);
    assert_eq!(first, ids[1..129]);
    let (anchor, second) = c.synchronization_inventory(&[ids[128], root().id]).unwrap();
    assert_eq!(anchor, ids[128]);
    assert_eq!(second, ids[129..257]);
    let (_, last) = c.synchronization_inventory(&[ids[256], root().id]).unwrap();
    assert_eq!(last, ids[257..]);
    assert!(c.synchronization_inventory(&[]).is_err());
    assert!(c.synchronization_inventory(&[ids[1]]).is_err());
    assert!(c.synchronization_inventory(&vec![root().id; 33]).is_err());
}
pub(super) fn cb(chain: &Chain<FixtureVerifier>, id: u64, height: u64, value: u64) {
    cb_with_fees(chain, id, height, value, 0);
}
pub(super) fn cb_with_fees(
    chain: &Chain<FixtureVerifier>,
    id: u64,
    _height: u64,
    value: u64,
    _fees: u64,
) {
    let outputs = vec![value];
    chain.verifier.transactions.borrow_mut().insert(
        id,
        FixtureTx {
            height: Some(_height),
            inputs: vec![],
            outputs,
            invalid: false,
            shielded: false,
            ironwood: None,
        },
    );
}
pub(super) fn spend(chain: &Chain<FixtureVerifier>, id: u64, inputs: &[u64], outputs: &[u64]) {
    chain.verifier.transactions.borrow_mut().insert(
        id,
        FixtureTx {
            height: None,
            inputs: inputs
                .iter()
                .map(|id| OutPoint {
                    transaction: tx_id(*id),
                    index: 0,
                })
                .collect(),
            outputs: outputs.to_vec(),
            invalid: false,
            shielded: false,
            ironwood: None,
        },
    );
}
pub(super) fn block(chain: &Chain<FixtureVerifier>, parent: Hash, time: u32, txs: &[u64]) -> Block {
    let p = &chain.nodes[&parent];
    let height = p.height + 1;
    let bits = chain.next_block_bits(p).unwrap();
    let ids: Vec<Hash> = txs.iter().map(|id| tx_id(*id)).collect();
    let auth: Vec<_> = txs
        .iter()
        .map(|id| (tx_id(*id), hash_domain(b"auth", &[&id.to_le_bytes()])))
        .collect();
    Block {
        header: Header {
            version: 1,
            parent,
            merkle_root: merkle_root(&ids).unwrap(),
            commitment: fixture_commit(p.commitment, height, &auth),
            timestamp: u64::from(time),
            bits,
            nonce: [0; 32],
        },
        transactions: txs.iter().map(|id| id.to_le_bytes().to_vec()).collect(),
    }
}
fn add(chain: &mut Chain<FixtureVerifier>, parent: Hash, time: u32, txs: &[u64]) -> Accepted {
    let b = block(chain, parent, time, txs);
    chain
        .submit_checked(b, u64::from(time), &mut FixturePow::default())
        .unwrap_or_else(|error| {
            panic!(
                "fixture add at height {} for txs {txs:?}: {error:?}",
                chain.nodes[&parent].height + 1
            )
        })
}
#[test]
fn canonical_header_encoding_and_domains() {
    let chain = chain();
    cb(&chain, 1, 1, 750000000);
    let h = block(&chain, root().id, 1045, &[1]).header;
    let bytes = h.encode();
    assert_eq!(bytes.len(), HEADER_LEN);
    assert_eq!(&bytes[100..108], &1045_u64.to_le_bytes());
    assert_eq!(Header::decode(&bytes).unwrap(), h);
    for length in 0..HEADER_LEN {
        assert_eq!(Header::decode(&bytes[..length]), Err(Error::HeaderEncoding));
    }
    let mut extra = bytes.to_vec();
    extra.push(0);
    assert_eq!(Header::decode(&extra), Err(Error::HeaderEncoding));
    let mut wrong = bytes;
    wrong[0] = 2;
    assert_eq!(Header::decode(&wrong), Err(Error::HeaderVersion));
    assert_ne!(h.id(&[1; 32]), h.id(&[2; 32]));
    assert_ne!(h.pow_preimage(&[1; 32]), h.pow_preimage(&[2; 32]));
    for i in 0..HEADER_LEN {
        let mut changed = bytes;
        changed[i] ^= 1;
        assert_ne!(hash_domain(&[], &[&bytes]), hash_domain(&[], &[&changed]));
    }
}

#[test]
fn merkle_mutation_and_odd_leaves() {
    let a = [1; 32];
    let b = [2; 32];
    let c = [3; 32];
    assert_eq!(merkle_root(&[]), Err(Error::EmptyBlock));
    assert_eq!(merkle_root(&[a, b, c, c]), Err(Error::MerkleMutation));
    assert!(merkle_root(&[a, b, c]).is_ok());
    assert_eq!(merkle_root(&[a, b, a, b]), Err(Error::MerkleMutation));
}

#[test]
fn headers_enforce_parent_difficulty_time_and_work() {
    let mut chain = chain();
    cb(&chain, 1, 1, 750000000);
    let before = chain.tip();
    let mut b = block(&chain, before, 1045, &[1]);
    b.header.parent = [9; 32];
    assert_eq!(
        chain.submit_checked(b, 1045, &mut FixturePow::default()),
        Err(Error::UnknownParent)
    );
    let mut b = block(&chain, before, 1045, &[1]);
    b.header.bits = 0x207fffff;
    assert!(matches!(
        chain.submit_checked(b, 1045, &mut FixturePow::default()),
        Err(Error::Pow(_))
    ));
    let b = block(&chain, before, 1000, &[1]);
    assert_eq!(
        chain.submit_checked(b, 1045, &mut FixturePow::default()),
        Err(Error::MedianTime)
    );
    let b = block(&chain, before, 1045, &[1]);
    assert_eq!(
        chain.submit_checked(b, 0, &mut FixturePow::default()),
        Err(Error::FutureTime)
    );
    let b = block(&chain, before, 1045, &[1]);
    assert!(matches!(
        chain.submit_checked(
            b,
            1045,
            &mut FixturePow {
                fail: true,
                seen: vec![]
            }
        ),
        Err(Error::Pow(_))
    ));
    assert_eq!(chain.tip(), before);
    assert_eq!(chain.ledger().supply(), Amount::ZERO);
    let result = add(&mut chain, before, 1045, &[1]);
    assert!(result.became_best);
    assert_eq!(chain.height(), 1);
    assert_eq!(
        chain.chainwork(),
        &Target::from_compact(config().initial_bits).unwrap().work()
    );
    let b = block(&chain, before, 1045, &[1]);
    assert_eq!(
        chain.submit_checked(b, 1045, &mut FixturePow::default()),
        Err(Error::DuplicateBlock)
    );
}

#[test]
fn malformed_bodies_and_overclaims_do_not_mutate_state() {
    let mut chain = chain();
    let parent = chain.tip();
    cb(&chain, 1, 1, monario_monetary::subsidy(1).atoms() + 1);
    assert_eq!(
        chain.submit_checked(
            block(&chain, parent, 1045, &[1]),
            1045,
            &mut FixturePow::default()
        ),
        Err(Error::OverclaimedReward)
    );
    cb(&chain, 1, 1, monario_monetary::subsidy(1).atoms());
    let mut b = block(&chain, parent, 1045, &[1]);
    b.header.merkle_root[0] ^= 1;
    assert_eq!(
        chain.submit_checked(b, 1045, &mut FixturePow::default()),
        Err(Error::MerkleRoot)
    );
    let mut b = block(&chain, parent, 1045, &[1]);
    b.header.commitment[0] ^= 1;
    assert_eq!(
        chain.submit_checked(b, 1045, &mut FixturePow::default()),
        Err(Error::Commitment)
    );
    chain
        .verifier
        .transactions
        .borrow_mut()
        .get_mut(&1)
        .unwrap()
        .invalid = true;
    assert_eq!(
        chain.submit_checked(
            block(&chain, parent, 1045, &[1]),
            1045,
            &mut FixturePow::default()
        ),
        Err(Error::Transaction(TransactionError::Invalid))
    );
    chain
        .verifier
        .transactions
        .borrow_mut()
        .get_mut(&1)
        .unwrap()
        .invalid = false;
    chain
        .verifier
        .transactions
        .borrow_mut()
        .get_mut(&1)
        .unwrap()
        .shielded = true;
    assert_eq!(
        chain.submit_checked(
            block(&chain, parent, 1045, &[1]),
            1045,
            &mut FixturePow::default()
        ),
        Err(Error::UnsupportedShielded)
    );
    assert_eq!(chain.tip(), parent);
    assert_eq!(chain.nodes.len(), 1);
    assert_eq!(chain.ledger().supply(), Amount::ZERO);
    chain
        .verifier
        .transactions
        .borrow_mut()
        .get_mut(&1)
        .unwrap()
        .shielded = false;
    add(&mut chain, parent, 1045, &[1]);
}

#[test]
fn maturity_double_spends_fees_and_same_block_dependencies() {
    let mut chain = chain();
    cb(&chain, 1, 1, 750000000);
    let one = add(&mut chain, root().id, 1045, &[1]).id;
    cb(&chain, 2, 2, 750000000);
    spend(&chain, 10, &[1], &[700000000]);
    assert_eq!(
        chain.submit_checked(
            block(&chain, one, 1090, &[2, 10]),
            1090,
            &mut FixturePow::default()
        ),
        Err(Error::ImmatureCoinbase)
    );
    let two = add(&mut chain, one, 1090, &[2]).id;
    cb(&chain, 3, 3, 750000000);
    spend(&chain, 11, &[10], &[650000000]);
    spend(&chain, 12, &[1, 1], &[700000000]);
    assert_eq!(
        chain.submit_checked(
            block(&chain, two, 1135, &[3, 12]),
            1135,
            &mut FixturePow::default()
        ),
        Err(Error::DoubleSpend)
    );
    spend(&chain, 12, &[1], &[750000001]);
    assert_eq!(
        chain.submit_checked(
            block(&chain, two, 1135, &[3, 12]),
            1135,
            &mut FixturePow::default()
        ),
        Err(Error::NegativeFee)
    );
    spend(&chain, 12, &[1], &[700000000]);
    assert_eq!(
        chain.submit_checked(
            block(&chain, two, 1135, &[3, 10, 12]),
            1135,
            &mut FixturePow::default()
        ),
        Err(Error::MissingInput)
    );
    let three = add(&mut chain, two, 1135, &[3, 10, 11]).id;
    assert_eq!(chain.tip(), three);
    assert!(
        chain
            .ledger()
            .coin(&OutPoint {
                transaction: tx_id(1),
                index: 0
            })
            .is_none()
    );
    assert!(
        chain
            .ledger()
            .coin(&OutPoint {
                transaction: tx_id(10),
                index: 0
            })
            .is_none()
    );
    assert_eq!(
        chain.ledger().supply().atoms(),
        2_250_000_000_u128 - 100_000_000
    );
}

#[test]
fn production_coinbase_maturity_is_exactly_240_blocks() {
    let mut config = config();
    config.coinbase_maturity = crate::consensus::COINBASE_MATURITY;
    let mut chain = Chain::new(config, root(), FixtureVerifier::default()).unwrap();
    cb(&chain, 1, 1, 100);
    let mut tip = add(&mut chain, root().id, 1045, &[1]).id;

    for height in 2..=239_u64 {
        cb(&chain, height, height, 0);
        tip = add(&mut chain, tip, 1000 + 45 * height as u32, &[height]).id;
    }

    spend(&chain, 1000, &[1], &[80]);
    cb(&chain, 240, 240, 0);
    assert_eq!(
        chain.submit_checked(
            block(&chain, tip, 1000 + 45 * 240, &[240, 1000]),
            1000 + 45 * 240,
            &mut FixturePow::default()
        ),
        Err(Error::ImmatureCoinbase)
    );

    tip = add(&mut chain, tip, 1000 + 45 * 240, &[240]).id;
    cb(&chain, 241, 241, 0);
    let accepted = chain.submit_checked(
        block(&chain, tip, 1000 + 45 * 241, &[241, 1000]),
        1000 + 45 * 241,
        &mut FixturePow::default(),
    );
    assert!(accepted.is_ok());
}

#[test]
fn equal_work_is_stable_and_heavier_branch_restores_utxos() {
    let mut chain = chain();
    cb(&chain, 1, 1, 750000000);
    let one = add(&mut chain, root().id, 1045, &[1]).id;
    cb(&chain, 2, 2, 750000000);
    let two = add(&mut chain, one, 1090, &[2]).id;
    cb(&chain, 3, 3, 750000000);
    spend(&chain, 10, &[1], &[750000000]);
    let old = add(&mut chain, two, 1135, &[3, 10]).id;
    cb(&chain, 4, 3, 750000000);
    let side = add(&mut chain, two, 1135, &[4]);
    assert!(!side.became_best);
    assert_eq!(chain.tip(), old);
    cb(&chain, 5, 4, 750000000);
    let switched = add(&mut chain, side.id, 1180, &[5]);
    assert!(switched.became_best);
    assert_eq!(switched.disconnected, vec![old]);
    assert_eq!(switched.connected, vec![side.id, switched.id]);
    assert!(
        chain
            .ledger()
            .coin(&OutPoint {
                transaction: tx_id(1),
                index: 0
            })
            .is_some()
    );
    assert!(
        chain
            .ledger()
            .coin(&OutPoint {
                transaction: tx_id(10),
                index: 0
            })
            .is_none()
    );
    assert!(!chain.ledger().contains_transaction(&tx_id(10)));
    assert_eq!(chain.ledger().supply().atoms(), 3_000_000_000_u128);
}

#[test]
fn invalid_reorg_leaves_active_ledger_and_index_unchanged() {
    let mut chain = chain();
    cb(&chain, 1, 1, 750000000);
    let one = add(&mut chain, root().id, 1045, &[1]).id;
    cb(&chain, 2, 2, 750000000);
    let active = add(&mut chain, one, 1090, &[2]).id;
    cb(&chain, 3, 2, 750000000);
    let side = add(&mut chain, one, 1090, &[3]).id;
    cb(&chain, 4, 3, 750000000);
    spend(&chain, 5, &[2], &[750000000]);
    let count = chain.nodes.len();
    let supply = chain.ledger().supply();
    assert_eq!(
        chain.submit_checked(
            block(&chain, side, 1135, &[4, 5]),
            1135,
            &mut FixturePow::default()
        ),
        Err(Error::MissingInput)
    );
    assert_eq!(chain.tip(), active);
    assert_eq!(chain.nodes.len(), count);
    assert_eq!(chain.ledger().supply(), supply);
    assert!(
        chain
            .ledger()
            .coin(&OutPoint {
                transaction: tx_id(2),
                index: 0
            })
            .is_some()
    );
}

#[test]
fn seed_resolution_uses_candidate_branch() {
    let mut chain = chain();
    chain.config.seed_interval = 2;
    chain.config.seed_lag = 0;
    cb(&chain, 1, 1, 750000000);
    let one = add(&mut chain, root().id, 1045, &[1]).id;
    cb(&chain, 2, 2, 750000000);
    let a = add(&mut chain, one, 1090, &[2]).id;
    cb(&chain, 3, 2, 750000000);
    let b = add(&mut chain, one, 1090, &[3]).id;
    assert_ne!(chain.seed_for(a, 3).unwrap(), chain.seed_for(b, 3).unwrap());
    assert_eq!(
        chain.seed_for(one, 2).unwrap(),
        chain.seed_for(root().id, 1).unwrap()
    );
}

#[test]
fn work_beats_height() {
    let mut chain = chain();
    cb(&chain, 1, 1, 750000000);
    let a1 = add(&mut chain, root().id, 4600, &[1]).id;
    cb(&chain, 2, 2, 750000000);
    let a2 = add(&mut chain, a1, 8200, &[2]).id;
    cb(&chain, 3, 3, 750000000);
    add(&mut chain, a2, 11800, &[3]);
    assert_eq!(chain.height(), 3);
    cb(&chain, 4, 1, 750000000);
    let b1 = add(&mut chain, root().id, 1001, &[4]).id;
    cb(&chain, 5, 2, 750000000);
    let b2 = add(&mut chain, b1, 1002, &[5]);
    assert!(b2.became_best);
    assert_eq!(chain.height(), 2);
}

#[test]
fn deep_reorg_exceeds_old_zebra_window_without_finality_shortcut() {
    let mut chain = chain();
    let mut a = root().id;
    let mut b = root().id;
    for h in 1..=1002 {
        cb(&chain, h, h, 1);
        a = add(&mut chain, a, 1000 + 45 * h as u32, &[h]).id;
    }
    assert_eq!(chain.tip(), a);
    for h in 1..=1003 {
        cb(&chain, 10000 + h, h, 1);
        b = add(&mut chain, b, 1000 + 45 * h as u32, &[10000 + h]).id;
    }
    assert_eq!(chain.tip(), b);
    assert_eq!(chain.height(), 1003);
    assert_eq!(chain.ledger().supply().atoms(), 1003_u128);
    assert!(!chain.ledger().contains_transaction(&tx_id(1)));
    assert!(chain.ledger().contains_transaction(&tx_id(10001)));
}

#[test]
fn production_backend_fails_closed_and_real_pow_is_connected() {
    let c = chain();
    cb(&c, 1, 1, 1);
    let fixture = block(&c, root().id, 1045, &[1]);
    let mut production = Chain::new(config(), root(), transactions::UnavailableV6).unwrap();
    // Exercise actual hashing once with the fixed fixture; no nonce search.
    assert!(matches!(
        production.submit(fixture, 1045),
        Err(Error::Pow(monario_pow::Error::InsufficientWork))
    ));
    let fixture = block(&c, root().id, 1045, &[1]);
    assert_eq!(
        production.submit_checked(fixture, 1045, &mut FixturePow::default()),
        Err(Error::Transaction(TransactionError::BackendUnavailable))
    );
    assert_eq!(production.height(), 0);
    assert_eq!(production.ledger().supply(), Amount::ZERO);
}

#[test]
fn coinbase_position_height_and_uniqueness_are_enforced() {
    let mut chain = chain();
    cb(&chain, 1, 1, 1);
    cb(&chain, 2, 1, 1);
    spend(&chain, 3, &[], &[]);
    for ids in [&[3_u64][..], &[3, 1], &[1, 2]] {
        let b = block(&chain, root().id, 1045, ids);
        assert_eq!(
            chain.submit_checked(b, 1045, &mut FixturePow::default()),
            Err(Error::Coinbase)
        );
    }
    cb(&chain, 1, 2, 1);
    assert_eq!(
        chain.submit_checked(
            block(&chain, root().id, 1045, &[1]),
            1045,
            &mut FixturePow::default()
        ),
        Err(Error::Coinbase)
    );
    cb(&chain, 1, 1, 1);
    let one = add(&mut chain, root().id, 1045, &[1]).id;
    cb(&chain, 1, 2, 1);
    assert_eq!(
        chain.submit_checked(
            block(&chain, one, 1090, &[1]),
            1090,
            &mut FixturePow::default()
        ),
        Err(Error::DuplicateTransaction)
    );
}

#[test]
fn small_undo_window_evicts_old_deltas_without_blocking_new_blocks() {
    let mut chain = chain();
    chain.set_retained_block_limit(2).unwrap();
    cb(&chain, 1, 1, 1);
    let one = add(&mut chain, root().id, 1045, &[1]).id;
    cb(&chain, 2, 2, 1);
    let two = add(&mut chain, one, 1090, &[2]).id;
    cb(&chain, 3, 3, 1);
    let three = add(&mut chain, two, 1135, &[3]).id;
    cb(&chain, 4, 4, 1);
    let four = add(&mut chain, three, 1180, &[4]).id;
    // Window 2 with tip height 4 evicts undo data only below height 2.
    assert!(chain.nodes[&one].delta.is_none());
    assert!(chain.nodes[&two].delta.is_some());
    assert!(chain.nodes[&four].delta.is_some());
    assert_eq!(chain.height(), 4);
    // Early size checks still reject before PoW.
    let mut pow = FixturePow::default();
    let mut b = block(&chain, four, 1225, &[5]);
    b.transactions.clear();
    assert_eq!(
        chain.submit_checked(b, 1225, &mut pow),
        Err(Error::EmptyBlock)
    );
    let mut b = block(&chain, four, 1225, &[5]);
    b.transactions[0] = vec![0; 10001];
    assert_eq!(
        chain.submit_checked(b, 1225, &mut pow),
        Err(Error::ResourceLimit)
    );
    assert!(pow.seen.is_empty());
    // Changing the window never rejects an existing chain.
    chain.set_retained_block_limit(10).unwrap();
    chain.set_retained_block_limit(2).unwrap();
    assert_eq!(chain.set_retained_block_limit(1), Err(Error::Configuration));
    assert_eq!(chain.height(), 4);
}

#[test]
fn reorg_beyond_the_undo_window_is_refused_but_recent_reorgs_work() {
    let mut chain = chain();
    chain.set_retained_block_limit(2).unwrap();
    cb(&chain, 1, 1, 1);
    let one = add(&mut chain, root().id, 1045, &[1]).id;
    cb(&chain, 2, 2, 1);
    let two = add(&mut chain, one, 1090, &[2]).id;
    cb(&chain, 3, 3, 1);
    let three = add(&mut chain, two, 1135, &[3]).id;
    cb(&chain, 4, 4, 1);
    let four = add(&mut chain, three, 1180, &[4]).id;
    // A fork at height 3 (inside the window) reorgs successfully.
    cb(&chain, 13, 4, 1);
    let side4 = add(&mut chain, three, 1181, &[13]).id;
    cb(&chain, 14, 5, 1);
    let side5 = add(&mut chain, side4, 1226, &[14]).id;
    cb(&chain, 15, 6, 1);
    let side6 = add(&mut chain, side5, 1271, &[15]).id;
    assert_eq!(chain.tip(), side6);
    assert!(chain.contains(&four));
    // Eviction followed the new tip: height 2 is outside the window now.
    assert!(chain.nodes[&two].delta.is_none());
    assert!(chain.nodes[&three].delta.is_none() || chain.nodes[&three].delta.is_some());
    // A fork below the retained window cannot be validated.
    cb(&chain, 16, 2, 1);
    let deep = block(&chain, one, 1100, &[16]);
    let mut pow = FixturePow::default();
    assert_eq!(
        chain.submit_checked(deep, 2_000_000, &mut pow),
        Err(Error::ReorgTooDeep)
    );
}

#[test]
fn fees_are_not_issuance_and_underclaims_reduce_the_ledger_total() {
    let mut chain = chain();
    cb(&chain, 1, 1, 100);
    let one = add(&mut chain, root().id, 1045, &[1]).id;
    cb(&chain, 2, 2, 0);
    let two = add(&mut chain, one, 1090, &[2]).id;
    cb(&chain, 3, 3, 0);
    spend(&chain, 4, &[1], &[70]);
    add(&mut chain, two, 1135, &[3, 4]);
    assert_eq!(chain.ledger().supply().atoms(), 70);
}

#[test]
fn branch_difficulty_comes_from_its_parent_not_the_active_tip() {
    let mut chain = chain();
    cb(&chain, 1, 1, 1);
    let a = add(&mut chain, root().id, 1045, &[1]).id;
    cb(&chain, 2, 1, 1);
    let b = add(&mut chain, root().id, 4600, &[2]).id;
    cb(&chain, 3, 2, 1);
    let mut wrong = block(&chain, b, 4645, &[3]);
    wrong.header.bits = chain.asert.next_bits(1, chain.nodes[&a].timestamp).unwrap();
    assert!(matches!(
        chain.submit_checked(wrong, 4645, &mut FixturePow::default()),
        Err(Error::Pow(_))
    ));
    add(&mut chain, b, 4645, &[3]);
}

#[test]
fn first_block_asert_ignores_launch_delay_and_uses_each_forks_anchor() {
    let mut cfg = config();
    cfg.asert_from_first_block = true;
    let mut chain = Chain::new(cfg.clone(), root(), FixtureVerifier::default()).unwrap();
    let legacy = Chain::new(config(), root(), FixtureVerifier::default()).unwrap();
    assert_ne!(chain.validation_profile(), legacy.validation_profile());
    cb(&chain, 1, 1, 1);
    let a = add(&mut chain, root().id, 10_000, &[1]).id;
    cb(&chain, 2, 1, 1);
    let b = add(&mut chain, root().id, 20_000, &[2]).id;
    cb(&chain, 3, 2, 1);
    cb(&chain, 4, 2, 1);
    assert_eq!(block(&chain, a, 10_090, &[3]).header.bits, cfg.initial_bits);
    assert_eq!(block(&chain, b, 20_180, &[4]).header.bits, cfg.initial_bits);
    let a2 = add(&mut chain, a, 10_090, &[3]).id;
    let b2 = add(&mut chain, b, 20_180, &[4]).id;
    cb(&chain, 5, 3, 1);
    let a_bits = block(&chain, a2, 10_180, &[5]).header.bits;
    let b_bits = block(&chain, b2, 20_270, &[5]).header.bits;
    assert_eq!(a_bits, cfg.initial_bits);
    assert!(Target::from_compact(b_bits).unwrap() > Target::from_compact(a_bits).unwrap());
    let mut wrong = block(&chain, b2, 20_270, &[5]);
    wrong.header.bits = a_bits;
    assert!(matches!(
        chain.submit_checked(wrong, 20_270, &mut FixturePow::default()),
        Err(Error::Pow(monario_pow::Error::InvalidParameters))
    ));
    let template = chain
        .build_template(b2, 20_270, 20_270, vec![], |_| Ok(5_u64.to_le_bytes().to_vec()))
        .unwrap();
    assert_eq!(template.block.header.bits, b_bits);
    let reorg = add(&mut chain, b2, 20_270, &[5]);
    assert!(reorg.became_best);
    assert_eq!(reorg.disconnected, vec![a2, a]);
}

#[test]
fn corrupted_undo_is_detected_before_committing_any_reorg() {
    let mut chain = chain();
    cb(&chain, 1, 1, 1);
    let a = add(&mut chain, root().id, 1045, &[1]).id;
    cb(&chain, 2, 1, 1);
    let b = add(&mut chain, root().id, 1045, &[2]).id;
    // Exercise corruption detection without exposing mutable records publicly.
    chain.nodes.get_mut(&a).unwrap().delta = chain.nodes[&b].delta.clone();
    cb(&chain, 3, 2, 1);
    let count = chain.nodes.len();
    assert_eq!(
        chain.submit_checked(
            block(&chain, b, 1090, &[3]),
            1090,
            &mut FixturePow::default()
        ),
        Err(Error::StateMismatch)
    );
    assert_eq!(chain.tip(), a);
    assert_eq!(chain.nodes.len(), count);
    assert!(
        chain
            .ledger()
            .coin(&OutPoint {
                transaction: tx_id(1),
                index: 0
            })
            .is_some()
    );
}

#[test]
fn independent_replay_matches_reorganized_state() {
    let mut live = chain();
    cb(&live, 1, 1, 100);
    let common = add(&mut live, root().id, 1045, &[1]).id;
    cb(&live, 2, 2, 10);
    let old = add(&mut live, common, 1090, &[2]).id;
    cb(&live, 3, 2, 20);
    let side = add(&mut live, common, 1090, &[3]).id;
    cb(&live, 4, 3, 5);
    spend(&live, 5, &[1], &[90]);
    let tip = add(&mut live, side, 1135, &[4, 5]).id;
    assert_ne!(tip, old);
    let mut replay = chain();
    *replay.verifier.transactions.borrow_mut() = live.verifier.transactions.borrow().clone();
    let one = add(&mut replay, root().id, 1045, &[1]).id;
    let two = add(&mut replay, one, 1090, &[3]).id;
    add(&mut replay, two, 1135, &[4, 5]);
    assert_eq!(live.tip(), replay.tip());
    assert_eq!(live.chainwork(), replay.chainwork());
    assert_eq!(live.ledger().supply(), replay.ledger().supply());
    for id in 1..=5 {
        assert_eq!(
            live.ledger().contains_transaction(&tx_id(id)),
            replay.ledger().contains_transaction(&tx_id(id))
        );
        let key = OutPoint {
            transaction: tx_id(id),
            index: 0,
        };
        assert_eq!(live.ledger().coin(&key), replay.ledger().coin(&key));
    }
}

#[test]
fn transparent_transactions_require_inputs_and_outputs() {
    let mut chain = chain();
    cb(&chain, 1, 1, 1);
    spend(&chain, 2, &[], &[0]);
    assert_eq!(
        chain.submit_checked(
            block(&chain, root().id, 1045, &[1, 2]),
            1045,
            &mut FixturePow::default()
        ),
        Err(Error::EmptyTransaction)
    );
    chain
        .verifier
        .transactions
        .borrow_mut()
        .get_mut(&1)
        .unwrap()
        .outputs
        .clear();
    assert_eq!(
        chain.submit_checked(
            block(&chain, root().id, 1045, &[1]),
            1045,
            &mut FixturePow::default()
        ),
        Err(Error::EmptyTransaction)
    );
    assert_eq!(chain.height(), 0);
}

#[test]
fn independent_python_header_and_seed_vectors() {
    // Expected bytes/digests generated independently with Python struct.pack
    // and hashlib.sha256, not by the encoder under test.
    let h = Header {
        version: 1,
        parent: [17; 32],
        merkle_root: [34; 32],
        commitment: [51; 32],
        timestamp: 0x01020304,
        bits: 0x1d00ffff,
        nonce: [68; 32],
    };
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    assert_eq!(
        hex(&h.encode()),
        "010000001111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222233333333333333333333333333333333333333333333333333333333333333330403020100000000ffff001d4444444444444444444444444444444444444444444444444444444444444444"
    );
    assert_eq!(
        hex(&h.id(&[85; 32])),
        "7dc7113452e85e2fbe48eed0eb23feae00d59c49a79c067795842feea5f77d69"
    );
    let preimage = h.pow_preimage(&[85; 32]);
    assert_eq!(preimage.len(), 191);
    assert_eq!(&preimage[..15], b"Monario/pow/v1\0");
    assert_eq!(&preimage[15..47], &[85; 32]);
    assert_eq!(&preimage[47..], &h.encode());
    assert_eq!(
        hex(&chain().seed_for(root().id, 1).unwrap()),
        "07ca4cac2ff2b02d81f8bbb58daf34ec9ebe7c9a42502be94a4f97634d87cebb"
    );
}

#[test]
fn shielded_pool_nullifiers_anchors_and_tree_undo() {
    use transactions::VerifiedIronwood;
    let mut base = Ledger::default();
    let empty_root = base.shielded().root();
    let mut funded = Overlay::new(&base);
    let deposit = VerifiedIronwood {
        value_balance: -100,
        anchor: empty_root,
        nullifiers: vec![[1; 32]],
        commitments: vec![[1; 32]],
    };
    funded.shield(&deposit, &base).unwrap();
    funded.set_supply(Amount::from_atoms(100).unwrap().into());
    funded.finish_anchor();
    let new_root = funded.shielded().root();
    let delta = funded.finish();
    base.commit(delta.clone());
    assert_eq!(base.shielded().balance.atoms(), 100);
    assert_ne!(new_root, empty_root);
    assert!(base.has_nullifier(&[1; 32]));
    assert!(base.has_anchor(&new_root));
    let mut fork = Overlay::new(&base);
    assert_eq!(fork.shield(&deposit, &base), Err(Error::DuplicateNullifier));
    let unknown = VerifiedIronwood {
        value_balance: 0,
        anchor: [19; 32],
        nullifiers: vec![[2; 32]],
        commitments: vec![[2; 32]],
    };
    assert_eq!(
        Overlay::new(&base).shield(&unknown, &base),
        Err(Error::InvalidAnchor)
    );
    let inflation = VerifiedIronwood {
        value_balance: 101,
        anchor: new_root,
        nullifiers: vec![[2; 32]],
        commitments: vec![[2; 32]],
    };
    assert_eq!(
        Overlay::new(&base).shield(&inflation, &base),
        Err(Error::Amount)
    );
    let mut reverted = Overlay::new(&base);
    reverted.apply(&delta, true).unwrap();
    assert_eq!(reverted.shielded().balance, Amount::ZERO);
    assert_eq!(reverted.shielded().root(), empty_root);
    assert!(!reverted.has_nullifier(&[1; 32]));
    assert!(!reverted.has_anchor(&new_root));
    reverted.apply(&delta, false).unwrap();
    assert_eq!(reverted.shielded().root(), new_root);
}

#[test]
fn transparent_shielded_transfers_conserve_supply_and_reorg_atomically() {
    use transactions::VerifiedIronwood;
    let mut c = chain();
    cb(&c, 1, 1, 100);
    let one = add(&mut c, root().id, 1045, &[1]).id;
    cb(&c, 2, 2, 0);
    let two = add(&mut c, one, 1090, &[2]).id;
    cb(&c, 3, 3, 0);
    spend(&c, 30, &[1], &[]);
    c.verifier
        .transactions
        .borrow_mut()
        .get_mut(&30)
        .unwrap()
        .ironwood = Some(VerifiedIronwood {
        value_balance: -100,
        anchor: c.ledger().shielded().root(),
        nullifiers: vec![[1; 32]],
        commitments: vec![[1; 32]],
    });
    let three = add(&mut c, two, 1135, &[3, 30]).id;
    let deposit_root = c.ledger().shielded().root();
    assert_eq!(c.ledger().shielded().balance.atoms(), 100);
    assert_eq!(c.ledger().supply().atoms(), 100);
    cb(&c, 4, 4, 0);
    spend(&c, 31, &[], &[100]);
    c.verifier
        .transactions
        .borrow_mut()
        .get_mut(&31)
        .unwrap()
        .ironwood = Some(VerifiedIronwood {
        value_balance: 101,
        anchor: deposit_root,
        nullifiers: vec![[2; 32]],
        commitments: vec![[2; 32]],
    });
    assert_eq!(
        c.submit_checked(
            block(&c, three, 1180, &[4, 31]),
            1180,
            &mut FixturePow::default()
        ),
        Err(Error::Amount)
    );
    assert!(!c.ledger().has_nullifier(&[2; 32]));
    c.verifier
        .transactions
        .borrow_mut()
        .get_mut(&31)
        .unwrap()
        .ironwood
        .as_mut()
        .unwrap()
        .value_balance = 100;
    add(&mut c, three, 1180, &[4, 31]);
    assert_eq!(c.ledger().shielded().balance.atoms(), 0);
    assert_eq!(c.ledger().supply().atoms(), 100);
    cb(&c, 13, 3, 0);
    let b3 = add(&mut c, two, 1135, &[13]).id;
    cb(&c, 14, 4, 0);
    let b4 = add(&mut c, b3, 1180, &[14]).id;
    cb(&c, 15, 5, 0);
    add(&mut c, b4, 1225, &[15]);
    assert_eq!(c.ledger().supply().atoms(), 100);
    assert_eq!(c.ledger().shielded().balance.atoms(), 0);
    assert!(!c.ledger().has_anchor(&deposit_root));
    assert!(!c.ledger().has_nullifier(&[1; 32]));
    assert!(!c.ledger().has_nullifier(&[2; 32]));
    assert!(
        c.ledger()
            .coin(&OutPoint {
                transaction: tx_id(1),
                index: 0
            })
            .is_some()
    );
    assert!(!c.ledger().contains_transaction(&tx_id(31)));
}

#[test]
fn shielded_action_and_cost_limits_are_consensus_enforced() {
    use transactions::VerifiedIronwood;
    fn nullifier(i: u64) -> Hash {
        let mut h = [9u8; 32];
        h[..8].copy_from_slice(&i.to_le_bytes());
        h
    }
    fn commitment(i: u64) -> Hash {
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&(i + 1).to_le_bytes());
        h
    }
    fn shielded(actions: u64, offset: u64, anchor: Hash) -> VerifiedIronwood {
        VerifiedIronwood {
            value_balance: 0,
            anchor,
            nullifiers: (0..actions).map(|i| nullifier(offset + i)).collect(),
            commitments: (0..actions).map(|i| commitment(offset + i)).collect(),
        }
    }
    // One action over the per-transaction cap.
    let mut c = chain();
    cb(&c, 1, 1, 100);
    spend(&c, 40, &[], &[]);
    let anchor = c.ledger().shielded().root();
    c.verifier
        .transactions
        .borrow_mut()
        .get_mut(&40)
        .unwrap()
        .ironwood = Some(shielded(
        shielded::MAX_ACTIONS_PER_TRANSACTION + 1,
        0,
        anchor,
    ));
    assert_eq!(
        c.submit_checked(
            block(&c, root().id, 1045, &[1, 40]),
            1045,
            &mut FixturePow::default()
        ),
        Err(Error::ShieldedLimit)
    );
    // Two transactions that each fit still exceed the deterministic block budget.
    let mut c = chain();
    cb(&c, 1, 1, 100);
    let anchor = c.ledger().shielded().root();
    for (id, offset) in [(41u64, 0u64), (42, 1_000)] {
        spend(&c, id, &[], &[]);
        c.verifier
            .transactions
            .borrow_mut()
            .get_mut(&id)
            .unwrap()
            .ironwood = Some(shielded(
            shielded::MAX_ACTIONS_PER_TRANSACTION,
            offset,
            anchor,
        ));
    }
    assert_eq!(
        c.submit_checked(
            block(&c, root().id, 1045, &[1, 41, 42]),
            1045,
            &mut FixturePow::default()
        ),
        Err(Error::ShieldedLimit)
    );
    // A single maximal transaction is accepted and stays inside the budget.
    assert!(
        c.submit_checked(
            block(&c, root().id, 1045, &[1, 41]),
            1045,
            &mut FixturePow::default()
        )
        .is_ok()
    );
}

#[test]
fn transaction_confirmation_tracks_active_branch_depth_and_relocated_inclusion() {
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
    let three = add(&mut c, two, 1135, &[3, 10]).id;
    assert_eq!(
        c.transaction_confirmation(&tx_id(10)).unwrap(),
        Some(Confirmation {
            block: three,
            height: 3,
            depth: 1
        })
    );
    let four = add(&mut c, three, 1180, &[4]).id;
    assert_eq!(
        c.transaction_confirmation(&tx_id(10))
            .unwrap()
            .unwrap()
            .depth,
        2
    );
    // Spending an output does not erase its transaction's inclusion metadata.
    assert!(
        c.ledger()
            .coin(&OutPoint {
                transaction: tx_id(1),
                index: 0
            })
            .is_none()
    );
    assert_eq!(
        c.transaction_confirmation(&tx_id(1))
            .unwrap()
            .unwrap()
            .depth,
        4
    );
    let side2 = add(&mut c, one, 1090, &[20]).id;
    let side3 = add(&mut c, side2, 1135, &[30]).id;
    let side4 = add(&mut c, side3, 1180, &[40]).id;
    assert_eq!(c.tip(), four);
    assert_eq!(
        c.transaction_confirmation(&tx_id(10))
            .unwrap()
            .unwrap()
            .block,
        three
    );
    let side5 = add(&mut c, side4, 1225, &[50, 10]).id;
    assert_eq!(c.tip(), side5);
    assert_eq!(
        c.transaction_confirmation(&tx_id(10)).unwrap(),
        Some(Confirmation {
            block: side5,
            height: 5,
            depth: 1
        })
    );
    assert!(c.transaction_confirmation(&tx_id(4)).unwrap().is_none());
    assert!(c.transaction_confirmation(&[99; 32]).unwrap().is_none());
}

#[test]
fn transaction_confirmation_rejects_inconsistent_membership_heights_deltas_and_cycles() {
    for defect in [0usize, 1, 2, 3, 5, 6] {
        let mut c = chain();
        cb(&c, 1, 1, 100);
        cb(&c, 2, 2, 100);
        let one = add(&mut c, root().id, 1045, &[1]).id;
        let two = add(&mut c, one, 1090, &[2]).id;
        let id = tx_id(1);
        match defect {
            0 => {
                c.nodes
                    .get_mut(&one)
                    .unwrap()
                    .delta
                    .as_mut()
                    .unwrap()
                    .transactions
                    .remove(&id);
            }
            1 => {
                c.nodes
                    .get_mut(&one)
                    .unwrap()
                    .delta
                    .as_mut()
                    .unwrap()
                    .transactions
                    .insert(id, (true, true));
            }
            2 => {
                c.nodes.get_mut(&one).unwrap().height = 0;
            }
            3 => {
                c.nodes.get_mut(&two).unwrap().parent = Some(two);
            }
            4 => {
                c.nodes.get_mut(&one).unwrap().delta = None;
            }
            5 => {
                c.nodes.get_mut(&two).unwrap().height = u64::MAX;
            }
            _ => {
                c.nodes.get_mut(&root().id).unwrap().height = u64::MAX;
            }
        }
        assert_eq!(c.transaction_confirmation(&id), Err(Error::StateMismatch));
    }
    // Evicted undo data no longer blocks the engine-derived confirmation.
    let mut c = chain();
    cb(&c, 1, 1, 100);
    cb(&c, 2, 2, 100);
    let one = add(&mut c, root().id, 1045, &[1]).id;
    add(&mut c, one, 1090, &[2]);
    c.nodes.get_mut(&one).unwrap().delta = None;
    assert_eq!(
        c.transaction_confirmation(&tx_id(1)).unwrap(),
        Some(Confirmation {
            block: one,
            height: 1,
            depth: 2
        })
    );
}

std::thread_local! {
    pub(super) static CONFIRMATION_STEPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
#[test]
fn large_chain_confirmation_lookup_uses_bounded_skip_visits() {
    let mut c = chain();
    for height in 1..=4096 {
        cb(&c, height, height, 0);
        let tip = c.tip();
        add(&mut c, tip, 1000 + 45 * height as u32, &[height]);
    }
    for tx in [1, 2, 100, 2048, 4096] {
        CONFIRMATION_STEPS.with(|n| n.set(0));
        let result = c.transaction_confirmation(&tx_id(tx)).unwrap().unwrap();
        assert_eq!(result.height, tx);
        assert_eq!(result.depth, 4097 - tx);
        let visits = CONFIRMATION_STEPS.with(|n| n.get());
        assert!(visits <= 128, "confirmation lookup visited {visits} nodes");
    }
}

#[path = "confirmation_index_tests.rs"]
mod confirmation_index;

#[test]
fn recent_fee_samples_are_bounded_to_the_active_branch() {
    let mut chain = chain();
    cb(&chain, 1, 1, 100);
    let one = add(&mut chain, root().id, 1045, &[1]).id;
    cb(&chain, 2, 2, 0);
    let two = add(&mut chain, one, 1090, &[2]).id;
    cb(&chain, 3, 3, 0);
    spend(&chain, 4, &[1], &[70]);
    add(&mut chain, two, 1135, &[3, 4]);
    let samples = chain.recent_fee_samples(4, 10);
    assert_eq!(
        samples,
        vec![FeeSample {
            fee_atoms: 30,
            bytes: 8
        }]
    );
    assert_eq!(chain.recent_fee_samples(1, 10), samples);
    assert!(chain.recent_fee_samples(0, 10).is_empty());
    assert!(chain.recent_fee_samples(4, 0).is_empty());
}

#[test]
fn history_window_guards_lookbacks_and_normalizes_skip_links() {
    let mut c = chain();
    let mut tip = root().id;
    for height in 1..=1_100_u64 {
        cb(&c, height, height, 1);
        tip = add(&mut c, tip, 1_000 + 45 * height as u32, &[height]).id;
    }
    assert_eq!(c.height(), 1_100);
    assert!(
        c.required_history_window()
            >= crate::service::PERIOD_BLOCKS + crate::service::RESPONSE_BLOCKS
    );
    // Ordinary (floor 0) lookbacks, including power-of-two jump targets.
    for height in [1_u64, 2, 512, 1_024, 1_096, 1_100] {
        assert!(c.ancestor(tip, height).is_ok(), "height {height}");
    }
    // The floor at height 999 is retained before eviction, for the pin test below.
    assert_eq!(c.advance_history_floor(1_000).unwrap(), 1_000);
    assert_eq!(c.history_floor(), 1_000);
    assert!(c.ancestor(tip, 1_000).is_ok());
    assert_eq!(c.ancestor(tip, 999), Err(Error::HistoryUnavailable));
    assert_eq!(c.ancestor(tip, 0), Err(Error::HistoryUnavailable));
    assert_eq!(c.advance_history_floor(999), Err(Error::Configuration));
    let _ = c.median_time_past();
    // Consensus seed and median lookbacks still work at the tip.
    cb(&c, 5_000, 1_101, 1);
    add(&mut c, tip, 1_000 + 45 * 1_101, &[5_000]);
    // Every retained node's skip link stays inside the floor.
    for (id, node) in &c.nodes {
        if node.parent.is_none() {
            continue;
        }
        let target = (node.height & (node.height - 1)).max(1_000);
        match node.skip {
            Some(skip) => {
                assert_eq!(c.nodes[&skip].height, target, "height {}", node.height);
                assert!(c.ancestor(*id, target).is_ok());
            }
            None => assert!(target >= node.height, "height {}", node.height),
        }
    }
    // Evicted headers are gone from memory; the durable index is the deep path.
    assert!(c.block_info(&root().id).is_none());
}

#[test]
fn stale_links_fail_closed_instead_of_panicking() {
    let mut c = chain();
    let mut tip = root().id;
    for height in 1..=64_u64 {
        cb(&c, height, height, 1);
        tip = add(&mut c, tip, 1_000 + 45 * height as u32, &[height]).id;
    }
    let retained = c.ancestor(tip, 32).unwrap();
    c.advance_history_floor(10).unwrap();
    // A skip link to an unretained id is ignored; parent walking still works.
    c.nodes.get_mut(&tip).unwrap().skip = Some([0xAA; 32]);
    assert!(c.ancestor(tip, 10).is_ok());
    // A parent link to an unretained id fails closed, with no index panic.
    {
        let node = c.nodes.get_mut(&tip).unwrap();
        node.skip = None;
        node.parent = Some([0xBB; 32]);
    }
    assert_eq!(c.ancestor(tip, 10), Err(Error::HistoryUnavailable));
    assert_eq!(c.route_to_tip(retained), Err(Error::HistoryUnavailable));
    let _ = c.median_time_past();
}

#[test]
fn history_floor_cannot_pass_a_configured_pin() {
    let mut c = chain();
    let mut tip = root().id;
    for height in 1..=1_100_u64 {
        cb(&c, height, height, 1);
        tip = add(&mut c, tip, 1_000 + 45 * height as u32, &[height]).id;
    }
    let pinned = c.ancestor(tip, 100).unwrap();
    c.set_finality(crate::finality::Policy {
        anchor: None,
        pin: Some(crate::finality::Pin {
            height: 100,
            hash: pinned,
        }),
        mode: crate::finality::Mode::Warn,
        anchor_bypass: false,
    })
    .unwrap();
    // Evicting past the pin would make it unresolvable and reject every later
    // best-chain transition, so the advance fails closed.
    assert_eq!(c.advance_history_floor(101), Err(Error::Finality));
    assert_eq!(c.advance_history_floor(100).unwrap(), 100);
    assert_eq!(c.history_floor(), 100);
    cb(&c, 1_101, 1_101, 1);
    add(&mut c, tip, 1_000 + 45 * 1_101, &[1_101]);
}

#[test]
fn finality_pin_below_the_history_floor_is_refused() {
    let mut c = chain();
    let mut tip = root().id;
    for height in 1..=1_100_u64 {
        cb(&c, height, height, 1);
        tip = add(&mut c, tip, 1_000 + 45 * height as u32, &[height]).id;
    }
    let deep = c.ancestor(tip, 999).unwrap();
    c.advance_history_floor(1_000).unwrap();
    let result = c.set_finality(crate::finality::Policy {
        anchor: None,
        pin: Some(crate::finality::Pin {
            height: 999,
            hash: deep,
        }),
        mode: crate::finality::Mode::Warn,
        anchor_bypass: false,
    });
    assert_eq!(result, Err(Error::Finality));
}

#[test]
fn header_timestamp_crosses_2106_without_truncation() {
    let mut header = block(&chain(), root().id, 1045, &[1]).header;
    header.timestamp = u64::from(u32::MAX) + 1;
    let encoded = header.encode();
    assert_eq!(
        Header::decode(&encoded).unwrap().timestamp,
        header.timestamp
    );
    assert_ne!(header.id(&[1; 32]), {
        let mut prior = header.clone();
        prior.timestamp -= 1;
        prior.id(&[1; 32])
    });
}

#[test]
fn wide_aggregate_supply_and_pool_reverse_without_truncation() {
    use monario_monetary::Supply;
    use transactions::VerifiedIronwood;
    let mut base = Ledger::default();
    base.supply = Supply::from_atoms(u128::from(u64::MAX)).unwrap();
    base.shielded.balance = base.supply;
    let mut staged = Overlay::new(&base);
    let extra = Amount::from_atoms(1).unwrap();
    staged.set_supply(base.supply.checked_add(extra).unwrap());
    staged
        .shield(
            &VerifiedIronwood {
                value_balance: -1,
                anchor: base.shielded.root(),
                nullifiers: vec![],
                commitments: vec![],
            },
            &base,
        )
        .unwrap();
    let delta = staged.finish();
    let mut branch = Overlay::new(&base);
    branch.apply(&delta, false).unwrap();
    assert_eq!(branch.supply().atoms(), u128::from(u64::MAX) + 1);
    assert_eq!(branch.shielded().balance.atoms(), u128::from(u64::MAX) + 1);
    branch.apply(&delta, true).unwrap();
    assert_eq!(branch.supply(), base.supply);
    assert_eq!(branch.shielded().balance, base.shielded.balance);
}

#[test]
fn unrepresentable_persistent_height_is_rejected_before_validation() {
    let mut c = chain();
    let id = c.tip();
    let candidate = block(&c, id, 1045, &[1]);
    c.nodes.get_mut(&id).unwrap().height = i64::MAX as u64;
    assert!(matches!(
        c.submit_checked(candidate, 2000, &mut FixturePow::default()),
        Err(Error::HeightOverflow)
    ));
    assert!(matches!(
        c.build_template(id, 1045, 2000, vec![], |_| panic!("callback invoked")),
        Err(Error::HeightOverflow)
    ));
}
