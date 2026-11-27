//! Public deterministic fixtures only. Fixed nonces are verified, never searched.
use super::*;
use monario_chain::{Config, Root, header::Header, storage::SnapshotLimits};
use zcash_primitives::transaction::{self, TransactionData};
use zcash_protocol::value::Zatoshis;
use zcash_script::script;
use zcash_transparent::{address::Script, bundle as tb};

#[path = "cache_tests.rs"]
mod cache;
#[path = "construction_tests.rs"]
mod construction;
#[path = "private_restore_tests.rs"]
mod private_restore;
#[path = "restore_tests.rs"]
mod restore;
#[path = "rollback_tests.rs"]
mod rollback;

#[path = "page_tests.rs"]
mod scan_page;

fn config() -> Config {
    Config {
        chain_id: [2; 32],
        initial_bits: 0x2100ffff,
        pow_limit_bits: 0x2100ffff,
        half_life_seconds: 3600,
        asert_from_first_block: false,
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
fn root() -> Root {
    Root {
        id: [3; 32],
        timestamp: 1000,
        commitment: [4; 32],
    }
}
fn limits() -> Limits {
    Limits {
        accounts: 128,
        transparent_addresses: 100,
        unspent_coins: 100,
        unspent_notes: 100,
    }
}
fn watch(seed: u8) -> WatchAccount {
    WatchAccount::from_seed(
        &Seed::from_bytes(&[seed; 32]).unwrap(),
        Network::Main,
        0,
        2,
        2,
    )
    .unwrap()
}
fn scanner(source: &DurableChain<V6Verifier>, seed: u8) -> Scanner {
    Scanner::new(source, Network::Main, vec![watch(seed)], limits()).unwrap()
}
fn coinbase(height: u32) -> Vec<u8> {
    assert!((1..=16).contains(&height));
    let key = Seed::from_bytes(&[7; 32])
        .unwrap()
        .transparent_key(Network::Main, 0, Scope::External, 0)
        .unwrap();
    let tx: TransactionData<transaction::Authorized> = TransactionData::from_parts_v6(
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
                Script(script::Code(key.address().script_pubkey().unwrap())),
            )],
            authorization: tb::Authorized,
        }),
        None,
        None,
        None,
    );
    let mut raw = Vec::new();
    tx.freeze().unwrap().write(&mut raw).unwrap();
    raw
}
fn fixture(name: &str) -> Vec<u8> {
    match name {
        "deposit" => include_bytes!("../../v6/tests/fixtures/spend-deposit-v6.bin").to_vec(),
        "transfer" => include_bytes!("../../v6/tests/fixtures/spend-transfer-v6.bin").to_vec(),
        "withdrawal" => include_bytes!("../../v6/tests/fixtures/spend-withdrawal-v6.bin").to_vec(),
        "conflict" => include_bytes!("../../v6/tests/fixtures/spend-conflict-v6.bin").to_vec(),
        _ => panic!("unknown public fixture"),
    }
}
#[derive(Clone)]
struct Model {
    parent: Hash,
    commitment: Hash,
    tree: CommitmentTree<MerkleHashOrchard, 32>,
}
impl Model {
    fn new() -> Self {
        Self {
            parent: root().id,
            commitment: root().commitment,
            tree: CommitmentTree::empty(),
        }
    }
    fn candidate(&self, height: u32, extra: &[Vec<u8>]) -> (Block, Self) {
        let mut transactions = vec![coinbase(height)];
        transactions.extend_from_slice(extra);
        let mut next = self.clone();
        let mut ids = Vec::new();
        for raw in &transactions {
            let tx = Transaction::read(raw.as_slice(), BranchId::Nu6_3).unwrap();
            ids.push((
                *tx.txid().as_ref(),
                tx.auth_commitment().as_bytes().try_into().unwrap(),
            ));
            if let Some(b) = tx.ironwood_bundle() {
                for a in b.actions() {
                    next.tree
                        .append(MerkleHashOrchard::from_cmx(a.cmx()))
                        .unwrap();
                }
            }
        }
        let commitment = V6Verifier
            .block_commitment_with_state(
                self.commitment,
                height.into(),
                &ids,
                next.tree.root().to_bytes(),
            )
            .unwrap();
        let header = Header {
            version: 1,
            parent: self.parent,
            merkle_root: merkle_root(&ids.iter().map(|(id, _)| *id).collect::<Vec<_>>()).unwrap(),
            commitment,
            timestamp: 1000 + 105 * u64::from(height),
            bits: config().initial_bits,
            nonce: [0; 32],
        };
        next.parent = header.id(&config().chain_id);
        next.commitment = commitment;
        (
            Block {
                header,
                transactions,
            },
            next,
        )
    }
    fn accept(&mut self, source: &mut DurableChain<V6Verifier>, height: u32, extra: &[Vec<u8>]) {
        let (block, next) = self.candidate(height, extra);
        let encoded = monario_chain::wire::encode(&block, &config().limits, &V6Verifier).unwrap();
        source.submit_encoded(&encoded, u64::MAX / 2).unwrap();
        *self = next;
    }
}
fn assert_balance(
    s: &Scanner,
    source: &DurableChain<V6Verifier>,
    transparent: u64,
    immature: u64,
    private: u64,
) {
    let b = s.balance(source, 0).unwrap();
    assert_eq!(
        (
            b.transparent.atoms(),
            b.immature_coinbase.atoms(),
            b.private.atoms()
        ),
        (transparent, immature, private)
    );
}

#[test]
fn a_cursor_below_the_source_floor_requires_a_rescan() {
    assert!(matches!(
        require_retained(17, 18),
        Err(Error::SourceHistory)
    ));
    // The floor itself is retained, and a full-history source imposes no bound.
    assert!(require_retained(18, 18).is_ok());
    assert!(require_retained(19, 18).is_ok());
    assert!(require_retained(0, 0).is_ok());
}

#[test]
fn real_chain_scans_spends_witnesses_maturity_restarts_and_deep_reorgs() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("chain.sqlite");
    let mut source = DurableChain::open(&path, config(), root(), V6Verifier, u64::MAX / 2).unwrap();
    let mut alice = scanner(&source, 7);
    let mut bob = scanner(&source, 8);
    let mut model = Model::new();
    model.accept(&mut source, 1, &[]);
    assert!(matches!(alice.balance(&source, 0), Err(Error::NotSynced)));
    assert!(alice.sync(&source, 1).unwrap().complete);
    assert_balance(&alice, &source, 0, 100, 0);
    model.accept(&mut source, 2, &[]);
    alice.sync(&source, 1).unwrap();
    assert_balance(&alice, &source, 100, 0, 0);
    model.accept(&mut source, 3, &[fixture("deposit")]);
    alice.sync(&source, 1).unwrap();
    bob.sync(&source, 100).unwrap();
    assert_balance(&alice, &source, 0, 0, 90);
    assert_balance(&bob, &source, 0, 0, 0);
    let nf = *alice.unspent_notes(&source).unwrap().keys().next().unwrap();
    let received = &alice.unspent_notes(&source).unwrap()[&nf];
    assert_eq!(received.address_index(), 0);
    assert_eq!(received.scope(), Scope::External);
    assert_eq!(received.account(), 0);
    assert_eq!(received.expose_memo(), &[0; 512]);
    assert_eq!(format!("{received:?}"), "ReceivedNote([REDACTED])");
    assert_eq!(
        alice
            .witness(&source, nf)
            .unwrap()
            .root(received.expose_note().commitment().into())
            .to_bytes(),
        source.chain().unwrap().ledger().shielded().root()
    );
    let funding = model.clone();
    model.accept(&mut source, 4, &[fixture("transfer")]);
    assert!(matches!(alice.witness(&source, nf), Err(Error::NotSynced)));
    alice.sync(&source, 100).unwrap();
    bob.sync(&source, 100).unwrap();
    assert_balance(&alice, &source, 0, 0, 0);
    assert!(matches!(
        alice.witness(&source, nf),
        Err(Error::UnknownNote)
    ));
    assert_balance(&bob, &source, 0, 0, 80);
    let bob_nf = *bob.unspent_notes(&source).unwrap().keys().next().unwrap();
    bob.witness(&source, bob_nf).unwrap();
    model.accept(&mut source, 5, &[fixture("withdrawal")]);
    alice.sync(&source, 100).unwrap();
    bob.sync(&source, 100).unwrap();
    assert_balance(&alice, &source, 70, 0, 0);
    assert_balance(&bob, &source, 0, 0, 0);
    assert_eq!(
        alice.observed_progress(&source).unwrap()[&0].private_external,
        1
    );
    let main_tip = source.chain().unwrap().tip();
    // Fresh scanners rebuild from the durable log without persisted plaintext notes.
    drop(source);
    let mut source = DurableChain::open(&path, config(), root(), V6Verifier, u64::MAX / 2).unwrap();
    let mut restored = scanner(&source, 7);
    assert!(!restored.sync(&source, 2).unwrap().complete);
    assert!(matches!(
        restored.balance(&source, 0),
        Err(Error::NotSynced)
    ));
    assert!(restored.sync(&source, 100).unwrap().complete);
    assert_balance(&restored, &source, 70, 0, 0);
    assert_eq!(
        restored.observed_progress(&source).unwrap(),
        alice.observed_progress(&source).unwrap()
    );
    let mut side = funding;
    side.accept(&mut source, 4, &[fixture("conflict")]);
    side.accept(&mut source, 5, &[]);
    assert_eq!(source.chain().unwrap().tip(), main_tip);
    assert!(!alice.sync(&source, 1).unwrap().restarted);
    side.accept(&mut source, 6, &[]);
    let progress = alice.sync(&source, 1).unwrap();
    assert!(!progress.restarted);
    assert_eq!(progress.rolled_back, 2);
    assert!(!progress.complete);
    assert_eq!(progress.height, 4);
    assert!(matches!(
        alice.unspent_coins(&source),
        Err(Error::NotSynced)
    ));
    alice.sync(&source, 100).unwrap();
    assert_eq!(bob.sync(&source, 100).unwrap().rolled_back, 2);
    assert_balance(&alice, &source, 0, 0, 0);
    assert_balance(&bob, &source, 0, 0, 79);
    assert_eq!(bob.unspent_notes(&source).unwrap().len(), 1);
    let nf = *bob.unspent_notes(&source).unwrap().keys().next().unwrap();
    bob.witness(&source, nf).unwrap();
    assert!(matches!(
        bob.witness(&source, bob_nf),
        Err(Error::UnknownNote)
    ));
    assert_eq!(
        source
            .chain()
            .unwrap()
            .route_to_tip(main_tip)
            .unwrap()
            .disconnected
            .len(),
        2
    );
    assert!(source.chain().unwrap().route_to_tip([99; 32]).is_err());
}

#[test]
fn body_authentication_rejects_changed_proof_with_unchanged_transaction_id() {
    let dir = tempfile::tempdir().unwrap();
    let source = DurableChain::open(
        &dir.path().join("chain.sqlite"),
        config(),
        root(),
        V6Verifier,
        2000,
    )
    .unwrap();
    let scanner = scanner(&source, 7);
    let mut model = Model::new();
    let mut state = State::empty(root().id);
    for height in 1..=3 {
        let extra = if height == 3 {
            vec![fixture("deposit")]
        } else {
            vec![]
        };
        let (mut block, next) = model.candidate(height, &extra);
        let info = BlockInfo {
            parent: Some(model.parent),
            height: height.into(),
            commitment: next.commitment,
            shielded_root: next.tree.root().to_bytes(),
        };
        if height == 3 {
            let original =
                Transaction::read(block.transactions[1].as_slice(), BranchId::Nu6_3).unwrap();
            // Binding signature mutation preserves the effects txid and block merkle root.
            let last = block.transactions[1].len() - 1;
            block.transactions[1][last] ^= 1;
            let changed =
                Transaction::read(block.transactions[1].as_slice(), BranchId::Nu6_3).unwrap();
            assert_eq!(original.txid(), changed.txid());
            let mut staged = state.clone();
            assert!(matches!(
                scanner.scan_block(&mut staged, &block, next.parent, info, model.commitment),
                Err(Error::InvalidBody)
            ));
            assert_eq!(state.tip, model.parent);
            block.transactions[1][last] ^= 1;
        }
        scanner
            .scan_block(&mut state, &block, next.parent, info, model.commitment)
            .unwrap();
        model = next;
    }
    assert_eq!(state.notes.len(), 1);
}

#[test]
fn capacity_batch_failure_is_atomic_and_descriptor_boundaries_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("chain.sqlite");
    let mut source = DurableChain::open(&path, config(), root(), V6Verifier, u64::MAX / 2).unwrap();
    let mut tiny = limits();
    tiny.unspent_coins = 1;
    let mut s = Scanner::new(&source, Network::Main, vec![watch(7)], tiny).unwrap();
    let mut model = Model::new();
    model.accept(&mut source, 1, &[]);
    model.accept(&mut source, 2, &[]);
    assert!(matches!(s.sync(&source, 2), Err(Error::Capacity)));
    assert_eq!(s.state.tip, root().id);
    assert!(s.state.coins.is_empty());
    assert!(s.sync(&source, 1).is_ok());
    assert_eq!(s.state.height, 1);
    assert!(matches!(s.sync(&source, 1), Err(Error::Capacity)));
    assert_eq!(s.state.height, 1);
    assert!(matches!(s.sync(&source, 0), Err(Error::Configuration)));
    assert!(Scanner::new(&source, Network::Main, vec![watch(7), watch(7)], limits()).is_err());
    assert!(Scanner::new(&source, Network::Test, vec![watch(7)], limits()).is_err());
    assert!(Scanner::new(&source, Network::Main, vec![], limits()).is_err());
    assert!(
        WatchAccount::from_seed(
            &Seed::from_bytes(&[7; 32]).unwrap(),
            Network::Main,
            0,
            10001,
            0
        )
        .is_err()
    );
    assert!(
        WatchAccount::from_seed(
            &Seed::from_bytes(&[7; 32]).unwrap(),
            Network::Main,
            1 << 31,
            0,
            0
        )
        .is_err()
    );
    let mut c = config();
    c.coinbase_maturity = 3;
    let other = DurableChain::open(
        &dir.path().join("other.sqlite"),
        c,
        root(),
        V6Verifier,
        2000,
    )
    .unwrap();
    assert!(matches!(s.sync(&other, 10), Err(Error::WrongChain)));
    assert!(source.stored_block(root().id).is_err());
    assert!(source.stored_block([99; 32]).is_err());
}

#[test]
fn checkpoint_skipped_body_corruption_is_detected_before_wallet_commit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("chain.sqlite");
    let mut source = DurableChain::open(&path, config(), root(), V6Verifier, u64::MAX / 2).unwrap();
    let mut model = Model::new();
    model.accept(&mut source, 1, &[]);
    model.accept(&mut source, 2, &[]);
    model.accept(&mut source, 3, &[fixture("deposit")]);
    let snapshot_limits = SnapshotLimits {
        max_entries: 10000,
        max_row_bytes: 1 << 20,
        max_bytes: 16 << 20,
    };
    let trusted = source.create_state_checkpoint(snapshot_limits).unwrap();
    drop(source);
    let db = rusqlite::Connection::open(&path).unwrap();
    let mut body: Vec<u8> = db
        .query_row("SELECT data FROM blocks WHERE seq=3", [], |r| r.get(0))
        .unwrap();
    let last = body.len() - 1;
    body[last] ^= 1;
    db.execute("UPDATE blocks SET data=?1 WHERE seq=3", [body])
        .unwrap();
    drop(db);
    let source = DurableChain::open_with_checkpoint(
        &path,
        config(),
        root(),
        V6Verifier,
        2000,
        trusted,
        snapshot_limits,
    )
    .unwrap();
    let mut s = scanner(&source, 7);
    assert!(s.sync(&source, 100).is_err());
    assert_eq!(s.state.tip, root().id);
    assert!(s.state.coins.is_empty());
    assert!(matches!(s.balance(&source, 0), Err(Error::NotSynced)));
}

#[test]
fn unspent_note_witness_advances_over_other_wallet_outputs() {
    let dir = tempfile::tempdir().unwrap();
    let source = DurableChain::open(
        &dir.path().join("chain.sqlite"),
        config(),
        root(),
        V6Verifier,
        2000,
    )
    .unwrap();
    let scanner = scanner(&source, 7);
    let mut state = State::empty(root().id);
    let mut model = Model::new();
    // Unit-test the projection kernel with authenticated metadata supplied here.
    // Full consensus acceptance is exercised separately by the real-chain test.
    for height in 1..=4 {
        let extra = match height {
            3 => vec![fixture("deposit")],
            // This older public fixture pays an unrelated raw spending key,
            // not the domain-separated Monario wallet watched by this scanner.
            4 => vec![include_bytes!("../../v6/tests/fixtures/private-v6.bin").to_vec()],
            _ => vec![],
        };
        let (block, next) = model.candidate(height, &extra);
        let info = BlockInfo {
            parent: Some(model.parent),
            height: height.into(),
            commitment: next.commitment,
            shielded_root: next.tree.root().to_bytes(),
        };
        scanner
            .scan_block(&mut state, &block, next.parent, info, model.commitment)
            .unwrap();
        model = next;
        if height >= 3 {
            assert_eq!(state.notes.len(), 1);
            let received = state.notes.values().next().unwrap();
            assert_eq!(received.witness.root(), state.tree.root());
            assert_eq!(u64::from(received.witness.witnessed_position()), 0);
        }
    }
    assert_eq!(state.tree.size(), 2);
}

#[test]
fn crash_worker() {
    let Some(path) = std::env::var_os("MONAR_SCAN_CRASH_CHAIN") else {
        return;
    };
    let batch: usize = std::env::var("MONAR_SCAN_CRASH_BATCH")
        .unwrap()
        .parse()
        .unwrap();
    assert!([0, 1, 100].contains(&batch));
    let source = DurableChain::open(
        std::path::Path::new(&path),
        config(),
        root(),
        V6Verifier,
        2000,
    )
    .unwrap();
    let mut s = scanner(&source, 7);
    if batch != 0 {
        s.sync(&source, batch).unwrap();
    }
    // Exit without destructors, before scanning, after a partial batch, or after
    // the complete in-memory projection. No wallet-derived data is persisted.
    std::process::exit(83);
}

#[test]
fn process_death_before_partial_and_complete_scan_rebuilds_from_durable_chain() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("chain.sqlite");
    let mut source = DurableChain::open(&path, config(), root(), V6Verifier, u64::MAX / 2).unwrap();
    let mut model = Model::new();
    model.accept(&mut source, 1, &[]);
    model.accept(&mut source, 2, &[]);
    model.accept(&mut source, 3, &[fixture("deposit")]);
    drop(source);
    for batch in ["0", "1", "100"] {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "tests::crash_worker", "--nocapture"])
            .env("MONAR_SCAN_CRASH_CHAIN", &path)
            .env("MONAR_SCAN_CRASH_BATCH", batch)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(83));
        let source = DurableChain::open(&path, config(), root(), V6Verifier, u64::MAX / 2).unwrap();
        assert_eq!(source.chain().unwrap().tip(), model.parent);
        let mut s = scanner(&source, 7);
        assert!(s.sync(&source, 100).unwrap().complete);
        assert_balance(&s, &source, 0, 0, 90);
        let nf = *s.unspent_notes(&source).unwrap().keys().next().unwrap();
        s.witness(&source, nf).unwrap();
    }
}
