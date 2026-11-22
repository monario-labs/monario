//! Real public-seed encrypted wallets, OS proof randomness, no services or nonce search.
use super::*;
use crate::build::{self, Funding, Payment, Policy, Request};
use monario_wallet::storage::{AddressKind, Password, StorageError, WalletDirectory, WalletStore};

fn atoms(n: u64) -> Amount {
    Amount::from_atoms(n).unwrap()
}
fn pool(source: &DurableChain<V6Verifier>) -> monario_chain::mempool::Mempool {
    monario_chain::mempool::Mempool::new(
        source.chain().unwrap(),
        monario_chain::mempool::Limits {
            transactions: 100,
            bytes: 1_000_000,
            inputs: 1000,
            minimum_fee: Amount::ZERO,
        },
    )
    .unwrap()
}
#[test]
fn real_private_mempool_conflicts_confirmation_resurrection_and_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("private-pool.sqlite");
    let mut source = DurableChain::open(&path, config(), root(), V6Verifier, u64::MAX / 2).unwrap();
    let mut model = Model::new();
    model.accept(&mut source, 1, &[]);
    model.accept(&mut source, 2, &[]);
    model.accept(&mut source, 3, &[fixture("deposit")]);
    let funding = model.clone();
    let mut pending = pool(&source);
    let id = pending
        .admit(source.chain().unwrap(), fixture("transfer"))
        .unwrap();
    assert_eq!(
        pending.fee(source.chain().unwrap(), id).unwrap(),
        Some(atoms(10))
    );
    assert!(
        pending
            .admit(source.chain().unwrap(), fixture("conflict"))
            .is_err()
    );
    assert_eq!(pending.len(), 1);
    model.accept(&mut source, 4, &[fixture("transfer")]);
    pending.synchronize(&source).unwrap();
    assert!(pending.is_empty());
    let mut side = funding.clone();
    side.accept(&mut source, 4, &[]);
    side.accept(&mut source, 5, &[]);
    pending.synchronize(&source).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(
        pending
            .transactions(source.chain().unwrap())
            .unwrap()
            .next()
            .unwrap(),
        fixture("transfer")
    );
    let mut alternate = funding;
    alternate.accept(&mut source, 4, &[fixture("conflict")]);
    alternate.accept(&mut source, 5, &[]);
    alternate.accept(&mut source, 6, &[]);
    let report = pending.synchronize(&source).unwrap();
    assert_eq!(report.retained, 0);
    assert!(!report.rejected.is_empty());
    drop(pending);
    drop(source);
    let source = DurableChain::open(&path, config(), root(), V6Verifier, u64::MAX / 2).unwrap();
    let mut pending = pool(&source);
    assert!(
        pending
            .admit(source.chain().unwrap(), fixture("transfer"))
            .is_err()
    );
    assert!(pending.is_empty());
}
#[test]
fn signed_wallet_reservations_reopen_and_reorg_without_freeing_inputs() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("reserved.sqlite");
    let mut source = DurableChain::open(&path, config(), root(), V6Verifier, u64::MAX / 2).unwrap();
    let mut model = Model::new();
    model.accept(&mut source, 1, &[]);
    model.accept(&mut source, 2, &[]);
    let funding = model.clone();
    let mut w = wallet(&dir, 7, "reserved_wallet", Network::Main);
    let mut scanner = scanner(&source, 7);
    scanner.sync(&source, 100).unwrap();
    let inputs = public_inputs(&scanner, &source);
    let intent = || {
        request(
            Funding::Transparent(inputs.clone()),
            vec![payment(8, false, 90)],
            1,
            AddressKind::Transparent,
        )
    };
    let policy = Policy { max_fee: atoms(10) };
    let tx = build::construct(&source, &scanner, &mut w, intent(), &policy).unwrap();
    let token = tx.reservation;
    assert_eq!(
        w.reservations().unwrap()[&token].expose_transaction(),
        Some(tx.expose_bytes())
    );
    let checkpoint = w.checkpoint().unwrap();
    assert!(matches!(
        build::construct(&source, &scanner, &mut w, intent(), &policy),
        Err(build::Error::Wallet(StorageError::InputReserved))
    ));
    assert_eq!(w.checkpoint().unwrap(), checkpoint);
    drop(w);
    let directory = WalletDirectory::open(dir.path()).unwrap();
    let password = Password::from_bytes(b"public transaction construction test password").unwrap();
    let mut w = WalletStore::open(&directory, "reserved_wallet", &password, checkpoint).unwrap();
    assert_eq!(
        w.reservations().unwrap()[&token].expose_transaction(),
        Some(tx.expose_bytes())
    );
    let mut pending = pool(&source);
    pending
        .admit(source.chain().unwrap(), tx.expose_bytes().to_vec())
        .unwrap();
    assert_eq!(
        crate::pending::statuses(&source, &w).unwrap()[&token],
        crate::pending::Status::Pending
    );
    model.accept(&mut source, 3, &[tx.expose_bytes().to_vec()]);
    pending.synchronize(&source).unwrap();
    assert!(pending.is_empty());
    assert_eq!(
        crate::pending::statuses(&source, &w).unwrap()[&token],
        crate::pending::Status::Confirmed
    );
    let mut side = funding;
    side.accept(&mut source, 3, &[]);
    side.accept(&mut source, 4, &[]);
    scanner.sync(&source, 100).unwrap();
    pending.synchronize(&source).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(
        crate::pending::statuses(&source, &w).unwrap()[&token],
        crate::pending::Status::Pending
    );
    assert!(matches!(
        build::construct(&source, &scanner, &mut w, intent(), &policy),
        Err(build::Error::Wallet(StorageError::InputReserved))
    ));
    drop(source);
    let source = DurableChain::open(&path, config(), root(), V6Verifier, u64::MAX / 2).unwrap();
    assert_eq!(
        crate::pending::statuses(&source, &w).unwrap()[&token],
        crate::pending::Status::Pending
    );
}

#[test]
fn real_coinbase_encoder_template_fixed_nonce_and_durable_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("coinbase-template.sqlite");
    let mut source = DurableChain::open(&path, config(), root(), V6Verifier, u64::MAX / 2).unwrap();
    let chain = source.chain().unwrap();
    let receiver = monario_v6::coinbase::CoinbaseReceiver::PublicKeyHash([7; 20]);
    let template = chain
        .build_template(root().id, 1045, 2000, vec![], |plan| {
            monario_v6::coinbase::encode(plan, receiver, b"MONAR")
                .map_err(monario_chain::Error::Transaction)
        })
        .unwrap();
    assert_eq!(
        template.coinbase.miner_maximum,
        monario_monetary::subsidy(1)
    );
    assert_eq!(chain.height(), 0);
    let effects = V6Verifier
        .verify(
            &template.block.transactions[0],
            monario_chain::transactions::TransactionContext {
                height: 1,
                median_time_past: 1000,
                state: chain.ledger(),
            },
        )
        .unwrap();
    let point = OutPoint {
        transaction: effects.id,
        index: 0,
    };
    // One fixed zero nonce is verified, never searched or varied.
    source.submit(template.block, u64::MAX / 2).unwrap();
    assert_eq!(
        source.chain().unwrap().ledger().coin(&point).unwrap().value,
        monario_monetary::subsidy(1)
    );
    drop(source);
    let source = DurableChain::open(&path, config(), root(), V6Verifier, u64::MAX / 2).unwrap();
    assert_eq!(source.chain().unwrap().height(), 1);
    assert!(
        source
            .chain()
            .unwrap()
            .ledger()
            .coin(&point)
            .unwrap()
            .coinbase
    );
}

#[test]
fn real_v6_templates_match_independent_private_flow_and_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("templates.sqlite");
    let mut source = DurableChain::open(&path, config(), root(), V6Verifier, u64::MAX / 2).unwrap();
    let mut reference = Model::new();
    for (height, name, fee) in [
        (1, None, 0),
        (2, None, 0),
        (3, Some("deposit"), 10),
        (4, Some("transfer"), 10),
        (5, Some("withdrawal"), 10),
    ] {
        let transactions: Vec<_> = name.into_iter().map(fixture).collect();
        let (expected, next) = reference.candidate(height, &transactions);
        let chain = source.chain().unwrap();
        let old = chain.tip();
        let old_root = chain.ledger().shielded().root();
        let template = chain
            .build_template(old, expected.header.timestamp, 2000, transactions, |plan| {
                assert_eq!(plan.height, u64::from(height));
                assert_eq!(plan.fees, atoms(fee));
                assert_eq!(
                    plan.miner_maximum,
                    monario_monetary::subsidy(plan.height)
                        .checked_add(plan.fees)
                        .unwrap()
                );
                Ok(coinbase(height))
            })
            .unwrap();
        assert_eq!(chain.tip(), old);
        assert_eq!(chain.ledger().shielded().root(), old_root);
        assert_eq!(template.block.header, expected.header);
        assert_eq!(template.block.transactions, expected.transactions);
        let encoded =
            monario_chain::wire::encode(&template.block, &config().limits, &V6Verifier).unwrap();
        source.submit_encoded(&encoded, u64::MAX / 2).unwrap();
        reference = next;
    }
    let chain = source.chain().unwrap();
    let tip = chain.tip();
    assert!(
        chain
            .build_template(
                tip,
                1270,
                2000,
                vec![fixture("conflict")],
                |_| unreachable!()
            )
            .is_err()
    );
    assert_eq!(chain.tip(), tip);
    drop(source);
    let source = DurableChain::open(&path, config(), root(), V6Verifier, u64::MAX / 2).unwrap();
    assert_eq!(source.chain().unwrap().tip(), reference.parent);
    assert_eq!(
        source.chain().unwrap().ledger().shielded().root(),
        reference.tree.root().to_bytes()
    );
}
fn wallet(dir: &tempfile::TempDir, seed: u8, name: &str, network: Network) -> WalletStore {
    WalletStore::create(
        &WalletDirectory::open(dir.path()).unwrap(),
        name,
        Seed::from_bytes(&[seed; 32]).unwrap(),
        network,
        &Password::from_bytes(b"public transaction construction test password").unwrap(),
    )
    .unwrap()
}
fn address(seed: u8, private: bool) -> monario_address::Address {
    let seed = Seed::from_bytes(&[seed; 32]).unwrap();
    if private {
        seed.private_account(Network::Main, 0)
            .unwrap()
            .address(Scope::External, 0)
            .unwrap()
    } else {
        seed.transparent_key(Network::Main, 0, Scope::External, 0)
            .unwrap()
            .address()
    }
}
fn payment(seed: u8, private: bool, value: u64) -> Payment {
    Payment::new(address(seed, private), atoms(value), None).unwrap()
}
fn request(
    funding: Funding,
    payments: Vec<Payment>,
    fee: u64,
    change_kind: AddressKind,
) -> Request {
    Request {
        service_record: None,
        account: 0,
        funding,
        payments,
        fee: atoms(fee),
        expiry_height: 16,
        change_kind,
    }
}
fn public_inputs(s: &Scanner, source: &DurableChain<V6Verifier>) -> Vec<OutPoint> {
    s.unspent_coins(source)
        .unwrap()
        .iter()
        .filter(|(_, (_, c))| c.value != Amount::ZERO)
        .map(|(p, _)| *p)
        .collect()
}
fn mature_coinbase_inputs(s: &Scanner, source: &DurableChain<V6Verifier>) -> Vec<OutPoint> {
    let next = source.chain().unwrap().height() + 1;
    let maturity = source.coinbase_maturity().unwrap();
    s.unspent_coins(source)
        .unwrap()
        .iter()
        .filter(|(_, (_, coin))| {
            coin.coinbase
                && coin.value != Amount::ZERO
                && next
                    .checked_sub(coin.created_height)
                    .is_some_and(|age| age >= maturity)
        })
        .map(|(outpoint, _)| *outpoint)
        .collect()
}
fn private_inputs(s: &Scanner, source: &DurableChain<V6Verifier>) -> Vec<Hash> {
    s.unspent_notes(source).unwrap().keys().copied().collect()
}
fn verify(source: &DurableChain<V6Verifier>, bytes: &[u8]) -> bool {
    let c = source.chain().unwrap();
    V6Verifier
        .verify(
            bytes,
            monario_chain::transactions::TransactionContext {
                height: c.height() + 1,
                median_time_past: c.median_time_past(),
                state: c.ledger(),
            },
        )
        .is_ok()
}

#[test]
fn constructed_transparent_shielded_private_and_withdrawal_multi_input_flows_validate() {
    let dir = tempfile::tempdir().unwrap();
    let mut source = DurableChain::open(
        &dir.path().join("chain.sqlite"),
        config(),
        root(),
        V6Verifier,
        2000,
    )
    .unwrap();
    let mut alice_wallet = wallet(&dir, 7, "alice", Network::Main);
    let mut bob_wallet = wallet(&dir, 8, "bob", Network::Main);
    let mut alice = scanner(&source, 7);
    let mut bob = scanner(&source, 8);
    let mut model = Model::new();
    let policy = Policy { max_fee: atoms(10) };
    model.accept(&mut source, 1, &[]);
    model.accept(&mut source, 2, &[]);
    alice.sync(&source, 100).unwrap();
    bob.sync(&source, 100).unwrap();
    let original = public_inputs(&alice, &source);
    let tx = build::construct(
        &source,
        &alice,
        &mut alice_wallet,
        request(
            Funding::Transparent(original.clone()),
            vec![payment(8, false, 20), payment(7, false, 10)],
            1,
            AddressKind::Transparent,
        ),
        &policy,
    )
    .unwrap();
    assert_eq!(tx.change, atoms(69));
    assert_eq!(tx.fee, atoms(1));
    assert_eq!(tx.checkpoint.unwrap(), alice_wallet.checkpoint().unwrap());
    assert_eq!(format!("{tx:?}"), "Constructed([REDACTED])");
    assert!(verify(&source, tx.expose_bytes()));
    let mut tampered = tx.expose_bytes().to_vec();
    tampered[12] ^= 1;
    assert!(!verify(&source, &tampered));
    model.accept(&mut source, 3, &[tx.expose_bytes().to_vec()]);
    let stale = build::construct(
        &source,
        &alice,
        &mut alice_wallet,
        request(
            Funding::Transparent(original.clone()),
            vec![payment(8, false, 1)],
            1,
            AddressKind::Transparent,
        ),
        &policy,
    );
    assert!(matches!(stale, Err(build::Error::Scan(Error::NotSynced))));
    alice.sync(&source, 100).unwrap();
    bob.sync(&source, 100).unwrap();
    assert_balance(&alice, &source, 79, 0, 0);
    assert_balance(&bob, &source, 20, 0, 0);
    let spent = build::construct(
        &source,
        &alice,
        &mut alice_wallet,
        request(
            Funding::Transparent(original),
            vec![payment(8, false, 1)],
            1,
            AddressKind::Transparent,
        ),
        &policy,
    );
    assert!(matches!(spent, Err(build::Error::MissingInput)));
    let inputs = public_inputs(&alice, &source);
    assert_eq!(inputs.len(), 2);
    let tx = build::construct(
        &source,
        &alice,
        &mut alice_wallet,
        request(
            Funding::Transparent(inputs),
            vec![payment(8, true, 30), payment(7, true, 20)],
            2,
            AddressKind::Transparent,
        ),
        &policy,
    )
    .unwrap();
    assert_eq!(tx.change, atoms(27));
    model.accept(&mut source, 4, &[tx.expose_bytes().to_vec()]);
    alice.sync(&source, 100).unwrap();
    bob.sync(&source, 100).unwrap();
    assert_balance(&alice, &source, 27, 0, 20);
    assert_balance(&bob, &source, 20, 0, 30);
    let inputs = private_inputs(&bob, &source);
    let before = bob_wallet.checkpoint().unwrap();
    let duplicate = build::construct(
        &source,
        &bob,
        &mut bob_wallet,
        request(
            Funding::Private(vec![inputs[0], inputs[0]]),
            vec![payment(7, true, 1)],
            1,
            AddressKind::Private,
        ),
        &policy,
    );
    assert!(matches!(duplicate, Err(build::Error::DuplicateInput)));
    let invalid_witness = alice.state.notes.values().next().unwrap().witness.clone();
    let saved = bob.state.notes.get(&inputs[0]).unwrap().witness.clone();
    bob.state.notes.get_mut(&inputs[0]).unwrap().witness = invalid_witness;
    let bad = build::construct(
        &source,
        &bob,
        &mut bob_wallet,
        request(
            Funding::Private(inputs.clone()),
            vec![payment(7, true, 1)],
            1,
            AddressKind::Private,
        ),
        &policy,
    );
    assert!(matches!(bad, Err(build::Error::Scan(Error::InvalidBody))));
    bob.state.notes.get_mut(&inputs[0]).unwrap().witness = saved;
    assert_eq!(bob_wallet.checkpoint().unwrap(), before);
    let mut memo = [0; 512];
    memo[..11].copy_from_slice(b"public memo");
    let tx = build::construct(
        &source,
        &bob,
        &mut bob_wallet,
        request(
            Funding::Private(inputs),
            vec![
                Payment::new(address(7, true), atoms(12), Some(memo)).unwrap(),
                payment(8, true, 5),
            ],
            1,
            AddressKind::Private,
        ),
        &policy,
    )
    .unwrap();
    assert_eq!(tx.change, atoms(12));
    let mut tampered = tx.expose_bytes().to_vec();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(!verify(&source, &tampered));
    let parsed = Transaction::read(tx.expose_bytes(), BranchId::Nu6_3).unwrap();
    assert_eq!(parsed.ironwood_bundle().unwrap().actions().len(), 3);
    model.accept(&mut source, 5, &[tx.expose_bytes().to_vec()]);
    alice.sync(&source, 100).unwrap();
    bob.sync(&source, 100).unwrap();
    assert_balance(&alice, &source, 27, 0, 32);
    assert_balance(&bob, &source, 20, 0, 17);
    assert!(
        alice
            .unspent_notes(&source)
            .unwrap()
            .values()
            .any(|n| n.expose_memo() == &memo)
    );
    assert!(
        bob.unspent_notes(&source)
            .unwrap()
            .values()
            .any(|n| n.scope() == Scope::Internal)
    );
    let inputs = private_inputs(&alice, &source);
    assert_eq!(inputs.len(), 2);
    let tx = build::construct(
        &source,
        &alice,
        &mut alice_wallet,
        request(
            Funding::Private(inputs),
            vec![payment(8, false, 25), payment(7, false, 3)],
            1,
            AddressKind::Private,
        ),
        &policy,
    )
    .unwrap();
    assert_eq!(tx.change, atoms(3));
    model.accept(&mut source, 6, &[tx.expose_bytes().to_vec()]);
    alice.sync(&source, 100).unwrap();
    bob.sync(&source, 100).unwrap();
    assert_balance(&alice, &source, 30, 0, 3);
    assert_balance(&bob, &source, 45, 0, 17);
    let inputs = private_inputs(&bob, &source);
    assert_eq!(inputs.len(), 2);
    let before = bob_wallet.checkpoint().unwrap();
    let tx = build::construct(
        &source,
        &bob,
        &mut bob_wallet,
        request(
            Funding::Private(inputs),
            vec![payment(7, true, 15)],
            2,
            AddressKind::Private,
        ),
        &policy,
    )
    .unwrap();
    assert_eq!(tx.change, Amount::ZERO);
    assert!(tx.checkpoint.is_some());
    assert_eq!(
        bob_wallet.checkpoint().unwrap().revision,
        before.revision + 2
    );
    model.accept(&mut source, 7, &[tx.expose_bytes().to_vec()]);
    alice.sync(&source, 100).unwrap();
    bob.sync(&source, 100).unwrap();
    assert_balance(&alice, &source, 30, 0, 18);
    assert_balance(&bob, &source, 45, 0, 0);
    assert_eq!(source.chain().unwrap().ledger().supply().atoms(), 93);
}

#[test]
fn intent_ownership_fee_expiry_and_capacity_errors_do_not_reserve_change() {
    let dir = tempfile::tempdir().unwrap();
    let mut source = DurableChain::open(
        &dir.path().join("chain.sqlite"),
        config(),
        root(),
        V6Verifier,
        2000,
    )
    .unwrap();
    let mut w = wallet(&dir, 7, "alice", Network::Main);
    let mut s = scanner(&source, 7);
    let mut model = Model::new();
    model.accept(&mut source, 1, &[]);
    s.sync(&source, 100).unwrap();
    let inputs = public_inputs(&s, &source);
    let policy = Policy { max_fee: atoms(10) };
    let before = w.checkpoint().unwrap();
    let make = || {
        request(
            Funding::Transparent(inputs.clone()),
            vec![payment(8, false, 20)],
            1,
            AddressKind::Transparent,
        )
    };
    assert!(matches!(
        build::construct(&source, &s, &mut w, make(), &policy),
        Err(build::Error::ImmatureCoinbase)
    ));
    assert_eq!(w.checkpoint().unwrap(), before);
    model.accept(&mut source, 2, &[]);
    s.sync(&source, 100).unwrap();
    let mut bad = make();
    bad.fee = atoms(11);
    assert!(matches!(
        build::construct(&source, &s, &mut w, bad, &policy),
        Err(build::Error::FeeLimit)
    ));
    for expiry in [0, 1, 2, u32::MAX] {
        let mut bad = make();
        bad.expiry_height = u64::from(expiry);
        assert!(matches!(
            build::construct(&source, &s, &mut w, bad, &policy),
            Err(build::Error::Expiry)
        ));
    }
    let mut bad = make();
    bad.payments = vec![payment(8, false, 100)];
    assert!(matches!(
        build::construct(&source, &s, &mut w, bad, &policy),
        Err(build::Error::InsufficientFunds)
    ));
    let mut bad = make();
    bad.funding = Funding::Transparent(vec![inputs[0], inputs[0]]);
    assert!(matches!(
        build::construct(&source, &s, &mut w, bad, &policy),
        Err(build::Error::DuplicateInput)
    ));
    let mut bad = make();
    bad.funding = Funding::Transparent(vec![]);
    assert!(matches!(
        build::construct(&source, &s, &mut w, bad, &policy),
        Err(build::Error::ResourceLimit)
    ));
    let mut bad = make();
    bad.funding = Funding::Private(vec![[99; 32]]);
    assert!(matches!(
        build::construct(&source, &s, &mut w, bad, &policy),
        Err(build::Error::MissingInput)
    ));
    let mut bad = make();
    bad.payments = (0..32).map(|_| payment(8, false, 1)).collect();
    assert!(matches!(
        build::construct(&source, &s, &mut w, bad, &policy),
        Err(build::Error::ResourceLimit)
    ));
    let mut bad = make();
    bad.payments.clear();
    assert!(matches!(
        build::construct(&source, &s, &mut w, bad, &policy),
        Err(build::Error::Intent)
    ));
    let mut bad = make();
    bad.account = 1;
    assert!(matches!(
        build::construct(&source, &s, &mut w, bad, &policy),
        Err(build::Error::WrongKey)
    ));
    let mut bad = make();
    bad.payments = vec![
        Payment::new(
            monario_address::Address::new(Network::Test, address(8, false).receiver()),
            atoms(1),
            None,
        )
        .unwrap(),
    ];
    assert!(matches!(
        build::construct(&source, &s, &mut w, bad, &policy),
        Err(build::Error::WrongNetwork)
    ));
    let mut bad = make();
    bad.payments = vec![
        Payment::new(
            address(8, true),
            Amount::from_atoms(u64::MAX).unwrap(),
            None,
        )
        .unwrap(),
    ];
    assert!(matches!(
        build::construct(&source, &s, &mut w, bad, &policy),
        Err(build::Error::Amount)
    ));
    let mut wrong = wallet(&dir, 8, "wrong", Network::Main);
    assert!(matches!(
        build::construct(&source, &s, &mut wrong, make(), &policy),
        Err(build::Error::WrongKey)
    ));
    let mut wrong_network = wallet(&dir, 7, "wrong_network", Network::Test);
    assert!(matches!(
        build::construct(&source, &s, &mut wrong_network, make(), &policy),
        Err(build::Error::WrongNetwork)
    ));
    assert!(Payment::new(address(8, false), atoms(1), Some([0; 512])).is_err());
    assert!(Payment::new(address(8, true), Amount::ZERO, None).is_err());
    assert_eq!(w.checkpoint().unwrap(), before);
    assert_eq!(s.balance(&source, 0).unwrap().transparent.atoms(), 100);
    let p2sh = monario_address::Address::new(
        Network::Main,
        monario_address::Receiver::Transparent(monario_address::TransparentReceiver::ScriptHash(
            [42; 20],
        )),
    );
    let tx = build::construct(
        &source,
        &s,
        &mut w,
        request(
            Funding::Transparent(inputs.clone()),
            vec![Payment::new(p2sh, atoms(99), None).unwrap()],
            1,
            AddressKind::Transparent,
        ),
        &policy,
    )
    .unwrap();
    assert!(verify(&source, tx.expose_bytes()));
    assert!(tx.checkpoint.is_some());
    let parsed = Transaction::read(tx.expose_bytes(), BranchId::Nu6_3).unwrap();
    assert_eq!(
        parsed.transparent_bundle().unwrap().vout[0]
            .script_pubkey()
            .0
            .0,
        p2sh.script_pubkey().unwrap()
    );
    assert_eq!(w.checkpoint().unwrap().revision, before.revision + 2);
    w.next_address(0, Scope::Internal, AddressKind::Transparent)
        .unwrap();
    w.next_address(0, Scope::Internal, AddressKind::Transparent)
        .unwrap();
    let before = w.checkpoint().unwrap();
    assert!(matches!(
        build::construct(&source, &s, &mut w, make(), &policy),
        Err(build::Error::ChangeNotWatched)
    ));
    assert_eq!(w.checkpoint().unwrap(), before);
    let directory = WalletDirectory::open(dir.path()).unwrap();
    let password = Password::from_bytes(b"public transaction backup test password").unwrap();
    let cp = w.backup(&directory, "backup", &password).unwrap();
    let mut restored = WalletStore::recover(
        &directory, "backup", &password, cp, &directory, "restored", &password,
    )
    .unwrap();
    assert!(matches!(
        build::construct(&source, &s, &mut restored, make(), &policy),
        Err(build::Error::Wallet(
            monario_wallet::storage::StorageError::RecoveryRequired
        ))
    ));
}

fn service_coinbase(height: u32) -> Vec<u8> {
    let mut number = Vec::new();
    let mut n = height;
    while n != 0 {
        number.push(n as u8);
        n >>= 8;
    }
    if number.last().is_some_and(|b| b & 0x80 != 0) {
        number.push(0);
    }
    let mut ss = if height <= 16 {
        vec![0x50 + height as u8]
    } else {
        let mut ss = vec![number.len() as u8];
        ss.extend(number);
        ss
    };
    ss.push(0);
    let tx: TransactionData<transaction::Authorized> = TransactionData::from_parts_v6(
        BranchId::Nu6_3,
        0,
        height.into(),
        Some(tb::Bundle {
            vin: vec![tb::TxIn::from_parts(
                tb::OutPoint::new([0; 32], u32::MAX),
                Script(script::Code(ss)),
                u32::MAX,
            )],
            vout: vec![tb::TxOut::new(
                Zatoshis::from_u64(monario_monetary::subsidy(height.into()).atoms()).unwrap(),
                Script(script::Code(address(7, false).script_pubkey().unwrap())),
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
fn accept_service_block(
    source: &mut DurableChain<V6Verifier>,
    parent: Hash,
    c: &Config,
    extra: &[Vec<u8>],
) -> Hash {
    let info = source.chain().unwrap().block_info(&parent).unwrap();
    let height = info.height + 1;
    let mut transactions = vec![service_coinbase(height as u32)];
    transactions.extend_from_slice(extra);
    let ids: Vec<_> = transactions
        .iter()
        .map(|raw| {
            let tx = Transaction::read(raw.as_slice(), BranchId::Nu6_3).unwrap();
            (
                *tx.txid().as_ref(),
                tx.auth_commitment().as_bytes().try_into().unwrap(),
            )
        })
        .collect();
    let commitment = V6Verifier
        .block_commitment_with_state(info.commitment, height, &ids, info.shielded_root)
        .unwrap();
    let block = Block {
        header: Header {
            version: 1,
            parent,
            merkle_root: merkle_root(&ids.iter().map(|p| p.0).collect::<Vec<_>>()).unwrap(),
            commitment,
            timestamp: 1000 + 105 * height,
            bits: c.initial_bits,
            nonce: [0; 32],
        },
        transactions,
    };
    source.submit(block, 100000).unwrap().id
}

#[test]
fn real_v6_collateral_registration_owner_spend_reorg_and_restart() {
    use monario_chain::service;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("registration.sqlite");
    let mut c = config();
    c.coinbase_maturity = monario_chain::consensus::COINBASE_MATURITY;
    c.seed_interval = 1 << 20;
    c.limits.block_bytes = 5_000_000;
    c.limits.script_bytes = service::MAX_RECORD_BYTES + 4;
    let mut source = DurableChain::open(&path, c.clone(), root(), V6Verifier, 100000).unwrap();
    let mut w = wallet(&dir, 7, "registration_wallet", Network::Main);
    let mut s = Scanner::new(
        &source,
        Network::Main,
        vec![WatchAccount::from_seed(w.expose_seed().unwrap(), Network::Main, 0, 1, 8).unwrap()],
        Limits {
            accounts: 1,
            transparent_addresses: 16,
            unspent_coins: 1000,
            unspent_notes: 10,
        },
    )
    .unwrap();
    for _ in 0..402 {
        let parent = source.chain().unwrap().tip();
        accept_service_block(&mut source, parent, &c, &[]);
    }
    s.sync(&source, 1000).unwrap();
    let policy = Policy {
        max_fee: atoms(10_000_000),
    };
    let selected = mature_coinbase_inputs(&s, &source)
        .into_iter()
        .take(32)
        .collect();
    let mut r = request(
        Funding::Transparent(selected),
        vec![payment(7, false, 1)],
        1_000_000,
        AddressKind::Transparent,
    );
    r.expiry_height = source.chain().unwrap().height() + 20;
    let mut tx = build::construct(&source, &s, &mut w, r, &policy).unwrap();
    let parent = source.chain().unwrap().tip();
    accept_service_block(&mut source, parent, &c, &[tx.expose_bytes().to_vec()]);
    s.sync(&source, 1000).unwrap();
    let mut consolidated = OutPoint {
        transaction: tx.id,
        index: 1,
    };
    for _ in 0..4 {
        let mut inputs = vec![consolidated];
        inputs.extend(mature_coinbase_inputs(&s, &source).into_iter().take(31));
        assert_eq!(inputs.len(), 32);
        let mut consolidate = request(
            Funding::Transparent(inputs),
            vec![payment(7, false, 1)],
            1_000_000,
            AddressKind::Transparent,
        );
        consolidate.expiry_height = source.chain().unwrap().height() + 20;
        tx = build::construct(&source, &s, &mut w, consolidate, &policy).unwrap();
        let parent = source.chain().unwrap().tip();
        accept_service_block(&mut source, parent, &c, &[tx.expose_bytes().to_vec()]);
        s.sync(&source, 1000).unwrap();
        consolidated = OutPoint {
            transaction: tx.id,
            index: 1,
        };
    }
    let mut r = request(
        Funding::Transparent(vec![consolidated]),
        vec![payment(7, false, service::COLLATERAL_ATOMS)],
        1_000_000,
        AddressKind::Transparent,
    );
    r.expiry_height = source.chain().unwrap().height() + 20;
    let tx = build::construct(&source, &s, &mut w, r, &policy).unwrap();
    let collateral = OutPoint {
        transaction: tx.id,
        index: 0,
    };
    let fee = OutPoint {
        transaction: tx.id,
        index: 1,
    };
    let parent = source.chain().unwrap().tip();
    accept_service_block(&mut source, parent, &c, &[tx.expose_bytes().to_vec()]);
    s.sync(&source, 1000).unwrap();
    let owner_key = w
        .expose_seed()
        .unwrap()
        .transparent_key(Network::Main, 0, Scope::External, 0)
        .unwrap();
    let mut native_owner =
        secp256k1::SecretKey::from_secret_bytes(*owner_key.expose_secret()).unwrap();
    let operator = secp256k1::SecretKey::from_secret_bytes([2; 32]).unwrap();
    let packet = service::registration_script(
        c.chain_id,
        root().id,
        collateral,
        &native_owner,
        secp256k1::PublicKey::from_secret_key(&operator).serialize(),
    )
    .unwrap();
    native_owner.non_secure_erase();
    let mut r = request(
        Funding::Transparent(vec![fee]),
        vec![],
        1_000_000,
        AddressKind::Transparent,
    );
    r.expiry_height = source.chain().unwrap().height() + 20;
    r.service_record = Some(packet);
    let tx = build::construct(&source, &s, &mut w, r, &policy).unwrap();
    let id = tx.id;
    let parent = source.chain().unwrap().tip();
    accept_service_block(&mut source, parent, &c, &[tx.expose_bytes().to_vec()]);
    let registered = source
        .chain()
        .unwrap()
        .ledger()
        .service_entry(&id)
        .unwrap()
        .clone();
    assert_eq!(
        registered.registered_height,
        source.chain().unwrap().height()
    );
    assert_eq!(registered.collateral, collateral);
    assert_eq!(registered.credited_seconds, 0);
    assert!(
        source
            .chain()
            .unwrap()
            .ledger()
            .coin(&OutPoint {
                transaction: id,
                index: 0
            })
            .is_none()
    );
    assert!(registered.next_start >= 235);
    assert!(service::proof_script(&source, id, &operator).is_err());
    // Registration-age boundaries are exercised by the long registry test.
    // Here the owner may withdraw even before qualification; use the real v6 path.
    for _ in 0..2 {
        let parent = source.chain().unwrap().tip();
        accept_service_block(&mut source, parent, &c, &[]);
    }
    let snapshot_limits = monario_chain::storage::SnapshotLimits {
        max_entries: 10000,
        max_row_bytes: 1 << 20,
        max_bytes: 16 << 20,
    };
    let checkpoint = source.create_state_checkpoint(snapshot_limits).unwrap();
    s.sync(&source, 1000).unwrap();
    let mut r = request(
        Funding::Transparent(vec![collateral]),
        vec![payment(7, false, service::COLLATERAL_ATOMS - 1_000_000)],
        1_000_000,
        AddressKind::Transparent,
    );
    r.expiry_height = source.chain().unwrap().height() + 20;
    let tx = build::construct(&source, &s, &mut w, r, &policy).unwrap();
    let common = source.chain().unwrap().tip();
    accept_service_block(&mut source, common, &c, &[tx.expose_bytes().to_vec()]);
    assert!(
        source
            .chain()
            .unwrap()
            .ledger()
            .service_entry(&id)
            .is_none()
    );
    let side = accept_service_block(&mut source, common, &c, &[]);
    accept_service_block(&mut source, side, &c, &[]);
    assert_eq!(
        source.chain().unwrap().ledger().service_entry(&id),
        Some(&registered)
    );
    drop(source);
    let source = DurableChain::open_with_checkpoint(
        &path,
        c,
        root(),
        V6Verifier,
        100000,
        checkpoint,
        snapshot_limits,
    )
    .unwrap();
    assert_eq!(
        source.chain().unwrap().ledger().service_entry(&id),
        Some(&registered)
    );
    assert!(source.chain().unwrap().ledger().coin(&collateral).is_some());
}
