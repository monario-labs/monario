//! Offline v6 construction. Explicit funding, fees, recipients and change pool.
//! No broadcast or fee estimation. Input claims are durably reserved.
#[path = "selection.rs"]
pub mod selection;
use super::{Error as ScanError, Scanner};
use monario_address::{Address, Receiver};
use monario_chain::{
    Hash,
    ledger::OutPoint,
    storage::DurableChain,
    transactions::{TransactionContext, TransactionVerifier},
};
use monario_monetary::Amount;
use monario_v6::V6Verifier;
use monario_wallet::{
    Scope,
    storage::{AddressKind, StorageError, WalletCheckpoint, WalletStore},
};
use orchard::{
    builder::{Builder, BundleType, InProgress, Unauthorized},
    bundle::BundleVersion,
    circuit::{OrchardCircuitVersion, ProvingKey},
    keys::{FullViewingKey, SpendAuthorizingKey},
    value::NoteValue,
};
use rand::{SeedableRng, rngs::StdRng};
use std::{collections::BTreeSet, sync::OnceLock};
use zcash_primitives::transaction::{
    self,
    sighash::{PrecomputedSighashData, SignableInput},
};
use zcash_protocol::{consensus::BranchId, value::Zatoshis};
use zcash_script::script;
use zcash_transparent::{
    address::Script,
    bundle as tb,
    sighash::{SighashType, TransparentAuthorizingContext},
};
use zeroize::Zeroizing;

/// Explicit inputs from ONE pool. Funding pools are never silently combined.
pub enum Funding {
    Transparent(Vec<OutPoint>),
    Private(Vec<Hash>),
}
/// Validated recipient intent. Memo bytes are sensitive and never formatted.
pub struct Payment {
    address: Address,
    amount: Amount,
    memo: Option<Zeroizing<[u8; 512]>>,
}
impl Payment {
    /// Reject zero payments and memos on transparent outputs rather than discard a memo.
    pub fn new(address: Address, amount: Amount, memo: Option<[u8; 512]>) -> Result<Self, Error> {
        if amount == Amount::ZERO
            || (memo.is_some() && matches!(address.receiver(), Receiver::Transparent(_)))
        {
            return Err(Error::Intent);
        }
        Ok(Self {
            address,
            amount,
            memo: memo.map(Zeroizing::new),
        })
    }
}
/// Trusted application fee ceiling, separate from individual payment intent.
pub struct Policy {
    pub max_fee: Amount,
}
/// Spending intent. Each list is limited to 32 entries, including any change output.
pub struct Request {
    /// Optional canonical zero-valued Monario service output (registration/proof).
    pub service_record: Option<Vec<u8>>,
    pub account: u32,
    pub funding: Funding,
    pub payments: Vec<Payment>,
    pub fee: Amount,
    /// Required finite expiry: next height through next height + 100 inclusive.
    pub expiry_height: u64,
    /// Change is derived/reserved internally in the encrypted wallet before return.
    pub change_kind: AddressKind,
}
/// Errors contain no seed, note, memo, password or signing-key contents.
#[derive(Debug)]
pub enum Error {
    Scan(ScanError),
    Wallet(StorageError),
    Intent,
    ResourceLimit,
    WrongKey,
    WrongNetwork,
    ChangeNotWatched,
    DuplicateInput,
    MissingInput,
    ImmatureCoinbase,
    InsufficientFunds,
    Amount,
    Expiry,
    FeeLimit,
    Entropy,
    Proof,
    Signing,
    Verification,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "transaction construction: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<ScanError> for Error {
    fn from(e: ScanError) -> Self {
        Self::Scan(e)
    }
}
impl From<StorageError> for Error {
    fn from(e: StorageError) -> Self {
        Self::Wallet(e)
    }
}

/// Signed/proved canonical bytes, self-verified against this exact validated tip.
/// Inputs and the exact signed transaction ID are durably reserved. This is not
/// mempool or blockchain acceptance.
pub struct Constructed {
    bytes: Vec<u8>,
    pub id: Hash,
    pub validated_tip: Hash,
    pub fee: Amount,
    pub change: Amount,
    /// Fresh receipt after durable input binding (also covers any change issuance).
    pub checkpoint: Option<WalletCheckpoint>,
    pub reservation: [u8; 16],
}
impl Constructed {
    /// Explicit sensitive transaction export. Do not log raw transactions or memos.
    pub fn expose_bytes(&self) -> &[u8] {
        &self.bytes
    }
}
impl std::fmt::Debug for Constructed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Constructed([REDACTED])")
    }
}

#[derive(Debug, Clone)]
struct Inputs(Vec<tb::TxOut>);
impl tb::Authorization for Inputs {
    type ScriptSig = Script;
}
impl TransparentAuthorizingContext for Inputs {
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
    type OrchardAuth = InProgress<orchard::Proof, Unauthorized>;
}
static PROVING_KEY: OnceLock<ProvingKey> = OnceLock::new();
fn amount(n: u64) -> Result<Amount, Error> {
    Amount::from_atoms(n).map_err(|_| Error::Amount)
}
fn value(n: Amount) -> Result<Zatoshis, Error> {
    Zatoshis::from_u64(n.atoms()).map_err(|_| Error::Amount)
}
fn add(a: Amount, b: Amount) -> Result<Amount, Error> {
    a.checked_add(b).map_err(|_| Error::Amount)
}
fn rng(fill: impl FnOnce(&mut [u8]) -> Result<(), ()>) -> Result<StdRng, Error> {
    let mut seed = Zeroizing::new([0; 32]);
    fill(seed.as_mut_slice()).map_err(|_| Error::Entropy)?;
    Ok(StdRng::from_seed(*seed))
}

/// Construct using OS-seeded cryptographic randomness; entropy failure is an error.
/// Wallet recovery gating, ownership, maturity and current scanner state are mandatory.
/// A failure AFTER change reservation burns that index safely; it is never rolled back.
pub fn construct(
    source: &DurableChain<V6Verifier>,
    scanner: &Scanner,
    wallet: &mut WalletStore,
    request: Request,
    policy: &Policy,
) -> Result<Constructed, Error> {
    let mut rng = rng(|b| getrandom::fill(b).map_err(|_| ()))?;
    construct_inner(source, scanner, wallet, request, policy, &mut rng, None)
}

/// Construct a fee-only automatic archival response, committing its authenticated
/// attempt tag with the input claim before any signing. Exactly one transparent
/// input and transparent change are allowed; the complete record is still
/// independently validated. Counts/fees include unsigned and orphaned attempts.
pub fn construct_service_proof(
    source: &DurableChain<V6Verifier>,
    scanner: &Scanner,
    wallet: &mut WalletStore,
    request: Request,
    policy: &Policy,
    period_fee_budget: u64,
) -> Result<Constructed, Error> {
    if !request.payments.is_empty()
        || !matches!(&request.funding,Funding::Transparent(p) if p.len()==1)
        || request.change_kind != AddressKind::Transparent
        || request.fee == Amount::ZERO
    {
        return Err(Error::Intent);
    }
    let script = request.service_record.as_ref().ok_or(Error::Intent)?;
    let (registration, period_start, challenge) =
        monario_chain::service::proof_context(script).map_err(|_| Error::Intent)?;
    let operator = source
        .chain()
        .map_err(ScanError::from)?
        .ledger()
        .service_entry(&registration)
        .ok_or(Error::Intent)?
        .operator;
    let proof = monario_wallet::storage::pending::ServiceProof {
        registration,
        period_start,
        challenge,
        operator,
        fee_atoms: request.fee.atoms(),
    };
    let mut rng = rng(|b| getrandom::fill(b).map_err(|_| ()))?;
    construct_inner(
        source,
        scanner,
        wallet,
        request,
        policy,
        &mut rng,
        Some((proof, period_fee_budget)),
    )
}

fn valid_expiry(height: u64, expiry: u64) -> bool {
    expiry >= height && expiry <= height.saturating_add(100)
}

fn construct_inner(
    source: &DurableChain<V6Verifier>,
    scanner: &Scanner,
    wallet: &mut WalletStore,
    request: Request,
    policy: &Policy,
    rng: &mut StdRng,
    service_proof: Option<(monario_wallet::storage::pending::ServiceProof, u64)>,
) -> Result<Constructed, Error> {
    scanner.current(source)?;
    if wallet.recovery_required()? {
        return Err(Error::Wallet(StorageError::RecoveryRequired));
    }
    let chain = source.chain().map_err(ScanError::from)?;
    let network = wallet.checkpoint()?.network;
    let height = chain.height().checked_add(1).ok_or(Error::Expiry)?;
    if !valid_expiry(height, request.expiry_height) {
        return Err(Error::Expiry);
    }
    if request.fee > policy.max_fee {
        return Err(Error::FeeLimit);
    }
    if (request.payments.is_empty() && request.service_record.is_none())
        || request.payments.len() > 32
    {
        return Err(Error::Intent);
    }
    if let Some(script) = &request.service_record {
        // Full semantics are checked against the resulting verified transaction below.
        monario_chain::service::check_encoding(script).map_err(|_| Error::Intent)?;
        if script.len() > chain.limits().script_bytes {
            return Err(Error::ResourceLimit);
        }
    }
    let watched = scanner
        .accounts
        .iter()
        .find(|a| a.id == request.account)
        .ok_or(Error::WrongKey)?;
    if watched.network != network {
        return Err(Error::WrongNetwork);
    }
    let account = wallet
        .expose_seed()?
        .private_account(network, request.account)
        .map_err(|_| Error::WrongKey)?;
    let viewing = FullViewingKey::from(account.expose_spending_key());
    if *Zeroizing::new(viewing.to_bytes()) != *Zeroizing::new(watched.viewing.to_bytes()) {
        return Err(Error::WrongKey);
    }
    let mut output_value = request.fee;
    for p in &request.payments {
        if p.address.network() != network {
            return Err(Error::WrongNetwork);
        }
        output_value = add(output_value, p.amount)?;
    }
    let anchor = Option::from(orchard::Anchor::from_bytes(
        chain.ledger().shielded().root(),
    ))
    .ok_or(Error::Verification)?;
    let version = BundleVersion::ironwood_v3();
    let mut builder = Builder::new(
        BundleType::DEFAULT,
        version,
        version.default_flags(),
        anchor,
    )
    .map_err(|_| Error::Proof)?;
    let mut transparent_inputs = Vec::new();
    let mut coins = Vec::new();
    let mut keys = Vec::new();
    let mut input_value = Amount::ZERO;
    let private_count;
    match &request.funding {
        Funding::Transparent(selected) => {
            if selected.is_empty()
                || selected.len() > 32
                || selected.len() > chain.limits().inputs_per_transaction
            {
                return Err(Error::ResourceLimit);
            }
            private_count = 0;
            let mut unique = BTreeSet::new();
            for outpoint in selected {
                if !unique.insert(*outpoint) {
                    return Err(Error::DuplicateInput);
                }
                let (owner, coin) = scanner
                    .state
                    .coins
                    .get(outpoint)
                    .ok_or(Error::MissingInput)?;
                if *owner != request.account || chain.ledger().coin(outpoint) != Some(coin) {
                    return Err(Error::MissingInput);
                }
                if coin.coinbase
                    && height
                        .checked_sub(coin.created_height)
                        .ok_or(Error::Verification)?
                        < source.coinbase_maturity().map_err(ScanError::from)?
                {
                    return Err(Error::ImmatureCoinbase);
                }
                let (_, scope, index) = scanner.scripts.get(&coin.script).ok_or(Error::WrongKey)?;
                let key = wallet
                    .expose_seed()?
                    .transparent_key(network, request.account, *scope, *index)
                    .map_err(|_| Error::WrongKey)?;
                if key.address().script_pubkey().as_ref() != Some(&coin.script) {
                    return Err(Error::WrongKey);
                }
                input_value = add(input_value, coin.value)?;
                transparent_inputs.push(tb::TxIn::from_parts(
                    tb::OutPoint::new(outpoint.transaction, outpoint.index),
                    Script::default(),
                    u32::MAX,
                ));
                coins.push(tb::TxOut::new(
                    value(coin.value)?,
                    Script(script::Code(coin.script.clone())),
                ));
                keys.push(key);
            }
        }
        Funding::Private(selected) => {
            if selected.is_empty() || selected.len() > 32 {
                return Err(Error::ResourceLimit);
            }
            private_count = selected.len();
            let mut unique = BTreeSet::new();
            for nf in selected {
                if !unique.insert(*nf) {
                    return Err(Error::DuplicateInput);
                }
                let received = scanner.state.notes.get(nf).ok_or(Error::MissingInput)?;
                if received.account != request.account
                    || chain.ledger().has_nullifier(nf)
                    || received.note.nullifier(&viewing).to_bytes() != *nf
                {
                    return Err(Error::WrongKey);
                }
                input_value = add(input_value, amount(received.note.value().inner())?)?;
                builder
                    .add_spend(
                        viewing.clone(),
                        received.note,
                        scanner.witness(source, *nf)?,
                    )
                    .map_err(|_| Error::Proof)?;
            }
        }
    }
    let change = input_value
        .checked_sub(output_value)
        .map_err(|_| Error::InsufficientFunds)?;
    if request.payments.len()
        + usize::from(change != Amount::ZERO)
        + usize::from(request.service_record.is_some())
        > 32
    {
        return Err(Error::ResourceLimit);
    }
    let mut private_outputs = request
        .payments
        .iter()
        .filter(|p| matches!(p.address.receiver(), Receiver::Private(_)))
        .count();
    let mut public_outputs =
        request.payments.len() - private_outputs + usize::from(request.service_record.is_some());
    if change != Amount::ZERO {
        match request.change_kind {
            AddressKind::Private => private_outputs += 1,
            AddressKind::Transparent => public_outputs += 1,
        }
    }
    let actions = BundleType::DEFAULT
        .num_actions(version.default_flags(), private_count, private_outputs)
        .map_err(|_| Error::ResourceLimit)?;
    if actions > chain.limits().outputs_per_transaction
        || public_outputs > chain.limits().outputs_per_transaction
        || (public_outputs > 0 && chain.limits().script_bytes < 25)
    {
        return Err(Error::ResourceLimit);
    }
    // Conservative serialized upper bound, before expensive proving or durable change issuance.
    let shielded_bytes = if actions == 0 {
        0
    } else {
        actions * (zcash_primitives::transaction::components::orchard::ACTION_SIZE + 64)
            + orchard::Proof::expected_proof_size(actions)
            + 128
    };
    let size_bound = 128
        + transparent_inputs.len() * 150
        + public_outputs * 40
        + shielded_bytes
        + request.service_record.as_ref().map_or(0, Vec::len);
    if size_bound > chain.limits().transaction_bytes {
        return Err(Error::ResourceLimit);
    }
    if let Some(script) = &request.service_record {
        let inputs = match &request.funding {
            Funding::Transparent(ids) => ids.as_slice(),
            Funding::Private(_) => &[],
        };
        chain
            .check_service_intent(script, inputs)
            .map_err(|_| Error::Verification)?;
    }
    if change != Amount::ZERO && matches!(request.change_kind, AddressKind::Transparent) {
        let next = wallet
            .account_progress()?
            .get(&request.account)
            .map_or(0, |p| p.transparent_internal);
        if next >= 1 << 31 {
            return Err(Error::Wallet(StorageError::Exhausted));
        }
        let key = wallet
            .expose_seed()?
            .transparent_key(network, request.account, Scope::Internal, next as u32)
            .map_err(|_| Error::WrongKey)?;
        let script = key.address().script_pubkey().ok_or(Error::WrongKey)?;
        if scanner.scripts.get(&script) != Some(&(request.account, Scope::Internal, next as u32)) {
            return Err(Error::ChangeNotWatched);
        }
    }
    let inputs = match &request.funding {
        Funding::Transparent(points) => points
            .iter()
            .map(|p| monario_wallet::storage::pending::Input::Transparent {
                transaction: p.transaction,
                index: p.index,
            })
            .collect(),
        Funding::Private(ids) => ids
            .iter()
            .map(|id| monario_wallet::storage::pending::Input::Private { nullifier: *id })
            .collect(),
    };
    let reservation = if let Some((proof, budget)) = service_proof {
        wallet.reserve_service_inputs(
            chain.validation_profile(),
            chain.tip(),
            request.expiry_height,
            inputs,
            proof,
            budget,
        )?
    } else {
        wallet.reserve_inputs(
            chain.validation_profile(),
            chain.tip(),
            request.expiry_height,
            inputs,
        )?
    };
    let mut payments = request.payments;
    let checkpoint = if change != Amount::ZERO {
        let issued = wallet.next_address(request.account, Scope::Internal, request.change_kind)?;
        payments.push(Payment::new(issued.address, change, None)?);
        Some(issued.checkpoint)
    } else {
        None
    };
    let mut outputs = Vec::new();
    if let Some(script) = request.service_record {
        if script.len() > chain.limits().script_bytes {
            return Err(Error::ResourceLimit);
        }
        outputs.push(tb::TxOut::new(
            value(Amount::ZERO)?,
            Script(script::Code(script)),
        ));
    }
    for (i, p) in payments.iter().enumerate() {
        match p.address.receiver() {
            Receiver::Transparent(_) => outputs.push(tb::TxOut::new(
                value(p.amount)?,
                Script(script::Code(
                    p.address.script_pubkey().ok_or(Error::Intent)?,
                )),
            )),
            Receiver::Private(receiver) => {
                let scope = if checkpoint.is_some() && i + 1 == payments.len() {
                    orchard::keys::Scope::Internal
                } else {
                    orchard::keys::Scope::External
                };
                let memo = p.memo.as_ref().map_or_else(
                    || {
                        let mut m = [0; 512];
                        m[0] = 0xf6;
                        m
                    },
                    |m| **m,
                );
                builder
                    .add_output(
                        Some(viewing.to_ovk(scope)),
                        receiver.to_upstream(),
                        NoteValue::from_raw(p.amount.atoms()),
                        memo,
                    )
                    .map_err(|_| Error::Proof)?;
            }
        }
    }
    let bundle = builder
        .build::<zcash_protocol::value::ZatBalance>(&mut *rng)
        .map_err(|_| Error::Proof)?
        .map(|(b, _)| {
            b.create_proof(
                PROVING_KEY.get_or_init(|| ProvingKey::build(OrchardCircuitVersion::PostNu6_3)),
                &mut *rng,
            )
        })
        .transpose()
        .map_err(|_| Error::Proof)?;
    let transparent = if transparent_inputs.is_empty() && outputs.is_empty() {
        None
    } else {
        Some(tb::Bundle {
            vin: transparent_inputs,
            vout: outputs,
            authorization: Inputs(coins.clone()),
        })
    };
    let data: transaction::TransactionData<Producer> = transaction::TransactionData::from_parts_v6(
        BranchId::Nu6_3,
        0,
        0u32.into(),
        transparent,
        None,
        None,
        bundle,
    )
    .with_monario_expiry(request.expiry_height);
    let pre = PrecomputedSighashData::new_zip244(data).map_err(|_| Error::Signing)?;
    let shielded_hash = *pre.signature_hash(&SignableInput::Shielded).as_ref();
    let mut signatures = Vec::new();
    for (index, (key, coin)) in keys.iter().zip(&coins).enumerate() {
        let input = zcash_transparent::sighash::SignableInput::from_parts(
            pre.tx().transparent_bundle().ok_or(Error::Signing)?,
            SighashType::ALL,
            index,
            coin.script_pubkey(),
            coin.script_pubkey(),
            coin.value(),
        )
        .map_err(|_| Error::Signing)?;
        let digest = *pre
            .signature_hash(&SignableInput::Transparent(input))
            .as_ref();
        let mut secret = secp256k1::SecretKey::from_secret_bytes(*key.expose_secret())
            .map_err(|_| Error::Signing)?;
        let sig = secp256k1::ecdsa::sign(secp256k1::Message::from_digest(digest), &secret)
            .serialize_der();
        secret.non_secure_erase();
        let mut der = sig.as_ref().to_vec();
        der.push(1);
        let mut script_sig = vec![u8::try_from(der.len()).map_err(|_| Error::Signing)?];
        script_sig.extend(der);
        script_sig.push(33);
        script_sig.extend(key.public_key());
        signatures.push(script_sig);
    }
    let signing_keys = if private_count == 0 {
        vec![]
    } else {
        vec![SpendAuthorizingKey::from(account.expose_spending_key())]
    };
    let mut failed = false;
    let signed = pre.into_tx().map_bundles::<transaction::Authorized>(
        |b| {
            b.map(|b| tb::Bundle {
                vin: b
                    .vin
                    .into_iter()
                    .zip(signatures)
                    .map(|(i, sig)| {
                        tb::TxIn::from_parts(
                            i.prevout().clone(),
                            Script(script::Code(sig)),
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
            b.and_then(
                |b| match b.apply_signatures(&mut *rng, shielded_hash, &signing_keys) {
                    Ok(b) => Some(b),
                    Err(_) => {
                        failed = true;
                        None
                    }
                },
            )
        },
    );
    if failed {
        return Err(Error::Signing);
    }
    let tx = signed.freeze().map_err(|_| Error::Signing)?;
    let mut bytes = Vec::new();
    tx.write(&mut bytes).map_err(|_| Error::Signing)?;
    if bytes.len() > chain.limits().transaction_bytes {
        return Err(Error::ResourceLimit);
    }
    let verified = V6Verifier
        .verify(
            &bytes,
            TransactionContext {
                height,
                median_time_past: chain.median_time_past(),
                state: chain.ledger(),
            },
        )
        .map_err(|_| Error::Verification)?;
    if verified.coinbase_height.is_some() {
        return Err(Error::Verification);
    }
    chain
        .check_service_effects(&verified)
        .map_err(|_| Error::Verification)?;
    // Independently reconcile the produced public/private value balances and the exact fee.
    let public_out = verified
        .outputs
        .iter()
        .try_fold(Amount::ZERO, |a, o| add(a, o.value))?;
    let public_in = coins
        .iter()
        .try_fold(Amount::ZERO, |a, c| add(a, amount(c.value().into_u64())?))?;
    let shielded = verified.ironwood.as_ref().map_or(0, |b| b.value_balance);
    if i128::from(public_in.atoms()) + i128::from(shielded) - i128::from(public_out.atoms())
        != i128::from(request.fee.atoms())
    {
        return Err(Error::Verification);
    }
    let mut actual: Vec<_> = verified
        .inputs
        .iter()
        .map(|p| monario_wallet::storage::pending::Input::Transparent {
            transaction: p.transaction,
            index: p.index,
        })
        .collect();
    if let Some(bundle) = &verified.ironwood {
        actual.extend(
            bundle
                .nullifiers
                .iter()
                // Padded actions include dummy spends, even for pure shielding.
                // Only actual owned notes are wallet input reservations; the
                // chain/mempool still enforce uniqueness for ALL nullifiers.
                .filter(|n| scanner.state.notes.contains_key(*n))
                .map(|n| monario_wallet::storage::pending::Input::Private { nullifier: *n }),
        );
    }
    actual.sort();
    let mut expected = wallet
        .reservations()?
        .get(&reservation)
        .ok_or(Error::Verification)?
        .inputs
        .clone();
    expected.sort();
    if actual != expected {
        return Err(Error::Verification);
    }
    let checkpoint = Some(wallet.bind_reservation(reservation, verified.id, &bytes)?);
    Ok(Constructed {
        bytes,
        id: verified.id,
        validated_tip: chain.tip(),
        fee: request.fee,
        change,
        checkpoint,
        reservation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn partial_entropy_failure_never_returns_a_rng() {
        assert!(matches!(
            rng(|b| {
                b[..8].fill(7);
                Err(())
            }),
            Err(Error::Entropy)
        ));
    }
}

#[cfg(test)]
mod wide_expiry_tests {
    #[test]
    fn accepts_bounded_expiry_on_both_sides_of_32_bit_boundary() {
        let next = u64::from(u32::MAX) + 1;
        assert!(super::valid_expiry(next, next));
        assert!(super::valid_expiry(next, next + 100));
        assert!(!super::valid_expiry(next, next - 1));
        assert!(!super::valid_expiry(next, next + 101));
    }
}
