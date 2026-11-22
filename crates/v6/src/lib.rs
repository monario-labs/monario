//! Monario's pinned v6 and Ironwood verification integration.
pub const BRANCH_ID: u32 = monario_chain::consensus::TRANSACTION_BRANCH_ID;
// A backend mismatch would otherwise let peers agree on a profile and diverge.
const _: () =
    assert!(zcash_protocol::value::MAX_MONEY == monario_monetary::MAX_TRANSACTION_VALUE_ATOMS);
const _: () = assert!(
    zcash_protocol::value::MAX_BALANCE as u64 == monario_monetary::MAX_TRANSACTION_VALUE_ATOMS
);
pub mod coinbase;
mod framing;
#[cfg(test)]
mod interop;
#[cfg(test)]
mod private_spend;
#[cfg(test)]
mod tests;

use monario_chain::{
    Hash,
    ledger::OutPoint,
    transactions::{
        Output, TransactionContext, TransactionError as Error, TransactionVerifier,
        VerifiedIronwood, VerifiedTransaction,
    },
};
use monario_monetary::Amount;
use orchard::circuit::{OrchardCircuitVersion, VerifyingKey};
use std::sync::OnceLock;
use zcash_primitives::transaction::{
    self, Transaction, TxVersion,
    sighash::{PrecomputedSighashData, SignableInput},
};
use zcash_protocol::{consensus::BranchId, value::Zatoshis};
use zcash_script::{
    interpreter::{CallbackTransactionSignatureChecker, Flags},
    script,
};
use zcash_transparent::{
    address::Script,
    bundle as tb,
    sighash::{SighashType, TransparentAuthorizingContext},
};

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
struct Auth;
impl transaction::Authorization for Auth {
    type TransparentAuth = Inputs;
    type SaplingAuth = <transaction::Authorized as transaction::Authorization>::SaplingAuth;
    type OrchardAuth = <transaction::Authorized as transaction::Authorization>::OrchardAuth;
}
impl tb::MapAuth<tb::Authorized, Inputs> for Inputs {
    fn map_script_sig(&self, s: Script) -> Script {
        s
    }
    fn map_authorization(&self, _: tb::Authorized) -> Inputs {
        self.clone()
    }
}

/// Stateless signature/proof validation. Branch state is supplied per call.
pub struct V6Verifier;
static KEY: OnceLock<VerifyingKey> = OnceLock::new();
fn invalid<T>(_: T) -> Error {
    Error::Invalid
}

fn coinbase_height(script: &[u8]) -> Result<u64, Error> {
    if !(2..=100).contains(&script.len()) {
        return Err(Error::Invalid);
    }
    if (0x51..=0x60).contains(&script[0]) {
        return Ok(u64::from(script[0] - 0x50));
    }
    let len = usize::from(script[0]);
    if len == 0 || len > 8 || script.len() <= len || script[len] & 0x80 != 0 {
        return Err(Error::Invalid);
    }
    if script[len] & 0x7f == 0 && (len == 1 || script[len - 1] & 0x80 == 0) {
        return Err(Error::Invalid);
    }
    let mut n = 0_u64;
    for (i, b) in script[1..=len].iter().enumerate() {
        n |= u64::from(*b) << (8 * i);
    }
    if n <= 16 {
        return Err(Error::Invalid);
    }
    Ok(n)
}

fn decode(bytes: &[u8]) -> Result<Transaction, Error> {
    if framing::transaction_length(bytes)? != bytes.len() {
        return Err(Error::Invalid);
    }
    let mut cursor = std::io::Cursor::new(bytes);
    let tx = Transaction::read(&mut cursor, BranchId::Nu6_3).map_err(invalid)?;
    if cursor.position() != bytes.len() as u64
        || tx.version() != TxVersion::V6
        || u32::from(tx.consensus_branch_id()) != BRANCH_ID
        || tx.sapling_bundle().is_some()
        || tx.orchard_bundle().is_some()
    {
        return Err(Error::Invalid);
    }
    let mut canonical = Vec::new();
    tx.write(&mut canonical).map_err(invalid)?;
    if canonical != bytes {
        return Err(Error::Invalid);
    }
    Ok(tx)
}

/// Canonical effects ID ONLY, including coinbase. This does not validate
/// signatures, proofs, expiry, inputs or chain inclusion. Never apply as effects.
pub fn transaction_id(bytes: &[u8]) -> Result<Hash, Error> {
    Ok(*decode(bytes)?.txid().as_ref())
}

/// Canonical effects ID and transparent references ONLY, without authorization,
/// proof, ownership, expiry or contextual validation. Never apply as effects.
pub fn transaction_references(bytes: &[u8]) -> Result<(Hash, Vec<OutPoint>), Error> {
    let tx = decode(bytes)?;
    let mut inputs = Vec::new();
    if let Some(bundle) = tx.transparent_bundle() {
        if bundle.is_coinbase() || bundle.vin.len() > 10000 {
            return Err(Error::Invalid);
        }
        for input in &bundle.vin {
            inputs.push(OutPoint {
                transaction: *input.prevout().hash(),
                index: input.prevout().n(),
            });
        }
    }
    Ok((*tx.txid().as_ref(), inputs))
}

impl TransactionVerifier for V6Verifier {
    fn transaction_length(&self, bytes: &[u8]) -> Result<usize, Error> {
        framing::transaction_length(bytes)
    }
    fn verify(
        &self,
        bytes: &[u8],
        context: TransactionContext<'_>,
    ) -> Result<VerifiedTransaction, Error> {
        let tx = decode(bytes)?;
        let transparent = tx.transparent_bundle();
        let coinbase = transparent.is_some_and(|b| b.is_coinbase());
        let expiry = tx.monario_expiry_height();
        if expiry != 0 && expiry < context.height {
            return Err(Error::Invalid);
        }
        let lock_bound = if tx.lock_time() < 500_000_000 {
            context.height
        } else {
            context.median_time_past
        };
        if tx.lock_time() != 0
            && u64::from(tx.lock_time()) >= lock_bound
            && transparent.is_some_and(|b| b.vin.iter().any(|i| i.sequence() != u32::MAX))
        {
            return Err(Error::Invalid);
        }
        let height = if coinbase {
            if tx.ironwood_bundle().is_some() || expiry != context.height {
                return Err(Error::Invalid);
            }
            Some(coinbase_height(
                &transparent.ok_or(Error::Invalid)?.vin[0].script_sig().0.0,
            )?)
        } else {
            None
        };
        if height.is_some_and(|h| h != context.height) {
            return Err(Error::Invalid);
        }
        let mut inputs = Vec::new();
        let mut coins = Vec::new();
        let mut outputs = Vec::new();
        if let Some(b) = transparent {
            if b.vin.len() > 10000 || b.vout.len() > 10000 {
                return Err(Error::Invalid);
            }
            if !coinbase {
                for i in &b.vin {
                    if i.prevout().hash() == &[0; 32] && i.prevout().n() == u32::MAX {
                        return Err(Error::Invalid);
                    }
                    let point = OutPoint {
                        transaction: *i.prevout().hash(),
                        index: i.prevout().n(),
                    };
                    let coin = context.state.coin(&point).ok_or(Error::MissingInput)?;
                    coins.push(tb::TxOut::new(
                        Zatoshis::from_u64(coin.value.atoms()).map_err(invalid)?,
                        Script(script::Code(coin.script.clone())),
                    ));
                    inputs.push(point);
                }
            }
            for o in &b.vout {
                outputs.push(Output {
                    value: Amount::from_atoms(u64::from(o.value())).map_err(invalid)?,
                    script: o.script_pubkey().0.0.clone(),
                });
            }
        }
        let id = *tx.txid().as_ref();
        let auth_digest: Hash = tx
            .auth_commitment()
            .as_bytes()
            .try_into()
            .map_err(invalid)?;
        let data = tx
            .into_data()
            .map_authorization::<Auth>(Inputs(coins.clone()), (), ());
        let sighasher = PrecomputedSighashData::new_zip244(data).map_err(invalid)?;
        if !coinbase && let Some(b) = sighasher.tx().transparent_bundle() {
            for (index, input) in b.vin.iter().enumerate() {
                let coin = &coins[index];
                let calculate = |code: &script::Code,
                                 hash_type: &zcash_script::signature::HashType|
                 -> Option<Hash> {
                    let kind = SighashType::parse(u8::try_from(hash_type.raw_bits()).ok()?)?;
                    if kind.encode() & 0x1f == 3 && index >= b.vout.len() {
                        return None;
                    }
                    let code = Script(code.clone());
                    let signable = zcash_transparent::sighash::SignableInput::from_parts(
                        b,
                        kind,
                        index,
                        &code,
                        coin.script_pubkey(),
                        coin.value(),
                    )
                    .ok()?;
                    Some(
                        *sighasher
                            .signature_hash(&SignableInput::Transparent(signable))
                            .as_ref(),
                    )
                };
                let checker = CallbackTransactionSignatureChecker {
                    sighash: &calculate,
                    lock_time: i64::from(sighasher.tx().lock_time()),
                    is_final: input.sequence() == u32::MAX,
                };
                let raw = script::Raw::from_raw_parts(
                    input.script_sig().0.0.clone(),
                    coin.script_pubkey().0.0.clone(),
                );
                if !raw
                    .eval(Flags::P2SH | Flags::CHECKLOCKTIMEVERIFY, &checker)
                    .map_err(invalid)?
                {
                    return Err(Error::Invalid);
                }
            }
        }
        let ironwood = if let Some(b) = sighasher.tx().ironwood_bundle() {
            if b.actions().len() > 4096 || !context.state.has_anchor(&b.anchor().to_bytes()) {
                return Err(Error::Invalid);
            }
            let hash = *sighasher.signature_hash(&SignableInput::Shielded).as_ref();
            let key = KEY.get_or_init(|| VerifyingKey::build(OrchardCircuitVersion::PostNu6_3));
            b.verify_proof(key).map_err(invalid)?;
            for a in b.actions().iter() {
                a.rk().verify(&hash, a.authorization()).map_err(invalid)?;
            }
            b.binding_validating_key()
                .verify(&hash, b.authorization().binding_signature())
                .map_err(invalid)?;
            Some(VerifiedIronwood {
                value_balance: i64::from(b.value_balance()),
                anchor: b.anchor().to_bytes(),
                nullifiers: b
                    .actions()
                    .iter()
                    .map(|a| a.nullifier().to_bytes())
                    .collect(),
                commitments: b.actions().iter().map(|a| a.cmx().to_bytes()).collect(),
            })
        } else {
            None
        };
        Ok(VerifiedTransaction {
            id,
            authorization_digest: auth_digest,
            coinbase_height: height,
            inputs,
            outputs,
            has_shielded_bundle: false,
            ironwood,
        })
    }
    fn block_commitment(&self, _: Hash, _: u64, _: &[(Hash, Hash)]) -> Result<Hash, Error> {
        Err(Error::Invalid)
    }
    fn block_commitment_with_state(
        &self,
        parent: Hash,
        height: u64,
        txs: &[(Hash, Hash)],
        root: Hash,
    ) -> Result<Hash, Error> {
        let mut h = blake2b_simd::Params::new()
            .hash_length(32)
            .personal(b"MONBlockCommitV1")
            .to_state();
        h.update(&parent);
        h.update(&height.to_le_bytes());
        h.update(&root);
        h.update(&(txs.len() as u64).to_le_bytes());
        for (id, auth) in txs {
            h.update(id);
            h.update(auth);
        }
        h.finalize().as_bytes().try_into().map_err(invalid)
    }
}
