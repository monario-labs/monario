//! Explicit offline spending intent and durable signed-transaction export.
use super::*;
#[path = "payment_plan.rs"]
pub(super) mod plan;
use monario_chain::{ledger::OutPoint, storage::DurableChain};
use monario_monetary::Amount;
use monario_v6::V6Verifier;
use monario_wallet::{Address, storage::pending::Input};
use monario_wallet_scan::{
    Scanner,
    build::{self, Funding, Payment, Policy, Request},
};
use serde::Deserialize;
use std::{collections::BTreeSet, fs::File};

pub(super) enum Options {
    Construct {
        file: String,
        max_fee: Amount,
    },
    Export {
        profile: [u8; 32],
        reservation: [u8; 16],
    },
}
impl Options {
    pub(super) fn parse(
        action: Action,
        options: &mut BTreeMap<String, OsString>,
    ) -> Result<Self, Error> {
        if action == Action::Construct {
            Ok(Self::Construct {
                file: balance::filename(&text(options.remove("--request"))?)?,
                max_fee: atoms(&text(options.remove("--max-fee-atoms"))?)
                    .map_err(|_| Error::Arguments)?,
            })
        } else {
            Ok(Self::Export {
                profile: balance::hash(&text(options.remove("--profile"))?)?,
                reservation: id(&text(options.remove("--reservation"))?)?,
            })
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u8,
    validated_tip: String,
    funding: Selected,
    payments: Vec<Recipient>,
    fee_atoms: String,
    expiry_height: u64,
    change: String,
    service: Option<service::Intent>,
}
#[derive(Deserialize)]
#[serde(
    tag = "pool",
    content = "inputs",
    rename_all = "lowercase",
    deny_unknown_fields
)]
enum Selected {
    Transparent(Vec<Point>),
    Private(Vec<String>),
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Point {
    transaction: String,
    index: u32,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Recipient {
    address: String,
    amount_atoms: String,
}
fn atoms(value: &str) -> Result<Amount, Error> {
    Amount::from_atoms(number(value).map_err(|_| Error::Transaction)?)
        .map_err(|_| Error::Transaction)
}
fn hash(value: &str) -> Result<[u8; 32], Error> {
    balance::hash(value).map_err(|_| Error::Transaction)
}
fn request(
    bytes: &[u8],
    network: Network,
    account: u32,
    tip: [u8; 32],
) -> Result<(Request, Option<service::Intent>), Error> {
    if bytes.len() > 65_536 {
        return Err(Error::Transaction);
    }
    let doc: Document = serde_json::from_slice(bytes).map_err(|_| Error::Transaction)?;
    if doc.version != 1
        || hash(&doc.validated_tip)? != tip
        || (doc.payments.is_empty() && doc.service.is_none())
        || doc.payments.len() > 32
    {
        return Err(Error::Transaction);
    }
    let funding = match doc.funding {
        Selected::Transparent(points) => {
            if points.is_empty() || points.len() > 32 {
                return Err(Error::Transaction);
            }
            let points = points
                .into_iter()
                .map(|p| {
                    Ok(OutPoint {
                        transaction: hash(&p.transaction)?,
                        index: p.index,
                    })
                })
                .collect::<Result<Vec<_>, Error>>()?;
            if points.iter().collect::<BTreeSet<_>>().len() != points.len() {
                return Err(Error::Transaction);
            }
            Funding::Transparent(points)
        }
        Selected::Private(ids) => {
            if ids.is_empty() || ids.len() > 32 {
                return Err(Error::Transaction);
            }
            let ids = ids.iter().map(|s| hash(s)).collect::<Result<Vec<_>, _>>()?;
            if ids.iter().collect::<BTreeSet<_>>().len() != ids.len() {
                return Err(Error::Transaction);
            }
            Funding::Private(ids)
        }
    };
    let payments = doc
        .payments
        .into_iter()
        .map(|p| {
            Payment::new(
                Address::decode(&p.address, network).map_err(|_| Error::Transaction)?,
                atoms(&p.amount_atoms)?,
                None,
            )
            .map_err(|_| Error::Transaction)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((
        Request {
            service_record: None,
            account,
            funding,
            payments,
            fee: atoms(&doc.fee_atoms)?,
            expiry_height: doc.expiry_height,
            change_kind: match doc.change.as_str() {
                "transparent" => AddressKind::Transparent,
                "private" => AddressKind::Private,
                _ => return Err(Error::Transaction),
            },
        },
        doc.service,
    ))
}
pub(super) fn execute(
    root: &Path,
    store: &mut WalletStore,
    account: u32,
    scan: Option<balance::Options>,
    options: Options,
) -> Result<TransactionOutput, Error> {
    match options {
        Options::Export {
            profile,
            reservation,
        } => export(store, profile, reservation),
        Options::Construct { file, max_fee } => {
            let bytes = read_request(root, &file)?;
            let options = scan.ok_or(Error::Arguments)?;
            let source = balance::open(&options)?;
            construct(store, account, &options, &source, &bytes, max_fee)
        }
    }
}
pub(super) fn construct(
    store: &mut WalletStore,
    account: u32,
    options: &balance::Options,
    source: &DurableChain<V6Verifier>,
    bytes: &[u8],
    max_fee: Amount,
) -> Result<TransactionOutput, Error> {
    let checkpoint = store.checkpoint().map_err(storage)?;
    let tip = source.chain().map_err(|_| Error::Scan)?.tip();
    let (mut request, intent) = request(bytes, checkpoint.network, account, tip)?;
    let scanner = balance::prepare(store, account, options, source)?;
    if let Some(intent) = intent {
        request.service_record = Some(service::script(source, store, account, intent)?);
    }
    let tx = build::construct(source, &scanner, store, request, &Policy { max_fee })
        .map_err(|_| Error::Transaction)?;
    let mut output = export(store, options.profile, tx.reservation)?;
    output.chain_checkpoint = options.checkpoint.map(|pin| hex(&pin));
    output.fee_atoms = Some(tx.fee.atoms().to_string());
    output.change_atoms = Some(tx.change.atoms().to_string());
    Ok(output)
}
#[derive(Serialize)]
pub(super) struct TransactionOutput {
    chain_checkpoint: Option<String>,
    checkpoint: Receipt,
    validation_profile: String,
    validated_tip: String,
    reservation: String,
    transaction_id: String,
    expiry_height: u64,
    transaction_hex: String,
    fee_atoms: Option<String>,
    change_atoms: Option<String>,
    broadcast: bool,
}
pub(super) fn export(
    store: &WalletStore,
    profile: [u8; 32],
    token: [u8; 16],
) -> Result<TransactionOutput, Error> {
    let r = store
        .reservations()
        .map_err(storage)?
        .get(&token)
        .filter(|r| r.profile == profile)
        .ok_or(Error::Transaction)?;
    let bytes = r.expose_transaction().ok_or(Error::Transaction)?;
    Ok(TransactionOutput {
        chain_checkpoint: None,
        checkpoint: receipt(
            store.checkpoint().map_err(storage)?,
            store.recovery_required().map_err(storage)?,
        ),
        validation_profile: hex(&profile),
        validated_tip: hex(&r.validated_tip),
        reservation: hex(&token),
        transaction_id: hex(&r.transaction.ok_or(Error::Transaction)?),
        expiry_height: r.expiry_height,
        transaction_hex: hex(bytes),
        fee_atoms: None,
        change_atoms: None,
        broadcast: false,
    })
}
pub(super) fn inputs(
    store: &WalletStore,
    source: &DurableChain<V6Verifier>,
    scanner: &Scanner,
    account: u32,
) -> Result<serde_json::Value, Error> {
    let profile = source.profile_id().map_err(|_| Error::Scan)?;
    let all = store.reservations().map_err(storage)?;
    let reservations: Vec<_> = all.values().filter(|r| r.profile == profile).collect();
    // The store conservatively rejects duplicate claims across profiles too.
    let claims: BTreeSet<_> = all
        .values()
        .flat_map(|r| r.inputs.iter().copied())
        .collect();
    let next = source
        .chain()
        .map_err(|_| Error::Scan)?
        .height()
        .checked_add(1)
        .ok_or(Error::Scan)?;
    let maturity = source.coinbase_maturity().map_err(|_| Error::Scan)?;
    let transparent: Vec<_> = scanner.unspent_coins(source).map_err(|_| Error::Scan)?.iter()
        .filter(|(_, (owner,_))| *owner == account).map(|(p,(_,c))| serde_json::json!({
            "transaction":hex(&p.transaction), "index":p.index, "amount_atoms":c.value.atoms().to_string(),
            "mature_next_block": !c.coinbase || next.saturating_sub(c.created_height) >= maturity,
            "reserved": claims.contains(&Input::Transparent { transaction:p.transaction,index:p.index }),
        })).collect();
    let private: Vec<_> = scanner
        .unspent_notes(source)
        .map_err(|_| Error::Scan)?
        .iter()
        .filter(|(_, n)| n.account() == account)
        .map(|(nf, n)| {
            serde_json::json!({
                "nullifier":hex(nf), "amount_atoms":n.expose_note().value().inner().to_string(),
                "reserved":claims.contains(&Input::Private { nullifier:*nf }),
            })
        })
        .collect();
    let reservations: Vec<_> = reservations
        .iter()
        .map(|r| {
            serde_json::json!({
                "reservation":hex(&r.id), "signed_bytes_available":r.expose_transaction().is_some(),
            })
        })
        .collect();
    Ok(
        serde_json::json!({ "checkpoint":receipt(store.checkpoint().map_err(storage)?,store.recovery_required().map_err(storage)?),
        "account":account, "validation_profile":hex(&profile), "validated_tip":hex(&source.chain().map_err(|_| Error::Scan)?.tip()),
        "transparent":transparent, "private":private, "reservations":reservations }),
    )
}

fn read_request(root: &Path, file: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    let path = root.join(balance::filename(file)?);
    balance::regular(&path).map_err(|_| Error::Transaction)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(&path)
            .map_err(|_| Error::Transaction)?
            .permissions()
            .mode()
            & 0o077
            != 0
        {
            return Err(Error::Transaction);
        }
    }
    let mut bytes = Zeroizing::new(Vec::new());
    File::open(path)
        .map_err(|_| Error::Transaction)?
        .take(65_537)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Transaction)?;
    if bytes.len() > 65_536 {
        return Err(Error::Transaction);
    }
    Ok(bytes)
}
