//! Unsigned payment planning. Signing always consumes a reviewed fixed-input request.
use super::*;
use monario_wallet_scan::build::selection::{self, Pool};

pub(crate) struct Options {
    file: String,
    max_fee: Amount,
}
impl Options {
    pub(crate) fn parse(options: &mut BTreeMap<String, OsString>) -> Result<Self, Error> {
        Ok(Self {
            file: balance::filename(&text(options.remove("--request"))?)?,
            max_fee: atoms(&text(options.remove("--max-fee-atoms"))?)
                .map_err(|_| Error::Arguments)?,
        })
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u8,
    validated_tip: String,
    funding: String,
    payments: Vec<Recipient>,
    fee_atoms: String,
    expiry_height: u64,
    change: String,
}
pub(crate) fn execute(
    root: &Path,
    store: &WalletStore,
    account: u32,
    options: balance::Options,
    plan: Options,
) -> Result<serde_json::Value, Error> {
    let bytes = read_request(root, &plan.file)?;
    let source = balance::open(&options)?;
    prepare(store, account, &options, &source, &bytes, plan.max_fee)
}
pub(crate) fn prepare(
    store: &WalletStore,
    account: u32,
    options: &balance::Options,
    source: &DurableChain<V6Verifier>,
    bytes: &[u8],
    max_fee: Amount,
) -> Result<serde_json::Value, Error> {
    if bytes.len() > 65_536 {
        return Err(Error::Transaction);
    }
    let doc: Document = serde_json::from_slice(bytes).map_err(|_| Error::Transaction)?;
    let chain = source.chain().map_err(|_| Error::Scan)?;
    let checkpoint = store.checkpoint().map_err(storage)?;
    let next = chain.height().checked_add(1).ok_or(Error::Transaction)?;
    if doc.version != 1
        || hash(&doc.validated_tip)? != chain.tip()
        || doc.payments.is_empty()
        || doc.payments.len() > 32
        || doc.expiry_height < next
        || doc.expiry_height > next.saturating_add(100)
        || !matches!(doc.change.as_str(), "transparent" | "private")
    {
        return Err(Error::Transaction);
    }
    let pool = match doc.funding.as_str() {
        "transparent" => Pool::Transparent,
        "private" => Pool::Private,
        _ => return Err(Error::Transaction),
    };
    let fee = atoms(&doc.fee_atoms)?;
    if fee > max_fee {
        return Err(Error::Transaction);
    }
    let mut required = fee;
    for p in &doc.payments {
        let n = atoms(&p.amount_atoms)?;
        Payment::new(
            Address::decode(&p.address, checkpoint.network).map_err(|_| Error::Transaction)?,
            n,
            None,
        )
        .map_err(|_| Error::Transaction)?;
        required = required.checked_add(n).map_err(|_| Error::Transaction)?;
    }
    let scanner = balance::prepare(store, account, options, source)?;
    let selected = selection::select(source, &scanner, store, account, pool, required)
        .map_err(|_| Error::Transaction)?;
    let (funding, count) = match selected.funding {
        Funding::Transparent(points) => {
            let count = points.len();
            (
                serde_json::json!({"pool":"transparent", "inputs":points.iter().map(|p| serde_json::json!({"transaction":hex(&p.transaction),"index":p.index})).collect::<Vec<_>>()}),
                count,
            )
        }
        Funding::Private(ids) => {
            let count = ids.len();
            (
                serde_json::json!({"pool":"private", "inputs":ids.iter().map(|p| hex(p)).collect::<Vec<_>>()}),
                count,
            )
        }
    };
    let change = selected
        .total
        .checked_sub(required)
        .map_err(|_| Error::Transaction)?;
    if doc.payments.len() + usize::from(change != Amount::ZERO) > 32 {
        return Err(Error::Transaction);
    }
    let fixed = serde_json::json!({"version":1,"validated_tip":hex(&chain.tip()),"funding":funding,
        "payments":doc.payments,"fee_atoms":doc.fee_atoms,"expiry_height":doc.expiry_height,"change":doc.change});
    // Keep the returned request on the existing, strictly decoded signing interface.
    request(
        &serde_json::to_vec(&fixed).map_err(|_| Error::Transaction)?,
        checkpoint.network,
        account,
        chain.tip(),
    )?;
    Ok(
        serde_json::json!({"wallet":receipt(checkpoint, store.recovery_required().map_err(storage)?),
        "account":account,"profile":hex(&options.profile),"validated_tip":hex(&chain.tip()),"height":chain.height(),
        "required_atoms":required.atoms().to_string(),"selected_atoms":selected.total.atoms().to_string(),
        "fee_atoms":fee.atoms().to_string(),"change_atoms":change.atoms().to_string(),"input_count":count,
        "request":fixed,"signed":false,"broadcast":false,"claims_reserved":false}),
    )
}
