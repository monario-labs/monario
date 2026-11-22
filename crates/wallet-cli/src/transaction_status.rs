//! Current validated transaction state, independent of historical inbox observations.
use super::*;
use monario_chain::storage::DurableChain;
use monario_v6::V6Verifier;
use monario_wallet_scan::pending::{self, Status};

pub(super) struct Options {
    chain: balance::Options,
    reservation: [u8; 16],
}
impl Options {
    pub(super) fn parse(options: &mut BTreeMap<String, OsString>) -> Result<Self, Error> {
        Ok(Self {
            chain: balance::Options::service_status(options)?,
            reservation: id(&text(options.remove("--reservation"))?)?,
        })
    }
}
pub(super) fn execute(store: &WalletStore, options: Options) -> Result<serde_json::Value, Error> {
    let source = balance::open(&options.chain)?;
    let mut value = inspect(store, &source, options.reservation)?;
    value["chain_checkpoint"] = serde_json::json!(options.chain.checkpoint.map(|p| hex(&p)));
    value["full_chain_replay"] = options.chain.checkpoint.is_none().into();
    Ok(value)
}
pub(super) fn inspect(
    store: &WalletStore,
    source: &DurableChain<V6Verifier>,
    reservation: [u8; 16],
) -> Result<serde_json::Value, Error> {
    let state = pending::status(source, store, reservation).map_err(|_| Error::Transaction)?;
    let r = store
        .reservations()
        .map_err(storage)?
        .get(&reservation)
        .ok_or(Error::Transaction)?;
    let chain = source.chain().map_err(|_| Error::Scan)?;
    let confirmation = r
        .transaction
        .map(|tx| source.transaction_confirmation(&tx))
        .transpose()
        .map_err(|_| Error::Scan)?
        .flatten();
    if confirmation.is_some() != (state == Status::Confirmed) {
        return Err(Error::Scan);
    }
    Ok(serde_json::json!({
        "checkpoint":receipt(store.checkpoint().map_err(storage)?,store.recovery_required().map_err(storage)?),
        "validation_profile":hex(&chain.validation_profile()),
        "validated_tip":hex(&chain.tip()),"height":chain.height().to_string(),
        "reservation":hex(&reservation),"transaction_id":r.transaction.map(|t|hex(&t)),
        "state":match state {
            Status::Unsigned=>"unsigned",Status::Confirmed=>"confirmed",Status::Expired=>"expired",
            Status::Pending=>"valid-for-next-block",Status::Unavailable=>"unavailable",Status::NeedsBytes=>"needs-bytes",
        },
        "expiry_height":r.expiry_height.to_string(),"input_claims":r.inputs.len(),
        "signed_bytes_available":r.expose_transaction().is_some(),"wallet_claims_retained":true,
        "confirmation_scope":"transaction-effects-id",
        "chain_confirmation_proven":state==Status::Confirmed,
        "confirmations":confirmation.map_or(0, |c| c.depth).to_string(),
        "confirmation_block":confirmation.map(|c|hex(&c.block)),
        "confirmation_height":confirmation.map(|c|c.height.to_string()),
        "mempool_membership_proven":false,"network_delivery_proven":false,
    }))
}
