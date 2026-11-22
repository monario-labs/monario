//! Bounded local rebroadcast of existing signatures; never releases wallet claims.
use super::*;
use monario_chain::storage::DurableChain;
use monario_v6::V6Verifier;
use monario_wallet_scan::pending::{self, Status};
use std::ops::Bound::{Excluded, Unbounded};

const PAGE: usize = 8;
pub(crate) struct Options {
    chain: balance::Options,
    destination: Destination,
    after: Option<[u8; 16]>,
}
impl Options {
    pub(crate) fn parse(options: &mut BTreeMap<String, OsString>) -> Result<Self, Error> {
        Ok(Self {
            chain: balance::Options::service_status(options)?,
            destination: Destination::parse(options)?,
            after: options
                .remove("--after-reservation")
                .map(|v| id(&text(Some(v))?))
                .transpose()?,
        })
    }
}
pub(crate) fn execute(store: &WalletStore, options: Options) -> Result<serde_json::Value, Error> {
    if store.recovery_required().map_err(storage)? {
        return Err(Error::RecoveryLocked);
    }
    let source = balance::open(&options.chain)?;
    let mut result = step(store, &source, options.destination, options.after, || {})?;
    result["chain_checkpoint"] = serde_json::json!(options.chain.checkpoint.map(|p| hex(&p)));
    result["full_chain_replay"] = options.chain.checkpoint.is_none().into();
    Ok(result)
}

pub(crate) fn step(
    store: &WalletStore,
    source: &DurableChain<V6Verifier>,
    destination: Destination,
    after: Option<[u8; 16]>,
    mut published: impl FnMut(),
) -> Result<serde_json::Value, Error> {
    if store.recovery_required().map_err(storage)? {
        return Err(Error::RecoveryLocked);
    }
    let chain = source.chain().map_err(|_| Error::Scan)?;
    let profile = chain.validation_profile();
    let mut inbox = Inbox::open(
        &destination.directory,
        &destination.inbox,
        profile,
        destination.node_key,
    )
    .map_err(|_| Error::Submission)?;
    if inbox.lifecycle().map_err(|_| Error::Submission)?.phase != 0 {
        return Err(Error::Submission);
    }
    let records = store.reservations().map_err(storage)?;
    let mut entries = records.range((after.map_or(Unbounded, Excluded), Unbounded));
    let mut results = Vec::new();
    let mut last = None;
    for (reservation, record) in entries.by_ref().take(PAGE) {
        let state = if record.profile != profile {
            "other-profile"
        } else {
            match pending::status(source, store, *reservation).map_err(|_| Error::Transaction)? {
                Status::Pending => "valid-for-next-block",
                Status::Confirmed => "confirmed",
                Status::Expired => "expired",
                Status::Unsigned => "unsigned",
                Status::NeedsBytes => "needs-bytes",
                Status::Unavailable => "unavailable",
            }
        };
        let submission = if state == "valid-for-next-block" {
            let bytes = record.expose_transaction().ok_or(Error::Transaction)?;
            let token = inbox.enqueue(bytes).map_err(|_| Error::Submission)?;
            published(); // Test seam for abrupt exit after one durable publication.
            Some(hex(&token))
        } else {
            None
        };
        results.push(serde_json::json!({
            "reservation":hex(reservation),"transaction_id":record.transaction.map(|t|hex(&t)),
            "state":state,"queued_exact_bytes":submission.is_some(),"submission":submission,
        }));
        last = Some(*reservation);
    }
    let more = entries.next().is_some();
    Ok(serde_json::json!({
        "checkpoint":receipt(store.checkpoint().map_err(storage)?,false),
        "validation_profile":hex(&profile),"node_public_key":hex(&destination.node_key),
        "validated_tip":hex(&chain.tip()),"height":chain.height().to_string(),
        "examined":results.len(),"results":results,
        "next_after_reservation":if more {last.map(|v|hex(&v))} else {None},
        "wallet_claims_retained":true,"mempool_membership_proven":false,
        "network_delivery_proven":false,"network_started":false,
    }))
}
