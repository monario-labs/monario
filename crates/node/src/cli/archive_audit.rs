//! Authenticated bounded archive reads; no runtime activation or trust flags saved.
use super::*;
use monario_chain::audit;

pub(super) fn execute(
    source: &DurableChain<V6Verifier>,
    after: [u8; 32],
    cp: Checkpoint,
    pin: Option<[u8; 32]>,
    output: &mut impl Write,
) -> Result<(), Error> {
    let page = audit::page(source, after).map_err(|error| match error {
        audit::Error::Cursor => Error::Configuration,
        audit::Error::Storage(StorageError::Pruned) => Error::Pruned,
        audit::Error::Storage(_) => Error::Storage,
    })?;
    report(
        &serde_json::json!({
            "operation":"archive-audit","profile":hex(&page.profile),"public_key":hex(&cp.public_key),
            "revision":cp.revision,"after":hex(&page.after),"end":hex(&page.end),
            "validated_tip":hex(&page.validated_tip),"blocks":page.blocks,"bytes":page.bytes,
            "at_tip":page.at_tip,"scope":"canonical-successors-only",
            "page_verification":"validated-archive-summary",
            "chain_checkpoint":pin.map(|p|hex(&p)),"full_chain_replay":pin.is_none(),"network_started":false,
        }),
        output,
    )
}
