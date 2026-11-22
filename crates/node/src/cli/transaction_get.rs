//! Historical bytes authenticated before disclosure, with no runtime activation.
use super::*;

pub(super) fn execute(
    source: &DurableChain<V6Verifier>,
    transaction: [u8; 32],
    cp: Checkpoint,
    pin: Option<[u8; 32]>,
    output: &mut impl Write,
) -> Result<(), Error> {
    let found = crate::lookup::confirmed(source, transaction).map_err(|_| Error::Storage)?;
    let chain = source.chain().map_err(|_| Error::Storage)?;
    let bytes = found.as_ref().map(|found| {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut text = String::with_capacity(found.bytes.len() * 2);
        for byte in &found.bytes {
            text.push(HEX[usize::from(byte >> 4)] as char);
            text.push(HEX[usize::from(byte & 15)] as char);
        }
        text
    });
    report(
        &serde_json::json!({
            "operation":"transaction-get","profile":hex(&cp.profile),"public_key":hex(&cp.public_key),
            "revision":cp.revision,"transaction_id":hex(&transaction),"confirmed":found.is_some(),
            "transaction_hex":bytes,"validated_tip":hex(&chain.tip()),"height":chain.height().to_string(),
            "confirmation_block":found.as_ref().map(|f|hex(&f.confirmation.block)),
            "confirmation_height":found.as_ref().map(|f|f.confirmation.height.to_string()),
            "confirmations":found.as_ref().map_or(0,|f|f.confirmation.depth).to_string(),
            "exact_payload_authenticated":found.is_some(),"confirmation_scope":"transaction-effects-id",
            "chain_checkpoint":pin.map(|p|hex(&p)),"full_chain_replay":pin.is_none(),
            "network_started":false,"mempool_membership_proven":false,"network_delivery_proven":false,
        }),
        output,
    )
}
