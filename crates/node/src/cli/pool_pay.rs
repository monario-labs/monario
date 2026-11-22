//! Bridge from a verified settlement to the wallet's existing unsigned payment
//! planner. It never signs, selects wallet inputs or broadcasts. Each emitted
//! file is a standard `plan-payment` request bound to the current validated tip.
use super::*;

/// `plan-payment` accepts at most 32 recipients per transaction.
const MAX_PAYMENTS: usize = 32;

pub struct Request<'a> {
    pub receipt: &'a str,
    pub fee: u64,
    pub expiry_blocks: u32,
    pub prefix: &'a str,
}

pub fn execute(
    root: &Path,
    config: &pool_config::Config,
    pool_id: [u8; 32],
    source: &DurableChain<V6Verifier>,
    request: Request<'_>,
    output: &mut impl Write,
) -> Result<(), Error> {
    if request.fee == 0 || !(1..=100).contains(&request.expiry_blocks) {
        return Err(Error::Arguments);
    }
    let prefix = name(request.prefix)?;
    if prefix.len() > 56 {
        return Err(Error::Arguments);
    }
    let payments = pool_verify::payments(
        &bounded(root, &name(request.receipt)?, 65_536)?,
        config,
        pool_id,
        &pool_verify::recorded(root, config, pool_id, request.receipt)?,
    )?;
    let fee = request.fee;
    let expiry_blocks = request.expiry_blocks;
    if payments.is_empty() {
        return Err(Error::Configuration);
    }
    let batches: Vec<&[(String, u64)]> = payments.chunks(MAX_PAYMENTS).collect();
    let chain = source.chain().map_err(|_| Error::Storage)?;
    let tip = chain.tip();
    let height = chain.height();
    let expiry = height
        .checked_add(u64::from(expiry_blocks))
        .ok_or(Error::Runtime)?;
    let total_atoms = payments
        .iter()
        .try_fold(0u64, |total, (_, atoms)| total.checked_add(*atoms))
        .ok_or(Error::Runtime)?;
    let count = u64::try_from(batches.len()).map_err(|_| Error::Runtime)?;
    let total_cost = total_atoms
        .checked_add(fee.checked_mul(count).ok_or(Error::Runtime)?)
        .ok_or(Error::Runtime)?;
    let mut files = Vec::with_capacity(batches.len());
    for (index, batch) in batches.iter().enumerate() {
        let file = name(&format!("{prefix}-{index}.json"))?;
        let path = root.join(&file);
        let document = serde_json::json!({
            "version":1,
            "validated_tip":hex(&tip),
            "funding":"transparent",
            "payments":batch.iter().map(|(address, atoms)| serde_json::json!({
                "address":address,"amount_atoms":atoms.to_string()})).collect::<Vec<_>>(),
            "fee_atoms":fee.to_string(),
            "expiry_height":expiry,
            "change":"transparent"
        });
        let bytes = serde_json::to_vec_pretty(&document).map_err(|_| Error::Output)?;
        // Never overwrite: an existing request may already be reviewed or signed.
        let mut file_handle = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|_| Error::Storage)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .map_err(|_| Error::Storage)?;
        }
        file_handle
            .write_all(&bytes)
            .and_then(|_| file_handle.write_all(b"\n"))
            .map_err(|_| Error::Output)?;
        files.push(serde_json::json!({"file":file,"payments":batch.len()}));
    }
    report(
        &serde_json::json!({
            "operation":"pool-pay","verified":true,"files":files,
            "batches":count.to_string(),"payments":payments.len(),
            "validated_tip":hex(&tip),"height":height.to_string(),"expiry_height":expiry.to_string(),
            "fee_atoms_per_batch":fee.to_string(),"total_atoms":total_atoms.to_string(),
            "total_cost_atoms":total_cost.to_string(),"pool":hex(&pool_id),
            "signed":false,"broadcast":false,
            "next":"run monario-wallet plan-payment on each file against this exact tip, review, construct, then submit"
        }),
        output,
    )
}
