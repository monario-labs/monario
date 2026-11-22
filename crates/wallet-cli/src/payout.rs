//! Execute one reviewed pool payout batch: plan fixed inputs against the
//! validated chain, sign through the ordinary construction path, and publish the
//! exact signed bytes to the pinned local inbox. The node still holds no key.
use super::*;
use monario_monetary::Amount;
use std::{fs::File, io::Read};

pub(super) struct Options {
    file: String,
    max_fee: Amount,
    destination: submission::Destination,
}

impl Options {
    pub(super) fn parse(options: &mut BTreeMap<String, OsString>) -> Result<Self, Error> {
        Ok(Self {
            file: balance::filename(&text(options.remove("--request"))?)?,
            max_fee: Amount::from_atoms(
                number(&text(options.remove("--max-fee-atoms"))?).map_err(|_| Error::Arguments)?,
            )
            .map_err(|_| Error::Arguments)?,
            destination: submission::Destination::parse(options)?,
        })
    }
}

pub(super) fn execute(
    root: &Path,
    store: &mut WalletStore,
    account: u32,
    scan: balance::Options,
    options: Options,
) -> Result<serde_json::Value, Error> {
    let path = root.join(&options.file);
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
    File::open(&path)
        .map_err(|_| Error::Transaction)?
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Transaction)?;
    if bytes.len() > 65536 {
        return Err(Error::Transaction);
    }
    let source = balance::open(&scan)?;
    // Fail before signing if the pinned inbox is unusable.
    options.destination.check(scan.profile)?;
    let plan =
        transactions::plan::prepare(store, account, &scan, &source, &bytes, options.max_fee)?;
    let fixed = serde_json::to_vec(&plan["request"]).map_err(|_| Error::Transaction)?;
    let signed = transactions::construct(store, account, &scan, &source, &fixed, options.max_fee)?;
    let mut signed = serde_json::to_value(&signed).map_err(|_| Error::Output)?;
    let reservation = id(signed["reservation"].as_str().ok_or(Error::Output)?)?;
    if let Some(fields) = signed.as_object_mut() {
        // Published bytes stay in the wallet reservation, not in stdout.
        fields.remove("transaction_hex");
    }
    let request = options.file;
    let submission = options
        .destination
        .publish(store, scan.profile, reservation)?;
    Ok(serde_json::json!({
        "operation":"payout-execute",
        "request":request,
        "required_atoms":plan["required_atoms"],
        "selected_atoms":plan["selected_atoms"],
        "input_count":plan["input_count"],
        "signed":signed,
        "submission":submission,
        "network_delivery_proven":false,
    }))
}
