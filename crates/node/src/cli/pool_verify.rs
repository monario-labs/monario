//! Settlement receipt verification. A receipt is only a claim; the durable ledger
//! is the authority. This command re-reads the recorded settlement for the period
//! and requires exact agreement on client, units, atoms, address, totals and pool
//! identity. It is read-only, binds no socket and prints no secret.
use super::*;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    operation: String,
    state: String,
    settled: bool,
    period: String,
    pot_atoms: String,
    units: String,
    atoms: String,
    clients: Vec<Entry>,
    pool: String,
    signed: bool,
    broadcast: bool,
    on_chain_payment: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    client: String,
    address: String,
    units: String,
    atoms: String,
}

fn decimal(text: &str) -> Result<u64, Error> {
    if text.is_empty() || text.len() > 20 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::Configuration);
    }
    text.parse().map_err(|_| Error::Configuration)
}

fn parse(bytes: &[u8]) -> Result<Document, Error> {
    if bytes.is_empty() || bytes.len() > 65_536 {
        return Err(Error::Configuration);
    }
    serde_json::from_slice(bytes).map_err(|_| Error::Configuration)
}

fn open(
    root: &Path,
    config: &pool_config::Config,
    pool_id: [u8; 32],
) -> Result<crate::mining::pool::ledger::Ledger, Error> {
    let path = root.join(name(&config.ledger)?);
    let limits = crate::mining::pool::ledger::Limits {
        max_shares: 1_000_000,
        max_clients: 1_024,
        max_units_per_share: 1_000,
        max_units_per_client: 1_000_000_000,
    };
    crate::mining::pool::ledger::Ledger::open_read_only(&path, pool_id, limits).map_err(|error| {
        match error {
            crate::mining::pool::ledger::Error::PoolMismatch => Error::Configuration,
            _ => Error::Storage,
        }
    })
}

/// Recorded ledger rows for the receipt's declared period. Not yet verified.
pub(crate) fn recorded(
    root: &Path,
    config: &pool_config::Config,
    pool_id: [u8; 32],
    receipt: &str,
) -> Result<Vec<crate::mining::pool::ledger::Payout>, Error> {
    let bytes = bounded(root, &name(receipt)?, 65_536)?;
    let doc = parse(&bytes)?;
    let ledger = open(root, config, pool_id)?;
    ledger
        .settlement(decimal(&doc.period)?)
        .map_err(|_| Error::Storage)
}

/// Verify the receipt and return its payments as `(address, atoms)` ordered by
/// client ID. The caller must pass the rows returned by `recorded`.
pub(crate) fn payments(
    bytes: &[u8],
    config: &pool_config::Config,
    pool_id: [u8; 32],
    rows: &[crate::mining::pool::ledger::Payout],
) -> Result<Vec<(String, u64)>, Error> {
    check(bytes, config, pool_id, rows)?;
    let doc = parse(bytes)?;
    let mut entries = Vec::with_capacity(doc.clients.len());
    for entry in &doc.clients {
        entries.push((
            fixed_hex::<16>(&entry.client)?,
            entry.address.clone(),
            decimal(&entry.atoms)?,
        ));
    }
    entries.sort_by_key(|entry| entry.0);
    Ok(entries
        .into_iter()
        .map(|(_, address, atoms)| (address, atoms))
        .collect())
}

/// Recompute agreement from the receipt and the ledger rows for its period.
pub fn check(
    bytes: &[u8],
    config: &pool_config::Config,
    pool_id: [u8; 32],
    rows: &[crate::mining::pool::ledger::Payout],
) -> Result<serde_json::Value, Error> {
    if rows.is_empty() {
        return Err(Error::Configuration);
    }
    let doc = parse(bytes)?;
    if doc.operation != "pool-payout"
        || doc.state != "settled"
        || !doc.settled
        || doc.signed
        || doc.broadcast
        || doc.on_chain_payment
        || fixed_hex::<32>(&doc.pool)? != pool_id
        || doc.clients.len() != rows.len()
    {
        return Err(Error::Configuration);
    }
    let period = decimal(&doc.period)?;
    if period == 0 {
        return Err(Error::Configuration);
    }
    let mut receipt = Vec::with_capacity(doc.clients.len());
    for entry in &doc.clients {
        let client = fixed_hex::<16>(&entry.client)?;
        let configured = config
            .clients
            .iter()
            .find(|configured| configured.client == client)
            .ok_or(Error::Configuration)?;
        if configured.payout_address != entry.address {
            return Err(Error::Configuration);
        }
        receipt.push((client, decimal(&entry.units)?, decimal(&entry.atoms)?));
    }
    receipt.sort_by_key(|entry| entry.0);
    let mut recorded: Vec<([u8; 16], u64, u64)> = rows
        .iter()
        .map(|payout| (payout.client, payout.units, payout.atoms))
        .collect();
    recorded.sort_by_key(|entry| entry.0);
    if receipt != recorded
        || receipt
            .iter()
            .any(|(_, units, atoms)| *units == 0 || *atoms == 0)
    {
        return Err(Error::Configuration);
    }
    let units = receipt
        .iter()
        .try_fold(0u64, |total, (_, units, _)| total.checked_add(*units))
        .ok_or(Error::Runtime)?;
    let atoms = receipt
        .iter()
        .try_fold(0u64, |total, (_, _, atoms)| total.checked_add(*atoms))
        .ok_or(Error::Runtime)?;
    if units != decimal(&doc.units)? || atoms != decimal(&doc.atoms)? {
        return Err(Error::Configuration);
    }
    if atoms != decimal(&doc.pot_atoms)? || atoms == 0 {
        return Err(Error::Configuration);
    }
    Ok(serde_json::json!({
        "operation":"pool-verify","verified":true,"pool":hex(&pool_id),
        "period":period.to_string(),"clients":receipt.len(),"units":units.to_string(),
        "atoms":atoms.to_string(),"signed":false,"broadcast":false,
        "ledger_is_authority":true
    }))
}

pub fn execute(
    root: &Path,
    config: &pool_config::Config,
    pool_id: [u8; 32],
    receipt: &str,
    output: &mut impl Write,
) -> Result<(), Error> {
    let bytes = bounded(root, &name(receipt)?, 65_536)?;
    let doc = parse(&bytes)?;
    let ledger = open(root, config, pool_id)?;
    let rows = ledger
        .settlement(decimal(&doc.period)?)
        .map_err(|_| Error::Storage)?;
    report(&check(&bytes, config, pool_id, &rows)?, output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> pool_config::Config {
        let address = monario_address::Address::new(
            monario_address::Network::Regtest,
            monario_address::Receiver::Transparent(
                monario_address::TransparentReceiver::PublicKeyHash([7; 20]),
            ),
        )
        .encode();
        let clients = vec![
            pool_config::Client {
                client: [7; 16],
                token_file: "a.token".into(),
                payout_address: address.clone(),
                prefix: [0; 24],
                start: 0,
                end: 1,
                share_target: [255; 32],
            },
            pool_config::Client {
                client: [8; 16],
                token_file: "b.token".into(),
                payout_address: address,
                prefix: [0; 24],
                start: 2,
                end: 3,
                share_target: [255; 32],
            },
        ];
        pool_config::Config {
            listen: "127.0.0.1:1".parse().unwrap(),
            network: monario_address::Network::Regtest,
            payout_address: String::new(),
            ledger: "pool.sqlite".into(),
            poll_ms: 1000,
            timestamp_seconds: 60,
            policy: crate::mining::pool::Policy {
                units_per_share: 1,
                units_per_block_candidate: 0,
            },
            clients,
        }
    }

    fn receipt(field_overrides: &str) -> Vec<u8> {
        format!(
            r#"{{"operation":"pool-payout","state":"settled","settled":true,"period":"4",
            "pot_atoms":"10","units":"10","atoms":"10","clients":[
            {{"client":"07070707070707070707070707070707","address":"{a}","units":"6","atoms":"6"}},
            {{"client":"08080808080808080808080808080808","address":"{a}","units":"4","atoms":"4"}}],
            "pool":"{p}","signed":false,"broadcast":false,"on_chain_payment":false{field_overrides}}}"#,
            a = monario_address::Address::new(
                monario_address::Network::Regtest,
                monario_address::Receiver::Transparent(
                    monario_address::TransparentReceiver::PublicKeyHash([7; 20])
                )
            )
            .encode(),
            p = hex(&[3; 32]),
        )
        .into_bytes()
    }

    fn rows() -> Vec<crate::mining::pool::ledger::Payout> {
        vec![
            crate::mining::pool::ledger::Payout {
                client: [7; 16],
                units: 6,
                atoms: 6,
            },
            crate::mining::pool::ledger::Payout {
                client: [8; 16],
                units: 4,
                atoms: 4,
            },
        ]
    }

    #[test]
    fn matching_receipt_verifies_and_tampering_fails_closed() {
        let bytes = receipt("");
        let value = check(&bytes, &config(), [3; 32], &rows()).unwrap();
        assert_eq!(value["verified"], true);
        assert_eq!(value["atoms"], "10");

        let tampered = String::from_utf8(receipt(""))
            .unwrap()
            .replace(r#""atoms":"6""#, r#""atoms":"5""#);
        assert!(check(tampered.as_bytes(), &config(), [3; 32], &rows()).is_err());

        let wrong_pool = String::from_utf8(receipt("")).unwrap().replace(
            &format!(r#""pool":"{}""#, hex(&[3; 32])),
            &format!(r#""pool":"{}""#, hex(&[4; 32])),
        );
        assert!(check(wrong_pool.as_bytes(), &config(), [3; 32], &rows()).is_err());

        let unknown_field = receipt(r#","extra":true"#);
        assert!(check(&unknown_field, &config(), [3; 32], &rows()).is_err());

        let empty_rows = [];
        assert!(check(&bytes, &config(), [3; 32], &empty_rows).is_err());
    }

    #[test]
    fn payments_are_ordered_by_client_and_sum_to_the_pot() {
        let payments = payments(&receipt(""), &config(), [3; 32], &rows()).unwrap();
        assert_eq!(payments.len(), 2);
        assert_eq!(payments.iter().map(|(_, atoms)| atoms).sum::<u64>(), 10);
        assert!(payments.iter().all(|(address, _)| !address.is_empty()));
    }
}
