//! Read-only pool operator preflight. It validates the manifest's token files,
//! opens the existing ledger, checks the pool identity and reports credited,
//! settled and available units. It never prints a token, binds no socket and
//! mutates nothing.
use super::*;

fn client_hex(client: &[u8; 16]) -> String {
    client.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn execute(
    root: &Path,
    config: &pool_config::Config,
    pool_id: [u8; 32],
    output: &mut impl Write,
) -> Result<(), Error> {
    // Tokens are read but never echoed; a malformed file fails the preflight.
    for client in &config.clients {
        let bytes = token_file(root, &client.token_file)?;
        crate::rpc::parse_token(&bytes).map_err(|_| Error::Credentials)?;
    }
    let path = root.join(name(&config.ledger)?);
    let limits = crate::mining::pool::ledger::Limits {
        max_shares: 1_000_000,
        max_clients: 1_024,
        max_units_per_share: 1_000,
        max_units_per_client: 1_000_000_000,
    };
    let ledger = crate::mining::pool::ledger::Ledger::open_read_only(&path, pool_id, limits)
        .map_err(|error| match error {
            crate::mining::pool::ledger::Error::PoolMismatch => Error::Configuration,
            _ => Error::Storage,
        })?;
    let mut configured = std::collections::BTreeSet::new();
    let mut entries = Vec::with_capacity(config.clients.len());
    let mut credited = 0u64;
    let mut settled = 0u64;
    let mut available = 0u64;
    for client in &config.clients {
        configured.insert(client.client);
        let total = ledger.total(client.client).map_err(|_| Error::Storage)?;
        let used = ledger.settled(client.client).map_err(|_| Error::Storage)?;
        let free = ledger
            .available(client.client)
            .map_err(|_| Error::Storage)?;
        credited = credited.checked_add(total).ok_or(Error::Runtime)?;
        settled = settled.checked_add(used).ok_or(Error::Runtime)?;
        available = available.checked_add(free).ok_or(Error::Runtime)?;
        entries.push(serde_json::json!({
            "client": client_hex(&client.client),
            "address": client.payout_address,
            "token": client.token_file,
            "credited": total.to_string(),
            "settled": used.to_string(),
            "available": free.to_string(),
        }));
    }
    // Credits held by a client that is no longer in the manifest stay visible so
    // an operator cannot silently strand them.
    let mut unconfigured = Vec::new();
    for (client, units) in ledger.clients().map_err(|_| Error::Storage)? {
        if !configured.contains(&client) {
            unconfigured.push(serde_json::json!({
                "client": client_hex(&client),
                "credited": units.to_string(),
            }));
        }
    }
    report(
        &serde_json::json!({
            "operation":"pool-status","ready":true,"pool":hex(&pool_id),
            "listen":config.listen.to_string(),"network":format!("{:?}", config.network).to_lowercase(),
            "ledger":config.ledger,"shares":ledger.share_count().map_err(|_| Error::Storage)?.to_string(),
            "clients":entries,"unconfigured":unconfigured,
            "credited_units":credited.to_string(),"settled_units":settled.to_string(),
            "available_units":available.to_string(),
            "listener_bound":false,"network_started":false
        }),
        output,
    )
}
