//! Strict private pool-server manifest. Every field is explicit, unknown fields
//! fail closed, and no secret is accepted inline: tokens are names of private
//! `.token` files inside the identity directory, read through `token_file`.
use super::*;
use serde::Deserialize;

const MAX_BYTES: u64 = 65_536;
const MAX_CLIENTS: usize = crate::mining::pool::session::MAX_CLIENTS;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u8,
    listen: String,
    network: String,
    payout_address: String,
    ledger: String,
    poll_ms: u64,
    timestamp_seconds: u32,
    units_per_share: u64,
    units_per_block_candidate: u64,
    clients: Vec<Entry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    client: String,
    token_file: String,
    payout_address: String,
    prefix: String,
    start: u64,
    end: u64,
    share_target: String,
}

/// One authenticated miner. `share_target` is a 32-byte little-endian target that
/// must be at least as easy as the current block target; the server refuses a
/// client whose assignment cannot be built rather than accepting weaker work.
pub struct Client {
    pub client: [u8; 16],
    pub token_file: String,
    /// Transparent destination used only by the settlement planner.
    pub payout_address: String,
    pub prefix: [u8; 24],
    pub start: u64,
    pub end: u64,
    pub share_target: [u8; 32],
}

pub struct Config {
    pub listen: SocketAddr,
    pub network: Network,
    pub payout_address: String,
    pub ledger: String,
    pub poll_ms: u64,
    pub timestamp_seconds: u32,
    pub policy: crate::mining::pool::Policy,
    pub clients: Vec<Client>,
}

/// Parse and validate a bounded pool-server manifest. Opens no database, reads
/// no token file and binds no listener.
pub fn parse(bytes: &[u8]) -> Result<Config, Error> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_BYTES {
        return Err(Error::Configuration);
    }
    let doc: Document = serde_json::from_slice(bytes).map_err(|_| Error::Configuration)?;
    if doc.version != 1
        || doc.clients.is_empty()
        || doc.clients.len() > MAX_CLIENTS
        || !(100..=60_000).contains(&doc.poll_ms)
        || doc.timestamp_seconds == 0
        || doc.timestamp_seconds > 3_600
        || doc.units_per_share == 0
        || doc
            .units_per_share
            .checked_add(doc.units_per_block_candidate)
            .is_none()
    {
        return Err(Error::Configuration);
    }
    let listen: SocketAddr = doc.listen.parse().map_err(|_| Error::Configuration)?;
    if listen.port() == 0 {
        return Err(Error::Configuration);
    }
    let network = match doc.network.as_str() {
        "main" => Network::Main,
        "test" => Network::Test,
        "regtest" => Network::Regtest,
        _ => return Err(Error::Configuration),
    };
    if doc.payout_address.is_empty() || doc.payout_address.len() > 128 {
        return Err(Error::Configuration);
    }
    match monario_address::Address::decode(&doc.payout_address, network)
        .map_err(|_| Error::Configuration)?
        .receiver()
    {
        monario_address::Receiver::Transparent(_) => {}
        monario_address::Receiver::Private(_) => return Err(Error::Configuration),
    }
    let ledger = name(&doc.ledger)?;
    if !ledger.ends_with(".sqlite") {
        return Err(Error::Configuration);
    }
    let mut clients = Vec::with_capacity(doc.clients.len());
    for entry in doc.clients {
        let token_file = name(&entry.token_file)?;
        if !token_file.ends_with(".token") {
            return Err(Error::Configuration);
        }
        let client = fixed_hex::<16>(&entry.client)?;
        let prefix = fixed_hex::<24>(&entry.prefix)?;
        let share_target = fixed_hex::<32>(&entry.share_target)?;
        if client == [0; 16]
            || entry.start > entry.end
            || entry.payout_address.is_empty()
            || entry.payout_address.len() > 128
        {
            return Err(Error::Configuration);
        }
        match monario_address::Address::decode(&entry.payout_address, network)
            .map_err(|_| Error::Configuration)?
            .receiver()
        {
            monario_address::Receiver::Transparent(_) => {}
            monario_address::Receiver::Private(_) => return Err(Error::Configuration),
        }
        clients.push(Client {
            client,
            token_file,
            payout_address: entry.payout_address,
            prefix,
            start: entry.start,
            end: entry.end,
            share_target,
        });
    }
    // A duplicate identity or an overlapping nonce partition can never serve two
    // clients; reject it before any connection is accepted.
    for (index, client) in clients.iter().enumerate() {
        if clients[..index]
            .iter()
            .any(|other| other.client == client.client)
        {
            return Err(Error::Configuration);
        }
        if clients[..index].iter().any(|other| {
            other.prefix == client.prefix && !(client.end < other.start || other.end < client.start)
        }) {
            return Err(Error::Configuration);
        }
    }
    Ok(Config {
        listen,
        network,
        payout_address: doc.payout_address,
        ledger,
        poll_ms: doc.poll_ms,
        timestamp_seconds: doc.timestamp_seconds,
        policy: crate::mining::pool::Policy {
            units_per_share: doc.units_per_share,
            units_per_block_candidate: doc.units_per_block_candidate,
        },
        clients,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address() -> String {
        monario_address::Address::new(
            Network::Regtest,
            monario_address::Receiver::Transparent(
                monario_address::TransparentReceiver::PublicKeyHash([7; 20]),
            ),
        )
        .encode()
    }

    fn document() -> serde_json::Value {
        serde_json::json!({
            "version": 1,
            "listen": "127.0.0.1:19444",
            "network": "regtest",
            "payout_address": address(),
            "ledger": "pool.sqlite",
            "poll_ms": 1000,
            "timestamp_seconds": 60,
            "units_per_share": 1,
            "units_per_block_candidate": 4,
            "clients": [
                {"client": "07070707070707070707070707070707", "token_file": "alice.token", "payout_address": address(),
                 "prefix": "000000000000000000000000000000000000000000000000", "start": 0, "end": 4294967295u64,
                 "share_target": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
                {"client": "08080808080808080808080808080808", "token_file": "bob.token", "payout_address": address(),
                 "prefix": "000000000000000000000000000000000000000000000000", "start": 4294967296u64, "end": 8589934591u64,
                 "share_target": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}
            ]
        })
    }

    #[test]
    fn valid_manifest_parses_with_disjoint_clients() {
        let config = parse(document().to_string().as_bytes()).unwrap();
        assert_eq!(config.listen.port(), 19444);
        assert_eq!(config.network, Network::Regtest);
        assert_eq!(config.clients.len(), 2);
        assert_eq!(config.policy.units_per_block_candidate, 4);
        assert_eq!(config.clients[1].start, 4_294_967_296);
    }

    #[test]
    fn unknown_fields_overlaps_and_inline_secrets_fail_closed() {
        let mut extra = document();
        extra["token"] = serde_json::json!("inline secret");
        assert!(parse(extra.to_string().as_bytes()).is_err());

        let mut overlap = document();
        overlap["clients"][1]["start"] = serde_json::json!(0);
        assert!(parse(overlap.to_string().as_bytes()).is_err());

        let mut duplicate = document();
        duplicate["clients"][1]["client"] = duplicate["clients"][0]["client"].clone();
        assert!(parse(duplicate.to_string().as_bytes()).is_err());

        let mut bad_token = document();
        bad_token["clients"][0]["token_file"] = serde_json::json!("alice.tok");
        assert!(parse(bad_token.to_string().as_bytes()).is_err());

        let mut bad_ledger = document();
        bad_ledger["ledger"] = serde_json::json!("pool.db");
        assert!(parse(bad_ledger.to_string().as_bytes()).is_err());

        let mut bad_target = document();
        bad_target["clients"][0]["share_target"] = serde_json::json!("00");
        assert!(parse(bad_target.to_string().as_bytes()).is_err());

        let mut no_clients = document();
        no_clients["clients"] = serde_json::json!([]);
        assert!(parse(no_clients.to_string().as_bytes()).is_err());

        let mut wrong_version = document();
        wrong_version["version"] = serde_json::json!(2);
        assert!(parse(wrong_version.to_string().as_bytes()).is_err());

        assert!(parse(b"").is_err());
        assert!(parse(&[0u8; MAX_BYTES as usize + 1]).is_err());
    }
}
