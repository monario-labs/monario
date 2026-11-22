//! Proportional pool settlement over the durable share ledger. This command
//! authorizes exact payouts and records them so a period cannot pay twice; it
//! holds no key, signs nothing, broadcasts nothing and creates no transaction.
use super::*;

/// Exact proportional split of `pot` atoms over `available` share units. Every
/// atom is assigned: integer remainders go to the largest fractional remainders,
/// ties broken by lower client ID. The result sums to `pot`.
pub fn plan(clients: &[[u8; 16]], available: &[u64], pot: u64) -> Result<Vec<u64>, Error> {
    if clients.len() != available.len() || clients.is_empty() || pot == 0 {
        return Err(Error::Configuration);
    }
    let total: u128 = available.iter().map(|units| u128::from(*units)).sum();
    if total == 0 {
        return Err(Error::Configuration);
    }
    let pot = u128::from(pot);
    let mut atoms = Vec::with_capacity(available.len());
    let mut remainders = Vec::with_capacity(available.len());
    let mut assigned = 0u128;
    for (index, units) in available.iter().enumerate() {
        let share = pot * u128::from(*units);
        let exact = share / total;
        atoms.push(u64::try_from(exact).map_err(|_| Error::Configuration)?);
        assigned += exact;
        if *units > 0 {
            remainders.push((share % total, index));
        }
    }
    remainders.sort_by(|left, right| {
        right
            .0
            .cmp(&left.0)
            .then_with(|| clients[left.1].cmp(&clients[right.1]))
    });
    if remainders.is_empty() {
        return Err(Error::Configuration);
    }
    let mut leftover = pot - assigned;
    let mut position = 0usize;
    while leftover > 0 {
        let index = remainders[position % remainders.len()].1;
        atoms[index] = atoms[index].checked_add(1).ok_or(Error::Configuration)?;
        leftover -= 1;
        position += 1;
    }
    Ok(atoms)
}

fn client_hex(client: &[u8; 16]) -> String {
    client.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Open the existing ledger, plan the period and record it atomically. Clients
/// with no available units are skipped; skipped clients keep their credits.
pub fn execute(
    root: &Path,
    config: &pool_config::Config,
    pool_id: [u8; 32],
    period: u64,
    pot: u64,
    output: &mut impl Write,
) -> Result<(), Error> {
    let path = root.join(name(&config.ledger)?);
    let limits = crate::mining::pool::ledger::Limits {
        max_shares: 1_000_000,
        max_clients: 1_024,
        max_units_per_share: 1_000,
        max_units_per_client: 1_000_000_000,
    };
    let mut ledger =
        crate::mining::pool::ledger::Ledger::open(&path, pool_id, limits).map_err(|error| {
            match error {
                crate::mining::pool::ledger::Error::PoolMismatch => Error::Configuration,
                _ => Error::Storage,
            }
        })?;
    let mut lines = Vec::new();
    for client in &config.clients {
        let available = ledger
            .available(client.client)
            .map_err(|_| Error::Storage)?;
        if available > 0 {
            lines.push((client.client, client.payout_address.clone(), available));
        }
    }
    if lines.is_empty() {
        return report(
            &serde_json::json!({"operation":"pool-payout","state":"no_units","period":period.to_string(),
            "pot_atoms":pot.to_string(),"pool":hex(&pool_id),"settled":false,"signed":false,"broadcast":false}),
            output,
        );
    }
    let clients: Vec<[u8; 16]> = lines.iter().map(|line| line.0).collect();
    let units: Vec<u64> = lines.iter().map(|line| line.2).collect();
    let atoms = plan(&clients, &units, pot)?;
    let mut payouts = Vec::new();
    let mut total_units = 0u64;
    let mut total_atoms = 0u64;
    let mut entries = Vec::new();
    for ((client, address, available), atoms) in lines.iter().zip(atoms) {
        // A share too small to earn one atom keeps its units for the next period.
        if atoms == 0 {
            continue;
        }
        payouts.push(crate::mining::pool::ledger::Payout {
            client: *client,
            units: *available,
            atoms,
        });
        total_units = total_units.checked_add(*available).ok_or(Error::Runtime)?;
        total_atoms = total_atoms.checked_add(atoms).ok_or(Error::Runtime)?;
        entries.push(serde_json::json!({
            "client": client_hex(client),
            "address": address,
            "units": available.to_string(),
            "atoms": atoms.to_string(),
        }));
    }
    if payouts.is_empty() || total_atoms != pot {
        return Err(Error::Configuration);
    }
    ledger
        .settle(period, &payouts)
        .map_err(|error| match error {
            crate::mining::pool::ledger::Error::AlreadyExists
            | crate::mining::pool::ledger::Error::Invalid
            | crate::mining::pool::ledger::Error::Capacity
            | crate::mining::pool::ledger::Error::Overflow => Error::Configuration,
            _ => Error::Storage,
        })?;
    report(
        &serde_json::json!({"operation":"pool-payout","state":"settled","settled":true,
        "period":period.to_string(),"pot_atoms":pot.to_string(),"units":total_units.to_string(),
        "atoms":total_atoms.to_string(),"clients":entries,"pool":hex(&pool_id),
        "signed":false,"broadcast":false,"on_chain_payment":false}),
        output,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> [u8; 16] {
        [n; 16]
    }

    #[test]
    fn plan_assigns_every_atom_and_respects_proportions() {
        let clients = [id(1), id(2)];
        assert_eq!(plan(&clients, &[1, 1], 10).unwrap(), [5, 5]);
        assert_eq!(plan(&clients, &[1, 2], 10).unwrap(), [3, 7]);
        assert_eq!(plan(&clients, &[2, 1], 10).unwrap(), [7, 3]);
        assert_eq!(
            plan(&[id(1), id(2), id(3)], &[1, 1, 1], 10).unwrap(),
            [4, 3, 3]
        );
        let atoms = plan(&clients, &[7, 13], 1000).unwrap();
        assert_eq!(atoms.iter().sum::<u64>(), 1000);
        assert_eq!(atoms, [350, 650]);
        let atoms = plan(&clients, &[0, 5], 100).unwrap();
        assert_eq!(atoms, [0, 100]);
    }

    #[test]
    fn plan_rejects_empty_or_zero_inputs() {
        let clients = [id(1), id(2)];
        assert!(plan(&clients, &[0, 0], 10).is_err());
        assert!(plan(&clients, &[1, 1], 0).is_err());
        assert!(plan(&clients, &[1], 10).is_err());
        assert!(plan(&[], &[], 10).is_err());
    }
}
