//! Read-only, deterministic funding selection. Construction revalidates every input.
use super::*;
use monario_wallet::storage::pending::Input;

/// The caller explicitly chooses one pool; selection never combines pools.
#[derive(Clone, Copy)]
pub enum Pool {
    Transparent,
    Private,
}

/// Sensitive input references and their checked total; no claims or keys are issued.
pub struct Selection {
    pub funding: Funding,
    pub total: Amount,
}

/// Prefer the smallest single covering input, otherwise largest inputs first.
/// Canonical identities break ties. Claims from every profile remain unavailable.
pub fn select(
    source: &DurableChain<V6Verifier>,
    scanner: &Scanner,
    wallet: &WalletStore,
    account: u32,
    pool: Pool,
    required: Amount,
) -> Result<Selection, Error> {
    scanner.current(source)?;
    if wallet.recovery_required()? {
        return Err(StorageError::RecoveryRequired.into());
    }
    let network = wallet.checkpoint()?.network;
    let watched = scanner
        .accounts
        .iter()
        .find(|a| a.id == account)
        .ok_or(Error::WrongKey)?;
    if watched.network != network {
        return Err(Error::WrongNetwork);
    }
    let key = wallet
        .expose_seed()?
        .private_account(network, account)
        .map_err(|_| Error::WrongKey)?;
    let viewing = FullViewingKey::from(key.expose_spending_key());
    if *Zeroizing::new(viewing.to_bytes()) != *Zeroizing::new(watched.viewing.to_bytes()) {
        return Err(Error::WrongKey);
    }
    let claims: BTreeSet<_> = wallet
        .reservations()?
        .values()
        .flat_map(|r| r.inputs.iter().copied())
        .collect();
    let chain = source.chain().map_err(ScanError::from)?;
    let ledger = chain.ledger();
    let limit = 32.min(chain.limits().inputs_per_transaction);
    let (funding, total) = match pool {
        Pool::Transparent => {
            let height = chain.height().checked_add(1).ok_or(Error::Expiry)?;
            let maturity = source.coinbase_maturity().map_err(ScanError::from)?;
            let candidates = scanner
                .state
                .coins
                .iter()
                .filter(|(p, (owner, coin))| {
                    *owner == account
                        && coin.value != Amount::ZERO
                        && ledger.coin(p) == Some(coin)
                        && ledger.service_collateral(p).is_none()
                        && !claims.contains(&Input::Transparent {
                            transaction: p.transaction,
                            index: p.index,
                        })
                        && (!coin.coinbase
                            || height
                                .checked_sub(coin.created_height)
                                .is_some_and(|age| age >= maturity))
                })
                .map(|(p, (_, coin))| (*p, coin.value))
                .collect();
            let (inputs, total) = choose(candidates, required, limit)?;
            (Funding::Transparent(inputs), total)
        }
        Pool::Private => {
            let mut candidates = Vec::new();
            for (nf, received) in &scanner.state.notes {
                if received.account != account
                    || ledger.has_nullifier(nf)
                    || claims.contains(&Input::Private { nullifier: *nf })
                {
                    continue;
                }
                if received.note.nullifier(&viewing).to_bytes() != *nf {
                    return Err(Error::WrongKey);
                }
                let value = amount(received.note.value().inner())?;
                if value != Amount::ZERO {
                    candidates.push((*nf, value));
                }
            }
            let (inputs, total) = choose(candidates, required, limit)?;
            for nf in &inputs {
                scanner.witness(source, *nf)?;
            }
            (Funding::Private(inputs), total)
        }
    };
    Ok(Selection { funding, total })
}

fn choose<T: Ord>(
    mut candidates: Vec<(T, Amount)>,
    required: Amount,
    limit: usize,
) -> Result<(Vec<T>, Amount), Error> {
    if required == Amount::ZERO {
        return Err(Error::Intent);
    }
    if limit == 0 {
        return Err(Error::ResourceLimit);
    }
    if let Some((index, _)) = candidates
        .iter()
        .enumerate()
        .filter(|(_, (_, n))| *n >= required)
        .min_by(|(_, a), (_, b)| a.1.cmp(&b.1).then(a.0.cmp(&b.0)))
    {
        let (id, total) = candidates.swap_remove(index);
        return Ok((vec![id], total));
    }
    candidates.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let mut inputs = Vec::new();
    let mut total = Amount::ZERO;
    for (id, value) in candidates
        .into_iter()
        .filter(|(_, n)| *n != Amount::ZERO)
        .take(limit)
    {
        total = add(total, value)?;
        inputs.push(id);
        if total >= required {
            return Ok((inputs, total));
        }
    }
    Err(Error::InsufficientFunds)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn a(n: u64) -> Amount {
        amount(n).unwrap()
    }
    #[test]
    fn smallest_single_then_largest_first_with_canonical_ties() {
        let values = vec![(9, a(10)), (3, a(7)), (2, a(7)), (1, a(1))];
        assert_eq!(choose(values.clone(), a(6), 32).unwrap(), (vec![2], a(7)));
        assert_eq!(
            choose(values.clone(), a(17), 32).unwrap(),
            (vec![9, 2], a(17))
        );
        assert_eq!(
            choose(values.into_iter().rev().collect(), a(18), 32).unwrap(),
            (vec![9, 2, 3], a(24))
        );
    }
    #[test]
    fn bounded_empty_zero_and_insufficient_selection() {
        assert!(choose::<u32>(vec![], a(1), 32).is_err());
        assert!(choose(vec![(0, a(0))], a(1), 32).is_err());
        assert!(choose(vec![(0, a(1))], a(0), 32).is_err());
        assert!(choose(vec![(0, a(1))], a(1), 0).is_err());
        let coins: Vec<_> = (0..33).map(|i| (i, a(1))).collect();
        assert!(choose(coins.clone(), a(33), 32).is_err());
        assert_eq!(choose(coins, a(32), 32).unwrap().0.len(), 32);
    }
}
