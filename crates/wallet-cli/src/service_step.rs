//! One bounded, authenticated proof-scheduler step. No timers, secrets on disk or sockets.
use super::*;
use monario_chain::{
    ledger::OutPoint,
    service as consensus,
    storage::DurableChain,
    transactions::{TransactionContext, TransactionVerifier},
};
use monario_monetary::Amount;
use monario_v6::V6Verifier;
use monario_wallet::storage::pending::{Input, MAX_SERVICE_ATTEMPTS};
use monario_wallet_scan::build::{self, Funding, Policy, Request};
use serde::Deserialize;
use std::{collections::BTreeSet, fs::File};

#[derive(Clone)]
pub(super) struct Options {
    file: String,
    max_fee: Amount,
    destination: submission::Destination,
}
impl Options {
    pub(super) fn parse(options: &mut BTreeMap<String, OsString>) -> Result<Self, Error> {
        Ok(Self {
            file: balance::filename(&text(options.remove("--schedule"))?)?,
            max_fee: amount(&text(options.remove("--max-fee-atoms"))?)?,
            destination: submission::Destination::parse(options)?,
        })
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u8,
    registration: String,
    operator_index: u32,
    fee_atoms: String,
    period_fee_budget_atoms: String,
    fee_inputs: Vec<Point>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Point {
    transaction: String,
    index: u32,
}
struct Schedule {
    registration: [u8; 32],
    index: u32,
    fee: Amount,
    budget: Amount,
    inputs: BTreeSet<OutPoint>,
}
fn amount(value: &str) -> Result<Amount, Error> {
    Amount::from_atoms(number(value).map_err(|_| Error::Transaction)?)
        .map_err(|_| Error::Transaction)
}
fn parse(bytes: &[u8], max_fee: Amount) -> Result<Schedule, Error> {
    if bytes.len() > 65536 {
        return Err(Error::Transaction);
    }
    let doc: Document = serde_json::from_slice(bytes).map_err(|_| Error::Transaction)?;
    let fee = amount(&doc.fee_atoms)?;
    let budget = amount(&doc.period_fee_budget_atoms)?;
    if doc.version != 1
        || doc.operator_index >= 1 << 31
        || fee == Amount::ZERO
        || fee > max_fee
        || budget < fee
        || doc.fee_inputs.is_empty()
        || doc.fee_inputs.len() > 256
    {
        return Err(Error::Transaction);
    }
    let count = doc.fee_inputs.len();
    let inputs = doc
        .fee_inputs
        .into_iter()
        .map(|p| {
            Ok(OutPoint {
                transaction: balance::hash(&p.transaction)?,
                index: p.index,
            })
        })
        .collect::<Result<BTreeSet<_>, Error>>()?;
    if inputs.len() != count {
        return Err(Error::Transaction);
    }
    Ok(Schedule {
        registration: balance::hash(&doc.registration)?,
        index: doc.operator_index,
        fee,
        budget,
        inputs,
    })
}
pub(super) fn execute(
    root: &Path,
    store: &mut WalletStore,
    account: u32,
    scan: balance::Options,
    options: Options,
) -> Result<serde_json::Value, Error> {
    execute_with_hook(root, store, account, scan, options, |_| {})
}
// Recovery tests terminate real child processes after signing and publication.
pub(super) fn execute_with_hook(
    root: &Path,
    store: &mut WalletStore,
    account: u32,
    scan: balance::Options,
    options: Options,
    mut hook: impl FnMut(bool),
) -> Result<serde_json::Value, Error> {
    if store.recovery_required().map_err(storage)? {
        return Err(Error::RecoveryLocked);
    }
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
    File::open(path)
        .map_err(|_| Error::Transaction)?
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Transaction)?;
    let schedule = parse(&bytes, options.max_fee)?;
    let source = balance::open(&scan)?;
    options.destination.check(scan.profile)?;
    step(store, account, &source, &scan, schedule, options, &mut hook)
}
fn step(
    store: &mut WalletStore,
    account: u32,
    source: &DurableChain<V6Verifier>,
    scan: &balance::Options,
    schedule: Schedule,
    options: Options,
    hook: &mut impl FnMut(bool),
) -> Result<serde_json::Value, Error> {
    let chain = source.chain().map_err(|_| Error::Scan)?;
    let height = chain.height().checked_add(1).ok_or(Error::Scan)?;
    let maturity = source.coinbase_maturity().map_err(|_| Error::Scan)?;
    let mut result = serde_json::json!({"registration":hex(&schedule.registration),"validation_profile":hex(&scan.profile),"validated_tip":hex(&chain.tip()),"next_height":height.to_string(),"chain_checkpoint":scan.checkpoint.map(|p|hex(&p)),"created":false,"network_delivery_proven":false,"chain_confirmation_proven":false});
    let Some(entry) = chain.ledger().service_entry(&schedule.registration) else {
        return status(store, result, "unregistered");
    };
    if entry.score.banned() {
        return status(store, result, "banned");
    }
    if service::issued_operator_public_key(store, account, schedule.index)? != entry.operator {
        return Err(Error::Transaction);
    }
    let first = entry
        .next_start
        .checked_add(consensus::PERIOD_BLOCKS)
        .and_then(|h| h.checked_add(1))
        .ok_or(Error::Scan)?;
    let deadline = entry.deadline().ok_or(Error::Scan)?;
    result["period_start"] = entry.next_start.to_string().into();
    result["first_response_height"] = first.to_string().into();
    result["deadline_height"] = deadline.to_string().into();
    if height < first || !entry.mature_for_block(height) {
        return status(store, result, "waiting");
    }
    if height > deadline {
        return status(store, result, "missed_window");
    }
    let registration = schedule.registration;
    let (start, challenge) = chain
        .service_challenge(registration)
        .map_err(|_| Error::Transaction)?;
    let attempts: Vec<_> = store
        .reservations()
        .map_err(storage)?
        .values()
        .filter(|r| {
            r.profile == scan.profile
                && r.service_proof
                    .is_some_and(|p| p.registration == registration && p.period_start == start)
        })
        .collect();
    let attempt_count = attempts.len();
    let spent: u128 = attempts
        .iter()
        .filter_map(|r| r.service_proof)
        .map(|p| u128::from(p.fee_atoms))
        .sum();
    result["attempts"] = attempt_count.into();
    result["maximum_attempts"] = MAX_SERVICE_ATTEMPTS.into();
    result["committed_fee_atoms"] = spent.to_string().into();
    if spent > u128::from(schedule.budget.atoms()) {
        return status(store, result, "fee_budget");
    }
    let current = attempts
        .iter()
        .filter(|r| {
            r.service_proof.is_some_and(|p| {
                p.challenge == challenge
                    && p.operator == entry.operator
                    && p.fee_atoms <= options.max_fee.atoms()
            }) && r.expiry_height >= height
                && r.transaction.is_some()
                && r.inputs.iter().all(|input| match input {
                    Input::Transparent { transaction, index } => {
                        let p = OutPoint {
                            transaction: *transaction,
                            index: *index,
                        };
                        schedule.inputs.contains(&p)
                            && usable_fee(
                                chain.ledger().coin(&p),
                                chain.ledger().service_collateral(&p).is_some(),
                                height,
                                maturity,
                            )
                    }
                    _ => false,
                })
        })
        .max_by_key(|r| (r.expiry_height, r.id))
        .map(|r| r.id);
    let reservation = if let Some(id) = current {
        let r = store
            .reservations()
            .map_err(storage)?
            .get(&id)
            .ok_or(Error::Transaction)?;
        let bytes = r.expose_transaction().ok_or(Error::Transaction)?;
        let verified = V6Verifier
            .verify(
                bytes,
                TransactionContext {
                    height,
                    median_time_past: chain.median_time_past(),
                    state: chain.ledger(),
                },
            )
            .map_err(|_| Error::Transaction)?;
        if Some(verified.id) != r.transaction
            || !verified.outputs.iter().any(|o| {
                consensus::proof_context(&o.script).ok() == Some((registration, start, challenge))
            })
        {
            return Err(Error::Transaction);
        }
        let proof = r.service_proof.ok_or(Error::Transaction)?;
        if verified.has_shielded_bundle
            || verified.inputs.len() != 1
            || r.inputs
                != vec![Input::Transparent {
                    transaction: verified.inputs[0].transaction,
                    index: verified.inputs[0].index,
                }]
        {
            return Err(Error::Transaction);
        }
        let input = chain
            .ledger()
            .coin(&verified.inputs[0])
            .ok_or(Error::Transaction)?
            .value
            .atoms();
        let output: u128 = verified
            .outputs
            .iter()
            .map(|o| u128::from(o.value.atoms()))
            .sum();
        if u128::from(input).checked_sub(output) != Some(u128::from(proof.fee_atoms)) {
            return Err(Error::Transaction);
        }
        chain
            .check_service_effects(&verified)
            .map_err(|_| Error::Transaction)?;
        r.id
    } else {
        if attempt_count >= MAX_SERVICE_ATTEMPTS {
            return status(store, result, "attempt_limit");
        }
        if spent + u128::from(schedule.fee.atoms()) > u128::from(schedule.budget.atoms()) {
            return status(store, result, "fee_budget");
        }
        let scanner = balance::prepare(store, account, scan, source)?;
        let claims: BTreeSet<_> = store
            .reservations()
            .map_err(storage)?
            .values()
            .flat_map(|r| r.inputs.iter().copied())
            .collect();
        let available = scanner.unspent_coins(source).map_err(|_| Error::Scan)?;
        let point = schedule.inputs.iter().find(|p| {
            usable_fee(
                chain.ledger().coin(p),
                chain.ledger().service_collateral(p).is_some(),
                height,
                maturity,
            ) && !claims.contains(&Input::Transparent {
                transaction: p.transaction,
                index: p.index,
            }) && available.get(*p).is_some_and(|(owner, c)| {
                *owner == account
                    && c.value.atoms() >= schedule.fee.atoms()
                    && (!c.coinbase || height.saturating_sub(c.created_height) >= maturity)
            })
        });
        let Some(point) = point else {
            return status(store, result, "no_funding");
        };
        let expiry = height
            .checked_add(100)
            .ok_or(Error::Transaction)?
            .min(deadline);
        let script = service::script(
            source,
            store,
            account,
            service::Intent::Proof {
                registration: hex(&registration),
                operator_index: schedule.index,
            },
        )?;
        let tx = build::construct_service_proof(
            source,
            &scanner,
            store,
            Request {
                service_record: Some(script),
                account,
                funding: Funding::Transparent(vec![*point]),
                payments: vec![],
                fee: schedule.fee,
                expiry_height: expiry,
                change_kind: AddressKind::Transparent,
            },
            &Policy {
                max_fee: options.max_fee,
            },
            schedule.budget.atoms(),
        )
        .map_err(|_| Error::Transaction)?;
        result["created"] = true.into();
        result["attempts"] = (attempt_count + 1).into();
        result["committed_fee_atoms"] = (spent + u128::from(schedule.fee.atoms()))
            .to_string()
            .into();
        tx.reservation
    };
    hook(false);
    let publication = options
        .destination
        .publish(store, scan.profile, reservation)?;
    hook(true);
    result["submission"] = publication;
    status(store, result, "published")
}
fn status(
    store: &WalletStore,
    mut result: serde_json::Value,
    state: &str,
) -> Result<serde_json::Value, Error> {
    result["state"] = state.into();
    result["checkpoint"] = serde_json::to_value(receipt(
        store.checkpoint().map_err(storage)?,
        store.recovery_required().map_err(storage)?,
    ))
    .map_err(|_| Error::Output)?;
    Ok(result)
}

// Both new selection and rebroadcast must honor the current branch's collateral
// registration and maturity, even if an earlier branch authorized this input.
fn usable_fee(
    coin: Option<&monario_chain::ledger::Coin>,
    collateral: bool,
    height: u64,
    maturity: u64,
) -> bool {
    !collateral
        && coin.is_some_and(|c| !c.coinbase || height.saturating_sub(c.created_height) >= maturity)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reorgs_that_register_or_unmature_fee_inputs_block_both_spending_paths() {
        let mut coin = monario_chain::ledger::Coin {
            value: Amount::from_atoms(10).unwrap(),
            created_height: 50,
            coinbase: true,
            script: vec![],
        };
        assert!(usable_fee(Some(&coin), false, 150, 100));
        // Same mature outpoint becomes collateral on a competing branch.
        assert!(!usable_fee(Some(&coin), true, 150, 100));
        assert!(!usable_fee(Some(&coin), false, 149, 100));
        assert!(!usable_fee(None, false, 150, 100));
        coin.coinbase = false;
        assert!(usable_fee(Some(&coin), false, 51, 100));
        assert!(!usable_fee(Some(&coin), true, 51, 100));
    }

    #[test]
    fn schedule_schema_bounds_fee_authority_and_inputs_before_side_effects() {
        let base = serde_json::json!({"version":1,"registration":hex(&[41;32]),"operator_index":0,"fee_atoms":"1","period_fee_budget_atoms":"3","fee_inputs":[{"transaction":hex(&[42;32]),"index":0}]});
        assert!(
            parse(
                &serde_json::to_vec(&base).unwrap(),
                Amount::from_atoms(1).unwrap()
            )
            .is_ok()
        );
        for (field, value) in [
            ("version", serde_json::json!(2)),
            ("operator_index", serde_json::json!(2147483648u32)),
            ("registration", serde_json::json!("00")),
            ("fee_atoms", serde_json::json!("0")),
            ("fee_atoms", serde_json::json!("2")),
            ("fee_atoms", serde_json::json!("18446744073709551616")),
            ("period_fee_budget_atoms", serde_json::json!("0")),
            ("secret", serde_json::json!("rejected")),
            ("rpc_url", serde_json::json!("rejected")),
            ("fee_inputs", serde_json::json!([])),
            (
                "fee_inputs",
                serde_json::json!([base["fee_inputs"][0], base["fee_inputs"][0]]),
            ),
        ] {
            let mut bad = base.clone();
            bad[field] = value;
            assert!(
                parse(
                    &serde_json::to_vec(&bad).unwrap(),
                    Amount::from_atoms(1).unwrap()
                )
                .is_err()
            );
        }
        assert!(parse(b"{", Amount::ZERO).is_err());
        assert!(parse(&vec![b' '; 65537], Amount::ZERO).is_err());
    }
}
