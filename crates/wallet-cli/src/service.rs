//! Offline operator key issuance and signed service intents. No secret export.
use super::*;
use monario_chain::{ledger::OutPoint, service as consensus, storage::DurableChain};
use monario_v6::V6Verifier;
use secp256k1::{PublicKey, SecretKey};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub(super) enum Intent {
    Rotation {
        registration: String,
        owner_index: u32,
        operator_public_key: String,
        authorization: String,
    },
    Reactivation {
        registration: String,
        owner_index: u32,
        authorization: String,
    },
    Registration {
        collateral_transaction: String,
        collateral_index: u32,
        owner_index: u32,
        operator_public_key: String,
    },
    Proof {
        registration: String,
        operator_index: u32,
    },
}

// Follow the existing native-key erasure convention on every return path.
// Upstream/compiler-generated copies retain the documented wallet memory limits.
struct SigningKey(SecretKey);
impl Drop for SigningKey {
    fn drop(&mut self) {
        self.0.non_secure_erase();
    }
}
fn key(store: &WalletStore, account: u32, index: u32) -> Result<SigningKey, Error> {
    if store.recovery_required().map_err(storage)? {
        return Err(Error::RecoveryLocked);
    }
    let network = store.checkpoint().map_err(storage)?.network;
    let derived = store
        .expose_seed()
        .map_err(storage)?
        .transparent_key(network, account, Scope::External, index)
        .map_err(|_| Error::Transaction)?;
    SecretKey::from_secret_bytes(*derived.expose_secret())
        .map(SigningKey)
        .map_err(|_| Error::Transaction)
}
pub(super) fn issue_key(store: &mut WalletStore, account: u32) -> Result<serde_json::Value, Error> {
    let issued = store
        .next_address(account, Scope::External, AddressKind::Transparent)
        .map_err(storage)?;
    let index = u32::try_from(issued.index).map_err(|_| Error::Transaction)?;
    let derived = store
        .expose_seed()
        .map_err(storage)?
        .transparent_key(issued.checkpoint.network, account, Scope::External, index)
        .map_err(|_| Error::Transaction)?;
    Ok(
        serde_json::json!({"checkpoint":receipt(issued.checkpoint,false),"account":account,"scope":"external",
        "index":issued.index.to_string(),"address":issued.address.encode(),"operator_public_key":hex(&derived.public_key())}),
    )
}
fn public_key(text: &str) -> Result<[u8; 33], Error> {
    if text.len() != 66
        || !text
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(Error::Transaction);
    }
    let mut out = [0; 33];
    for (i, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        out[i] = digit(pair[0]) * 16 + digit(pair[1]);
    }
    PublicKey::from_byte_array_compressed(out).map_err(|_| Error::Transaction)?;
    Ok(out)
}
pub(super) fn status(
    source: &DurableChain<V6Verifier>,
    registration: [u8; 32],
) -> Result<serde_json::Value, Error> {
    let chain = source.chain().map_err(|_| Error::Scan)?;
    let next = chain.height().checked_add(1).ok_or(Error::Scan)?;
    let mut value = serde_json::json!({"validation_profile":hex(&chain.validation_profile()),"validated_tip":hex(&chain.tip()),
        "height":chain.height().to_string(),"registration":hex(&registration),"registered":false});
    if let Some(e) = chain.ledger().service_entry(&registration) {
        let first = e
            .next_start
            .checked_add(consensus::PERIOD_BLOCKS)
            .and_then(|h| h.checked_add(1))
            .ok_or(Error::Scan)?;
        value["registered"] = true.into();
        value["service"] = serde_json::json!({"operator_public_key":hex(&e.operator),"registered_height":e.registered_height.to_string(),"control_head":hex(&e.control_head),
            "registration_confirmations":chain.height().saturating_sub(e.registered_height).saturating_add(1).to_string(),
            "mature_for_next_block":e.mature_for_block(next),"credited_seconds":e.credited_seconds.to_string(),
            "required_seconds":consensus::QUALIFY_SECONDS.to_string(),"banned":e.score.banned(),"penalty":e.penalty_at(next).ok_or(Error::Scan)?,
            "period_start":e.next_start.to_string(),"first_response_height":first.to_string(),"deadline_height":e.deadline().map(|h|h.to_string()),
            "proof_due_next_block":next>=first&&e.deadline().is_some_and(|h|next<=h),
            "qualified_before_next_block_transactions":e.qualified(next)});
    }
    Ok(value)
}
pub(super) fn script(
    source: &DurableChain<V6Verifier>,
    store: &WalletStore,
    account: u32,
    intent: Intent,
) -> Result<Vec<u8>, Error> {
    let chain = source.chain().map_err(|_| Error::Scan)?;
    match intent {
        Intent::Rotation {
            registration,
            owner_index,
            operator_public_key,
            authorization,
        } => {
            let bytes = authorization_bytes(&authorization)?;
            let operator = public_key(&operator_public_key)?;
            // Layout: header, registration (32), control head (32), new operator (33).
            let key = consensus::RECORD_HEADER_LEN + 32 + 32;
            if bytes.get(consensus::KIND) != Some(&2)
                || bytes.get(key..key + 33) != Some(operator.as_slice())
            {
                return Err(Error::Transaction);
            }
            finish_control(source, store, account, &registration, owner_index, &bytes)
        }
        Intent::Reactivation {
            registration,
            owner_index,
            authorization,
        } => {
            let bytes = authorization_bytes(&authorization)?;
            if bytes.get(consensus::KIND) != Some(&3) {
                return Err(Error::Transaction);
            }
            finish_control(source, store, account, &registration, owner_index, &bytes)
        }
        Intent::Registration {
            collateral_transaction,
            collateral_index,
            owner_index,
            operator_public_key,
        } => {
            let collateral = OutPoint {
                transaction: balance::hash(&collateral_transaction)
                    .map_err(|_| Error::Transaction)?,
                index: collateral_index,
            };
            let operator = public_key(&operator_public_key)?;
            let owner = key(store, account, owner_index)?;
            let public = PublicKey::from_secret_key(&owner.0).serialize();
            let coin = chain.ledger().coin(&collateral).ok_or(Error::Transaction)?;
            if coin.value.atoms() != consensus::COLLATERAL_ATOMS
                || coin.script != consensus::owner_script(&public)
            {
                return Err(Error::Transaction);
            }
            let script = consensus::registration_script(
                chain.chain_id(),
                chain.root_id(),
                collateral,
                &owner.0,
                operator,
            )
            .map_err(|_| Error::Transaction)?;
            chain
                .check_service_intent(&script, &[])
                .map_err(|_| Error::Transaction)?;
            Ok(script)
        }
        Intent::Proof {
            registration,
            operator_index,
        } => {
            let id = balance::hash(&registration).map_err(|_| Error::Transaction)?;
            let operator = key(store, account, operator_index)?;
            consensus::proof_script(source, id, &operator.0).map_err(|_| Error::Transaction)
        }
    }
}

pub(super) struct AuthorizationOptions {
    purpose: bool,
    index: u32,
}
impl AuthorizationOptions {
    pub(super) fn parse(options: &mut BTreeMap<String, OsString>) -> Result<Self, Error> {
        let purpose = match text(options.remove("--purpose"))?.as_str() {
            "rotation" => false,
            "reactivation" => true,
            _ => return Err(Error::Arguments),
        };
        let index = number(&text(options.remove("--operator-index"))?)?;
        if index >= 1 << 31 {
            return Err(Error::Arguments);
        }
        Ok(Self {
            purpose,
            index: index as u32,
        })
    }
}
pub(super) fn authorize(
    source: &DurableChain<V6Verifier>,
    store: &WalletStore,
    account: u32,
    registration: [u8; 32],
    options: AuthorizationOptions,
) -> Result<serde_json::Value, Error> {
    let operator = issued_operator_key(store, account, options.index)?;
    let chain = source.chain().map_err(|_| Error::Scan)?;
    let bytes = if options.purpose {
        consensus::reactivation_authorization(source, registration, &operator.0)
    } else {
        consensus::rotation_authorization(chain, registration, &operator.0)
    }
    .map_err(|_| Error::Transaction)?;
    Ok(
        serde_json::json!({"purpose":if options.purpose {"reactivation"}else{"rotation"},"registration":hex(&registration),"control_head":hex(&chain.ledger().service_entry(&registration).ok_or(Error::Transaction)?.control_head),
        "operator_public_key":hex(&PublicKey::from_secret_key(&operator.0).serialize()),"validation_profile":hex(&chain.validation_profile()),"validated_tip":hex(&chain.tip()),"authorization":hex(&bytes)}),
    )
}
fn authorization_bytes(value: &str) -> Result<Vec<u8>, Error> {
    if value.len() > consensus::MAX_RECORD_BYTES * 2 || !value.len().is_multiple_of(2) {
        return Err(Error::Transaction);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |b: u8| match b {
                b'0'..=b'9' => Ok(b - b'0'),
                b'a'..=b'f' => Ok(b - b'a' + 10),
                _ => Err(Error::Transaction),
            };
            Ok(digit(pair[0])? * 16 + digit(pair[1])?)
        })
        .collect()
}
fn finish_control(
    source: &DurableChain<V6Verifier>,
    store: &WalletStore,
    account: u32,
    registration: &str,
    owner_index: u32,
    bytes: &[u8],
) -> Result<Vec<u8>, Error> {
    let id = balance::hash(registration).map_err(|_| Error::Transaction)?;
    if bytes.get(consensus::RECORD_HEADER_LEN..consensus::RECORD_HEADER_LEN + 32)
        != Some(id.as_slice())
    {
        return Err(Error::Transaction);
    }
    let owner = key(store, account, owner_index)?;
    consensus::control_script(source.chain().map_err(|_| Error::Scan)?, bytes, &owner.0)
        .map_err(|_| Error::Transaction)
}

fn issued_operator_key(store: &WalletStore, account: u32, index: u32) -> Result<SigningKey, Error> {
    let issued = store
        .account_progress()
        .map_err(storage)?
        .get(&account)
        .map_or(0, |p| p.transparent_external);
    if u64::from(index) >= issued {
        return Err(Error::Transaction);
    }
    key(store, account, index)
}
pub(super) fn issued_operator_public_key(
    store: &WalletStore,
    account: u32,
    index: u32,
) -> Result<[u8; 33], Error> {
    let key = issued_operator_key(store, account, index)?;
    Ok(PublicKey::from_secret_key(&key.0).serialize())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn operator_authorization_requires_a_durably_issued_key() {
        #[cfg(unix)]
        let dir = {
            use std::os::unix::fs::PermissionsExt;
            tempfile::Builder::new()
                .permissions(fs::Permissions::from_mode(0o700))
                .tempdir()
                .unwrap()
        };
        #[cfg(not(unix))]
        let dir = tempfile::tempdir().unwrap();
        let mut store = WalletStore::create(
            &WalletDirectory::open(dir.path()).unwrap(),
            "operator",
            Seed::from_bytes(&[7; 32]).unwrap(),
            Network::Main,
            &password(b"public issued service key test password").unwrap(),
        )
        .unwrap();
        assert!(issued_operator_key(&store, 0, 0).is_err());
        issue_key(&mut store, 0).unwrap();
        let cp = store.checkpoint().unwrap();
        assert!(issued_operator_key(&store, 0, 0).is_ok());
        assert!(issued_operator_key(&store, 0, 1).is_err());
        assert!(issued_operator_key(&store, 1, 0).is_err());
        assert_eq!(store.checkpoint().unwrap(), cp);
    }
}
