//! Disposable encrypted scan projection; never an issuance or pending-claim source.
use super::*;
use chacha20poly1305::{AeadInOut, KeyInit, Tag, XChaCha20Poly1305, XNonce};
use rusqlite::OptionalExtension;

const SCHEMA: &str = "CREATE TABLE scan_cache(singleton INTEGER PRIMARY KEY CHECK(singleton=1), envelope BLOB NOT NULL)";
/// Local cache bound, independent of consensus limits.
const MAX: usize = 4 * 1024 * 1024;

pub(super) fn valid_schema(db: &Connection, objects: i64) -> Result<bool, StorageError> {
    if objects == 1 {
        return Ok(true);
    }
    if objects != 2 {
        return Ok(false);
    }
    let sql: Option<String> = db
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE name='scan_cache' AND type='table'",
            [],
            |r| r.get(0),
        )
        .optional()
        .map_err(|_| StorageError::Invalid)?;
    Ok(sql.as_deref() == Some(SCHEMA))
}
impl WalletStore {
    fn scan_key(&self) -> Zeroizing<[u8; 32]> {
        let bytes = super::super::prf(
            b"Monario/wallet-scan-cache/key/v1\0",
            &[
                self.state.seed.expose_for_backup(),
                &self.header.checkpoint.wallet_id,
            ],
        );
        let mut key = Zeroizing::new([0; 32]);
        key.copy_from_slice(&bytes[..32]);
        key
    }
    /// Load an authenticated disposable projection. A different scan scope is a cache miss.
    /// Cache rollback is safe only because callers recheck the validated chain and sync its tail.
    pub fn load_scan_cache(
        &self,
        context: [u8; 32],
    ) -> Result<Option<Zeroizing<Vec<u8>>>, StorageError> {
        self.ready()?;
        let exists: i64 = self
            .db
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name='scan_cache'",
                [],
                |r| r.get(0),
            )
            .map_err(|_| StorageError::Storage)?;
        if exists == 0 {
            return Ok(None);
        }
        let data: Vec<u8> = self.db.query_row("SELECT CASE WHEN length(envelope) BETWEEN 72 AND ?1 THEN envelope ELSE NULL END FROM scan_cache WHERE singleton=1", [MAX as i64 + 72], |r| r.get(0)).map_err(|_| StorageError::Invalid)?;
        let aad = &data[..32];
        let cipher = XChaCha20Poly1305::new_from_slice(self.scan_key().as_slice())
            .map_err(|_| StorageError::Invalid)?;
        let end = data.len() - 16;
        let mut plain = Zeroizing::new(data[56..end].to_vec());
        let nonce: [u8; 24] = data[32..56].try_into().map_err(|_| StorageError::Invalid)?;
        let tag = Tag::try_from(&data[end..]).map_err(|_| StorageError::Invalid)?;
        cipher
            .decrypt_inout_detached(&XNonce::from(nonce), aad, plain.as_mut_slice().into(), &tag)
            .map_err(|_| StorageError::Invalid)?;
        if aad != context {
            return Ok(None);
        }
        Ok(Some(plain))
    }
    /// Atomically replace the derived cache, preserving wallet revision, seed, indices and claims.
    /// Backups deliberately omit it; changing a password does not change its seed-derived key.
    pub fn save_scan_cache(&self, context: [u8; 32], plain: &[u8]) -> Result<(), StorageError> {
        self.save_scan_cache_inner(context, plain, |_| {})
    }
    pub(super) fn save_scan_cache_inner(
        &self,
        context: [u8; 32],
        plain: &[u8],
        mut hook: impl FnMut(bool),
    ) -> Result<(), StorageError> {
        self.ready()?;
        if plain.len() > MAX {
            return Err(StorageError::Capacity);
        }
        let nonce: [u8; 24] = crypto::random()?;
        let cipher = XChaCha20Poly1305::new_from_slice(self.scan_key().as_slice())
            .map_err(|_| StorageError::Invalid)?;
        let mut encrypted = Zeroizing::new(plain.to_vec());
        let tag = cipher
            .encrypt_inout_detached(
                &XNonce::from(nonce),
                &context,
                encrypted.as_mut_slice().into(),
            )
            .map_err(|_| StorageError::Invalid)?;
        let mut data = Vec::with_capacity(encrypted.len() + 72);
        data.extend(context);
        data.extend(nonce);
        data.extend_from_slice(&encrypted);
        data.extend_from_slice(&tag);
        let tx = self
            .db
            .unchecked_transaction()
            .map_err(|_| StorageError::Storage)?;
        let page_size: i64 = tx
            .query_row("PRAGMA page_size", [], |r| r.get(0))
            .map_err(|_| StorageError::Storage)?;
        if !(512..=65536).contains(&page_size) || !(page_size as u64).is_power_of_two() {
            return Err(StorageError::Invalid);
        }
        tx.pragma_update(None, "max_page_count", 16 * 1024 * 1024 / page_size)
            .map_err(|_| StorageError::Storage)?;
        tx.execute(
            &SCHEMA.replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS "),
            [],
        )
        .map_err(|_| StorageError::Storage)?;
        tx.execute("INSERT INTO scan_cache VALUES(1,?1) ON CONFLICT(singleton) DO UPDATE SET envelope=excluded.envelope", [data]).map_err(|_| StorageError::Storage)?;
        hook(false);
        tx.commit().map_err(|_| StorageError::Storage)?;
        hook(true);
        Ok(())
    }
}
