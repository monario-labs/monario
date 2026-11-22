use super::*;
use rusqlite::{OpenFlags, params};
use std::{fs::OpenOptions, time::Duration};

const APP_ID: i64 = 0x4d4f_5031;
const SCHEMA: &str = "CREATE TABLE identity(singleton INTEGER PRIMARY KEY CHECK(singleton=1), envelope BLOB NOT NULL)";
pub(super) fn linked(meta: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return true;
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.is_file() && meta.nlink() != 1 {
            return true;
        }
    }
    meta.file_type().is_symlink()
}
fn bounded(path: &Path, required: bool) -> Result<(), StoreError> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_file() && !linked(&m) && m.len() <= 1024 * 1024 => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if m.permissions().mode() & 0o077 != 0 {
                    return Err(StoreError::Invalid);
                }
            }
            Ok(())
        }
        Err(e) if !required && e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(StoreError::Invalid),
    }
}
pub(super) fn connect(path: &Path, create: bool) -> Result<Connection, StoreError> {
    if rusqlite::version_number() < 3_051_003 {
        return Err(StoreError::UnsupportedEngine);
    }
    if create {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options
            .open(path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    StoreError::AlreadyExists
                } else {
                    StoreError::Io
                }
            })?
            .sync_all()
            .map_err(|_| StoreError::Io)?;
    }
    bounded(path, true)?;
    for suffix in ["-journal", "-wal", "-shm"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        bounded(Path::new(&sidecar), false)?;
    }
    let db = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| StoreError::Storage)?;
    db.busy_timeout(Duration::from_millis(250))
        .map_err(|_| StoreError::Storage)?;
    db.execute_batch(
        "PRAGMA trusted_schema=OFF; PRAGMA cache_size=-256; PRAGMA temp_store=MEMORY;",
    )
    .map_err(|_| StoreError::Storage)?;
    let app: i64 = db
        .query_row("PRAGMA application_id", [], |r| r.get(0))
        .map_err(|_| StoreError::Invalid)?;
    let version: i64 = db
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(|_| StoreError::Invalid)?;
    let objects: i64 = db
        .query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))
        .map_err(|_| StoreError::Invalid)?;
    if create {
        if app != 0 || version != 0 || objects != 0 {
            return Err(StoreError::Invalid);
        }
    } else {
        let schema: String = db
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE name='identity' AND type='table'",
                [],
                |r| r.get(0),
            )
            .map_err(|_| StoreError::Invalid)?;
        if app != APP_ID || version != 1 || objects != 1 || schema != SCHEMA {
            return Err(StoreError::Invalid);
        }
    }
    db.execute_batch("PRAGMA locking_mode=EXCLUSIVE; PRAGMA journal_mode=DELETE; PRAGMA synchronous=EXTRA; BEGIN EXCLUSIVE; COMMIT;").map_err(|_| StoreError::Storage)?;
    let mode: String = db
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .map_err(|_| StoreError::Storage)?;
    let sync: i64 = db
        .query_row("PRAGMA synchronous", [], |r| r.get(0))
        .map_err(|_| StoreError::Storage)?;
    if mode != "delete" || sync != 3 {
        return Err(StoreError::UnsupportedEngine);
    }
    Ok(db)
}
pub(super) fn read(db: &Connection) -> Result<Vec<u8>, StoreError> {
    let count: i64 = db
        .query_row("SELECT count(*) FROM identity", [], |r| r.get(0))
        .map_err(|_| StoreError::Invalid)?;
    if count != 1 {
        return Err(StoreError::Invalid);
    }
    db.query_row("SELECT CASE WHEN length(envelope)=?1 THEN envelope ELSE NULL END FROM identity WHERE singleton=1", params![crypto::TOTAL as i64], |r| r.get(0)).map_err(|_| StoreError::Invalid)
}
pub(super) fn write(
    db: &mut Connection,
    envelope: &[u8],
    create: bool,
    mut hook: impl FnMut(bool),
) -> Result<(), StoreError> {
    let tx = db.transaction().map_err(|_| StoreError::Storage)?;
    if create {
        tx.execute(SCHEMA, []).map_err(|_| StoreError::Storage)?;
        tx.pragma_update(None, "application_id", APP_ID)
            .map_err(|_| StoreError::Storage)?;
        tx.pragma_update(None, "user_version", 1)
            .map_err(|_| StoreError::Storage)?;
        tx.execute("INSERT INTO identity VALUES(1,?1)", params![envelope])
            .map_err(|_| StoreError::Storage)?;
    } else if tx
        .execute(
            "UPDATE identity SET envelope=?1 WHERE singleton=1",
            params![envelope],
        )
        .map_err(|_| StoreError::Storage)?
        != 1
    {
        return Err(StoreError::Invalid);
    }
    if read(&tx)? != envelope {
        return Err(StoreError::Invalid);
    }
    hook(false);
    tx.commit().map_err(|_| StoreError::Storage)?;
    hook(true);
    Ok(())
}
