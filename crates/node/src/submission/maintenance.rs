//! Atomic local maintenance. No transaction cancellation or wallet access.
use super::*;
pub struct Lifecycle {
    /// 0 active, 1 staged/disabled, 2 retired/disabled.
    pub phase: u8,
    /// Informational basename only. Never automatically followed.
    pub peer: Option<String>,
}
pub(super) struct Metadata {
    pub(super) instance: [u8; 16],
    pub(super) next_seq: i64,
    pub(super) phase: u8,
    peer: Option<String>,
    peer_instance: Option<[u8; 16]>,
}
pub(super) fn instance() -> Result<[u8; 16], Error> {
    let mut id = [0; 16];
    getrandom::fill(&mut id).map_err(|_| Error::Storage)?;
    Ok(id)
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Staged,
    Retired,
    Activated,
}
impl Inbox {
    pub(super) fn metadata(&self) -> Result<Metadata, Error> {
        let m = self.db.query_row(
            "SELECT instance,next_seq,phase,peer,peer_instance FROM metadata WHERE singleton=1",
            [],
            |r| {
                Ok(Metadata {
                    instance: r.get(0)?,
                    next_seq: r.get(1)?,
                    phase: r.get(2)?,
                    peer: r.get(3)?,
                    peer_instance: r.get(4)?,
                })
            },
        )?;
        if m.next_seq < 1 || m.phase > 2 {
            return Err(Error::Invalid);
        }
        match (&m.peer, m.peer_instance, m.phase) {
            (None, None, 0) => {}
            (Some(peer), Some(_), 1 | 2)
                if peer != &self.name
                    && !peer.is_empty()
                    && peer.len() <= 64
                    && peer
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
                    && crate::cli::name(peer).is_ok() => {}
            _ => return Err(Error::Invalid),
        }
        Ok(m)
    }
    pub fn lifecycle(&self) -> Result<Lifecycle, Error> {
        self.check()?;
        let m = self.metadata()?;
        Ok(Lifecycle {
            phase: m.phase,
            peer: m.peer,
        })
    }
    pub(super) fn upgrade_inner(
        &mut self,
        mut hook: impl FnMut(&Connection, bool),
    ) -> Result<(), Error> {
        self.db.execute_batch("BEGIN IMMEDIATE")?;
        let result = (|| {
            self.check_base(1, LEGACY_META)?;
            let (min, max): (i64, i64) = self.db.query_row(
                "SELECT coalesce(min(seq),1),coalesce(max(seq),0) FROM requests",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            if min < 1 {
                return Err(Error::Invalid);
            }
            let next = max.checked_add(1).ok_or(Error::Capacity)?;
            {
                let mut query=self.db.prepare("SELECT token,CASE WHEN length(raw)<=2000000 THEN raw ELSE NULL END,state,tip FROM requests ORDER BY seq LIMIT 257")?;
                let mut rows = query.query([])?;
                while let Some(row) = rows.next()? {
                    let token: Hash = row.get(0)?;
                    let raw: Vec<u8> = row.get(1)?;
                    let state: u8 = row.get(2)?;
                    let tip: Option<Hash> = row.get(3)?;
                    frame(&raw)?;
                    if digest(&raw) != token || state > 2 || (state == 0) != tip.is_none() {
                        return Err(Error::Invalid);
                    }
                }
            }
            let id = instance()?;
            self.db
                .execute_batch("ALTER TABLE metadata RENAME TO old_metadata")?;
            self.db.execute_batch(META)?;
            self.db.execute(
                "INSERT INTO metadata VALUES(1,?1,?2,?3,?4,0,NULL,NULL)",
                params![
                    self.profile.as_slice(),
                    self.node_key.as_slice(),
                    id.as_slice(),
                    next
                ],
            )?;
            self.db
                .execute_batch("DROP TABLE old_metadata; PRAGMA user_version=2;")?;
            hook(&self.db, false);
            Ok(id)
        })();
        match result {
            Ok(id) => {
                self.db.execute_batch("COMMIT")?;
                self.instance = id;
                hook(&self.db, true);
                Ok(())
            }
            Err(e) => {
                self.db.execute_batch("ROLLBACK")?;
                Err(e)
            }
        }
    }
    /// Removes one exact delivery record. Does not remove a mempool transaction,
    /// revoke signatures, rewind generation counters or release any wallet claim.
    pub fn forget(&mut self, token: Hash) -> Result<bool, Error> {
        self.forget_inner(token, |_, _| {})
    }
    fn forget_inner(
        &mut self,
        token: Hash,
        mut hook: impl FnMut(&Connection, bool),
    ) -> Result<bool, Error> {
        self.db.execute_batch("BEGIN IMMEDIATE")?;
        let result = (|| {
            self.require_active()?;
            let changed = self
                .db
                .execute("DELETE FROM requests WHERE token=?1", [token.as_slice()])?;
            hook(&self.db, false);
            Ok(changed == 1)
        })();
        match result {
            Ok(found) => {
                self.db.execute_batch("COMMIT")?;
                hook(&self.db, true);
                Ok(found)
            }
            Err(e) => {
                self.db.execute_batch("ROLLBACK")?;
                Err(e)
            }
        }
    }
    /// Recoverable copy -> retire -> activate. Old files are retained; an existing
    /// unrelated target is never replaced. Retry the same pair after interruption.
    pub fn rotate(&mut self, target: &str) -> Result<Inbox, Error> {
        self.rotate_inner(target, |_| {})
    }
    fn rotate_inner(&mut self, target: &str, mut hook: impl FnMut(Stage)) -> Result<Inbox, Error> {
        let destination = path(&self.root, target)?;
        if self.name.eq_ignore_ascii_case(target) {
            return Err(Error::Invalid);
        }
        self.db.execute_batch("BEGIN IMMEDIATE")?;
        let result = (|| {
            self.check()?;
            let source = self.metadata()?;
            if source.phase == 1 || (source.phase == 2 && source.peer.as_deref() != Some(target)) {
                return Err(Error::Inactive);
            }
            let exists = match fs::symlink_metadata(&destination) {
                Ok(_) => true,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
                Err(_) => return Err(Error::Invalid),
            };
            if !exists && source.phase != 0 {
                return Err(Error::Invalid);
            }
            let mut dest = if exists {
                Inbox::open(&self.root, target, self.profile, self.node_key)?
            } else {
                Inbox::connect(
                    &self.root,
                    target,
                    self.profile,
                    self.node_key,
                    true,
                    Some((&self.name, source.instance)),
                )?
            };
            let dm = dest.metadata()?;
            if dm.instance == source.instance {
                return Err(Error::Invalid);
            }
            if source.phase == 2 {
                if source.peer_instance != Some(dm.instance) {
                    return Err(Error::Invalid);
                }
                if dm.phase == 0 {
                    self.db.execute_batch("COMMIT")?;
                    return Ok(dest);
                }
            }
            if dm.phase != 1
                || dm.peer.as_deref() != Some(self.name.as_str())
                || dm.peer_instance != Some(source.instance)
            {
                return Err(Error::Invalid);
            }
            dest.copy_staged(self)?;
            hook(Stage::Staged);
            self.db.execute(
                "UPDATE metadata SET phase=2,peer=?1,peer_instance=?2 WHERE singleton=1",
                params![target, dm.instance.as_slice()],
            )?;
            self.db.execute_batch("COMMIT")?;
            hook(Stage::Retired);
            dest.activate(self)?;
            hook(Stage::Activated);
            Ok(dest)
        })();
        if !self.db.is_autocommit() {
            self.db.execute_batch("ROLLBACK")?;
        }
        result
    }
    fn copy_staged(&mut self, source: &Inbox) -> Result<(), Error> {
        self.db.execute_batch("BEGIN IMMEDIATE")?;
        let result = (|| {
            self.check()?;
            let meta = self.metadata()?;
            if meta.phase != 1
                || meta.peer.as_deref() != Some(source.name.as_str())
                || meta.peer_instance != Some(source.instance)
            {
                return Err(Error::Invalid);
            }
            self.db.execute("DELETE FROM requests", [])?;
            let mut query=source.db.prepare("SELECT token,CASE WHEN length(raw)<=2000000 THEN raw ELSE NULL END FROM requests ORDER BY seq LIMIT 257")?;
            let mut rows = query.query([])?;
            let mut seq = 1_i64;
            while let Some(row) = rows.next()? {
                if seq > RECORDS {
                    return Err(Error::Capacity);
                }
                let token: Hash = row.get(0)?;
                let raw: Vec<u8> = row.get(1)?;
                frame(&raw)?;
                if digest(&raw) != token {
                    return Err(Error::Invalid);
                }
                self.db.execute(
                    "INSERT INTO requests(seq,token,raw,state) VALUES(?1,?2,?3,0)",
                    params![seq, token.as_slice(), raw],
                )?;
                seq += 1;
            }
            self.db
                .execute("UPDATE metadata SET next_seq=?1 WHERE singleton=1", [seq])?;
            self.check()?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                self.db.execute_batch("COMMIT")?;
                #[cfg(unix)]
                fs::File::open(&self.root)
                    .and_then(|f| f.sync_all())
                    .map_err(|_| Error::Storage)?;
                Ok(())
            }
            Err(e) => {
                self.db.execute_batch("ROLLBACK")?;
                Err(e)
            }
        }
    }
    fn activate(&mut self, source: &Inbox) -> Result<(), Error> {
        self.db.execute_batch("BEGIN IMMEDIATE")?;
        let result = (|| {
            self.check()?;
            let meta = self.metadata()?;
            if meta.phase != 1
                || meta.peer.as_deref() != Some(source.name.as_str())
                || meta.peer_instance != Some(source.instance)
            {
                return Err(Error::Invalid);
            }
            self.db.execute(
                "UPDATE metadata SET phase=0,peer=NULL,peer_instance=NULL WHERE singleton=1",
                [],
            )?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                self.db.execute_batch("COMMIT")?;
                Ok(())
            }
            Err(e) => {
                self.db.execute_batch("ROLLBACK")?;
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests;
