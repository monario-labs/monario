use super::*;
use crate::{tests::private_tempdir, transport::Identity};
use zeroize::Zeroizing;
mod dependencies;
fn key() -> Hash {
    Identity::from_secret(Zeroizing::new([11; 32])).public_key()
}
fn raw() -> Vec<u8> {
    include_bytes!("../../../v6/tests/fixtures/spend-deposit-v6.bin").to_vec()
}
#[test]
fn explicit_creation_pins_schema_identity_and_idempotent_payloads() {
    let dir = private_tempdir();
    assert!(Inbox::open(dir.path(), "local", [2; 32], key()).is_err());
    assert!(!dir.path().join("local.mons").exists());
    let mut q = Inbox::create(dir.path(), "local", [2; 32], key()).unwrap();
    assert!(Inbox::create(dir.path(), "local", [2; 32], key()).is_err());
    let token = q.enqueue(&raw()).unwrap();
    assert_eq!(q.enqueue(&raw()).unwrap(), token);
    assert_eq!(q.status(token).unwrap().unwrap().state, 0);
    assert!(q.status([0; 32]).unwrap().is_none());
    assert!(Inbox::open(dir.path(), "local", [3; 32], key()).is_err());
    assert!(Inbox::open(dir.path(), "local", [2; 32], [1; 32]).is_err());
    for bad in [
        Vec::new(),
        vec![0; 2_000_001],
        raw()[..raw().len() - 1].to_vec(),
        {
            let mut r = raw();
            r.push(0);
            r
        },
    ] {
        assert!(q.enqueue(&bad).is_err());
    }
    assert_eq!(
        q.db.query_row("SELECT count(*) FROM requests", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    q.db.execute_batch(
        "CREATE TRIGGER unexpected AFTER INSERT ON requests BEGIN DELETE FROM requests; END;",
    )
    .unwrap();
    assert!(q.enqueue(&raw()).is_err());
    assert!(q.record(1, token, 1, [3; 32]).is_err());
    drop(q);
    assert!(Inbox::open(dir.path(), "local", [2; 32], key()).is_err());
}
#[test]
fn bounds_jails_permissions_corruption_and_busy_publication_fail_closed() {
    let dir = private_tempdir();
    for name in ["../escape", "a.b", "CON", "", "a/b"] {
        assert!(Inbox::create(dir.path(), name, [2; 32], key()).is_err());
    }
    let mut q = Inbox::create(dir.path(), "local", [2; 32], key()).unwrap();
    let other = Inbox::open(dir.path(), "local", [2; 32], key()).unwrap();
    other.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert_eq!(q.enqueue(&raw()).unwrap_err(), Error::Busy);
    other.db.execute_batch("ROLLBACK").unwrap();
    drop(other);
    let original = raw();
    for i in 0..256_u16 {
        let mut b = original.clone();
        let n = b.len();
        b[n - 2..].copy_from_slice(&i.to_le_bytes());
        q.enqueue(&b).unwrap();
    }
    let mut b = original.clone();
    let n = b.len();
    b[n - 2..].copy_from_slice(&256_u16.to_le_bytes());
    assert_eq!(q.enqueue(&b).unwrap_err(), Error::Capacity);
    let token: Hash =
        q.db.query_row("SELECT token FROM requests ORDER BY seq LIMIT 1", [], |r| {
            r.get(0)
        })
        .unwrap();
    q.db.execute(
        "UPDATE requests SET raw=?1 WHERE token=?2",
        params![original, token.as_slice()],
    )
    .unwrap();
    assert!(
        q.next(&mut BTreeSet::new(), &mut BTreeMap::new(), 0)
            .is_err()
    );
    drop(q);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let p = dir.path().join("local.mons");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Inbox::open(dir.path(), "local", [2; 32], key()).is_err());
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&p, dir.path().join("alias")).unwrap();
        assert!(Inbox::open(dir.path(), "local", [2; 32], key()).is_err());
        fs::remove_file(dir.path().join("alias")).unwrap();
        symlink("local.mons", dir.path().join("local.mons-journal")).unwrap();
        assert!(Inbox::open(dir.path(), "local", [2; 32], key()).is_err());
    }
}
#[test]
fn submission_crash_worker() {
    let Some(dir) = std::env::var_os("MONAR_INBOX_TEST_DIR") else {
        return;
    };
    let after = std::env::var("MONAR_INBOX_TEST_AFTER").unwrap() == "yes";
    let mut q = Inbox::open(Path::new(&dir), "local", [2; 32], key()).unwrap();
    q.enqueue_inner(&raw(), |committed| {
        if committed == after {
            std::process::exit(if after { 82 } else { 81 });
        }
    })
    .unwrap();
    panic!("crash hook did not execute");
}
#[test]
fn publication_crashes_recover_atomic_rows_and_retry_the_same_bytes() {
    for after in [false, true] {
        let dir = private_tempdir();
        drop(Inbox::create(dir.path(), "local", [2; 32], key()).unwrap());
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "submission::tests::submission_crash_worker"])
            .env("MONAR_INBOX_TEST_DIR", dir.path())
            .env("MONAR_INBOX_TEST_AFTER", if after { "yes" } else { "no" })
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert_eq!(result.code(), Some(if after { 82 } else { 81 }));
        let mut q = Inbox::open(dir.path(), "local", [2; 32], key()).unwrap();
        assert_eq!(q.status(digest(&raw())).unwrap().is_some(), after);
        q.enqueue(&raw()).unwrap();
        q.enqueue(&raw()).unwrap();
        assert_eq!(
            q.db.query_row("SELECT count(*) FROM requests", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
}
