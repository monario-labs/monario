use super::*;
use crate::{tests::private_tempdir, transport::Identity};
use zeroize::Zeroizing;
fn key() -> Hash {
    Identity::from_secret(Zeroizing::new([11; 32])).public_key()
}
fn raw(n: u8) -> Vec<u8> {
    let mut r = include_bytes!("../../../../v6/tests/fixtures/spend-deposit-v6.bin").to_vec();
    *r.last_mut().unwrap() = n;
    r
}
fn create(root: &Path) -> Inbox {
    Inbox::create(root, "local", [2; 32], key()).unwrap()
}
fn open(root: &Path, name: &str) -> Inbox {
    Inbox::open(root, name, [2; 32], key()).unwrap()
}
fn legacy(root: &Path) {
    let path = path(root, "local").unwrap();
    let mut f = OpenOptions::new();
    f.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        f.mode(0o600);
    }
    drop(f.open(&path).unwrap());
    let db = Connection::open(&path).unwrap();
    db.execute_batch("PRAGMA synchronous=FULL").unwrap();
    db.execute_batch(LEGACY_META).unwrap();
    db.execute_batch(REQUESTS).unwrap();
    db.execute(
        "INSERT INTO metadata VALUES(1,?1,?2)",
        params![[2_u8; 32].as_slice(), key().as_slice()],
    )
    .unwrap();
    db.execute(
        "INSERT INTO requests(seq,token,raw,state,tip) VALUES(7,?1,?2,1,?3)",
        params![digest(&raw(1)).as_slice(), raw(1), [3_u8; 32].as_slice()],
    )
    .unwrap();
    db.execute_batch("PRAGMA application_id=1297044273; PRAGMA user_version=1;")
        .unwrap();
}
#[test]
fn cleanup_republication_uses_new_generation_and_bounds_consumer_cache() {
    let d = private_tempdir();
    let mut q = create(d.path());
    let token = q.enqueue(&raw(1)).unwrap();
    let mut seen = BTreeSet::new();
    let (old, _, _) = q.next(&mut seen, &mut BTreeMap::new(), 0).unwrap().unwrap();
    seen.insert((old, token));
    assert!(q.forget(token).unwrap());
    assert!(!q.forget(token).unwrap());
    assert_eq!(q.enqueue(&raw(1)).unwrap(), token);
    let (new, _, _) = q
        .next(&mut seen, &mut BTreeMap::new(), old)
        .unwrap()
        .unwrap();
    assert!(new > old);
    assert!(seen.is_empty());
    assert!(!q.record(old, token, 1, [4; 32]).unwrap());
    assert_eq!(q.status(token).unwrap().unwrap().state, 0);
    for _ in 0..100 {
        let (seq, _, _) = q.next(&mut seen, &mut BTreeMap::new(), 0).unwrap().unwrap();
        seen.insert((seq, token));
        q.forget(token).unwrap();
        q.enqueue(&raw(1)).unwrap();
    }
    q.next(&mut seen, &mut BTreeMap::new(), 0).unwrap();
    assert!(seen.is_empty());
    q.db.execute("UPDATE metadata SET next_seq=?1", [i64::MAX])
        .unwrap();
    q.forget(token).unwrap();
    assert_eq!(q.enqueue(&raw(2)).unwrap_err(), Error::Capacity);
    assert!(q.status(digest(&raw(2))).unwrap().is_none());
}
#[test]
fn rotation_disables_old_writers_preserves_exact_payloads_and_never_overwrites() {
    let d = private_tempdir();
    let mut q = create(d.path());
    let token = q.enqueue(&raw(1)).unwrap();
    q.record(1, token, 1, [4; 32]).unwrap();
    assert!(q.rotate("LOCAL").is_err());
    assert!(q.rotate("../bad").is_err());
    let other = Inbox::create(d.path(), "occupied", [2; 32], key()).unwrap();
    let other_id = other.instance;
    drop(other);
    assert!(q.rotate("occupied").is_err());
    assert_eq!(open(d.path(), "occupied").instance, other_id);
    let blocker = open(d.path(), "local");
    blocker.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert_eq!(q.forget(token).unwrap_err(), Error::Busy);
    assert!(q.rotate("busy").is_err());
    assert!(!d.path().join("busy.mons").exists());
    blocker.db.execute_batch("ROLLBACK").unwrap();
    drop(blocker);
    let old = open(d.path(), "local");
    let mut dest = q.rotate("next").unwrap();
    assert_eq!(q.lifecycle().unwrap().phase, 2);
    assert_eq!(dest.lifecycle().unwrap().phase, 0);
    assert!(q.enqueue(&raw(2)).is_err());
    assert!(q.forget(token).is_err());
    assert!(
        old.next(&mut BTreeSet::new(), &mut BTreeMap::new(), 0)
            .is_err()
    );
    assert_eq!(q.status(token).unwrap().unwrap().state, 1);
    assert_eq!(dest.status(token).unwrap().unwrap().state, 0);
    assert_eq!(
        dest.next(&mut BTreeSet::new(), &mut BTreeMap::new(), 0)
            .unwrap()
            .unwrap()
            .2,
        raw(1)
    );
    let additional = dest.enqueue(&raw(2)).unwrap();
    dest.record(2, additional, 1, [5; 32]).unwrap();
    drop(dest);
    let dest = q.rotate("next").unwrap();
    assert_eq!(dest.status(additional).unwrap().unwrap().state, 1);
}
#[test]
fn abandoned_staging_corruption_wrong_identity_and_upgrade_fail_closed() {
    let d = private_tempdir();
    let mut q = create(d.path());
    let token = q.enqueue(&raw(1)).unwrap();
    let mut staged = Inbox::connect(
        d.path(),
        "next",
        [2; 32],
        key(),
        true,
        Some(("local", q.instance)),
    )
    .unwrap();
    assert_eq!(staged.lifecycle().unwrap().phase, 1);
    assert!(staged.enqueue(&raw(2)).is_err());
    assert!(q.rotate("next").is_ok());
    drop(staged);
    assert!(Inbox::open(d.path(), "next", [3; 32], key()).is_err());
    let d = private_tempdir();
    let mut q = create(d.path());
    q.enqueue(&raw(1)).unwrap();
    q.db.execute("UPDATE requests SET raw=?1", [raw(2)])
        .unwrap();
    assert!(q.rotate("next").is_err());
    assert_eq!(q.lifecycle().unwrap().phase, 0);
    assert_eq!(open(d.path(), "next").lifecycle().unwrap().phase, 1);
    q.forget(token).unwrap();
    assert!(q.rotate("next").is_ok());
    let d = private_tempdir();
    legacy(d.path());
    let q = open(d.path(), "local");
    assert_eq!(q.status(digest(&raw(1))).unwrap().unwrap().state, 1);
    assert_eq!(q.metadata().unwrap().next_seq, 8);
    assert_eq!(
        q.db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        2
    );
    let d = private_tempdir();
    legacy(d.path());
    let db = Connection::open(path(d.path(), "local").unwrap()).unwrap();
    db.execute_batch("CREATE TABLE unexpected(data)").unwrap();
    drop(db);
    assert!(Inbox::open(d.path(), "local", [2; 32], key()).is_err());
    let db = Connection::open(path(d.path(), "local").unwrap()).unwrap();
    assert_eq!(
        db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    drop(db);
    for sql in [
        "UPDATE requests SET raw=zeroblob(length(raw))",
        "UPDATE requests SET token=zeroblob(32)",
        "UPDATE requests SET tip=NULL",
    ] {
        let d = private_tempdir();
        legacy(d.path());
        let db = Connection::open(path(d.path(), "local").unwrap()).unwrap();
        db.execute_batch(sql).unwrap();
        drop(db);
        assert!(Inbox::open(d.path(), "local", [2; 32], key()).is_err());
        let db = Connection::open(path(d.path(), "local").unwrap()).unwrap();
        assert_eq!(
            db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
}
#[test]
fn maintenance_crash_worker() {
    let Some(root) = std::env::var_os("MONAR_MAINTENANCE_TEST_DIR") else {
        return;
    };
    let root = PathBuf::from(root);
    let phase = std::env::var("MONAR_MAINTENANCE_TEST_PHASE").unwrap();
    if phase.starts_with("upgrade") {
        let db = Connection::open(path(&root, "local").unwrap()).unwrap();
        db.execute_batch("PRAGMA synchronous=FULL").unwrap();
        let mut q = Inbox {
            db,
            profile: [2; 32],
            node_key: key(),
            instance: [0; 16],
            root: root.clone(),
            name: "local".into(),
        };
        q.upgrade_inner(|db, after| {
            if after == phase.ends_with("after") {
                db.cache_flush().unwrap();
                std::process::exit(if after { 82 } else { 81 });
            }
        })
        .unwrap();
    } else if phase.starts_with("forget") {
        let mut q = open(&root, "local");
        q.forget_inner(digest(&raw(1)), |db, after| {
            if after == phase.ends_with("after") {
                db.cache_flush().unwrap();
                std::process::exit(if after { 82 } else { 81 });
            }
        })
        .unwrap();
    } else {
        let stage = match phase.as_str() {
            "staged" => Stage::Staged,
            "retired" => Stage::Retired,
            "activated" => Stage::Activated,
            _ => panic!("invalid phase"),
        };
        open(&root, "local")
            .rotate_inner("next", |now| {
                if now == stage {
                    std::process::exit(83);
                }
            })
            .unwrap();
    }
    panic!("crash hook did not execute");
}
fn crash(root: &Path, phase: &str, code: i32) {
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "submission::maintenance::tests::maintenance_crash_worker",
        ])
        .env("MONAR_MAINTENANCE_TEST_DIR", root)
        .env("MONAR_MAINTENANCE_TEST_PHASE", phase)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert_eq!(result.code(), Some(code));
}
#[test]
fn cleanup_and_migration_crashes_keep_atomic_rows_and_generations() {
    for phase in [
        "forget-before",
        "forget-after",
        "upgrade-before",
        "upgrade-after",
    ] {
        let d = private_tempdir();
        if phase.starts_with("upgrade") {
            legacy(d.path())
        } else {
            create(d.path()).enqueue(&raw(1)).unwrap();
        }
        crash(
            d.path(),
            phase,
            if phase.ends_with("after") { 82 } else { 81 },
        );
        let mut q = open(d.path(), "local");
        let exists = phase.starts_with("upgrade") || phase.ends_with("before");
        assert_eq!(q.status(digest(&raw(1))).unwrap().is_some(), exists);
        if phase.starts_with("upgrade") {
            assert_eq!(q.metadata().unwrap().next_seq, 8);
        } else {
            q.enqueue(&raw(1)).unwrap();
            let seq = q
                .next(&mut BTreeSet::new(), &mut BTreeMap::new(), 0)
                .unwrap()
                .unwrap()
                .0;
            assert_eq!(seq, if exists { 1 } else { 2 });
        }
    }
}
#[test]
fn rotation_crashes_resume_stages_without_losing_late_publications() {
    for phase in ["staged", "retired", "activated"] {
        let d = private_tempdir();
        let mut q = create(d.path());
        let first = q.enqueue(&raw(1)).unwrap();
        drop(q);
        crash(d.path(), phase, 83);
        let mut source = open(d.path(), "local");
        let mut dest = open(d.path(), "next");
        if phase == "staged" {
            assert_eq!(source.lifecycle().unwrap().phase, 0);
            source.enqueue(&raw(2)).unwrap();
        } else {
            assert_eq!(source.lifecycle().unwrap().phase, 2);
            assert!(source.enqueue(&raw(2)).is_err());
        }
        if phase == "activated" {
            assert_eq!(dest.lifecycle().unwrap().phase, 0);
            dest.enqueue(&raw(3)).unwrap();
        } else {
            assert_eq!(dest.lifecycle().unwrap().phase, 1);
            assert!(dest.enqueue(&raw(3)).is_err());
        }
        drop(dest);
        let dest = source.rotate("next").unwrap();
        assert!(dest.status(first).unwrap().is_some());
        assert_eq!(
            dest.status(digest(&raw(2))).unwrap().is_some(),
            phase == "staged"
        );
        assert_eq!(
            dest.status(digest(&raw(3))).unwrap().is_some(),
            phase == "activated"
        );
        assert_eq!(source.lifecycle().unwrap().phase, 2);
        assert_eq!(dest.lifecycle().unwrap().phase, 0);
    }
}
