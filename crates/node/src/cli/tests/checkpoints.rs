//! No launch: existing synthetic zero-supply root metadata and real verifier only.
use super::*;
fn command(action: &str, root: &Path, cp: Checkpoint, pin: Option<[u8; 32]>) -> Vec<String> {
    let mut values = args(action, root, cp);
    if action == "checkpoint-create" {
        values.extend(["--manifest".into(), "node.json".into()]);
    }
    if let Some(pin) = pin {
        values.extend(["--checkpoint".into(), hex(&pin)]);
    }
    values
}
fn run(
    action: &str,
    root: &Path,
    cp: Checkpoint,
    pin: Option<[u8; 32]>,
) -> Result<serde_json::Value, Error> {
    let mut out = Vec::new();
    execute(
        parse(command(action, root, cp, pin)),
        &mut Cursor::new(frame(OLD)),
        &mut out,
        &Arc::new(AtomicBool::new(true)),
    )?;
    Ok(serde_json::from_slice(&out).unwrap())
}
#[test]
fn checkpoint_cli_requires_explicit_trust_and_full_replay_creation() {
    let dir = private_tempdir();
    let cp = chain_fixture(dir.path());
    let identity = fs::read(dir.path().join("node.monp")).unwrap();
    let receipt = run("checkpoint-create", dir.path(), cp, None).unwrap();
    let pin = hash(receipt["chain_checkpoint"].as_str().unwrap()).unwrap();
    assert_eq!(receipt["full_chain_replay"], true);
    assert_eq!(receipt["height"], "0");
    assert_eq!(
        hash(receipt["validated_tip"].as_str().unwrap()).unwrap(),
        [3; 32]
    );
    assert_eq!(
        run("checkpoint-create", dir.path(), cp, None).unwrap()["chain_checkpoint"],
        receipt["chain_checkpoint"]
    );
    let loaded = run("check", dir.path(), cp, Some(pin)).unwrap();
    assert_eq!(loaded["chain_checkpoint"], receipt["chain_checkpoint"]);
    assert_eq!(loaded["full_chain_replay"], false);
    assert!(run("run", dir.path(), cp, Some(pin)).is_ok());
    // A valid database must not cause a missing pin to fall back to full replay.
    assert_eq!(
        run("check", dir.path(), cp, Some([0; 32])).err(),
        Some(Error::Storage)
    );
    for action in ["checkpoint-create", "identity-info", "submission-create"] {
        assert!(
            Command::parse(
                command(action, dir.path(), cp, Some(pin))
                    .into_iter()
                    .map(OsString::from)
            )
            .is_err()
        );
    }
    let mut malformed = command("check", dir.path(), cp, None);
    malformed.extend(["--checkpoint".into(), "bad".into()]);
    assert!(Command::parse(malformed.into_iter().map(OsString::from)).is_err());
    let path = dir.path().join("chain.sqlite");
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute(
        "UPDATE checkpoint_rows SET data=zeroblob(length(data)+1) WHERE ordinal=0",
        [],
    )
    .unwrap();
    drop(db);
    assert!(run("check", dir.path(), cp, Some(pin)).is_err());
    assert!(run("check", dir.path(), cp, None).is_ok());
    // Re-creation authenticates history again and repairs this identical cache.
    assert_eq!(
        run("checkpoint-create", dir.path(), cp, None).unwrap()["chain_checkpoint"],
        receipt["chain_checkpoint"]
    );
    assert!(run("check", dir.path(), cp, Some(pin)).is_ok());
    assert_eq!(fs::read(dir.path().join("node.monp")).unwrap(), identity);
}
#[test]
fn checkpoint_cli_crash_worker() {
    let Some(root) = std::env::var_os("MONAR_CHECKPOINT_CLI_TEST_DIR") else {
        return;
    };
    let root = PathBuf::from(root);
    let cp = Checkpoint {
        profile: hash(&std::env::var("MONAR_CHECKPOINT_CLI_TEST_PROFILE").unwrap()).unwrap(),
        public_key: hash(&std::env::var("MONAR_CHECKPOINT_CLI_TEST_KEY").unwrap()).unwrap(),
        revision: 0,
    };
    let command = parse(command("checkpoint-create", &root, cp, None));
    if std::env::var("MONAR_CHECKPOINT_CLI_TEST_PHASE").unwrap() == "before" {
        execute(
            command,
            &mut CrashInput {
                sent_prefix_byte: false,
            },
            &mut Vec::new(),
            &Arc::new(AtomicBool::new(true)),
        )
        .unwrap();
    } else {
        struct Capture(PathBuf);
        impl Write for Capture {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                fs::write(&self.0, b).unwrap();
                std::process::exit(82)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                std::process::exit(82)
            }
        }
        execute(
            command,
            &mut Cursor::new(frame(OLD)),
            &mut Capture(root.join("receipt.json")),
            &Arc::new(AtomicBool::new(true)),
        )
        .unwrap();
    }
}
#[test]
fn checkpoint_cli_crashes_preserve_identity_and_committed_cache() {
    for after in [false, true] {
        let dir = private_tempdir();
        let cp = chain_fixture(dir.path());
        let before = fs::read(dir.path().join("node.monp")).unwrap();
        let result = Process::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "cli::tests::checkpoints::checkpoint_cli_crash_worker",
            ])
            .env("MONAR_CHECKPOINT_CLI_TEST_DIR", dir.path())
            .env("MONAR_CHECKPOINT_CLI_TEST_PROFILE", hex(&cp.profile))
            .env("MONAR_CHECKPOINT_CLI_TEST_KEY", hex(&cp.public_key))
            .env(
                "MONAR_CHECKPOINT_CLI_TEST_PHASE",
                if after { "after" } else { "before" },
            )
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert_eq!(result.code(), Some(if after { 82 } else { 81 }));
        let db = rusqlite::Connection::open(dir.path().join("chain.sqlite")).unwrap();
        let tables:i64=db.query_row("SELECT count(*) FROM sqlite_schema WHERE type='table' AND name='state_checkpoints'",[],|r|r.get(0)).unwrap();
        assert_eq!(tables, i64::from(after));
        drop(db);
        if after {
            let receipt: serde_json::Value =
                serde_json::from_slice(&fs::read(dir.path().join("receipt.json")).unwrap())
                    .unwrap();
            let pin = hash(receipt["chain_checkpoint"].as_str().unwrap()).unwrap();
            assert!(run("check", dir.path(), cp, Some(pin)).is_ok());
        }
        let receipt = run("checkpoint-create", dir.path(), cp, None).unwrap();
        assert!(
            run(
                "check",
                dir.path(),
                cp,
                Some(hash(receipt["chain_checkpoint"].as_str().unwrap()).unwrap())
            )
            .is_ok()
        );
        assert_eq!(fs::read(dir.path().join("node.monp")).unwrap(), before);
    }
}
