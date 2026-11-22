use super::*;
use std::{
    io::{self, Cursor},
    process::{Command as Process, Stdio},
};

const OLD: &[u8] = b"public wallet cli password only";
const NEW: &[u8] = b"public replacement wallet password";
const BACKUP: &[u8] = b"public backup wallet password";
fn tempdir() -> tempfile::TempDir {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }
    #[cfg(not(unix))]
    {
        tempfile::tempdir().unwrap()
    }
}
fn frames(values: &[&[u8]]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for value in values {
        bytes.extend((value.len() as u16).to_le_bytes());
        bytes.extend(*value);
    }
    bytes
}
fn args(action: &str, root: &Path, checkpoint: WalletCheckpoint) -> Vec<String> {
    let mut values = vec![
        action.into(),
        "--directory".into(),
        root.to_str().unwrap().into(),
        "--name".into(),
        if action == "recover" {
            "restored".into()
        } else {
            "wallet".into()
        },
        "--network".into(),
        network(checkpoint.network).into(),
        "--password-stdin".into(),
    ];
    if action != "create" {
        values.extend([
            "--wallet-id".into(),
            hex(&checkpoint.wallet_id),
            "--revision".into(),
            checkpoint.revision.to_string(),
        ]);
    }
    if action == "address" {
        values.extend(["--type".into(), "private".into()]);
    }
    if matches!(action, "backup" | "recover") {
        values.extend(["--backup-name".into(), "snapshot".into()]);
    }
    values
}
fn parse(args: Vec<String>) -> Command {
    Command::parse(args.into_iter().map(OsString::from)).unwrap()
}
fn run(
    action: &str,
    root: &Path,
    checkpoint: WalletCheckpoint,
    secrets: &[&[u8]],
) -> Result<serde_json::Value, Error> {
    let mut output = Vec::new();
    execute(
        parse(args(action, root, checkpoint)),
        &mut Cursor::new(frames(secrets)),
        &mut output,
    )?;
    Ok(serde_json::from_slice(&output).unwrap())
}
fn checkpoint(value: &serde_json::Value) -> WalletCheckpoint {
    let value = value.get("checkpoint").unwrap_or(value);
    WalletCheckpoint {
        wallet_id: id(value["wallet_id"].as_str().unwrap()).unwrap(),
        network: match value["network"].as_str().unwrap() {
            "main" => Network::Main,
            "test" => Network::Test,
            "regtest" => Network::Regtest,
            _ => panic!(),
        },
        revision: value["revision"].as_str().unwrap().parse().unwrap(),
    }
}
fn fresh() -> WalletCheckpoint {
    WalletCheckpoint {
        wallet_id: [0; 16],
        network: Network::Regtest,
        revision: 0,
    }
}
fn fixture() -> (tempfile::TempDir, WalletCheckpoint) {
    let root = tempdir();
    let directory = WalletDirectory::open(root.path()).unwrap();
    let store = WalletStore::create(
        &directory,
        "wallet",
        Seed::from_bytes(&[7; 32]).unwrap(),
        Network::Regtest,
        &password(OLD).unwrap(),
    )
    .unwrap();
    let checkpoint = store.checkpoint().unwrap();
    drop(store);
    (root, checkpoint)
}
#[test]
fn argument_policy_rejects_untrusted_names_secrets_and_network_actions() {
    let root = tempdir();
    for command in [
        "create",
        "info",
        "address",
        "password-change",
        "backup",
        "recover",
    ] {
        assert!(
            Command::parse(
                args(command, root.path(), fresh())
                    .into_iter()
                    .map(OsString::from)
            )
            .is_ok()
        );
    }
    for command in [
        "run",
        "mine",
        "genesis",
        "send",
        "seed-export",
        "finish-recovery",
    ] {
        assert!(Command::parse([command].map(OsString::from)).is_err());
    }
    for extra in [
        vec!["--password", "must-not-echo"],
        vec!["--seed", "must-not-echo"],
        vec!["--name", "duplicate"],
        vec!["--index", "0"],
        vec!["--account", "0"],
    ] {
        let mut values = args("create", root.path(), fresh());
        values.extend(extra.into_iter().map(str::to_owned));
        assert!(Command::parse(values.into_iter().map(OsString::from)).is_err());
    }
    for invalid in [
        "",
        "../wallet",
        "a/b",
        "a\\b",
        "CON",
        "LPT9",
        "a:stream",
        "wallet.monw",
        "é",
        "name ",
    ] {
        assert!(name(invalid).is_err());
    }
    for invalid in ["", "+1", "-1", "1.0", "18446744073709551616"] {
        assert!(number(invalid).is_err());
    }
    let mut address = args("address", root.path(), fresh());
    address.extend(["--account".into(), "2147483648".into()]);
    assert!(Command::parse(address.into_iter().map(OsString::from)).is_err());
    let mut backup = args("backup", root.path(), fresh());
    *backup.last_mut().unwrap() = "WALLET".into();
    assert!(Command::parse(backup.into_iter().map(OsString::from)).is_err());
}
#[test]
fn credential_lengths_confirmation_and_eof_precede_any_creation() {
    let root = tempdir();
    let mut extra = frames(&[OLD, OLD]);
    extra.push(0);
    for input in [
        vec![],
        vec![12],
        frames(&[b"short", b"short"]),
        frames(&[OLD, NEW]),
        frames(&[OLD]),
        1025u16.to_le_bytes().to_vec(),
        extra,
    ] {
        assert_eq!(
            execute(
                parse(args("create", root.path(), fresh())),
                &mut Cursor::new(input),
                &mut Vec::new()
            ),
            Err(Error::Credentials)
        );
        assert!(!root.path().join("wallet.monw").exists());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o750)).unwrap();
        let mut input = Cursor::new(frames(&[OLD, OLD]));
        assert_eq!(
            execute(
                parse(args("create", root.path(), fresh())),
                &mut input,
                &mut Vec::new()
            ),
            Err(Error::Configuration)
        );
        assert_eq!(input.position(), 0);
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let created = run("create", root.path(), fresh(), &[OLD, OLD]).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let cp = checkpoint(&created);
        let path = root.path().join("wallet.monw");
        fs::hard_link(&path, root.path().join("alias.monw")).unwrap();
        assert_eq!(run("info", root.path(), cp, &[OLD]), Err(Error::Storage));
        fs::remove_file(root.path().join("alias.monw")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(run("info", root.path(), cp, &[OLD]), Err(Error::Storage));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(run("info", root.path(), cp, &[OLD]).is_ok());
        std::os::unix::fs::symlink(&path, root.path().join("wallet.monw-journal")).unwrap();
        assert_eq!(run("info", root.path(), cp, &[OLD]), Err(Error::Storage));
    }
    #[cfg(not(unix))]
    assert!(!created["wallet_id"].as_str().unwrap().is_empty());
}
#[test]
fn addresses_match_owned_keys_and_persist_across_reopen_without_fallback() {
    let (root, original) = fixture();
    let seed = Seed::from_bytes(&[7; 32]).unwrap();
    for (kind, label) in [
        (AddressKind::Private, "private"),
        (AddressKind::Transparent, "transparent"),
    ] {
        for expected_index in 0..2 {
            let mut command = args("address", root.path(), original);
            *command.last_mut().unwrap() = label.into();
            let mut bytes = Vec::new();
            execute(parse(command), &mut Cursor::new(frames(&[OLD])), &mut bytes).unwrap();
            let output: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(output["index"], expected_index.to_string());
            assert_eq!(output["address_type"], label);
            let expected = if kind == AddressKind::Private {
                seed.private_account(Network::Regtest, 0)
                    .unwrap()
                    .address(Scope::External, expected_index)
                    .unwrap()
            } else {
                seed.transparent_key(Network::Regtest, 0, Scope::External, expected_index as u32)
                    .unwrap()
                    .address()
            };
            assert_eq!(output["address"], expected.encode());
            assert_eq!(
                monario_wallet::Address::decode(
                    output["address"].as_str().unwrap(),
                    Network::Regtest
                )
                .unwrap(),
                expected
            );
            assert!(
                monario_wallet::Address::decode(output["address"].as_str().unwrap(), Network::Main)
                    .is_err()
            );
            assert!(!bytes.windows(32).any(|w| w == [7; 32]));
            assert!(!bytes.windows(OLD.len()).any(|w| w == OLD));
        }
    }
    let info = run("info", root.path(), original, &[OLD]).unwrap();
    assert_eq!(checkpoint(&info).revision, 4);
    for changed in [
        WalletCheckpoint {
            wallet_id: [9; 16],
            ..original
        },
        WalletCheckpoint {
            network: Network::Main,
            ..original
        },
        WalletCheckpoint {
            revision: 5,
            ..original
        },
    ] {
        assert_eq!(
            run("info", root.path(), changed, &[OLD]),
            Err(Error::Credentials)
        );
    }
}
#[test]
fn operator_key_issuance_is_authenticated_durable_and_never_exports_secrets() {
    let (root, cp) = fixture();
    assert_eq!(
        run("service-key", root.path(), cp, &[NEW]),
        Err(Error::Credentials)
    );
    let seed = Seed::from_bytes(&[7; 32]).unwrap();
    for index in 0..2 {
        let value = run("service-key", root.path(), cp, &[OLD]).unwrap();
        let key = seed
            .transparent_key(Network::Regtest, 0, Scope::External, index)
            .unwrap();
        assert_eq!(value["operator_public_key"], hex(&key.public_key()));
        assert_eq!(value["index"], index.to_string());
        assert_eq!(value["address"], key.address().encode());
        assert_eq!(checkpoint(&value).revision, u64::from(index) + 1);
        let out = serde_json::to_string(&value).unwrap();
        assert!(!out.contains(&hex(key.expose_secret())));
        assert!(!out.contains(&hex(seed.expose_for_backup())));
    }
    assert_eq!(
        execute(
            parse(args("service-key", root.path(), cp)),
            &mut Cursor::new(frames(&[OLD])),
            &mut BrokenOutput
        ),
        Err(Error::Output)
    );
    let next = run("service-key", root.path(), cp, &[OLD]).unwrap();
    assert_eq!(next["index"], "3");
    assert_eq!(checkpoint(&next).revision, 4);
}
#[test]
fn password_rotation_backup_and_recovery_preserve_keys_and_recovery_lock() {
    let (root, original) = fixture();
    let backup = run("backup", root.path(), original, &[OLD, BACKUP, BACKUP]).unwrap();
    assert_eq!(checkpoint(&backup), original);
    assert!(run("backup", root.path(), original, &[OLD, BACKUP, BACKUP]).is_err());
    let rotated = run("password-change", root.path(), original, &[OLD, NEW, NEW]).unwrap();
    assert_eq!(checkpoint(&rotated).revision, 1);
    assert_eq!(
        run("info", root.path(), original, &[OLD]),
        Err(Error::Credentials)
    );
    assert!(run("info", root.path(), original, &[NEW]).is_ok());
    let recovered = run("recover", root.path(), original, &[BACKUP, NEW, NEW]).unwrap();
    assert_eq!(recovered["recovery_required"], true);
    let recovered_cp = checkpoint(&recovered);
    let mut command = args("address", root.path(), recovered_cp);
    let pos = command.iter().position(|s| s == "--name").unwrap();
    command[pos + 1] = "restored".into();
    assert_eq!(
        execute(
            parse(command),
            &mut Cursor::new(frames(&[NEW])),
            &mut Vec::new()
        ),
        Err(Error::RecoveryLocked)
    );
    let mut command = args("service-key", root.path(), recovered_cp);
    let pos = command.iter().position(|s| s == "--name").unwrap();
    command[pos + 1] = "restored".into();
    assert_eq!(
        execute(
            parse(command),
            &mut Cursor::new(frames(&[NEW])),
            &mut Vec::new()
        ),
        Err(Error::RecoveryLocked)
    );
    assert!(run("recover", root.path(), original, &[BACKUP, NEW, NEW]).is_err());
    let directory = WalletDirectory::open(root.path()).unwrap();
    let restored = WalletStore::open(
        &directory,
        "restored",
        &password(NEW).unwrap(),
        recovered_cp,
    )
    .unwrap();
    assert_eq!(restored.expose_seed().unwrap().expose_for_backup(), [7; 32]);
    assert!(restored.recovery_required().unwrap());
}
struct BrokenOutput;
impl Write for BrokenOutput {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::ErrorKind::BrokenPipe.into())
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::ErrorKind::BrokenPipe.into())
    }
}
#[test]
fn output_failure_after_address_commit_skips_instead_of_reusing_an_index() {
    let (root, original) = fixture();
    assert_eq!(
        execute(
            parse(args("address", root.path(), original)),
            &mut Cursor::new(frames(&[OLD])),
            &mut BrokenOutput
        ),
        Err(Error::Output)
    );
    let next = run("address", root.path(), original, &[OLD]).unwrap();
    assert_eq!(next["index"], "1");
    assert_eq!(checkpoint(&next).revision, 2);
}
struct CrashInput(bool);
impl Read for CrashInput {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.0 {
            std::process::exit(81);
        }
        self.0 = true;
        out[0] = OLD.len() as u8;
        Ok(1)
    }
}
struct CrashOutput(PathBuf);
impl Write for CrashOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        // Controlled test instrumentation captures only public output before stdout acknowledgment.
        fs::write(&self.0, bytes).unwrap();
        std::process::exit(82)
    }
    fn flush(&mut self) -> io::Result<()> {
        std::process::exit(82)
    }
}
#[test]
fn crash_worker() {
    let Some(root) = std::env::var_os("MONAR_WALLET_CLI_CRASH_DIR") else {
        return;
    };
    let root = PathBuf::from(root);
    let action = std::env::var("MONAR_WALLET_CLI_CRASH_ACTION").unwrap();
    let cp = WalletCheckpoint {
        wallet_id: id(&std::env::var("MONAR_WALLET_CLI_CRASH_ID").unwrap()).unwrap(),
        ..fresh()
    };
    let actual_action = if action.starts_with("address-") {
        "address"
    } else {
        &action
    };
    let mut values = args(actual_action, &root, cp);
    if action == "address-transparent" {
        *values.last_mut().unwrap() = "transparent".into();
    }
    let command = parse(values);
    if std::env::var("MONAR_WALLET_CLI_CRASH_PHASE").unwrap() == "before" {
        execute(command, &mut CrashInput(false), &mut Vec::new()).unwrap();
    } else {
        let secrets: &[&[u8]] = match action.as_str() {
            "create" => &[OLD, OLD],
            "address-private" | "address-transparent" | "service-key" => &[OLD],
            "password-change" => &[OLD, NEW, NEW],
            "backup" => &[OLD, BACKUP, BACKUP],
            "recover" => &[BACKUP, NEW, NEW],
            _ => panic!("invalid worker action"),
        };
        execute(
            command,
            &mut Cursor::new(frames(secrets)),
            &mut CrashOutput(root.join("committed.json")),
        )
        .unwrap();
    }
    panic!("crash hook did not run");
}
#[test]
fn process_death_preserves_wallets_counters_passwords_and_encrypted_backups() {
    for action in [
        "create",
        "address-private",
        "address-transparent",
        "service-key",
        "password-change",
        "backup",
        "recover",
    ] {
        for after in [false, true] {
            let (root, original) = if action == "create" {
                (tempdir(), fresh())
            } else {
                fixture()
            };
            if action == "recover" {
                run("backup", root.path(), original, &[OLD, BACKUP, BACKUP]).unwrap();
            }
            let status = Process::new(std::env::current_exe().unwrap())
                .args(["--exact", "tests::crash_worker"])
                .env("MONAR_WALLET_CLI_CRASH_DIR", root.path())
                .env("MONAR_WALLET_CLI_CRASH_ACTION", action)
                .env("MONAR_WALLET_CLI_CRASH_ID", hex(&original.wallet_id))
                .env(
                    "MONAR_WALLET_CLI_CRASH_PHASE",
                    if after { "after" } else { "before" },
                )
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(if after { 82 } else { 81 }));
            assert_eq!(root.path().join("committed.json").exists(), after);
            if action == "create" && !after {
                assert!(!root.path().join("wallet.monw").exists());
                continue;
            }
            if action == "recover" && !after {
                assert!(!root.path().join("restored.monw").exists());
            }
            let latest = if after {
                checkpoint(
                    &serde_json::from_slice::<serde_json::Value>(
                        &fs::read(root.path().join("committed.json")).unwrap(),
                    )
                    .unwrap(),
                )
            } else {
                original
            };
            let directory = WalletDirectory::open(root.path()).unwrap();
            if action == "backup" {
                assert_eq!(root.path().join("snapshot.monw").exists(), after);
                if after {
                    let recovered = WalletStore::recover(
                        &directory,
                        "snapshot",
                        &password(BACKUP).unwrap(),
                        original,
                        &directory,
                        "verified",
                        &password(NEW).unwrap(),
                    )
                    .unwrap();
                    assert_eq!(
                        recovered.expose_seed().unwrap().expose_for_backup(),
                        [7; 32]
                    );
                }
            }
            let restored = action == "recover" && after;
            let credentials = if restored || (action == "password-change" && after) {
                NEW
            } else {
                OLD
            };
            let store = WalletStore::open(
                &directory,
                if restored { "restored" } else { "wallet" },
                &password(credentials).unwrap(),
                if action == "recover" && !after {
                    original
                } else {
                    latest
                },
            )
            .unwrap();
            assert_eq!(store.recovery_required().unwrap(), restored);
            if action != "create" {
                assert_eq!(store.expose_seed().unwrap().expose_for_backup(), [7; 32]);
            }
            assert_eq!(
                store.checkpoint().unwrap().revision,
                u64::from(
                    after
                        && matches!(
                            action,
                            "address-private"
                                | "address-transparent"
                                | "service-key"
                                | "password-change"
                                | "recover"
                        )
                )
            );
            drop(store);
            if action.starts_with("address-") || action == "service-key" {
                let mut values = args(
                    if action == "service-key" {
                        "service-key"
                    } else {
                        "address"
                    },
                    root.path(),
                    original,
                );
                if action.ends_with("transparent") {
                    *values.last_mut().unwrap() = "transparent".into();
                }
                let mut output = Vec::new();
                execute(parse(values), &mut Cursor::new(frames(&[OLD])), &mut output).unwrap();
                let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
                assert_eq!(value["index"], if after { "1" } else { "0" });
            }
            for file in fs::read_dir(root.path()).unwrap() {
                let bytes = fs::read(file.unwrap().path()).unwrap();
                for secret in [OLD, NEW, BACKUP, [7; 32].as_slice()] {
                    assert!(!bytes.windows(secret.len()).any(|w| w == secret));
                }
            }
        }
    }
}

#[test]
fn service_authorization_rejects_bad_flags_and_authenticates_before_chain_access() {
    let (dir, cp) = fixture();
    let mut values = args("service-authorize", dir.path(), cp);
    values.extend(
        [
            "--chain-directory",
            "missing-chain",
            "--manifest",
            "chain.json",
            "--profile",
            &hex(&[0; 32]),
            "--registration",
            &hex(&[1; 32]),
            "--purpose",
            "rotation",
            "--operator-index",
            "0",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    assert_eq!(
        execute(
            parse(values.clone()),
            &mut Cursor::new(frames(&[NEW])),
            &mut Vec::new()
        ),
        Err(Error::Credentials)
    );
    for (flag, bad) in [
        ("--purpose", "revive"),
        ("--operator-index", "2147483648"),
        ("--registration", "00"),
    ] {
        let mut bad_values = values.clone();
        let pos = bad_values.iter().position(|v| v == flag).unwrap();
        bad_values[pos + 1] = bad.into();
        assert!(Command::parse(bad_values.into_iter().map(OsString::from)).is_err());
    }
    values.extend(["--secret".into(), "rejected".into()]);
    assert!(Command::parse(values.into_iter().map(OsString::from)).is_err());
}

#[test]
fn service_step_authentication_and_argument_boundaries_precede_all_io() {
    let (dir, cp) = fixture();
    let mut values = args("service-step", dir.path(), cp);
    values.extend(
        [
            "--chain-directory",
            "missing-chain",
            "--manifest",
            "chain.json",
            "--profile",
            &hex(&[0; 32]),
            "--external",
            "1",
            "--internal",
            "4",
            "--schedule",
            "schedule.json",
            "--max-fee-atoms",
            "1",
            "--node-directory",
            "missing-node",
            "--submission-inbox",
            "inbox",
            "--node-public-key",
            &hex(&[1; 32]),
        ]
        .into_iter()
        .map(str::to_owned),
    );
    assert_eq!(
        execute(
            parse(values.clone()),
            &mut Cursor::new(frames(&[NEW])),
            &mut Vec::new()
        ),
        Err(Error::Credentials)
    );
    let mut bad = values.clone();
    let index = bad.iter().position(|s| s == "--schedule").unwrap();
    bad[index + 1] = "../escape.json".into();
    assert!(Command::parse(bad.into_iter().map(OsString::from)).is_err());
    values.extend(["--reservation".into(), hex(&[1; 16])]);
    assert!(Command::parse(values.into_iter().map(OsString::from)).is_err());
}

#[test]
fn discover_arguments_are_bounded_and_offline_only() {
    let (root, cp) = fixture();
    let profile = "ab".repeat(32);
    let mut base = args("discover", root.path(), cp);
    base.extend(
        [
            "--chain-directory",
            root.path().to_str().unwrap(),
            "--manifest",
            "chain.json",
            "--profile",
            &profile,
            "--account",
            "0",
            "--gap",
            "2",
            "--start",
            "4",
            "--max",
            "16",
            "--max-blocks",
            "50",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    let command = parse(base.clone());
    assert_eq!(
        command.discovery,
        Some(Discovery {
            gap: 2,
            start: 4,
            max: 16,
            blocks: 50,
        })
    );
    for (flag, value) in [
        ("--gap", "0"),
        ("--start", "1"),
        ("--max", "3"),
        ("--max", "10001"),
        ("--max-blocks", "0"),
    ] {
        let mut invalid = base.clone();
        let index = invalid.iter().position(|arg| arg == flag).unwrap();
        invalid[index + 1] = value.into();
        assert!(
            Command::parse(invalid.into_iter().map(OsString::from)).is_err(),
            "{flag}={value}"
        );
    }
    let mut extra = base;
    extra.extend(["--external".into(), "20".into()]);
    assert!(Command::parse(extra.into_iter().map(OsString::from)).is_err());
}

#[test]
fn fee_estimate_arguments_are_bounded_and_offline_only() {
    let (root, cp) = fixture();
    let profile = "ab".repeat(32);
    let mut base = args("fee-estimate", root.path(), cp);
    base.extend(
        [
            "--chain-directory",
            root.path().to_str().unwrap(),
            "--manifest",
            "chain.json",
            "--profile",
            &profile,
            "--blocks",
            "5",
            "--samples",
            "50",
            "--tx-bytes",
            "300",
            "--floor-atoms",
            "7",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    let command = parse(base.clone());
    let fee = command.fee.expect("fee options");
    assert_eq!(fee.blocks, 5);
    assert_eq!(fee.samples, 50);
    assert_eq!(fee.tx_bytes, 300);
    assert_eq!(fee.floor_atoms, 7);
    for (flag, value) in [
        ("--blocks", "0"),
        ("--blocks", "1001"),
        ("--samples", "0"),
        ("--tx-bytes", "0"),
        ("--tx-bytes", "4000001"),
        ("--floor-atoms", "x"),
    ] {
        let mut invalid = base.clone();
        let index = invalid.iter().position(|arg| arg == flag).unwrap();
        invalid[index + 1] = value.into();
        assert!(
            Command::parse(invalid.into_iter().map(OsString::from)).is_err(),
            "{flag}={value}"
        );
    }
    let mut extra = base;
    extra.extend(["--external".into(), "20".into()]);
    assert!(Command::parse(extra.into_iter().map(OsString::from)).is_err());
}

#[test]
fn every_wallet_action_parses_its_documented_flags() {
    let hash = "11".repeat(32);
    let wallet_id = "22".repeat(16);
    let reservation = "33".repeat(16);
    let flags =
        |items: &[&str]| -> Vec<String> { items.iter().map(|value| (*value).to_owned()).collect() };
    let scan_status = flags(&[
        "--chain-directory",
        "chain",
        "--manifest",
        "chain.json",
        "--profile",
        hash.as_str(),
        "--checkpoint",
        hash.as_str(),
    ]);
    let mut scan_full = scan_status.clone();
    scan_full.extend(flags(&[
        "--external",
        "2",
        "--internal",
        "2",
        "--account",
        "0",
        "--max-blocks",
        "100",
    ]));
    let step = flags(&[
        "--schedule",
        "schedule.json",
        "--max-fee-atoms",
        "1",
        "--node-directory",
        "node",
        "--submission-inbox",
        "inbox",
        "--node-public-key",
        hash.as_str(),
    ]);
    let node = flags(&[
        "--node-directory",
        "node",
        "--submission-inbox",
        "inbox",
        "--node-public-key",
        hash.as_str(),
    ]);
    let mut service_step = scan_full.clone();
    service_step.extend(step.clone());
    let mut service_supervise = service_step.clone();
    service_supervise.extend(flags(&[
        "--interval-seconds",
        "30",
        "--max-steps",
        "2",
        "--stop-file",
        "halt.stop",
        "--health-file",
        "supervise-health.json",
    ]));
    let mut service_authorize = scan_status.clone();
    service_authorize.extend(flags(&[
        "--registration",
        hash.as_str(),
        "--purpose",
        "rotation",
        "--operator-index",
        "0",
        "--account",
        "0",
    ]));
    let mut service_status = scan_status.clone();
    service_status.extend(flags(&["--registration", hash.as_str()]));
    let mut discover = scan_status.clone();
    discover.extend(flags(&[
        "--account",
        "0",
        "--gap",
        "2",
        "--start",
        "4",
        "--max",
        "16",
        "--max-blocks",
        "50",
    ]));
    let mut fee = scan_status.clone();
    fee.extend(flags(&[
        "--blocks",
        "20",
        "--samples",
        "200",
        "--tx-bytes",
        "250",
        "--floor-atoms",
        "0",
    ]));
    let mut construct = scan_full.clone();
    construct.extend(flags(&[
        "--request",
        "request.json",
        "--max-fee-atoms",
        "1",
    ]));
    let mut payout = scan_full.clone();
    payout.extend(flags(&[
        "--request",
        "payout.json",
        "--max-fee-atoms",
        "1",
        "--node-directory",
        "node",
        "--submission-inbox",
        "inbox",
        "--node-public-key",
        hash.as_str(),
    ]));
    let mut balance = scan_full.clone();
    balance.push("--rescan".to_owned());
    let mut transaction_status = scan_status.clone();
    transaction_status.extend(flags(&["--reservation", reservation.as_str()]));
    let mut rebroadcast = scan_status.clone();
    rebroadcast.extend(node.clone());
    rebroadcast.extend(flags(&["--after-reservation", reservation.as_str()]));
    let mut submit = node.clone();
    submit.extend(flags(&[
        "--profile",
        hash.as_str(),
        "--reservation",
        reservation.as_str(),
    ]));
    let export = flags(&[
        "--profile",
        hash.as_str(),
        "--reservation",
        reservation.as_str(),
    ]);
    let pull = flags(&[
        "--chain-directory",
        "chain",
        "--manifest",
        "chain.json",
        "--profile",
        hash.as_str(),
        "--remote",
        "127.0.0.1:18081",
        "--token-file",
        "scan.token",
        "--remote-public-key",
        hash.as_str(),
        "--max-blocks",
        "10",
        "--timeout-seconds",
        "5",
        "--checkpoint",
        hash.as_str(),
    ]);
    type ParseRow<'a> = (&'a str, Action, Vec<String>, fn(&Command) -> bool);
    let rows: Vec<ParseRow> = vec![
        ("create", Action::Create, vec![], |c| c.expected.is_none()),
        ("info", Action::Info, vec![], |c| c.scan.is_none()),
        (
            "address",
            Action::Address,
            flags(&["--type", "private", "--account", "0"]),
            |c| c.kind.is_some(),
        ),
        (
            "service-key",
            Action::ServiceKey,
            flags(&["--account", "0"]),
            |c| c.account == 0,
        ),
        (
            "service-status",
            Action::ServiceStatus,
            service_status,
            |c| c.scan.is_some() && c.registration.is_some(),
        ),
        (
            "service-authorize",
            Action::ServiceAuthorize,
            service_authorize,
            |c| c.authorization.is_some() && c.registration.is_some(),
        ),
        ("service-step", Action::ServiceStep, service_step, |c| {
            c.scan.is_some() && c.step.is_some()
        }),
        (
            "service-supervise",
            Action::ServiceSupervise,
            service_supervise,
            |c| c.supervise.is_some() && c.step.is_some(),
        ),
        ("password-change", Action::Password, vec![], |_| true),
        (
            "backup",
            Action::Backup,
            flags(&["--backup-name", "snapshot"]),
            |c| c.backup.is_some(),
        ),
        (
            "recover",
            Action::Recover,
            flags(&["--backup-name", "snapshot"]),
            |c| c.backup.is_some(),
        ),
        ("balance", Action::Balance, balance, |c| c.scan.is_some()),
        ("discover", Action::Discover, discover, |c| {
            c.scan.is_some() && c.discovery.is_some()
        }),
        ("fee-estimate", Action::FeeEstimate, fee, |c| {
            c.scan.is_some() && c.fee.is_some()
        }),
        ("inputs", Action::Inputs, scan_full.clone(), |c| {
            c.scan.is_some()
        }),
        ("construct", Action::Construct, construct, |c| {
            c.scan.is_some() && c.transaction.is_some()
        }),
        ("payout-execute", Action::PayoutExecute, payout, |c| {
            c.scan.is_some() && c.payout.is_some()
        }),
        (
            "plan-payment",
            Action::Plan,
            {
                let mut value = scan_full.clone();
                value.extend(flags(&[
                    "--request",
                    "request.json",
                    "--max-fee-atoms",
                    "1",
                ]));
                value
            },
            |c| c.scan.is_some() && c.plan.is_some(),
        ),
        ("transaction-export", Action::Export, export, |c| {
            c.scan.is_none() && c.transaction.is_some()
        }),
        (
            "transaction-status",
            Action::TransactionStatus,
            transaction_status,
            |c| c.status.is_some(),
        ),
        ("rebroadcast-step", Action::Rebroadcast, rebroadcast, |c| {
            c.rebroadcast.is_some()
        }),
        ("submit", Action::Submit, submit.clone(), |c| {
            c.submission.is_some()
        }),
        ("submission-status", Action::SubmissionStatus, submit, |c| {
            c.submission.is_some()
        }),
        ("pull-remote", Action::PullRemote, pull, |c| {
            c.remote.is_some() && !c.needs_password()
        }),
    ];
    let documented: Vec<&str> = HELP
        .lines()
        .find(|line| line.starts_with("Commands: "))
        .unwrap()
        .trim_start_matches("Commands: ")
        .split(", ")
        .collect();
    let mut listed: Vec<&str> = rows.iter().map(|(action, ..)| *action).collect();
    assert_eq!(
        listed.len(),
        documented.len(),
        "the table must cover every documented command"
    );
    listed.sort_unstable();
    let mut documented = documented;
    documented.sort_unstable();
    assert_eq!(listed, documented);
    for (action, expected, extra, check) in rows {
        let mut args: Vec<OsString> = vec![action.into()];
        if action != "pull-remote" {
            args.extend(
                [
                    "--directory",
                    "wallet",
                    "--name",
                    "wallet",
                    "--network",
                    "main",
                    "--password-stdin",
                ]
                .into_iter()
                .map(OsString::from),
            );
            if action != "create" {
                args.extend(
                    ["--wallet-id", wallet_id.as_str(), "--revision", "0"]
                        .into_iter()
                        .map(OsString::from),
                );
            }
        }
        args.extend(extra.into_iter().map(OsString::from));
        let command = Command::parse(args)
            .unwrap_or_else(|_| panic!("{action} must parse its documented flags"));
        assert!(command.action == expected, "{action}");
        assert!(
            check(&command),
            "{action} did not populate its documented options"
        );
        assert!(HELP.contains(action), "{action} must be documented in HELP");
    }
}
