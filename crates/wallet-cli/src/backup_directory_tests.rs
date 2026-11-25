use super::*;
use std::io::Cursor;

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

fn args(action: &str, root: &Path, cp: WalletCheckpoint, extra: &[&str]) -> Vec<OsString> {
    let mut values: Vec<OsString> = vec![
        OsString::from(action),
        OsString::from("--directory"),
        root.as_os_str().to_owned(),
        OsString::from("--name"),
        OsString::from(if action == "recover" { "restored" } else { "wallet" }),
        OsString::from("--network"),
        OsString::from(network(cp.network)),
        OsString::from("--password-stdin"),
    ];
    if action != "create" {
        values.extend([
            OsString::from("--wallet-id"),
            OsString::from(hex(&cp.wallet_id)),
            OsString::from("--revision"),
            OsString::from(cp.revision.to_string()),
        ]);
    }
    if matches!(action, "backup" | "recover") {
        values.extend([OsString::from("--backup-name"), OsString::from("snapshot")]);
    }
    values.extend(extra.iter().map(|value| OsString::from(*value)));
    values
}

fn run(values: Vec<OsString>, secrets: &[&[u8]]) -> Result<serde_json::Value, Error> {
    let mut output = Vec::new();
    execute(
        Command::parse(values)?,
        &mut Cursor::new(frames(secrets)),
        &mut output,
    )?;
    Ok(serde_json::from_slice(&output).unwrap())
}

fn checkpoint(value: &serde_json::Value) -> WalletCheckpoint {
    WalletCheckpoint {
        wallet_id: id(value["wallet_id"].as_str().unwrap()).unwrap(),
        network: Network::Regtest,
        revision: value["revision"].as_str().unwrap().parse().unwrap(),
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
    let cp = store.checkpoint().unwrap();
    drop(store);
    (root, cp)
}

#[test]
fn encrypted_backup_routes_to_explicit_directory_and_recovers_from_it() {
    let (root, cp) = fixture();
    let dest = tempdir();
    let dest_arg = dest.path().to_str().unwrap();
    let flag = ["--backup-directory", dest_arg];

    let backup = run(args("backup", root.path(), cp, &flag), &[OLD, BACKUP, BACKUP]).unwrap();
    assert_eq!(checkpoint(&backup), cp);
    assert!(dest.path().join("snapshot.monw").is_file());
    assert!(!root.path().join("snapshot.monw").exists());

    let recovered = run(
        args("recover", root.path(), cp, &flag),
        &[BACKUP, NEW, NEW],
    )
    .unwrap();
    assert_eq!(recovered["recovery_required"], true);
    assert!(root.path().join("restored.monw").is_file());
    assert!(!dest.path().join("restored.monw").exists());

    let directory = WalletDirectory::open(root.path()).unwrap();
    let store = WalletStore::open(
        &directory,
        "restored",
        &password(NEW).unwrap(),
        checkpoint(&recovered),
    )
    .unwrap();
    assert_eq!(store.expose_seed().unwrap().expose_for_backup(), [7; 32]);
    assert!(store.recovery_required().unwrap());
}

#[test]
fn default_backup_and_recover_stay_in_the_wallet_directory() {
    let (root, cp) = fixture();
    let parsed = Command::parse(args("backup", root.path(), cp, &[])).unwrap();
    assert!(parsed.backup_directory.is_none());

    run(args("backup", root.path(), cp, &[]), &[OLD, BACKUP, BACKUP]).unwrap();
    assert!(root.path().join("snapshot.monw").is_file());
    run(args("recover", root.path(), cp, &[]), &[BACKUP, NEW, NEW]).unwrap();
    assert!(root.path().join("restored.monw").is_file());
}

#[test]
fn backup_directory_is_rejected_for_unrelated_commands_and_empty_values() {
    let (root, cp) = fixture();
    let dest = tempdir();
    let dest_arg = dest.path().to_str().unwrap();
    for action in ["create", "info", "password-change", "service-key"] {
        let values = args(action, root.path(), cp, &["--backup-directory", dest_arg]);
        assert!(Command::parse(values).is_err(), "{action}");
    }
    let empty = args("backup", root.path(), cp, &["--backup-directory", ""]);
    assert!(Command::parse(empty).is_err());
    let valid = args("backup", root.path(), cp, &["--backup-directory", dest_arg]);
    assert!(Command::parse(valid).is_ok());
}

#[test]
fn backup_collisions_never_replace_an_existing_snapshot() {
    let (root, cp) = fixture();
    let dest = tempdir();
    let dest_arg = dest.path().to_str().unwrap();
    let flag = ["--backup-directory", dest_arg];
    run(args("backup", root.path(), cp, &flag), &[OLD, BACKUP, BACKUP]).unwrap();
    let before = fs::read(dest.path().join("snapshot.monw")).unwrap();
    assert!(run(args("backup", root.path(), cp, &flag), &[OLD, BACKUP, BACKUP]).is_err());
    assert_eq!(
        fs::read(dest.path().join("snapshot.monw")).unwrap(),
        before
    );
}

#[test]
fn missing_backup_directory_is_rejected_before_any_write() {
    let (root, cp) = fixture();
    let dest = tempdir();
    let missing = dest.path().join("missing");
    let missing_arg = missing.to_str().unwrap();
    assert_eq!(
        run(
            args("backup", root.path(), cp, &["--backup-directory", missing_arg]),
            &[OLD, BACKUP, BACKUP]
        ),
        Err(Error::Configuration)
    );
    assert!(!missing.exists());
    assert!(!root.path().join("snapshot.monw").exists());
}

#[cfg(unix)]
#[test]
fn unreadable_backup_directory_is_rejected_without_writes() {
    use std::os::unix::fs::PermissionsExt;
    let (root, cp) = fixture();
    let dest = tempdir();
    let dest_arg = dest.path().to_str().unwrap();
    fs::set_permissions(dest.path(), fs::Permissions::from_mode(0o750)).unwrap();
    assert_eq!(
        run(
            args("backup", root.path(), cp, &["--backup-directory", dest_arg]),
            &[OLD, BACKUP, BACKUP]
        ),
        Err(Error::Configuration)
    );
    assert!(!dest.path().join("snapshot.monw").exists());
    fs::set_permissions(dest.path(), fs::Permissions::from_mode(0o700)).unwrap();
}

#[cfg(unix)]
#[test]
fn symlinked_backup_directory_is_rejected_for_backup_and_recover() {
    let (root, cp) = fixture();
    let dest = tempdir();
    let scratch = tempdir();
    let link = scratch.path().join("link");
    std::os::unix::fs::symlink(dest.path(), &link).unwrap();
    let link_arg = link.to_str().unwrap();
    let flag = ["--backup-directory", link_arg];
    assert_eq!(
        run(args("backup", root.path(), cp, &flag), &[OLD, BACKUP, BACKUP]),
        Err(Error::Configuration)
    );
    assert!(!dest.path().join("snapshot.monw").exists());
    assert_eq!(
        run(args("recover", root.path(), cp, &flag), &[BACKUP, NEW, NEW]),
        Err(Error::Configuration)
    );
    assert!(!root.path().join("restored.monw").exists());
}

#[cfg(unix)]
#[test]
fn symlinked_snapshot_inside_backup_directory_is_rejected() {
    let (root, cp) = fixture();
    let dest = tempdir();
    let outside = tempdir();
    let target = outside.path().join("target.monw");
    fs::write(&target, b"outside").unwrap();
    std::os::unix::fs::symlink(&target, dest.path().join("snapshot.monw")).unwrap();
    let dest_arg = dest.path().to_str().unwrap();
    let flag = ["--backup-directory", dest_arg];
    assert_eq!(
        run(args("backup", root.path(), cp, &flag), &[OLD, BACKUP, BACKUP]),
        Err(Error::Storage)
    );
    assert_eq!(fs::read(&target).unwrap(), b"outside");
    assert_eq!(
        run(args("recover", root.path(), cp, &flag), &[BACKUP, NEW, NEW]),
        Err(Error::Storage)
    );
    assert!(!root.path().join("restored.monw").exists());
}
