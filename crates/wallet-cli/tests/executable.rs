//! Offline subprocess tests. Resolve the installed build artifact at runtime, never via env! paths.
use std::{
    ffi::OsStr,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};
const PASSWORD: &[u8] = b"public wallet executable password";
fn tempdir() -> tempfile::TempDir {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }
    #[cfg(not(unix))]
    {
        tempfile::tempdir().unwrap()
    }
}
fn binary() -> PathBuf {
    std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join(if cfg!(windows) {
            "monario-wallet.exe"
        } else {
            "monario-wallet"
        })
}
fn run(args: &[&OsStr], frames: usize) -> Output {
    let mut child = Command::new(binary())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    for _ in 0..frames {
        input
            .write_all(&(PASSWORD.len() as u16).to_le_bytes())
            .unwrap();
        input.write_all(PASSWORD).unwrap();
    }
    drop(input);
    child.wait_with_output().unwrap()
}
fn common<'a>(action: &'a str, root: &'a Path) -> Vec<&'a OsStr> {
    vec![
        OsStr::new(action),
        OsStr::new("--directory"),
        root.as_os_str(),
        OsStr::new("--name"),
        OsStr::new("wallet"),
        OsStr::new("--network"),
        OsStr::new("regtest"),
        OsStr::new("--password-stdin"),
    ]
}
#[test]
fn executable_rejects_network_key_exports_and_secret_arguments_without_echoing() {
    let help = run(&[OsStr::new("--help")], 0);
    assert!(help.status.success());
    assert!(
        std::str::from_utf8(&help.stdout)
            .unwrap()
            .contains("No network")
    );
    for args in [
        vec![OsStr::new("run")],
        vec![OsStr::new("seed-export")],
        vec![
            OsStr::new("create"),
            OsStr::new("--password"),
            OsStr::new("private-value-must-not-echo"),
        ],
    ] {
        let error = run(&args, 0);
        assert!(!error.status.success());
        assert!(error.stdout.is_empty());
        assert_eq!(error.stderr, b"error: invalid arguments; use --help\n");
    }
}
#[test]
fn executable_creates_and_reopens_an_encrypted_wallet_and_receiving_address() {
    let root = tempdir();
    let created = run(&common("create", root.path()), 2);
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let receipt: serde_json::Value = serde_json::from_slice(&created.stdout).unwrap();
    assert_eq!(receipt["revision"], "0");
    assert_eq!(receipt["recovery_required"], false);
    let id = receipt["wallet_id"].as_str().unwrap();
    let mut address = common("address", root.path());
    address.extend([
        OsStr::new("--wallet-id"),
        OsStr::new(id),
        OsStr::new("--revision"),
        OsStr::new("0"),
        OsStr::new("--type"),
        OsStr::new("private"),
    ]);
    let issued = run(&address, 1);
    assert!(issued.status.success());
    let result: serde_json::Value = serde_json::from_slice(&issued.stdout).unwrap();
    assert_eq!(result["index"], "0");
    assert_eq!(result["checkpoint"]["revision"], "1");
    assert!(
        monario_wallet::Address::decode(
            result["address"].as_str().unwrap(),
            monario_wallet::Network::Regtest
        )
        .is_ok()
    );
    let repeated = run(&address, 1);
    assert!(repeated.status.success());
    let repeated: serde_json::Value = serde_json::from_slice(&repeated.stdout).unwrap();
    assert_eq!(repeated["index"], "1");
    let mut info = common("info", root.path());
    info.extend([
        OsStr::new("--wallet-id"),
        OsStr::new(id),
        OsStr::new("--revision"),
        OsStr::new("2"),
    ]);
    let reopened = run(&info, 1);
    assert!(reopened.status.success());
    for bytes in [
        &created.stdout,
        &created.stderr,
        &issued.stdout,
        &reopened.stdout,
        &std::fs::read(root.path().join("wallet.monw")).unwrap(),
    ] {
        assert!(!bytes.windows(PASSWORD.len()).any(|w| w == PASSWORD));
    }
}
