//! Real executable, offline commands only. Locate binaries at runtime: no build paths embedded.
use monario_node::transport::persistent::TrustedPeers;
use std::{
    ffi::OsStr,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};
const SECRET: &[u8] = b"public cli integration password";
fn private_tempdir() -> tempfile::TempDir {
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
    let test = std::env::current_exe().unwrap();
    let executable = test
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join(if cfg!(windows) {
            "monario-node.exe"
        } else {
            "monario-node"
        });
    assert!(executable.is_file());
    executable
}
fn run(args: &[&OsStr], password: bool) -> Output {
    let mut child = Command::new(binary())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if password {
        let mut input = child.stdin.take().unwrap();
        input
            .write_all(&(SECRET.len() as u16).to_le_bytes())
            .unwrap();
        input.write_all(SECRET).unwrap();
    } else {
        drop(child.stdin.take());
    }
    child.wait_with_output().unwrap()
}
fn common<'a>(action: &'a str, root: &'a Path, profile: &'a str) -> Vec<&'a OsStr> {
    vec![
        OsStr::new(action),
        OsStr::new("--directory"),
        root.as_os_str(),
        OsStr::new("--profile"),
        OsStr::new(profile),
        OsStr::new("--password-stdin"),
    ]
}
#[test]
fn executable_help_and_errors_never_echo_arguments_or_enable_a_network() {
    let help = run(&[OsStr::new("--help")], false);
    assert!(help.status.success());
    assert!(help.stderr.is_empty());
    assert!(
        std::str::from_utf8(&help.stdout)
            .unwrap()
            .contains("--enable-network")
    );
    let bad = run(
        &[
            OsStr::new("run"),
            OsStr::new("--password"),
            OsStr::new("private-argument-must-not-be-echoed"),
        ],
        false,
    );
    assert!(!bad.status.success());
    assert!(bad.stdout.is_empty());
    assert_eq!(bad.stderr, b"error: invalid arguments; use --help\n");
    let dir = private_tempdir();
    let profile = "02".repeat(32);
    let key = "11".repeat(32);
    let mut args = common("run", dir.path(), &profile);
    args.extend([
        OsStr::new("--public-key"),
        OsStr::new(&key),
        OsStr::new("--revision"),
        OsStr::new("0"),
        OsStr::new("--manifest"),
        OsStr::new("node.json"),
    ]);
    let rejected = run(&args, false); // No --enable-network, rejected before files/passwords.
    assert!(!rejected.status.success());
    assert!(fs_empty(dir.path()));
}
fn fs_empty(root: &Path) -> bool {
    std::fs::read_dir(root).unwrap().next().is_none()
}
#[test]
fn executable_offline_identity_receipt_reopens_without_exposing_secrets() {
    let dir = private_tempdir();
    let profile = "02".repeat(32);
    std::fs::write(
        dir.path().join("peers.json"),
        TrustedPeers::empty([2; 32]).document().unwrap(),
    )
    .unwrap();
    let mut create = common("identity-create", dir.path(), &profile);
    create.extend([OsStr::new("--peers"), OsStr::new("peers.json")]);
    let created = run(&create, true);
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let receipt: serde_json::Value = serde_json::from_slice(&created.stdout).unwrap();
    assert_eq!(receipt["revision"], 0);
    assert_eq!(receipt["profile"], profile);
    let key = receipt["public_key"].as_str().unwrap();
    let mut info = common("identity-info", dir.path(), &profile);
    info.extend([
        OsStr::new("--public-key"),
        OsStr::new(key),
        OsStr::new("--revision"),
        OsStr::new("0"),
    ]);
    let opened = run(&info, true);
    assert!(opened.status.success());
    assert_eq!(opened.stdout, created.stdout);
    let exists = run(&create, true);
    assert!(!exists.status.success());
    assert!(exists.stdout.is_empty());
    for bytes in [
        &created.stdout,
        &created.stderr,
        &opened.stdout,
        &exists.stderr,
        &std::fs::read(dir.path().join("node.monp")).unwrap(),
    ] {
        assert!(!bytes.windows(SECRET.len()).any(|w| w == SECRET));
    }
}
