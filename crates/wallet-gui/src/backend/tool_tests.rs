use super::*;

const PASSWORD: &str = "correct horse battery";

fn wallet() -> WalletRef {
    WalletRef {
        directory: "C:/wallets".into(),
        name: "main".into(),
        network: Network::Test,
        wallet_id: "0123456789abcdef0123456789abcdef".into(),
        revision: 4,
    }
}

fn secret(text: &str) -> Zeroizing<String> {
    Zeroizing::new(text.to_owned())
}

fn frame(bytes: &[u8]) -> Vec<u8> {
    let mut out = (bytes.len() as u16).to_le_bytes().to_vec();
    out.extend_from_slice(bytes);
    out
}

#[test]
fn sign_stdin_is_password_frame_then_message_frame() {
    let spec = wallet_sign_message(&wallet(), &secret(PASSWORD), 0, 7, "hi there").unwrap();
    let mut expected = frame(PASSWORD.as_bytes());
    expected.extend(frame(b"hi there"));
    assert_eq!(spec.stdin().unwrap().as_slice(), expected.as_slice());
}

#[test]
fn sign_message_keeps_exact_bytes_without_trim() {
    let spec = wallet_sign_message(&wallet(), &secret(PASSWORD), 0, 0, "  spaced\n").unwrap();
    let mut expected = frame(PASSWORD.as_bytes());
    expected.extend(frame(b"  spaced\n"));
    assert_eq!(spec.stdin().unwrap().as_slice(), expected.as_slice());
}

#[test]
fn sign_args_carry_indices_but_no_secret_content() {
    let spec = wallet_sign_message(&wallet(), &secret(PASSWORD), 3, 7, "secret words").unwrap();
    assert_eq!(spec.args[0], "sign-message");
    assert!(spec.args.contains(&"--password-stdin".to_owned()));
    let tail = &spec.args[spec.args.len() - 4..];
    assert_eq!(tail, ["--account", "3", "--address-index", "7"]);
    for arg in &spec.args {
        assert!(!arg.contains(PASSWORD));
        assert!(!arg.contains("secret words"));
    }
}

#[test]
fn sign_debug_prints_no_payload() {
    let spec = wallet_sign_message(&wallet(), &secret(PASSWORD), 0, 0, "secret words").unwrap();
    let debug = format!("{spec:?}");
    assert!(!debug.contains(PASSWORD));
    assert!(!debug.contains("secret words"));
}

#[test]
fn sign_message_bounds_are_enforced() {
    let pw = secret(PASSWORD);
    assert!(wallet_sign_message(&wallet(), &pw, 0, 0, "").is_err());
    let max = "m".repeat(MAX_MESSAGE);
    assert!(wallet_sign_message(&wallet(), &pw, 0, 0, &max).is_ok());
    let over = "m".repeat(MAX_MESSAGE + 1);
    assert!(wallet_sign_message(&wallet(), &pw, 0, 0, &over).is_err());
}

#[test]
fn sign_password_validation_is_preserved() {
    let short = secret("short");
    let spec = wallet_sign_message(&wallet(), &short, 0, 0, "hi").unwrap();
    assert!(spec.stdin().is_err());
}

#[test]
fn verify_stdin_is_two_frames_and_no_password() {
    let spec = wallet_verify_message(Network::Main, "hello", "abc123").unwrap();
    assert_eq!(
        spec.args,
        ["verify-message", "--network", "main"].map(str::to_owned)
    );
    let mut expected = frame(b"hello");
    expected.extend(frame(b"abc123"));
    assert_eq!(spec.stdin().unwrap().as_slice(), expected.as_slice());
}

#[test]
fn verify_content_never_reaches_argv_or_debug() {
    let spec = wallet_verify_message(Network::Test, "private message", "proofdata").unwrap();
    for arg in &spec.args {
        assert!(!arg.contains("private message"));
        assert!(!arg.contains("proofdata"));
    }
    let debug = format!("{spec:?}");
    assert!(!debug.contains("private message"));
    assert!(!debug.contains("proofdata"));
}

#[test]
fn verify_bounds_are_enforced() {
    assert!(wallet_verify_message(Network::Test, "", "p").is_err());
    let max = "m".repeat(MAX_MESSAGE);
    assert!(wallet_verify_message(Network::Test, &max, "p").is_ok());
    let over = "m".repeat(MAX_MESSAGE + 1);
    assert!(wallet_verify_message(Network::Test, &over, "p").is_err());
    let proof_max = "p".repeat(MAX_PROOF);
    assert!(wallet_verify_message(Network::Test, "m", &proof_max).is_ok());
    let proof_over = "p".repeat(MAX_PROOF + 1);
    assert!(wallet_verify_message(Network::Test, "m", &proof_over).is_err());
    assert!(wallet_verify_message(Network::Test, "m", "pröof").is_err());
    assert!(wallet_verify_message(Network::Test, "m", "").is_err());
}

#[test]
fn passwordless_spec_without_payload_still_rejects_stdin_encoding() {
    let spec = CommandSpec::new(Program::Wallet, vec!["pull-remote".into()]);
    assert!(spec.stdin().is_err());
}

#[test]
fn backup_default_has_no_directory_flag() {
    let spec = wallet_backup(&wallet(), "backup1", &secret(PASSWORD), &secret(PASSWORD)).unwrap();
    assert!(!spec.args.contains(&"--backup-directory".to_owned()));
}

#[test]
fn backup_explicit_directory_is_added_before_process() {
    let spec = wallet_backup_to(
        &wallet(),
        "backup1",
        &secret(PASSWORD),
        &secret(PASSWORD),
        Some("D:/backups"),
    )
    .unwrap();
    let tail = &spec.args[spec.args.len() - 4..];
    assert_eq!(tail, ["--backup-name", "backup1", "--backup-directory", "D:/backups"]);
}

#[test]
fn backup_empty_directory_is_rejected() {
    let result = wallet_backup_to(
        &wallet(),
        "backup1",
        &secret(PASSWORD),
        &secret(PASSWORD),
        Some(""),
    );
    assert!(result.is_err());
}

#[test]
fn recover_default_has_no_backup_directory_flag() {
    let spec = wallet_recover(
        "C:/wallets",
        "backup1",
        "restored",
        Network::Test,
        "0123456789abcdef0123456789abcdef",
        4,
        &secret(PASSWORD),
        &secret("another password!"),
    )
    .unwrap();
    assert!(!spec.args.contains(&"--backup-directory".to_owned()));
}

#[test]
fn recover_explicit_source_adds_backup_directory_and_rejects_empty() {
    let spec = wallet_recover_from(
        "C:/wallets",
        "backup1",
        "restored",
        Network::Test,
        "0123456789abcdef0123456789abcdef",
        4,
        &secret(PASSWORD),
        &secret("another password!"),
        Some("E:/source"),
    )
    .unwrap();
    let tail = &spec.args[spec.args.len() - 2..];
    assert_eq!(tail, ["--backup-directory", "E:/source"]);
    let empty = wallet_recover_from(
        "C:/wallets",
        "backup1",
        "restored",
        Network::Test,
        "0123456789abcdef0123456789abcdef",
        4,
        &secret(PASSWORD),
        &secret("another password!"),
        Some(""),
    );
    assert!(empty.is_err());
}
