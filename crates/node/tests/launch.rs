//! Launch-ceremony helper stays offline and fails closed on placeholders.
use monario_node::cli::manifest::{
    PLACEHOLDER_CHAIN_ID, PLACEHOLDER_ROOT_COMMITMENT, PLACEHOLDER_ROOT_ID,
};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

/// Locate the sibling release/debug binary at runtime. Using `CARGO_BIN_EXE_*`
/// would embed an absolute build path in this test executable, which release
/// scanning must reject.
fn binary() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    if path.file_name().is_some_and(|name| name == "deps") {
        path.pop();
    }
    path.push(if cfg!(windows) {
        "monario-launch.exe"
    } else {
        "monario-launch"
    });
    path
}

fn run(exe: &Path, args: &[&str]) -> std::process::Output {
    Command::new(exe).args(args).output().unwrap()
}

#[test]
fn template_and_check_are_offline_and_fail_closed() {
    let exe = binary();
    assert!(exe.is_file(), "missing {}", exe.display());
    let template = run(&exe, &["template"]);
    assert!(template.status.success());
    let text = String::from_utf8(template.stdout).unwrap();
    assert!(text.contains(PLACEHOLDER_CHAIN_ID));
    assert!(text.contains("\"version\": 1"));

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.json");
    fs::write(&path, &text).unwrap();
    // Unedited placeholders must never validate.
    let rejected = run(&exe, &["check", path.to_str().unwrap()]);
    assert!(!rejected.status.success());

    let filled = text
        .replace(PLACEHOLDER_CHAIN_ID, &"11".repeat(32))
        .replace(PLACEHOLDER_ROOT_ID, &"22".repeat(32))
        .replace(PLACEHOLDER_ROOT_COMMITMENT, &"33".repeat(32));
    fs::write(&path, &filled).unwrap();
    let accepted = run(&exe, &["check", path.to_str().unwrap()]);
    assert!(accepted.status.success());
    let value: serde_json::Value = serde_json::from_slice(&accepted.stdout).unwrap();
    assert_eq!(value["network_started"], false);
    assert_eq!(
        value["consensus_version"].as_u64(),
        Some(u64::from(monario_chain::consensus::VERSION))
    );
    assert_eq!(value["phase"], "pre-genesis");
    assert_eq!(value["profile"].as_str().unwrap().len(), 64);
    assert_eq!(value["rules_hash"].as_str().unwrap().len(), 64);
    assert_eq!(value["recommended_parameters"], true);

    // A non-recommended value is reported, and `--strict` fails closed.
    let mut altered: serde_json::Value = serde_json::from_str(&filled).unwrap();
    altered["half_life_seconds"] = serde_json::json!(21_601);
    fs::write(&path, serde_json::to_string_pretty(&altered).unwrap()).unwrap();
    let warned = run(&exe, &["check", path.to_str().unwrap()]);
    assert!(warned.status.success());
    let value: serde_json::Value = serde_json::from_slice(&warned.stdout).unwrap();
    assert_eq!(value["recommended_parameters"], false);
    assert_eq!(value["parameter_mismatches"][0], "half_life_seconds");
    assert!(
        !run(&exe, &["check", path.to_str().unwrap(), "--strict"])
            .status
            .success()
    );
}

#[test]
fn root_preimage_derives_and_cross_checks_the_manifest() {
    let exe = binary();
    let chain = "11".repeat(32);
    let commitment = "33".repeat(32);
    let timestamp = 1_700_000_000u64;

    let preimage = run(&exe, &["root-preimage"]);
    assert!(preimage.status.success());
    let text = String::from_utf8(preimage.stdout).unwrap();
    assert!(text.contains(PLACEHOLDER_CHAIN_ID));
    let filled = text
        .replace(PLACEHOLDER_CHAIN_ID, &chain)
        .replace(PLACEHOLDER_ROOT_COMMITMENT, &commitment)
        .replace(
            "\"root_timestamp\": 0",
            &format!("\"root_timestamp\": {timestamp}"),
        );

    let dir = tempfile::tempdir().unwrap();
    let root_path = dir.path().join("root.json");
    fs::write(&root_path, &filled).unwrap();
    let checked = run(&exe, &["root-check", root_path.to_str().unwrap()]);
    assert!(checked.status.success());
    let value: serde_json::Value = serde_json::from_slice(&checked.stdout).unwrap();
    assert_eq!(value["network_started"], false);
    assert_eq!(value["phase"], "pre-genesis");
    assert_eq!(value["root_id_supplied"], false);
    assert_eq!(value["manifest_checked"], false);
    assert_eq!(value["chain_id"], chain);
    assert_eq!(value["root_timestamp"].as_u64(), Some(timestamp));
    let root_id = value["root_id"].as_str().unwrap().to_owned();
    assert_eq!(root_id.len(), 64);
    assert_ne!(root_id, commitment);

    // The manifest must carry exactly the derived root fields.
    let manifest = run(&exe, &["template"]);
    assert!(manifest.status.success());
    let node_text = String::from_utf8(manifest.stdout)
        .unwrap()
        .replace(PLACEHOLDER_CHAIN_ID, &chain)
        .replace(PLACEHOLDER_ROOT_ID, &root_id)
        .replace(PLACEHOLDER_ROOT_COMMITMENT, &commitment)
        .replace(
            "\"root_timestamp\": 0",
            &format!("\"root_timestamp\": {timestamp}"),
        );
    let node_path = dir.path().join("node.json");
    fs::write(&node_path, &node_text).unwrap();
    let cross = run(
        &exe,
        &[
            "root-check",
            root_path.to_str().unwrap(),
            node_path.to_str().unwrap(),
        ],
    );
    assert!(cross.status.success());
    let value: serde_json::Value = serde_json::from_slice(&cross.stdout).unwrap();
    assert_eq!(value["manifest_checked"], true);
    assert_eq!(value["manifest_profile"].as_str().unwrap().len(), 64);

    // A supplied identifier that does not match the preimage fails closed.
    let wrong = filled.replace(
        "}",
        &format!(",\n  \"root_id\": \"{}\"\n}}", "00".repeat(32)),
    );
    fs::write(&root_path, wrong).unwrap();
    assert!(
        !run(&exe, &["root-check", root_path.to_str().unwrap()])
            .status
            .success()
    );

    // A manifest with a different root id is rejected by the cross-check.
    fs::write(&root_path, &filled).unwrap();
    let wrong_node = node_text.replace(&root_id, &"44".repeat(32));
    fs::write(&node_path, wrong_node).unwrap();
    assert!(
        !run(
            &exe,
            &[
                "root-check",
                root_path.to_str().unwrap(),
                node_path.to_str().unwrap(),
            ],
        )
        .status
        .success()
    );

    // Oversized and missing root records fail before parsing.
    let big = dir.path().join("big-root.json");
    fs::write(&big, vec![b' '; 1_025]).unwrap();
    assert!(
        !run(&exe, &["root-check", big.to_str().unwrap()])
            .status
            .success()
    );
    assert!(
        !run(&exe, &["root-check", "definitely-missing-root.json"])
            .status
            .success()
    );
}

#[test]
fn finality_pin_check_is_offline_and_fails_closed() {
    let exe = binary();
    let dir = tempfile::tempdir().unwrap();
    let hash = "11".repeat(32);
    let path = dir.path().join("finality.json");
    let pin = format!(r#"{{"source":"operator","height":123,"hash":"{hash}","mode":"warn"}}"#);
    fs::write(&path, &pin).unwrap();
    let checked = run(&exe, &["finality-check", path.to_str().unwrap()]);
    assert!(checked.status.success());
    let value: serde_json::Value = serde_json::from_slice(&checked.stdout).unwrap();
    assert_eq!(value["operation"], "finality-pin-check");
    assert_eq!(value["source"], "operator");
    assert_eq!(value["signed"], false);
    assert_eq!(value["mode"], "warn");
    assert_eq!(value["height"].as_u64(), Some(123));
    assert_eq!(value["hash"].as_str(), Some(hash.as_str()));
    assert_eq!(value["signing_digest"].as_str().unwrap().len(), 64);
    assert_eq!(value["enforced"], false);
    assert_eq!(value["consensus"], false);
    assert_eq!(value["network_started"], false);

    let unknown =
        format!(r#"{{"source":"operator","height":123,"hash":"{hash}","mode":"warn","extra":1}}"#);
    fs::write(&path, unknown).unwrap();
    assert!(
        !run(&exe, &["finality-check", path.to_str().unwrap()])
            .status
            .success()
    );

    let signed = format!(
        r#"{{"source":"signed","height":123,"hash":"{hash}","mode":"refuse","signers":[],"threshold":1,"signatures":[]}}"#
    );
    fs::write(&path, signed).unwrap();
    assert!(
        !run(&exe, &["finality-check", path.to_str().unwrap()])
            .status
            .success()
    );
    assert!(
        !run(&exe, &["finality-check", "missing-finality.json"])
            .status
            .success()
    );
}

#[test]
fn check_rejects_missing_oversized_and_non_regular_inputs() {
    let exe = binary();
    assert!(
        !run(&exe, &["check", "definitely-missing.json"])
            .status
            .success()
    );
    let dir = tempfile::tempdir().unwrap();
    let big = dir.path().join("big.json");
    fs::write(&big, vec![b' '; 16_385]).unwrap();
    assert!(
        !run(&exe, &["check", big.to_str().unwrap()])
            .status
            .success()
    );
    assert!(!run(&exe, &[]).status.success());
    assert!(!run(&exe, &["unknown"]).status.success());
}
