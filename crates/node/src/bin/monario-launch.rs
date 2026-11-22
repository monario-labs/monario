//! Offline launch-ceremony helper: manifest template, pre-flight check and
//! deterministic root record.
//!
//! It emits the recommended consensus parameters and validates a completed
//! manifest or root record. It never creates a root, genesis block, chain
//! database, key or network connection, and it reads no password.
use monario_node::cli::{manifest, root};
use std::{
    env, fs,
    io::Write,
    path::Path,
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(()) => ExitCode::FAILURE,
    }
}

fn run() -> Result<(), ()> {
    let args = env::args_os()
        .skip(1)
        .map(|arg| arg.into_string().map_err(|_| ()))
        .collect::<Result<Vec<_>, _>>()?;
    match args.as_slice() {
        [action] if action == "template" => {
            let text = manifest::template().map_err(|_| ())?;
            write_stdout(&text)?;
            eprintln!(
                "launch template: replace the chain/root placeholders, set root_timestamp from the \
                 ceremony, confirm the difficulty bits, then run `monario-launch check FILE`.\n\
                 This tool never creates a genesis, root, chain database or network."
            );
            Ok(())
        }
        [action] if action == "root-preimage" => {
            let text = root::template().map_err(|_| ())?;
            write_stdout(&text)?;
            eprintln!(
                "root preimage: replace and publish the chain id, timestamp and commitment from \
                 the ceremony, then run `monario-launch root-check ROOT.json` to derive the public \
                 root id.\nThis tool never creates a genesis, root, allocation, chain database or \
                 network."
            );
            Ok(())
        }
        [action, path] if action == "check" => check(path, false),
        [action, path, flag] if action == "check" && flag == "--strict" => check(path, true),
        [action, path] if action == "root-check" => check_root(path, None),
        [action, path, node] if action == "root-check" => check_root(path, Some(node)),
        [action, path] if action == "finality-check" => check_finality(path),
        [action, network, descriptor, node] if action == "bootstrap-check" => {
            let (profile, _) = manifest::profile(&bounded(node, 16_384)?).map_err(|_| ())?;
            let bytes = if descriptor == "--bundled" {
                None
            } else {
                Some(bounded(descriptor, 32_768)?)
            };
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| ())?
                .as_secs();
            let summary =
                monario_node::cli::verify_bootstrap_bundle(network, profile, bytes.as_deref(), now)
                    .map_err(|_| {
                        eprintln!("invalid bootstrap bundle");
                    })?;
            write_stdout(&summary.to_string())
        }
        _ => {
            eprintln!(
                "usage: monario-launch template | check NAME.json [--strict] | root-preimage | \
                 root-check ROOT.json [NAME.json] | finality-check NAME.json | \
                 bootstrap-check mainnet|testnet DESCRIPTOR.json|--bundled NAME.json"
            );
            Err(())
        }
    }
}

fn check(path: &str, strict: bool) -> Result<(), ()> {
    let bytes = bounded(path, 16_384)?;
    let (profile, parsed) = manifest::profile(&bytes).map_err(|_| ())?;
    let mismatches = manifest::recommended_mismatches(&parsed);
    let recommended = mismatches.is_empty();
    if strict && !recommended {
        return Err(());
    }
    let value = serde_json::json!({
        "operation": "manifest-check",
        "consensus_version": monario_chain::consensus::VERSION,
        "profile": hex(&profile),
        "rules_hash": hex(&monario_chain::consensus::rules_hash()),
        "chain_id": hex(&parsed.config.chain_id),
        "root_id": hex(&parsed.root.id),
        "root_timestamp": parsed.root.timestamp,
        "recommended_parameters": recommended,
        "parameter_mismatches": mismatches,
        "height": "0",
        "phase": "pre-genesis",
        "network_started": false,
    });
    let text = serde_json::to_string(&value).map_err(|_| ())?;
    write_stdout(&text)
}

/// Validate a root preimage or completed record. When a manifest path is given,
/// every root field must match exactly; otherwise the command fails closed.
fn check_root(path: &str, node: Option<&str>) -> Result<(), ()> {
    let bytes = bounded(path, root::MAX_BYTES)?;
    let record = root::parse(&bytes).map_err(|_| ())?;
    let mut value = serde_json::json!({
        "operation": "root-check",
        "version": root::VERSION,
        "chain_id": hex(&record.chain_id),
        "root_timestamp": record.root_timestamp,
        "root_commitment": hex(&record.root_commitment),
        "root_id": hex(&record.root_id),
        "root_id_supplied": record.supplied,
        "manifest_checked": false,
        "phase": "pre-genesis",
        "network_started": false,
    });
    if let Some(node) = node {
        let manifest_bytes = bounded(node, 16_384)?;
        let (profile, parsed) = manifest::profile(&manifest_bytes).map_err(|_| ())?;
        if !root::matches_manifest(&record, &parsed) {
            return Err(());
        }
        value["manifest_checked"] = serde_json::Value::Bool(true);
        value["manifest_profile"] = serde_json::Value::String(hex(&profile));
    }
    let text = serde_json::to_string(&value).map_err(|_| ())?;
    write_stdout(&text)
}

/// Verify one finality-pin document offline. This reads no chain, proves no
/// freshness and enforces no policy; the node's `--finality-pin` path still does
/// the chain-bound checks before installing a local policy.
fn check_finality(path: &str) -> Result<(), ()> {
    let bytes = bounded(path, 16_384)?;
    let summary = monario_node::cli::verify_finality_pin(&bytes).map_err(|_| ())?;
    let mode = match summary.mode {
        monario_chain::finality::Mode::Warn => "warn",
        monario_chain::finality::Mode::Refuse => "refuse",
    };
    let value = serde_json::json!({
        "operation": "finality-pin-check",
        "source": if summary.signed { "signed" } else { "operator" },
        "signed": summary.signed,
        "mode": mode,
        "height": summary.pin.height,
        "hash": hex(&summary.pin.hash),
        "signing_digest": hex(&monario_chain::finality::signing_digest(summary.pin)),
        "signers": summary.signers,
        "threshold": summary.threshold,
        "enforced": false,
        "consensus": false,
        "phase": "pre-genesis",
        "network_started": false,
        "note": "Offline local-policy verification only: reads no chain, proves no freshness and enforces no finality.",
    });
    let text = serde_json::to_string(&value).map_err(|_| ())?;
    write_stdout(&text)
}

fn write_stdout(text: &str) -> Result<(), ()> {
    let mut out = std::io::stdout().lock();
    out.write_all(text.as_bytes()).map_err(|_| ())?;
    out.write_all(b"\n").map_err(|_| ())
}

/// Read a bounded regular file; reject symlinks and oversized inputs.
fn bounded(path: &str, limit: usize) -> Result<Vec<u8>, ()> {
    let path = Path::new(path);
    let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    if !metadata.file_type().is_file() || metadata.len() > limit as u64 {
        return Err(());
    }
    fs::read(path).map_err(|_| ())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}
