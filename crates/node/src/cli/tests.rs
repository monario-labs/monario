use super::*;
use crate::{tests::private_tempdir, transport::Identity};
use monario_chain::{Config, Root};
use std::{io::Cursor, process::Command as Process};

mod archive_audit;
mod blocks;
mod checkpoints;
mod prune;
mod signals;
mod transaction_get;

const OLD: &[u8] = b"public cli password only";
const NEW: &[u8] = b"public new cli password only";
fn frame(bytes: &[u8]) -> Vec<u8> {
    let mut v = (bytes.len() as u16).to_le_bytes().to_vec();
    v.extend(bytes);
    v
}
fn parse(args: Vec<String>) -> Command {
    Command::parse(args.into_iter().map(OsString::from)).unwrap()
}
fn args(action: &str, root: &Path, cp: Checkpoint) -> Vec<String> {
    let mut v = vec![
        action.into(),
        "--directory".into(),
        root.to_str().unwrap().into(),
        "--profile".into(),
        hex(&cp.profile),
        "--password-stdin".into(),
    ];
    if action != "identity-create" {
        v.extend([
            "--public-key".into(),
            hex(&cp.public_key),
            "--revision".into(),
            cp.revision.to_string(),
        ]);
    }
    if matches!(action, "identity-create" | "peers-set") {
        v.extend(["--peers".into(), "peers.json".into()]);
    }
    if matches!(action, "chain-init" | "check" | "run") {
        v.extend(["--manifest".into(), "node.json".into()]);
    }
    if action == "chain-init" {
        v.extend(["--root-ceremony".into(), "root.json".into()]);
    }
    if action == "run" {
        v.push("--enable-network".into());
    }
    v
}
fn cp(output: &[u8]) -> Checkpoint {
    let v: serde_json::Value = serde_json::from_slice(output).unwrap();
    Checkpoint {
        profile: hash(v["profile"].as_str().unwrap()).unwrap(),
        public_key: hash(v["public_key"].as_str().unwrap()).unwrap(),
        revision: v["revision"].as_u64().unwrap(),
    }
}
fn invoke(
    action: &str,
    root: &Path,
    checkpoint: Checkpoint,
    input: Vec<u8>,
) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    execute(
        parse(args(action, root, checkpoint)),
        &mut Cursor::new(input),
        &mut output,
        &Arc::new(AtomicBool::new(true)),
    )?;
    Ok(output)
}
fn fixture() -> (tempfile::TempDir, Checkpoint) {
    let dir = private_tempdir();
    let cp = Checkpoint {
        profile: [2; 32],
        public_key: [0; 32],
        revision: 0,
    };
    fs::write(
        dir.path().join("peers.json"),
        TrustedPeers::empty(cp.profile).document().unwrap(),
    )
    .unwrap();
    (dir, cp)
}
fn changed_peers(profile: [u8; 32]) -> Vec<u8> {
    let peer = Identity::from_secret(Zeroizing::new([11; 32])).public_key();
    serde_json::to_vec(&serde_json::json!({"version":1,"profile":hex(&profile),"listen":"off","peers":[{"address":"127.0.0.1:12345","public_key":hex(&peer)}]})).unwrap()
}
fn chain_fixture(root: &Path) -> Checkpoint {
    let mut config: Config = crate::tests::config();
    config.coinbase_maturity = monario_chain::consensus::COINBASE_MATURITY;
    config.limits.block_bytes = 5_000_000;
    let origin = Root {
        id: [3; 32],
        timestamp: 1000,
        commitment: [4; 32],
    };
    // Test-only pre-provisioned empty metadata, never a genesis block or nonce search.
    let chain = DurableChain::open(
        &root.join("chain.sqlite"),
        config.clone(),
        origin,
        V6Verifier,
        1_000_000,
    )
    .unwrap();
    let profile = chain.chain().unwrap().validation_profile();
    chain.checkpoint().unwrap();
    drop(chain);
    let doc = serde_json::json!({"version":1,"chain_file":"chain.sqlite","chain_id":hex(&config.chain_id),"root_id":hex(&origin.id),"root_timestamp":origin.timestamp,"root_commitment":hex(&origin.commitment),"initial_bits":config.initial_bits,"pow_limit_bits":config.pow_limit_bits,"half_life_seconds":config.half_life_seconds,"seed_interval":config.seed_interval,"seed_lag":config.seed_lag,"max_future_seconds":config.max_future_seconds,"retained_blocks":config.retained_blocks,"transaction_bytes":config.limits.transaction_bytes,"transactions":config.limits.transactions,"inputs_per_transaction":config.limits.inputs_per_transaction,"outputs_per_transaction":config.limits.outputs_per_transaction,"script_bytes":config.limits.script_bytes});
    fs::write(root.join("node.json"), serde_json::to_vec(&doc).unwrap()).unwrap();
    fs::write(
        root.join("peers.json"),
        TrustedPeers::empty(profile).document().unwrap(),
    )
    .unwrap();
    let initial = Checkpoint {
        profile,
        public_key: [0; 32],
        revision: 0,
    };
    cp(&invoke("identity-create", root, initial, frame(OLD)).unwrap())
}

#[test]
fn arguments_fail_closed_without_secret_echo_or_implicit_network() {
    let (dir, cp) = fixture();
    for action in [
        "identity-create",
        "identity-info",
        "peers-set",
        "password-change",
        "chain-init",
        "check",
        "run",
    ] {
        assert!(
            Command::parse(args(action, dir.path(), cp).into_iter().map(OsString::from)).is_ok()
        );
    }
    let mut run = args("run", dir.path(), cp);
    run.pop();
    assert!(Command::parse(run.into_iter().map(OsString::from)).is_err());
    for tail in [
        vec!["--password", "secret"],
        vec!["--enable-network"],
        vec!["--directory", "other"],
        vec!["unexpected"],
    ] {
        let mut v = args("identity-create", dir.path(), cp);
        v.extend(tail.into_iter().map(str::to_owned));
        assert!(Command::parse(v.into_iter().map(OsString::from)).is_err());
    }
    for invalid in [
        "../escape",
        "a/b",
        "a\\b",
        "CON.json",
        "COM1",
        "name.",
        "..",
        "a:b",
        "a b",
    ] {
        assert!(name(invalid).is_err());
    }
    for invalid in ["+1", "-1", "18446744073709551616"] {
        let mut v = args("identity-info", dir.path(), cp);
        *v.last_mut().unwrap() = invalid.into();
        assert!(Command::parse(v.into_iter().map(OsString::from)).is_err());
    }
    let mut output = Vec::new();
    execute(
        parse(vec!["--help".into()]),
        &mut Cursor::new(Vec::new()),
        &mut output,
        &Arc::new(AtomicBool::new(true)),
    )
    .unwrap();
    assert!(
        std::str::from_utf8(&output)
            .unwrap()
            .contains("--enable-network")
    );
    assert!(
        std::str::from_utf8(&output)
            .unwrap()
            .contains("--enable-mining")
    );
}

#[test]
fn mining_is_explicit_bounded_and_never_implies_network_activation() {
    let (dir, cp) = fixture();
    let mut mine = args("check", dir.path(), cp);
    mine[0] = "mine".into();
    mine.extend(
        [
            "--enable-mining",
            "--miner-address",
            "rmont1fixture",
            "--miner-workers",
            "2",
            "--miner-network",
            "regtest",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    let command = parse(mine.clone());
    assert!(command.is_mine());
    assert!(command.is_run());
    assert!(!command.network);
    let mining = command.mining.as_ref().unwrap();
    assert_eq!(mining.workers, 2);
    assert_eq!(mining.network, monario_address::Network::Regtest);

    let mut with_network = mine.clone();
    with_network.push("--enable-network".into());
    assert!(parse(with_network).network);

    let mut without_activation = mine.clone();
    let index = without_activation
        .iter()
        .position(|arg| arg == "--enable-mining")
        .unwrap();
    without_activation.remove(index);
    assert!(Command::parse(without_activation.into_iter().map(OsString::from)).is_err());

    for workers in ["0", "129", "18446744073709551616"] {
        let mut invalid = mine.clone();
        let index = invalid
            .iter()
            .position(|arg| arg == "--miner-workers")
            .unwrap()
            + 1;
        invalid[index] = workers.into();
        assert!(Command::parse(invalid.into_iter().map(OsString::from)).is_err());
    }
    let mut automatic = mine.clone();
    let index = automatic
        .iter()
        .position(|arg| arg == "--miner-workers")
        .unwrap()
        + 1;
    automatic[index] = "auto".into();
    match Command::parse(automatic.into_iter().map(OsString::from)) {
        Ok(command) => {
            let workers = command.mining.as_ref().unwrap().workers;
            assert!((1..=monario_randomx::MAX_WORKERS).contains(&workers));
        }
        Err(Error::MiningCapacity) => {}
        Err(error) => panic!("unexpected error parsing --miner-workers auto: {error:?}"),
    }
    let mut shared_maximum = mine.clone();
    let index = shared_maximum
        .iter()
        .position(|arg| arg == "--miner-workers")
        .unwrap()
        + 1;
    shared_maximum[index] = monario_randomx::MAX_WORKERS.to_string();
    assert_eq!(
        parse(shared_maximum).mining.as_ref().unwrap().workers,
        monario_randomx::MAX_WORKERS
    );
    for network in ["mainnet", "testnet", "Regtest", ""] {
        let mut invalid = mine.clone();
        let index = invalid
            .iter()
            .position(|arg| arg == "--miner-network")
            .unwrap()
            + 1;
        invalid[index] = network.into();
        assert!(Command::parse(invalid.into_iter().map(OsString::from)).is_err());
    }
    let mut wrong_action = args("check", dir.path(), cp);
    wrong_action.push("--enable-mining".into());
    assert!(Command::parse(wrong_action.into_iter().map(OsString::from)).is_err());

    let mut with_status = mine.clone();
    with_status.extend(["--status-file", "gui.json"].into_iter().map(str::to_owned));
    assert_eq!(
        Command::parse(with_status.into_iter().map(OsString::from))
            .unwrap()
            .status_file
            .as_deref(),
        Some("gui.json")
    );
    let mut bad_status = mine.clone();
    bad_status.extend(["--status-file", "gui.txt"].into_iter().map(str::to_owned));
    assert!(Command::parse(bad_status.into_iter().map(OsString::from)).is_err());
    let mut check_status = args("check", dir.path(), cp);
    check_status.extend(["--status-file", "gui.json"].into_iter().map(str::to_owned));
    assert!(Command::parse(check_status.into_iter().map(OsString::from)).is_err());

    let mut with_stop = mine.clone();
    with_stop.extend(["--stop-file", "gui.stop"].into_iter().map(str::to_owned));
    assert_eq!(
        Command::parse(with_stop.into_iter().map(OsString::from))
            .unwrap()
            .stop_file
            .as_deref(),
        Some("gui.stop")
    );
    let mut bad_stop = mine.clone();
    bad_stop.extend(["--stop-file", "gui.json"].into_iter().map(str::to_owned));
    assert!(Command::parse(bad_stop.into_iter().map(OsString::from)).is_err());
    let mut check_stop = args("check", dir.path(), cp);
    check_stop.extend(["--stop-file", "gui.stop"].into_iter().map(str::to_owned));
    assert!(Command::parse(check_stop.into_iter().map(OsString::from)).is_err());

    let mut with_rpc = mine.clone();
    with_rpc.extend(
        [
            "--enable-rpc",
            "--rpc-bind",
            "127.0.0.1:9000",
            "--rpc-token-file",
            "gui.token",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    let rpc = Command::parse(with_rpc.into_iter().map(OsString::from))
        .unwrap()
        .rpc
        .unwrap();
    assert_eq!(rpc.bind, "127.0.0.1:9000".parse().unwrap());
    assert_eq!(rpc.token_file, "gui.token");
    assert!(!rpc.allow_remote);

    for missing in ["--rpc-bind", "--rpc-token-file"] {
        let mut invalid = mine.clone();
        invalid.push("--enable-rpc".into());
        if missing == "--rpc-token-file" {
            invalid.extend(["--rpc-bind".into(), "127.0.0.1:9000".into()]);
        }
        assert!(Command::parse(invalid.into_iter().map(OsString::from)).is_err());
    }
    let mut orphan_bind = mine.clone();
    orphan_bind.extend(["--rpc-bind".into(), "127.0.0.1:9000".into()]);
    assert!(Command::parse(orphan_bind.into_iter().map(OsString::from)).is_err());
    let mut bad_bind = mine.clone();
    bad_bind.extend(
        [
            "--enable-rpc",
            "--rpc-bind",
            "not-an-address",
            "--rpc-token-file",
            "gui.token",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    assert!(Command::parse(bad_bind.into_iter().map(OsString::from)).is_err());
    let mut bad_token = mine.clone();
    bad_token.extend(
        [
            "--enable-rpc",
            "--rpc-bind",
            "127.0.0.1:9000",
            "--rpc-token-file",
            "gui.json",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    assert!(Command::parse(bad_token.into_iter().map(OsString::from)).is_err());
    let mut check_rpc = args("check", dir.path(), cp);
    check_rpc.extend(
        [
            "--enable-rpc",
            "--rpc-bind",
            "127.0.0.1:9000",
            "--rpc-token-file",
            "gui.token",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    assert!(Command::parse(check_rpc.into_iter().map(OsString::from)).is_err());
}

#[test]
fn scan_server_is_explicit_and_bound_to_runtime() {
    let (dir, cp) = fixture();
    let mut base = args("check", dir.path(), cp);
    base[0] = "mine".into();
    base.extend(
        [
            "--enable-mining",
            "--miner-address",
            "rmont1fixture",
            "--miner-workers",
            "1",
            "--miner-network",
            "regtest",
        ]
        .into_iter()
        .map(str::to_owned),
    );

    let mut with_scan = base.clone();
    with_scan.extend(
        [
            "--enable-scan",
            "--scan-bind",
            "127.0.0.1:19445",
            "--scan-token-file",
            "scan.token",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    let scan = Command::parse(with_scan.into_iter().map(OsString::from))
        .unwrap()
        .scan
        .unwrap();
    assert_eq!(scan.bind, "127.0.0.1:19445".parse().unwrap());
    assert_eq!(scan.token_file, "scan.token");
    assert!(!scan.allow_remote);

    for missing in ["--scan-bind", "--scan-token-file"] {
        let mut invalid = base.clone();
        invalid.push("--enable-scan".into());
        if missing == "--scan-token-file" {
            invalid.extend(["--scan-bind".into(), "127.0.0.1:19445".into()]);
        }
        assert!(Command::parse(invalid.into_iter().map(OsString::from)).is_err());
    }
    let mut orphan_bind = base.clone();
    orphan_bind.extend(["--scan-bind".into(), "127.0.0.1:19445".into()]);
    assert!(Command::parse(orphan_bind.into_iter().map(OsString::from)).is_err());
    let mut bad_token = base.clone();
    bad_token.extend(
        [
            "--enable-scan",
            "--scan-bind",
            "127.0.0.1:19445",
            "--scan-token-file",
            "scan.json",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    assert!(Command::parse(bad_token.into_iter().map(OsString::from)).is_err());
    let mut check_scan = args("check", dir.path(), cp);
    check_scan.extend(
        [
            "--enable-scan",
            "--scan-bind",
            "127.0.0.1:19445",
            "--scan-token-file",
            "scan.token",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    assert!(Command::parse(check_scan.into_iter().map(OsString::from)).is_err());
}

#[test]
fn pool_mode_is_explicit_bounded_and_has_no_silent_fallback() {
    let (dir, cp) = fixture();
    let mut base = args("check", dir.path(), cp);
    base[0] = "mine".into();
    base.extend(
        [
            "--enable-mining",
            "--miner-address",
            "rmont1fixture",
            "--miner-workers",
            "2",
            "--miner-network",
            "regtest",
        ]
        .into_iter()
        .map(str::to_owned),
    );

    let key = "11".repeat(32);
    let client = "22".repeat(16);

    // Official mode needs credentials but no address; the published host is used.
    let mut official = base.clone();
    official.extend(
        [
            "--pool-mode",
            "official",
            "--pool-public-key",
            &key,
            "--pool-client",
            &client,
            "--pool-token-file",
            "pool.token",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    let command = parse(official.clone());
    let pool = command.mining.as_ref().unwrap().pool.as_ref().unwrap();
    assert_eq!(pool.address, OFFICIAL_POOL_ADDRESS);
    assert_eq!(pool.client, [0x22; 16]);

    // Any missing credential is rejected, never degraded to solo.
    for missing in ["--pool-public-key", "--pool-client", "--pool-token-file"] {
        let mut invalid = official.clone();
        let index = invalid.iter().position(|a| a == missing).unwrap();
        invalid.drain(index..index + 2);
        assert!(Command::parse(invalid.into_iter().map(OsString::from)).is_err());
    }
    // Official mode never accepts an address override.
    let mut override_address = official.clone();
    override_address.extend(
        ["--pool-address", "127.0.0.1:1234"]
            .into_iter()
            .map(str::to_owned),
    );
    assert!(Command::parse(override_address.into_iter().map(OsString::from)).is_err());

    // Custom requires a bounded HOST:PORT.
    let mut custom = base.clone();
    custom.extend(
        [
            "--pool-mode",
            "custom",
            "--pool-address",
            "127.0.0.1:1234",
            "--pool-public-key",
            &key,
            "--pool-client",
            &client,
            "--pool-token-file",
            "pool.token",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    assert!(
        parse(custom.clone())
            .mining
            .as_ref()
            .unwrap()
            .pool
            .is_some()
    );
    for address in [
        "127.0.0.1:0",
        "127.0.0.1",
        "bad host:1234",
        ":1234",
        "127.0.0.1:70000",
    ] {
        let mut invalid = custom.clone();
        let index = invalid.iter().position(|a| a == "--pool-address").unwrap() + 1;
        invalid[index] = address.into();
        assert!(Command::parse(invalid.into_iter().map(OsString::from)).is_err());
    }

    // Solo must not smuggle pool credentials.
    let mut solo = base.clone();
    solo.extend(
        ["--pool-mode", "solo", "--pool-client", &client]
            .into_iter()
            .map(str::to_owned),
    );
    assert!(Command::parse(solo.into_iter().map(OsString::from)).is_err());

    // Bounded credential encodings.
    for (flag, value) in [
        ("--pool-client", "22".repeat(15)),
        ("--pool-client", "22".repeat(17)),
        ("--pool-client", "ZZ".repeat(16)),
        ("--pool-public-key", "11".repeat(31)),
        ("--pool-public-key", "AA".repeat(32)),
        ("--pool-token-file", "pool.json".to_owned()),
    ] {
        let mut invalid = custom.clone();
        let index = invalid.iter().position(|a| a == flag).unwrap() + 1;
        invalid[index] = value;
        assert!(Command::parse(invalid.into_iter().map(OsString::from)).is_err());
    }
}

#[test]
fn finality_pin_is_explicit_and_only_for_runtime_activation() {
    let (dir, cp) = fixture();
    let mut base = args("check", dir.path(), cp);
    base[0] = "mine".into();
    base.extend(
        [
            "--enable-mining",
            "--miner-address",
            "rmont1fixture",
            "--miner-workers",
            "1",
            "--miner-network",
            "regtest",
        ]
        .into_iter()
        .map(str::to_owned),
    );

    let mut with_pin = base.clone();
    with_pin.extend(
        ["--finality-pin", "finality.json"]
            .into_iter()
            .map(str::to_owned),
    );
    let command = parse(with_pin.clone());
    assert_eq!(command.finality_pin.as_deref(), Some("finality.json"));
    assert!(!command.no_anchor);

    let mut with_bypass = base.clone();
    with_bypass.push("--no-checkpoint-anchor".into());
    assert!(parse(with_bypass).no_anchor);

    // Only a bounded .json pin name is accepted.
    let mut bad_name = base.clone();
    bad_name.extend(
        ["--finality-pin", "finality.txt"]
            .into_iter()
            .map(str::to_owned),
    );
    assert!(Command::parse(bad_name.into_iter().map(OsString::from)).is_err());

    // Flags are not accepted by non-runtime commands.
    let mut check = args("check", dir.path(), cp);
    check.extend(
        ["--finality-pin", "finality.json"]
            .into_iter()
            .map(str::to_owned),
    );
    assert!(Command::parse(check.into_iter().map(OsString::from)).is_err());
    let mut check_bypass = args("check", dir.path(), cp);
    check_bypass.push("--no-checkpoint-anchor".into());
    assert!(Command::parse(check_bypass.into_iter().map(OsString::from)).is_err());
}

#[test]
fn finality_policy_loader_fails_closed() {
    let dir = private_tempdir();
    let root = dir.path();
    let hash = "11".repeat(32);
    let pin = format!(r#"{{"source":"operator","height":123,"hash":"{hash}","mode":"warn"}}"#);
    std::fs::write(root.join("pin.json"), pin.as_bytes()).unwrap();
    let policy = finality_policy(root, Some("pin.json"), false)
        .unwrap()
        .unwrap();
    assert_eq!(policy.pin.unwrap().height, 123);
    assert_eq!(policy.mode, monario_chain::finality::Mode::Warn);
    assert!(!policy.anchor_bypass);

    let summary = verify_finality_pin(pin.as_bytes()).unwrap();
    assert_eq!(summary.pin.height, 123);
    assert_eq!(summary.mode, monario_chain::finality::Mode::Warn);
    assert!(!summary.signed);
    assert_eq!(summary.signers, 0);
    assert_eq!(summary.threshold, 0);

    // Explicit anchor bypass needs no pin file.
    let bypass = finality_policy(root, None, true).unwrap().unwrap();
    assert!(bypass.anchor_bypass && bypass.pin.is_none());
    assert!(finality_policy(root, None, false).unwrap().is_none());

    for (name, body) in [
        (
            "zero.json",
            r#"{"source":"operator","height":0,"hash":"1111111111111111111111111111111111111111111111111111111111111111","mode":"warn"}"#.to_owned(),
        ),
        (
            "short.json",
            r#"{"source":"operator","height":1,"hash":"11","mode":"warn"}"#.to_owned(),
        ),
        (
            "mode.json",
            format!(r#"{{"source":"operator","height":1,"hash":"{hash}","mode":"halt"}}"#),
        ),
        (
            "source.json",
            format!(r#"{{"source":"unknown","height":1,"hash":"{hash}","mode":"warn"}}"#),
        ),
        (
            "signed.json",
            format!(
                r#"{{"source":"signed","height":1,"hash":"{hash}","mode":"refuse","signers":[],"threshold":1,"signatures":[]}}"#
            ),
        ),
        (
            "extra.json",
            format!(
                r#"{{"source":"operator","height":1,"hash":"{hash}","mode":"warn","extra":1}}"#
            ),
        ),
    ] {
        std::fs::write(root.join(name), body.as_bytes()).unwrap();
        assert!(
            finality_policy(root, Some(name), false).is_err(),
            "{name} must fail closed"
        );
        assert!(
            verify_finality_pin(body.as_bytes()).is_err(),
            "{name} must fail closed offline"
        );
    }
    assert!(verify_finality_pin(&[]).is_err());
    assert!(verify_finality_pin(&vec![b' '; 16 * 1024 + 1]).is_err());
}

#[test]
fn stop_file_is_bounded_and_only_regular_files_request_shutdown() {
    let (dir, _) = fixture();
    let stop = AtomicBool::new(false);
    let mut control = StopControl::new(dir.path(), "gui.stop").unwrap();
    control.check(&stop, 0);
    assert!(!stop.load(Ordering::Acquire));
    // A directory with the marker name must not trigger a stop.
    std::fs::create_dir(dir.path().join("gui.stop")).unwrap();
    control.check(&stop, 250);
    assert!(!stop.load(Ordering::Acquire));
    std::fs::remove_dir(dir.path().join("gui.stop")).unwrap();
    std::fs::write(dir.path().join("gui.stop"), b"").unwrap();
    control.check(&stop, 500);
    assert!(stop.load(Ordering::Acquire));

    assert!(StopControl::new(dir.path(), "gui.json").is_err());
    assert!(StopControl::new(dir.path(), "../gui.stop").is_err());
}

#[test]
fn bounded_credentials_and_files_reject_before_any_creation() {
    let (dir, cp) = fixture();
    for bad in [
        vec![],
        vec![1],
        frame(b"short"),
        {
            let mut b = frame(OLD);
            b.pop();
            b
        },
        {
            let mut b = frame(OLD);
            b.push(0);
            b
        },
        1025u16.to_le_bytes().to_vec(),
    ] {
        assert!(invoke("identity-create", dir.path(), cp, bad).is_err());
        assert!(!dir.path().join("node.monp").exists());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o750)).unwrap();
        let mut input = Cursor::new(frame(OLD));
        assert_eq!(
            execute(
                parse(args("identity-create", dir.path(), cp)),
                &mut input,
                &mut Vec::new(),
                &Arc::new(AtomicBool::new(true))
            ),
            Err(Error::Configuration)
        );
        assert_eq!(input.position(), 0);
        assert!(!dir.path().join("node.monp").exists());
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(dir.path().join("peers.json"), vec![b' '; 6145]).unwrap();
    assert_eq!(
        invoke("identity-create", dir.path(), cp, frame(OLD)),
        Err(Error::Configuration)
    );
    assert!(!dir.path().join("node.monp").exists());
    #[cfg(unix)]
    {
        fs::remove_file(dir.path().join("peers.json")).unwrap();
        std::os::unix::fs::symlink("missing", dir.path().join("peers.json")).unwrap();
        assert!(invoke("identity-create", dir.path(), cp, frame(OLD)).is_err());
    }
}
#[test]
fn offline_identity_administration_preserves_keys_and_authenticates_pins() {
    let (dir, initial) = fixture();
    let first = cp(&invoke("identity-create", dir.path(), initial, frame(OLD)).unwrap());
    assert_ne!(first.public_key, [0; 32]);
    assert!(invoke("identity-create", dir.path(), initial, frame(OLD)).is_err());
    assert_eq!(
        cp(&invoke("identity-info", dir.path(), first, frame(OLD)).unwrap()),
        first
    );
    assert_eq!(
        invoke("identity-info", dir.path(), first, frame(NEW)),
        Err(Error::Credentials)
    );
    fs::write(dir.path().join("peers.json"), changed_peers(first.profile)).unwrap();
    let second = cp(&invoke("peers-set", dir.path(), first, frame(OLD)).unwrap());
    assert_eq!(
        second,
        Checkpoint {
            revision: 1,
            ..first
        }
    );
    let directory = IdentityDirectory::open(dir.path()).unwrap();
    let store = IdentityStore::open(
        &directory,
        "node",
        &Password::from_bytes(OLD).unwrap(),
        second,
    )
    .unwrap();
    assert_eq!(store.configuration().unwrap().peers().len(), 1);
    drop(store);
    let mut both = frame(OLD);
    both.extend(frame(NEW));
    let third = cp(&invoke("password-change", dir.path(), second, both).unwrap());
    assert_eq!(
        third,
        Checkpoint {
            revision: 2,
            ..first
        }
    );
    assert!(invoke("identity-info", dir.path(), third, frame(OLD)).is_err());
    assert_eq!(
        cp(&invoke("identity-info", dir.path(), third, frame(NEW)).unwrap()),
        third
    );
    let bytes = fs::read(dir.path().join("node.monp")).unwrap();
    for secret in [OLD, NEW] {
        assert!(!bytes.windows(secret.len()).any(|w| w == secret));
    }
}
#[test]
fn manifest_schema_profile_and_existing_chain_requirements_are_enforced() {
    let dir = private_tempdir();
    let cp = chain_fixture(dir.path());
    let original = fs::read(dir.path().join("node.json")).unwrap();
    let base: serde_json::Value = serde_json::from_slice(&original).unwrap();
    for (field, value) in [
        ("version", 2.into()),
        ("retained_blocks", 0.into()),
        ("chain_file", "../escape".into()),
        ("chain_id", hex(&[8; 32]).into()),
        ("extra", true.into()),
        ("transaction_bytes", 0.into()),
        ("coinbase_maturity", 2.into()),
    ] {
        let mut bad = base.clone();
        bad[field] = value;
        assert!(manifest::parse(&serde_json::to_vec(&bad).unwrap(), cp.profile).is_err());
    }
    fs::remove_file(dir.path().join("chain.sqlite")).unwrap();
    assert!(invoke("check", dir.path(), cp, frame(OLD)).is_err());
    assert!(!dir.path().join("chain.sqlite").exists());
    fs::write(dir.path().join("chain.sqlite"), []).unwrap();
    assert!(invoke("check", dir.path(), cp, frame(OLD)).is_err());
    assert_eq!(
        fs::metadata(dir.path().join("chain.sqlite")).unwrap().len(),
        0
    );
    let mut duplicate = String::from_utf8(original).unwrap();
    duplicate.insert_str(1, "\"version\":1,");
    assert!(manifest::parse(duplicate.as_bytes(), cp.profile).is_err());
}

#[test]
fn chain_init_creates_only_a_height_zero_database_and_never_overwrites() {
    let dir = private_tempdir();
    let previous = chain_fixture(dir.path());
    fs::remove_file(dir.path().join("chain.sqlite")).unwrap();
    fs::remove_file(dir.path().join("node.monp")).unwrap();
    let mut document: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.path().join("node.json")).unwrap()).unwrap();
    let chain_id = hash(document["chain_id"].as_str().unwrap()).unwrap();
    let root_timestamp = 1_700_000_000_u64;
    let root_commitment = [4; 32];
    let root_id = root::derive(&chain_id, root_timestamp, &root_commitment);
    document["root_timestamp"] = root_timestamp.into();
    document["root_commitment"] = hex(&root_commitment).into();
    document["root_id"] = hex(&root_id).into();
    let manifest_bytes = serde_json::to_vec(&document).unwrap();
    fs::write(dir.path().join("node.json"), &manifest_bytes).unwrap();
    let profile = manifest::profile(&manifest_bytes).unwrap().0;
    fs::write(
        dir.path().join("peers.json"),
        TrustedPeers::empty(profile).document().unwrap(),
    )
    .unwrap();
    fs::write(
        dir.path().join("root.json"),
        serde_json::to_vec(&serde_json::json!({
            "version": root::VERSION,
            "chain_id": hex(&chain_id),
            "root_timestamp": root_timestamp,
            "root_commitment": hex(&root_commitment),
            "root_id": hex(&root_id),
        }))
        .unwrap(),
    )
    .unwrap();
    let initial = Checkpoint {
        profile,
        public_key: [0; 32],
        revision: 0,
    };
    let identity = cp(&invoke("identity-create", dir.path(), initial, frame(OLD)).unwrap());
    assert_ne!(identity.profile, previous.profile);

    let ceremony_path = dir.path().join("root.json");
    let ceremony = fs::read(&ceremony_path).unwrap();
    let mut tampered: serde_json::Value = serde_json::from_slice(&ceremony).unwrap();
    tampered["root_timestamp"] = (root_timestamp + 1).into();
    fs::write(&ceremony_path, serde_json::to_vec(&tampered).unwrap()).unwrap();
    assert!(invoke("chain-init", dir.path(), identity, frame(OLD)).is_err());
    assert!(!dir.path().join("chain.sqlite").exists());
    fs::write(&ceremony_path, ceremony).unwrap();

    let output = invoke("chain-init", dir.path(), identity, frame(OLD)).unwrap();
    let receipt: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(receipt["operation"], "chain-init");
    assert_eq!(receipt["profile"], hex(&identity.profile));
    assert_eq!(receipt["height"], 0);
    assert_eq!(receipt["phase"], "height-zero");
    assert_eq!(receipt["block_created"], false);
    assert_eq!(receipt["network_started"], false);
    assert!(dir.path().join("chain.sqlite").is_file());

    let before = fs::read(dir.path().join("chain.sqlite")).unwrap();
    assert!(invoke("chain-init", dir.path(), identity, frame(OLD)).is_err());
    assert_eq!(fs::read(dir.path().join("chain.sqlite")).unwrap(), before);

    let checked = invoke("check", dir.path(), identity, frame(OLD)).unwrap();
    let checked: serde_json::Value = serde_json::from_slice(&checked).unwrap();
    assert_eq!(checked["profile"], hex(&identity.profile));
}

#[test]
fn history_blocks_is_an_explicit_optional_manifest_choice() {
    let dir = private_tempdir();
    let cp = chain_fixture(dir.path());
    let original: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.path().join("node.json")).unwrap()).unwrap();
    // Absent means full history; never implicitly bounded.
    assert!(
        manifest::parse(&serde_json::to_vec(&original).unwrap(), cp.profile)
            .unwrap()
            .history_blocks
            .is_none()
    );
    let mut opted = original.clone();
    opted["history_blocks"] = 2_500.into();
    assert_eq!(
        manifest::parse(&serde_json::to_vec(&opted).unwrap(), cp.profile)
            .unwrap()
            .history_blocks,
        Some(2_500)
    );
    for value in [
        serde_json::json!(0),
        serde_json::json!(-1),
        serde_json::json!(100_000_001),
        serde_json::json!(true),
    ] {
        let mut invalid = original.clone();
        invalid["history_blocks"] = value;
        assert!(manifest::parse(&serde_json::to_vec(&invalid).unwrap(), cp.profile).is_err());
    }
}
#[test]
fn metadata_guard_rejects_forged_headers_and_missing_or_malformed_rows_before_activation() {
    for schema in [
        "",
        "CREATE TABLE metadata(singleton INTEGER);",
        "CREATE TABLE metadata(singleton INTEGER); INSERT INTO metadata VALUES(2);",
        "CREATE TABLE metadata(singleton TEXT); INSERT INTO metadata VALUES('1');",
        "CREATE TABLE metadata(other INTEGER); INSERT INTO metadata VALUES(1);",
    ] {
        for action in ["check", "run"] {
            let dir = private_tempdir();
            let checkpoint = chain_fixture(dir.path());
            let path = dir.path().join("chain.sqlite");
            fs::remove_file(&path).unwrap();
            let db = rusqlite::Connection::open(&path).unwrap();
            db.execute_batch("PRAGMA application_id=1297042993; PRAGMA user_version=1;")
                .unwrap();
            db.execute_batch(schema).unwrap();
            drop(db);
            let chain_before = fs::read(&path).unwrap();
            let identity_before = fs::read(dir.path().join("node.monp")).unwrap();
            let mut output = Vec::new();
            assert_eq!(
                execute_with(
                    parse(args(action, dir.path(), checkpoint)),
                    &mut Cursor::new(frame(OLD)),
                    &mut output,
                    &Arc::new(AtomicBool::new(false)),
                    |_| panic!("rejected chain installed signal handling"),
                    |_, _, _| panic!("rejected chain activated transport"),
                ),
                Err(Error::Storage)
            );
            assert!(output.is_empty());
            assert_eq!(fs::read(&path).unwrap(), chain_before);
            assert_eq!(
                fs::read(dir.path().join("node.monp")).unwrap(),
                identity_before
            );
            assert_eq!(
                cp(&invoke("identity-info", dir.path(), checkpoint, frame(OLD)).unwrap()),
                checkpoint
            );
        }
    }
}

#[test]
fn metadata_guard_crash_worker() {
    let Some(root) = std::env::var_os("MONAR_METADATA_GUARD_TEST_DIR") else {
        return;
    };
    let db = rusqlite::Connection::open(PathBuf::from(root).join("chain.sqlite")).unwrap();
    db.execute_batch(
        "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; BEGIN IMMEDIATE; DELETE FROM metadata;",
    )
    .unwrap();
    // Spill the uncommitted change so process death exercises real WAL recovery.
    db.cache_flush().unwrap();
    if std::env::var("MONAR_METADATA_GUARD_TEST_COMMIT").unwrap() == "yes" {
        db.execute_batch("COMMIT;").unwrap();
        std::process::exit(84);
    }
    std::process::exit(83);
}

#[test]
fn metadata_guard_survives_process_death_around_row_deletion_commit() {
    for committed in [false, true] {
        let dir = private_tempdir();
        let checkpoint = chain_fixture(dir.path());
        let path = dir.path().join("chain.sqlite");
        let identity_before = fs::read(dir.path().join("node.monp")).unwrap();
        let db = rusqlite::Connection::open(&path).unwrap();
        let original: (Vec<u8>, Vec<u8>, i64) = db
            .query_row(
                "SELECT identity,tip,records FROM metadata WHERE singleton=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        drop(db);
        let status = Process::new(std::env::current_exe().unwrap())
            .args(["--exact", "cli::tests::metadata_guard_crash_worker"])
            .env("MONAR_METADATA_GUARD_TEST_DIR", dir.path())
            .env(
                "MONAR_METADATA_GUARD_TEST_COMMIT",
                if committed { "yes" } else { "no" },
            )
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(if committed { 84 } else { 83 }));
        for action in ["check", "run"] {
            if committed {
                let mut output = Vec::new();
                assert_eq!(
                    execute_with(
                        parse(args(action, dir.path(), checkpoint)),
                        &mut Cursor::new(frame(OLD)),
                        &mut output,
                        &Arc::new(AtomicBool::new(false)),
                        |_| panic!("missing metadata installed signal handling"),
                        |_, _, _| panic!("missing metadata activated transport"),
                    ),
                    Err(Error::Storage)
                );
                assert!(output.is_empty());
            } else {
                // Pre-stopped run cannot open a socket; committed metadata remains valid.
                assert_eq!(
                    cp(&invoke(action, dir.path(), checkpoint, frame(OLD)).unwrap()),
                    checkpoint
                );
            }
            assert_eq!(
                fs::read(dir.path().join("node.monp")).unwrap(),
                identity_before
            );
        }
        let db = rusqlite::Connection::open(&path).unwrap();
        let rows: i64 = db
            .query_row("SELECT count(*) FROM metadata", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, i64::from(!committed));
        if committed {
            // Only this explicit test repair restores the trusted original row.
            // A failed CLI invocation must never initialize a replacement chain.
            db.execute(
                "INSERT INTO metadata(singleton,identity,tip,records) VALUES(1,?1,?2,?3)",
                rusqlite::params![original.0, original.1, original.2],
            )
            .unwrap();
        }
        drop(db);
        assert_eq!(
            cp(&invoke("check", dir.path(), checkpoint, frame(OLD)).unwrap()),
            checkpoint
        );
    }
}

#[test]
fn pre_stopped_mine_is_explicit_and_starts_no_worker_or_socket() {
    let dir = private_tempdir();
    let checkpoint = chain_fixture(dir.path());
    let address = monario_address::Address::new(
        monario_address::Network::Regtest,
        monario_address::Receiver::Transparent(
            monario_address::TransparentReceiver::PublicKeyHash([7; 20]),
        ),
    )
    .encode();
    let mut mine = args("check", dir.path(), checkpoint);
    mine[0] = "mine".into();
    mine.extend(
        [
            "--enable-mining",
            "--miner-address",
            address.as_str(),
            "--miner-workers",
            "1",
            "--miner-network",
            "regtest",
            "--status-file",
            "gui-status.json",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    fs::write(dir.path().join("gui.token"), "11".repeat(32)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            dir.path().join("gui.token"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    // Occupy the port so any accidental bind makes this test fail.
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = occupied.local_addr().unwrap().port();
    mine.extend([
        "--enable-rpc".to_owned(),
        "--rpc-bind".to_owned(),
        format!("127.0.0.1:{port}"),
        "--rpc-token-file".to_owned(),
        "gui.token".to_owned(),
    ]);
    let mut output = Vec::new();
    // The stop flag is already set: no signal handler, worker thread, socket or nonce search.
    execute(
        parse(mine),
        &mut Cursor::new(frame(OLD)),
        &mut output,
        &Arc::new(AtomicBool::new(true)),
    )
    .unwrap();
    assert!(!output.is_empty());
    let status = fs::read_to_string(dir.path().join("gui-status.json")).unwrap();
    assert!(!status.contains(std::str::from_utf8(OLD).unwrap()));
    let value: serde_json::Value = serde_json::from_str(&status).unwrap();
    assert_eq!(value["version"], 1);
    assert_eq!(value["stopped"], true);
    assert_eq!(value["profile"].as_str().unwrap().len(), 64);
    assert_eq!(value["mining"], serde_json::Value::Null);
}

#[test]
fn authenticated_inbox_provisioning_is_explicit_and_run_remains_pre_stopped() {
    let dir = private_tempdir();
    let checkpoint = chain_fixture(dir.path());
    assert!(
        Command::parse(
            args("submission-create", dir.path(), checkpoint)
                .into_iter()
                .map(OsString::from)
        )
        .is_err()
    );
    let mut values = args("submission-create", dir.path(), checkpoint);
    values.extend(["--submission-inbox".into(), "local".into()]);
    let mut output = Vec::new();
    execute(
        parse(values.clone()),
        &mut Cursor::new(frame(OLD)),
        &mut output,
        &Arc::new(AtomicBool::new(true)),
    )
    .unwrap();
    assert_eq!(cp(&output), checkpoint);
    assert!(
        crate::submission::Inbox::open(
            dir.path(),
            "local",
            checkpoint.profile,
            checkpoint.public_key
        )
        .is_ok()
    );
    assert!(
        execute(
            parse(values),
            &mut Cursor::new(frame(OLD)),
            &mut Vec::new(),
            &Arc::new(AtomicBool::new(true))
        )
        .is_err()
    );
    let mut values = args("run", dir.path(), checkpoint);
    values.extend(["--submission-inbox".into(), "local".into()]);
    let mut output = Vec::new();
    execute(
        parse(values),
        &mut Cursor::new(frame(OLD)),
        &mut output,
        &Arc::new(AtomicBool::new(true)),
    )
    .unwrap();
    assert_eq!(cp(&output), checkpoint);
    assert!(!dir.path().join("missing.mons").exists());
}

#[test]
fn authenticated_cleanup_rotation_and_lost_receipts_never_cancel_transactions() {
    let dir = private_tempdir();
    let checkpoint = chain_fixture(dir.path());
    let raw = include_bytes!("../../../v6/tests/fixtures/spend-deposit-v6.bin");
    let mut inbox = crate::submission::Inbox::create(
        dir.path(),
        "local",
        checkpoint.profile,
        checkpoint.public_key,
    )
    .unwrap();
    let token = inbox.enqueue(raw).unwrap();
    let mut forget = args("submission-forget", dir.path(), checkpoint);
    forget.extend([
        "--submission-inbox".into(),
        "local".into(),
        "--submission".into(),
        hex(&token),
    ]);
    assert!(Command::parse(forget.clone().into_iter().map(OsString::from)).is_err());
    forget.push("--acknowledge-not-cancellation".into());
    assert!(
        execute(
            parse(forget.clone()),
            &mut Cursor::new(frame(NEW)),
            &mut Vec::new(),
            &Arc::new(AtomicBool::new(true))
        )
        .is_err()
    );
    assert!(inbox.status(token).unwrap().is_some());
    let directory = IdentityDirectory::open(dir.path()).unwrap();
    let owner = IdentityStore::open(
        &directory,
        "node",
        &Password::from_bytes(OLD).unwrap(),
        checkpoint,
    )
    .unwrap();
    assert!(
        execute(
            parse(forget.clone()),
            &mut Cursor::new(frame(OLD)),
            &mut Vec::new(),
            &Arc::new(AtomicBool::new(true))
        )
        .is_err()
    );
    assert!(inbox.status(token).unwrap().is_some());
    drop(owner);
    assert_eq!(
        execute(
            parse(forget.clone()),
            &mut Cursor::new(frame(OLD)),
            &mut BrokenOutput,
            &Arc::new(AtomicBool::new(true))
        ),
        Err(Error::Output)
    );
    assert!(inbox.status(token).unwrap().is_none());
    let mut out = Vec::new();
    execute(
        parse(forget),
        &mut Cursor::new(frame(OLD)),
        &mut out,
        &Arc::new(AtomicBool::new(true)),
    )
    .unwrap();
    let receipt: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(receipt["removed"], false);
    assert_eq!(receipt["wallet_claims_released"], false);
    assert_eq!(receipt["not_cancellation"], true);
    inbox.enqueue(raw).unwrap();
    let mut rotate = args("submission-rotate", dir.path(), checkpoint);
    rotate.extend([
        "--submission-inbox".into(),
        "local".into(),
        "--new-submission-inbox".into(),
        "next".into(),
        "--acknowledge-not-cancellation".into(),
    ]);
    assert_eq!(
        execute(
            parse(rotate.clone()),
            &mut Cursor::new(frame(OLD)),
            &mut BrokenOutput,
            &Arc::new(AtomicBool::new(true))
        ),
        Err(Error::Output)
    );
    let mut target = crate::submission::Inbox::open(
        dir.path(),
        "next",
        checkpoint.profile,
        checkpoint.public_key,
    )
    .unwrap();
    let mut another = raw.to_vec();
    *another.last_mut().unwrap() ^= 1;
    let additional = target.enqueue(&another).unwrap();
    let mut out = Vec::new();
    execute(
        parse(rotate),
        &mut Cursor::new(frame(OLD)),
        &mut out,
        &Arc::new(AtomicBool::new(true)),
    )
    .unwrap();
    assert_eq!(cp(&out), checkpoint);
    assert!(target.status(token).unwrap().is_some());
    assert!(target.status(additional).unwrap().is_some());
    let mut invalid = args("submission-rotate", dir.path(), checkpoint);
    invalid.extend([
        "--submission-inbox".into(),
        "next".into(),
        "--new-submission-inbox".into(),
        "NEXT".into(),
        "--acknowledge-not-cancellation".into(),
    ]);
    assert!(Command::parse(invalid.into_iter().map(OsString::from)).is_err());
}

#[test]
fn offline_check_and_pre_stopped_runtime_release_both_database_owners() {
    let dir = private_tempdir();
    let checkpoint = chain_fixture(dir.path());
    for command in ["check", "run"] {
        // The stop flag is set before calling run; no socket or signal handler is installed.
        assert_eq!(
            cp(&invoke(command, dir.path(), checkpoint, frame(OLD)).unwrap()),
            checkpoint
        );
        let directory = IdentityDirectory::open(dir.path()).unwrap();
        assert!(
            IdentityStore::open(
                &directory,
                "node",
                &Password::from_bytes(OLD).unwrap(),
                checkpoint
            )
            .is_ok()
        );
    }
}
struct BrokenOutput;
impl Write for BrokenOutput {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }
}
#[test]
fn lost_output_after_commit_never_rolls_back_or_repeats_an_update() {
    let (dir, initial) = fixture();
    let first = cp(&invoke("identity-create", dir.path(), initial, frame(OLD)).unwrap());
    fs::write(dir.path().join("peers.json"), changed_peers(first.profile)).unwrap();
    assert_eq!(
        execute(
            parse(args("peers-set", dir.path(), first)),
            &mut Cursor::new(frame(OLD)),
            &mut BrokenOutput,
            &Arc::new(AtomicBool::new(true))
        ),
        Err(Error::Output)
    );
    let latest = cp(&invoke("identity-info", dir.path(), first, frame(OLD)).unwrap());
    assert_eq!(latest.revision, 1);
}

struct CrashInput {
    sent_prefix_byte: bool,
}
impl Read for CrashInput {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.sent_prefix_byte {
            std::process::exit(81);
        }
        self.sent_prefix_byte = true;
        out[0] = OLD.len() as u8;
        Ok(1)
    }
}
struct CrashOutput;
impl Write for CrashOutput {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        std::process::exit(82)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        std::process::exit(82)
    }
}
#[test]
fn cli_crash_worker() {
    let Some(root) = std::env::var_os("MONAR_CLI_CRASH_DIR") else {
        return;
    };
    let root = PathBuf::from(root);
    let action = std::env::var("MONAR_CLI_CRASH_ACTION").unwrap();
    let first = Checkpoint {
        profile: [2; 32],
        public_key: hash(&std::env::var("MONAR_CLI_CRASH_KEY").unwrap()).unwrap(),
        revision: 0,
    };
    let command = parse(args(&action, &root, first));
    let stop = Arc::new(AtomicBool::new(true));
    if std::env::var("MONAR_CLI_CRASH_PHASE").unwrap() == "before" {
        execute(
            command,
            &mut CrashInput {
                sent_prefix_byte: false,
            },
            &mut Vec::new(),
            &stop,
        )
        .unwrap();
    } else {
        let mut input = frame(OLD);
        if action == "password-change" {
            input.extend(frame(NEW));
        }
        execute(command, &mut Cursor::new(input), &mut CrashOutput, &stop).unwrap();
    }
    panic!("crash hook did not execute");
}
#[test]
fn cli_process_death_before_credentials_and_before_commit_acknowledgment() {
    for action in ["identity-create", "peers-set", "password-change"] {
        for after in [false, true] {
            let (dir, mut first) = fixture();
            if action != "identity-create" {
                first = cp(&invoke("identity-create", dir.path(), first, frame(OLD)).unwrap());
            }
            fs::write(dir.path().join("peers.json"), changed_peers(first.profile)).unwrap();
            let status = Process::new(std::env::current_exe().unwrap())
                .args(["--exact", "cli::tests::cli_crash_worker"])
                .env("MONAR_CLI_CRASH_DIR", dir.path())
                .env("MONAR_CLI_CRASH_ACTION", action)
                .env("MONAR_CLI_CRASH_KEY", hex(&first.public_key))
                .env(
                    "MONAR_CLI_CRASH_PHASE",
                    if after { "after" } else { "before" },
                )
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(if after { 82 } else { 81 }));
            let path = dir.path().join("node.monp");
            if action == "identity-create" && !after {
                assert!(!path.exists());
                continue;
            }
            if action == "identity-create" {
                // Test-only inspection of our child's freshly provisioned public header.
                // Production CLI never promotes a key from an untrusted file into a pin.
                let db = rusqlite::Connection::open(&path).unwrap();
                let bytes: Vec<u8> = db
                    .query_row("SELECT envelope FROM identity", [], |r| r.get(0))
                    .unwrap();
                first.public_key.copy_from_slice(&bytes[40..72]);
                drop(db);
            }
            let credentials = if action == "password-change" && after {
                NEW
            } else {
                OLD
            };
            let latest =
                cp(&invoke("identity-info", dir.path(), first, frame(credentials)).unwrap());
            assert_eq!(
                latest,
                Checkpoint {
                    revision: u64::from(action != "identity-create" && after),
                    ..first
                }
            );
            let directory = IdentityDirectory::open(dir.path()).unwrap();
            let store = IdentityStore::open(
                &directory,
                "node",
                &Password::from_bytes(credentials).unwrap(),
                latest,
            )
            .unwrap();
            let expected_peers =
                usize::from(action == "identity-create" || (action == "peers-set" && after));
            assert_eq!(store.configuration().unwrap().peers().len(), expected_peers);
            drop(store);
            let bytes = fs::read(path).unwrap();
            for secret in [OLD, NEW] {
                assert!(!bytes.windows(secret.len()).any(|w| w == secret));
            }
        }
    }
}
