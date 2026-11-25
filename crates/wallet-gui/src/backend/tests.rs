use super::*;

/// Fixed valid vectors from `crates/address/tests/vectors.txt`.
const SOLO_REGTEST: &str = "rmont1qyqqqqgzqvzq2ps8pqys5zcvp58q7yq3zgfs7grwe7";
const SOLO_TEST: &str = "testmont1qyqqqqgzqvzq2ps8pqys5zcvp58q7yq3zgfsxp6xum";
const SOLO_REGTEST_PRIVATE: &str =
    "rmonz1qypgluecd9cuke9cuaufjzxa367hm6f2drjcdg6dhrl2nx006gqkltnkw5904elwjstyd09ey8n3q4";

fn pw(value: &str) -> Zeroizing<String> {
    Zeroizing::new(value.to_owned())
}

fn wallet() -> WalletRef {
    WalletRef {
        directory: "C:/Monario/wallet".into(),
        name: "primary".into(),
        network: Network::Main,
        wallet_id: "00".repeat(16),
        revision: 7,
    }
}

fn node() -> NodeRef {
    NodeRef {
        directory: "C:/Monario/node".into(),
        profile: "11".repeat(32),
        public_key: "22".repeat(32),
        revision: 3,
    }
}

fn source() -> ChainSource {
    ChainSource {
        directory: "C:/Monario/chain".into(),
        manifest: "chain.json".into(),
        profile: "33".repeat(32),
        ..ChainSource::default()
    }
}

#[test]
fn password_frames_are_exact_and_bounded() {
    let spec = CommandSpec::new(Program::Wallet, vec!["create".into()]).with_secrets(vec![
        pw("correct horse battery"),
        pw("correct horse battery"),
    ]);
    let bytes = spec.stdin().unwrap();
    assert_eq!(&bytes[..2], &(21u16).to_le_bytes());
    assert_eq!(&bytes[2..23], b"correct horse battery");
    assert_eq!(&bytes[23..25], &(21u16).to_le_bytes());
    assert_eq!(&bytes[25..46], b"correct horse battery");
    assert_eq!(bytes.len(), 46);

    let short =
        CommandSpec::new(Program::Wallet, vec!["info".into()]).with_secrets(vec![pw("short")]);
    assert!(short.stdin().is_err());
    let long = CommandSpec::new(Program::Wallet, vec!["info".into()])
        .with_secrets(vec![pw(&"a".repeat(1025))]);
    assert!(long.stdin().is_err());
    let none = CommandSpec::new(Program::Wallet, vec!["info".into()]);
    assert!(none.stdin().is_err());
    let too_many =
        CommandSpec::new(Program::Wallet, vec!["info".into()])
            .with_secrets(vec![pw("aaaaaaaaaaaa"); 4]);
    assert!(too_many.stdin().is_err());
}

#[test]
fn pull_remote_is_passwordless_and_bounded() {
    let source = ChainSource {
        directory: ".".into(),
        manifest: "chain.json".into(),
        profile: "11".repeat(32),
        ..Default::default()
    };
    let key = "33".repeat(32);
    let spec = pull_remote(&source, "127.0.0.1:19445", "scan.token", 1_000, &key).unwrap();
    assert_eq!(spec.program, Program::Wallet);
    assert_eq!(spec.args[0], "pull-remote");
    assert!(spec.frames.is_empty());
    assert!(
        spec.args
            .windows(2)
            .any(|pair| pair[0] == "--remote" && pair[1] == "127.0.0.1:19445")
    );
    assert!(
        spec.args
            .windows(2)
            .any(|pair| pair[0] == "--token-file" && pair[1] == "scan.token")
    );
    assert!(
        spec.args
            .windows(2)
            .any(|pair| pair[0] == "--max-blocks" && pair[1] == "1000")
    );

    assert!(
        spec.args
            .windows(2)
            .any(|pair| pair[0] == "--remote-public-key" && pair[1] == key)
    );

    for remote in ["0.0.0.0:19445", "127.0.0.1:0", "not-an-address"] {
        assert!(
            pull_remote(&source, remote, "scan.token", 1, &key).is_err(),
            "{remote}"
        );
    }
    assert!(pull_remote(&source, "127.0.0.1:1", "scan.json", 1, &key).is_err());
    assert!(pull_remote(&source, "127.0.0.1:1", "scan.token", 0, &key).is_err());
    assert!(pull_remote(&source, "127.0.0.1:1", "scan.token", 10_001, &key).is_err());

    let secure = pull_remote(&source, "192.0.2.1:19445", "scan.token", 1, &key).unwrap();
    assert!(
        secure
            .args
            .windows(2)
            .any(|pair| pair[0] == "--remote-public-key" && pair[1] == key)
    );
    assert!(pull_remote(&source, "192.0.2.1:19445", "scan.token", 1, "").is_err());
    assert!(pull_remote(&source, "127.0.0.1:19445", "scan.token", 1, "").is_err());
    assert!(pull_remote(&source, "192.0.2.1:19445", "scan.token", 1, "11").is_err());
}

#[test]
fn passwords_never_reach_arguments() {
    let secret = pw("super-secret-password");
    for spec in [
        wallet_create("C:/Monario", "primary", Network::Main, &secret).unwrap(),
        wallet_info(&wallet(), &secret).unwrap(),
        wallet_address(&wallet(), AddressKind::Transparent, 0, &secret).unwrap(),
        wallet_service_key(&wallet(), 0, &secret).unwrap(),
        node_identity_create("C:/Monario/node", &"11".repeat(32), "peers.json", &secret).unwrap(),
        node_identity_info(&node(), &secret).unwrap(),
        node_mine(
            &node(),
            "chain.json",
            "",
            "gui-status.json",
            "gui.stop",
            &MiningConfig {
                address: SOLO_REGTEST.into(),
                workers: 2,
                network: Network::Regtest,
                pool_mode: PoolMode::Solo,
                pool: None,
            },
            false,
            &secret,
        )
        .unwrap(),
    ] {
        spec.validate().unwrap();
        assert!(!spec.args.iter().any(|arg| arg.contains("super-secret")));
        assert!(spec.stdin().unwrap().len() > 12);
    }
}

#[test]
fn names_directories_and_hex_are_bounded() {
    for good in ["primary", "wallet-1", "A_b"] {
        validate_name(good).unwrap();
    }
    for bad in ["", "has space", "../x", "con", "LPT1", &"a".repeat(65)] {
        assert!(validate_name(bad).is_err(), "{bad}");
    }
    for good in ["chain.json", "peers-v1.json", "a.b"] {
        validate_filename(good).unwrap();
    }
    for bad in ["", ".hidden", "trailing.", "a..b", "../x"] {
        assert!(validate_filename(bad).is_err(), "{bad}");
    }
    assert!(validate_directory("").is_err());
    assert!(validate_directory("C:/Monario").is_ok());
    assert!(validate_hex(&"00".repeat(32), 32, "id").is_ok());
    assert!(validate_hex(&"00".repeat(31), 32, "id").is_err());
    assert!(validate_hex(&"AA".repeat(32), 32, "id").is_err());
    assert!(validate_address("rmont1qexample").is_ok());
    assert!(validate_address("has space").is_err());
    assert!(validate_address(&"a".repeat(129)).is_err());
}

#[test]
fn amounts_round_trip_without_floating_point() {
    assert_eq!(parse_monar("1").unwrap(), ATOMS_PER_MONAR);
    assert_eq!(parse_monar("1000").unwrap(), COLLATERAL_ATOMS);
    assert_eq!(parse_monar("0.00000001").unwrap(), 1);
    assert_eq!(parse_monar(".5").unwrap(), 50_000_000);
    assert_eq!(parse_monar("1.25").unwrap(), 125_000_000);
    assert_eq!(format_monar(ATOMS_PER_MONAR), "1");
    assert_eq!(format_monar(125_000_000), "1.25");
    assert_eq!(format_monar(1), "0.00000001");
    assert_eq!(format_monar(COLLATERAL_ATOMS), "1000");
    for bad in ["", "1.123456789", "-1", "1e3", "1,5", "abc"] {
        assert!(parse_monar(bad).is_err(), "{bad}");
    }
    assert!(parse_monar(&"9".repeat(31)).is_err());
    assert_eq!(parse_u64("42", "n").unwrap(), 42);
    assert!(parse_u64("4x", "n").is_err());
}

#[test]
fn wallet_commands_carry_the_exact_public_selector() {
    let spec = wallet_address(&wallet(), AddressKind::Private, 2, &pw("aaaaaaaaaaaa")).unwrap();
    assert_eq!(spec.program, Program::Wallet);
    assert_eq!(spec.args[0], "address");
    for expected in [
        "--directory",
        "C:/Monario/wallet",
        "--name",
        "primary",
        "--network",
        "main",
        "--password-stdin",
        "--wallet-id",
        "--revision",
        "7",
        "--type",
        "private",
        "--account",
        "2",
    ] {
        assert!(spec.args.iter().any(|arg| arg == expected), "{expected}");
    }
    let balance = wallet_balance(&wallet(), &source(), &pw("aaaaaaaaaaaa")).unwrap();
    for expected in [
        "--chain-directory",
        "C:/Monario/chain",
        "--manifest",
        "chain.json",
        "--profile",
        "--external",
        "20",
        "--internal",
        "20",
        "--max-blocks",
        "100000",
    ] {
        assert!(balance.args.iter().any(|arg| arg == expected), "{expected}");
    }
    assert!(!balance.args.iter().any(|arg| arg == "--rescan"));
}

#[test]
fn node_activation_is_always_explicit() {
    let mining = MiningConfig {
        address: SOLO_TEST.into(),
        workers: 3,
        network: Network::Test,
        pool_mode: PoolMode::Solo,
        pool: None,
    };
    let spec = node_mine(
        &node(),
        "chain.json",
        "",
        "gui-status.json",
        "gui.stop",
        &mining,
        false,
        &pw("aaaaaaaaaaaa"),
    )
    .unwrap();
    assert!(spec.args.iter().any(|arg| arg == "--enable-mining"));
    assert!(!spec.args.iter().any(|arg| arg == "--enable-network"));
    assert!(
        spec.args
            .windows(2)
            .any(|w| w == ["--miner-network", "test"])
    );
    assert!(!spec.args.iter().any(|arg| arg.starts_with("--pool-")));
    assert!(spec.args.iter().any(|arg| arg == "--miner-workers"));
    assert!(spec.args.iter().any(|arg| arg == "3"));
    assert!(spec.args.iter().any(|arg| arg == "--status-file"));
    assert!(spec.args.iter().any(|arg| arg == "--stop-file"));
    assert!(spec.args.iter().any(|arg| arg == "gui.stop"));

    let mut workers = mining.clone();
    workers.workers = MAX_WORKERS + 1;
    assert!(
        node_mine(
            &node(),
            "chain.json",
            "",
            "gui-status.json",
            "gui.stop",
            &workers,
            false,
            &pw("aaaaaaaaaaaa")
        )
        .is_err()
    );
    let mut bad_stop = mining.clone();
    bad_stop.address = SOLO_TEST.into();
    assert!(
        node_mine(
            &node(),
            "chain.json",
            "",
            "gui-status.json",
            "gui.json",
            &bad_stop,
            false,
            &pw("aaaaaaaaaaaa")
        )
        .is_err()
    );

    let run = node_run(
        &node(),
        "chain.json",
        "",
        "gui-status.json",
        "gui.stop",
        None,
        &pw("aaaaaaaaaaaa"),
    )
    .unwrap();
    assert!(run.args.iter().any(|arg| arg == "run"));
    assert!(run.args.iter().any(|arg| arg == "--enable-network"));
}

#[test]
fn custom_pool_passes_credentials_on_stdin_only() {
    let token = "33".repeat(32);
    let credential = Zeroizing::new(format!(
        "monp1:{}:{}:{token}",
        "11".repeat(32),
        "22".repeat(16)
    ));
    let mut setup = MiningConfig {
        address: String::new(),
        workers: 12,
        network: Network::Test,
        pool_mode: PoolMode::Custom,
        pool: Some(PoolSpec {
            address: pool_endpoint("2001:db8::1", "19444").unwrap(),
            credential: &credential,
        }),
    };
    let password = pw("aaaaaaaaaaaa");
    let spec = node_mine(
        &node(),
        "chain.json",
        "",
        "gui-status.json",
        "gui.stop",
        &setup,
        false,
        &password,
    )
    .unwrap();
    assert!(spec.args.windows(2).any(|w| w == ["--pool-mode", "custom"]));
    assert!(
        spec.args
            .windows(2)
            .any(|w| w == ["--pool-address", "[2001:db8::1]:19444"])
    );
    assert!(spec.args.windows(2).any(|w| w == ["--miner-workers", "12"]));
    assert!(spec.args.iter().any(|arg| arg == "--pool-credential-stdin"));
    assert!(
        !spec.args.iter().any(|arg| arg == "--enable-network"
            || arg == "--miner-address"
            || arg.contains(&token))
    );
    assert!(!format!("{spec:?}").contains(&token));
    let frames = spec.stdin().unwrap();
    let after_password = 2 + password.len();
    assert_eq!(
        &frames[after_password..after_password + 2],
        &(credential.len() as u16).to_le_bytes()
    );
    assert_eq!(&frames[after_password + 2..], credential.as_bytes());
    setup.pool_mode = PoolMode::Solo;
    assert!(setup.validate().is_err());
    setup.pool_mode = PoolMode::Custom;
    setup.pool = None;
    assert!(setup.validate().is_err());
    assert!(validate_pool_credential("regular-password").is_err());
    assert!(pool_endpoint("host", "0").is_err());
    assert!(pool_endpoint("https://example.org", "19444").is_err());
}

#[test]
fn payment_requests_are_validated_and_encoded() {
    let request = PaymentRequest {
        validated_tip: "44".repeat(32),
        funding: vec![OutPoint {
            transaction: "55".repeat(32),
            index: 1,
        }],
        payments: vec![Payment {
            address: "rmont1qrecipient".into(),
            atoms: 12_500_000,
        }],
        fee_atoms: 1_000,
        expiry_height: 500,
        change: AddressKind::Transparent,
        service: None,
    };
    let json = request.to_json().unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(value["version"], 1);
    assert_eq!(value["funding"]["pool"], "transparent");
    assert_eq!(value["payments"][0]["amount_atoms"], "12500000");
    assert_eq!(value["fee_atoms"], "1000");
    assert_eq!(value["change"], "transparent");
    assert!(value.get("service").is_some());

    let mut empty = request.clone();
    empty.payments.clear();
    assert!(empty.to_json().is_err());
    let mut zero = request.clone();
    zero.payments[0].atoms = 0;
    assert!(zero.to_json().is_err());
    let mut duplicate = request.clone();
    duplicate.funding.push(request.funding[0].clone());
    assert!(duplicate.to_json().is_err());
    let mut bad_address = request.clone();
    bad_address.payments[0].address = "bad address".into();
    assert!(bad_address.to_json().is_err());
}

#[test]
fn registration_intent_and_schedule_are_encoded() {
    let intent = RegistrationIntent {
        collateral_transaction: "66".repeat(32),
        collateral_index: 0,
        owner_index: 4,
        operator_public_key: format!("02{}", "77".repeat(32)),
    };
    intent.validate().unwrap();
    let value = intent.json();
    assert_eq!(value["kind"], "registration");
    assert_eq!(value["owner_index"], 4);
    assert_eq!(value["collateral_transaction"], "66".repeat(32));
    assert!(value.get("payout").is_none());

    let schedule = proof_schedule_json(
        &"88".repeat(32),
        4,
        500,
        100_000,
        &[OutPoint {
            transaction: "99".repeat(32),
            index: 2,
        }],
    )
    .unwrap();
    let value: serde_json::Value = serde_json::from_str(&schedule).unwrap();
    assert_eq!(value["version"], 1);
    assert_eq!(value["fee_atoms"], "500");
    assert_eq!(value["period_fee_budget_atoms"], "100000");
    assert!(proof_schedule_json(&"88".repeat(32), 4, 500, 100, &[]).is_err());

    let mut bad = intent.clone();
    bad.operator_public_key = "00".repeat(32);
    assert!(bad.validate().is_err());
}

#[test]
fn coins_are_parsed_and_filtered() {
    let value = serde_json::json!({
        "transparent": [
            {"transaction": "aa".repeat(32), "index": 0, "amount_atoms": "100000000000", "mature_next_block": true, "reserved": false},
            {"transaction": "bb".repeat(32), "index": 1, "amount_atoms": "10", "mature_next_block": false, "reserved": false},
            {"transaction": "cc".repeat(32), "index": 2, "amount_atoms": "10", "mature_next_block": true, "reserved": true},
            {"transaction": "broken"}
        ]
    });
    let coins = parse_coins(&value);
    assert_eq!(coins.len(), 3);
    assert_eq!(coins[0].atoms, COLLATERAL_ATOMS);
    assert!(coins[0].selectable());
    assert!(!coins[1].selectable());
    assert!(!coins[2].selectable());
}

#[test]
fn wallet_creation_and_reopen_receipts_expose_the_checkpoint() {
    let receipt = serde_json::json!({
        "wallet_id": "ab".repeat(16),
        "network": "test",
        "revision": "0",
        "recovery_required": false
    });
    assert_eq!(checkpoint_of(&receipt), Some(("ab".repeat(16), 0)));

    let mut malformed = receipt.clone();
    malformed["wallet_id"] = serde_json::json!("invalid");
    assert!(checkpoint_of(&malformed).is_none());

    let mut malformed = receipt.clone();
    malformed["revision"] = serde_json::json!("18446744073709551616");
    assert!(checkpoint_of(&malformed).is_none());

    let mut ambiguous = receipt;
    ambiguous["checkpoint"] = serde_json::Value::Null;
    assert!(checkpoint_of(&ambiguous).is_none());
}

#[test]
fn receipts_expose_checkpoint_updates() {
    let wallet = serde_json::json!({
        "checkpoint": {"wallet_id": "ab".repeat(16), "network": "main", "revision": "9", "recovery_required": false},
        "address": "rmont1qexample"
    });
    assert_eq!(checkpoint_of(&wallet), Some(("ab".repeat(16), 9)));
    let node = serde_json::json!({"profile": "11", "public_key": "cd".repeat(32), "revision": 4});
    assert_eq!(node_checkpoint_of(&node), Some(("cd".repeat(32), 4)));
    assert!(checkpoint_of(&serde_json::json!({})).is_none());
}

#[test]
fn program_resolution_prefers_the_explicit_directory() {
    let root = std::env::temp_dir().join(format!("monario-gui-test-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let wallet = root.join(Program::Wallet.executable());
    std::fs::write(&wallet, b"").unwrap();
    let resolved = resolve_program(Program::Wallet, Some(&root)).unwrap();
    assert_eq!(resolved, wallet);
    let missing = resolve_program(Program::Node, Some(&root)).unwrap();
    assert!(!missing.is_absolute());
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn status_snapshots_are_bounded_and_typed() {
    let root = std::env::temp_dir().join(format!("monario-gui-status-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("status.json");
    std::fs::write(
        &path,
        br#"{"version":1,"profile":"aa","tip":"bb","height":"10","peers":2,"stopped":false,"updated_unix":5,"mining":{"refreshed":true,"workers":2,"accepted":null,"job":"cc"},"candidates":[{"address":"127.0.0.1:9000","public_key":"dd"}],"candidates_untrusted":true}"#,
    )
    .unwrap();
    let status = read_status(&path).unwrap();
    assert_eq!(status.height, "10");
    assert_eq!(status.peers, 2);
    assert_eq!(status.mining.unwrap().workers, 2);
    assert_eq!(status.candidates.len(), 1);
    assert_eq!(status.candidates[0].address, "127.0.0.1:9000");
    assert!(status.candidates_untrusted);

    std::fs::write(&path, vec![b'x'; (MAX_STATUS_BYTES + 1) as usize]).unwrap();
    assert!(read_status(&path).is_err());
    std::fs::write(&path, b"not json").unwrap();
    assert!(read_status(&path).is_err());
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn pool_phase_status_is_optional_and_rejection_is_typed() {
    let root = std::env::temp_dir().join(format!("monario-gui-pool-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("status.json");
    // An older node snapshot without a phase still parses.
    std::fs::write(
        &path,
        br#"{"version":1,"profile":"aa","tip":"bb","height":"1","peers":0,"stopped":false,"updated_unix":1,"pool":{"connected":true,"assigned":false,"workers":0,"submitted":0,"block_candidates":0}}"#,
    )
    .unwrap();
    let status = read_status(&path).unwrap();
    let pool = status.pool.unwrap();
    assert_eq!(pool.phase, None);
    assert!(pool.connected);
    assert_eq!(status.pid, None);

    std::fs::write(
        &path,
        br#"{"version":1,"pid":4242,"profile":"aa","tip":"bb","height":"1","peers":0,"stopped":false,"updated_unix":1,"pool":{"connected":false,"phase":"rejected","assigned":false,"workers":0,"submitted":0,"block_candidates":0}}"#,
    )
    .unwrap();
    let status = read_status(&path).unwrap();
    assert_eq!(status.pid, Some(4242));
    assert_eq!(
        status.pool.unwrap().phase,
        Some(PoolPhase::Rejected)
    );
    assert!(!POOL_AUTH_REJECTED.is_empty());
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn managed_node_status_ignores_snapshots_from_another_pid() {
    let root = std::env::temp_dir().join(format!("monario-gui-pid-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("status.json");
    let node = ManagedNode {
        child: None,
        status_path: path.clone(),
        stop_path: root.join("gui.stop"),
        stdout: Arc::new(Mutex::new(String::new())),
        stderr: Arc::new(Mutex::new(String::new())),
        pid: 4242,
    };
    // A snapshot from a different process is not accepted.
    std::fs::write(
        &path,
        br#"{"version":1,"pid":1111,"profile":"aa","tip":"bb","height":"1","peers":0,"stopped":false,"updated_unix":1}"#,
    )
    .unwrap();
    assert!(node.status().is_err());
    // The matching process and older snapshots without a pid are accepted.
    std::fs::write(
        &path,
        br#"{"version":1,"pid":4242,"profile":"aa","tip":"bb","height":"1","peers":0,"stopped":false,"updated_unix":1}"#,
    )
    .unwrap();
    assert_eq!(node.status().unwrap().pid, Some(4242));
    std::fs::write(
        &path,
        br#"{"version":1,"profile":"aa","tip":"bb","height":"1","peers":0,"stopped":false,"updated_unix":1}"#,
    )
    .unwrap();
    assert_eq!(node.status().unwrap().pid, None);
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn live_chain_requires_current_pid_profile_and_fresh_canonical_status() {
    let tip = "bb".repeat(32);
    let status = |pid: Option<u32>, profile: &str, height: &str, stopped: bool, updated: u64| {
        NodeStatus {
            version: 1,
            pid,
            profile: profile.into(),
            tip: tip.clone(),
            height: height.into(),
            peers: 2,
            stopped,
            updated_unix: updated,
            ..NodeStatus::default()
        }
    };
    let fresh = status(Some(4242), "aa", "7", false, 100);
    assert_eq!(
        live_chain(&fresh, 4242, "aa", 105),
        Some(LiveChain {
            height: 7,
            tip: tip.clone(),
            peers: 2,
        })
    );
    assert!(live_chain(&fresh, 4242, "aa", 110).is_some());
    assert!(live_chain(&fresh, 4242, "aa", 111).is_none());
    assert!(live_chain(&fresh, 1111, "aa", 105).is_none());
    assert!(live_chain(&status(None, "aa", "7", false, 100), 4242, "aa", 105).is_none());
    assert!(live_chain(&fresh, 4242, "bb", 105).is_none());
    assert!(live_chain(&status(Some(4242), "aa", "7", true, 100), 4242, "aa", 105).is_none());
    assert!(live_chain(&status(Some(4242), "aa", "7", false, 200), 4242, "aa", 105).is_none());
    for bad in ["", "07", "+7", "-1", "7x", "18446744073709551616"] {
        assert!(live_chain(&status(Some(4242), "aa", bad, false, 100), 4242, "aa", 105).is_none());
    }
    assert!(live_chain(&status(Some(4242), "aa", "0", false, 100), 4242, "aa", 105).is_some());
    let mut upper = fresh.clone();
    upper.tip = "BB".repeat(32);
    assert!(live_chain(&upper, 4242, "aa", 105).is_none());
    upper.tip = "bb".into();
    assert!(live_chain(&upper, 4242, "aa", 105).is_none());
}

#[test]
fn solo_payout_address_needs_matching_network_and_transparent_receiver() {
    assert!(validate_solo_address(SOLO_REGTEST, Network::Regtest).is_ok());
    assert!(validate_solo_address(SOLO_TEST, Network::Test).is_ok());
    assert!(validate_solo_address(SOLO_REGTEST, Network::Test).is_err());
    assert!(validate_solo_address(SOLO_TEST, Network::Main).is_err());
    assert!(validate_solo_address(SOLO_REGTEST_PRIVATE, Network::Regtest).is_err());
    assert!(validate_solo_address("rmont1fixture", Network::Regtest).is_err());
    assert!(validate_solo_address("", Network::Regtest).is_err());
    // Pool payouts stay operator-configured; pool mode must not require a solo
    // address and must not decode it.
    let credential = Zeroizing::new(format!(
        "monp1:{}:{}:{}",
        "11".repeat(32),
        "22".repeat(16),
        "33".repeat(32)
    ));
    let pool = MiningConfig {
        address: "rmont1fixture".into(),
        workers: 1,
        network: Network::Regtest,
        pool_mode: PoolMode::Custom,
        pool: Some(PoolSpec {
            address: pool_endpoint("pool.example", "19444").unwrap(),
            credential: &credential,
        }),
    };
    pool.validate().unwrap();
}

#[test]
fn recovery_frames_are_bounded_and_names_must_differ() {
    let backup = pw("backup-password");
    let fresh = pw("new-wallet-password");
    let spec = wallet_recover(
        "C:/Monario/wallet",
        "snapshot",
        "restored",
        Network::Regtest,
        &"ab".repeat(16),
        3,
        &backup,
        &fresh,
    )
    .unwrap();
    assert!(spec.args.iter().any(|arg| arg == "recover"));
    assert!(spec.args.iter().any(|arg| arg == "--backup-name"));
    assert!(spec.args.iter().any(|arg| arg == "snapshot"));
    assert!(spec.args.iter().any(|arg| arg == "restored"));
    assert!(
        !spec
            .args
            .iter()
            .any(|arg| arg == "backup-password" || arg == "new-wallet-password")
    );
    let bytes = spec.stdin().unwrap();
    assert_eq!(bytes.len(), (2 + 15) + (2 + 19) + (2 + 19));

    assert!(
        wallet_recover(
            "C:/Monario/wallet",
            "same",
            "SAME",
            Network::Regtest,
            &"ab".repeat(16),
            0,
            &backup,
            &fresh,
        )
        .is_err()
    );
    assert!(
        wallet_recover(
            "C:/Monario/wallet",
            "snapshot",
            "restored",
            Network::Regtest,
            "bad",
            0,
            &backup,
            &fresh,
        )
        .is_err()
    );
}

#[test]
fn discovery_arguments_are_bounded_and_never_require_a_scan_window() {
    let spec = wallet_discovery(
        &wallet(),
        &source(),
        0,
        20,
        64,
        10_000,
        100_000,
        &pw("aaaaaaaaaaaa"),
    )
    .unwrap();
    for expected in [
        "discover",
        "--gap",
        "20",
        "--start",
        "64",
        "--max",
        "10000",
        "--max-blocks",
        "100000",
    ] {
        assert!(spec.args.iter().any(|arg| arg == expected), "{expected}");
    }
    assert!(!spec.args.iter().any(|arg| arg == "--external"));
    assert!(
        wallet_discovery(
            &wallet(),
            &source(),
            0,
            0,
            64,
            10_000,
            100_000,
            &pw("aaaaaaaaaaaa")
        )
        .is_err()
    );
    assert!(
        wallet_discovery(
            &wallet(),
            &source(),
            0,
            20,
            10,
            10_000,
            100_000,
            &pw("aaaaaaaaaaaa")
        )
        .is_err()
    );
}

#[test]
fn fee_estimate_arguments_are_bounded() {
    let spec =
        wallet_fee_estimate(&wallet(), &source(), 20, 200, 250, 0, &pw("aaaaaaaaaaaa")).unwrap();
    for expected in [
        "fee-estimate",
        "--blocks",
        "20",
        "--samples",
        "200",
        "--tx-bytes",
        "250",
        "--floor-atoms",
        "0",
    ] {
        assert!(spec.args.iter().any(|arg| arg == expected), "{expected}");
    }
    assert!(!spec.args.iter().any(|arg| arg == "--external"));
    assert!(
        wallet_fee_estimate(&wallet(), &source(), 0, 200, 250, 0, &pw("aaaaaaaaaaaa")).is_err()
    );
    assert!(wallet_fee_estimate(&wallet(), &source(), 20, 200, 0, 0, &pw("aaaaaaaaaaaa")).is_err());
}

const PRIVATE_MAIN: &str =
    "monz1qypgluecd9cuke9cuaufjzxa367hm6f2drjcdg6dhrl2nx006gqkltnkw5904elwjstyd09e6zseag";
const PRIVATE_TEST: &str =
    "testmonz1qypgluecd9cuke9cuaufjzxa367hm6f2drjcdg6dhrl2nx006gqkltnkw5904elwjstyd09e9eqypq";

fn nullifier(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

fn note(byte: u8, atoms: u64, reserved: bool) -> PrivateNote {
    PrivateNote {
        nullifier: nullifier(byte),
        atoms,
        reserved,
    }
}

fn shielded_good() -> ShieldedRequest {
    ShieldedRequest {
        network: Network::Test,
        validated_tip: "44".repeat(32),
        nullifiers: vec![nullifier(1)],
        input_atoms: 100,
        recipient: PRIVATE_TEST.into(),
        amount_atoms: 60,
        fee_atoms: 10,
        expiry_height: 500,
    }
}

#[test]
fn shielded_request_json_matches_the_cli_schema_exactly() {
    let request = ShieldedRequest {
        network: Network::Regtest,
        validated_tip: "44".repeat(32),
        nullifiers: vec![nullifier(1), nullifier(2)],
        input_atoms: 300,
        recipient: SOLO_REGTEST_PRIVATE.into(),
        amount_atoms: 120,
        fee_atoms: 10,
        expiry_height: 500,
    };
    let value: serde_json::Value = serde_json::from_str(&request.to_json().unwrap()).unwrap();
    assert_eq!(
        value,
        serde_json::json!({
            "version": 1,
            "validated_tip": "44".repeat(32),
            "funding": {"pool": "private", "inputs": [nullifier(1), nullifier(2)]},
            "payments": [{"address": SOLO_REGTEST_PRIVATE, "amount_atoms": "120"}],
            "fee_atoms": "10",
            "expiry_height": 500,
            "change": "private",
            "service": null
        })
    );
    assert_eq!(FundingPool::default(), FundingPool::Transparent);
}

#[test]
fn shielded_request_rejects_malformed_duplicate_and_mismatched_inputs() {
    let good = shielded_good();
    assert!(good.to_json().is_ok());

    let mut duplicate = good.clone();
    duplicate.nullifiers.push(nullifier(1));
    assert!(duplicate.to_json().is_err());

    let mut malformed = good.clone();
    malformed.nullifiers = vec!["AB".repeat(32)];
    assert!(malformed.to_json().is_err());

    let mut empty = good.clone();
    empty.nullifiers.clear();
    assert!(empty.to_json().is_err());

    let mut many = good.clone();
    many.nullifiers = (0..33u8).map(nullifier).collect();
    assert!(many.to_json().is_err());

    let mut transparent = good.clone();
    transparent.recipient = SOLO_TEST.into();
    assert!(transparent.to_json().is_err());

    let mut wrong_network = good.clone();
    wrong_network.network = Network::Regtest;
    assert!(wrong_network.to_json().is_err());

    let mut zero = good.clone();
    zero.amount_atoms = 0;
    assert!(zero.to_json().is_err());

    let mut no_fee = good.clone();
    no_fee.fee_atoms = 0;
    assert!(no_fee.to_json().is_err());

    let mut no_expiry = good.clone();
    no_expiry.expiry_height = 0;
    assert!(no_expiry.to_json().is_err());

    let mut short = good.clone();
    short.input_atoms = 69;
    assert!(short.to_json().is_err());

    let mut bad_tip = good.clone();
    bad_tip.validated_tip = "44".into();
    assert!(bad_tip.to_json().is_err());

    let mut overflow = good;
    overflow.amount_atoms = u64::MAX;
    overflow.fee_atoms = 1;
    overflow.input_atoms = u64::MAX;
    assert!(overflow.to_json().is_err());
}

#[test]
fn shielded_recipient_must_be_private_on_the_same_network() {
    assert!(validate_private_recipient(SOLO_REGTEST_PRIVATE, Network::Regtest).is_ok());
    assert!(validate_private_recipient(PRIVATE_TEST, Network::Test).is_ok());
    assert!(validate_private_recipient(PRIVATE_MAIN, Network::Main).is_ok());

    assert!(validate_private_recipient(SOLO_REGTEST_PRIVATE, Network::Test).is_err());
    assert!(validate_private_recipient(PRIVATE_TEST, Network::Main).is_err());
    assert!(validate_private_recipient(PRIVATE_MAIN, Network::Regtest).is_err());

    assert!(validate_private_recipient(SOLO_REGTEST, Network::Regtest).is_err());
    assert!(validate_private_recipient(SOLO_TEST, Network::Test).is_err());

    let truncated = &SOLO_REGTEST_PRIVATE[..SOLO_REGTEST_PRIVATE.len() - 1];
    let padded = format!(" {SOLO_REGTEST_PRIVATE}");
    for bad in ["", "rmonz1fixture", truncated, padded.as_str()] {
        assert!(
            validate_private_recipient(bad, Network::Regtest).is_err(),
            "{bad}"
        );
    }
}

#[test]
fn private_inventory_is_parsed_fail_closed() {
    let value = serde_json::json!({
        "private": [
            {"nullifier": nullifier(1), "amount_atoms": "700", "reserved": false},
            {"nullifier": nullifier(2), "amount_atoms": "5", "reserved": true},
        ]
    });
    let notes = parse_private_notes(&value).unwrap();
    assert_eq!(notes, vec![note(1, 700, false), note(2, 5, true)]);
    assert!(notes[0].selectable());
    assert!(!notes[1].selectable());

    let malformed = [
        serde_json::json!({"nullifier": nullifier(0xab).to_uppercase(), "amount_atoms": "1", "reserved": false}),
        serde_json::json!({"nullifier": "ab".repeat(31), "amount_atoms": "1", "reserved": false}),
        serde_json::json!({"nullifier": nullifier(4), "amount_atoms": 1, "reserved": false}),
        serde_json::json!({"nullifier": nullifier(4), "amount_atoms": "+1", "reserved": false}),
        serde_json::json!({"nullifier": nullifier(4), "amount_atoms": "18446744073709551616", "reserved": false}),
        serde_json::json!({"nullifier": nullifier(4), "amount_atoms": "1", "reserved": "no"}),
        serde_json::json!({"nullifier": nullifier(4), "reserved": false}),
    ];
    for bad in malformed {
        let value = serde_json::json!({"private": [bad]});
        assert!(parse_private_notes(&value).is_err(), "{value}");
    }

    let duplicate = serde_json::json!({"private": [
        {"nullifier": nullifier(1), "amount_atoms": "1", "reserved": false},
        {"nullifier": nullifier(1), "amount_atoms": "2", "reserved": true},
    ]});
    assert!(parse_private_notes(&duplicate).is_err());
    assert!(parse_private_notes(&serde_json::json!({"transparent": []})).is_err());
    assert!(
        parse_private_notes(&serde_json::json!({"private": []}))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn shielded_plan_spends_only_selected_unreserved_notes_with_checked_sums() {
    let notes = vec![note(1, 700, false), note(2, 300, false), note(3, 50, true)];
    let plan = plan_shielded(&notes, &[nullifier(1)], 600, 10, 20).unwrap();
    assert_eq!(plan.nullifiers, vec![nullifier(1)]);
    assert_eq!(
        (
            plan.selected_atoms,
            plan.amount_atoms,
            plan.fee_atoms,
            plan.change_atoms
        ),
        (700, 600, 10, 90)
    );

    assert!(plan_shielded(&notes, &[nullifier(3)], 1, 1, 1).is_err());
    assert!(plan_shielded(&notes, &[nullifier(9)], 1, 1, 1).is_err());
    assert!(plan_shielded(&notes, &[nullifier(1), nullifier(1)], 1, 1, 1).is_err());
    assert!(plan_shielded(&notes, &[], 1, 1, 1).is_err());
    let many: Vec<String> = (0..33u8).map(nullifier).collect();
    assert!(plan_shielded(&notes, &many, 1, 1, 1).is_err());

    assert!(plan_shielded(&notes, &[nullifier(1)], 700, 1, 1).is_err());
    assert!(plan_shielded(&notes, &[nullifier(1)], 0, 1, 1).is_err());
    assert!(plan_shielded(&notes, &[nullifier(1)], 1, 0, 1).is_err());
    assert!(plan_shielded(&notes, &[nullifier(1)], 1, 2, 1).is_err());

    let huge = vec![note(1, u64::MAX, false), note(2, 1, false)];
    assert!(plan_shielded(&huge, &[nullifier(1), nullifier(2)], 1, 1, 1).is_err());
    assert!(plan_shielded(&notes, &[nullifier(1)], u64::MAX, u64::MAX, u64::MAX).is_err());
}
