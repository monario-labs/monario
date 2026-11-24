use super::*;

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
                address: "rmont1example".into(),
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
        address: "testmont1example".into(),
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
    bad_stop.address = "testmont1example".into();
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
fn pool_modes_build_bounded_flags_and_reject_missing_credentials() {
    let pool = PoolSpec {
        address: OFFICIAL_POOL_ADDRESS.into(),
        public_key: "11".repeat(32),
        client: "22".repeat(16),
        token_file: "pool.token".into(),
    };
    let mut official = MiningConfig {
        address: "testmont1example".into(),
        workers: 1,
        network: Network::Test,
        pool_mode: PoolMode::Official,
        pool: Some(pool.clone()),
    };
    let spec = node_mine(
        &node(),
        "chain.json",
        "",
        "gui-status.json",
        "gui.stop",
        &official,
        false,
        &pw("aaaaaaaaaaaa"),
    )
    .unwrap();
    assert!(
        spec.args
            .windows(2)
            .any(|w| w[0] == "--pool-mode" && w[1] == "official")
    );
    assert!(!spec.args.iter().any(|arg| arg == "--pool-address"));
    assert!(
        spec.args
            .windows(2)
            .any(|w| w == ["--miner-network", "test"])
    );
    assert!(!spec.args.iter().any(|arg| arg == "--enable-network"));
    assert!(
        spec.args
            .windows(2)
            .any(|w| w[0] == "--pool-token-file" && w[1] == "pool.token")
    );

    let mut custom = official.clone();
    custom.pool_mode = PoolMode::Custom;
    custom.pool.as_mut().unwrap().address = "127.0.0.1:1234".into();
    let spec = node_mine(
        &node(),
        "chain.json",
        "",
        "gui-status.json",
        "gui.stop",
        &custom,
        false,
        &pw("aaaaaaaaaaaa"),
    )
    .unwrap();
    assert!(spec.args.windows(2).any(|w| w == ["--pool-mode", "custom"]));
    assert!(!spec.args.iter().any(|arg| arg == "--enable-network"));
    assert!(
        spec.args
            .windows(2)
            .any(|w| w[0] == "--pool-address" && w[1] == "127.0.0.1:1234")
    );

    // Solo must not carry credentials.
    let mut solo = custom.clone();
    solo.pool_mode = PoolMode::Solo;
    assert!(
        node_mine(
            &node(),
            "chain.json",
            "",
            "gui-status.json",
            "gui.stop",
            &solo,
            false,
            &pw("aaaaaaaaaaaa"),
        )
        .is_err()
    );
    // A pool mode without credentials fails closed.
    let mut missing = custom.clone();
    missing.pool = None;
    assert!(
        node_mine(
            &node(),
            "chain.json",
            "",
            "gui-status.json",
            "gui.stop",
            &missing,
            false,
            &pw("aaaaaaaaaaaa"),
        )
        .is_err()
    );
    // Bounded credential and endpoint encodings.
    for (field, value, valid) in [
        ("_public", "jj".repeat(32), false),
        ("_public", "11".repeat(31), false),
        ("_client", "zz".repeat(16), false),
        ("_token", "pool.json".into(), false),
        ("_address", "127.0.0.1:0".into(), false),
        ("_address", "no-port".into(), false),
        ("_address", "127.0.0.1:1234".into(), true),
    ] {
        let mut config = custom.clone();
        let pool = config.pool.as_mut().unwrap();
        match field {
            "_public" => pool.public_key = value.clone(),
            "_client" => pool.client = value.clone(),
            "_token" => pool.token_file = value.clone(),
            _ => pool.address = value.clone(),
        }
        assert_eq!(config.validate().is_ok(), valid, "{field}:{value}");
    }
    // The official host is fixed; a different address is rejected.
    official.pool.as_mut().unwrap().address = "127.0.0.1:1234".into();
    assert!(official.validate().is_err());
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
