//! Authenticated lookup never activates a node, listener or signal handler.
use super::*;

fn values(root: &Path, cp: Checkpoint, transaction: [u8; 32]) -> Vec<String> {
    let mut values = args("transaction-get", root, cp);
    values.extend([
        "--manifest".into(),
        "node.json".into(),
        "--transaction".into(),
        hex(&transaction),
    ]);
    values
}

#[test]
fn transaction_get_requires_chain_and_exact_id_without_runtime_or_file_authority() {
    let (dir, cp) = fixture();
    let good = values(dir.path(), cp, [3; 32]);
    assert!(Command::parse(good.clone().into_iter().map(OsString::from)).is_ok());
    for flag in ["--transaction", "--manifest"] {
        let mut bad = good.clone();
        let index = bad.iter().position(|v| v == flag).unwrap();
        bad.drain(index..index + 2);
        assert!(Command::parse(bad.into_iter().map(OsString::from)).is_err());
    }
    for bad in [
        vec!["--enable-network"],
        vec!["--submission-inbox", "local"],
        vec!["--block-file", "out.monb"],
        vec!["--transaction", "bad"],
    ] {
        let mut values = good.clone();
        values.extend(bad.into_iter().map(str::to_owned));
        assert!(Command::parse(values.into_iter().map(OsString::from)).is_err());
    }
}

fn open(root: &Path, cp: Checkpoint) -> DurableChain<V6Verifier> {
    let manifest = manifest::parse(&fs::read(root.join("node.json")).unwrap(), cp.profile).unwrap();
    DurableChain::open(
        &root.join(manifest.file),
        manifest.config,
        manifest.root,
        V6Verifier,
        1_000_000,
    )
    .unwrap()
}
fn append(root: &Path, cp: Checkpoint, parent: [u8; 32], timestamp: u32) -> [u8; 32] {
    let mut source = open(root, cp);
    let template = source
        .chain()
        .unwrap()
        .build_template(parent, u64::from(timestamp), 1_000_000, vec![], |p| {
            Ok(crate::tests::coinbase(
                p,
                if p.height == 1 { 100 } else { 0 },
            ))
        })
        .unwrap();
    source.submit(template.block, 1_000_000).unwrap().id
}
fn call(values: Vec<String>, input: Vec<u8>, output: &mut impl Write) -> Result<(), Error> {
    execute_with(
        parse(values),
        &mut Cursor::new(input),
        output,
        &Arc::new(AtomicBool::new(false)),
        |_| panic!("lookup installed signals"),
        |_, _, _| panic!("lookup activated transport"),
    )
}
fn run(values: Vec<String>) -> serde_json::Value {
    let mut output = Vec::new();
    call(values, frame(OLD), &mut output).unwrap();
    serde_json::from_slice(&output).unwrap()
}

#[test]
fn authenticated_lookup_returns_exact_bytes_depth_and_checkpoint_scope_without_activation() {
    let _serial = crate::tests::REAL.lock().unwrap();
    let dir = private_tempdir();
    let cp = chain_fixture(dir.path());
    let first = append(dir.path(), cp, [3; 32], 1105);
    let second = append(dir.path(), cp, first, 1210);
    let mut chain = open(dir.path(), cp);
    let bytes = chain.stored_block(first).unwrap().transactions.remove(0);
    let id = monario_v6::transaction_id(&bytes).unwrap();
    let pin = chain
        .create_state_checkpoint(STATE_CHECKPOINT_LIMITS)
        .unwrap()
        .commitment();
    chain.checkpoint().unwrap();
    drop(chain);
    let identity = fs::read(dir.path().join("node.monp")).unwrap();
    for checkpoint in [None, Some(pin)] {
        let mut values = values(dir.path(), cp, id);
        if let Some(pin) = checkpoint {
            values.extend(["--checkpoint".into(), hex(&pin)]);
        }
        let receipt = run(values);
        assert_eq!(receipt["confirmed"], true);
        let text = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(receipt["transaction_hex"], text);
        assert_eq!(receipt["confirmations"], "2");
        assert_eq!(receipt["confirmation_block"], hex(&first));
        assert_eq!(receipt["validated_tip"], hex(&second));
        assert_eq!(receipt["full_chain_replay"], checkpoint.is_none());
        assert_eq!(receipt["network_started"], false);
        assert_eq!(receipt["exact_payload_authenticated"], true);
    }
    let absent = run(values(dir.path(), cp, [99; 32]));
    assert_eq!(absent["confirmed"], false);
    assert!(absent["transaction_hex"].is_null());
    assert!(absent["confirmation_block"].is_null());
    assert_eq!(absent["confirmations"], "0");
    assert_eq!(fs::read(dir.path().join("node.monp")).unwrap(), identity);
    for flag in ["--profile", "--public-key"] {
        let mut invalid = values(dir.path(), cp, id);
        let at = invalid.iter().position(|v| v == flag).unwrap() + 1;
        invalid[at] = hex(&[0; 32]);
        let mut output = Vec::new();
        assert!(call(invalid, frame(OLD), &mut output).is_err());
        assert!(output.is_empty());
    }
    let mut invalid = values(dir.path(), cp, id);
    invalid.extend(["--checkpoint".into(), hex(&[0; 32])]);
    let mut output = Vec::new();
    assert!(call(invalid, frame(OLD), &mut output).is_err());
    assert!(output.is_empty());
    let mut wrong = frame(OLD);
    wrong[2] ^= 1;
    assert!(call(values(dir.path(), cp, id), wrong, &mut output).is_err());
    assert!(output.is_empty());
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    assert_eq!(
        call(values(dir.path(), cp, id), frame(OLD), &mut Broken),
        Err(Error::Output)
    );
    assert_eq!(run(values(dir.path(), cp, id))["confirmations"], "2");
}

#[test]
fn transaction_get_crash_worker() {
    let Some(root) = std::env::var_os("MONAR_TRANSACTION_GET_CRASH_DIR") else {
        return;
    };
    let root = Path::new(&root);
    let cp = cp(&fs::read(root.join("pins.json")).unwrap());
    let transaction = hash(&std::env::var("MONAR_TRANSACTION_GET_CRASH_ID").unwrap()).unwrap();
    let before = std::env::var("MONAR_TRANSACTION_GET_CRASH_PHASE").unwrap() == "before";
    struct ExitRead;
    impl Read for ExitRead {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            std::process::exit(95)
        }
    }
    struct ExitOutput(File);
    impl Write for ExitOutput {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.write_all(&bytes[..bytes.len() / 2]).unwrap();
            self.0.sync_all().unwrap();
            std::process::exit(96)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut input: Box<dyn Read> = if before {
        Box::new(ExitRead)
    } else {
        Box::new(Cursor::new(frame(OLD)))
    };
    execute_with(
        parse(values(root, cp, transaction)),
        &mut input,
        &mut ExitOutput(File::create(root.join("partial.json")).unwrap()),
        &Arc::new(AtomicBool::new(false)),
        |_| panic!("lookup installed signals"),
        |_, _, _| panic!("lookup started transport"),
    )
    .unwrap();
    panic!("crash hook did not run");
}

#[test]
fn process_death_before_authentication_and_mid_receipt_leaves_validated_history_recoverable() {
    let _serial = crate::tests::REAL.lock().unwrap();
    let dir = private_tempdir();
    let cp = chain_fixture(dir.path());
    let first = append(dir.path(), cp, [3; 32], 1105);
    let chain = open(dir.path(), cp);
    let original = chain.authenticated_block_bytes(first).unwrap();
    let bytes = &chain.stored_block(first).unwrap().transactions[0];
    let id = monario_v6::transaction_id(bytes).unwrap();
    drop(chain);
    let mut pins = Vec::new();
    receipt(cp, &mut pins).unwrap();
    fs::write(dir.path().join("pins.json"), pins).unwrap();
    for (phase, code) in [("before", 95), ("partial", 96)] {
        let status = Process::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "cli::tests::transaction_get::transaction_get_crash_worker",
                "--nocapture",
            ])
            .env("MONAR_TRANSACTION_GET_CRASH_DIR", dir.path())
            .env("MONAR_TRANSACTION_GET_CRASH_ID", hex(&id))
            .env("MONAR_TRANSACTION_GET_CRASH_PHASE", phase)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(code));
        let partial = fs::read(dir.path().join("partial.json")).unwrap();
        assert_eq!(partial.is_empty(), phase == "before");
        assert!(serde_json::from_slice::<serde_json::Value>(&partial).is_err());
        let chain = open(dir.path(), cp);
        assert_eq!(chain.chain().unwrap().tip(), first);
        assert_eq!(chain.authenticated_block_bytes(first).unwrap(), original);
        drop(chain);
        assert_eq!(run(values(dir.path(), cp, id))["confirmations"], "1");
    }
}
