//! Archive checks never authorize runtime, file export or an implicit cursor.
use super::*;

fn values(root: &Path, cp: Checkpoint, after: [u8; 32]) -> Vec<String> {
    let mut values = args("archive-audit", root, cp);
    values.extend([
        "--manifest".into(),
        "node.json".into(),
        "--after".into(),
        hex(&after),
    ]);
    values
}
#[test]
fn archive_audit_requires_manifest_and_cursor_and_rejects_unrelated_authority() {
    let (dir, cp) = fixture();
    let good = values(dir.path(), cp, [3; 32]);
    assert!(Command::parse(good.clone().into_iter().map(OsString::from)).is_ok());
    for flag in ["--manifest", "--after"] {
        let mut bad = good.clone();
        let index = bad.iter().position(|v| v == flag).unwrap();
        bad.drain(index..index + 2);
        assert!(Command::parse(bad.into_iter().map(OsString::from)).is_err());
    }
    for extra in [
        vec!["--enable-network"],
        vec!["--submission-inbox", "local"],
        vec!["--block-file", "page.monb"],
        vec!["--transaction", "00"],
        vec!["--after", "bad"],
    ] {
        let mut bad = good.clone();
        bad.extend(extra.into_iter().map(str::to_owned));
        assert!(Command::parse(bad.into_iter().map(OsString::from)).is_err());
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
fn append(root: &Path, cp: Checkpoint, parent: [u8; 32], time: u32) -> [u8; 32] {
    let mut source = open(root, cp);
    let template = source
        .chain()
        .unwrap()
        .build_template(parent, u64::from(time), 1_000_000, vec![], |p| {
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
        |_| panic!("archive audit installed signals"),
        |_, _, _| panic!("archive audit activated transport"),
    )
}
fn run(values: Vec<String>) -> serde_json::Value {
    let mut out = Vec::new();
    call(values, frame(OLD), &mut out).unwrap();
    serde_json::from_slice(&out).unwrap()
}

#[test]
fn authenticated_pages_preserve_scope_pins_and_state_and_failed_receipts_retry_identically() {
    let _serial = crate::tests::REAL.lock().unwrap();
    let dir = private_tempdir();
    let cp = chain_fixture(dir.path());
    let first = append(dir.path(), cp, [3; 32], 1105);
    let best = append(dir.path(), cp, first, 1210);
    let mut chain = open(dir.path(), cp);
    let first_bytes = chain.authenticated_block_bytes(first).unwrap();
    let total = first_bytes.len() + chain.authenticated_block_bytes(best).unwrap().len();
    let pin = chain
        .create_state_checkpoint(STATE_CHECKPOINT_LIMITS)
        .unwrap()
        .commitment();
    chain.checkpoint().unwrap();
    drop(chain);
    let identity = fs::read(dir.path().join("node.monp")).unwrap();
    let values = values(dir.path(), cp, [3; 32]);
    for checkpoint in [None, Some(pin)] {
        let mut values = values.clone();
        if let Some(pin) = checkpoint {
            values.extend(["--checkpoint".into(), hex(&pin)]);
        }
        let result = run(values);
        assert_eq!(result["blocks"], 2);
        assert_eq!(result["bytes"], total);
        assert_eq!(result["after"], hex(&[3; 32]));
        assert_eq!(result["end"], hex(&best));
        assert_eq!(result["validated_tip"], hex(&best));
        assert_eq!(result["at_tip"], true);
        assert_eq!(result["full_chain_replay"], checkpoint.is_none());
        assert_eq!(result["network_started"], false);
        assert_eq!(result["scope"], "canonical-successors-only");
        assert!(result.get("whole_archive_verified").is_none());
    }
    let mut empty = values.clone();
    *empty.last_mut().unwrap() = hex(&best);
    let result = run(empty);
    assert_eq!(result["blocks"], 0);
    assert_eq!(result["bytes"], 0);
    assert_eq!(result["at_tip"], true);
    for flag in ["--profile", "--public-key", "--after"] {
        let mut bad = values.clone();
        let at = bad.iter().position(|v| v == flag).unwrap() + 1;
        bad[at] = hex(&[99; 32]);
        let mut out = Vec::new();
        assert!(call(bad, frame(OLD), &mut out).is_err());
        assert!(out.is_empty());
    }
    let mut bad = values.clone();
    bad.extend(["--checkpoint".into(), hex(&[0; 32])]);
    let mut out = Vec::new();
    assert!(call(bad, frame(OLD), &mut out).is_err());
    assert!(out.is_empty());
    let mut wrong = frame(OLD);
    wrong[2] ^= 1;
    assert!(call(values.clone(), wrong, &mut out).is_err());
    assert!(out.is_empty());
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
        call(values.clone(), frame(OLD), &mut Broken),
        Err(Error::Output)
    );
    assert_eq!(run(values)["bytes"], total);
    let chain = open(dir.path(), cp);
    assert_eq!(chain.chain().unwrap().tip(), best);
    assert_eq!(chain.authenticated_block_bytes(first).unwrap(), first_bytes);
    drop(chain);
    assert_eq!(fs::read(dir.path().join("node.monp")).unwrap(), identity);
}

#[test]
fn archive_audit_crash_worker() {
    let Some(root) = std::env::var_os("MONAR_ARCHIVE_AUDIT_CRASH_DIR") else {
        return;
    };
    let root = Path::new(&root);
    let cp = cp(&fs::read(root.join("pins.json")).unwrap());
    struct ExitRead;
    impl Read for ExitRead {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            std::process::exit(93)
        }
    }
    struct ExitOutput(File);
    impl Write for ExitOutput {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.write_all(&bytes[..bytes.len() / 2]).unwrap();
            self.0.sync_all().unwrap();
            std::process::exit(94)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let before = std::env::var("MONAR_ARCHIVE_AUDIT_CRASH_PHASE").unwrap() == "before";
    let mut input: Box<dyn Read> = if before {
        Box::new(ExitRead)
    } else {
        Box::new(Cursor::new(frame(OLD)))
    };
    execute_with(
        parse(values(root, cp, [3; 32])),
        &mut input,
        &mut ExitOutput(File::create(root.join("partial.json")).unwrap()),
        &Arc::new(AtomicBool::new(false)),
        |_| panic!("audit installed signals"),
        |_, _, _| panic!("audit started transport"),
    )
    .unwrap();
    panic!("crash hook did not execute");
}

#[test]
fn abrupt_exit_before_credentials_and_mid_receipt_preserves_history_without_saving_audit_trust() {
    let _serial = crate::tests::REAL.lock().unwrap();
    let dir = private_tempdir();
    let cp = chain_fixture(dir.path());
    let first = append(dir.path(), cp, [3; 32], 1105);
    let original = open(dir.path(), cp)
        .authenticated_block_bytes(first)
        .unwrap();
    let mut pins = Vec::new();
    receipt(cp, &mut pins).unwrap();
    fs::write(dir.path().join("pins.json"), pins).unwrap();
    for (phase, code) in [("before", 93), ("partial", 94)] {
        let status = Process::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "cli::tests::archive_audit::archive_audit_crash_worker",
                "--nocapture",
            ])
            .env("MONAR_ARCHIVE_AUDIT_CRASH_DIR", dir.path())
            .env("MONAR_ARCHIVE_AUDIT_CRASH_PHASE", phase)
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
        let result = run(values(dir.path(), cp, [3; 32]));
        assert_eq!(result["blocks"], 1);
        assert_eq!(result["end"], hex(&first));
    }
}
