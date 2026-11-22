//! Offline commands never install signals or activate a transport.
use super::*;

fn values(
    action: &str,
    root: &Path,
    cp: Checkpoint,
    file: &str,
    after: Option<[u8; 32]>,
) -> Vec<String> {
    let mut values = args(action, root, cp);
    values.extend([
        "--manifest".into(),
        "node.json".into(),
        "--block-file".into(),
        file.into(),
    ]);
    if let Some(after) = after {
        values.extend(["--after".into(), hex(&after)]);
    }
    values
}

#[test]
fn arguments_require_jailed_files_and_explicit_export_cursor_without_network_flags() {
    let (dir, cp) = fixture();
    for action in ["blocks-import", "blocks-export"] {
        let after = (action == "blocks-export").then_some([3; 32]);
        let good = values(action, dir.path(), cp, "page.monb", after);
        assert!(Command::parse(good.clone().into_iter().map(OsString::from)).is_ok());
        for extra in [
            vec!["--enable-network", ""],
            vec!["--submission-inbox", "local"],
        ] {
            let mut bad = good.clone();
            bad.extend(
                extra
                    .into_iter()
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned),
            );
            assert!(Command::parse(bad.into_iter().map(OsString::from)).is_err());
        }
        for bad in [
            "../page.monb",
            "a/b.monb",
            "a\\b.monb",
            "CON.monb",
            "page.json",
            ".page.monb",
        ] {
            assert!(
                Command::parse(
                    values(action, dir.path(), cp, bad, after)
                        .into_iter()
                        .map(OsString::from)
                )
                .is_err()
            );
        }
    }
    assert!(
        Command::parse(
            values("blocks-export", dir.path(), cp, "page.monb", None)
                .into_iter()
                .map(OsString::from)
        )
        .is_err()
    );
    assert!(
        Command::parse(
            values("blocks-import", dir.path(), cp, "page.monb", Some([3; 32]))
                .into_iter()
                .map(OsString::from)
        )
        .is_err()
    );
}

fn call(
    action: &str,
    root: &Path,
    cp: Checkpoint,
    file: &str,
    after: Option<[u8; 32]>,
    output: &mut impl Write,
) -> Result<(), Error> {
    execute_with(
        parse(values(action, root, cp, file, after)),
        &mut Cursor::new(frame(OLD)),
        output,
        &Arc::new(AtomicBool::new(false)),
        |_| panic!("offline command installed signals"),
        |_, _, _| panic!("offline command activated transport"),
    )
}
fn run(
    action: &str,
    root: &Path,
    cp: Checkpoint,
    file: &str,
    after: Option<[u8; 32]>,
) -> Result<serde_json::Value, Error> {
    let mut out = Vec::new();
    call(action, root, cp, file, after, &mut out)?;
    Ok(serde_json::from_slice(&out).unwrap())
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
    let mut chain = open(root, cp);
    let c = chain.chain().unwrap();
    let template = c
        .build_template(parent, u64::from(timestamp), 1_000_000, vec![], |p| {
            Ok(crate::tests::coinbase(
                p,
                if p.height == 1 { 100 } else { 0 },
            ))
        })
        .unwrap();
    let id = chain.submit(template.block, 1_000_000).unwrap().id;
    chain.checkpoint().unwrap();
    id
}

#[test]
fn authenticated_commands_copy_reorganize_and_retry_without_network_or_identity_changes() {
    let _serial = crate::tests::REAL.lock().unwrap();
    let source = private_tempdir();
    let scp = chain_fixture(source.path());
    let first = append(source.path(), scp, [3; 32], 1105);
    let old = append(source.path(), scp, first, 1210);
    let before = fs::read(source.path().join("node.monp")).unwrap();
    let page = run(
        "blocks-export",
        source.path(),
        scp,
        "page.monb",
        Some([3; 32]),
    )
    .unwrap();
    assert_eq!(page["end"], hex(&old));
    assert_eq!(page["blocks"], 2);
    assert_eq!(page["network_started"], false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(source.path().join("page.monb"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let dest = private_tempdir();
    let dcp = chain_fixture(dest.path());
    fs::copy(
        source.path().join("page.monb"),
        dest.path().join("page.monb"),
    )
    .unwrap();
    let imported = run("blocks-import", dest.path(), dcp, "page.monb", None).unwrap();
    assert_eq!(imported["accepted"], 2);
    assert_eq!(imported["validated_tip"], hex(&old));
    let side = append(source.path(), scp, first, 1151);
    let tip = append(source.path(), scp, side, 1315);
    run(
        "blocks-export",
        source.path(),
        scp,
        "fork.monb",
        Some(first),
    )
    .unwrap();
    fs::copy(
        source.path().join("fork.monb"),
        dest.path().join("fork.monb"),
    )
    .unwrap();
    let result = run("blocks-import", dest.path(), dcp, "fork.monb", None).unwrap();
    assert_eq!(result["accepted"], 2);
    assert_eq!(result["validated_tip"], hex(&tip));
    let result = run("blocks-import", dest.path(), dcp, "fork.monb", None).unwrap();
    assert_eq!(result["accepted"], 0);
    assert_eq!(result["known"], 2);
    assert_eq!(fs::read(source.path().join("node.monp")).unwrap(), before);
    assert_eq!(
        run("blocks-export", source.path(), scp, "stale.monb", Some(old)).err(),
        Some(Error::Transfer)
    );
}

#[test]
fn authentication_existing_chain_file_bounds_links_and_no_clobber_fail_closed() {
    let dir = private_tempdir();
    let cp = chain_fixture(dir.path());
    let mut out = Vec::new();
    assert_eq!(
        execute_with(
            parse(values(
                "blocks-export",
                dir.path(),
                cp,
                "page.monb",
                Some([3; 32])
            )),
            &mut Cursor::new(frame(NEW)),
            &mut out,
            &Arc::new(AtomicBool::new(false)),
            |_| panic!("signals"),
            |_, _, _| panic!("network")
        ),
        Err(Error::Credentials)
    );
    assert!(!dir.path().join("page.monb").exists());
    run("blocks-export", dir.path(), cp, "page.monb", Some([3; 32])).unwrap();
    let bytes = fs::read(dir.path().join("page.monb")).unwrap();
    assert!(run("blocks-export", dir.path(), cp, "page.monb", Some([3; 32])).is_err());
    assert_eq!(fs::read(dir.path().join("page.monb")).unwrap(), bytes);
    fs::create_dir(dir.path().join("folder.monb")).unwrap();
    assert_eq!(
        run("blocks-import", dir.path(), cp, "folder.monb", None).err(),
        Some(Error::Configuration)
    );
    let file = fs::File::create(dir.path().join("huge.monb")).unwrap();
    file.set_len(74 + 128 * (4 + 5_000_000) + 1).unwrap();
    drop(file);
    assert_eq!(
        run("blocks-import", dir.path(), cp, "huge.monb", None).err(),
        Some(Error::Configuration)
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        symlink("page.monb", dir.path().join("link.monb")).unwrap();
        assert!(run("blocks-import", dir.path(), cp, "link.monb", None).is_err());
        assert!(run("blocks-export", dir.path(), cp, "link.monb", Some([3; 32])).is_err());
        fs::hard_link(dir.path().join("page.monb"), dir.path().join("hard.monb")).unwrap();
        assert!(run("blocks-import", dir.path(), cp, "hard.monb", None).is_err());
    }
    fs::remove_file(dir.path().join("chain.sqlite")).unwrap();
    for action in ["blocks-import", "blocks-export"] {
        assert!(
            run(
                action,
                dir.path(),
                cp,
                "absent.monb",
                (action == "blocks-export").then_some([3; 32])
            )
            .is_err()
        );
        assert!(!dir.path().join("chain.sqlite").exists());
        assert!(!dir.path().join("absent.monb").exists());
    }
    let path = dir.path().join("chain.sqlite");
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch("PRAGMA application_id=1297042993; PRAGMA user_version=1;")
        .unwrap();
    drop(db);
    let forged = fs::read(&path).unwrap();
    for action in ["blocks-import", "blocks-export"] {
        assert_eq!(
            run(
                action,
                dir.path(),
                cp,
                "absent.monb",
                (action == "blocks-export").then_some([3; 32])
            )
            .err(),
            Some(Error::Storage)
        );
        assert_eq!(fs::read(&path).unwrap(), forged);
        assert!(!dir.path().join("absent.monb").exists());
    }
}

#[test]
fn malformed_stream_preserves_valid_prefix_and_checkpoint_retry_does_not_double_reward() {
    let _serial = crate::tests::REAL.lock().unwrap();
    let source = private_tempdir();
    let scp = chain_fixture(source.path());
    let first = append(source.path(), scp, [3; 32], 1105);
    let tip = append(source.path(), scp, first, 1210);
    run(
        "blocks-export",
        source.path(),
        scp,
        "page.monb",
        Some([3; 32]),
    )
    .unwrap();
    let packet = fs::read(source.path().join("page.monb")).unwrap();
    let first_len = u32::from_le_bytes(packet[74..78].try_into().unwrap()) as usize;
    let dest = private_tempdir();
    let dcp = chain_fixture(dest.path());
    fs::write(dest.path().join("page.monb"), &packet[..78 + first_len + 2]).unwrap();
    assert_eq!(
        run("blocks-import", dest.path(), dcp, "page.monb", None).err(),
        Some(Error::Transfer)
    );
    let mut d = open(dest.path(), dcp);
    assert_eq!(d.chain().unwrap().tip(), first);
    let pin = d.create_state_checkpoint(STATE_CHECKPOINT_LIMITS).unwrap();
    d.checkpoint().unwrap();
    drop(d);
    fs::write(dest.path().join("page.monb"), &packet).unwrap();
    let mut command = values("blocks-import", dest.path(), dcp, "page.monb", None);
    command.extend(["--checkpoint".into(), hex(&pin.commitment())]);
    let mut out = Vec::new();
    execute_with(
        parse(command),
        &mut Cursor::new(frame(OLD)),
        &mut out,
        &Arc::new(AtomicBool::new(false)),
        |_| panic!("signals"),
        |_, _, _| panic!("network"),
    )
    .unwrap();
    let result: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(result["accepted"], 1);
    assert_eq!(result["known"], 1);
    assert_eq!(result["validated_tip"], hex(&tip));
    assert_eq!(result["full_chain_replay"], false);
    assert_eq!(result["chain_checkpoint"], hex(&pin.commitment()));
}

#[test]
fn failed_receipt_output_keeps_export_and_import_commits_recoverable() {
    let _serial = crate::tests::REAL.lock().unwrap();
    let source = private_tempdir();
    let cp = chain_fixture(source.path());
    let tip = append(source.path(), cp, [3; 32], 1105);
    assert_eq!(
        call(
            "blocks-export",
            source.path(),
            cp,
            "page.monb",
            Some([3; 32]),
            &mut BrokenOutput
        ),
        Err(Error::Output)
    );
    assert!(source.path().join("page.monb").exists());
    assert!(
        run(
            "blocks-export",
            source.path(),
            cp,
            "page.monb",
            Some([3; 32])
        )
        .is_err()
    );
    let dest = private_tempdir();
    let dcp = chain_fixture(dest.path());
    fs::copy(
        source.path().join("page.monb"),
        dest.path().join("page.monb"),
    )
    .unwrap();
    assert_eq!(
        call(
            "blocks-import",
            dest.path(),
            dcp,
            "page.monb",
            None,
            &mut BrokenOutput
        ),
        Err(Error::Output)
    );
    let result = run("blocks-import", dest.path(), dcp, "page.monb", None).unwrap();
    assert_eq!(result["accepted"], 0);
    assert_eq!(result["known"], 1);
    assert_eq!(result["validated_tip"], hex(&tip));
}

#[test]
fn blocks_cli_crash_worker() {
    let Some(dir) = std::env::var_os("MONAR_BLOCKS_CLI_DIR") else {
        return;
    };
    let root = PathBuf::from(dir);
    let cp = Checkpoint {
        profile: hash(&std::env::var("MONAR_BLOCKS_CLI_PROFILE").unwrap()).unwrap(),
        public_key: hash(&std::env::var("MONAR_BLOCKS_CLI_KEY").unwrap()).unwrap(),
        revision: 0,
    };
    let action = std::env::var("MONAR_BLOCKS_CLI_ACTION").unwrap();
    let command = parse(values(
        &action,
        &root,
        cp,
        "page.monb",
        (action == "blocks-export").then_some([3; 32]),
    ));
    if std::env::var("MONAR_BLOCKS_CLI_PHASE").unwrap() == "before" {
        execute(
            command,
            &mut CrashInput {
                sent_prefix_byte: false,
            },
            &mut Vec::new(),
            &Arc::new(AtomicBool::new(true)),
        )
        .unwrap();
    } else {
        struct CrashOutput;
        impl Write for CrashOutput {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                std::process::exit(82)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                std::process::exit(82)
            }
        }
        execute(
            command,
            &mut Cursor::new(frame(OLD)),
            &mut CrashOutput,
            &Arc::new(AtomicBool::new(true)),
        )
        .unwrap();
    }
}

#[test]
fn process_death_before_credentials_and_after_committed_transfer_preserves_recoverable_state() {
    let _serial = crate::tests::REAL.lock().unwrap();
    let source = private_tempdir();
    let scp = chain_fixture(source.path());
    let tip = append(source.path(), scp, [3; 32], 1105);
    run(
        "blocks-export",
        source.path(),
        scp,
        "source.monb",
        Some([3; 32]),
    )
    .unwrap();
    for action in ["blocks-import", "blocks-export"] {
        for phase in ["before", "after"] {
            let dir = private_tempdir();
            let cp = chain_fixture(dir.path());
            if action == "blocks-import" {
                fs::copy(
                    source.path().join("source.monb"),
                    dir.path().join("page.monb"),
                )
                .unwrap();
            } else {
                append(dir.path(), cp, [3; 32], 1105);
            }
            let identity = fs::read(dir.path().join("node.monp")).unwrap();
            let result = Process::new(std::env::current_exe().unwrap())
                .args(["--exact", "cli::tests::blocks::blocks_cli_crash_worker"])
                .env("MONAR_BLOCKS_CLI_DIR", dir.path())
                .env("MONAR_BLOCKS_CLI_PROFILE", hex(&cp.profile))
                .env("MONAR_BLOCKS_CLI_KEY", hex(&cp.public_key))
                .env("MONAR_BLOCKS_CLI_ACTION", action)
                .env("MONAR_BLOCKS_CLI_PHASE", phase)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .unwrap();
            assert_eq!(result.code(), Some(if phase == "before" { 81 } else { 82 }));
            assert_eq!(fs::read(dir.path().join("node.monp")).unwrap(), identity);
            let d = open(dir.path(), cp);
            assert_eq!(
                d.chain().unwrap().tip(),
                if action == "blocks-import" && phase == "before" {
                    [3; 32]
                } else {
                    tip
                }
            );
            drop(d);
            if action == "blocks-export" {
                assert_eq!(dir.path().join("page.monb").exists(), phase == "after");
                if phase == "after" {
                    assert!(run(action, dir.path(), cp, "page.monb", Some([3; 32])).is_err());
                }
            } else {
                let receipt = run(action, dir.path(), cp, "page.monb", None).unwrap();
                assert_eq!(receipt["known"], u64::from(phase == "after"));
            }
        }
    }
}
