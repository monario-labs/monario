//! All activations use encrypted memory streams. OS signals target owned child processes only.
use super::*;
use crate::transport::{Identity, Role, SecureConnection};
use std::{
    cell::Cell,
    io, thread,
    time::{Duration, Instant},
};

struct Tracked<S> {
    stream: S,
    dropped: Arc<std::sync::atomic::AtomicUsize>,
}
impl<S: Read> Read for Tracked<S> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.stream.read(out)
    }
}
impl<S: Write> Write for Tracked<S> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.stream.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}
impl<S> Drop for Tracked<S> {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::Release);
    }
}
struct HalfHeader(bool);
impl Read for HalfHeader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.0 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.0 = true;
        out[0] = 32;
        Ok(1)
    }
}
impl Write for HalfHeader {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::ErrorKind::WouldBlock.into())
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::ErrorKind::WouldBlock.into())
    }
}
fn clock(ms: u64) -> crate::Clock {
    crate::Clock {
        monotonic_ms: ms,
        unix_seconds: 1_000_000,
    }
}
fn isolated_loop(
    node: &mut Node,
    stop: &AtomicBool,
    root: &Path,
    checkpoint: Checkpoint,
    mode: &str,
    dropped: Arc<std::sync::atomic::AtomicUsize>,
) -> Result<(), crate::Error> {
    let manifest = manifest::parse(
        &fs::read(root.join("node.json")).unwrap(),
        checkpoint.profile,
    )
    .unwrap();
    let remote_chain = DurableChain::open(
        &root.join("isolated.sqlite"),
        manifest.config,
        manifest.root,
        V6Verifier,
        1_000_000,
    )
    .unwrap();
    let mut remote = Node::new(
        remote_chain,
        node.limits,
        mempool::Limits {
            transactions: 100,
            bytes: 1_000_000,
            inputs: 1000,
            minimum_fee: monario_monetary::Amount::ZERO,
        },
    )
    .unwrap();
    let local_id = node.add_peer(clock(0)).unwrap();
    let remote_id = remote.add_peer(clock(0)).unwrap();
    let a_key = Identity::from_secret(Zeroizing::new([7; 32]));
    let b_key = Identity::from_secret(Zeroizing::new([11; 32]));
    let (a, b) = crate::transport::isolated_memory_pair();
    let mut a = SecureConnection::new(
        Tracked {
            stream: a,
            dropped: dropped.clone(),
        },
        &a_key,
        Role::Initiator {
            remote_key: b_key.public_key(),
        },
        checkpoint.profile,
        0,
    )
    .unwrap();
    let mut b = SecureConnection::new(
        Tracked {
            stream: b,
            dropped: dropped.clone(),
        },
        &b_key,
        Role::Responder,
        checkpoint.profile,
        0,
    )
    .unwrap();
    for ms in 0..200 {
        a.poll(node, local_id, clock(ms)).unwrap();
        b.poll(&mut remote, remote_id, clock(ms)).unwrap();
        node.tick(clock(ms)).unwrap();
        remote.tick(clock(ms)).unwrap();
    }
    assert!(node.peers[&local_id].ready && remote.peers[&remote_id].ready);
    let initial_tip = node.source().chain().unwrap().tip();
    // Verify a fixed-nonce public fixture. No nonce search, mining loop or genesis block.
    let committed_tip = crate::tests::append(node, initial_tip, vec![], 300);
    let stalled_id = node.add_peer(clock(300)).unwrap();
    let mut stalled = SecureConnection::new(
        Tracked {
            stream: HalfHeader(false),
            dropped: dropped.clone(),
        },
        &a_key,
        Role::Responder,
        checkpoint.profile,
        300,
    )
    .unwrap();
    stalled.poll(node, stalled_id, clock(300)).unwrap();
    assert!(node.buffered_bytes().1 > 0);
    assert_eq!(node.peer_count(), 2);
    fs::write(
        root.join("ready.tmp"),
        serde_json::to_vec(
            &serde_json::json!({"pid":std::process::id(),"tip":hex(&committed_tip)}),
        )
        .unwrap(),
    )
    .unwrap();
    fs::rename(root.join("ready.tmp"), root.join("ready.json")).unwrap();
    let began = Instant::now();
    while !stop.load(Ordering::Acquire) {
        assert!(
            began.elapsed() < Duration::from_secs(15),
            "isolated signal wait timed out"
        );
        thread::sleep(Duration::from_millis(1));
    }
    if mode == "crash" {
        std::process::exit(83);
    }
    if matches!(mode, "burst" | "delayed-burst") {
        // Scheduler delays must not let the receiver exit before the sender
        // completes its burst. Both platform helpers publish this marker last.
        let began = Instant::now();
        while !root.join("sent").exists() {
            assert!(
                began.elapsed() < Duration::from_secs(15),
                "signal burst completion timed out"
            );
            thread::sleep(Duration::from_millis(1));
        }
    }
    assert!(stop.load(Ordering::Acquire));
    remote.shutdown().unwrap();
    if mode == "error" {
        Err(crate::Error::Io)
    } else {
        Ok(())
    }
}

#[test]
fn signal_worker() {
    let Some(root) = std::env::var_os("MONAR_SIGNAL_DIRECTORY") else {
        return;
    };
    let root = PathBuf::from(root);
    let mode = std::env::var("MONAR_SIGNAL_MODE").unwrap();
    #[cfg(windows)]
    if matches!(mode.as_str(), "probe" | "wrong-pid" | "exit-code") {
        // Exercise the console helper without expensive chain setup. Keep the
        // owned receiver alive until every burst notification has been sent.
        let stop = Arc::new(AtomicBool::new(false));
        install_signals(&stop).unwrap();
        fs::write(
            root.join("ready.tmp"),
            serde_json::to_vec(&serde_json::json!({"pid":if mode == "wrong-pid" { 0 } else { std::process::id() }})).unwrap(),
        )
        .unwrap();
        fs::rename(root.join("ready.tmp"), root.join("ready.json")).unwrap();
        let began = Instant::now();
        while !stop.load(Ordering::Acquire) || (mode != "exit-code" && !root.join("sent").exists())
        {
            assert!(began.elapsed() < Duration::from_secs(15));
            thread::sleep(Duration::from_millis(1));
        }
        if mode == "exit-code" {
            std::process::exit(83);
        }
        fs::write(root.join("done.json"), b"{\"shutdown\":true}").unwrap();
        return;
    }
    assert!(matches!(
        mode.as_str(),
        "graceful" | "burst" | "delayed-burst" | "error" | "crash" | "kill" | "conflict"
    ));
    let checkpoint = Checkpoint {
        profile: hash(&std::env::var("MONAR_SIGNAL_PROFILE").unwrap()).unwrap(),
        public_key: hash(&std::env::var("MONAR_SIGNAL_KEY").unwrap()).unwrap(),
        revision: 0,
    };
    let stop = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let activated = Cell::new(false);
    if mode == "conflict" {
        ctrlc::set_handler(|| {}).unwrap();
    }
    let result = execute_with(
        parse(args("run", &root, checkpoint)),
        &mut Cursor::new(frame(OLD)),
        &mut Vec::new(),
        &stop,
        install_signals,
        |driver, node, stop| {
            activated.set(true);
            let directory = IdentityDirectory::open(&root).unwrap();
            assert!(
                IdentityStore::open(
                    &directory,
                    "node",
                    &Password::from_bytes(OLD).unwrap(),
                    checkpoint
                )
                .is_err()
            );
            let result = crate::transport::drive(node, stop, |node, stop| {
                isolated_loop(node, stop, &root, checkpoint, &mode, dropped.clone())
            });
            assert!(node.stopped());
            assert_eq!(node.peer_count(), 0);
            assert_eq!(node.buffered_bytes(), (0, 0));
            assert_eq!(dropped.load(Ordering::Acquire), 3);
            assert_eq!(driver.checkpoint().unwrap(), checkpoint);
            result
        },
    );
    if mode == "conflict" {
        assert_eq!(result, Err(Error::Signal));
        assert!(!activated.get());
    } else {
        assert!(activated.get());
        assert!(stop.load(Ordering::Acquire));
        assert_eq!(
            result,
            if mode == "error" {
                Err(Error::Runtime)
            } else {
                Ok(())
            }
        );
    }
    // Both database owners must be released before success is reported.
    assert!(invoke("check", &root, checkpoint, frame(OLD)).is_ok());
    fs::write(root.join("done.json"), b"{\"shutdown\":true}").unwrap();
}

#[test]
fn registration_and_output_failures_never_activate_the_transport() {
    let dir = private_tempdir();
    let checkpoint = chain_fixture(dir.path());
    let stop = Arc::new(AtomicBool::new(false));
    let installed = Cell::new(false);
    let activated = Cell::new(false);
    let result = execute_with(
        parse(args("run", dir.path(), checkpoint)),
        &mut Cursor::new(frame(OLD)),
        &mut BrokenOutput,
        &stop,
        |_| {
            installed.set(true);
            Ok(())
        },
        |_, _, _| {
            activated.set(true);
            Ok(())
        },
    );
    assert_eq!(result, Err(Error::Output));
    assert!(!installed.get() && !activated.get());
    let result = execute_with(
        parse(args("run", dir.path(), checkpoint)),
        &mut Cursor::new(frame(OLD)),
        &mut Vec::new(),
        &stop,
        |_| Err(Error::Signal),
        |_, _, _| {
            activated.set(true);
            Ok(())
        },
    );
    assert_eq!(result, Err(Error::Signal));
    assert!(!activated.get());
    assert!(!stop.load(Ordering::Acquire));
    assert!(invoke("check", dir.path(), checkpoint, frame(OLD)).is_ok());
}
#[test]
fn startup_stop_races_skip_registration_or_isolated_work() {
    let dir = private_tempdir();
    let checkpoint = chain_fixture(dir.path());
    for preset in [true, false] {
        let installed = Cell::new(false);
        let stop = Arc::new(AtomicBool::new(preset));
        let result = execute_with(
            parse(args("run", dir.path(), checkpoint)),
            &mut Cursor::new(frame(OLD)),
            &mut Vec::new(),
            &stop,
            |stop| {
                installed.set(true);
                stop.store(true, Ordering::Release);
                Ok(())
            },
            |driver, node, stop| {
                let result = crate::transport::drive(node, stop, |_, _| {
                    panic!("pre-stopped execution started work")
                });
                assert!(node.stopped());
                assert_eq!(driver.checkpoint().unwrap(), checkpoint);
                result
            },
        );
        assert_eq!(result, Ok(()));
        assert_eq!(installed.get(), !preset);
    }
}

fn wait(child: &mut std::process::Child, timeout: Duration) -> std::process::ExitStatus {
    let began = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if began.elapsed() >= timeout {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("owned signal worker timed out");
        }
        thread::sleep(Duration::from_millis(10));
    }
}
#[cfg(windows)]
fn worker(root: &Path, mode: &str, checkpoint: Checkpoint) -> std::process::ExitStatus {
    use std::os::windows::process::CommandExt;
    let log = fs::File::create(root.join("helper.log")).unwrap();
    let mut child = Process::new("powershell.exe")
        // CREATE_NO_WINDOW applies to the helper; Start-Process hides the worker console.
        .creation_flags(0x08000000)
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            include_str!("signal_windows.ps1"),
        ])
        .env("MONAR_SIGNAL_WORKER", std::env::current_exe().unwrap())
        .env("MONAR_SIGNAL_DIRECTORY", root)
        .env("MONAR_SIGNAL_MODE", mode)
        .env("MONAR_SIGNAL_PROFILE", hex(&checkpoint.profile))
        .env("MONAR_SIGNAL_KEY", hex(&checkpoint.public_key))
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .spawn()
        .unwrap();
    let status = wait(&mut child, Duration::from_secs(60));
    if !status.success() || matches!(mode, "crash" | "exit-code") {
        for name in ["helper.log", "worker.out", "worker.err"] {
            match fs::read(root.join(name)) {
                Ok(bytes) => eprintln!(
                    "{mode} {name}: {}",
                    String::from_utf8_lossy(&bytes[bytes.len().saturating_sub(16384)..])
                ),
                Err(error) => eprintln!("{mode} {name}: unavailable ({error})"),
            }
        }
    }
    status
}
#[cfg(unix)]
fn worker(root: &Path, mode: &str, checkpoint: Checkpoint) -> std::process::ExitStatus {
    let mut child = Process::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "cli::tests::signals::signal_worker",
            "--nocapture",
        ])
        .env("MONAR_SIGNAL_DIRECTORY", root)
        .env("MONAR_SIGNAL_MODE", mode)
        .env("MONAR_SIGNAL_PROFILE", hex(&checkpoint.profile))
        .env("MONAR_SIGNAL_KEY", hex(&checkpoint.public_key))
        .spawn()
        .unwrap();
    let began = Instant::now();
    while !root.join("ready.json").exists() {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if began.elapsed() > Duration::from_secs(40) {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("worker readiness timeout");
        }
        thread::sleep(Duration::from_millis(10));
    }
    let ready: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("ready.json")).unwrap()).unwrap();
    assert_eq!(ready["pid"].as_u64().unwrap(), u64::from(child.id()));
    if mode == "kill" {
        child.kill().unwrap();
    } else {
        let signal = match mode {
            "error" => "-TERM",
            "crash" => "-HUP",
            _ => "-INT",
        };
        for i in 0..if matches!(mode, "burst" | "delayed-burst") {
            4
        } else {
            1
        } {
            assert!(
                child.try_wait().unwrap().is_none(),
                "worker exited before signal {i}"
            );
            assert!(
                Process::new("kill")
                    .args([signal, &child.id().to_string()])
                    .status()
                    .unwrap()
                    .success()
            );
            if mode == "delayed-burst" && i == 0 {
                thread::sleep(Duration::from_secs(5));
            } else if mode == "burst" {
                thread::sleep(Duration::from_millis(20));
            }
        }
        if matches!(mode, "burst" | "delayed-burst") {
            fs::write(root.join("sent"), b"sent").unwrap();
        }
    }
    wait(&mut child, Duration::from_secs(20))
}
#[test]
fn owned_os_signals_and_process_death_preserve_committed_chain_and_identity() {
    let _serial = crate::tests::REAL.lock().unwrap();
    for mode in [
        "delayed-burst",
        "graceful",
        "burst",
        "error",
        "crash",
        "kill",
        "conflict",
    ] {
        let dir = private_tempdir();
        let checkpoint = chain_fixture(dir.path());
        let status = worker(dir.path(), mode, checkpoint);
        if mode == "crash" {
            assert_eq!(status.code(), Some(83), "isolated worker failed: {mode}");
        } else if mode == "kill" {
            assert!(!status.success());
        } else {
            assert!(status.success(), "isolated worker failed: {mode}: {status}");
        }
        assert_eq!(
            dir.path().join("done.json").exists(),
            !matches!(mode, "crash" | "kill")
        );
        assert_eq!(
            cp(&invoke("check", dir.path(), checkpoint, frame(OLD)).unwrap()),
            checkpoint
        );
        let manifest = manifest::parse(
            &fs::read(dir.path().join("node.json")).unwrap(),
            checkpoint.profile,
        )
        .unwrap();
        let chain = DurableChain::open(
            &dir.path().join("chain.sqlite"),
            manifest.config,
            manifest.root,
            V6Verifier,
            1_000_000,
        )
        .unwrap();
        let expected = if mode == "conflict" {
            manifest.root.id
        } else {
            let ready: serde_json::Value =
                serde_json::from_slice(&fs::read(dir.path().join("ready.json")).unwrap()).unwrap();
            hash(ready["tip"].as_str().unwrap()).unwrap()
        };
        assert_eq!(chain.chain().unwrap().tip(), expected);
        drop(chain);
        let directory = IdentityDirectory::open(dir.path()).unwrap();
        let store = IdentityStore::open(
            &directory,
            "node",
            &Password::from_bytes(OLD).unwrap(),
            checkpoint,
        )
        .unwrap();
        assert_eq!(store.checkpoint().unwrap(), checkpoint);
        assert!(store.configuration().unwrap().peers().is_empty());
        drop(store);
        let bytes = fs::read(dir.path().join("node.monp")).unwrap();
        assert!(!bytes.windows(OLD.len()).any(|b| b == OLD));
    }
}

#[cfg(windows)]
#[test]
fn windows_console_bursts_preserve_the_owned_helper_and_receiver() {
    for _ in 0..4 {
        let dir = private_tempdir();
        let checkpoint = Checkpoint {
            profile: [2; 32],
            public_key: [3; 32],
            revision: 0,
        };
        let status = worker(dir.path(), "probe", checkpoint);
        assert!(status.success(), "console burst helper failed: {status}");
        assert!(dir.path().join("done.json").is_file());
    }
}

#[cfg(windows)]
#[test]
fn windows_console_helper_rejects_unowned_readiness_before_signalling() {
    let dir = private_tempdir();
    let status = worker(
        dir.path(),
        "wrong-pid",
        Checkpoint {
            profile: [2; 32],
            public_key: [3; 32],
            revision: 0,
        },
    );
    assert_eq!(status.code(), Some(1));
    assert!(!dir.path().join("sent").exists());
    assert!(!dir.path().join("done.json").exists());
    assert!(
        String::from_utf8_lossy(&fs::read(dir.path().join("helper.log")).unwrap())
            .contains("Worker PID mismatch")
    );
}

#[cfg(windows)]
#[test]
fn windows_console_helper_preserves_exit_code_after_worker_death() {
    for _ in 0..8 {
        let dir = private_tempdir();
        let status = worker(
            dir.path(),
            "exit-code",
            Checkpoint {
                profile: [2; 32],
                public_key: [3; 32],
                revision: 0,
            },
        );
        assert_eq!(status.code(), Some(83));
        assert!(!dir.path().join("done.json").exists());
    }
}
