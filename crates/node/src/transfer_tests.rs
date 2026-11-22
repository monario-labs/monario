//! Offline stream exchange exercises the public durable validation path only.
use super::*;
use monario_chain::transfer::{self, Error};
use std::io::{self, Cursor, Read, Write};

fn target(path: &std::path::Path) -> DurableChain<V6Verifier> {
    DurableChain::open(path, config(), root(), V6Verifier, 1_000_000).unwrap()
}

#[test]
fn portable_page_import_is_validated_and_exact_retry_is_idempotent() {
    let _serial = REAL.lock().unwrap();
    let (_dir, mut n) = node();
    let first = append(&mut n, root().id, vec![], 0);
    let second = append(&mut n, first, vec![], 0);
    let mut packet = Vec::new();
    let page = transfer::export(n.source(), root().id, &mut packet).unwrap();
    assert_eq!(page.end, second);
    assert_eq!(page.blocks, 2);
    let dir = private_tempdir();
    let mut d = target(&dir.path().join("copy.sqlite"));
    let report = transfer::import(&mut d, &mut packet.as_slice(), 2000).unwrap();
    assert_eq!((report.accepted, report.known, report.end), (2, 0, second));
    let supply = d.chain().unwrap().ledger().supply();
    let pin = d
        .create_state_checkpoint(crate::cli::STATE_CHECKPOINT_LIMITS)
        .unwrap();
    d.checkpoint().unwrap();
    drop(d);
    let mut d = DurableChain::open_with_checkpoint(
        &dir.path().join("copy.sqlite"),
        config(),
        root(),
        V6Verifier,
        1_000_000,
        pin,
        crate::cli::STATE_CHECKPOINT_LIMITS,
    )
    .unwrap();
    let report = transfer::import(&mut d, &mut packet.as_slice(), 2000).unwrap();
    assert_eq!((report.accepted, report.known), (0, 2));
    assert_eq!(d.chain().unwrap().ledger().supply(), supply);
    let mut empty = Vec::new();
    assert_eq!(
        transfer::export(n.source(), second, &mut empty)
            .unwrap()
            .blocks,
        0
    );
    assert_eq!(
        transfer::import(&mut d, &mut empty.as_slice(), 2000)
            .unwrap()
            .end,
        second
    );
}

#[test]
fn malformed_profiles_counts_lengths_and_every_truncation_fail_before_effects() {
    let _serial = REAL.lock().unwrap();
    let (_dir, mut n) = node();
    append(&mut n, root().id, vec![], 0);
    let mut packet = Vec::new();
    transfer::export(n.source(), root().id, &mut packet).unwrap();
    let dir = private_tempdir();
    let mut d = target(&dir.path().join("copy.sqlite"));
    for end in 0..packet.len() {
        assert!(transfer::import(&mut d, &mut &packet[..end], 2000).is_err());
        assert_eq!(d.chain().unwrap().tip(), root().id);
    }
    for index in [0, 8, 40, 72, 74] {
        let mut bad = packet.clone();
        match index {
            72 => bad[72..74].copy_from_slice(&129u16.to_le_bytes()),
            74 => bad[74..78].copy_from_slice(&u32::MAX.to_le_bytes()),
            _ => bad[index] ^= 1,
        }
        let mut input = Cursor::new(bad);
        assert!(transfer::import(&mut d, &mut input, 2000).is_err());
        assert!(input.position() <= 78); // Reject before allocating/reading a body.
        assert_eq!(d.chain().unwrap().tip(), root().id);
    }
    let mut invalid = packet.clone();
    invalid[78 + 36] ^= 1; // Canonical header with a false body commitment.
    assert!(matches!(
        transfer::import(&mut d, &mut invalid.as_slice(), 2000),
        Err(Error::Storage(_))
    ));
    assert_eq!(d.chain().unwrap().tip(), root().id);
}

#[test]
fn trailing_data_known_body_mutation_and_noncontiguous_pages_never_gain_validity() {
    let _serial = REAL.lock().unwrap();
    let (_dir, mut n) = node();
    let first = append(&mut n, root().id, vec![], 0);
    let tip = append(&mut n, first, vec![], 0);
    let mut packet = Vec::new();
    transfer::export(n.source(), root().id, &mut packet).unwrap();
    let dir = private_tempdir();
    let mut d = target(&dir.path().join("copy.sqlite"));
    let first_len = u32::from_le_bytes(packet[74..78].try_into().unwrap()) as usize;
    let mut broken = packet.clone();
    broken[78 + first_len + 4 + 4] ^= 1; // Second block's parent.
    assert!(matches!(
        transfer::import(&mut d, &mut broken.as_slice(), 2000),
        Err(Error::Format)
    ));
    assert_eq!(d.chain().unwrap().tip(), first); // Prior validated commit remains.
    let mut trailing = packet.clone();
    trailing.push(0);
    assert!(matches!(
        transfer::import(&mut d, &mut trailing.as_slice(), 2000),
        Err(Error::Format)
    ));
    assert_eq!(d.chain().unwrap().tip(), tip);
    let supply = d.chain().unwrap().ledger().supply();
    let mut changed = packet.clone();
    changed[78 + first_len - 1] ^= 1; // Known header ID, different exact body bytes.
    assert!(matches!(
        transfer::import(&mut d, &mut changed.as_slice(), 2000),
        Err(Error::Format)
    ));
    assert_eq!(d.chain().unwrap().ledger().supply(), supply);
    assert_eq!(
        transfer::import(&mut d, &mut packet.as_slice(), 2000)
            .unwrap()
            .known,
        2
    );
}

#[test]
fn imported_heavier_fork_reorganizes_by_validated_work_and_old_cursor_is_refused() {
    let _serial = REAL.lock().unwrap();
    let (_dir, mut n) = node();
    let first = append(&mut n, root().id, vec![], 0);
    let fork = append(&mut n, first, vec![], 0);
    let funding = n.source().stored_block(first).unwrap();
    let coin = *transaction::Transaction::read(funding.transactions[0].as_slice(), BranchId::Nu6_3)
        .unwrap()
        .txid()
        .as_ref();
    let parent = raw(0, Some((coin, 0)), 90);
    let old = append(&mut n, fork, vec![parent.clone()], 0);
    let mut packet = Vec::new();
    transfer::export(n.source(), root().id, &mut packet).unwrap();
    let dir = private_tempdir();
    let mut d = target(&dir.path().join("copy.sqlite"));
    transfer::import(&mut d, &mut packet.as_slice(), 2000).unwrap();
    let side = append(&mut n, fork, vec![], 0);
    let tip = append(&mut n, side, vec![], 0);
    let mut page = Vec::new();
    assert!(matches!(
        transfer::export(n.source(), old, &mut page),
        Err(Error::Format)
    ));
    assert!(page.is_empty());
    transfer::export(n.source(), fork, &mut page).unwrap();
    let result = transfer::import(&mut d, &mut page.as_slice(), 2000).unwrap();
    assert_eq!((result.accepted, result.end), (2, tip));
    assert_eq!(d.chain().unwrap().tip(), tip);
    let id = monario_v6::transaction_references(&parent).unwrap().0;
    assert!(!d.chain().unwrap().ledger().contains_transaction(&id));
    assert!(
        d.chain()
            .unwrap()
            .ledger()
            .coin(&monario_chain::ledger::OutPoint {
                transaction: coin,
                index: 0
            })
            .is_some()
    );
}

struct FailingWriter {
    remaining: usize,
}
impl Write for FailingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::Error::other("fixture failure"));
        }
        let n = self.remaining.min(bytes.len());
        self.remaining -= n;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("fixture flush failure"))
    }
}
#[test]
fn output_failure_never_returns_a_complete_page_or_changes_source() {
    let _serial = REAL.lock().unwrap();
    let (_dir, mut n) = node();
    let tip = append(&mut n, root().id, vec![], 0);
    for remaining in [0, 10, 74, usize::MAX] {
        assert!(matches!(
            transfer::export(n.source(), root().id, &mut FailingWriter { remaining }),
            Err(Error::Output)
        ));
        assert_eq!(n.source().chain().unwrap().tip(), tip);
    }
}

#[test]
fn transfer_crash_worker() {
    let Some(dir) = std::env::var_os("MONAR_TRANSFER_TEST_DIR") else {
        return;
    };
    let dir = std::path::Path::new(&dir);
    let packet = std::fs::read(dir.join("page.bin")).unwrap();
    let first_len = u32::from_le_bytes(packet[74..78].try_into().unwrap()) as usize;
    let cut = if std::env::var("MONAR_TRANSFER_TEST_PHASE").unwrap() == "partial" {
        78 + first_len / 2
    } else {
        78 + first_len
    };
    struct Interrupted {
        bytes: Vec<u8>,
        pos: usize,
        cut: usize,
    }
    impl Read for Interrupted {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            if self.pos == self.cut {
                std::process::exit(97);
            }
            let n = out.len().min(self.cut - self.pos);
            out[..n].copy_from_slice(&self.bytes[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }
    let mut d = target(&dir.join("copy.sqlite"));
    transfer::import(
        &mut d,
        &mut Interrupted {
            bytes: packet,
            pos: 0,
            cut,
        },
        2000,
    )
    .unwrap();
    panic!("crash boundary not reached");
}

#[test]
fn process_death_retains_only_valid_prefix_and_full_page_retry_has_no_double_reward() {
    let _serial = REAL.lock().unwrap();
    let (_dir, mut n) = node();
    let first = append(&mut n, root().id, vec![], 0);
    let tip = append(&mut n, first, vec![], 0);
    let mut packet = Vec::new();
    transfer::export(n.source(), root().id, &mut packet).unwrap();
    for phase in ["partial", "committed"] {
        let dir = private_tempdir();
        drop(target(&dir.path().join("copy.sqlite")));
        std::fs::write(dir.path().join("page.bin"), &packet).unwrap();
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "tests::transfer::transfer_crash_worker"])
            .env("MONAR_TRANSFER_TEST_DIR", dir.path())
            .env("MONAR_TRANSFER_TEST_PHASE", phase)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert_eq!(result.code(), Some(97));
        let mut d = target(&dir.path().join("copy.sqlite"));
        assert_eq!(
            d.chain().unwrap().tip(),
            if phase == "partial" { root().id } else { first }
        );
        let result = transfer::import(&mut d, &mut packet.as_slice(), 2000).unwrap();
        assert_eq!(result.known, u16::from(phase == "committed"));
        assert_eq!(result.accepted + result.known, 2);
        assert_eq!(d.chain().unwrap().tip(), tip);
        assert_eq!(
            d.chain().unwrap().ledger().supply(),
            n.source().chain().unwrap().ledger().supply()
        );
    }
}
