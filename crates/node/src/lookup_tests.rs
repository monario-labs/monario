use super::*;
use crate::tests::{REAL, append, clock, config, node, open, raw, root};

#[test]
fn coinbase_and_pending_lookup_return_only_selected_confirmed_exact_bytes() {
    let _serial = REAL.lock().unwrap();
    let (_dir, mut n) = node();
    let first = append(&mut n, root().id, vec![], 0);
    let bytes = n
        .source()
        .stored_block(first)
        .unwrap()
        .transactions
        .remove(0);
    let id = monario_v6::transaction_id(&bytes).unwrap();
    let second = append(&mut n, first, vec![], 0);
    let found = confirmed(n.source(), id).unwrap().unwrap();
    assert_eq!(found.bytes, bytes);
    assert_eq!(found.validated_tip, second);
    assert_eq!(
        (
            found.confirmation.block,
            found.confirmation.height,
            found.confirmation.depth
        ),
        (first, 1, 2)
    );
    let spend = raw(0, Some((id, 0)), 90);
    let spend_id = monario_v6::transaction_id(&spend).unwrap();
    n.submit_transaction(spend.clone(), clock(0)).unwrap();
    assert!(confirmed(n.source(), spend_id).unwrap().is_none());
    assert!(confirmed(n.source(), [99; 32]).unwrap().is_none());
    assert_eq!(n.mempool().len(), 1);
    let best = append(&mut n, second, vec![spend.clone()], 0);
    let result = confirmed(n.source(), spend_id).unwrap().unwrap();
    assert_eq!(result.bytes, spend);
    assert_eq!(
        (result.confirmation.block, result.confirmation.depth),
        (best, 1)
    );
}

#[test]
fn reorg_removes_detached_receipts_and_relocated_inclusion_is_recomputed_after_restart() {
    let _serial = REAL.lock().unwrap();
    let (dir, mut n) = node();
    let first = append(&mut n, root().id, vec![], 0);
    let id = monario_v6::transaction_id(&n.source().stored_block(first).unwrap().transactions[0])
        .unwrap();
    let base = append(&mut n, first, vec![], 0);
    let bytes = raw(0, Some((id, 0)), 90);
    let txid = monario_v6::transaction_id(&bytes).unwrap();
    let old = append(&mut n, base, vec![bytes.clone()], 0);
    let receipt = confirmed(n.source(), txid).unwrap().unwrap();
    assert_eq!(receipt.confirmation.block, old);
    let side = append(&mut n, base, vec![], 0);
    let side = append(&mut n, side, vec![], 0);
    assert!(confirmed(n.source(), txid).unwrap().is_none());
    let best = append(&mut n, side, vec![bytes.clone()], 0);
    n.shutdown().unwrap();
    drop(n);
    let n = open(&dir.path().join("node.sqlite"));
    let fresh = confirmed(n.source(), txid).unwrap().unwrap();
    assert_eq!(fresh.bytes, bytes);
    assert_eq!(
        (
            fresh.confirmation.block,
            fresh.confirmation.height,
            fresh.confirmation.depth
        ),
        (best, 5, 1)
    );
    assert_ne!(receipt.validated_tip, fresh.validated_tip);
}

#[test]
fn checkpoint_history_corruption_with_forged_disk_digest_never_discloses_changed_authorization() {
    use sha2::{Digest, Sha256};
    let _serial = REAL.lock().unwrap();
    let (dir, mut n) = node();
    let prefix = append(&mut n, root().id, vec![], 0);
    let first = append(&mut n, prefix, vec![], 0);
    let bytes = n
        .source()
        .stored_block(first)
        .unwrap()
        .transactions
        .remove(0);
    let txid = monario_v6::transaction_id(&bytes).unwrap();
    let pin = n
        .store
        .create_state_checkpoint(crate::cli::STATE_CHECKPOINT_LIMITS)
        .unwrap();
    n.shutdown().unwrap();
    drop(n);
    let db = rusqlite::Connection::open(dir.path().join("node.sqlite")).unwrap();
    let mut data: Vec<u8> = db
        .query_row(
            "SELECT data FROM blocks WHERE id=?1",
            [first.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    let mut original_digest = Sha256::new();
    original_digest.update(b"Monario/stored-block/v1\0");
    original_digest.update(&data);
    let original_digest = Sha256::digest(original_digest.finalize());
    let mut changed = bytes.clone();
    let at = changed.windows(3).position(|w| w == [2, 0x52, 0]).unwrap() + 2;
    changed[at] = 0x51;
    assert_eq!(monario_v6::transaction_id(&changed).unwrap(), txid);
    data[148 + at] = 0x51; // Stored header, u32 count and u32 transaction length.
    let mut digest = Sha256::new();
    digest.update(b"Monario/stored-block/v1\0");
    digest.update(&data);
    let digest = Sha256::digest(digest.finalize());
    db.execute(
        "UPDATE blocks SET data=?1,digest=?2 WHERE id=?3",
        rusqlite::params![data, digest.as_slice(), first.as_slice()],
    )
    .unwrap();
    drop(db);
    assert!(matches!(
        DurableChain::open_with_checkpoint(
            &dir.path().join("node.sqlite"),
            config(),
            root(),
            V6Verifier,
            1_000_000,
            pin,
            crate::cli::STATE_CHECKPOINT_LIMITS,
        ),
        Err(monario_chain::storage::StorageError::Corrupt)
    ));
    // Keeping the original local digest permits fast restoration of metadata,
    // but must not permit disclosure of the changed historical body.
    let db = rusqlite::Connection::open(dir.path().join("node.sqlite")).unwrap();
    db.execute(
        "UPDATE blocks SET digest=?1 WHERE id=?2",
        rusqlite::params![original_digest.as_slice(), first.as_slice()],
    )
    .unwrap();
    drop(db);
    let source = DurableChain::open_with_checkpoint(
        &dir.path().join("node.sqlite"),
        config(),
        root(),
        V6Verifier,
        1_000_000,
        pin,
        crate::cli::STATE_CHECKPOINT_LIMITS,
    )
    .unwrap();
    assert!(source.stored_block(first).is_err());
    assert!(source.authenticated_block_bytes(prefix).is_ok());
    assert!(matches!(confirmed(&source, txid), Err(Error::Storage)));
    assert!(matches!(
        monario_chain::audit::page(&source, root().id),
        Err(monario_chain::audit::Error::Storage(_))
    ));
    // An exclusive cursor does not authenticate its own body or earlier history.
    let empty = monario_chain::audit::page(&source, first).unwrap();
    assert_eq!((empty.blocks, empty.bytes, empty.at_tip), (0, 0, true));
}
