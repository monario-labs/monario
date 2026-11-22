//! Archive pages use real fixed-nonce blocks; no nonce search or networking.
use super::*;
use monario_chain::audit::{self, Error};

fn append(n: &mut Node, parent: Hash, timestamp: u32) -> Hash {
    let chain = n.source().chain().unwrap();
    let template = chain
        .build_template(parent, u64::from(timestamp), 1_000_000, vec![], |p| {
            monario_v6::coinbase::encode(
                p,
                monario_address::TransparentReceiver::PublicKeyHash([7; 20]),
                b"public audit fixture",
            )
            .map_err(|_| monario_chain::Error::Coinbase)
        })
        .unwrap();
    let raw = monario_chain::wire::encode(&template.block, chain.limits(), &V6Verifier).unwrap();
    n.import_block(&raw, clock(0)).unwrap().id
}

#[test]
fn pages_are_bounded_contiguous_repeatable_and_do_not_certify_the_excluded_cursor() {
    let _serial = REAL.lock().unwrap();
    let (dir, mut n) = node();
    let empty = audit::page(n.source(), root().id).unwrap();
    assert_eq!(
        (empty.blocks, empty.bytes, empty.end, empty.at_tip),
        (0, 0, root().id, true)
    );
    let mut ids = vec![root().id];
    for height in 1..=17 {
        let id = append(&mut n, *ids.last().unwrap(), 1000 + 105 * height);
        ids.push(id);
    }
    let supply = n.source().chain().unwrap().ledger().supply();
    let first = audit::page(n.source(), root().id).unwrap();
    assert_eq!(
        (first.blocks, first.end, first.validated_tip, first.at_tip),
        (16, ids[16], ids[17], false)
    );
    assert_eq!(first.profile, n.profile);
    assert_eq!(first.after, root().id);
    let bytes: u64 = ids[1..=16]
        .iter()
        .map(|id| n.source().authenticated_block_bytes(*id).unwrap().len() as u64)
        .sum();
    assert_eq!(first.bytes, bytes);
    assert!(first.bytes <= 16 * 5_000_000);
    n.shutdown().unwrap();
    drop(n);
    let n = open(&dir.path().join("node.sqlite"));
    let repeated = audit::page(n.source(), root().id).unwrap();
    assert_eq!((repeated.end, repeated.bytes), (first.end, first.bytes));
    let last = audit::page(n.source(), first.end).unwrap();
    assert_eq!((last.blocks, last.end, last.at_tip), (1, ids[17], true));
    let none = audit::page(n.source(), last.end).unwrap();
    assert_eq!((none.blocks, none.bytes, none.at_tip), (0, 0, true));
    assert_eq!(n.source().chain().unwrap().ledger().supply(), supply);
    assert!(matches!(
        audit::page(n.source(), [99; 32]),
        Err(Error::Cursor)
    ));
}

#[test]
fn detached_resume_cursor_is_refused_and_common_prefix_resumes_on_the_winning_branch() {
    let _serial = REAL.lock().unwrap();
    let (_dir, mut n) = node();
    let base = append(&mut n, root().id, 1105);
    let old = append(&mut n, base, 1210);
    let page = audit::page(n.source(), base).unwrap();
    assert_eq!(page.end, old);
    let side = append(&mut n, base, 1151);
    let best = append(&mut n, side, 1315);
    assert!(matches!(audit::page(n.source(), old), Err(Error::Cursor)));
    let fresh = audit::page(n.source(), base).unwrap();
    assert_eq!(
        (fresh.blocks, fresh.end, fresh.validated_tip, fresh.at_tip),
        (2, best, best, true)
    );
    assert_ne!(page.validated_tip, fresh.validated_tip);
}
