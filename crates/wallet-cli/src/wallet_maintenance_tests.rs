//! Cleanup removes delivery history, never an authorization or encrypted input claim.
use super::*;
#[test]
fn cleanup_rotation_and_reorgs_preserve_signed_bytes_and_wallet_claims() {
    for private in [false, true] {
        let dir = private_dir();
        let local = private_dir();
        let (source, model) = source(dir.path(), private);
        let profile = source.profile_id().unwrap();
        let mut store = wallet(dir.path());
        let doc = intent(&store, &source, private, false, 8);
        let signed = make(&mut store, &source, &doc).unwrap();
        let raw = decode(signed["transaction_hex"].as_str().unwrap());
        let token = id(signed["reservation"].as_str().unwrap()).unwrap();
        let cp = store.checkpoint().unwrap();
        drop(store);
        let unchanged = fs::read(dir.path().join("wallet.monw")).unwrap();
        let mut inbox = Inbox::create(local.path(), "local", profile, key()).unwrap();
        let queued = run(
            dir.path(),
            local.path(),
            cp,
            (profile, key()),
            token,
            "submit",
        )
        .unwrap();
        let delivery = balance::hash(queued["submission"].as_str().unwrap()).unwrap();
        let mut n = node(source);
        n.attach_submission_inbox(Inbox::open(local.path(), "local", profile, key()).unwrap())
            .unwrap();
        let mut ms = 0;
        advance(&mut n, &mut ms);
        assert_eq!(n.mempool().len(), 1);
        inbox.forget(delivery).unwrap();
        assert_eq!(n.mempool().len(), 1);
        assert_eq!(
            run(
                dir.path(),
                local.path(),
                cp,
                (profile, key()),
                token,
                "submission-status"
            )
            .unwrap()["last_observation"],
            "absent"
        );
        run(
            dir.path(),
            local.path(),
            cp,
            (profile, key()),
            token,
            "submit",
        )
        .unwrap();
        advance(&mut n, &mut ms);
        assert_eq!(inbox.status(delivery).unwrap().unwrap().state, 1);
        let mut store = open_wallet(dir.path(), cp);
        assert!(make(&mut store, n.source(), &doc).is_err());
        assert_eq!(store.checkpoint().unwrap(), cp);
        drop(store);
        let height = if private { 4 } else { 3 };
        let base = model.clone();
        let mut best = model;
        import(
            &mut n,
            &mut best,
            height,
            std::slice::from_ref(&raw),
            &mut ms,
        );
        advance(&mut n, &mut ms);
        assert!(n.mempool().is_empty());
        inbox.forget(delivery).unwrap();
        let mut side = base;
        import(&mut n, &mut side, height, &[], &mut ms);
        import(&mut n, &mut side, height + 1, &[], &mut ms);
        advance(&mut n, &mut ms);
        // Orphan resurrection is independent of inbox history: forgetting is not cancellation.
        assert_eq!(n.mempool().len(), 1);
        assert!(inbox.status(delivery).unwrap().is_none());
        run(
            dir.path(),
            local.path(),
            cp,
            (profile, key()),
            token,
            "submit",
        )
        .unwrap();
        advance(&mut n, &mut ms);
        let target = inbox.rotate("next").unwrap();
        assert_eq!(n.mempool().len(), 1);
        assert!(
            run(
                dir.path(),
                local.path(),
                cp,
                (profile, key()),
                token,
                "submit"
            )
            .is_err()
        );
        let old = run(
            dir.path(),
            local.path(),
            cp,
            (profile, key()),
            token,
            "submission-status",
        )
        .unwrap();
        assert_eq!(old["inbox_phase"], "retired");
        assert_eq!(old["inbox_peer"], "next");
        assert_eq!(target.status(delivery).unwrap().unwrap().state, 0);
        drop(target);
        n.shutdown().unwrap();
        drop(n);
        let source = DurableChain::open(
            &dir.path().join("chain.sqlite"),
            config(),
            root(),
            V6Verifier,
            u64::MAX / 2,
        )
        .unwrap();
        let mut n = node(source);
        n.attach_submission_inbox(Inbox::open(local.path(), "next", profile, key()).unwrap())
            .unwrap();
        n.tick(clock(0)).unwrap();
        assert_eq!(n.mempool().len(), 1);
        let store = open_wallet(dir.path(), cp);
        assert_eq!(store.checkpoint().unwrap(), cp);
        assert_eq!(store.reservations().unwrap().len(), 1);
        assert_eq!(
            store.reservations().unwrap()[&token].expose_transaction(),
            Some(raw.as_slice())
        );
        drop(store);
        assert_eq!(fs::read(dir.path().join("wallet.monw")).unwrap(), unchanged);
        n.shutdown().unwrap();
    }
}
