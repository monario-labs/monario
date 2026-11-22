//! Registry/service credit recovery around the actual block commit boundary.
use super::*;
use crate::service::{
    self,
    tests::{Model, Verifier, candidate, config, operator, raw, root},
};
use crate::tests::FixturePow;

fn open_service(path: &Path) -> DurableChain<Verifier> {
    DurableChain::open_checked(
        path,
        config(),
        root(),
        Verifier,
        2_000_000,
        &mut FixturePow::default(),
    )
    .unwrap()
}
fn populate(path: &Path, model: &Model) {
    let mut d = open_service(path);
    let mut rows: Vec<_> = model
        .bodies
        .iter()
        .map(|(id, bytes)| (model.chain.nodes[id].height, *id, bytes))
        .collect();
    rows.sort_unstable_by_key(|r| r.0);
    // Fixture loading only: one transaction avoids thousands of test-only fsyncs.
    // open_service below independently validates EVERY loaded event before use.
    let t = d.db.transaction().unwrap();
    for (_, id, bytes) in rows {
        let b = wire::decode(bytes, &config().limits, &Verifier).unwrap();
        let data = encode(&b).unwrap();
        let digest = hash_domain(b"Monario/stored-block/v1\0", &[&data]);
        t.execute(
            "INSERT INTO blocks(id,data,digest) VALUES(?1,?2,?3)",
            params![id.as_slice(), data, digest.as_slice()],
        )
        .unwrap();
    }
    t.execute(
        "UPDATE metadata SET tip=?1,records=?2",
        params![model.chain.tip().as_slice(), model.chain.height() as i64],
    )
    .unwrap();
    t.commit().unwrap();
}
#[test]
fn service_crash_worker() {
    let Some(path) = std::env::var_os("MONAR_SERVICE_CRASH_DB") else {
        return;
    };
    let phase = std::env::var("MONAR_SERVICE_CRASH_PHASE").unwrap();
    let control = std::env::var("MONAR_SERVICE_CONTROL").ok();
    let mut d = if control.is_some() {
        let bytes = std::fs::read(Path::new(&path).with_extension("pin")).unwrap();
        open_control(
            Path::new(&path),
            TrustedCheckpoint::from_commitment(bytes.try_into().unwrap()),
        )
    } else {
        open_service(Path::new(&path))
    };
    let block = if let Some(kind) = control {
        let id = *d.chain.ledger.services.keys().next().unwrap();
        let packet = {
            let authorization = if kind == "rotation" {
                service::rotation_authorization(
                    &d.chain,
                    id,
                    &secp256k1::SecretKey::from_secret_bytes([9; 32]).unwrap(),
                )
            } else {
                service::reactivation_authorization(&d, id, &operator())
            }
            .unwrap();
            service::control_script(&d.chain, &authorization, &service::tests::owner()).unwrap()
        };
        let fee = *d
            .chain
            .ledger
            .coins
            .iter()
            .find(|(_, c)| c.value.atoms() == 3 * monario_monetary::ATOMS_PER_COIN)
            .unwrap()
            .0;
        let coin = d.chain.ledger.coin(&fee).unwrap();
        let raw = raw(
            0,
            &[fee],
            &[(coin.value.atoms(), coin.script.clone()), (0, packet)],
        );
        candidate(&d.chain, d.chain.tip(), &[raw])
    } else {
        let id = *d.chain.ledger.services.keys().next().unwrap();
        let packet = service::proof_script(&d, id, &operator()).unwrap();
        let fee = ledger::OutPoint {
            transaction: id,
            index: 0,
        };
        let coin = d.chain.ledger.coin(&fee).unwrap();
        let record = raw(
            0,
            &[fee],
            &[(coin.value.atoms(), coin.script.clone()), (0, packet)],
        );
        candidate(&d.chain, d.chain.tip(), &[record])
    };
    let db = &mut d.db;
    d.chain
        .submit_recorded(
            block,
            2_000_000,
            &mut FixturePow::default(),
            |b, id, tip, _, _| {
                let data = encode(b).unwrap();
                let digest = hash_domain(b"Monario/stored-block/v1\0", &[&data]);
                let t = db.transaction().unwrap();
                t.execute(
                    "INSERT INTO blocks(id,data,digest) VALUES(?1,?2,?3)",
                    params![id.as_slice(), data, digest.as_slice()],
                )
                .unwrap();
                t.execute(
                    "UPDATE metadata SET tip=?1,records=records+1",
                    params![tip.as_slice()],
                )
                .unwrap();
                if phase == "before" {
                    std::process::exit(91);
                }
                t.commit().unwrap();
                std::process::exit(92);
            },
        )
        .unwrap();
}
#[test]
fn service_credit_crash_recovery_checkpoint_corruption_and_collateral_reorg() {
    let mut model = Model::new();
    let (id, collateral, _) = model.register();
    let end = model.chain.ledger().service_entry(&id).unwrap().next_start + service::PERIOD_BLOCKS;
    model.to(end);
    for (phase, code, seconds) in [("before", 91, 0), ("after", 92, 86400)] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("service.sqlite");
        populate(&path, &model);
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "storage::service_tests::service_crash_worker",
                "--nocapture",
            ])
            .env("MONAR_SERVICE_CRASH_DB", &path)
            .env("MONAR_SERVICE_CRASH_PHASE", phase)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(code));
        let mut d = open_service(&path);
        assert_eq!(
            d.chain
                .ledger()
                .service_entry(&id)
                .unwrap()
                .credited_seconds,
            seconds
        );
        let limits = SnapshotLimits {
            max_entries: 100000,
            max_row_bytes: 1 << 20,
            max_bytes: 64 << 20,
        };
        let trusted = d.create_state_checkpoint(limits).unwrap();
        drop(d);
        let mut d = DurableChain::open_recovered(
            &path,
            config(),
            root(),
            Verifier,
            2_000_000,
            &mut FixturePow::default(),
            Some((trusted, limits)),
        )
        .unwrap();
        assert_eq!(
            d.chain
                .ledger()
                .service_entry(&id)
                .unwrap()
                .credited_seconds,
            seconds
        );
        let old = d.chain.tip();
        let entry = d.chain.ledger().service_entry(&id).unwrap().clone();
        let spend = raw(
            0,
            &[collateral],
            &[(
                service::COLLATERAL_ATOMS,
                service::owner_script(&entry.owner),
            )],
        );
        let block = candidate(&d.chain, old, &[spend]);
        d.submit_checked(block, 2_000_000, &mut FixturePow::default())
            .unwrap();
        assert!(d.chain.ledger().service_entry(&id).is_none());
        let side = candidate(&d.chain, old, &[]);
        let side = d
            .submit_checked(side, 2_000_000, &mut FixturePow::default())
            .unwrap()
            .id;
        let side = candidate(&d.chain, side, &[]);
        d.submit_checked(side, 2_000_000, &mut FixturePow::default())
            .unwrap();
        assert_eq!(d.chain.ledger().service_entry(&id), Some(&entry));
        drop(d);
        let mut d = open_service(&path);
        assert_eq!(d.chain.ledger().service_entry(&id), Some(&entry));
        let trusted = d.create_state_checkpoint(limits).unwrap();
        d.db.execute(
            "UPDATE checkpoint_rows SET data=zeroblob(length(data)) WHERE kind=6",
            [],
        )
        .unwrap();
        drop(d);
        assert!(
            DurableChain::open_recovered(
                &path,
                config(),
                root(),
                Verifier,
                2_000_000,
                &mut FixturePow::default(),
                Some((trusted, limits))
            )
            .is_err()
        );
        let mut d = open_service(&path);
        assert_eq!(d.chain.ledger().service_entry(&id), Some(&entry));
        // Even a self-authenticated checkpoint must reject impossible credit state.
        let mut inflated = entry.clone();
        inflated.credited_seconds = service::QUALIFY_SECONDS;
        d.chain.ledger.set_service(id, Some(inflated));
        let impossible = d.create_state_checkpoint(limits).unwrap();
        drop(d);
        assert!(
            DurableChain::open_recovered(
                &path,
                config(),
                root(),
                Verifier,
                2_000_000,
                &mut FixturePow::default(),
                Some((impossible, limits))
            )
            .is_err()
        );
        assert_eq!(
            open_service(&path).chain.ledger().service_entry(&id),
            Some(&entry)
        );
    }
}

fn control_limits() -> SnapshotLimits {
    SnapshotLimits {
        max_entries: 500000,
        max_row_bytes: 1 << 20,
        max_bytes: 256 << 20,
    }
}
fn open_control(path: &Path, pin: TrustedCheckpoint) -> DurableChain<Verifier> {
    DurableChain::open_recovered(
        path,
        config(),
        root(),
        Verifier,
        2_000_000,
        &mut FixturePow::default(),
        Some((pin, control_limits())),
    )
    .unwrap()
}
#[test]
fn signed_controls_crash_checkpoint_and_reorg_preserve_authority_and_credit() {
    let (mut model, id, _, _) = service::tests::qualified_model();
    let end =
        model.chain.ledger().service_entry(&id).unwrap().next_start + 2 * service::PERIOD_BLOCKS;
    // A real timeout first makes the qualified node stale; seed only the sticky
    // ban in that timeout's projection, then prove the next completed interval.
    for kind in ["rotation", "reactivation"] {
        model.to(end);
        for (phase, code) in [("before", 91), ("after", 92)] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("controls.sqlite");
            populate(&path, &model);
            let mut d = open_service(&path);
            if kind == "reactivation" {
                // Explicit synthetic sticky-ban checkpoint fixture, NOT a claim
                // that the small fixture population naturally reaches this ban.
                // Keep its undo projection consistent. Only this initial score
                // is seeded; control signatures, archive checks, disk commits,
                // checkpoint authentication and reorg execution are unchanged.
                let mut e = d.chain.ledger().service_entry(&id).unwrap().clone();
                e.score.punish_failure(1);
                e.score.punish_failure(1);
                let node = d
                    .chain
                    .nodes
                    .values_mut()
                    .find(|n| n.height == e.score_height)
                    .unwrap();
                node.delta
                    .as_mut()
                    .unwrap()
                    .services
                    .get_mut(&id)
                    .unwrap()
                    .1 = Some(e.clone());
                d.chain.ledger.set_service(id, Some(e));
            }
            let before = d.chain.ledger().service_entry(&id).unwrap().clone();
            let parent = d.chain.tip();
            let pin = d.create_state_checkpoint(control_limits()).unwrap();
            drop(d);
            std::fs::write(path.with_extension("pin"), pin.commitment()).unwrap();
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "storage::service_tests::service_crash_worker"])
                .env("MONAR_SERVICE_CRASH_DB", &path)
                .env("MONAR_SERVICE_CRASH_PHASE", phase)
                .env("MONAR_SERVICE_CONTROL", kind)
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(code));
            let mut d = open_control(&path, pin);
            let after = d.chain.ledger().service_entry(&id).unwrap();
            if phase == "before" {
                assert_eq!(after, &before);
            } else {
                assert_ne!(after.control_head, before.control_head);
                assert_eq!(after.credited_seconds, before.credited_seconds);
                if kind == "reactivation" {
                    assert!(!after.score.banned());
                    assert_eq!(after.score.penalty(), 50);
                    assert!(after.qualified(d.chain.height()));
                } else {
                    assert_ne!(after.operator, before.operator);
                }
            }
            let state = d.chain.ledger().service_entry(&id).unwrap().clone();
            let fresh = d.create_state_checkpoint(control_limits()).unwrap();
            drop(d);
            let mut d = open_control(&path, fresh);
            assert_eq!(d.chain.ledger().service_entry(&id), Some(&state));
            if phase == "after" {
                let fork = candidate(&d.chain, parent, &[]);
                let fork = d
                    .submit_checked(fork, 2_000_000, &mut FixturePow::default())
                    .unwrap()
                    .id;
                let fork = candidate(&d.chain, fork, &[]);
                d.submit_checked(fork, 2_000_000, &mut FixturePow::default())
                    .unwrap();
                let expected = before.clone();
                assert_eq!(d.chain.ledger().service_entry(&id), Some(&expected));
            }
        }
    }
}
