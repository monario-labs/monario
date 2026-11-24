//! Bounded, independently hashed share candidates for a future authenticated pool.
pub mod ledger;
pub mod link;
pub mod session;
pub mod tcp;
pub mod wire;
use super::{Node, Work, cpu::Solution};
use std::collections::BTreeSet;

const MAX_SHARES: usize = 4096;
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Assignment,
    Stale,
    Duplicate,
    Capacity,
    Overflow,
    Policy,
    InvalidShare,
    Storage,
    Hash(monario_randomx::Error),
    Ledger(ledger::Error),
}

/// A share observation is ephemeral and is not a durable credit or block receipt.
pub struct Share {
    pub block_candidate: bool,
}

/// Trusted server-side share-credit policy. Units are not on-chain value and do
/// not become spendable without a separate payout system.
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    pub units_per_share: u64,
    pub units_per_block_candidate: u64,
}

impl Policy {
    pub fn units(&self, block_candidate: bool) -> Result<u64, Error> {
        let extra = if block_candidate {
            self.units_per_block_candidate
        } else {
            0
        };
        self.units_per_share
            .checked_add(extra)
            .filter(|units| *units > 0)
            .ok_or(Error::Policy)
    }
}
struct Rules {
    work: Work,
    prefix: [u8; 24],
    start: u64,
    end: u64,
    target: [u8; 32],
    block_target: [u8; 32],
    job_id: [u8; 32],
    seen: BTreeSet<u64>,
}
impl Rules {
    fn new(
        work: &Work,
        prefix: [u8; 24],
        start: u64,
        end: u64,
        target: [u8; 32],
    ) -> Result<Self, Error> {
        let block_target = work.target_le();
        if start > end || target.iter().rev().cmp(block_target.iter().rev()).is_lt() {
            return Err(Error::Assignment);
        }
        Ok(Self {
            work: work.clone(),
            prefix,
            start,
            end,
            target,
            block_target,
            job_id: work.id(),
            seen: BTreeSet::new(),
        })
    }
    fn precheck(&self, node: &Node, solution: &Solution) -> Result<u64, Error> {
        let chain = node.source().chain().map_err(|_| Error::Storage)?;
        if chain.tip() != self.work.parent() || chain.validation_profile() != self.work.profile {
            return Err(Error::Stale);
        }
        if solution.job_id != self.job_id || solution.nonce[8..] != self.prefix {
            return Err(Error::Assignment);
        }
        let value = u64::from_le_bytes(solution.nonce[..8].try_into().expect("fixed nonce"));
        if value < self.start || value > self.end {
            return Err(Error::Assignment);
        }
        Ok(value)
    }

    fn digest(
        &self,
        solution: &Solution,
        mut hash: impl FnMut(&[u8]) -> Result<[u8; 32], Error>,
    ) -> Result<[u8; 32], Error> {
        let mut input = self.work.pow_preimage();
        let offset = input.len() - 32;
        input[offset..].copy_from_slice(&solution.nonce);
        hash(&input)
    }

    fn target(&self, digest: &[u8; 32]) -> Result<Share, Error> {
        if digest.iter().rev().cmp(self.target.iter().rev()).is_gt() {
            return Err(Error::InvalidShare);
        }
        let block_candidate = digest
            .iter()
            .rev()
            .cmp(self.block_target.iter().rev())
            .is_le();
        Ok(Share { block_candidate })
    }

    fn check(
        &mut self,
        node: &Node,
        solution: &Solution,
        hash: impl FnMut(&[u8]) -> Result<[u8; 32], Error>,
    ) -> Result<Share, Error> {
        let value = self.precheck(node, solution)?;
        if self.seen.contains(&value) {
            return Err(Error::Duplicate);
        }
        if self.seen.len() >= MAX_SHARES {
            return Err(Error::Capacity);
        }
        let digest = self.digest(solution, hash)?;
        let share = self.target(&digest)?;
        self.seen.insert(value);
        Ok(share)
    }
}

/// Durable variant: cheap checks, a pre-hash durable duplicate lookup, hashing,
/// target validation, then one transaction that rechecks uniqueness and credits.
fn durable_check(
    rules: &Rules,
    node: &Node,
    solution: &Solution,
    ledger: &ledger::Ledger,
    hash: impl FnMut(&[u8]) -> Result<[u8; 32], Error>,
) -> Result<Share, Error> {
    rules.precheck(node, solution)?;
    if ledger
        .contains(&rules.job_id, &solution.nonce)
        .map_err(map_ledger)?
    {
        return Err(Error::Duplicate);
    }
    let digest = rules.digest(solution, hash)?;
    rules.target(&digest)
}

fn durable(
    rules: &Rules,
    node: &Node,
    solution: &Solution,
    ledger: &mut ledger::Ledger,
    client: [u8; 16],
    policy: &Policy,
    hash: impl FnMut(&[u8]) -> Result<[u8; 32], Error>,
) -> Result<Share, Error> {
    let share = durable_check(rules, node, solution, ledger, hash)?;
    let units = policy.units(share.block_candidate)?;
    ledger
        .credit(
            &rules.job_id,
            &solution.nonce,
            client,
            units,
            share.block_candidate,
        )
        .map_err(map_ledger)?;
    Ok(share)
}

fn map_ledger(error: ledger::Error) -> Error {
    match error {
        ledger::Error::Duplicate => Error::Duplicate,
        ledger::Error::Capacity => Error::Capacity,
        ledger::Error::Overflow => Error::Overflow,
        other => Error::Ledger(other),
    }
}

/// One VM and one assignment. Apply transport authentication and rate limits
/// before calling: invalid shares can still require an expensive RandomX hash.
pub struct Verifier {
    rules: Rules,
    vm: monario_randomx::Verifier,
}
impl Verifier {
    pub fn new(
        work: &Work,
        prefix: [u8; 24],
        start: u64,
        end: u64,
        target: [u8; 32],
        mode: monario_randomx::Mode,
    ) -> Result<Self, Error> {
        let cache = monario_randomx::SharedCache::new(&work.seed()).map_err(Error::Hash)?;
        Self::new_with_verifier(
            work,
            prefix,
            start,
            end,
            target,
            cache.verifier(mode).map_err(Error::Hash)?,
        )
    }

    /// Bind an already initialized, seed-verified VM to one assignment.
    pub(crate) fn new_with_verifier(
        work: &Work,
        prefix: [u8; 24],
        start: u64,
        end: u64,
        target: [u8; 32],
        vm: monario_randomx::Verifier,
    ) -> Result<Self, Error> {
        if vm.seed() != work.seed().as_slice() {
            return Err(Error::Hash(monario_randomx::Error::InvalidSeed));
        }
        let rules = Rules::new(work, prefix, start, end, target)?;
        Ok(Self { rules, vm })
    }

    pub fn verify(&mut self, node: &Node, solution: &Solution) -> Result<Share, Error> {
        self.rules.check(node, solution, |input| {
            self.vm.hash(input).map_err(Error::Hash)
        })
    }

    /// Independently hash a candidate, then durably reject replay and credit its
    /// server-policy units. A duplicate is rejected before the expensive hash.
    pub fn verify_durable(
        &mut self,
        node: &Node,
        solution: &Solution,
        ledger: &mut ledger::Ledger,
        client: [u8; 16],
        policy: &Policy,
    ) -> Result<Share, Error> {
        let Self { rules, vm } = self;
        durable(rules, node, solution, ledger, client, policy, |input| {
            vm.hash(input).map_err(Error::Hash)
        })
    }

    /// Verify without crediting. The caller submits a block candidate to the node
    /// first, then calls `ledger.credit` in a separate authoritative transaction.
    pub fn verify_share_durable(
        &mut self,
        node: &Node,
        solution: &Solution,
        ledger: &ledger::Ledger,
    ) -> Result<Share, Error> {
        let Self { rules, vm } = self;
        durable_check(rules, node, solution, ledger, |input| {
            vm.hash(input).map_err(Error::Hash)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{REAL, append, clock, node, raw, root};
    use monario_address::{Address, Network, Receiver, TransparentReceiver};
    fn work(n: &mut Node) -> Work {
        let address = Address::new(
            Network::Regtest,
            Receiver::Transparent(TransparentReceiver::PublicKeyHash([7; 20])),
        )
        .encode();
        n.prepare_work(
            super::super::Request {
                address: &address,
                network: Network::Regtest,
                timestamp: 1105,
                extra_data: b"",
            },
            clock(0),
        )
        .unwrap()
        .work
    }
    fn solution(work: &Work, value: u64, prefix: [u8; 24]) -> Solution {
        let mut nonce = [0; 32];
        nonce[..8].copy_from_slice(&value.to_le_bytes());
        nonce[8..].copy_from_slice(&prefix);
        Solution {
            job_id: work.id(),
            nonce,
        }
    }
    #[test]
    fn forged_assignment_invalid_hash_duplicate_and_stale_tip_fail_closed() {
        let _serial = REAL.lock().unwrap();
        let (_dir, mut n) = node();
        let w = work(&mut n);
        assert!(matches!(
            Rules::new(&w, [3; 24], 1, 3, [0; 32]),
            Err(Error::Assignment)
        ));
        let mut rules = Rules::new(&w, [3; 24], 1, 3, [255; 32]).unwrap();
        let mut wrong = solution(&w, 1, [3; 24]);
        wrong.job_id = [0; 32];
        assert!(matches!(
            rules.check(&n, &wrong, |_| panic!("must reject before hashing")),
            Err(Error::Assignment)
        ));
        assert!(matches!(
            rules.check(&n, &solution(&w, 1, [4; 24]), |_| panic!("bad prefix")),
            Err(Error::Assignment)
        ));
        assert!(matches!(
            rules.check(&n, &solution(&w, 4, [3; 24]), |_| panic!("bad range")),
            Err(Error::Assignment)
        ));
        let valid = solution(&w, 1, [3; 24]);
        let result = rules.check(&n, &valid, |_| Ok([255; 32])).unwrap();
        assert!(!result.block_candidate);
        assert!(matches!(
            rules.check(&n, &valid, |_| panic!("duplicate")),
            Err(Error::Duplicate)
        ));
        let block = solution(&w, 2, [3; 24]);
        assert!(
            rules
                .check(&n, &block, |_| Ok([0; 32]))
                .unwrap()
                .block_candidate
        );
        append(&mut n, root().id, vec![], 0);
        assert!(matches!(
            rules.check(&n, &solution(&w, 3, [3; 24]), |_| panic!("stale")),
            Err(Error::Stale)
        ));
    }
    #[test]
    fn invalid_share_and_hash_failure_do_not_consume_replay_slots() {
        let (_dir, mut n) = node();
        let w = work(&mut n);
        let mut rules = Rules::new(&w, [3; 24], 1, 2, w.target_le()).unwrap();
        let candidate = solution(&w, 1, [3; 24]);
        assert!(matches!(
            rules.check(&n, &candidate, |_| Ok([255; 32])),
            Err(Error::InvalidShare)
        ));
        assert!(matches!(
            rules.check(&n, &candidate, |_| Err(Error::Hash(
                monario_randomx::Error::AllocationFailed
            ))),
            Err(Error::Hash(_))
        ));
        assert!(rules.seen.is_empty());
        assert!(rules.check(&n, &candidate, |_| Ok([0; 32])).is_ok());
    }
    #[test]
    fn replay_capacity_is_bounded_and_does_not_hash_past_the_limit() {
        let (_dir, mut n) = node();
        let w = work(&mut n);
        let mut rules = Rules::new(&w, [3; 24], 0, 4096, [255; 32]).unwrap();
        for i in 0..4096 {
            rules
                .check(&n, &solution(&w, i, [3; 24]), |_| Ok([0; 32]))
                .unwrap();
        }
        assert!(matches!(
            rules.check(&n, &solution(&w, 4096, [3; 24]), |_| panic!("capacity")),
            Err(Error::Capacity)
        ));
        assert_eq!(rules.seen.len(), 4096);
    }
    #[test]
    fn restart_requires_durable_external_replay_protection() {
        let (_dir, mut n) = node();
        let w = work(&mut n);
        let s = solution(&w, 1, [3; 24]);
        let mut first = Rules::new(&w, [3; 24], 1, 2, [255; 32]).unwrap();
        first.check(&n, &s, |_| Ok([0; 32])).unwrap();
        let mut restarted = Rules::new(&w, [3; 24], 1, 2, [255; 32]).unwrap();
        assert!(restarted.check(&n, &s, |_| Ok([0; 32])).is_ok());
    }
    #[test]
    fn share_crash_worker() {
        if std::env::var_os("MONAR_SHARE_CRASH_FIXTURE").is_none() {
            return;
        }
        let (_dir, mut n) = node();
        let w = work(&mut n);
        let s = solution(&w, 1, [3; 24]);
        let mut rules = Rules::new(&w, [3; 24], 1, 2, [255; 32]).unwrap();
        rules.check(&n, &s, |_| Ok([0; 32])).unwrap();
        std::process::exit(86);
    }
    #[test]
    fn abrupt_exit_discards_ephemeral_replay_state() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "mining::pool::tests::share_crash_worker",
                "--nocapture",
            ])
            .env("MONAR_SHARE_CRASH_FIXTURE", "1")
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(86));
        let (_dir, mut n) = node();
        let w = work(&mut n);
        let s = solution(&w, 1, [3; 24]);
        let mut rules = Rules::new(&w, [3; 24], 1, 2, [255; 32]).unwrap();
        assert!(rules.check(&n, &s, |_| Ok([0; 32])).is_ok());
    }
    #[test]
    fn competing_branch_reorg_rejects_old_assignment_before_hashing() {
        let _serial = REAL.lock().unwrap();
        let (_dir, mut n) = node();
        let first = append(&mut n, root().id, vec![], 0);
        let base = append(&mut n, first, vec![], 0);
        let old = append(&mut n, base, vec![], 0);
        let coin =
            monario_v6::transaction_id(&n.source().stored_block(first).unwrap().transactions[0])
                .unwrap();
        let address = Address::new(
            Network::Regtest,
            Receiver::Transparent(TransparentReceiver::PublicKeyHash([7; 20])),
        )
        .encode();
        let w = n
            .prepare_work(
                super::super::Request {
                    address: &address,
                    network: Network::Regtest,
                    timestamp: 1420,
                    extra_data: b"",
                },
                clock(0),
            )
            .unwrap()
            .work;
        let mut rules = Rules::new(&w, [3; 24], 1, 2, [255; 32]).unwrap();
        let share = solution(&w, 1, [3; 24]);
        let side = append(&mut n, base, vec![raw(0, Some((coin, 0)), 90)], 0);
        assert_ne!(old, side);
        let tip = append(&mut n, side, vec![], 0);
        assert_eq!(n.source().chain().unwrap().tip(), tip);
        assert!(matches!(
            rules.check(&n, &share, |_| panic!("stale reorg share must not hash")),
            Err(Error::Stale)
        ));
        assert!(rules.seen.is_empty());
    }

    fn durable_limits() -> ledger::Limits {
        ledger::Limits {
            max_shares: 64,
            max_clients: 8,
            max_units_per_share: 100,
            max_units_per_client: 10_000,
        }
    }

    fn durable_ledger(pool: [u8; 32]) -> (tempfile::TempDir, ledger::Ledger) {
        let dir = crate::tests::private_tempdir();
        let ledger =
            ledger::Ledger::create(&dir.path().join("pool.sqlite"), pool, durable_limits())
                .unwrap();
        (dir, ledger)
    }

    fn durable_policy() -> Policy {
        Policy {
            units_per_share: 1,
            units_per_block_candidate: 4,
        }
    }

    #[test]
    fn durable_replay_survives_restart_overlapping_assignments_and_reorg() {
        let _serial = REAL.lock().unwrap();
        let (_dir, mut n) = node();
        let w = work(&mut n);
        let (ledger_dir, mut ledger) = durable_ledger([9; 32]);
        let ledger_path = ledger_dir.path().join("pool.sqlite");
        let rules = Rules::new(&w, [3; 24], 1, 4, [255; 32]).unwrap();
        let first = solution(&w, 1, [3; 24]);
        let share = durable(
            &rules,
            &n,
            &first,
            &mut ledger,
            [7; 16],
            &durable_policy(),
            |_| Ok([0; 32]),
        )
        .unwrap();
        assert!(share.block_candidate);
        assert_eq!(ledger.total([7; 16]).unwrap(), 5);
        assert_eq!(ledger.share_count().unwrap(), 1);

        assert!(matches!(
            durable(
                &rules,
                &n,
                &first,
                &mut ledger,
                [8; 16],
                &durable_policy(),
                |_| panic!("duplicate must not hash")
            ),
            Err(Error::Duplicate)
        ));
        let overlapping = Rules::new(&w, [3; 24], 1, 4, [255; 32]).unwrap();
        assert!(matches!(
            durable(
                &overlapping,
                &n,
                &first,
                &mut ledger,
                [7; 16],
                &durable_policy(),
                |_| panic!("overlapping assignment must not hash")
            ),
            Err(Error::Duplicate)
        ));

        drop(ledger);
        let mut ledger = ledger::Ledger::open(&ledger_path, [9; 32], durable_limits()).unwrap();
        assert!(matches!(
            durable(
                &overlapping,
                &n,
                &first,
                &mut ledger,
                [7; 16],
                &durable_policy(),
                |_| panic!("restart must not re-credit")
            ),
            Err(Error::Duplicate)
        ));

        let hard = Rules::new(&w, [3; 24], 1, 4, w.target_le()).unwrap();
        let bad = solution(&w, 2, [3; 24]);
        assert!(matches!(
            durable(
                &hard,
                &n,
                &bad,
                &mut ledger,
                [7; 16],
                &durable_policy(),
                |_| Ok([255; 32])
            ),
            Err(Error::InvalidShare)
        ));
        assert!(!ledger.contains(&w.id(), &bad.nonce).unwrap());

        append(&mut n, root().id, vec![], 0);
        let stale = solution(&w, 3, [3; 24]);
        assert!(matches!(
            durable(
                &hard,
                &n,
                &stale,
                &mut ledger,
                [7; 16],
                &durable_policy(),
                |_| panic!("stale tip must not hash")
            ),
            Err(Error::Stale)
        ));
        assert_eq!(ledger.share_count().unwrap(), 1);
        assert_eq!(ledger.total([7; 16]).unwrap(), 5);
    }
}
