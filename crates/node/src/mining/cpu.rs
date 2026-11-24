//! Explicit bounded light-mode CPU worker. Construction starts no thread or search.
use super::{Clock, Node, Submitted, Work};
use std::sync::atomic::{AtomicBool, Ordering};

/// Maximum hashes per call, to give callers regular cancellation/staleness checks.
pub const MAX_BATCH: u32 = 4096;

#[derive(Debug)]
pub enum Error {
    Batch,
    Exhausted,
    Hash(monario_randomx::Error),
    JobMismatch,
    CacheUnavailable,
    ShareTarget,
    Submit(super::Error),
}

/// Untrusted candidate; only the node's full submit path can accept it.
pub struct Solution {
    pub job_id: [u8; 32],
    pub nonce: [u8; 32],
}

pub enum Batch {
    Found(Solution),
    Pending,
    Cancelled,
    Exhausted,
}

/// One thread-local RandomX VM and a caller-selected, non-overlapping nonce range.
/// The caller must stop and replace this worker when the validated tip changes.
pub struct Miner<'a> {
    work: &'a Work,
    verifier: monario_randomx::Verifier,
    next: Option<u64>,
    end: u64,
    target: [u8; 32],
    prefix: [u8; 24],
}
impl<'a> Miner<'a> {
    /// Inclusive range with a private light cache for standalone callers.
    pub fn new(
        work: &'a Work,
        start: u64,
        end: u64,
        mode: monario_randomx::Mode,
    ) -> Result<Self, Error> {
        if start > end {
            return Err(Error::Exhausted);
        }
        let verifier =
            monario_randomx::Verifier::with_mode(&work.seed(), mode).map_err(Error::Hash)?;
        Self::with_verifier(work, start, end, verifier)
    }

    pub(crate) fn with_verifier(
        work: &'a Work,
        start: u64,
        end: u64,
        verifier: monario_randomx::Verifier,
    ) -> Result<Self, Error> {
        if start > end {
            return Err(Error::Exhausted);
        }
        if verifier.seed() != work.seed() {
            return Err(Error::JobMismatch);
        }
        Ok(Self {
            work,
            verifier,
            next: Some(start),
            end,
            target: work.target_le(),
            prefix: [0; 24],
        })
    }

    /// Search a pool-assigned nonce partition against its easier share target.
    /// Pool transport, authentication and independent share verification are
    /// the caller's responsibility; shares do not automatically become blocks.
    pub fn new_pool(
        work: &'a Work,
        start: u64,
        end: u64,
        prefix: [u8; 24],
        share_target: [u8; 32],
        mode: monario_randomx::Mode,
    ) -> Result<Self, Error> {
        if share_target
            .iter()
            .rev()
            .cmp(work.target_le().iter().rev())
            .is_lt()
        {
            return Err(Error::ShareTarget);
        }
        if start > end {
            return Err(Error::Exhausted);
        }
        let verifier =
            monario_randomx::Verifier::with_mode(&work.seed(), mode).map_err(Error::Hash)?;
        Self::with_pool_verifier(work, start, end, prefix, share_target, verifier)
    }

    pub(crate) fn with_pool_verifier(
        work: &'a Work,
        start: u64,
        end: u64,
        prefix: [u8; 24],
        share_target: [u8; 32],
        verifier: monario_randomx::Verifier,
    ) -> Result<Self, Error> {
        if share_target
            .iter()
            .rev()
            .cmp(work.target_le().iter().rev())
            .is_lt()
        {
            return Err(Error::ShareTarget);
        }
        let mut worker = Self::with_verifier(work, start, end, verifier)?;
        worker.prefix = prefix;
        worker.target = share_target;
        Ok(worker)
    }

    /// Search at most `limit` hashes; cancellation is checked before every hash.
    pub fn search_batch(&mut self, limit: u32, stop: &AtomicBool) -> Result<Batch, Error> {
        let mut preimage = self.work.pow_preimage();
        let prefix_start = preimage.len() - 24;
        preimage[prefix_start..].copy_from_slice(&self.prefix);
        search(
            self.work.id(),
            &preimage,
            self.target,
            &mut self.next,
            self.end,
            limit,
            stop,
            |input| self.verifier.hash(input).map_err(Error::Hash),
        )
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Explicit job, range, cancellation and hasher boundaries"
)]
fn search(
    job_id: [u8; 32],
    preimage: &[u8],
    target: [u8; 32],
    next: &mut Option<u64>,
    end: u64,
    limit: u32,
    stop: &AtomicBool,
    mut hash: impl FnMut(&[u8]) -> Result<[u8; 32], Error>,
) -> Result<Batch, Error> {
    if limit == 0 || limit > MAX_BATCH || preimage.len() < 32 {
        return Err(Error::Batch);
    }
    let mut input = preimage.to_vec();
    let offset = input.len() - 32;
    for _ in 0..limit {
        if stop.load(Ordering::Acquire) {
            return Ok(Batch::Cancelled);
        }
        let Some(current) = *next else {
            return Ok(Batch::Exhausted);
        };
        let mut nonce = [0u8; 32];
        nonce[..8].copy_from_slice(&current.to_le_bytes());
        nonce[8..].copy_from_slice(&input[offset + 8..]);
        input[offset..].copy_from_slice(&nonce);
        let digest = hash(&input)?;
        *next = if current == end {
            None
        } else {
            current.checked_add(1)
        };
        if digest.iter().rev().cmp(target.iter().rev()).is_le() {
            return Ok(Batch::Found(Solution { job_id, nonce }));
        }
    }
    Ok(if next.is_some() {
        Batch::Pending
    } else {
        Batch::Exhausted
    })
}

impl Node {
    /// Job ID is checked before ordinary full PoW, consensus and durable validation.
    pub fn submit_solution(
        &mut self,
        work: &Work,
        solution: &Solution,
        clock: Clock,
    ) -> Result<Submitted, Error> {
        if solution.job_id != work.id() {
            return Err(Error::JobMismatch);
        }
        self.submit_work(work, solution.nonce, clock)
            .map_err(Error::Submit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_ranges_cancellation_and_exhaustion_do_not_repeat_nonces() {
        let stop = AtomicBool::new(false);
        let mut next = Some(u64::MAX - 1);
        let mut seen = Vec::new();
        let mut fake = |input: &[u8]| {
            seen.push(input[input.len() - 32..].to_vec());
            Ok([255; 32])
        };
        assert!(matches!(
            search(
                [1; 32],
                &[0; 64],
                [0; 32],
                &mut next,
                u64::MAX,
                1,
                &stop,
                &mut fake
            ),
            Ok(Batch::Pending)
        ));
        stop.store(true, Ordering::Release);
        assert!(matches!(
            search(
                [1; 32],
                &[0; 64],
                [0; 32],
                &mut next,
                u64::MAX,
                1,
                &stop,
                &mut fake
            ),
            Ok(Batch::Cancelled)
        ));
        stop.store(false, Ordering::Release);
        assert!(matches!(
            search(
                [1; 32],
                &[0; 64],
                [0; 32],
                &mut next,
                u64::MAX,
                1,
                &stop,
                &mut fake
            ),
            Ok(Batch::Exhausted)
        ));
        assert!(matches!(
            search(
                [1; 32],
                &[0; 64],
                [0; 32],
                &mut next,
                u64::MAX,
                0,
                &stop,
                &mut fake
            ),
            Err(Error::Batch)
        ));
        assert_eq!(seen.len(), 2);
        assert_ne!(seen[0], seen[1]);
        assert!(next.is_none());
    }
    #[test]
    fn solutions_bind_job_and_use_little_endian_target_comparison() {
        let stop = AtomicBool::new(false);
        let mut next = Some(7);
        let result = search([9; 32], &[0; 64], [1; 32], &mut next, 8, 2, &stop, |_| {
            Ok([0; 32])
        })
        .unwrap();
        let Batch::Found(solution) = result else {
            panic!("expected fixture solution")
        };
        assert_eq!(solution.job_id, [9; 32]);
        assert_eq!(&solution.nonce[..8], &7u64.to_le_bytes());
        assert_eq!(next, Some(8));
    }
    #[test]
    fn hasher_error_does_not_skip_the_nonce() {
        let mut next = Some(4);
        let stop = AtomicBool::new(false);
        assert!(matches!(
            search([0; 32], &[0; 64], [0; 32], &mut next, 9, 1, &stop, |_| Err(
                Error::Hash(monario_randomx::Error::AllocationFailed)
            )),
            Err(Error::Hash(_))
        ));
        assert_eq!(next, Some(4));
    }
    #[test]
    fn wrong_job_is_rejected_before_node_state_changes() {
        use crate::tests::{clock, node};
        use monario_address::{Address, Network, Receiver, TransparentReceiver};
        let (_dir, mut node) = node();
        let address = Address::new(
            Network::Regtest,
            Receiver::Transparent(TransparentReceiver::PublicKeyHash([7; 20])),
        )
        .encode();
        let tip = node.source().chain().unwrap().tip();
        let work = node
            .prepare_work(
                super::super::Request {
                    address: &address,
                    network: Network::Regtest,
                    timestamp: 1105,
                    extra_data: b"",
                },
                clock(0),
            )
            .unwrap()
            .work;
        let solution = Solution {
            job_id: [0; 32],
            nonce: [0; 32],
        };
        assert!(matches!(
            node.submit_solution(&work, &solution, clock(0)),
            Err(Error::JobMismatch)
        ));
        assert_eq!(node.source().chain().unwrap().tip(), tip);
        assert!(node.mempool().is_empty());
        assert!(matches!(
            Miner::new_pool(
                &work,
                0,
                0,
                [1; 24],
                [0; 32],
                monario_randomx::Mode::Interpreter
            ),
            Err(Error::ShareTarget)
        ));
    }
    #[test]
    fn assigned_pool_prefix_is_preserved_and_share_target_is_used() {
        let stop = AtomicBool::new(false);
        let mut next = Some(42);
        let mut preimage = [0; 64];
        preimage[40..].copy_from_slice(&[7; 24]);
        let result = search(
            [9; 32],
            &preimage,
            [255; 32],
            &mut next,
            42,
            1,
            &stop,
            |input| {
                assert_eq!(&input[input.len() - 24..], &[7; 24]);
                Ok([254; 32])
            },
        )
        .unwrap();
        let Batch::Found(solution) = result else {
            panic!("expected fixture share")
        };
        assert_eq!(&solution.nonce[..8], &42u64.to_le_bytes());
        assert_eq!(&solution.nonce[8..], &[7; 24]);
        assert_eq!(solution.job_id, [9; 32]);
        assert!(next.is_none());
    }
    #[test]
    fn fake_worker_crash_child() {
        if std::env::var_os("MONAR_CPU_CRASH_FIXTURE").is_none() {
            return;
        }
        let mut next = Some(7);
        let stop = AtomicBool::new(false);
        let result = search([9; 32], &[0; 64], [1; 32], &mut next, 8, 1, &stop, |_| {
            Ok([0; 32])
        })
        .unwrap();
        assert!(matches!(result, Batch::Found(_)));
        std::process::exit(89);
    }
    #[test]
    fn process_death_discards_ephemeral_progress_and_retry_restarts_range() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "mining::cpu::tests::fake_worker_crash_child",
                "--nocapture",
            ])
            .env("MONAR_CPU_CRASH_FIXTURE", "1")
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(89));
        let mut next = Some(7);
        let stop = AtomicBool::new(false);
        let result = search([9; 32], &[0; 64], [1; 32], &mut next, 8, 1, &stop, |_| {
            Ok([0; 32])
        })
        .unwrap();
        let Batch::Found(solution) = result else {
            panic!("expected fixture solution")
        };
        assert_eq!(&solution.nonce[..8], &7u64.to_le_bytes());
    }
}
