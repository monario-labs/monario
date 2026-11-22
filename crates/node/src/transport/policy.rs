//! Bounded transient retry backoff for connection endpoints.
//!
//! This is local operational policy, not discovery or identity trust. It never
//! promotes a peer, adds a dial target or persists a ban. Entries are keyed by
//! the kernel-supplied socket address, never by peer-supplied wire data, and the
//! table is bounded so failed connections cannot grow memory without limit.

use std::collections::BTreeMap;
use std::net::IpAddr;

/// Delay after the first failure.
pub const BASE_MS: u64 = 10_000;
/// Maximum delay for a repeatedly failing endpoint.
pub const MAX_MS: u64 = 600_000;
/// Maximum remembered endpoints. Expired entries are pruned before eviction.
const MAX_ENTRIES: usize = 1_024;

#[derive(Clone, Copy, Debug)]
struct Entry {
    failures: u32,
    until: u64,
}

/// Per-IP exponential retry schedule. `failure` and `success` are explicit so a
/// caller can credit only a completed handshake, not a socket that merely opened.
#[derive(Default)]
pub struct RetryPolicy {
    entries: BTreeMap<IpAddr, Entry>,
}

impl RetryPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether an endpoint may be dialed or accepted at `now_ms`.
    pub fn allows(&self, ip: IpAddr, now_ms: u64) -> bool {
        self.entries
            .get(&ip)
            .is_none_or(|entry| entry.until <= now_ms)
    }

    /// Record one failed connection/handshake and return the applied delay.
    ///
    /// The schedule is 10 s, 20 s, 40 s, 80 s, 160 s, 320 s, then 600 s. The
    /// counter saturates and the deadline never overflows.
    pub fn failure(&mut self, ip: IpAddr, now_ms: u64) -> u64 {
        if !self.entries.contains_key(&ip) && self.entries.len() >= MAX_ENTRIES {
            self.evict(now_ms);
        }
        let entry = self.entries.entry(ip).or_insert(Entry {
            failures: 0,
            until: 0,
        });
        entry.failures = entry.failures.saturating_add(1);
        let delay = backoff(entry.failures);
        entry.until = now_ms.saturating_add(delay);
        delay
    }

    /// Clear the history for a completed handshake.
    pub fn success(&mut self, ip: IpAddr) {
        self.entries.remove(&ip);
    }

    /// Number of remembered endpoints. Intended for bounded-state tests.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }

    fn evict(&mut self, now_ms: u64) {
        self.entries.retain(|_, entry| entry.until > now_ms);
        if self.entries.len() < MAX_ENTRIES {
            return;
        }
        if let Some(oldest) = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.until)
            .map(|(ip, _)| *ip)
        {
            self.entries.remove(&oldest);
        }
    }
}

/// Deterministic delay for a failure count, independent of wall time.
pub fn backoff(failures: u32) -> u64 {
    let shift = failures.saturating_sub(1).min(6);
    BASE_MS.saturating_mul(1_u64 << shift).min(MAX_MS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
    }

    #[test]
    fn backoff_is_monotonic_and_capped() {
        let expected = [
            10_000_u64, 20_000, 40_000, 80_000, 160_000, 320_000, 600_000, 600_000,
        ];
        for (index, delay) in expected.into_iter().enumerate() {
            assert_eq!(backoff(index as u32 + 1), delay);
        }
        assert_eq!(backoff(0), BASE_MS);
        assert_eq!(backoff(u32::MAX), MAX_MS);
    }

    #[test]
    fn failure_blocks_only_until_the_deadline_then_allows() {
        let mut policy = RetryPolicy::new();
        let ip = v4(1);
        assert!(policy.allows(ip, 0));
        assert_eq!(policy.failure(ip, 1_000), BASE_MS);
        assert!(!policy.allows(ip, 1_000));
        assert!(!policy.allows(ip, 1_000 + BASE_MS - 1));
        assert!(policy.allows(ip, 1_000 + BASE_MS));

        assert_eq!(policy.failure(ip, 1_000 + BASE_MS), 2 * BASE_MS);
        assert!(!policy.allows(ip, 1_000 + BASE_MS));
        assert_eq!(policy.len(), 1);
    }

    #[test]
    fn success_resets_and_addresses_are_independent() {
        let mut policy = RetryPolicy::new();
        let a = v4(2);
        let b = IpAddr::V6(Ipv6Addr::LOCALHOST);
        policy.failure(a, 0);
        policy.failure(a, 0);
        policy.failure(b, 0);
        assert!(!policy.allows(a, 0));
        assert!(!policy.allows(b, 0));

        policy.success(a);
        assert!(policy.allows(a, 0));
        assert!(!policy.allows(b, 0));
        assert_eq!(policy.len(), 1);
    }

    #[test]
    fn expired_entries_are_pruned_and_the_table_is_bounded() {
        let mut policy = RetryPolicy::new();
        for index in 0..MAX_ENTRIES {
            let ip = IpAddr::V4(Ipv4Addr::new(
                10,
                (index >> 16) as u8,
                (index >> 8) as u8,
                index as u8,
            ));
            policy.failure(ip, 0);
        }
        assert_eq!(policy.len(), MAX_ENTRIES);

        // A new endpoint evicts an existing entry instead of growing without bound.
        let extra = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        policy.failure(extra, 0);
        assert_eq!(policy.len(), MAX_ENTRIES);
        assert!(!policy.allows(extra, 0));

        // Once deadlines pass, expired entries are discarded before eviction.
        let later = MAX_MS + 1;
        policy.failure(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)), later);
        assert_eq!(policy.len(), 1);
    }

    #[test]
    fn deadline_saturates_at_the_maximum_clock() {
        let mut policy = RetryPolicy::new();
        let ip = v4(9);
        assert_eq!(policy.failure(ip, u64::MAX), BASE_MS);
        assert!(policy.allows(ip, u64::MAX));
    }
}
