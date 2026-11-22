//! Population-based PoSe arithmetic, following Dash's threshold/decay convention.
//! NOT a service verifier or integrated eligibility state. The authenticated
//! registry, unique challenge outcomes and signed revival records remain required.

/// Maximum penalty: all registered identities, including banned ones, with a
/// floor of 100. The floor prevents a tiny population from rounding penalties away.
pub fn maximum_penalty(registered: u32) -> u32 {
    registered.max(100)
}

/// Missed-proof increment: floor(66% of the population-based maximum).
/// Wide multiplication avoids overflow even for a hostile u32 maximum count.
pub fn failure_penalty(registered: u32) -> u32 {
    (u64::from(maximum_penalty(registered)) * 66 / 100) as u32
}

/// Pure score primitive. It grants no payment eligibility and verifies no evidence.
/// The future registry must apply decay exactly once per block BEFORE that block's
/// authenticated failure outcomes. Never feed peer allegations into this type.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Score {
    penalty: u32,
    banned: bool,
}
impl Score {
    pub fn penalty(self) -> u32 {
        self.penalty
    }
    pub fn banned(self) -> bool {
        self.banned
    }
    /// Unbanned entries decay by one per processed block; banned entries never heal.
    /// Population shrinkage alone does not implicitly unban or newly ban an entry.
    pub fn decay_block(&mut self) {
        self.decay_blocks(1);
    }
    pub(crate) fn decay_blocks(&mut self, blocks: u64) {
        if !self.banned {
            self.penalty = self
                .penalty
                .saturating_sub(blocks.min(u64::from(u32::MAX)) as u32);
        }
    }
    pub(crate) fn from_parts(penalty: u32, banned: bool) -> Option<Self> {
        (!banned || penalty > 0).then_some(Self { penalty, banned })
    }
    /// Apply ONE independently established missed scheduled proof. Replays must be
    /// rejected by the future registry/challenge layer, not by this arithmetic type.
    pub fn punish_failure(&mut self, registered: u32) {
        if self.banned {
            return;
        }
        let maximum = maximum_penalty(registered);
        self.penalty = (u64::from(self.penalty) + u64::from(failure_penalty(registered)))
            .min(u64::from(maximum)) as u32;
        self.banned = self.penalty == maximum;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn population_floor_rounding_and_integer_extremes() {
        for n in [0, 1, 2, 99, 100, 101, 102, 1000, 5000, u32::MAX] {
            assert_eq!(maximum_penalty(n), n.max(100));
            assert_eq!(
                u128::from(failure_penalty(n)),
                u128::from(n.max(100)) * 66 / 100
            );
            assert!(failure_penalty(n) > 0);
            let mut s = Score::default();
            s.punish_failure(n);
            s.punish_failure(n);
            assert_eq!(s.penalty(), maximum_penalty(n));
            assert!(s.banned());
        }
    }
    #[test]
    fn published_dash_example_caps_at_ban_and_never_automatically_heals() {
        let mut s = Score::default();
        s.punish_failure(5000);
        assert_eq!(s.penalty(), 3300);
        for _ in 0..1733 {
            s.decay_block();
        }
        assert_eq!(s.penalty(), 1567);
        s.punish_failure(5000);
        assert_eq!(s.penalty(), 4867);
        for _ in 0..3766 {
            s.decay_block();
        }
        assert_eq!(s.penalty(), 1101);
        s.punish_failure(5000);
        assert_eq!(s.penalty(), 4401);
        for _ in 0..1500 {
            s.decay_block();
        }
        assert_eq!(s.penalty(), 2901);
        s.punish_failure(5000);
        assert_eq!(s.penalty(), 5000);
        assert!(s.banned());
        for _ in 0..10000 {
            s.decay_block();
        }
        s.punish_failure(u32::MAX);
        assert_eq!(s.penalty(), 5000);
        assert!(s.banned());
    }
    #[test]
    fn one_node_penalties_saturate_and_population_churn_does_not_clear_bans() {
        let mut s = Score::default();
        s.decay_block();
        assert_eq!(s.penalty(), 0);
        s.punish_failure(1);
        assert_eq!(s.penalty(), 66);
        assert!(!s.banned());
        s.decay_block();
        assert_eq!(s.penalty(), 65);
        s.punish_failure(1);
        assert_eq!(s.penalty(), 100);
        assert!(s.banned());
        s.punish_failure(5000);
        s.decay_block();
        assert_eq!(s.penalty(), 100);
        assert!(s.banned());
        let mut s = Score::default();
        s.punish_failure(5000);
        s.decay_block();
        assert_eq!(s.penalty(), 3299);
        assert!(!s.banned());
        s.punish_failure(1);
        assert_eq!(s.penalty(), 100);
        assert!(s.banned());
    }
}
