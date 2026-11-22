//! Deterministic offline fee estimation from validated active-branch samples.
//! No mempool, node connection, socket or inclusion guarantee.
use super::*;
use monario_chain::storage::DurableChain;
use monario_v6::V6Verifier;

pub(super) struct Options {
    pub(super) blocks: usize,
    pub(super) samples: usize,
    pub(super) tx_bytes: u32,
    pub(super) floor_atoms: u64,
}

impl Options {
    pub(super) fn parse(options: &mut BTreeMap<String, OsString>) -> Result<Self, Error> {
        let blocks = options
            .remove("--blocks")
            .map(|v| number(&text(Some(v))?))
            .transpose()?
            .unwrap_or(20);
        let samples = options
            .remove("--samples")
            .map(|v| number(&text(Some(v))?))
            .transpose()?
            .unwrap_or(200);
        let tx_bytes = options
            .remove("--tx-bytes")
            .map(|v| number(&text(Some(v))?))
            .transpose()?
            .unwrap_or(250);
        let floor_atoms = options
            .remove("--floor-atoms")
            .map(|v| number(&text(Some(v))?))
            .transpose()?
            .unwrap_or(0);
        if !(1..=1_000).contains(&blocks)
            || !(1..=10_000).contains(&samples)
            || !(1..=2_000_000).contains(&tx_bytes)
        {
            return Err(Error::Arguments);
        }
        Ok(Self {
            blocks: blocks as usize,
            samples: samples as usize,
            tx_bytes: u32::try_from(tx_bytes).map_err(|_| Error::Arguments)?,
            floor_atoms,
        })
    }
}

/// Minimum samples before a suggestion is published. Fewer samples are reported
/// as insufficient rather than silently treated as a market rate.
const MIN_SAMPLES: usize = 8;
const RATE_SCALE: u128 = 1_000;

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Estimate {
    pub(super) samples: usize,
    pub(super) rate_samples: usize,
    pub(super) median_per_kb: Option<u128>,
    pub(super) p75_per_kb: Option<u128>,
    pub(super) suggested: Option<u64>,
    pub(super) enough: bool,
}

/// Pure, deterministic estimator shared by the CLI and tests. The rate is
/// ordered atoms per 1,000 canonical transaction bytes. It never guesses when
/// there are fewer than `MIN_SAMPLES` valid observations.
fn estimate(samples: &[monario_chain::FeeSample], tx_bytes: u32, floor: u64) -> Estimate {
    let mut rates: Vec<u128> = samples
        .iter()
        .filter(|sample| sample.bytes > 0)
        .map(|sample| (u128::from(sample.fee_atoms) * RATE_SCALE) / u128::from(sample.bytes))
        .collect();
    rates.sort_unstable();
    let percentile = |percent: usize| -> Option<u128> {
        if rates.is_empty() {
            None
        } else {
            let index = ((rates.len() - 1) * percent) / 100;
            rates.get(index).copied()
        }
    };
    let median = percentile(50);
    let p75 = percentile(75);
    let enough = rates.len() >= MIN_SAMPLES;
    let suggested = if enough {
        median.map(|rate| {
            let atoms = (rate * u128::from(tx_bytes)).div_ceil(RATE_SCALE);
            u64::try_from(atoms).unwrap_or(u64::MAX).max(floor)
        })
    } else {
        None
    };
    Estimate {
        samples: samples.len(),
        rate_samples: rates.len(),
        median_per_kb: median,
        p75_per_kb: p75,
        suggested,
        enough,
    }
}

pub(super) fn execute(
    source: &DurableChain<V6Verifier>,
    options: Options,
) -> Result<serde_json::Value, Error> {
    let chain = source.chain().map_err(|_| Error::Scan)?;
    let raw = chain.recent_fee_samples(options.blocks, options.samples);
    let estimate = estimate(&raw, options.tx_bytes, options.floor_atoms);
    Ok(serde_json::json!({
        "validation_profile": hex(&chain.validation_profile()),
        "validated_tip": hex(&chain.tip()),
        "height": chain.height().to_string(),
        "blocks_requested": options.blocks,
        "samples_requested": options.samples,
        "sample_count": estimate.samples,
        "rate_sample_count": estimate.rate_samples,
        "enough_data": estimate.enough,
        "minimum_samples": MIN_SAMPLES,
        "tx_bytes": options.tx_bytes,
        "floor_atoms": options.floor_atoms.to_string(),
        "median_atoms_per_kb": estimate.median_per_kb.map(|rate| rate.to_string()),
        "p75_atoms_per_kb": estimate.p75_per_kb.map(|rate| rate.to_string()),
        "suggested_fee_atoms": estimate.suggested.map(|atoms| atoms.to_string()),
        "heuristic": true,
        "samples_are_active_branch_only": true,
        "note": "Historical validated fee samples only. This is a heuristic, not mempool policy, a relay guarantee or an inclusion guarantee.",
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Options, Error> {
        let mut map = BTreeMap::new();
        let mut i = 0;
        while i < args.len() {
            map.insert(args[i].to_owned(), OsString::from(args[i + 1]));
            i += 2;
        }
        Options::parse(&mut map)
    }

    #[test]
    fn fee_options_are_bounded_and_defaulted() {
        let defaults = parse(&[]).unwrap();
        assert_eq!(defaults.blocks, 20);
        assert_eq!(defaults.samples, 200);
        assert_eq!(defaults.tx_bytes, 250);
        assert_eq!(defaults.floor_atoms, 0);
        let custom = parse(&[
            "--blocks",
            "5",
            "--samples",
            "50",
            "--tx-bytes",
            "300",
            "--floor-atoms",
            "7",
        ])
        .unwrap();
        assert_eq!(custom.blocks, 5);
        assert_eq!(custom.samples, 50);
        assert_eq!(custom.tx_bytes, 300);
        assert_eq!(custom.floor_atoms, 7);
        for bad in [
            &["--blocks", "0"][..],
            &["--blocks", "1001"][..],
            &["--samples", "0"][..],
            &["--tx-bytes", "0"][..],
            &["--tx-bytes", "4000001"][..],
            &["--floor-atoms", "x"][..],
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }
}

#[cfg(test)]
mod estimator_tests {
    use super::*;
    use monario_chain::FeeSample;

    fn sample(fee_atoms: u64, bytes: u32) -> FeeSample {
        FeeSample { fee_atoms, bytes }
    }

    #[test]
    fn estimate_requires_enough_valid_samples() {
        let none = estimate(&[], 250, 0);
        assert_eq!(none.samples, 0);
        assert_eq!(none.rate_samples, 0);
        assert!(!none.enough);
        assert_eq!(none.suggested, None);
        let seven = vec![sample(10, 100); 7];
        let e = estimate(&seven, 250, 1_000);
        assert_eq!(e.samples, 7);
        assert!(!e.enough);
        assert_eq!(e.suggested, None);
        let eight = vec![sample(10, 100); 8];
        let e = estimate(&eight, 250, 0);
        assert!(e.enough);
        assert_eq!(e.rate_samples, 8);
        assert_eq!(e.median_per_kb, Some(100));
        assert_eq!(e.p75_per_kb, Some(100));
        assert_eq!(e.suggested, Some(25));
    }

    #[test]
    fn estimate_ignores_zero_bytes_rounds_up_and_applies_a_floor() {
        let mut samples = vec![sample(1, 3); 8];
        samples.push(sample(1_000, 0));
        let e = estimate(&samples, 10, 0);
        assert_eq!(e.samples, 9);
        assert_eq!(e.rate_samples, 8);
        assert_eq!(e.median_per_kb, Some(333));
        // ceil(333 * 10 / 1000) = 4
        assert_eq!(e.suggested, Some(4));
        let floor = estimate(&samples, 10, 9);
        assert_eq!(floor.suggested, Some(9));
        assert_eq!(floor.median_per_kb, Some(333));
    }

    #[test]
    fn estimate_is_deterministic_for_equal_rates() {
        let samples = vec![sample(5, 4); 8];
        let first = estimate(&samples, 1_000, 0);
        let second = estimate(&samples, 1_000, 0);
        assert_eq!(first, second);
        assert_eq!(first.median_per_kb, Some(1_250));
        assert_eq!(first.suggested, Some(1_250));
    }
}
