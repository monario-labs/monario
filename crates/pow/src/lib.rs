//! Offline Monario PoW primitives. Network parameters and ancestry must be supplied
//! by validated consensus state, never taken from a peer's claimed difficulty or seed.
use num_bigint::BigUint;

/// Required mean spacing in seconds.
pub const BLOCK_SECONDS: u64 = 90;
/// Invalid consensus parameters or proof-of-work input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    ZeroTarget,
    TargetOverflow,
    NegativeTarget,
    NonCanonicalTarget,
    AboveLimit,
    InvalidParameters,
    InvalidHeight,
    WrongSeed,
    InsufficientWork,
    RandomX(monario_randomx::Error),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PoW: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Nonzero unsigned 256-bit target with exact integer comparison.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Target(BigUint);
impl Target {
    pub fn from_le_bytes(bytes: [u8; 32]) -> Result<Self, Error> {
        let n = BigUint::from_bytes_le(&bytes);
        if n == BigUint::ZERO {
            Err(Error::ZeroTarget)
        } else {
            Ok(Self(n))
        }
    }
    pub fn to_le_bytes(&self) -> [u8; 32] {
        let bytes = self.0.to_bytes_le();
        let mut result = [0; 32];
        result[..bytes.len()].copy_from_slice(&bytes);
        result
    }
    /// Decode canonical Bitcoin-style compact encoding, rejecting sign/overflow/zero.
    pub fn from_compact(bits: u32) -> Result<Self, Error> {
        if bits & 0x0080_0000 != 0 {
            return Err(Error::NegativeTarget);
        }
        let size = bits >> 24;
        let word = bits & 0x007f_ffff;
        if size > 34 {
            return Err(Error::TargetOverflow);
        }
        let n = if size <= 3 {
            BigUint::from(word >> (8 * (3 - size)))
        } else {
            BigUint::from(word) << (8 * (size - 3)) as usize
        };
        if n == BigUint::ZERO {
            return Err(Error::ZeroTarget);
        }
        if n.bits() > 256 {
            return Err(Error::TargetOverflow);
        }
        let target = Self(n);
        if target.to_compact() != bits {
            return Err(Error::NonCanonicalTarget);
        }
        Ok(target)
    }
    /// Round down to a compact target; never makes work easier.
    pub fn to_compact(&self) -> u32 {
        let mut size = self.0.bits().div_ceil(8) as u32;
        let mantissa = if size <= 3 {
            &self.0 << (8 * (3 - size)) as usize
        } else {
            &self.0 >> (8 * (size - 3)) as usize
        };
        let mut word = mantissa.to_u32_digits()[0];
        if word & 0x0080_0000 != 0 {
            word >>= 8;
            size += 1;
        }
        (size << 24) | word
    }
    /// RandomX digest is interpreted as a little-endian unsigned integer.
    pub fn accepts(&self, digest: &[u8; 32]) -> bool {
        BigUint::from_bytes_le(digest) <= self.0
    }
    /// Exact work, with no machine-word truncation or wrapping.
    pub fn work(&self) -> BigUint {
        (BigUint::from(1_u8) << 256_usize) / (&self.0 + 1_u8)
    }
}

/// Fixed-anchor ASERT configuration. No default half-life or launch target exists.
pub struct Asert {
    half_life: u64,
    anchor_height: u64,
    anchor_parent_time: u64,
    anchor: Target,
    limit: Target,
}
impl Asert {
    pub fn new(
        half_life: u64,
        anchor_height: u64,
        anchor_parent_time: u64,
        anchor: Target,
        limit: Target,
    ) -> Result<Self, Error> {
        if half_life == 0 || anchor_height == 0 || anchor_height == u64::MAX {
            return Err(Error::InvalidParameters);
        }
        if anchor > limit {
            return Err(Error::AboveLimit);
        }
        if Target::from_compact(anchor.to_compact())? != anchor {
            return Err(Error::NonCanonicalTarget);
        }
        Ok(Self {
            half_life,
            anchor_height,
            anchor_parent_time,
            anchor,
            limit,
        })
    }
    /// Calculate for the child of this validated parent, not using the child's timestamp.
    /// Caller must establish that the fixed anchor belongs to the parent's branch.
    pub fn next_target(&self, parent_height: u64, parent_time: u64) -> Result<Target, Error> {
        if parent_height < self.anchor_height || parent_height == u64::MAX {
            return Err(Error::InvalidHeight);
        }
        let dh = i128::from(parent_height - self.anchor_height) + 1;
        let dt = i128::from(parent_time) - i128::from(self.anchor_parent_time);
        // u64 times/heights and a 90-second interval fit comfortably in i128,
        // including the multiplication by 65536. Signed division truncates to zero.
        let exponent = ((dt - i128::from(BLOCK_SECONDS) * dh) * 65536) / i128::from(self.half_life);
        let integral = exponent.div_euclid(65536);
        let fraction = exponent.rem_euclid(65536) as u128;
        let factor = 65536
            + ((195766423245049_u128 * fraction
                + 971821376 * fraction * fraction
                + 5127 * fraction * fraction * fraction
                + (1_u128 << 47))
                >> 48);
        // Saturate BEFORE any variable-sized allocation or conversion to usize.
        let raw = if integral >= 256 {
            self.limit.0.clone()
        } else if integral <= -257 {
            BigUint::from(1_u8)
        } else {
            let product = &self.anchor.0 * BigUint::from(factor);
            if integral >= 0 {
                (product << integral as usize) >> 16_usize
            } else {
                product >> (16 - integral) as usize
            }
        };
        let raw = raw.max(BigUint::from(1_u8)).min(self.limit.0.clone());
        // Header difficulty and work always use the compact-quantized target.
        Target::from_compact(Target(raw).to_compact())
    }
    pub fn next_bits(&self, parent_height: u64, parent_time: u64) -> Result<u32, Error> {
        Ok(self.next_target(parent_height, parent_time)?.to_compact())
    }
    /// Reject a miner-supplied target unless it equals the computed expected target.
    pub fn validate_bits(
        &self,
        bits: u32,
        parent_height: u64,
        parent_time: u64,
    ) -> Result<Target, Error> {
        let claimed = Target::from_compact(bits)?;
        if claimed > self.limit {
            return Err(Error::AboveLimit);
        }
        let expected = self.next_target(parent_height, parent_time)?;
        if claimed != expected {
            return Err(Error::InvalidParameters);
        }
        Ok(expected)
    }
}

/// Compute a lagged seed ancestor height. Parameters are explicit, not launch defaults.
/// At a boundary, use the preceding interval until the lag has elapsed.
pub fn seed_height(height: u64, interval: u64, lag: u64) -> Result<u64, Error> {
    if interval == 0 || lag >= interval {
        return Err(Error::InvalidParameters);
    }
    let shifted = height.saturating_sub(lag).saturating_sub(1);
    Ok((shifted / interval) * interval)
}

/// Verify one supplied preimage using a branch-derived seed and expected target.
/// This is not header validation: the caller owns canonical encoding and ancestry.
pub fn verify(
    verifier: &mut monario_randomx::Verifier,
    expected_seed: &[u8; 32],
    preimage: &[u8],
    expected_target: &Target,
) -> Result<(), Error> {
    if verifier.seed() != expected_seed {
        return Err(Error::WrongSeed);
    }
    let hash = verifier.hash(preimage).map_err(Error::RandomX)?;
    if expected_target.accepts(&hash) {
        Ok(())
    } else {
        Err(Error::InsufficientWork)
    }
}
