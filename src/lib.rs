//! Monario (MONAR) monetary consensus primitives.
//!
//! This library does not implement a node, proof system, wallet, or mining.

use std::{fmt, str::FromStr};

pub mod rewards;

/// Target mean block interval. This constant alone does not implement difficulty.
pub const TARGET_BLOCK_SECONDS: u64 = 90;
/// Number of indivisible units in one MONAR.
pub const ATOMS_PER_COIN: u64 = 100_000_000;
/// Maximum absolute individual v6 value or shielded value balance, in atoms.
/// This wire-format bound is not a cap on total supply.
pub const MAX_TRANSACTION_VALUE_ATOMS: u64 = 2_100_000_000_000_000;
/// Subsidy for the first paying block: 7.7 MONAR.
pub const INITIAL_SUBSIDY_ATOMS: u64 = 770_000_000;
/// Number of blocks in the 15-year main emission era at 90-second blocks.
pub const MAIN_EMISSION_BLOCKS: u64 = 5_256_000;
/// Perpetual tail emission per block from the end of the main era onward.
pub const TAIL_EMISSION_ATOMS: u64 = 20_000_000;
/// Exact scheduled subsidy through [`MAIN_EMISSION_BLOCKS`], inclusive: 21 million MONAR.
pub const MAIN_EMISSION_ATOMS: u128 = 2_100_000_000_000_000;
/// Number of linear segments used to interpolate the gently curved main schedule.
pub const EMISSION_CURVE_SEGMENTS: u64 = 16;
/// Mid-curve bonus amplitude for `4*x*(1-x)`, in atoms.
pub const EMISSION_CURVE_BONUS_ATOMS: u64 = 6_841_796;
/// One-atom rounding correction applied over this many early main-era blocks.
pub const EMISSION_ROUNDING_BLOCKS: u64 = 516_988;

/// Nonnegative atomic amount. The whole `u64` range is representable: supply has
/// no ceiling, so arithmetic is bounded by machine overflow rather than a cap.
///
/// The private representation prevents unchecked construction. No floating-point
/// conversion or implicit arithmetic is provided. Signed pool balances require
/// a separate type and must not be represented by this type.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Amount(u64);

/// Failure to construct or calculate a valid amount.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AmountError {
    /// Arithmetic overflowed the `u64` atomic range.
    OutOfRange,
    /// Subtraction would produce a negative amount.
    Underflow,
    /// Input does not follow the documented decimal grammar.
    InvalidDecimal,
}

impl fmt::Display for AmountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::OutOfRange => "amount exceeds the atomic range",
            Self::Underflow => "amount subtraction underflow",
            Self::InvalidDecimal => "invalid decimal amount",
        })
    }
}

impl std::error::Error for AmountError {}

impl Amount {
    /// Zero MONAR.
    pub const ZERO: Self = Self(0);

    /// Construct an amount from exact atomic units. Every `u64` is valid.
    pub const fn from_atoms(atoms: u64) -> Result<Self, AmountError> {
        Ok(Self(atoms))
    }

    /// Return exact atomic units.
    pub const fn atoms(self) -> u64 {
        self.0
    }

    /// Add amounts, rejecting `u64` overflow.
    pub fn checked_add(self, other: Self) -> Result<Self, AmountError> {
        self.0
            .checked_add(other.0)
            .map(Self)
            .ok_or(AmountError::OutOfRange)
    }

    /// Subtract amounts, rejecting a negative result.
    pub fn checked_sub(self, other: Self) -> Result<Self, AmountError> {
        self.0
            .checked_sub(other.0)
            .map(Self)
            .ok_or(AmountError::Underflow)
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{:08}",
            self.0 / ATOMS_PER_COIN,
            self.0 % ATOMS_PER_COIN
        )
    }
}

impl FromStr for Amount {
    type Err = AmountError;

    /// Parse ASCII decimal MONAR without rounding or floating point.
    ///
    /// Requires an integer part without redundant leading zeroes and an optional
    /// fractional part of one to eight digits. Signs, whitespace, exponents,
    /// separators, and non-ASCII digits are rejected. Input is bounded before
    /// scanning; values that overflow `u64` atoms fail with `OutOfRange`.
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if input.is_empty() || input.len() > 21 {
            return Err(AmountError::InvalidDecimal);
        }
        let (whole, fraction) = match input.split_once('.') {
            Some((whole, fraction)) if !fraction.is_empty() && fraction.len() <= 8 => {
                (whole, fraction)
            }
            Some(_) => return Err(AmountError::InvalidDecimal),
            None => (input, ""),
        };
        if whole.is_empty()
            || whole.len() > 12
            || (whole.len() > 1 && whole.starts_with('0'))
            || !whole.bytes().all(|b| b.is_ascii_digit())
            || !fraction.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(AmountError::InvalidDecimal);
        }
        // At most twelve and eight ASCII digits per part respectively: both folds
        // fit in `u64`; the product and sum are checked against the atomic range.
        let digits = |s: &str| s.bytes().fold(0_u64, |n, b| n * 10 + u64::from(b - b'0'));
        let atoms = digits(whole)
            .checked_mul(ATOMS_PER_COIN)
            .and_then(|n| n.checked_add(digits(fraction) * 10_u64.pow(8 - fraction.len() as u32)))
            .ok_or(AmountError::OutOfRange)?;
        Self::from_atoms(atoms)
    }
}

/// Aggregate issued supply or shielded pool balance in atoms.
/// The bound is the maximum scheduled issuance over all representable heights.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Supply(u128);

// Snapshot delta checks compare aggregate balances using signed 128-bit arithmetic.
const _: () = assert!(cumulative_subsidy(u64::MAX) <= i128::MAX as u128);
const _: () = assert!(cumulative_subsidy(MAIN_EMISSION_BLOCKS) == MAIN_EMISSION_ATOMS);

impl Supply {
    /// An empty aggregate balance.
    pub const ZERO: Self = Self(0);
    /// Construct an aggregate balance, rejecting values beyond scheduled issuance.
    pub const fn from_atoms(atoms: u128) -> Result<Self, AmountError> {
        if atoms > cumulative_subsidy(u64::MAX) {
            Err(AmountError::OutOfRange)
        } else {
            Ok(Self(atoms))
        }
    }
    /// Return the exact aggregate balance in atoms.
    pub const fn atoms(self) -> u128 {
        self.0
    }
    /// Add an individual transaction amount without wrapping.
    pub fn checked_add(self, amount: Amount) -> Result<Self, AmountError> {
        Self::from_atoms(
            self.0
                .checked_add(u128::from(amount.atoms()))
                .ok_or(AmountError::OutOfRange)?,
        )
    }
    /// Subtract an individual transaction amount without underflow.
    pub fn checked_sub(self, amount: Amount) -> Result<Self, AmountError> {
        Self::from_atoms(
            self.0
                .checked_sub(u128::from(amount.atoms()))
                .ok_or(AmountError::Underflow)?,
        )
    }
}

impl From<Amount> for Supply {
    fn from(value: Amount) -> Self {
        Self(u128::from(value.atoms()))
    }
}

impl PartialEq<Amount> for Supply {
    fn eq(&self, other: &Amount) -> bool {
        self.0 == u128::from(other.atoms())
    }
}

const fn emission_curve_knot(segment: u64) -> (u64, u64) {
    let span = MAIN_EMISSION_BLOCKS - 1;
    let position = segment * span / EMISSION_CURVE_SEGMENTS;
    let decline = (INITIAL_SUBSIDY_ATOMS - TAIL_EMISSION_ATOMS) as u128 * (span - position) as u128
        / span as u128;
    let curve =
        EMISSION_CURVE_BONUS_ATOMS as u128 * 4 * position as u128 * (span - position) as u128
            / (span as u128 * span as u128);
    (
        position,
        TAIL_EMISSION_ATOMS + decline as u64 + curve as u64,
    )
}

/// Maximum subsidy at a height, excluding transaction fees.
///
/// Genesis (height zero) issues nothing. The main era starts at 7.7 MONAR and
/// follows a gently curved, 16-segment integer schedule through block 5,256,000.
/// Its exact cumulative subsidy is 21,000,000 MONAR. Each later block pays the
/// perpetual 0.2 MONAR tail, so lifetime issuance is not capped at 21 million.
/// Integer arithmetic and rounding are consensus-defined and platform-independent.
pub const fn subsidy(height: u64) -> Amount {
    if height == 0 {
        return Amount::ZERO;
    }
    if height >= MAIN_EMISSION_BLOCKS {
        return Amount(TAIL_EMISSION_ATOMS);
    }
    let position = height - 1;
    let mut low = 0;
    let mut high = EMISSION_CURVE_SEGMENTS;
    while low + 1 < high {
        let middle = low + (high - low) / 2;
        if emission_curve_knot(middle).0 <= position {
            low = middle;
        } else {
            high = middle;
        }
    }
    let (start, first) = emission_curve_knot(low);
    let (end, second) = emission_curve_knot(low + 1);
    let decline = (first - second) as u128 * (position - start) as u128 / (end - start) as u128;
    let rounding_atom = if height >= 2 && height <= EMISSION_ROUNDING_BLOCKS + 1 {
        1
    } else {
        0
    };
    Amount(first - decline as u64 + rounding_atom)
}

/// Sum of `floor((a * i + b) / m)` for `i` in `0..n`, with `m > 0`.
///
/// This is the standard Euclidean floor-sum algorithm, evaluated in `u128` so
/// the linear issuance total never depends on a per-block loop. For the monetary
/// schedule `a < m` and `n <= 5,256,000`, so every intermediate product fits.
const fn floor_sum(n: u128, m: u128, a: u128, b: u128) -> u128 {
    let mut n = n;
    let mut m = m;
    let mut a = a;
    let mut b = b;
    let mut total: u128 = 0;
    while n > 0 {
        if a >= m {
            total += n * (n - 1) / 2 * (a / m);
            a %= m;
        }
        if b >= m {
            total += n * (b / m);
            b %= m;
        }
        let y = a * n + b;
        if y < m {
            break;
        }
        n = y / m;
        b = y % m;
        let old_m = m;
        m = a;
        a = old_m;
    }
    total
}

/// Total authorized subsidy through `height`, inclusive, in atoms.
///
/// This is an issuance upper bound, not a measurement of spendable supply.
/// Underclaims, burns, and lost keys cannot increase it. Fees are excluded.
/// The 16 main-era segments are summed with Euclidean floor sums, then the tail
/// is added directly. The result is exact for every `u64` height without a scan.
pub const fn cumulative_subsidy(height: u64) -> u128 {
    if height == 0 {
        return 0;
    }
    let main_blocks = if height < MAIN_EMISSION_BLOCKS {
        height
    } else {
        MAIN_EMISSION_BLOCKS
    };
    let mut total = 0_u128;
    let mut remaining = main_blocks;
    let mut segment = 0;
    while segment < EMISSION_CURVE_SEGMENTS && remaining > 0 {
        let (start, first) = emission_curve_knot(segment);
        let (end, second) = emission_curve_knot(segment + 1);
        let length = end - start;
        let count = if remaining < length {
            remaining
        } else {
            length
        };
        let decline = floor_sum(count as u128, length as u128, (first - second) as u128, 0);
        total += count as u128 * first as u128 - decline;
        remaining -= count;
        segment += 1;
    }
    // The last main-era block is the final knot at position MAIN_EMISSION_BLOCKS-1.
    if remaining > 0 {
        total += remaining as u128 * TAIL_EMISSION_ATOMS as u128;
    }
    let rounding_blocks = if main_blocks > 1 {
        let eligible = main_blocks - 1;
        if eligible < EMISSION_ROUNDING_BLOCKS {
            eligible
        } else {
            EMISSION_ROUNDING_BLOCKS
        }
    } else {
        0
    };
    total += rounding_blocks as u128;
    total + (height - main_blocks) as u128 * TAIL_EMISSION_ATOMS as u128
}
