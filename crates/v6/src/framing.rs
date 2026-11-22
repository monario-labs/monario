//! Allocation-free structural preflight for the pinned Monario v6 grammar.
//! Curve elements, authorization and contextual validity remain verifier duties.
use super::{BRANCH_ID, Error};
use monario_chain::wire::read_compact_size;
use zcash_primitives::transaction::components::orchard::{ACTION_SIZE, SPEND_AUTH_SIG_SIZE};

struct Reader<'a> {
    bytes: &'a [u8],
}
impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], Error> {
        if n > self.bytes.len() {
            return Err(Error::Invalid);
        }
        let (value, rest) = self.bytes.split_at(n);
        self.bytes = rest;
        Ok(value)
    }
    fn compact(&mut self) -> Result<usize, Error> {
        usize::try_from(read_compact_size(&mut self.bytes).map_err(|_| Error::Invalid)?)
            .map_err(|_| Error::Invalid)
    }
    fn count(&mut self, min_bytes: usize, max: usize) -> Result<usize, Error> {
        let n = self.compact()?;
        if n > max || n > self.bytes.len() / min_bytes {
            return Err(Error::Invalid);
        }
        Ok(n)
    }
    fn script(&mut self) -> Result<(), Error> {
        let n = self.count(1, self.bytes.len())?;
        self.take(n)?;
        Ok(())
    }
}
pub(super) fn transaction_length(bytes: &[u8]) -> Result<usize, Error> {
    // This existing backend limit is also applied before upstream allocation.
    let bounded = &bytes[..bytes.len().min(2_000_000)];
    let mut r = Reader { bytes: bounded };
    let header = r.take(24)?;
    if header[..4] != 0x8000_0006_u32.to_le_bytes()
        || header[4..8] != zcash_protocol::constants::V6_VERSION_GROUP_ID.to_le_bytes()
        || header[8..12] != BRANCH_ID.to_le_bytes()
    {
        return Err(Error::Invalid);
    }
    let inputs = r.count(41, 10000)?;
    for _ in 0..inputs {
        r.take(36)?;
        r.script()?;
        r.take(4)?;
    }
    let outputs = r.count(9, 10000)?;
    for _ in 0..outputs {
        r.take(8)?;
        r.script()?;
    }
    // Nonempty Sapling spends/outputs and the old Orchard pool are prohibited.
    for _ in 0..3 {
        if r.compact()? != 0 {
            return Err(Error::Invalid);
        }
    }
    let actions = r.count(ACTION_SIZE + SPEND_AUTH_SIG_SIZE, 4096)?;
    if actions != 0 {
        r.take(actions.checked_mul(ACTION_SIZE).ok_or(Error::Invalid)?)?;
        let flag = r.take(1)?[0];
        orchard::bundle::Flags::from_byte(flag, orchard::bundle::BundleVersion::ironwood_v3())
            .ok_or(Error::Invalid)?;
        r.take(8 + 32)?; // signed pool balance and anchor
        let proof = r.compact()?;
        if proof != orchard::Proof::expected_proof_size(actions) {
            return Err(Error::Invalid);
        }
        r.take(proof)?;
        r.take(
            actions
                .checked_mul(SPEND_AUTH_SIG_SIZE)
                .ok_or(Error::Invalid)?,
        )?;
        r.take(64)?; // binding signature
    }
    Ok(bounded.len() - r.bytes.len())
}
