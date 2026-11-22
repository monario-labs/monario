//! Required transaction-verifier boundary. No permissive production implementation.
use crate::ledger::OutPoint;
use crate::{Hash, LedgerView};
use monario_monetary::Amount;

#[derive(Clone, Debug)]
pub struct Output {
    pub value: Amount,
    pub script: Vec<u8>,
}

/// Result of authenticating and decoding the exact supplied transaction bytes.
/// This is a trusted code boundary, never a network-deserializable receipt.
pub struct VerifiedTransaction {
    pub id: Hash,
    pub authorization_digest: Hash,
    pub coinbase_height: Option<u64>,
    pub inputs: Vec<OutPoint>,
    pub outputs: Vec<Output>,
    /// Reports unsupported legacy shielded bundles. Ironwood uses the separately
    /// authenticated `ironwood` effects, never this rejection flag.
    pub has_shielded_bundle: bool,
    pub ironwood: Option<VerifiedIronwood>,
}

/// Effects authenticated by the corrected Ironwood proof and binding signature.
#[derive(Clone)]
pub struct VerifiedIronwood {
    pub value_balance: i64,
    pub anchor: Hash,
    pub nullifiers: Vec<Hash>,
    pub commitments: Vec<Hash>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionError {
    BackendUnavailable,
    Invalid,
    /// Canonical bytes reference an unavailable transparent coin. This is NOT
    /// signature/proof verification or permission to apply transaction effects.
    MissingInput,
}

pub struct TransactionContext<'a> {
    pub height: u64,
    pub median_time_past: u64,
    pub state: &'a dyn LedgerView,
}

/// Implementations MUST validate canonical v6 encoding, exact consumption,
/// network signing domain, expiry/locktime, scripts/signatures, and every proof
/// before returning effects. IDs and authorization digests must be derived from
/// those same bytes. Do not implement this trait using caller-supplied effects.
/// Calls must be deterministic and must not mutate external consensus state.
pub trait TransactionVerifier {
    /// Frame exactly the first transaction in a bounded byte prefix. This MUST
    /// check structural lengths/canonical count encodings without proof/signature
    /// verification or allocations based on unchecked counts. It grants no validity.
    /// Backends without a framer fail closed for encoded submission.
    fn transaction_length(&self, _bytes: &[u8]) -> Result<usize, TransactionError> {
        Err(TransactionError::BackendUnavailable)
    }
    fn block_commitment_with_state(
        &self,
        parent: Hash,
        height: u64,
        transactions: &[(Hash, Hash)],
        _root: Hash,
    ) -> Result<Hash, TransactionError> {
        self.block_commitment(parent, height, transactions)
    }
    fn verify(
        &self,
        bytes: &[u8],
        context: TransactionContext<'_>,
    ) -> Result<VerifiedTransaction, TransactionError>;
    /// Compute the selected protocol's header commitment, including authorization
    /// data and required parent history. No generic SHA hash substitutes for it.
    fn block_commitment(
        &self,
        parent_commitment: Hash,
        height: u64,
        transactions: &[(Hash, Hash)],
    ) -> Result<Hash, TransactionError>;
}

/// Explicit fail-closed default until the real v6/Ironwood backend is integrated.
pub struct UnavailableV6;
impl TransactionVerifier for UnavailableV6 {
    fn verify(
        &self,
        _: &[u8],
        _: TransactionContext<'_>,
    ) -> Result<VerifiedTransaction, TransactionError> {
        Err(TransactionError::BackendUnavailable)
    }
    fn block_commitment(
        &self,
        _: Hash,
        _: u64,
        _: &[(Hash, Hash)],
    ) -> Result<Hash, TransactionError> {
        Err(TransactionError::BackendUnavailable)
    }
}
