//! Bounded, transport-independent compact block pages.
//!
//! A page carries canonical block bytes from one contiguous best-chain range and
//! is bound to the source's validated profile and root. It is a **transport and
//! framing primitive**, not a light-client trust model: [`Page::verify`] checks
//! canonical encoding, block identity and parent linkage only. It does not verify
//! proof of work, ASERT, signatures, proofs or state transitions, and it proves no
//! finality. A caller must submit the returned blocks to a validating chain before
//! using them for consensus state or wallet scanning.
//!
//! No socket, listener, node, chain database or wallet is created here.

use crate::{Error, Hash};
use monario_chain::{Block, Limits, archive::MAX_BLOCK_BYTES, storage::DurableChain, wire};
use monario_v6::V6Verifier;
use sha2::{Digest, Sha256};

/// Page framing magic, distinct from block, job and wire envelopes.
pub const MAGIC: [u8; 8] = *b"MONPAGE1";
/// Page format version.
pub const VERSION: u8 = 1;
/// Maximum blocks in one page.
pub const MAX_BLOCKS: usize = 16;
/// Maximum encoded page size, including page and per-block headers.
pub const MAX_PAGE_BYTES: usize = 8 * 1024 * 1024;

#[path = "page_transport.rs"]
pub mod transport;

const HEADER_BYTES: usize = MAGIC.len() + 1 + 32 + 32 + 8 + 2;
const BLOCK_HEADER_BYTES: usize = 8 + 32 + 4;
const DIGEST_DOMAIN: &[u8] = b"Monario/scan-page/v1\0";

/// One block in a page: the indexed identity, its height and exact canonical
/// payload bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageBlock {
    pub id: Hash,
    pub height: u64,
    pub bytes: Vec<u8>,
}

/// A contiguous best-chain range. Fields are public so a caller can inspect the
/// binding before verification, but [`Page::encode`] and [`Page::verify`] enforce
/// the shape and fail closed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Page {
    pub profile: Hash,
    pub root: Hash,
    pub start_height: u64,
    pub blocks: Vec<PageBlock>,
}

impl Page {
    /// Assemble a page from a validated durable chain. At most `max_blocks` and
    /// `max_bytes` are returned; the page is shortened rather than oversized. A
    /// single block that cannot fit returns [`Error::Capacity`]. Pruned or
    /// non-retained history fails closed.
    pub fn from_chain(
        source: &DurableChain<V6Verifier>,
        start_height: u64,
        max_blocks: usize,
        max_bytes: usize,
    ) -> Result<Self, Error> {
        if start_height == 0
            || max_blocks == 0
            || max_blocks > MAX_BLOCKS
            || !(HEADER_BYTES + BLOCK_HEADER_BYTES + 1..=MAX_PAGE_BYTES).contains(&max_bytes)
        {
            return Err(Error::Configuration);
        }
        let chain = source.chain()?;
        let tip = chain.tip();
        let tip_height = chain.height();
        if start_height > tip_height {
            return Err(Error::Configuration);
        }
        let available = tip_height - start_height + 1;
        let count =
            usize::try_from(available.min(max_blocks as u64)).map_err(|_| Error::Capacity)?;
        let end_height = start_height
            .checked_add(count as u64 - 1)
            .ok_or(Error::Capacity)?;
        let end_id = chain.ancestor(tip, end_height).map_err(|e| match e {
            monario_chain::Error::HistoryUnavailable => Error::SourceHistory,
            _ => Error::WrongChain,
        })?;

        // The chain exposes parent links, not child links. Walk back once from the
        // range end, then reverse; the skip list keeps the ancestor lookup bounded.
        let mut ids = Vec::with_capacity(count);
        let mut current = end_id;
        loop {
            ids.push(current);
            if ids.len() == count {
                break;
            }
            let info = source.block_info(&current)?.ok_or(Error::InvalidBody)?;
            current = info.parent.ok_or(Error::InvalidBody)?;
        }
        ids.reverse();

        let profile = source.profile_id()?;
        let root = chain.root_id();
        let mut total = HEADER_BYTES;
        let mut blocks = Vec::with_capacity(count);
        for (index, id) in ids.into_iter().enumerate() {
            let height = start_height
                .checked_add(index as u64)
                .ok_or(Error::Capacity)?;
            let info = source.block_info(&id)?.ok_or(Error::InvalidBody)?;
            if info.height != height {
                return Err(Error::InvalidBody);
            }
            let bytes = source.authenticated_block_bytes(id)?;
            if bytes.is_empty() || bytes.len() > MAX_BLOCK_BYTES {
                return Err(Error::InvalidBody);
            }
            let next = total
                .checked_add(BLOCK_HEADER_BYTES)
                .and_then(|n| n.checked_add(bytes.len()))
                .ok_or(Error::Capacity)?;
            if next > max_bytes {
                if blocks.is_empty() {
                    return Err(Error::Capacity);
                }
                break;
            }
            total = next;
            blocks.push(PageBlock { id, height, bytes });
        }
        let page = Self {
            profile,
            root,
            start_height,
            blocks,
        };
        page.check_shape()?;
        Ok(page)
    }

    /// Encode exactly one bounded page. No trailing bytes are produced.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let total = self.check_shape()?;
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&self.profile);
        out.extend_from_slice(&self.root);
        out.extend_from_slice(&self.start_height.to_le_bytes());
        out.extend_from_slice(
            &u16::try_from(self.blocks.len())
                .map_err(|_| Error::Capacity)?
                .to_le_bytes(),
        );
        for block in &self.blocks {
            out.extend_from_slice(&block.height.to_le_bytes());
            out.extend_from_slice(&block.id);
            out.extend_from_slice(
                &u32::try_from(block.bytes.len())
                    .map_err(|_| Error::Capacity)?
                    .to_le_bytes(),
            );
            out.extend_from_slice(&block.bytes);
        }
        debug_assert_eq!(out.len(), total);
        Ok(out)
    }

    /// Decode one bounded page. Magic, version, count, lengths, contiguous
    /// heights and trailing data are all checked before returning.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_PAGE_BYTES || bytes.len() < HEADER_BYTES {
            return Err(Error::InvalidBody);
        }
        let mut reader = Reader::new(bytes);
        if reader.take(MAGIC.len())? != MAGIC {
            return Err(Error::InvalidBody);
        }
        if reader.u8()? != VERSION {
            return Err(Error::InvalidBody);
        }
        let profile = reader.hash()?;
        let root = reader.hash()?;
        let start_height = reader.u64()?;
        let count = usize::from(reader.u16()?);
        if count == 0 || count > MAX_BLOCKS {
            return Err(Error::InvalidBody);
        }
        let mut blocks = Vec::with_capacity(count);
        for _ in 0..count {
            let height = reader.u64()?;
            let id = reader.hash()?;
            let len = usize::try_from(reader.u32()?).map_err(|_| Error::InvalidBody)?;
            if len == 0 || len > MAX_BLOCK_BYTES {
                return Err(Error::InvalidBody);
            }
            let bytes = reader.take(len)?.to_vec();
            blocks.push(PageBlock { id, height, bytes });
        }
        if !reader.done() {
            return Err(Error::InvalidBody);
        }
        let page = Self {
            profile,
            root,
            start_height,
            blocks,
        };
        page.check_shape()?;
        Ok(page)
    }

    /// Domain-separated digest of the exact encoded page. This is an integrity
    /// identifier for a trusted channel or checkpoint, not an authorization.
    pub fn digest(&self) -> Result<Hash, Error> {
        let encoded = self.encode()?;
        let mut h = Sha256::new();
        h.update(DIGEST_DOMAIN);
        h.update(&encoded);
        Ok(h.finalize().into())
    }

    /// Verify canonical encoding, block identity and parent linkage.
    ///
    /// `expected_parent` is the trusted block before `expected_start` (the root id
    /// for the first page). The returned blocks are structurally decoded only;
    /// submit them to a validating chain before relying on their consensus state.
    pub fn verify(
        &self,
        chain_id: &Hash,
        expected_profile: &Hash,
        expected_root: &Hash,
        expected_start: u64,
        expected_parent: Hash,
        limits: &Limits,
    ) -> Result<Vec<Block>, Error> {
        self.check_shape()?;
        if self.profile != *expected_profile
            || self.root != *expected_root
            || self.start_height != expected_start
        {
            return Err(Error::WrongChain);
        }
        let mut parent = expected_parent;
        let mut out = Vec::with_capacity(self.blocks.len());
        for (index, entry) in self.blocks.iter().enumerate() {
            let height = expected_start
                .checked_add(index as u64)
                .ok_or(Error::InvalidBody)?;
            if entry.height != height {
                return Err(Error::InvalidBody);
            }
            let block =
                wire::decode(&entry.bytes, limits, &V6Verifier).map_err(|_| Error::InvalidBody)?;
            if block.header.id(chain_id) != entry.id || block.header.parent != parent {
                return Err(Error::InvalidBody);
            }
            parent = entry.id;
            out.push(block);
        }
        Ok(out)
    }

    /// Exact encoded size after structural validation.
    fn check_shape(&self) -> Result<usize, Error> {
        if self.profile == [0; 32]
            || self.root == [0; 32]
            || self.start_height == 0
            || self.blocks.is_empty()
            || self.blocks.len() > MAX_BLOCKS
        {
            return Err(Error::Configuration);
        }
        let mut total = HEADER_BYTES;
        for (index, block) in self.blocks.iter().enumerate() {
            if block.id == [0; 32] || block.bytes.is_empty() || block.bytes.len() > MAX_BLOCK_BYTES
            {
                return Err(Error::InvalidBody);
            }
            let expected = self
                .start_height
                .checked_add(index as u64)
                .ok_or(Error::InvalidBody)?;
            if block.height != expected {
                return Err(Error::InvalidBody);
            }
            total = total
                .checked_add(BLOCK_HEADER_BYTES)
                .and_then(|n| n.checked_add(block.bytes.len()))
                .ok_or(Error::Capacity)?;
            if total > MAX_PAGE_BYTES {
                return Err(Error::Capacity);
            }
        }
        Ok(total)
    }
}

/// A transport-agnostic client cursor over contiguous pages.
///
/// The first page must start at the trusted cursor height and descend from the
/// trusted parent (the root id for a fresh scan). Every later page must start at
/// exactly the next height and extend the previous page. A page is accepted only
/// after full [`Page::verify`]; errors leave the cursor unchanged, so replays,
/// gaps, reordered pages and tampered pages cannot advance it.
///
/// Accepting pages does not validate consensus. The caller must submit the
/// returned blocks to a validating chain or scan them under an explicit trust
/// model before using their state.
pub struct Cursor {
    chain_id: Hash,
    profile: Hash,
    root: Hash,
    limits: Limits,
    next_height: u64,
    parent: Hash,
    accepted: u64,
}

impl Cursor {
    pub fn new(
        chain_id: Hash,
        profile: Hash,
        root: Hash,
        start_height: u64,
        parent: Hash,
        limits: Limits,
    ) -> Result<Self, Error> {
        if chain_id == [0; 32]
            || profile == [0; 32]
            || root == [0; 32]
            || start_height == 0
            || parent == [0; 32]
        {
            return Err(Error::Configuration);
        }
        Ok(Self {
            chain_id,
            profile,
            root,
            limits,
            next_height: start_height,
            parent,
            accepted: 0,
        })
    }

    /// Verify and accept one encoded page, returning its decoded blocks.
    pub fn accept(&mut self, encoded: &[u8]) -> Result<Vec<Block>, Error> {
        let page = Page::decode(encoded)?;
        let blocks = self.verify_page(&page)?;
        self.advance(&page)?;
        Ok(blocks)
    }

    fn verify_page(&self, page: &Page) -> Result<Vec<Block>, Error> {
        if page.start_height != self.next_height {
            return Err(Error::InvalidBody);
        }
        page.verify(
            &self.chain_id,
            &self.profile,
            &self.root,
            self.next_height,
            self.parent,
            &self.limits,
        )
    }

    fn advance(&mut self, page: &Page) -> Result<(), Error> {
        let count = u64::try_from(page.blocks.len()).map_err(|_| Error::Capacity)?;
        let next = self.next_height.checked_add(count).ok_or(Error::Capacity)?;
        let accepted = self.accepted.checked_add(count).ok_or(Error::Capacity)?;
        let parent = page.blocks.last().ok_or(Error::InvalidBody)?.id;
        self.next_height = next;
        self.parent = parent;
        self.accepted = accepted;
        Ok(())
    }

    /// Height expected by the next page.
    pub fn next_height(&self) -> u64 {
        self.next_height
    }

    /// Last accepted block id, or the initial trusted parent.
    pub fn parent(&self) -> Hash {
        self.parent
    }

    /// Number of blocks accepted so far.
    pub fn accepted_blocks(&self) -> u64 {
        self.accepted
    }
}

/// Maximum blocks one [`pull`] call may commit.
pub const MAX_PULL_BLOCKS: usize = 10_000;

/// Supplies encoded pages. This crate implements no socket, RPC or file source;
/// a caller may use memory, a protected stream or a trusted local import.
pub trait PageSource {
    /// Return the encoded page starting at `start_height`, or `None` when the
    /// source has reached its tip. Implementations must honor the block/byte
    /// bounds and must not return a page that starts elsewhere.
    fn page(
        &mut self,
        start_height: u64,
        max_blocks: usize,
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, Error>;
}

/// Result of a bounded pull.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pulled {
    pub blocks: usize,
    pub reached_tip: bool,
}

/// Pull, fully validate and durably commit up to `blocks` single-block pages.
///
/// Each page is verified against the cursor **before** submission. The local
/// chain must be exactly at the cursor parent; submission uses the ordinary
/// `DurableChain::submit_encoded` path, so header PoW, ASERT, signatures, proofs,
/// state transitions and durable commit all run locally. The cursor advances only
/// after the block is committed. A failed page leaves both the cursor and the
/// local chain at their previous state; a source can therefore withhold or
/// censor, but cannot forge a block.
///
/// Pages are requested one block at a time deliberately: a multi-block page
/// cannot be committed atomically by the current single-block durable API, and a
/// partial commit must never advance the scan cursor. Larger pages remain valid
/// for other consumers of [`Page`].
pub fn pull(
    source: &mut impl PageSource,
    cursor: &mut Cursor,
    chain: &mut DurableChain<V6Verifier>,
    blocks: usize,
    now: u64,
) -> Result<Pulled, Error> {
    if blocks == 0 || blocks > MAX_PULL_BLOCKS {
        return Err(Error::Configuration);
    }
    let mut committed = 0usize;
    while committed < blocks {
        if chain.chain()?.tip() != cursor.parent() {
            return Err(Error::NotSynced);
        }
        let Some(encoded) = source.page(cursor.next_height(), 1, MAX_PAGE_BYTES)? else {
            return Ok(Pulled {
                blocks: committed,
                reached_tip: true,
            });
        };
        let page = Page::decode(&encoded)?;
        if page.blocks.len() != 1 {
            return Err(Error::InvalidBody);
        }
        cursor.verify_page(&page)?;
        let accepted = chain.submit_encoded(&page.blocks[0].bytes, now)?;
        if accepted.id != page.blocks[0].id || !accepted.became_best {
            return Err(Error::InvalidBody);
        }
        cursor.advance(&page)?;
        committed += 1;
    }
    Ok(Pulled {
        blocks: committed,
        reached_tip: false,
    })
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(len).ok_or(Error::InvalidBody)?;
        let out = self.bytes.get(self.at..end).ok_or(Error::InvalidBody)?;
        self.at = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(
            self.take(2)?.try_into().map_err(|_| Error::InvalidBody)?,
        ))
    }

    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().map_err(|_| Error::InvalidBody)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().map_err(|_| Error::InvalidBody)?,
        ))
    }

    fn hash(&mut self) -> Result<Hash, Error> {
        self.take(32)?.try_into().map_err(|_| Error::InvalidBody)
    }

    fn done(&self) -> bool {
        self.at == self.bytes.len()
    }
}
