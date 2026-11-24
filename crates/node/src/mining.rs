//! Explicit offline work exchange. No nonce search, sockets or initialization.
use crate::{Clock, Node};
use monario_address::{Address, Network, Receiver};
use monario_chain::{Block, Hash, mempool, storage::DurableChain, wire};
use monario_v6::{V6Verifier, coinbase};
use sha2::{Digest, Sha256};
pub mod cpu;
pub mod operator;
pub mod pool;
pub mod refresh;

const MAGIC: &[u8; 8] = b"MONJOB01";
const PREFIX: usize = 72;
#[derive(Debug)]
pub enum Error {
    Address,
    Encoding,
    Stale,
    Node(crate::Error),
    Selection(mempool::Error),
    Consensus(monario_chain::Error),
    Storage,
}
/// Public receiving address, expected namespace and public coinbase data only.
pub struct Request<'a> {
    pub address: &'a str,
    pub network: Network,
    pub timestamp: u64,
    pub extra_data: &'a [u8],
}
/// Immutable candidate plus chain-derived hashing context. Never an acceptance receipt.
#[derive(Clone)]
pub struct Work {
    profile: Hash,
    chain_id: Hash,
    seed: Hash,
    header: monario_chain::header::Header,
    packet: Vec<u8>,
}
pub struct Prepared {
    pub work: Work,
    pub selection: mempool::Selection,
}
/// A repeated submission after a lost acknowledgment is distinguishable from new work.
pub enum Submitted {
    Accepted(monario_chain::Accepted),
    AlreadyKnown(Hash),
}
impl Work {
    fn new(source: &DurableChain<V6Verifier>, block: Block, seed: Hash) -> Result<Self, Error> {
        let c = source.chain().map_err(|_| Error::Storage)?;
        let profile = c.validation_profile();
        let mut packet = MAGIC.to_vec();
        packet.extend(profile);
        packet.extend(seed);
        packet.extend(wire::encode(&block, c.limits(), &V6Verifier).map_err(Error::Consensus)?);
        Ok(Self {
            profile,
            chain_id: c.chain_id(),
            seed,
            header: block.header,
            packet,
        })
    }
    /// Canonical portable packet; contains public candidate transactions, not wallet keys.
    pub fn encode(&self) -> &[u8] {
        &self.packet
    }
    /// Identifier binds the profile, seed and complete zero-nonce canonical candidate.
    pub fn id(&self) -> Hash {
        let mut h = Sha256::new();
        h.update(b"Monario/mining-job/v1\0");
        h.update(&self.packet);
        h.finalize().into()
    }
    pub fn seed(&self) -> Hash {
        self.seed
    }
    pub fn target_le(&self) -> [u8; 32] {
        monario_pow::Target::from_compact(self.header.bits)
            .expect("validated target")
            .to_le_bytes()
    }
    /// RandomX v2 input. An external miner may change only its final 32 nonce bytes.
    pub fn pow_preimage(&self) -> Vec<u8> {
        self.header.pow_preimage(&self.chain_id)
    }
    pub fn parent(&self) -> Hash {
        self.header.parent
    }
    /// Identifier of the exact block this work and nonce would produce. Used to
    /// journal a block candidate before the node import call. Decoding reuses the
    /// canonical codec and the current profile limits, so an invalid packet is
    /// rejected before a pending credit record is written.
    pub fn block_id(
        &self,
        source: &DurableChain<V6Verifier>,
        nonce: [u8; 32],
    ) -> Result<Hash, Error> {
        let c = source.chain().map_err(|_| Error::Storage)?;
        let mut block = wire::decode(&self.packet[PREFIX..], c.limits(), &V6Verifier)
            .map_err(Error::Consensus)?;
        block.header.nonce = nonce;
        Ok(block.header.id(&c.chain_id()))
    }
    /// Revalidate an untrusted packet against its retained parent without hashing PoW.
    /// The packet has no authority to select a profile, seed, difficulty or root.
    pub fn decode(source: &DurableChain<V6Verifier>, raw: &[u8], now: u64) -> Result<Self, Error> {
        let c = source.chain().map_err(|_| Error::Storage)?;
        if raw.len() < PREFIX
            || raw.len() > PREFIX + c.limits().block_bytes.min(5_000_000)
            || &raw[..8] != MAGIC
        {
            return Err(Error::Encoding);
        }
        if raw[8..40] != c.validation_profile() {
            return Err(Error::Stale);
        }
        let block =
            wire::decode(&raw[PREFIX..], c.limits(), &V6Verifier).map_err(Error::Consensus)?;
        if c.block_info(&block.header.parent).is_none() {
            return Err(Error::Stale);
        }
        if block.header.nonce != [0; 32] {
            return Err(Error::Encoding);
        }
        let rebuilt = c
            .build_template(
                block.header.parent,
                block.header.timestamp,
                now,
                block.transactions[1..].to_vec(),
                |_| Ok(block.transactions[0].clone()),
            )
            .map_err(Error::Consensus)?;
        if rebuilt.block.header != block.header || raw[40..72] != rebuilt.pow_seed {
            return Err(Error::Encoding);
        }
        let work = Self::new(source, rebuilt.block, rebuilt.pow_seed)?;
        if work.encode() != raw {
            return Err(Error::Encoding);
        }
        Ok(work)
    }
}
impl Node {
    /// Read-only work construction aside from runtime clock bookkeeping; opens no transport.
    pub fn prepare_work(&mut self, request: Request<'_>, clock: Clock) -> Result<Prepared, Error> {
        self.clock(clock).map_err(Error::Node)?;
        let receiver = match Address::decode(request.address, request.network)
            .map_err(|_| Error::Address)?
            .receiver()
        {
            Receiver::Transparent(receiver) => receiver,
            Receiver::Private(_) => return Err(Error::Address),
        };
        let c = self.store.chain().map_err(|_| Error::Storage)?;
        let encode = |p: &monario_chain::assembly::CoinbasePlan| {
            coinbase::encode(p, receiver, request.extra_data)
                .map_err(|_| monario_chain::Error::Coinbase)
        };
        // Amount fields are fixed-width. Reserve one additional P2PKH output (34
        // bytes) for the canonical miner coinbase output.
        let empty = c
            .build_template(
                c.tip(),
                request.timestamp,
                clock.unix_seconds,
                Vec::new(),
                encode,
            )
            .map_err(Error::Consensus)?;
        let reserve = empty.block.transactions[0]
            .len()
            .checked_add(if self.pool.is_empty() { 0 } else { 34 })
            .ok_or(Error::Encoding)?;
        let selection = self.pool.select(c, reserve).map_err(Error::Selection)?;
        let template = c
            .build_template(
                c.tip(),
                request.timestamp,
                clock.unix_seconds,
                selection.transactions.clone(),
                encode,
            )
            .map_err(Error::Consensus)?;
        if template.coinbase.fees != selection.fees {
            return Err(Error::Encoding);
        }
        let work = Work::new(&self.store, template.block, template.pow_seed)?;
        Ok(Prepared { work, selection })
    }
    /// Only the nonce can change. Full canonical/contextual/RandomX validation and
    /// the existing atomic durable commit run before mempool reconciliation/relay.
    pub fn submit_work(
        &mut self,
        work: &Work,
        nonce: [u8; 32],
        clock: Clock,
    ) -> Result<Submitted, Error> {
        self.clock(clock).map_err(Error::Node)?;
        let c = self.store.chain().map_err(|_| Error::Storage)?;
        if work.profile != c.validation_profile() {
            return Err(Error::Stale);
        }
        let mut block = wire::decode(&work.packet[PREFIX..], c.limits(), &V6Verifier)
            .map_err(Error::Consensus)?;
        block.header.nonce = nonce;
        let id = block.header.id(&c.chain_id());
        let bytes = wire::encode(&block, c.limits(), &V6Verifier).map_err(Error::Consensus)?;
        if c.block_info(&id).is_some() {
            if self
                .store
                .authenticated_block_bytes(id)
                .map_err(|_| Error::Storage)?
                != bytes
            {
                return Err(Error::Encoding);
            }
            return Ok(Submitted::AlreadyKnown(id));
        }
        if block.header.parent != c.tip() {
            return Err(Error::Stale);
        }
        self.import_block(&bytes, clock)
            .map(Submitted::Accepted)
            .map_err(Error::Node)
    }
}

#[cfg(test)]
mod tests;
