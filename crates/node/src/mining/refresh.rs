//! Explicit, validated job refresh. No threads, nonce search or network transport.
use super::{Clock, Error, Node, Request, Work};
use monario_address::Network;
use sha2::{Digest, Sha256};

/// Fixed payout settings for the lifetime of this manager.
pub struct Manager {
    address: String,
    network: Network,
    extra_data: Vec<u8>,
    current: Option<Work>,
    pool_fingerprint: Option<[u8; 32]>,
}
impl Manager {
    /// The normal work builder validates the address, namespace and extra data.
    pub fn new(address: String, network: Network, extra_data: Vec<u8>) -> Self {
        Self {
            address,
            network,
            extra_data,
            current: None,
            pool_fingerprint: None,
        }
    }

    /// Refresh on tip, timestamp or exact mempool change. A failed refresh never
    /// returns the previously cached job. Caller supplies trusted time and drives
    /// network polling independently; this function never starts a transport.
    pub fn refresh(
        &mut self,
        node: &mut Node,
        timestamp: u64,
        clock: Clock,
    ) -> Result<&Work, Error> {
        let chain = node.source().chain().map_err(|_| Error::Storage)?;
        let mut digest = Sha256::new();
        digest.update(b"Monario/miner-pool-snapshot/v1\0");
        for (id, bytes) in node
            .mempool()
            .relay_transactions(chain)
            .map_err(Error::Selection)?
        {
            digest.update(id);
            digest.update((bytes.len() as u64).to_le_bytes());
            digest.update(bytes);
        }
        let pool: [u8; 32] = digest.finalize().into();
        let refresh = self.current.as_ref().is_none_or(|work| {
            work.parent() != chain.tip()
                || work.profile != chain.validation_profile()
                || work.header.timestamp != timestamp
                || self.pool_fingerprint != Some(pool)
        });
        if refresh {
            self.current = None;
            self.pool_fingerprint = None;
            let prepared = node.prepare_work(
                Request {
                    address: &self.address,
                    network: self.network,
                    timestamp,
                    extra_data: &self.extra_data,
                },
                clock,
            )?;
            self.current = Some(prepared.work);
            self.pool_fingerprint = Some(pool);
        } else {
            node.clock(clock).map_err(Error::Node)?;
        }
        self.current.as_ref().ok_or(Error::Storage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{REAL, append, clock, node, open, raw, root};
    use monario_address::{Address, Receiver, TransparentReceiver};
    fn manager() -> Manager {
        Manager::new(
            Address::new(
                Network::Regtest,
                Receiver::Transparent(TransparentReceiver::PublicKeyHash([7; 20])),
            )
            .encode(),
            Network::Regtest,
            vec![],
        )
    }
    #[test]
    fn tip_reorg_timestamp_and_same_size_mempool_change_refresh_jobs() {
        let _serial = REAL.lock().unwrap();
        let (_dir, mut n) = node();
        let first = append(&mut n, root().id, vec![], 0);
        let base = append(&mut n, first, vec![], 0);
        let coin =
            monario_v6::transaction_id(&n.source().stored_block(first).unwrap().transactions[0])
                .unwrap();
        let mut jobs = manager();
        let empty = jobs.refresh(&mut n, 1315, clock(0)).unwrap().id();
        assert_eq!(jobs.refresh(&mut n, 1315, clock(0)).unwrap().id(), empty);
        let spend = raw(0, Some((coin, 0)), 90);
        let id = n.submit_transaction(spend, clock(0)).unwrap();
        let one = jobs.refresh(&mut n, 1315, clock(0)).unwrap().id();
        assert_ne!(one, empty);
        n.pool.remove(n.store.chain().unwrap(), id).unwrap();
        n.submit_transaction(raw(0, Some((coin, 0)), 80), clock(0))
            .unwrap();
        assert_eq!(n.mempool().len(), 1);
        let changed = jobs.refresh(&mut n, 1315, clock(0)).unwrap().id();
        assert_ne!(changed, one);
        let timed = jobs.refresh(&mut n, 1136, clock(0)).unwrap().id();
        assert_ne!(timed, changed);
        let old = append(&mut n, base, vec![], 0);
        let old_job = jobs.refresh(&mut n, 1420, clock(0)).unwrap().id();
        let side = append(&mut n, base, vec![raw(0, Some((coin, 0)), 80)], 0);
        assert_ne!(old, side);
        let tip = append(&mut n, side, vec![], 0);
        let refreshed = jobs.refresh(&mut n, 1525, clock(0)).unwrap();
        assert_eq!(refreshed.parent(), tip);
        assert_ne!(refreshed.id(), timed);
        assert_ne!(refreshed.id(), old_job);
        assert!(matches!(
            jobs.refresh(&mut n, 999, clock(0)),
            Err(Error::Consensus(_))
        ));
        assert!(jobs.current.is_none());
    }
    #[test]
    fn refresh_crash_worker() {
        let Some(path) = std::env::var_os("MONAR_REFRESH_CRASH_DB") else {
            return;
        };
        let mut n = open(std::path::Path::new(&path));
        let mut jobs = manager();
        jobs.refresh(&mut n, 1315, clock(0)).unwrap();
        std::process::exit(87);
    }
    #[test]
    fn process_death_discards_cache_and_rebuilds_from_recovered_validated_chain() {
        let _serial = REAL.lock().unwrap();
        let (dir, mut n) = node();
        let first = append(&mut n, root().id, vec![], 0);
        let tip = append(&mut n, first, vec![], 0);
        let expected = manager().refresh(&mut n, 1315, clock(0)).unwrap().id();
        n.shutdown().unwrap();
        drop(n);
        let path = dir.path().join("node.sqlite");
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "mining::refresh::tests::refresh_crash_worker",
                "--nocapture",
            ])
            .env("MONAR_REFRESH_CRASH_DB", &path)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(87));
        let mut n = open(&path);
        assert_eq!(n.source().chain().unwrap().tip(), tip);
        assert_eq!(
            manager().refresh(&mut n, 1315, clock(0)).unwrap().id(),
            expected
        );
        assert_eq!(n.peer_count(), 0);
    }
}
