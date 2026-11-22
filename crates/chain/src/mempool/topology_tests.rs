use super::*;

#[test]
fn ancestor_boundary_rejection_is_atomic_and_leaves_independent_capacity() {
    let c = selection_fixture();
    let mut pool = Mempool::new(&c, limits()).unwrap();
    let mut parent = 1;
    for n in 0..64u64 {
        let id = 1000 + n;
        spend(&c, id, &[parent], &[100]);
        pool.admit(&c, id.to_le_bytes().to_vec()).unwrap();
        parent = id;
    }
    spend(&c, 1064, &[parent], &[100]);
    let before = pool
        .transactions(&c)
        .unwrap()
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    assert_eq!(
        pool.admit(&c, 1064u64.to_le_bytes().to_vec()),
        Err(Error::Capacity)
    );
    assert_eq!(
        pool.transactions(&c)
            .unwrap()
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>(),
        before
    );
    assert!(
        pool.known_transaction(&c, &1064u64.to_le_bytes())
            .unwrap()
            .is_none()
    );
    spend(&c, 2000, &[2], &[90]);
    pool.admit(&c, 2000u64.to_le_bytes().to_vec()).unwrap();
    assert_eq!(pool.len(), 65);
}

fn indexed_spend(c: &Chain<FixtureVerifier>, id: u64, parent: u64, index: u32, value: u64) {
    spend(c, id, &[parent], &[value]);
    c.verifier
        .transactions
        .borrow_mut()
        .get_mut(&id)
        .unwrap()
        .inputs[0]
        .index = index;
}

#[test]
fn shared_ancestors_count_once_and_removal_frees_transitive_descendant_slots() {
    let c = selection_fixture();
    let mut pool = Mempool::new(&c, limits()).unwrap();
    spend(&c, 1000, &[1], &[1; 64]);
    let root = pool.admit(&c, 1000u64.to_le_bytes().to_vec()).unwrap();
    indexed_spend(&c, 1001, 1000, 0, 1);
    let left = pool.admit(&c, 1001u64.to_le_bytes().to_vec()).unwrap();
    indexed_spend(&c, 1002, 1000, 1, 1);
    pool.admit(&c, 1002u64.to_le_bytes().to_vec()).unwrap();
    spend(&c, 1003, &[1001, 1002], &[2]);
    pool.admit(&c, 1003u64.to_le_bytes().to_vec()).unwrap();
    assert_eq!(
        pool.entries
            .iter()
            .find(|e| e.id == root)
            .unwrap()
            .descendants,
        4
    );
    for index in 2..62u32 {
        let id = 2000 + u64::from(index);
        indexed_spend(&c, id, 1000, index, 1);
        pool.admit(&c, id.to_le_bytes().to_vec()).unwrap();
    }
    assert_eq!(pool.len(), 64);
    indexed_spend(&c, 3000, 1000, 62, 1);
    assert_eq!(
        pool.admit(&c, 3000u64.to_le_bytes().to_vec()),
        Err(Error::Capacity)
    );
    assert_eq!(
        pool.entries
            .iter()
            .find(|e| e.id == root)
            .unwrap()
            .descendants,
        64
    );
    let result = pool.remove(&c, left).unwrap();
    assert_eq!(result.retained, 62); // Removing left also invalidates the join.
    assert_eq!(
        pool.entries
            .iter()
            .find(|e| e.id == root)
            .unwrap()
            .descendants,
        62
    );
    pool.admit(&c, 3000u64.to_le_bytes().to_vec()).unwrap();
    indexed_spend(&c, 3001, 1000, 63, 1);
    pool.admit(&c, 3001u64.to_le_bytes().to_vec()).unwrap();
    spend(&c, 3002, &[3001], &[1]);
    assert_eq!(
        pool.admit(&c, 3002u64.to_le_bytes().to_vec()),
        Err(Error::Capacity)
    );
}

#[test]
fn merging_individually_bounded_chains_checks_the_full_unique_ancestor_union() {
    for left_count in [31, 32u64] {
        let c = selection_fixture();
        let mut pool = Mempool::new(&c, limits()).unwrap();
        let mut tails = Vec::new();
        for (start, head, count) in [(1000, 1, left_count), (2000, 2, 32)] {
            let mut parent = head;
            for offset in 0..count {
                let id = start + offset;
                spend(&c, id, &[parent], &[100]);
                pool.admit(&c, id.to_le_bytes().to_vec()).unwrap();
                parent = id;
            }
            tails.push(parent);
        }
        spend(&c, 3000, &tails, &[200]);
        let result = pool.admit(&c, 3000u64.to_le_bytes().to_vec());
        assert_eq!(result.is_ok(), left_count == 31);
        if left_count == 32 {
            assert_eq!(result, Err(Error::Capacity));
        }
    }
}

#[test]
fn confirmation_rebuild_releases_ancestor_slots_and_removal_never_leaves_stale_counts() {
    let mut c = selection_fixture();
    let mut pool = Mempool::new(&c, limits()).unwrap();
    let mut parent = 1;
    for id in 1000..1064u64 {
        spend(&c, id, &[parent], &[100]);
        pool.admit(&c, id.to_le_bytes().to_vec()).unwrap();
        parent = id;
    }
    cb(&c, 4000, 4, 0);
    let block = block(&c, c.tip(), 1180, &[4000, 1000]);
    c.submit_checked(block, 2000, &mut FixturePow::default())
        .unwrap();
    assert_eq!(pool.rebuild(&c, Vec::new(), None).unwrap().retained, 63);
    spend(&c, 1064, &[1063], &[100]);
    pool.admit(&c, 1064u64.to_le_bytes().to_vec()).unwrap();
    let first = pool.entries[0].id;
    assert_eq!(pool.remove(&c, first).unwrap().retained, 0);
    assert!(pool.entries.is_empty());
    // The confirmed parent's still-unspent output can start a fresh family.
    spend(&c, 5000, &[1000], &[100]);
    pool.admit(&c, 5000u64.to_le_bytes().to_vec()).unwrap();
    assert_eq!(pool.entries[0].descendants, 1);
}
