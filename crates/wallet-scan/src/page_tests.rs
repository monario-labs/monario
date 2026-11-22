//! Transport-independent page framing tests. No socket, listener or nonce search.
use super::*;
use crate::page::transport::{
    Request, Status, TOKEN_BYTES, handle_page_request, read_response, serve, write_request,
};
use crate::page::{Cursor, MAX_BLOCKS, MAX_PAGE_BYTES, Page, PageBlock, PageSource, Pulled, pull};
use std::io::{Cursor as IoCursor, Read, Write};

struct Pipe {
    input: IoCursor<Vec<u8>>,
    output: Vec<u8>,
}

impl Read for Pipe {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        self.input.read(out)
    }
}

impl Write for Pipe {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.output.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn temp() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

fn chain_with(dir: &std::path::Path, height: u32) -> DurableChain<V6Verifier> {
    let path = dir.join("pages.sqlite");
    let mut source = DurableChain::open(&path, config(), root(), V6Verifier, u64::MAX / 2).unwrap();
    let mut model = Model::new();
    for h in 1..=height {
        model.accept(&mut source, h, &[]);
    }
    source
}

struct MemorySource {
    pages: Vec<Vec<u8>>,
    served: usize,
}

impl PageSource for MemorySource {
    fn page(
        &mut self,
        start_height: u64,
        max_blocks: usize,
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, Error> {
        if self.served == self.pages.len() {
            return Ok(None);
        }
        let encoded = &self.pages[self.served];
        let page = Page::decode(encoded)?;
        if page.start_height != start_height {
            return Err(Error::InvalidBody);
        }
        if page.blocks.len() > max_blocks || encoded.len() > max_bytes {
            return Err(Error::Capacity);
        }
        self.served += 1;
        Ok(Some(encoded.clone()))
    }
}

fn local_chain(dir: &std::path::Path) -> DurableChain<V6Verifier> {
    DurableChain::open(
        &dir.join("local.sqlite"),
        config(),
        root(),
        V6Verifier,
        u64::MAX / 2,
    )
    .unwrap()
}

fn verify(page: &Page) -> Result<Vec<Block>, Error> {
    page.verify(
        &config().chain_id,
        &page.profile,
        &page.root,
        page.start_height,
        root().id,
        &config().limits,
    )
}

#[test]
fn pages_round_trip_and_verify_best_chain_linkage() {
    let dir = temp();
    let source = chain_with(dir.path(), 4);
    let page = Page::from_chain(&source, 1, 4, MAX_PAGE_BYTES).unwrap();
    assert_eq!(page.start_height, 1);
    assert_eq!(page.blocks.len(), 4);
    assert_eq!(page.profile, source.profile_id().unwrap());
    assert_eq!(page.root, root().id);
    for (index, block) in page.blocks.iter().enumerate() {
        assert_eq!(block.height, 1 + index as u64);
        assert!(!block.bytes.is_empty());
    }

    let encoded = page.encode().unwrap();
    assert_eq!(Page::decode(&encoded).unwrap(), page);
    let digest = page.digest().unwrap();
    assert_ne!(digest, [0; 32]);

    let blocks = verify(&page).unwrap();
    assert_eq!(blocks.len(), 4);
    assert_eq!(blocks[0].header.parent, root().id);
    assert_eq!(blocks[3].header.id(&config().chain_id), page.blocks[3].id);
    assert_eq!(page.digest().unwrap(), digest);
}

#[test]
fn pages_shorten_at_the_tip_and_cross_page_linkage_is_checked() {
    let dir = temp();
    let source = chain_with(dir.path(), 6);
    let short = Page::from_chain(&source, 5, 4, MAX_PAGE_BYTES).unwrap();
    assert_eq!(short.blocks.len(), 2);
    assert_eq!(short.blocks[0].height, 5);
    assert_eq!(short.blocks[1].height, 6);

    let first = Page::from_chain(&source, 1, 2, MAX_PAGE_BYTES).unwrap();
    assert_eq!(first.blocks.len(), 2);
    let next = Page::from_chain(&source, 3, 2, MAX_PAGE_BYTES).unwrap();
    let blocks = next
        .verify(
            &config().chain_id,
            &next.profile,
            &next.root,
            3,
            first.blocks[1].id,
            &config().limits,
        )
        .unwrap();
    assert_eq!(blocks[0].header.parent, first.blocks[1].id);

    assert!(matches!(
        Page::from_chain(&source, 1, 1, 128),
        Err(Error::Capacity)
    ));
    assert!(matches!(
        Page::from_chain(&source, 0, 1, MAX_PAGE_BYTES),
        Err(Error::Configuration)
    ));
    assert!(matches!(
        Page::from_chain(&source, 7, 1, MAX_PAGE_BYTES),
        Err(Error::Configuration)
    ));
    assert!(matches!(
        Page::from_chain(&source, 1, MAX_BLOCKS + 1, MAX_PAGE_BYTES),
        Err(Error::Configuration)
    ));
}

#[test]
fn wrong_bindings_and_tampered_blocks_fail_closed() {
    let dir = temp();
    let source = chain_with(dir.path(), 3);
    let page = Page::from_chain(&source, 1, 3, MAX_PAGE_BYTES).unwrap();
    let chain_id = config().chain_id;
    let limits = config().limits;

    assert!(matches!(
        page.verify(&chain_id, &[9; 32], &page.root, 1, root().id, &limits),
        Err(Error::WrongChain)
    ));
    assert!(matches!(
        page.verify(&chain_id, &page.profile, &[9; 32], 1, root().id, &limits),
        Err(Error::WrongChain)
    ));
    assert!(matches!(
        page.verify(&chain_id, &page.profile, &page.root, 2, root().id, &limits),
        Err(Error::WrongChain)
    ));
    assert!(matches!(
        page.verify(&chain_id, &page.profile, &page.root, 1, [9; 32], &limits),
        Err(Error::InvalidBody)
    ));

    let mut wrong_id = page.clone();
    wrong_id.blocks[1].id[0] ^= 1;
    assert!(matches!(verify(&wrong_id), Err(Error::InvalidBody)));

    let mut wrong_bytes = page.clone();
    wrong_bytes.blocks[1].bytes[0] ^= 1;
    assert!(matches!(verify(&wrong_bytes), Err(Error::InvalidBody)));

    let mut wrong_height = page.clone();
    wrong_height.blocks[1].height += 1;
    assert!(matches!(verify(&wrong_height), Err(Error::InvalidBody)));

    let mut empty = page.clone();
    empty.blocks.clear();
    assert!(empty.encode().is_err());

    let mut oversized = page.clone();
    oversized.blocks[0].bytes = vec![0; monario_chain::archive::MAX_BLOCK_BYTES + 1];
    assert!(oversized.encode().is_err());

    let mut too_many = page.clone();
    let base = too_many.blocks[0].clone();
    too_many.blocks = (0..=MAX_BLOCKS)
        .map(|index| PageBlock {
            id: base.id,
            height: 1 + index as u64,
            bytes: base.bytes.clone(),
        })
        .collect();
    assert!(too_many.encode().is_err());

    assert_ne!(page.digest().unwrap(), wrong_id.digest().unwrap());
}

#[test]
fn cursor_accepts_only_contiguous_verified_pages() {
    let dir = temp();
    let source = chain_with(dir.path(), 6);
    let first = Page::from_chain(&source, 1, 2, MAX_PAGE_BYTES).unwrap();
    let second = Page::from_chain(&source, 3, 2, MAX_PAGE_BYTES).unwrap();
    let mut cursor = Cursor::new(
        config().chain_id,
        first.profile,
        first.root,
        1,
        root().id,
        config().limits.clone(),
    )
    .unwrap();

    assert_eq!(cursor.next_height(), 1);
    assert_eq!(cursor.parent(), root().id);
    let blocks = cursor.accept(&first.encode().unwrap()).unwrap();
    assert_eq!(blocks.len(), 2);
    assert_eq!(cursor.next_height(), 3);
    assert_eq!(cursor.parent(), first.blocks[1].id);
    assert_eq!(cursor.accepted_blocks(), 2);

    let blocks = cursor.accept(&second.encode().unwrap()).unwrap();
    assert_eq!(blocks[0].header.parent, first.blocks[1].id);
    assert_eq!(cursor.next_height(), 5);
    assert_eq!(cursor.accepted_blocks(), 4);

    // A replay, a gap and a wrong binding must not advance the cursor.
    assert!(cursor.accept(&first.encode().unwrap()).is_err());
    assert_eq!(cursor.next_height(), 5);
    let gap = Page::from_chain(&source, 6, 1, MAX_PAGE_BYTES).unwrap();
    assert!(cursor.accept(&gap.encode().unwrap()).is_err());
    assert_eq!(cursor.next_height(), 5);

    let mut wrong = Page::from_chain(&source, 5, 1, MAX_PAGE_BYTES).unwrap();
    wrong.root[0] ^= 1;
    assert!(cursor.accept(&wrong.encode().unwrap()).is_err());
    assert_eq!(cursor.next_height(), 5);
    assert_eq!(cursor.accepted_blocks(), 4);

    let mut tampered = Page::from_chain(&source, 5, 1, MAX_PAGE_BYTES).unwrap();
    tampered.blocks[0].id[0] ^= 1;
    assert!(cursor.accept(&tampered.encode().unwrap()).is_err());
    assert_eq!(cursor.next_height(), 5);

    let tail = Page::from_chain(&source, 5, 2, MAX_PAGE_BYTES).unwrap();
    assert_eq!(cursor.accept(&tail.encode().unwrap()).unwrap().len(), 2);
    assert_eq!(cursor.next_height(), 7);
    assert_eq!(cursor.accepted_blocks(), 6);

    assert!(Cursor::new([0; 32], [1; 32], [2; 32], 1, [3; 32], config().limits).is_err());
    assert!(
        Cursor::new(
            config().chain_id,
            [1; 32],
            [2; 32],
            0,
            [3; 32],
            config().limits
        )
        .is_err()
    );
}

#[test]
fn pull_validates_and_commits_pages_then_scans_locally() {
    let remote_dir = temp();
    let remote = chain_with(remote_dir.path(), 3);
    let pages: Vec<Vec<u8>> = (1..=3)
        .map(|height| {
            Page::from_chain(&remote, height, 1, MAX_PAGE_BYTES)
                .unwrap()
                .encode()
                .unwrap()
        })
        .collect();
    let profile = remote.profile_id().unwrap();
    let mut cursor = Cursor::new(
        config().chain_id,
        profile,
        root().id,
        1,
        root().id,
        config().limits.clone(),
    )
    .unwrap();

    let local_dir = temp();
    let mut local = local_chain(local_dir.path());
    let mut source = MemorySource { pages, served: 0 };
    let pulled = pull(&mut source, &mut cursor, &mut local, 5, u64::MAX / 2).unwrap();
    assert_eq!(
        pulled,
        Pulled {
            blocks: 3,
            reached_tip: true
        }
    );
    assert_eq!(local.chain().unwrap().height(), 3);
    assert_eq!(cursor.next_height(), 4);
    assert_eq!(cursor.parent(), local.chain().unwrap().tip());

    let mut wallet = scanner(&local, 7);
    let progress = wallet.sync(&local, 3).unwrap();
    assert!(progress.complete);
    assert_balance(&wallet, &local, 100, 0, 0);
}

#[test]
fn pull_rejects_tampered_multi_block_and_misaligned_pages() {
    let remote_dir = temp();
    let remote = chain_with(remote_dir.path(), 2);
    let first = Page::from_chain(&remote, 1, 1, MAX_PAGE_BYTES).unwrap();
    let profile = remote.profile_id().unwrap();
    let limits = config().limits.clone();

    let local_dir = temp();
    let mut local = local_chain(local_dir.path());
    let mut cursor = Cursor::new(
        config().chain_id,
        profile,
        root().id,
        1,
        root().id,
        limits.clone(),
    )
    .unwrap();

    let mut tampered = first.clone();
    tampered.blocks[0].id[0] ^= 1;
    let mut source = MemorySource {
        pages: vec![tampered.encode().unwrap()],
        served: 0,
    };
    assert!(matches!(
        pull(&mut source, &mut cursor, &mut local, 1, u64::MAX / 2),
        Err(Error::InvalidBody)
    ));
    assert_eq!(local.chain().unwrap().height(), 0);
    assert_eq!(cursor.next_height(), 1);
    assert_eq!(cursor.accepted_blocks(), 0);

    let multi = Page::from_chain(&remote, 1, 2, MAX_PAGE_BYTES).unwrap();
    let mut source = MemorySource {
        pages: vec![multi.encode().unwrap()],
        served: 0,
    };
    assert!(matches!(
        pull(&mut source, &mut cursor, &mut local, 1, u64::MAX / 2),
        Err(Error::Capacity)
    ));
    assert_eq!(local.chain().unwrap().height(), 0);

    // A source that returns a page starting elsewhere is rejected.
    let mut source = MemorySource {
        pages: vec![
            Page::from_chain(&remote, 2, 1, MAX_PAGE_BYTES)
                .unwrap()
                .encode()
                .unwrap(),
        ],
        served: 0,
    };
    assert!(matches!(
        pull(&mut source, &mut cursor, &mut local, 1, u64::MAX / 2),
        Err(Error::InvalidBody)
    ));
}

#[test]
fn pull_requires_the_local_chain_to_be_at_the_cursor() {
    let remote_dir = temp();
    let remote = chain_with(remote_dir.path(), 1);
    let page = Page::from_chain(&remote, 1, 1, MAX_PAGE_BYTES).unwrap();
    let profile = remote.profile_id().unwrap();

    let local_dir = temp();
    let mut local = local_chain(local_dir.path());
    let mut model = Model::new();
    model.accept(&mut local, 1, &[]);
    assert_eq!(local.chain().unwrap().height(), 1);

    let mut cursor = Cursor::new(
        config().chain_id,
        profile,
        root().id,
        1,
        root().id,
        config().limits.clone(),
    )
    .unwrap();
    let mut source = MemorySource {
        pages: vec![page.encode().unwrap()],
        served: 0,
    };
    assert!(matches!(
        pull(&mut source, &mut cursor, &mut local, 1, u64::MAX / 2),
        Err(Error::NotSynced)
    ));
    assert_eq!(source.served, 0);
    assert_eq!(cursor.next_height(), 1);
}

#[test]
fn blocking_serve_returns_a_bounded_page_for_a_valid_token() {
    let remote_dir = temp();
    let remote = chain_with(remote_dir.path(), 2);
    let token = [9u8; TOKEN_BYTES];
    let mut input = Vec::new();
    write_request(&mut input, &token, Request::new(1, 1).unwrap()).unwrap();
    let mut pipe = Pipe {
        input: IoCursor::new(input),
        output: Vec::new(),
    };
    assert_eq!(
        serve(&mut pipe, &remote, &token, MAX_PAGE_BYTES, 1).unwrap(),
        1
    );
    let response = read_response(&mut IoCursor::new(pipe.output), MAX_PAGE_BYTES).unwrap();
    assert_eq!(response.status, Status::Ok);
    let page = Page::decode(&response.page).unwrap();
    assert_eq!(page.start_height, 1);
    assert_eq!(page.blocks.len(), 1);
    assert_eq!(page.blocks[0].height, 1);
}

#[test]
fn page_requests_report_tip_generic_failure_and_bad_tokens() {
    let remote_dir = temp();
    let remote = chain_with(remote_dir.path(), 2);

    let tip = handle_page_request(&remote, Request::new(3, 1).unwrap(), MAX_PAGE_BYTES);
    assert_eq!(tip.status, Status::AtTip);
    assert!(tip.page.is_empty());

    let unavailable = handle_page_request(&remote, Request::new(1, 1).unwrap(), 128);
    assert_eq!(unavailable.status, Status::Unavailable);
    assert!(unavailable.page.is_empty());

    let token = [9u8; TOKEN_BYTES];
    let mut input = Vec::new();
    write_request(&mut input, &token, Request::new(1, 1).unwrap()).unwrap();
    let mut pipe = Pipe {
        input: IoCursor::new(input),
        output: Vec::new(),
    };
    assert!(matches!(
        serve(&mut pipe, &remote, &[8u8; TOKEN_BYTES], MAX_PAGE_BYTES, 1),
        Err(Error::Transport)
    ));
    assert!(pipe.output.is_empty());
}

#[test]
fn malformed_page_encodings_are_rejected_without_panicking() {
    let dir = temp();
    let source = chain_with(dir.path(), 2);
    let encoded = Page::from_chain(&source, 1, 2, MAX_PAGE_BYTES)
        .unwrap()
        .encode()
        .unwrap();

    assert!(Page::decode(&[]).is_err());
    assert!(Page::decode(&encoded[..encoded.len() - 1]).is_err());
    assert!(Page::decode(&vec![0; MAX_PAGE_BYTES + 1]).is_err());

    let mut bad_magic = encoded.clone();
    bad_magic[0] ^= 1;
    assert!(Page::decode(&bad_magic).is_err());

    let mut bad_version = encoded.clone();
    bad_version[8] = 2;
    assert!(Page::decode(&bad_version).is_err());

    let mut zero_profile = encoded.clone();
    zero_profile[9..41].fill(0);
    assert!(Page::decode(&zero_profile).is_err());

    let mut zero_count = encoded.clone();
    zero_count[81..83].copy_from_slice(&0_u16.to_le_bytes());
    assert!(Page::decode(&zero_count).is_err());

    let mut huge_count = encoded.clone();
    huge_count[81..83].copy_from_slice(&((MAX_BLOCKS + 1) as u16).to_le_bytes());
    assert!(Page::decode(&huge_count).is_err());

    let mut trailing = encoded;
    trailing.push(0);
    assert!(Page::decode(&trailing).is_err());
}
