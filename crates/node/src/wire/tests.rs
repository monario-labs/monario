use super::*;
fn decode(raw: &[u8], chunk: usize) -> Result<Frame, Error> {
    let mut d = Decoder::new();
    let mut result = None;
    for piece in raw.chunks(chunk) {
        let (_, frame) = d.feed(piece, [1; 4], MAX_BLOCK, 2_000_000, MAX_BLOCK + 32, |_| {
            true
        })?;
        if frame.is_some() {
            result = frame;
        }
    }
    result.ok_or(Error::Length)
}
#[test]
fn fragments_lengths_checksums_and_reserved_fields() {
    for payload in [vec![0; 88], vec![7; 88]] {
        let raw = encode([1; 4], HELLO, &payload, MAX_BLOCK, 2_000_000).unwrap();
        for n in [1, 2, 15, 16, 17, 104] {
            assert_eq!(decode(&raw, n).unwrap().payload, payload);
        }
        for end in 0..raw.len() {
            assert!(decode(&raw[..end], 1).is_err());
        }
        for offset in [0, 4, 5, 6, 7, 8, 12, 16, raw.len() - 1] {
            let mut bad = raw.clone();
            bad[offset] ^= 128;
            assert!(decode(&bad, 1).is_err());
        }
    }
    assert_eq!(
        decode(&encode([1; 4], ACK, &[], MAX_BLOCK, 2_000_000).unwrap(), 1)
            .unwrap()
            .kind,
        ACK
    );
}
#[test]
fn oversized_and_unsolicited_payloads_rejected_before_allocation() {
    let mut header = [0u8; HEADER];
    header[..4].copy_from_slice(&[1; 4]);
    header[4] = BLOCK;
    header[6] = VERSION;
    header[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    let mut d = Decoder::new();
    assert!(
        d.feed(
            &header,
            [1; 4],
            MAX_BLOCK,
            2_000_000,
            MAX_BLOCK + 32,
            |_| true
        )
        .is_err()
    );
    assert_eq!(d.reserved(), 0);
    header[8..12].copy_from_slice(&(MAX_BLOCK as u32 + 32).to_le_bytes());
    let mut d = Decoder::new();
    assert_eq!(
        d.feed(
            &header,
            [1; 4],
            MAX_BLOCK,
            2_000_000,
            MAX_BLOCK + 32,
            |_| false
        )
        .err(),
        Some(Error::Sequence)
    );
    assert_eq!(d.reserved(), 0);
    let mut d = Decoder::new();
    assert_eq!(
        d.feed(&header, [1; 4], MAX_BLOCK, 2_000_000, 1, |_| true)
            .unwrap()
            .0,
        HEADER
    );
    assert_eq!(d.reserved(), 0);
}

#[test]
fn parent_frames_require_version_two_expected_phase_and_exact_length_bounds() {
    for kind in [GET_TRANSACTION, TRANSACTION_NOT_FOUND] {
        assert!(encode([1; 4], kind, &[0; 47], MAX_BLOCK, 100).is_err());
        assert!(encode([1; 4], kind, &[0; 49], MAX_BLOCK, 100).is_err());
        assert_eq!(
            decode(&encode([1; 4], kind, &[0; 48], MAX_BLOCK, 100).unwrap(), 1)
                .unwrap()
                .payload
                .len(),
            48
        );
    }
    assert!(encode([1; 4], PARENT_TRANSACTION, &[0; 48], MAX_BLOCK, 100).is_err());
    assert!(encode([1; 4], PARENT_TRANSACTION, &[0; 149], MAX_BLOCK, 100).is_err());
    let frame = encode([1; 4], PARENT_TRANSACTION, &[0; 148], MAX_BLOCK, 100).unwrap();
    let mut decoder = Decoder::new();
    assert_eq!(
        decoder
            .feed(&frame[..HEADER], [1; 4], MAX_BLOCK, 100, 1000, |_| false)
            .err(),
        Some(Error::Sequence)
    );
    assert_eq!(decoder.reserved(), 0);
    let mut legacy = frame;
    legacy[6] = 1;
    let mut decoder = Decoder::new();
    assert_eq!(
        decoder
            .feed(&legacy[..HEADER], [1; 4], MAX_BLOCK, 100, 1000, |_| true)
            .err(),
        Some(Error::Header)
    );
    assert_eq!(decoder.reserved(), 0);
}

#[test]
fn candidates_round_trip_and_reject_malformed_payloads() {
    let candidates = vec![
        ("127.0.0.1:9000".parse().unwrap(), [7; 32]),
        ("[::1]:9001".parse().unwrap(), [8; 32]),
    ];
    let payload = encode_candidates(&candidates).unwrap();
    assert!(valid_length(
        CANDIDATES,
        payload.len(),
        MAX_BLOCK,
        2_000_000
    ));
    let raw = encode([1; 4], CANDIDATES, &payload, MAX_BLOCK, 2_000_000).unwrap();
    let frame = decode(&raw, 2).unwrap();
    assert_eq!(frame.kind, CANDIDATES);
    assert_eq!(parse_candidates(&frame.payload).unwrap(), candidates);

    assert!(encode_candidates(&[]).is_err());
    let too_many = vec![("127.0.0.1:1".parse().unwrap(), [1; 32]); MAX_CANDIDATES_PER_FRAME + 1];
    assert!(encode_candidates(&too_many).is_err());
    assert!(parse_candidates(&[]).is_err());
    let mut trailing = payload.clone();
    trailing.push(0);
    assert!(parse_candidates(&trailing).is_err());
    let mut zero_length = payload.clone();
    zero_length[1] = 0;
    assert!(parse_candidates(&zero_length).is_err());
    let mut wrong_count = payload.clone();
    wrong_count[0] = (MAX_CANDIDATES_PER_FRAME + 1) as u8;
    assert!(parse_candidates(&wrong_count).is_err());
    assert!(parse_candidates(&payload[..payload.len() - 1]).is_err());
    let mut invalid_utf8 = payload.clone();
    invalid_utf8[2] = 0xff;
    assert!(parse_candidates(&invalid_utf8).is_err());
    let mut invalid_text = payload.clone();
    invalid_text[2] = b'x';
    assert!(parse_candidates(&invalid_text).is_err());

    let mut header = [0u8; HEADER];
    header[..4].copy_from_slice(&[1; 4]);
    header[4] = CANDIDATES;
    header[6] = VERSION;
    header[8..12].copy_from_slice(&(MAX_CANDIDATE_PAYLOAD as u32 + 1).to_le_bytes());
    let mut d = Decoder::new();
    assert!(
        d.feed(
            &header,
            [1; 4],
            MAX_BLOCK,
            2_000_000,
            MAX_BLOCK + 32,
            |_| true
        )
        .is_err()
    );
}
