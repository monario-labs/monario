use super::*;
use bech32::{Bech32, ByteIterExt, Fe32, Fe32IterExt};

fn unhex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|c| u8::from_str_radix(core::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}
fn network(name: &str) -> Network {
    match name {
        "main" => Network::Main,
        "test" => Network::Test,
        "regtest" => Network::Regtest,
        _ => panic!("bad vector network"),
    }
}
fn vectors() -> Vec<(Network, u8, Vec<u8>, String)> {
    include_str!("../tests/vectors.txt")
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| {
            let columns: Vec<_> = line.split_whitespace().collect();
            (
                network(columns[0]),
                columns[1].parse().unwrap(),
                unhex(columns[2]),
                columns[3].to_string(),
            )
        })
        .collect()
}
fn valid_private() -> PrivateReceiver {
    let raw = vectors()
        .into_iter()
        .find(|(_, kind, _, _)| *kind == 2)
        .unwrap()
        .2;
    PrivateReceiver::from_raw(raw[2..].try_into().unwrap()).unwrap()
}
fn encode_raw(prefix: &str, data: &[u8]) -> String {
    bech32::encode::<Bech32m>(Hrp::parse(prefix).unwrap(), data).unwrap()
}

#[test]
fn independent_vectors_networks_types_and_case_roundtrip() {
    let rows = vectors();
    assert_eq!(rows.len(), 9);
    for (network, kind, payload, text) in rows {
        let address = Address::decode(&text, network).unwrap();
        assert_eq!(address.network(), network);
        assert_eq!(address.encode(), text);
        assert_eq!(
            Address::decode(&text.to_ascii_uppercase(), network).unwrap(),
            address
        );
        match address.receiver() {
            Receiver::Transparent(TransparentReceiver::PublicKeyHash(h)) => {
                assert_eq!(kind, 0);
                assert_eq!(h.as_slice(), &payload[2..]);
            }
            Receiver::Transparent(TransparentReceiver::ScriptHash(h)) => {
                assert_eq!(kind, 1);
                assert_eq!(h.as_slice(), &payload[2..]);
            }
            Receiver::Private(receiver) => {
                assert_eq!(kind, 2);
                assert_eq!(receiver.to_raw().as_slice(), &payload[2..]);
                assert_eq!(
                    receiver.to_upstream().to_raw_address_bytes(),
                    receiver.to_raw()
                );
            }
        }
        assert_eq!(
            text.len(),
            if kind == 2 {
                match network {
                    Network::Main => 83,
                    Network::Test => 87,
                    Network::Regtest => 84,
                }
            } else if network == Network::Main {
                47
            } else if network == Network::Test {
                51
            } else {
                48
            }
        );
        for wrong in [Network::Main, Network::Test, Network::Regtest] {
            if wrong != network {
                assert_eq!(
                    Address::decode(&text, wrong),
                    Err(AddressError::WrongNetwork)
                );
            }
        }
    }
}

#[test]
fn constructors_emit_exact_p2pkh_p2sh_scripts_and_no_private_fallback() {
    let hash: [u8; 20] = core::array::from_fn(|n| n as u8);
    for receiver in [
        TransparentReceiver::PublicKeyHash(hash),
        TransparentReceiver::ScriptHash(hash),
    ] {
        let address = Address::new(Network::Main, Receiver::Transparent(receiver));
        assert_eq!(
            Address::decode(&address.encode(), Network::Main).unwrap(),
            address
        );
        let script = address.script_pubkey().unwrap();
        match receiver {
            TransparentReceiver::PublicKeyHash(_) => assert_eq!(
                script,
                [&[0x76, 0xa9, 0x14][..], &hash, &[0x88, 0xac]].concat()
            ),
            TransparentReceiver::ScriptHash(_) => {
                assert_eq!(script, [&[0xa9, 0x14][..], &hash, &[0x87]].concat())
            }
        }
    }
    let private = Address::new(Network::Main, Receiver::Private(valid_private()));
    assert!(private.script_pubkey().is_none());
    assert_eq!(
        Address::decode(&private.encode(), Network::Main).unwrap(),
        private
    );
}

#[test]
fn checksum_variant_version_type_and_namespace_fail_closed() {
    for (network, _, mut payload, text) in vectors() {
        let prefix = text.split_once('1').unwrap().0;
        let old = bech32::encode::<Bech32>(Hrp::parse(prefix).unwrap(), &payload).unwrap();
        assert!(Address::decode(&old, network).is_err());
        for foreign in ["bc", "tb", "u", "utest", "zs", "ztestsapling"] {
            assert!(Address::decode(&encode_raw(foreign, &payload), network).is_err());
        }
        payload[0] = 2;
        assert_eq!(
            Address::decode(&encode_raw(prefix, &payload), network),
            Err(AddressError::UnsupportedVersion)
        );
        payload[0] = 1;
        for kind in [3, 255] {
            payload[1] = kind;
            assert_eq!(
                Address::decode(&encode_raw(prefix, &payload), network),
                Err(AddressError::UnsupportedReceiver)
            );
        }
    }
    let private = valid_private().to_raw();
    let mut private_payload = vec![1, 2];
    private_payload.extend(private);
    assert!(Address::decode(&encode_raw("mont", &private_payload), Network::Main).is_err());
    for kind in [0, 1] {
        private_payload[1] = kind;
        assert_eq!(
            Address::decode(&encode_raw("monz", &private_payload), Network::Main),
            Err(AddressError::UnsupportedReceiver)
        );
    }
    let mut transparent = vec![1, 2];
    transparent.extend([0; 20]);
    assert_eq!(
        Address::decode(&encode_raw("mont", &transparent), Network::Main),
        Err(AddressError::UnsupportedReceiver)
    );
}

#[test]
fn whitespace_unicode_mixed_case_lengths_and_payload_extensions_fail() {
    for (network, _, payload, text) in vectors() {
        for malformed in [
            format!(" {text}"),
            format!("{text} "),
            format!("{text}\n"),
            format!("{text}\0"),
            text.replacen('o', "ο", 1),
            format!("monario:{text}"),
            format!("{text}?amount=1"),
            format!("{}{}", text[..1].to_ascii_uppercase(), &text[1..]),
        ] {
            assert!(Address::decode(&malformed, network).is_err());
        }
        let prefix = text.split_once('1').unwrap().0;
        for data in [
            &payload[..payload.len() - 1],
            &[payload.as_slice(), &[0]].concat(),
            &[],
        ] {
            assert!(Address::decode(&encode_raw(prefix, data), network).is_err());
        }
        for end in 0..text.len() {
            assert!(Address::decode(&text[..end], network).is_err());
        }
    }
    assert!(Address::decode(&"x".repeat(100000), Network::Main).is_err());
}

#[test]
fn invalid_private_points_fail_even_with_valid_checksum() {
    let raw = valid_private().to_raw();
    for key in [[0; 32], [255; 32]] {
        let mut bad = raw;
        bad[11..].copy_from_slice(&key);
        assert_eq!(
            PrivateReceiver::from_raw(bad),
            Err(AddressError::InvalidReceiver)
        );
        let payload = [&[1, 2][..], &bad].concat();
        assert_eq!(
            Address::decode(&encode_raw("monz", &payload), Network::Main),
            Err(AddressError::InvalidReceiver)
        );
    }
}

#[test]
fn padding_aliases_with_recomputed_checksums_are_rejected() {
    let (_, _, payload, _) = vectors().remove(0);
    let prefix = Hrp::parse("mont").unwrap();
    let original: Vec<Fe32> = payload.iter().copied().bytes_to_fes().collect();
    let mut nonzero = original.clone();
    let last = nonzero.last_mut().unwrap();
    *last = Fe32::try_from(last.to_u8() | 1).unwrap();
    let nonzero: String = nonzero
        .into_iter()
        .with_checksum::<Bech32m>(&prefix)
        .chars()
        .collect();
    assert!(CheckedHrpstring::new::<Bech32m>(&nonzero).is_ok());
    assert_eq!(
        Address::decode(&nonzero, Network::Main),
        Err(AddressError::Encoding)
    );
    let mut excess = original;
    excess.push(Fe32::Q);
    let excess: String = excess
        .into_iter()
        .with_checksum::<Bech32m>(&prefix)
        .chars()
        .collect();
    assert!(CheckedHrpstring::new::<Bech32m>(&excess).is_ok());
    assert_eq!(
        Address::decode(&excess, Network::Main),
        Err(AddressError::Encoding)
    );
    // A 45-byte private payload has no padding. One extra zero symbol yields
    // the SAME decoded bytes unless the excess five padding bits are rejected.
    let payload = vectors()
        .into_iter()
        .find(|(_, kind, _, _)| *kind == 2)
        .unwrap()
        .2;
    let mut symbols: Vec<Fe32> = payload.iter().copied().bytes_to_fes().collect();
    symbols.push(Fe32::Q);
    let prefix = Hrp::parse("monz").unwrap();
    let alias: String = symbols
        .into_iter()
        .with_checksum::<Bech32m>(&prefix)
        .chars()
        .collect();
    let checked = CheckedHrpstring::new::<Bech32m>(&alias).unwrap();
    assert_eq!(checked.byte_iter().collect::<Vec<_>>(), payload);
    assert_eq!(
        Address::decode(&alias, Network::Main),
        Err(AddressError::Encoding)
    );
}

#[test]
fn substitutions_transpositions_insertions_and_deletions_reject() {
    let alphabet = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    for (network, _, _, text) in vectors() {
        for index in 0..text.len() {
            for replacement in alphabet {
                if *replacement != text.as_bytes()[index] {
                    let mut changed = text.as_bytes().to_vec();
                    changed[index] = *replacement;
                    assert!(
                        Address::decode(core::str::from_utf8(&changed).unwrap(), network).is_err()
                    );
                }
            }
            let mut changed = text.clone();
            changed.remove(index);
            assert!(Address::decode(&changed, network).is_err());
            let mut changed = text.clone();
            changed.insert(index, 'q');
            assert!(Address::decode(&changed, network).is_err());
            if index + 1 < text.len() && text.as_bytes()[index] != text.as_bytes()[index + 1] {
                let mut changed = text.as_bytes().to_vec();
                changed.swap(index, index + 1);
                assert!(Address::decode(core::str::from_utf8(&changed).unwrap(), network).is_err());
            }
        }
    }
}

#[test]
fn deterministic_transparent_roundtrips_preserve_type_and_hash() {
    for n in 0..256_u16 {
        let hash = core::array::from_fn(|i| (n as u8).wrapping_add(i as u8));
        for network in [Network::Main, Network::Test, Network::Regtest] {
            for receiver in [
                TransparentReceiver::PublicKeyHash(hash),
                TransparentReceiver::ScriptHash(hash),
            ] {
                let address = Address::new(network, Receiver::Transparent(receiver));
                assert_eq!(
                    Address::decode(&address.encode(), network).unwrap(),
                    address
                );
            }
        }
    }
}
