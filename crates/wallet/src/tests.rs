//! All seeds and expected secrets are public test vectors. Never use for funds.
use super::*;

#[test]
fn seed_lengths_bounds_and_entropy_failure_fail_closed() {
    for len in [0, 16, 31, 33, 63, 65, 1000] {
        assert!(matches!(
            Seed::from_bytes(&vec![7; len]),
            Err(Error::SeedLength)
        ));
    }
    for len in [32, 64] {
        assert_eq!(
            Seed::from_bytes(&vec![7; len])
                .unwrap()
                .expose_for_backup()
                .len(),
            len
        );
    }
    assert!(matches!(
        Seed::generate_with(|bytes| {
            bytes[..8].fill(7);
            Err(())
        }),
        Err(Error::Entropy)
    ));
    let generated = Seed::generate_with(|bytes| {
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = i as u8;
        }
        Ok(())
    })
    .unwrap();
    assert_eq!(generated.expose_for_backup(), (0..32).collect::<Vec<u8>>());
    assert!(matches!(
        generated.transparent_key(Network::Main, 1 << 31, Scope::External, 0),
        Err(Error::Index)
    ));
    assert!(matches!(
        generated.transparent_key(Network::Main, 0, Scope::External, 1 << 31),
        Err(Error::Index)
    ));
    assert!(matches!(
        generated.private_account(Network::Main, u32::MAX),
        Err(Error::Index)
    ));
}

#[test]
fn deterministic_derivation_isolates_network_account_scope_and_pool() {
    let seed = Seed::from_bytes(&[7; 32]).unwrap();
    let mut public_keys = std::collections::BTreeSet::new();
    let mut private_keys = std::collections::BTreeSet::new();
    let mut addresses = std::collections::BTreeSet::new();
    for network in [Network::Main, Network::Test, Network::Regtest] {
        for account in [0, 1] {
            let private = seed.private_account(network, account).unwrap();
            assert!(private_keys.insert(*private.expose_spending_key().to_bytes()));
            for scope in [Scope::External, Scope::Internal] {
                for index in [0, 1] {
                    let key = seed
                        .transparent_key(network, account, scope, index)
                        .unwrap();
                    assert!(public_keys.insert(key.public_key()));
                    let address = key.address();
                    assert_eq!(
                        Address::decode(&address.encode(), network).unwrap(),
                        address
                    );
                    assert!(addresses.insert(address.encode()));
                    assert_eq!(
                        seed.transparent_key(network, account, scope, index)
                            .unwrap()
                            .public_key(),
                        key.public_key()
                    );
                    let private_address = private.address(scope, u128::from(index)).unwrap();
                    assert_eq!(
                        Address::decode(&private_address.encode(), network).unwrap(),
                        private_address
                    );
                    assert!(private_address.script_pubkey().is_none());
                    assert!(addresses.insert(private_address.encode()));
                }
            }
        }
    }
    assert_eq!(addresses.len(), 48);
    assert_ne!(
        *seed.domain_seed(Network::Main, 0),
        *seed.domain_seed(Network::Main, 1)
    );
    let account = seed.private_account(Network::Main, 0).unwrap();
    assert!(account.address(Scope::External, (1_u128 << 88) - 1).is_ok());
    assert_eq!(
        account.address(Scope::External, 1_u128 << 88),
        Err(Error::Index)
    );
    assert!(
        seed.transparent_key(Network::Main, (1 << 31) - 1, Scope::Internal, (1 << 31) - 1)
            .is_ok()
    );
}

#[test]
fn secret_debug_is_redacted_and_owned_buffers_support_zeroization() {
    fn wiped_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    wiped_on_drop::<Seed>();
    wiped_on_drop::<TransparentKey>();
    wiped_on_drop::<PrivateAccount>();
    wiped_on_drop::<orchard::keys::SpendingKey>();
    let seed = Seed::from_bytes(&[7; 32]).unwrap();
    let key = seed
        .transparent_key(Network::Main, 0, Scope::External, 0)
        .unwrap();
    let private = seed.private_account(Network::Main, 0).unwrap();
    assert_eq!(format!("{seed:?}"), "Seed([REDACTED])");
    assert_eq!(format!("{key:?}"), "TransparentKey([REDACTED])");
    assert_eq!(format!("{private:?}"), "PrivateAccount([REDACTED])");
    let mut owned = Zeroizing::new([7_u8; 32]);
    owned.zeroize();
    assert_eq!(*owned, [0; 32]);
}

#[test]
fn bip32_matches_upstream_including_hardened_and_leading_zero_paths() {
    use bip32::{ChildNumber, ExtendedPrivateKey};
    for seed in [[0_u8; 32], [7; 32], core::array::from_fn(|i| i as u8)] {
        let mut own = bip32_key::Node::master(&seed).unwrap();
        let mut upstream = ExtendedPrivateKey::<secp256k1::SecretKey>::new(&seed).unwrap();
        assert_eq!(*own.key, upstream.to_bytes());
        assert_eq!(*own.chain, upstream.attrs().chain_code);
        for (index, hardened) in [
            (0, true),
            (1, false),
            (2, true),
            (2, false),
            (1_000_000_000, false),
        ] {
            own = own.child(index, hardened).unwrap();
            upstream = upstream
                .derive_child(ChildNumber::new(index, hardened).unwrap())
                .unwrap();
            assert_eq!(*own.key, upstream.to_bytes());
            assert_eq!(*own.chain, upstream.attrs().chain_code);
        }
    }
}

fn unhex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|c| u8::from_str_radix(core::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}
#[test]
fn independent_recovery_vectors_match_both_pools_and_networks() {
    let mut count = 0;
    for line in include_str!("../tests/vectors.txt")
        .lines()
        .filter(|l| !l.starts_with('#'))
    {
        let v: Vec<_> = line.split_whitespace().collect();
        assert_eq!(v.len(), 12);
        let seed = Seed::from_bytes(&unhex(v[0])).unwrap();
        let network = match v[1] {
            "main" => Network::Main,
            "test" => Network::Test,
            "regtest" => Network::Regtest,
            _ => panic!("bad network"),
        };
        let account = v[2].parse().unwrap();
        let scope = if v[3] == "0" {
            Scope::External
        } else {
            Scope::Internal
        };
        let index = v[4].parse().unwrap();
        assert_eq!(seed.domain_seed(network, 0).as_slice(), unhex(v[5]));
        let key = seed
            .transparent_key(network, account, scope, index)
            .unwrap();
        assert_eq!(key.expose_secret().as_slice(), unhex(v[6]));
        assert_eq!(key.public_key().as_slice(), unhex(v[8]));
        assert_eq!(key.address().encode(), v[9]);
        let domain = seed.domain_seed(network, 0);
        let mut node = bip32_key::Node::master(domain.as_slice()).unwrap();
        for (n, h) in [
            (44, true),
            (COIN_TYPE, true),
            (account, true),
            (scope.number(), false),
            (index, false),
        ] {
            node = node.child(n, h).unwrap();
        }
        assert_eq!(node.chain.as_slice(), unhex(v[7]));
        assert_eq!(seed.domain_seed(network, 1).as_slice(), unhex(v[10]));
        let private = seed.private_account(network, account).unwrap();
        assert_eq!(
            private.expose_spending_key().to_bytes().as_slice(),
            unhex(v[11])
        );
        let address = private.address(scope, u128::from(index)).unwrap();
        let fvk = orchard::keys::FullViewingKey::from(private.expose_spending_key());
        let Receiver::Private(receiver) = address.receiver() else {
            panic!("private type required");
        };
        assert_eq!(
            fvk.scope_for_address(&receiver.to_upstream()),
            Some(scope.private())
        );
        count += 1;
    }
    assert_eq!(count, 48);
}

#[test]
fn derived_transparent_key_signs_and_wrong_key_rejects() {
    let seed = Seed::from_bytes(&[7; 32]).unwrap();
    let key = seed
        .transparent_key(Network::Main, 0, Scope::External, 0)
        .unwrap();
    let mut secret = secp256k1::SecretKey::from_secret_bytes(*key.expose_secret()).unwrap();
    let message = secp256k1::Message::from_digest([42; 32]);
    let signature = secp256k1::ecdsa::sign(message, &secret);
    secret.non_secure_erase();
    let public = secp256k1::PublicKey::from_byte_array_compressed(key.public_key()).unwrap();
    assert!(signature.verify(message, &public).is_ok());
    let wrong = seed
        .transparent_key(Network::Main, 0, Scope::External, 1)
        .unwrap();
    let wrong = secp256k1::PublicKey::from_byte_array_compressed(wrong.public_key()).unwrap();
    assert!(signature.verify(message, &wrong).is_err());
}

#[test]
fn published_bip32_leading_zero_vectors() {
    use bip32::{ChildNumber, ExtendedPrivateKey};
    for seed in [
        "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
        "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678",
    ] {
        let seed = unhex(seed);
        let mut own = bip32_key::Node::master(&seed).unwrap();
        let mut upstream = ExtendedPrivateKey::<secp256k1::SecretKey>::new(&seed).unwrap();
        for _ in 0..3 {
            assert_eq!(*own.key, upstream.to_bytes());
            assert_eq!(*own.chain, upstream.attrs().chain_code);
            own = own.child(0, true).unwrap();
            upstream = upstream
                .derive_child(ChildNumber::new(0, true).unwrap())
                .unwrap();
        }
    }
}
