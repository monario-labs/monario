//! Offline message signatures for issued external transparent P2PKH addresses.
//! Proofs bind a canonical address, compressed key and low-S ECDSA signature to a
//! Monario domain digest. Messages, proofs and keys are never accepted from argv.
use super::*;
use monario_address::{Address, Receiver, TransparentReceiver};
use ripemd::Ripemd160;
use secp256k1::{
    Message, PublicKey, SecretKey,
    ecdsa::{self, Signature},
};
use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"Monario/SignedMessage/v1\0";
const PREFIX: &str = "monmsg1";
const MAX_MESSAGE: usize = 4096;
const MAX_PROOF: usize = 512;

pub(super) struct Options {
    pub(super) index: u32,
}
impl Options {
    pub(super) fn parse(options: &mut BTreeMap<String, OsString>) -> Result<Self, Error> {
        let index = number(&text(options.remove("--address-index"))?)?;
        if index >= 1 << 31 {
            return Err(Error::Arguments);
        }
        Ok(Self {
            index: index as u32,
        })
    }
}

// Same erasure convention as service.rs; the transient signing copy is wiped on every path.
struct SigningKey(SecretKey);
impl Drop for SigningKey {
    fn drop(&mut self) {
        self.0.non_secure_erase();
    }
}

#[derive(Serialize)]
pub(super) struct SignOutput {
    address: String,
    proof: String,
}

#[derive(Serialize)]
pub(super) struct VerifyOutput {
    valid: bool,
    address: String,
}

fn frame(input: &mut impl Read, max: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut header = [0; 2];
    input.read_exact(&mut header).map_err(|_| Error::Message)?;
    let len = usize::from(u16::from_le_bytes(header));
    if !(1..=max).contains(&len) {
        return Err(Error::Message);
    }
    let mut bytes = Zeroizing::new(vec![0; len]);
    input.read_exact(&mut bytes).map_err(|_| Error::Message)?;
    Ok(bytes)
}

/// Read one u16 little-endian frame of 1..=4096 exact UTF-8 bytes. No trimming.
pub(super) fn read_message(input: &mut impl Read) -> Result<Zeroizing<Vec<u8>>, Error> {
    let bytes = frame(input, MAX_MESSAGE)?;
    std::str::from_utf8(&bytes).map_err(|_| Error::Message)?;
    Ok(bytes)
}

fn end(input: &mut impl Read) -> Result<(), Error> {
    let mut extra = [0; 1];
    if input.read(&mut extra).map_err(|_| Error::Message)? != 0 {
        return Err(Error::Message);
    }
    Ok(())
}

fn digest(address: &str, message: &[u8]) -> Message {
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update((address.len() as u32).to_le_bytes());
    hash.update(address.as_bytes());
    hash.update((message.len() as u32).to_le_bytes());
    hash.update(message);
    Message::from_digest(hash.finalize().into())
}

fn fixed<const N: usize>(text: &str) -> Result<[u8; N], Error> {
    if text.len() != 2 * N
        || !text
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(Error::Message);
    }
    let mut out = [0; N];
    for (i, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        let digit = |c: u8| if c <= b'9' { c - b'0' } else { c - b'a' + 10 };
        out[i] = digit(pair[0]) * 16 + digit(pair[1]);
    }
    Ok(out)
}

/// Sign only a previously issued external transparent index under a clear recovery lock.
pub(super) fn sign(
    store: &WalletStore,
    account: u32,
    index: u32,
    message: &[u8],
) -> Result<SignOutput, Error> {
    if store.recovery_required().map_err(storage)? {
        return Err(Error::RecoveryLocked);
    }
    let issued = store
        .account_progress()
        .map_err(storage)?
        .get(&account)
        .map_or(0, |progress| progress.transparent_external);
    if u64::from(index) >= issued {
        return Err(Error::Message);
    }
    let network = store.checkpoint().map_err(storage)?.network;
    let key = store
        .expose_seed()
        .map_err(storage)?
        .transparent_key(network, account, Scope::External, index)
        .map_err(|_| Error::Message)?;
    let address = key.address().encode();
    let public = key.public_key();
    let secret =
        SigningKey(SecretKey::from_secret_bytes(*key.expose_secret()).map_err(|_| Error::Message)?);
    let signature = ecdsa::sign(digest(&address, message), &secret.0);
    let proof = format!(
        "{PREFIX}:{address}:{}:{}",
        hex(&public),
        hex(&signature.serialize_compact())
    );
    Ok(SignOutput { address, proof })
}

/// Verify exact message and proof frames against an explicit network, then EOF.
pub(super) fn verify(network: Network, input: &mut impl Read) -> Result<VerifyOutput, Error> {
    let message = read_message(input)?;
    let raw = frame(input, MAX_PROOF)?;
    end(input)?;
    let proof = std::str::from_utf8(&raw).map_err(|_| Error::Message)?;
    let address = check(network, &message, proof)?;
    Ok(VerifyOutput {
        valid: true,
        address,
    })
}

fn check(network: Network, message: &[u8], proof: &str) -> Result<String, Error> {
    if !proof
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b':')
    {
        return Err(Error::Message);
    }
    let parts: Vec<&str> = proof.split(':').collect();
    let [prefix, address, public, signature]: [&str; 4] =
        parts.try_into().map_err(|_| Error::Message)?;
    if prefix != PREFIX {
        return Err(Error::Message);
    }
    let decoded = Address::decode(address, network).map_err(|_| Error::Message)?;
    if decoded.encode() != address {
        return Err(Error::Message);
    }
    let Receiver::Transparent(TransparentReceiver::PublicKeyHash(owner)) = decoded.receiver()
    else {
        return Err(Error::Message);
    };
    let public_bytes: [u8; 33] = fixed(public)?;
    let key = PublicKey::from_byte_array_compressed(public_bytes).map_err(|_| Error::Message)?;
    let hash: [u8; 20] = Ripemd160::digest(Sha256::digest(public_bytes)).into();
    if hash != owner {
        return Err(Error::Message);
    }
    let signature_bytes: [u8; 64] = fixed(signature)?;
    let signature = Signature::from_compact(&signature_bytes).map_err(|_| Error::Message)?;
    let mut normalized = signature;
    normalized.normalize_s();
    if normalized != signature {
        return Err(Error::Message);
    }
    ecdsa::verify(&signature, digest(address, message), &key).map_err(|_| Error::Message)?;
    Ok(address.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use monario_wallet::{
        Network, Scope, Seed,
        storage::{AddressKind, Password, WalletDirectory, WalletStore},
    };
    use std::io::Cursor;

    const PASSWORD: &[u8] = b"public message wallet password";
    const NEW: &[u8] = b"public replacement message password";
    const MESSAGE: &[u8] = b"hello monario";
    const ORDER: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x41,
    ];

    fn wire(values: &[&[u8]]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for value in values {
            bytes.extend((value.len() as u16).to_le_bytes());
            bytes.extend(*value);
        }
        bytes
    }

    fn fixture() -> (tempfile::TempDir, WalletStore) {
        let root = tempfile::tempdir().unwrap();
        let dir = WalletDirectory::open(root.path()).unwrap();
        let store = WalletStore::create(
            &dir,
            "wallet",
            Seed::from_bytes(&[7; 32]).unwrap(),
            Network::Regtest,
            &Password::from_bytes(PASSWORD).unwrap(),
        )
        .unwrap();
        (root, store)
    }

    fn issue(store: &mut WalletStore, scope: Scope, kind: AddressKind) -> String {
        store.next_address(0, scope, kind).unwrap().address.encode()
    }

    fn high_s(mut sig: [u8; 64]) -> [u8; 64] {
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let v = i16::from(ORDER[i]) - i16::from(sig[32 + i]) - borrow;
            let (byte, next) = if v < 0 {
                ((v + 256) as u8, 1)
            } else {
                (v as u8, 0)
            };
            sig[32 + i] = byte;
            borrow = next;
        }
        sig
    }

    #[test]
    fn signed_message_verifies_for_its_exact_network_address_and_bytes() {
        let (_root, mut store) = fixture();
        let address = issue(&mut store, Scope::External, AddressKind::Transparent);
        let signed = sign(&store, 0, 0, MESSAGE).unwrap();
        assert_eq!(signed.address, address);
        let parts: Vec<&str> = signed.proof.split(':').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0], "monmsg1");
        assert_eq!(parts[2].len(), 66);
        assert_eq!(parts[3].len(), 128);
        assert_eq!(
            check(Network::Regtest, MESSAGE, &signed.proof).unwrap(),
            address
        );
        assert!(check(Network::Main, MESSAGE, &signed.proof).is_err());
        assert!(check(Network::Test, MESSAGE, &signed.proof).is_err());
        let max = vec![b'a'; MAX_MESSAGE];
        let long = sign(&store, 0, 0, &max).unwrap();
        assert!(check(Network::Regtest, &max, &long.proof).is_ok());
    }

    #[test]
    fn altered_message_address_key_signature_and_network_are_rejected() {
        let (_root, mut store) = fixture();
        issue(&mut store, Scope::External, AddressKind::Transparent);
        let other_address = issue(&mut store, Scope::External, AddressKind::Transparent);
        let signed = sign(&store, 0, 0, MESSAGE).unwrap();
        let other = sign(&store, 0, 1, MESSAGE).unwrap();
        assert_eq!(other.address, other_address);
        let proof = signed.proof.clone();
        let other_key = other.proof.split(':').nth(2).unwrap();
        let key = proof.split(':').nth(2).unwrap();

        assert!(check(Network::Regtest, b"hello monario!", &proof).is_err());
        assert!(check(Network::Regtest, b"Hello monario", &proof).is_err());
        assert!(check(Network::Regtest, b"hello monario ", &proof).is_err());
        assert!(
            check(
                Network::Regtest,
                MESSAGE,
                &proof.replacen(&signed.address, &other.address, 1)
            )
            .is_err()
        );
        assert!(
            check(
                Network::Regtest,
                MESSAGE,
                &proof.replacen(key, other_key, 1)
            )
            .is_err()
        );

        let mut flipped = proof.clone();
        let last = flipped.pop().unwrap();
        flipped.push(if last == '0' { '1' } else { '0' });
        assert!(check(Network::Regtest, MESSAGE, &flipped).is_err());
        assert!(
            check(
                Network::Regtest,
                MESSAGE,
                &proof.replacen("monmsg1", "monmsg2", 1)
            )
            .is_err()
        );
    }

    #[test]
    fn high_s_uppercase_and_malformed_proofs_are_rejected() {
        let (_root, mut store) = fixture();
        issue(&mut store, Scope::External, AddressKind::Transparent);
        let signed = sign(&store, 0, 0, MESSAGE).unwrap();
        let parts: Vec<&str> = signed.proof.split(':').collect();
        let sig: [u8; 64] = fixed(parts[3]).unwrap();
        let high = hex(&high_s(sig));
        let high_proof = format!("monmsg1:{}:{}:{high}", parts[1], parts[2]);
        assert_eq!(
            check(Network::Regtest, MESSAGE, &high_proof).err(),
            Some(Error::Message)
        );
        let malformed = [
            signed.proof.to_ascii_uppercase(),
            format!("{} ", signed.proof),
            format!("{}:", signed.proof),
            format!("{}:{}", signed.proof, "00"),
            signed
                .proof
                .replacen(parts[3], &parts[3].to_ascii_uppercase(), 1),
            signed.proof.replacen(parts[2], &parts[2][..64], 1),
            signed.proof.replacen(parts[3], &parts[3][..127], 1),
            signed
                .proof
                .replacen(parts[3], &format!("{}g", &parts[3][..127]), 1),
            format!("monmsg1:{}:{}", parts[1], parts[2]),
            String::new(),
        ];
        for proof in malformed {
            assert_eq!(
                check(Network::Regtest, MESSAGE, &proof).err(),
                Some(Error::Message),
                "{proof}"
            );
        }
    }

    #[test]
    fn message_and_proof_frames_are_exact_and_bounded() {
        let (_root, mut store) = fixture();
        issue(&mut store, Scope::External, AddressKind::Transparent);
        let proof = sign(&store, 0, 0, MESSAGE).unwrap().proof;
        let proof = proof.as_bytes();
        let verify_bytes = |bytes: Vec<u8>| verify(Network::Regtest, &mut Cursor::new(bytes)).err();
        assert!(verify(Network::Regtest, &mut Cursor::new(wire(&[MESSAGE, proof]))).is_ok());
        let oversize_message = vec![b'a'; MAX_MESSAGE + 1];
        let oversize_proof = vec![b'a'; MAX_PROOF + 1];
        assert_eq!(verify_bytes(wire(&[&b""[..], proof])), Some(Error::Message));
        assert_eq!(
            verify_bytes(wire(&[&oversize_message[..], proof])),
            Some(Error::Message)
        );
        assert_eq!(
            verify_bytes(wire(&[&[0xffu8][..], proof])),
            Some(Error::Message)
        );
        assert_eq!(
            verify_bytes(wire(&[MESSAGE, &b""[..]])),
            Some(Error::Message)
        );
        assert_eq!(
            verify_bytes(wire(&[MESSAGE, &oversize_proof[..]])),
            Some(Error::Message)
        );
        let mut trailing = wire(&[MESSAGE, proof]);
        trailing.push(0);
        assert_eq!(verify_bytes(trailing), Some(Error::Message));
        let mut truncated = wire(&[MESSAGE, proof]);
        truncated.pop();
        assert_eq!(verify_bytes(truncated), Some(Error::Message));
        assert_eq!(verify_bytes(vec![5]), Some(Error::Message));

        let exact = vec![b'a'; MAX_MESSAGE];
        assert!(read_message(&mut Cursor::new(wire(&[&exact[..]]))).is_ok());
        assert_eq!(
            read_message(&mut Cursor::new(wire(&[&oversize_message[..]]))).err(),
            Some(Error::Message)
        );
        assert_eq!(
            read_message(&mut Cursor::new(wire(&[&[0xc3u8][..]]))).err(),
            Some(Error::Message)
        );
    }

    #[test]
    fn signing_requires_an_issued_external_transparent_index() {
        let (_root, mut store) = fixture();
        assert_eq!(sign(&store, 0, 0, MESSAGE).err(), Some(Error::Message));
        issue(&mut store, Scope::Internal, AddressKind::Transparent);
        issue(&mut store, Scope::External, AddressKind::Private);
        assert_eq!(sign(&store, 0, 0, MESSAGE).err(), Some(Error::Message));
        issue(&mut store, Scope::External, AddressKind::Transparent);
        assert!(sign(&store, 0, 0, MESSAGE).is_ok());
        assert_eq!(sign(&store, 0, 1, MESSAGE).err(), Some(Error::Message));
        assert_eq!(sign(&store, 1, 0, MESSAGE).err(), Some(Error::Message));
    }

    #[test]
    fn recovery_locked_wallets_refuse_signing() {
        let (root, mut store) = fixture();
        issue(&mut store, Scope::External, AddressKind::Transparent);
        let dir = WalletDirectory::open(root.path()).unwrap();
        let checkpoint = store
            .backup(&dir, "snapshot", &Password::from_bytes(PASSWORD).unwrap())
            .unwrap();
        let restored = WalletStore::recover(
            &dir,
            "snapshot",
            &Password::from_bytes(PASSWORD).unwrap(),
            checkpoint,
            &dir,
            "restored",
            &Password::from_bytes(NEW).unwrap(),
        )
        .unwrap();
        assert!(restored.recovery_required().unwrap());
        assert_eq!(
            sign(&restored, 0, 0, MESSAGE).err(),
            Some(Error::RecoveryLocked)
        );
    }

    #[test]
    fn cli_arguments_and_stdin_frames_produce_only_public_outputs() {
        let (root, mut store) = fixture();
        issue(&mut store, Scope::External, AddressKind::Transparent);
        let checkpoint = store.checkpoint().unwrap();
        drop(store);
        let directory = root.path().to_str().unwrap().to_owned();
        let sign_args: Vec<OsString> = [
            "sign-message".to_owned(),
            "--directory".into(),
            directory.clone(),
            "--name".into(),
            "wallet".into(),
            "--network".into(),
            "regtest".into(),
            "--password-stdin".into(),
            "--wallet-id".into(),
            hex(&checkpoint.wallet_id),
            "--revision".into(),
            checkpoint.revision.to_string(),
            "--address-index".into(),
            "0".into(),
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        let command = Command::parse(sign_args.clone()).unwrap();
        assert!(command.needs_password());
        let mut output = Vec::new();
        execute(
            command,
            &mut Cursor::new(wire(&[PASSWORD, MESSAGE])),
            &mut output,
        )
        .unwrap();
        let signed: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(signed.as_object().unwrap().len(), 2);
        let proof = signed["proof"].as_str().unwrap().to_owned();
        assert!(!String::from_utf8_lossy(&output).contains("public message wallet"));

        let mut trailing = Vec::new();
        assert!(
            execute(
                Command::parse(sign_args.clone()).unwrap(),
                &mut Cursor::new({
                    let mut bytes = wire(&[PASSWORD, MESSAGE]);
                    bytes.push(0);
                    bytes
                }),
                &mut trailing,
            )
            .is_err()
        );
        assert!(trailing.is_empty());

        let verify_args: Vec<OsString> = ["verify-message", "--network", "regtest"]
            .into_iter()
            .map(OsString::from)
            .collect();
        let command = Command::parse(verify_args.clone()).unwrap();
        assert!(!command.needs_password());
        let mut output = Vec::new();
        execute(
            command,
            &mut Cursor::new(wire(&[MESSAGE, proof.as_bytes()])),
            &mut output,
        )
        .unwrap();
        let verified: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(verified["valid"], true);
        assert_eq!(verified["address"], signed["address"]);

        let mut ignored = Vec::new();
        assert_eq!(
            execute(
                Command::parse(verify_args.clone()).unwrap(),
                &mut Cursor::new(wire(&[&b"other message"[..], proof.as_bytes()])),
                &mut ignored,
            )
            .err(),
            Some(Error::Message)
        );
        assert!(ignored.is_empty());

        let mut with_directory = verify_args.clone();
        with_directory.extend(["--directory", directory.as_str()].map(OsString::from));
        assert!(Command::parse(with_directory).is_err());
        let mut bad_index = sign_args.clone();
        bad_index.pop();
        bad_index.push("2147483648".into());
        assert!(Command::parse(bad_index).is_err());
    }
}
