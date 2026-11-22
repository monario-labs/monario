use monario_randomx::{Error, MAX_INPUT_BYTES, Mode, Verifier};

fn hex(bytes: [u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn pinned_v2_vectors_and_lifecycle() {
    assert!(matches!(Verifier::new(&[]), Err(Error::InvalidSeed)));
    assert!(matches!(Verifier::new(&[0; 65]), Err(Error::InvalidSeed)));
    // Two bounded cache lifetimes, sequentially; no nonce search or mining loop.
    for mode in [Mode::Interpreter, Mode::SecureJit] {
        let mut v = Verifier::with_mode(b"test key 000", mode).unwrap();
        assert_eq!(v.seed(), b"test key 000");
        assert_eq!(
            hex(v.hash(b"This is a test").unwrap()),
            "22ec6b861b3eb23686b2efbad69513c967ecfce80983df66c9c5b4fbfb4cdb6f"
        );
        assert_eq!(
            hex(v.hash(b"Lorem ipsum dolor sit amet").unwrap()),
            "9e2c772c12fd48f93c14c97fdc89d556264d9100597023f44d9163e279012ecf"
        );
        assert_eq!(
            v.hash(&vec![0; MAX_INPUT_BYTES + 1]),
            Err(Error::InputTooLarge)
        );
        assert_eq!(
            hex(v.hash(b"This is a test").unwrap()),
            "22ec6b861b3eb23686b2efbad69513c967ecfce80983df66c9c5b4fbfb4cdb6f"
        );
    }
    let mut v = Verifier::new(b"test key 001").unwrap();
    assert_eq!(
        hex(v
            .hash(b"sed do eiusmod tempor incididunt ut labore et dolore magna aliqua")
            .unwrap()),
        "97024134686ce27d362ea8d86d8ef16483ac272abdabd46ef13359400777fe5e"
    );
}
