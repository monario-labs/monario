use monario_pow::{Error, Target, verify};
use monario_randomx::Verifier;

#[test]
fn branch_seed_and_expected_target_are_enforced() {
    let seed = [19; 32];
    let mut v = Verifier::new(&seed).unwrap();
    let hardest = Target::from_compact(0x01010000).unwrap();
    let easiest = Target::from_le_bytes([255; 32]).unwrap();
    assert_eq!(
        verify(&mut v, &[20; 32], b"fixed validation fixture", &easiest),
        Err(Error::WrongSeed)
    );
    assert_eq!(
        verify(&mut v, &seed, b"fixed validation fixture", &hardest),
        Err(Error::InsufficientWork)
    );
    assert_eq!(
        verify(&mut v, &seed, b"fixed validation fixture", &easiest),
        Ok(())
    );
    assert_eq!(
        verify(&mut v, &seed, &[0; 4097], &easiest),
        Err(Error::RandomX(monario_randomx::Error::InputTooLarge))
    );
}
