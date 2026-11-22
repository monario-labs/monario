use monario_pow::{Asert, Error, Target, seed_height};

fn limit() -> Target {
    Target::from_compact(0x207fffff).unwrap()
}
fn anchor() -> Target {
    Target::from_compact(0x1d00ffff).unwrap()
}
fn controller() -> Asert {
    Asert::new(3600, 1, 0, anchor(), limit()).unwrap()
}

#[test]
fn compact_rejects_malformed_and_noncanonical_values() {
    for bits in [
        0, 0x01000000, 0x01800001, 0x1d80ffff, 0x23000001, 0x22000100, 0x02000100, 0x03000001,
    ] {
        assert!(Target::from_compact(bits).is_err(), "accepted {bits:x}");
    }
    for bits in [
        0x01010000, 0x02008000, 0x03008000, 0x1d00ffff, 0x207fffff, 0x2100ffff,
    ] {
        assert_eq!(Target::from_compact(bits).unwrap().to_compact(), bits);
    }
    assert_eq!(Target::from_le_bytes([0; 32]), Err(Error::ZeroTarget));
}

#[test]
fn exact_schedule_and_halflife_changes() {
    let a = controller();
    for height in [1, 2, 100, 100000] {
        assert_eq!(a.next_target(height, 90 * height).unwrap(), anchor());
    }
    assert_eq!(a.next_bits(100, 9000 + 3600).unwrap(), 0x1d01fffe);
    assert_eq!(a.next_bits(100, 9000 - 3600).unwrap(), 0x1c7fff80);
    assert!(a.validate_bits(0x207fffff, 100, 9000).is_err());
    assert_eq!(a.validate_bits(0x1d00ffff, 100, 9000).unwrap(), anchor());
}

#[test]
fn extrema_are_bounded_and_parameters_fail_closed() {
    assert!(Asert::new(1, u64::MAX, 0, anchor(), limit()).is_err());
    assert!(Asert::new(0, 1, 0, anchor(), limit()).is_err());
    assert!(Asert::new(1, 0, 0, anchor(), limit()).is_err());
    assert!(Asert::new(1, 1, 0, limit(), anchor()).is_err());
    assert_eq!(controller().next_target(0, 0), Err(Error::InvalidHeight));
    assert_eq!(
        controller().next_target(u64::MAX, 0),
        Err(Error::InvalidHeight)
    );
    let a = Asert::new(1, 1, 0, anchor(), limit()).unwrap();
    assert_eq!(a.next_target(1, u64::MAX).unwrap(), limit());
    assert_eq!(a.next_bits(u64::MAX - 1, 0).unwrap(), 0x01010000);
    let a = Asert::new(1, 1, u64::MAX, anchor(), limit()).unwrap();
    assert_eq!(a.next_bits(1, 0).unwrap(), 0x01010000);
    // Easy RandomX targets exceed the BCH implementation's original bound.
    let easy = Asert::new(
        3600,
        1,
        0,
        limit(),
        Target::from_compact(0x2100ffff).unwrap(),
    )
    .unwrap();
    assert_eq!(easy.next_bits(1, 90).unwrap(), 0x207fffff);
    assert_eq!(easy.next_bits(1, 3690).unwrap(), 0x2100ffff);
}

#[test]
fn shock_direction_and_no_wall_clock_dependency() {
    let a = controller();
    for block_seconds in [120, 450, 900, 4500] {
        assert!(a.next_target(1, block_seconds).unwrap() > anchor());
    }
    for block_seconds in [4, 0] {
        assert!(a.next_target(1, block_seconds).unwrap() < anchor());
    }
    let before = a.next_target(1, 90).unwrap();
    // No time input changes unless a parent arrives; there is no wall-clock read.
    assert_eq!(before, a.next_target(1, 90).unwrap());
    let mut previous = Target::from_compact(0x01010000).unwrap();
    for time in 0..20000 {
        let next = a.next_target(100, time).unwrap();
        assert!(next >= previous);
        previous = next;
    }
}

#[test]
fn seed_boundaries_and_reorg_identity() {
    assert!(seed_height(1, 0, 0).is_err());
    assert!(seed_height(1, 64, 64).is_err());
    for (h, expected) in [(0, 0), (2112, 0), (2113, 2048), (4160, 2048), (4161, 4096)] {
        assert_eq!(seed_height(h, 2048, 64), Ok(expected));
    }
    let h = seed_height(u64::MAX, 2048, 64).unwrap();
    assert!(h < u64::MAX - 64);
}

#[test]
fn hash_ordering_equality_and_work() {
    let one = Target::from_compact(0x01010000).unwrap();
    let mut bytes = [0; 32];
    bytes[0] = 1;
    assert!(one.accepts(&bytes));
    bytes[0] = 2;
    assert!(!one.accepts(&bytes));
    bytes = [0; 32];
    bytes[31] = 1;
    assert!(!one.accepts(&bytes));
    assert_eq!(one.work().bits(), 256);
    assert!(anchor().work() > limit().work());
    let max = Target::from_le_bytes([255; 32]).unwrap();
    assert_eq!(max.work(), 1_u8.into());
    // Compact encoding always rounds down, including the 256-bit boundary.
    assert!(Target::from_compact(max.to_compact()).unwrap() <= max);
}

#[test]
fn python_arbitrary_integer_reference_vectors() {
    for row in include_str!("asert_vectors.csv").lines().skip(1) {
        let n: Vec<u64> = row.split(',').map(|s| s.parse().unwrap()).collect();
        let a = Asert::new(
            n[2],
            1,
            0,
            Target::from_compact(n[0] as u32).unwrap(),
            Target::from_compact(n[1] as u32).unwrap(),
        )
        .unwrap();
        assert_eq!(a.next_bits(n[3], n[4]).unwrap(), n[5] as u32, "{row}");
    }
}
