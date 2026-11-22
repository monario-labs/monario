use super::*;
pub(super) const MAX_ACCOUNTS: usize = 128;
pub(super) const T_END: u64 = 1 << 31;
pub(super) const P_END: u128 = 1 << 88;
pub(super) struct State {
    pub seed: Seed,
    pub accounts: BTreeMap<u32, AccountProgress>,
    pub recovery: bool,
    pub pending: BTreeMap<[u8; 16], pending::Reservation>,
}
pub(super) fn valid(accounts: &BTreeMap<u32, AccountProgress>) -> Result<(), StorageError> {
    if accounts.len() > MAX_ACCOUNTS {
        return Err(StorageError::Capacity);
    }
    for (id, p) in accounts {
        if *id >= 1 << 31
            || p.transparent_external > T_END
            || p.transparent_internal > T_END
            || p.private_external > P_END
            || p.private_internal > P_END
        {
            return Err(StorageError::Invalid);
        }
    }
    Ok(())
}
#[cfg(test)]
pub(super) fn encode(
    seed: &Seed,
    accounts: &BTreeMap<u32, AccountProgress>,
    recovery: bool,
) -> Result<Zeroizing<Vec<u8>>, StorageError> {
    encode_pending(seed, accounts, recovery, &BTreeMap::new())
}
pub(super) fn encode_pending(
    seed: &Seed,
    accounts: &BTreeMap<u32, AccountProgress>,
    recovery: bool,
    pending: &BTreeMap<[u8; 16], pending::Reservation>,
) -> Result<Zeroizing<Vec<u8>>, StorageError> {
    valid(accounts)?;
    let mut b = Zeroizing::new(Vec::with_capacity(crypto::PLAIN_LEN));
    b.extend([u8::from(recovery), seed.expose_for_backup().len() as u8]);
    b.extend(seed.expose_for_backup());
    b.extend((accounts.len() as u16).to_le_bytes());
    for (id, p) in accounts {
        b.extend(id.to_le_bytes());
        b.extend(p.transparent_external.to_le_bytes());
        b.extend(p.transparent_internal.to_le_bytes());
        b.extend(p.private_external.to_le_bytes());
        b.extend(p.private_internal.to_le_bytes());
    }
    pending::encode(pending, &mut b)?;
    if b.len() > crypto::PLAIN_LEN {
        return Err(StorageError::Capacity);
    }
    b.resize(crypto::PLAIN_LEN, 0);
    Ok(b)
}
pub(super) fn decode(bytes: &[u8]) -> Result<State, StorageError> {
    if !matches!(bytes.len(), crypto::PLAIN_LEN | crypto::LEGACY_PLAIN_LEN)
        || bytes[0] > 1
        || !matches!(bytes[1], 32 | 64)
    {
        return Err(StorageError::Invalid);
    }
    let n = usize::from(bytes[1]);
    let seed = Seed::from_bytes(&bytes[2..2 + n]).map_err(|_| StorageError::Invalid)?;
    let count = u16::from_le_bytes(
        bytes[2 + n..4 + n]
            .try_into()
            .map_err(|_| StorageError::Invalid)?,
    ) as usize;
    if count > MAX_ACCOUNTS {
        return Err(StorageError::Capacity);
    }
    let mut offset = 4 + n;
    let mut accounts = BTreeMap::new();
    let mut last = None;
    for _ in 0..count {
        let b = &bytes[offset..offset + 52];
        offset += 52;
        let id = u32::from_le_bytes(b[..4].try_into().map_err(|_| StorageError::Invalid)?);
        if last.is_some_and(|v| id <= v) {
            return Err(StorageError::Invalid);
        }
        last = Some(id);
        accounts.insert(
            id,
            AccountProgress {
                transparent_external: u64::from_le_bytes(
                    b[4..12].try_into().map_err(|_| StorageError::Invalid)?,
                ),
                transparent_internal: u64::from_le_bytes(
                    b[12..20].try_into().map_err(|_| StorageError::Invalid)?,
                ),
                private_external: u128::from_le_bytes(
                    b[20..36].try_into().map_err(|_| StorageError::Invalid)?,
                ),
                private_internal: u128::from_le_bytes(
                    b[36..52].try_into().map_err(|_| StorageError::Invalid)?,
                ),
            },
        );
    }
    let pending = if bytes.len() == crypto::PLAIN_LEN {
        pending::decode(bytes, &mut offset)?
    } else {
        BTreeMap::new()
    };
    if bytes[offset..].iter().any(|b| *b != 0) {
        return Err(StorageError::Invalid);
    }
    valid(&accounts)?;
    Ok(State {
        seed,
        accounts,
        recovery: bytes[0] != 0,
        pending,
    })
}
