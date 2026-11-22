# Public v6 interoperability fixtures

These are public, deterministic test transactions, not real funds. NEVER use the
test scalars, recipient seed or RNG seed for a wallet or confidential activity.
No user keys or environment data are part of the fixtures.

Producer: Monario-adapted zcash_primitives 0.31.0, upstream orchard 0.16.0
and secp256k1 0.33.1, using the documented MON7 branch and eight-byte expiry. Consumer:
Monario's production V6Verifier after serialized canonical decoding.

- signed-v6.bin: 188 bytes; one test UTXO worth 100 atoms pays 90 atoms to the
  public fixture script, with 10 atoms left as a fee. Positive ECDSA authorization.
- private-v6.bin: 6127 bytes; the same test input shields 90 atoms into Ironwood,
  with 10 atoms left as a fee. One valid corrected-circuit proof, spend and binding
  signatures and positive ECDSA input authorization.

The input is a preloaded test view (txid [7;32], output 0), not a mined transaction.
The signing scalar is the public byte array [1;32], recipient test seed [7;32],
and deterministic StdRng seed [42;32]. No entropy or user wallet is created.

SHA-256:

    signed-v6.bin  c72970980a65cc74eee7c75c87c9399e73522251923ede579019a54160643df2
    private-v6.bin 7f178579460ffb5eadff78e8014e68d3686f9936815c7daccedeea3845854b33

Normal tests consume the committed files. Regeneration is intentionally ignored
by default and was separately executed successfully:

    cargo test -p monario-v6 --release --offline --locked generate_public_interoperability_fixtures -- --ignored

Tests accept both complete fixtures and reject altered input values, transaction
data, proof bytes, spend signatures and binding signatures. This establishes
upstream-builder-to-Monario-verifier compatibility for these two shapes. It is
not an independent second implementation or a complete multi-wallet matrix.

## Real private-input flow

The four spend-* fixtures add a connected, wallet-derived flow using public raw
Seed bytes [7;32] and [8;32], Main network, account 0, external address 0, and the
documented Monario version-1 key/address domains. StdRng uses [43;32]. The producer
is private_spend.rs and uses only PostNu6_3 proving keys and Ironwood v3 bundles.

| File | Bytes | Effect in atoms |
|---|---|---|
| spend-deposit-v6.bin | 6161 | Real height-1 fixture coinbase input 100 -> private note 90, fee 10 |
| spend-transfer-v6.bin | 6014 | Wallet-7 private note 90 -> wallet-8 private note 80, fee 10 |
| spend-withdrawal-v6.bin | 6048 | Wallet-8 private note 80 -> transparent output 70, fee 10 |
| spend-conflict-v6.bin | 6014 | Distinct authorized competing spend of note 90 -> private note 79, fee 11 |

The deposit references the deterministic coinbase txid produced by this test's
helper, rather than a preloaded arbitrary UTXO. Spends decrypt the actual preceding
note and use actual note-tree witnesses. The transfer decodes its receiver through
Monario's private address codec. No real wallet, genesis or nonce search is used.

SHA-256:

    spend-deposit-v6.bin    457a8c50b17b430ab401175224d53c3b86440a4e0f4f58d39b0ede6d0cf0d7fa
    spend-transfer-v6.bin   741e60d6105f1043cf0a4d75a10610e2fb68987f4e3d5d6a7c5ea5363421279c
    spend-withdrawal-v6.bin 3090a6e720717c9f46a2365c84036c1e396fbef2706cdcf44f8a9af0a988c321
    spend-conflict-v6.bin   8a3beac9a127392b6c6943f0567aae7eea40dd52ef570ace76bd9b1e50ff7aef

Generate them explicitly (expensive, executed successfully during implementation):

    cargo test -p monario-v6 --release --offline --locked private_spend::generate_public_private_spend_fixtures -- --ignored --exact

Normal tests read the frozen fixtures. A real DurableChain/V6Verifier flow accepts
fixed-header blocks at 105-second fixture intervals, using real RandomX verification
and no PoW substitutes. Only the first fixture coinbase pays 100 atoms; later
coinbases pay zero and underclaim fees. Ledger supply/pool balance therefore move
100 -> 90 -> 80 -> 70, ending with a transparent 70-atom output and an empty pool.

The competing spend has a different txid and valid proof/authorization but repeats
the original note's nullifier; submission after the transfer rejects DuplicateNullifier
without changing tip/tree. An authenticated checkpoint is restored, then a heavier
alternative branch with that competing spend triggers a two-block disconnection.
The orphaned withdrawal/transfer state is reversed, its transparent output removed,
and private balance/supply become 79. Full replay after restart reproduces tip,
work, tree and supply. No 1,000-block finality rule is introduced.

Tests reject changed branch/locktime, transparent payout, private value balance,
anchor, ciphertext, proof, spend authorization and binding signature. Wallet-8 decrypts its
80-atom output and wallet-7 cannot decrypt it. This is real single-note private
spending and integrated conservation/reorg evidence. Broader multi-input/output,
cross-wallet software, fuzzing and independent cryptographic review remain.
