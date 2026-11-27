# Monario testnet launch bundle

This frozen profile defines a testnet only. `root.json` describes the zero-supply
height-zero anchor. `root-commitment.txt` is the public commitment preimage.
`node.json` contains the matching network and consensus parameters. Keep the
commitment file in UTF-8 with LF line endings and a final newline.

## Verify before use

From this directory, using a qualified `monario-launch` binary:

```sh
sha256sum root-commitment.txt
monario-launch root-check root.json node.json
monario-launch check node.json --strict
monario-launch bootstrap-check testnet --bundled node.json
```

Compare the SHA-256 result with `root_commitment` in `root.json`. All three commands
must report this validation profile:

```text
b98e1a569780fb47a7ac68e284525da49e13267224eec5029b90a9970d989d18
```

The bundled check verifies the descriptor compiled into the binary. In the
release archive, `bootstrap.json` is its public copy and `peers.json` is the
matching sequence-2 signed envelope for `https://testnet.monario.org/testnet/peers.json`.
The list expires on 2027-02-01 at 00:00 UTC. Deploy the matching seed identity
and envelope as part of the profile cutover. The previous endpoint and
height-zero database belong to a different validation profile.

## Starting difficulty

The initial target (`0x1f074822`) gives roughly 9,000 hashes per accepted
block on average, or a 90-second initial interval at an assumed combined
100 hashes/second. The PoW limit (`0x2000ffff`) permits approximately 256 hashes
per block at the easiest target. ASERT uses a six-hour half-life.

The height-zero root timestamp is 2026-11-27 00:00 UTC. With
`asert_from_first_block` enabled, each branch derives its ASERT reference time
from its own validated block 1. Blocks 1 and 2 both use the initial target.
From block 3, the expected elapsed time at parent height `h` is
`(h - 1) × 90 seconds` since block 1. This keeps a delayed launch from aging
the difficulty reference. The root record still establishes the chain identity
and earliest block timestamp. The profile uses `testnet-v2.sqlite`.

## Release hygiene

Build with `python3 tools/build_private.py --node-tools` from the workspace
using the pinned Cargo lockfile and a clean Ubuntu build directory. Fetch
locked dependencies before invoking the offline build. To check identities
from a separate host, set `MONARIO_PRIVATE_SCAN_FILE` to a private local file
with one identifying string per line. Keep that file, build logs and build
caches outside the release package. Package only scanned executables, reviewed
launch files and checksums. Repeat the build and scan for the mainnet release
with a separate root, manifest and profile.
