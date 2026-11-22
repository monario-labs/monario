# Monario testnet rehearsal bundle

This candidate defines a testnet only. `root.json` describes the zero-supply
height-zero anchor. `root-commitment.txt` is the public commitment preimage.
`node.json` contains the matching network and consensus parameters. Keep the
commitment file in UTF-8 with LF line endings and a final newline.

## Verify before use

From this directory, using a qualified `monario-launch` binary:

```sh
sha256sum root-commitment.txt
monario-launch root-check root.json node.json
monario-launch check node.json --strict
```

Compare the SHA-256 result with `root_commitment` in `root.json`. Both commands
must report this validation profile:

```text
fb9a57f8dfb02c16822ded5440d0147864cd3e5a0dadcc568a24ff41cd53b02b
```

The strict manifest check covers recommended parameters. Also review the
chain ID, root and difficulty fields, which are explicit operator inputs.

## Starting difficulty

The initial target (`0x1f074822`) gives roughly 9,000 hashes per accepted
block on average, or a 90-second initial interval at an assumed combined
100 hashes/second. Benchmark participating CPUs before freezing the launch
configuration. The PoW limit (`0x2000ffff`) permits approximately 256 hashes
per block at the easiest target. ASERT uses a six-hour half-life.

The anchor timestamp is 2026-11-21 19:49 UTC. A delay between this timestamp
and the first mined block affects ASERT from block 2. If operators rehearse
substantially later, prepare a fresh record and manifest near the planned
start, verify the resulting profile and distribute the new bundle together.

## Release hygiene

Build with `python3 tools/build_private.py --node-tools` from the workspace
using the pinned Cargo lockfile and a clean Ubuntu build directory. Fetch
locked dependencies before invoking the offline build. To check identities
from a separate host, set `MONARIO_PRIVATE_SCAN_FILE` to a private local file
with one identifying string per line. Keep that file, build logs and build
caches outside the release package. Package only scanned executables, reviewed
launch files and checksums. Repeat the build and scan for the mainnet release
with a separate root, manifest and profile.
