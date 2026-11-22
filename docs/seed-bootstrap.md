# Signed Monario peer bootstrap

| Network | Signed list | Shipped descriptor |
|---|---|---|
| Mainnet | `https://node.monario.org/mainnet/peers.json` | `launch/bootstrap/mainnet.json` |
| Testnet | `https://testnet.monario.org/testnet/peers.json` | `launch/bootstrap/testnet.json` |

`null` means the network has no release bootstrap configuration. Mainnet
remains disabled. Testnet embeds the signed fallback for the launch profile
documented in [the testnet bundle](../launch/testnet/README.md).
A release with a configured descriptor fetches once on each
explicitly network-enabled start for that exact validation profile. Offline
commands, pre-stopped startup, and unrecognized or regtest profiles skip the
fetch. The destination is compiled into the node. HTTPS verifies certificates
using the OS trust store. Redirects and proxies
from the environment are disabled. The request has a five-second configured
timeout and the response is limited to 16 KiB.

The list contributes up to 16 public numeric IP:port endpoints with pinned
X25519 keys. Operators' existing peers take priority and the combined dial
plan remains capped at 32 targets. Bootstrapping never changes the sealed
peer configuration or advertises the seeds as operator-pinned candidates.
The usual encrypted P2P handshake and full consensus validation still apply.

## Prepare a release and publish updates

1. Prepare the final network manifest and obtain its validation profile with
   `monario-launch check node.json --strict`. Use a separate offline Ed25519
   signing key and separate seed operators for each network where available.
2. Build the UTF-8 JSON payload. Use `version: 1`, `network` (`mainnet` or
   `testnet`), `profile` (64 lowercase hex), a positive integer `sequence`,
   `expires` (UTC Unix seconds), and `peers`. Each peer has `address` and
   `public_key` (64 lowercase hex). Start sequence numbering at 1 and increase
   it for every update. Select real, reachable P2P servers on independent hosts.
3. Sign the exact payload bytes prefixed by `Monario/signed-peers/v1` and one
   NUL byte. The envelope is a JSON object containing `payload` (the original
   JSON text as a string) and `signature` (the raw 64-byte Ed25519 signature as
   128 lowercase hex characters). Retain exact whitespace in the payload; the
   verifier signs and verifies bytes rather than reserializing JSON. Publish
   only the envelope at the network's HTTPS endpoint.
4. For the shipped descriptor, commit an object with `profile`, `signing_key`
   (the raw 32-byte Ed25519 public key as lowercase hex), and `fallback` (a
   complete signed envelope). Keep the private signing key out of the repo,
   web server and build artifacts. Use an expiration that gives operators
   time to obtain a newer signed list before the fallback expires.
5. Validate the descriptor locally and include it in the release build. This
   preflight command reads the two files and performs no networking:

   ```sh
   monario-launch bootstrap-check testnet launch/bootstrap/testnet.json node.json
   monario-launch bootstrap-check testnet --bundled node.json
   ```

   Use `mainnet` and the mainnet descriptor/manifest for a mainnet release.
   Check the network identity and seed public keys out of band before signing.

An unexpired bundled list works when the endpoint is unavailable and there
is no newer accepted list. An accepted refresh is saved with atomic replacement
as `bootstrap-peers.json` in the private node directory. Older or same-sequence
updates cannot replace the trusted list. An expired cached list still sets the
rollback floor: the node will not resuscitate older seeds after expiry. If the
cache fails validation, the node uses the operator's peers only. Keep separate
node directories for the two networks. Protect the directory from tampering;
deleting or restoring its cache removes or rolls back that local floor. A signer
rotation requires a reviewed new release and explicit cache migration.

## Explorer hostname

Reserve `explorer.monario.org` for the read-only explorer. Serve testnet there
when testnet launches and point it at mainnet when mainnet launches. Keep the
network clearly labeled and use separate data stores. The explorer hostname
and its DNS do not participate in peer bootstrap.
