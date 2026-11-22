# One-hop peer candidate exchange

For release-pinned, signed seed lists on explicitly network-enabled startup,
see [signed peer bootstrap](seed-bootstrap.md). That mechanism is independent
of the untrusted candidate exchange described here.

Monario now supports a **bounded, one-hop, operator-reviewed** peer candidate
exchange. It is deliberately not automatic peer discovery, not trust-on-first-use
and not a dialing policy change.

## What the node does

- After a peer completes the application handshake (`HELLO` then `ACK`), the node
  sends a `CANDIDATES` frame containing **only the peers already pinned in its
  local trusted configuration**.
- It never advertises candidates it received from another peer. Discovery is
  one hop and never becomes transitive gossip.
- A received candidate is stored in an in-memory, bounded list. It is **never**
  added to the pinned configuration, never scheduled for a connection and never
  used for synchronization or relay.
- The list is capped at 128 entries. Duplicates, the local identity, pinned peers
  and self-advertisements are ignored. Malformed contents, invalid keys or invalid
  addresses drop the offending peer as a protocol violation.

## Wire format

Kind `15`, bounded to 1,553 payload bytes:

```
count u8                 (1..=16)
repeat count times:
    address_len u8       (1..=64)
    address              ASCII numeric IP:port, IPv6 bracketed
    public_key[32]       X25519 transport public key
```

- No DNS names, trailing bytes, partial records or count mismatches are accepted.
- Addresses must have a nonzero port and must not be unspecified or multicast.
- Keys must pass the same noncontributory X25519 rejection used by the transport.
- The frame checksum detects corruption; it does **not** authenticate the
  advertised identities. All candidates are untrusted.

## Operator workflow

1. Start the node with an existing pinned peers manifest.
2. The status snapshot (`--status-file`) includes `candidates` and
   `candidates_untrusted: true`.
3. The GUI Node page shows those candidates and can copy each as
   `{"address":"…","public_key":"…"}`.
4. The operator pastes chosen records into the peers manifest editor and clicks
   **Validate and write**. That explicit step is the only way a candidate can
   become a dial target.
5. Restart the runtime so the new pinned configuration is loaded.

The GUI never promotes a candidate automatically and never writes one into the
trusted peers file. A candidate is not evidence of liveness, honesty or identity
ownership.

## What this does not provide

- Automatic dialing or automatic promotion.
- DNS seeds, DHT discovery, peer exchange beyond one hop, or peer scoring.
- Eclipse resistance, Sybil resistance or liveness guarantees.
- Candidate persistence across process restarts. A candidate that is not reviewed
  is lost with the process.
- Authenticated discovery records. The pin remains the trust anchor.

## Tests

- Wire round-trip and strict rejection of bad counts, lengths, UTF-8, addresses,
  trailing bytes and oversized frames.
- Node tests prove advertisement to a ready peer, bounded deduplication, self/pinned
  filtering, invalid-candidate protocol rejection, and that a candidate creates no
  peer and no dial target.
- Existing pinned-peer, transport and reorg tests remain unchanged.
