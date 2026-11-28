# Read-only management RPC

`monario-node run|mine` can start an explicitly activated, token-authenticated,
**read-only** management listener. It is not a wallet API: it never signs, mines,
mutates chain state, changes peer trust or exports keys. It is also not a
replacement for the P2P transport.

## Activation

```text
monario-node run ... \
  --enable-rpc \
  --rpc-bind 127.0.0.1:9100 \
  --rpc-token-file rpc.token
```

- `--enable-rpc` is required; without it, `--rpc-bind`, `--rpc-token-file` and
  `--rpc-allow-remote` are rejected.
- The bind must be a numeric `IP:port` with a nonzero port. Unspecified and
  multicast addresses are rejected.
- Loopback is the default policy. A non-loopback bind additionally requires the
  explicit `--rpc-allow-remote` flag.
- A pre-stopped process does not bind the RPC listener. A failed bind aborts
  startup before any runtime activation.
- The listener is polled inside the node loop, so it shares the node's lifecycle
  and stop file/signal handling. No separate daemon or thread is created.

## Token file

`--rpc-token-file NAME.token` must name a file inside the identity directory.

- Exactly 64 lowercase hexadecimal characters, optionally followed by one `\n`
  or `\r\n`.
- All-zero tokens are rejected.
- The file must be a regular single-link file, not a symlink.
- On Unix it must have no group/other permissions (`0600` or stricter).
- The token is read once at startup and kept in memory. It is never printed or
  written to the status snapshot.

Generate a token with an independent CSPRNG, for example `openssl rand -hex 32`,
and protect the file with the same care as the node password.

## Transport and quotas

- The client connects, then sends exactly 32 raw token bytes.
- The server compares in constant time. A wrong token closes the connection with
  no diagnostic and no retry opportunity on that connection.
- After a successful handshake the server writes one `0x00` byte, then exchanges
  newline-delimited JSON requests and responses.
- At most 8 simultaneous connections.
- At most 16 KiB per request line; 64 KiB of queued response per connection.
- At most 256 requests per connection and a 30-second idle timeout.
- A protocol violation drops that connection. Listener failure stops the caller's
  runtime with a generic I/O error.

There is no TLS in this version. Use loopback, an SSH tunnel or another protected
transport for remote access. `--rpc-allow-remote` only disables the loopback
policy check; it does not add transport encryption.

## Methods

Requests are objects with a scalar `id`, a `method` and optional `params`.
Unknown methods, malformed JSON, invalid parameters and missing objects return a
generic error.

| Method | Params | Result |
|---|---|---|
| `status` | none | profile, tip, height, peers, stopped, mempool count, candidate count, `read_only: true` |
| `block` | `{"id":"<64hex>"}` | height, parent (or null), commitment |
| `block-transactions` | `{"id":"<64hex>","network":"test"}` | authenticated block's transaction count and first 24 effects IDs in block order, plus the first eight transparent coinbase outputs |
| `transaction` | `{"id":"<64hex>"}` | current branch block, height and depth for the transaction-effects ID |
| `mempool` | none | admitted transaction count |
| `peers` | none | connected peer count |
| `candidates` | none | bounded untrusted discovery candidates |
| `ping` | none | `{"pong":true}` |

Example:

```text
{"id":1,"method":"status"}
{"id":2,"method":"block","params":{"id":"<64 lowercase hex>"}}
```

Responses:

```text
{"id":1,"ok":true,"result":{...}}
{"id":2,"ok":false,"error":"not-found"}
```

`transaction` reports a current validated inclusion only. It is not a finality,
mempool-membership or relay proof. Candidate addresses and keys are untrusted
peer claims and are never dialed automatically.

`block-transactions` reads one authenticated, retained block. The first ID is
the coinbase. Public output values are decimal atom strings. The supplied
`main`, `test` or `regtest` value controls address encoding. Outputs with an
unrecognized script return a null address. Callers walking the current branch
should follow parent links from the validated tip.

## Tests

- Strict token parsing, all-zero rejection and constant-time comparison.
- Bind policy: loopback by default, explicit remote opt-in, rejected unspecified /
  multicast / port-zero addresses.
- Handler tests for status, ping, mempool, peers, candidates, unknown methods,
  malformed JSON, invalid IDs/params, not-found and oversized requests.
- CLI parse tests for missing/invalid RPC flags and for `check` rejecting them.
- A pre-stopped `mine` test occupies an RPC port and proves no listener is bound.

No test binds a listener or opens a live connection. Remote RPC is implemented as
code and explicit activation, not exercised against a live network in this
repository.
