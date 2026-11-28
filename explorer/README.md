# Monario testnet explorer

The explorer shows the validated tip and up to 24 recent blocks. It filters that
window by height, block hash or transaction ID. Each block shows its parent,
commitment, transaction count, its first 24 effects IDs, and its first eight
transparent coinbase outputs. Shielded output amounts and recipients are
private. The browser fetches a public JSON snapshot from the static host.

## Data source

Provision a dedicated node identity and database using the verified testnet
release, with the matching manifest and height-zero root. Pin the public key of
the seed from the verified signed peer list. Set the identity's peer-list
`listen` value to `off`. Use `monario-node run --enable-network` with the
usual identity arguments and the following additional options.

```sh
--enable-rpc --rpc-bind 127.0.0.1:9100 --rpc-token-file explorer.token
```

Generate a distinct 32-byte credential encoded as lowercase hexadecimal and
store it under the replica's identity directory with mode 0600. Keep the
credential, password frame, binary and identity directory outside the web root.
The replica needs outbound peer connectivity. It has no mining or wallet flags.

Use a node that supports the `block-transactions` management method. The Compose
replica runs the node and publisher in the same private network
namespace. To run the publisher separately during a check, use the replica's
network namespace and set the profile from the verified release.

```sh
python3 -B publish.py --port 9100 --profile "$MONARIO_TESTNET_PROFILE" \
  --token-file "$REPLICA_IDENTITY/explorer.token" \
  --output "$EXPLORER_SNAPSHOT_DIR/snapshot.json"
```

Each run confirms the profile and reads the tip again after walking the recent
chain. A changing tip or an unavailable replica leaves the last snapshot intact.
The UI shows its age and marks snapshots over two minutes old.

## Serving

Use `compose.yaml` in a dedicated Monario Coolify resource. Set the
`MONARIO_EXPLORER_ROOT`, `MONARIO_EXPLORER_UID` and `MONARIO_EXPLORER_GID`
values for the host staging directory and its unprivileged owner. Put the
static assets in `public/`, the validated node database and manifest in
`private/identity/`, and the verified executable, identity-create receipt,
and private stdin frame in `private/` as `monario-node`, `receipt.json`, and
`credential.frame`. The replica writes to `snapshots/`. Nginx only mounts
`public/`, `snapshots/` and `nginx.conf`, all read-only.
Verify that loopback port 18755 is free, then use it as the upstream for
`explorer.monario.org` in the existing host Caddy once DNS is set. Keep the node
RPC loopback only and out of Caddy.
