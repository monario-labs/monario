#!/bin/sh
# Run offline qualification on each native Mac before writing its preview ZIP.
set -eu
cd "$(dirname "$0")/.."

if [ "$(uname -s)" != Darwin ]; then
    echo "macOS packaging requires a native Mac" >&2
    exit 1
fi
if [ "$(/usr/sbin/sysctl -in sysctl.proc_translated 2>/dev/null || true)" = 1 ]; then
    echo "Use native tools outside Rosetta to qualify this Mac" >&2
    exit 1
fi
case "$(uname -m)" in
    arm64) expected_host=aarch64-apple-darwin ;;
    x86_64) expected_host=x86_64-apple-darwin ;;
    *) echo "Unsupported macOS architecture" >&2; exit 1 ;;
esac
if ! rustc -vV | grep -Fxq "host: $expected_host"; then
    echo "Install the Rust toolchain for this Mac's native architecture" >&2
    exit 1
fi

python3 tools/verify_vendor.py
cargo test --locked --offline -p monario-wallet-gui --lib
for test in pool_mode_is_explicit_bounded_and_has_no_silent_fallback \
            pre_stopped_local_run_spawns_no_worker \
            pre_stopped_pool_binds_no_listener_and_construction_opens_nothing; do
    cargo test --locked --offline --release -p monario-node --lib "$test"
done
cargo test --locked --offline --release -p monario-randomx --test vectors
python3 tools/package_desktop.py
