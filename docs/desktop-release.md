# Monario desktop testnet preview

Extract the entire archive. Open `monario-wallet-gui.exe` on Windows,
`monario-wallet-gui` on Linux, or `Monario Wallet.app` on macOS. Keep the node,
wallet and launch helper binaries with the GUI. Linux needs a desktop session
with OpenGL and either X11 or Wayland support.

The top bar selects Testnet, Mainnet or Regtest. New installations default to
Testnet. Switching locks the wallet and loads a separate set of saved wallet,
node, chain and miner settings. Stop the node or miner and finish pending wallet
jobs before switching. Each network needs its own wallet and validated chain.
This preview includes only the testnet manifest and root record.

The Mining screen supports solo CPU mining and authenticated Monario pools.
Set up and sync a compatible node first. Solo mining requires that node and a
transparent payout address matching the active network. Custom pool mining takes
the pool host or IP, port, and a credential from the operator that ties your
authenticated identity to that pool; register your payout address with the
operator. No pool preset, credentials, or working pool are bundled. Mining starts
only after an explicit action.

## Build and verify a native package

Use Rust 1.96 or later, Python 3, CMake, and a native C/C++ toolchain. Windows
uses Visual Studio 2022 Build Tools and LLVM objcopy. Build Linux releases on
Ubuntu 24.04 or a compatible baseline with X11, Wayland, OpenGL, binutils, and
OpenSSL development libraries (`libssl-dev` on Ubuntu). The Linux node uses
the system OpenSSL runtime for HTTPS seed discovery.
The packager rejects executables that require a glibc version newer than 2.39.
macOS uses Xcode Command Line Tools and a separate native build on Intel and
Apple silicon.

```sh
cargo fetch --locked
python3 tools/package_desktop.py
```

On Windows, use `python` if `python3` is unavailable. The packager runs the
locked offline build and artifact scan, then includes checksums in the archive.
Use `MONARIO_PRIVATE_SCAN_FILE` for additional private identifiers from a
separate source or build host. Keep build logs and caches out of distribution.

Verify launch/profile checks and the desktop on each platform before publishing.
For macOS, run the commands below once on a native Intel Mac and once on Apple
silicon. The packager checks the exact archived binaries with `lipo` and runs
the packaged helpers' offline launch and version checks before producing the ZIP.

```sh
cargo fetch --locked
sh tools/package_macos.sh
```

The mining control tests construct and validate arguments only. The RandomX
vectors evaluate fixed inputs without starting a miner.

### GitHub Actions

Put the clean source bundle in a private repository with Actions enabled. The
`macOS testnet wallet` workflow must be present on the default branch before it
can be started manually from the Actions tab. Its matrix verifies both native
architectures. Download the architecture ZIP and `SHA256SUMS` from the successful
run's artifacts. The workflow uploads only those two files for each architecture.

For public macOS distribution, sign the executable helpers and app with
Developer ID, notarize it, then verify and checksum the signed package. Native
build archives produced by this script are unsigned preview artifacts.
