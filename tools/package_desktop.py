"""Build and package the native Monario testnet desktop preview."""
from hashlib import sha256
from io import BytesIO
from pathlib import Path
import gzip
import json
import os
import plistlib
import re
import subprocess
import sys
import tarfile
import tempfile
import zipfile


def verify_package(read, bin_dir, platform):
    """Run offline checks against the exact archived binaries and configuration."""
    def run(args, cwd):
        result = subprocess.run(args, cwd=cwd, capture_output=True, check=False, timeout=30)
        if result.returncode != 0:
            raise SystemExit("Desktop package smoke check failed")
        return result.stdout

    with tempfile.TemporaryDirectory(prefix="monario-check-") as directory:
        root = Path(directory)
        tools = []
        suffix = ".exe" if platform.startswith("windows") else ""
        for tool in ("monario-wallet-gui", "monario-wallet", "monario-node", "monario-launch"):
            name = tool + suffix
            path = root / name
            path.write_bytes(read(bin_dir + name))
            path.chmod(0o755)
            if platform.startswith("macos"):
                arch = platform.removeprefix("macos-")
                if run(["/usr/bin/lipo", "-archs", path], root).strip() != arch.encode("ascii"):
                    raise SystemExit(f"Unexpected Mach-O architecture for {name}")
            tools.append(path)
        _, wallet, node, launch = tools
        for name in ("root.json", "node.json", "root-commitment.txt", "bootstrap.json"):
            (root / name).write_bytes(read(f"testnet/{name}"))
        root_check = json.loads(run([launch, "root-check", "root.json", "node.json"], root))
        manifest_check = json.loads(run([launch, "check", "node.json", "--strict"], root))
        bootstrap = json.loads(run([launch, "bootstrap-check", "testnet", "--bundled", "node.json"], root))
        archived = json.loads(run([launch, "bootstrap-check", "testnet", "bootstrap.json", "node.json"], root))
        commitment = sha256((root / "root-commitment.txt").read_bytes()).hexdigest()
        if (root_check.get("manifest_checked") is not True
                or root_check.get("root_commitment") != commitment
                or root_check.get("manifest_profile") != manifest_check.get("profile")
                or bootstrap.get("profile") != manifest_check.get("profile")
                or archived != bootstrap
                or root_check.get("network_started") is not False
                or manifest_check.get("network_started") is not False
                or bootstrap.get("network_started") is not False):
            raise SystemExit("Desktop package testnet configuration failed verification")
        run([wallet, "--version"], root)
        run([node, "--version"], root)


def main():
    root = Path(__file__).resolve().parents[1]
    host = subprocess.check_output(["rustc", "-vV"], text=True).split("host: ")[1].splitlines()[0]
    platform = {
        "x86_64-pc-windows-msvc": "windows-x86_64",
        "x86_64-unknown-linux-gnu": "linux-x86_64",
        "x86_64-apple-darwin": "macos-x86_64",
        "aarch64-apple-darwin": "macos-arm64",
    }.get(host)
    if not platform or os.environ.get("CARGO_BUILD_TARGET"):
        raise SystemExit("Desktop packaging requires a supported native target")
    target = Path(os.environ.get("CARGO_TARGET_DIR", root / "target"))
    target = (root / target).resolve()
    subprocess.run([sys.executable, "tools/build_private.py", "--desktop"], cwd=root, check=True)

    mac = platform.startswith("macos")
    windows = platform.startswith("windows")
    suffix = ".exe" if windows else ""
    bin_dir = "Monario Wallet.app/Contents/MacOS/" if mac else ""
    files = {}
    for name in ("monario-wallet-gui", "monario-wallet", "monario-node", "monario-launch"):
        executable = name + suffix
        path = target / "release" / executable
        if platform.startswith("linux"):
            info = subprocess.check_output(["readelf", "--version-info", "--wide", str(path)], text=True)
            versions = [(int(major), int(minor)) for major, minor in re.findall(r"\bGLIBC_(\d+)\.(\d+)\b", info)]
            if not versions or max(versions) > (2, 39):
                raise SystemExit(f"{executable} requires an unsupported glibc ABI; build on Ubuntu 24.04")
        files[bin_dir + executable] = (path.read_bytes(), 0o755)
    if mac:
        info = dict(CFBundleExecutable="monario-wallet-gui", CFBundleName="Monario Wallet",
                    CFBundleIdentifier="org.monario.wallet", CFBundlePackageType="APPL",
                    CFBundleVersion="1", CFBundleShortVersionString="0.1.0",
                    NSHighResolutionCapable=True)
        files["Monario Wallet.app/Contents/Info.plist"] = (plistlib.dumps(info), 0o644)
    for name in ("README.md", "node.json", "root.json", "root-commitment.txt", "peers.json"):
        files[f"testnet/{name}"] = ((root / "launch/testnet" / name).read_bytes(), 0o644)
    descriptor = (root / "launch/bootstrap/testnet.json").read_bytes()
    if json.loads(descriptor)["fallback"] != json.loads(files["testnet/peers.json"][0]):
        raise SystemExit("Published peer envelope differs from the bundled testnet fallback")
    files["testnet/bootstrap.json"] = (descriptor, 0o644)
    files["README.md"] = ((root / "docs/desktop-release.md").read_bytes(), 0o644)
    checksums = "".join(f"{sha256(data).hexdigest()}  {name}\n" for name, (data, _) in sorted(files.items()))
    files["SHA256SUMS"] = (checksums.encode("ascii"), 0o644)

    filename = f"monario-testnet-desktop-{platform}"
    archive = target / (filename + (".zip" if windows or mac else ".tar.gz"))
    pending = archive.with_suffix(archive.suffix + ".new")
    paths = sorted(files)
    if windows or mac:
        with zipfile.ZipFile(pending, "w", compression=zipfile.ZIP_DEFLATED) as output:
            for path in paths:
                data, mode = files[path]
                entry = zipfile.ZipInfo(path)
                entry.create_system = 3
                entry.external_attr = (0o100000 | mode) << 16
                output.writestr(entry, data, compress_type=zipfile.ZIP_DEFLATED)
        with zipfile.ZipFile(pending) as output:
            if output.namelist() != paths or any(output.read(path) != files[path][0] for path in paths):
                raise SystemExit("Desktop archive verification failed")
            verify_package(output.read, bin_dir, platform)
    else:
        with pending.open("wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as output:
                for path in paths:
                    data, mode = files[path]
                    entry = tarfile.TarInfo(path)
                    entry.size, entry.mode = len(data), mode
                    output.addfile(entry, BytesIO(data))
        with tarfile.open(pending) as output:
            if output.getnames() != paths or any(output.extractfile(path).read() != files[path][0] for path in paths):
                raise SystemExit("Desktop archive verification failed")
            verify_package(lambda path: output.extractfile(path).read(), bin_dir, platform)
    pending.replace(archive)
    print(f"{sha256(archive.read_bytes()).hexdigest()}  {archive.name}")


if __name__ == "__main__":
    main()
