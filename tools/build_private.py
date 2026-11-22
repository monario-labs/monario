"""Build release artifacts with local paths remapped; never launches the result.

Local build caches/logs can contain local paths. Only scanned release artifacts
are suitable for distribution; never distribute target/ wholesale.
"""
from pathlib import Path
import os
import shlex
import socket
import subprocess
import sys
import tempfile
import json
import shutil

root = Path(__file__).resolve().parents[1]
home = Path.home()
env = os.environ.copy()
if sys.argv[1:] not in ([], ["--test"], ["--node-tools"], ["--desktop"]):
    raise SystemExit("Usage: python tools/build_private.py [--test | --node-tools | --desktop]")
if env.get("RUSTFLAGS") or env.get("CARGO_ENCODED_RUSTFLAGS"):
    raise SystemExit("Unset external Rust flags before a private release build")
prefixes = [(root, "/monario"), (home, "/builder"), (Path(tempfile.gettempdir()), "/tmp")]
for variable, mapped in [("CARGO_HOME", "/cargo"), ("RUSTUP_HOME", "/rustup"), ("CARGO_TARGET_DIR", "/target")]:
    if env.get(variable):
        prefixes.append((Path(env[variable]).resolve(), mapped))
# Rust uses the last matching prefix, so put the most specific paths last.
prefixes.sort(key=lambda item: len(str(item[0])))
flags = [f"--remap-path-prefix={path}={mapped}" for path, mapped in prefixes]
flags += ["-C", "debuginfo=0", "-C", "strip=debuginfo"]
if sys.platform == "win32":
    flags += ["-C", "link-arg=/PDBALTPATH:monario.pdb"]
env["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join(flags)
if sys.platform == "win32":
    native_flags = " ".join(f'/pathmap:"{path}"={mapped}' for path, mapped in prefixes)
else:
    env["CC_SHELL_ESCAPED_FLAGS"] = "1"
    native_flags = shlex.join(f"-ffile-prefix-map={path}={mapped}" for path, mapped in prefixes)
env["CFLAGS"] = env["CXXFLAGS"] = native_flags
env["CARGO_PROFILE_RELEASE_DEBUG"] = "0"
if sys.argv[1:] in (["--node-tools"], ["--desktop"]):
    targets = ["-p", "monario-node", "-p", "monario-wallet-cli", "--bins"]
    if sys.argv[1:] == ["--desktop"]:
        targets.extend(["-p", "monario-wallet-gui"])
else:
    targets = ["--workspace", "--all-targets"]
process = subprocess.Popen(["cargo", "build", *targets, "--release", "--locked", "--offline", "--message-format=json"],
                           cwd=root, env=env, stdout=subprocess.PIPE, text=True)
artifacts = set()
test_executables = {}
for line in process.stdout:
    item = json.loads(line)
    if item.get("reason") == "compiler-message":
        sys.stderr.write(item["message"].get("rendered", ""))
    if item.get("reason") == "compiler-artifact" and not set(item["target"]["kind"]) & {"custom-build", "proc-macro"}:
        if item.get("executable"):
            executable = Path(item["executable"])
            artifacts.add(executable)
            if item["profile"]["test"]:
                test_executables[executable] = Path(item["manifest_path"]).parent
        for name in item["filenames"]:
            path = Path(name)
            if path.suffix in {".rlib", ".a", ".lib", ".dll", ".exe", ".so", ".dylib"}:
                artifacts.add(path)
if process.wait() != 0:
    raise SystemExit("Private release compilation failed")
if sys.argv[1:] == ["--test"]:
    subprocess.run(["cargo", "test", "--workspace", "--doc", "--release", "--locked", "--offline"],
                   cwd=root, env=env, check=True)
if sys.platform == "darwin":
    strip = ["/usr/bin/strip", "-S"]
else:
    objcopy = (Path(os.environ["ProgramFiles"]) / "LLVM/bin/llvm-objcopy.exe"
               if sys.platform == "win32" else (shutil.which("llvm-objcopy") or shutil.which("objcopy")))
    strip = [str(objcopy), "--strip-debug"] if objcopy else []
if not strip or not Path(strip[0]).is_file():
    raise SystemExit("An objcopy implementation is required for release debug-metadata stripping")
hostname = socket.gethostname()
hosted_runner = env.get("GITHUB_ACTIONS") == "true" and env.get("RUNNER_ENVIRONMENT") == "github-hosted"
private_values = {root.parent.name}
if hosted_runner:
    # Generic image labels can also occur in program strings. Scan the full
    # hosted paths below and keep explicit private terms strict on every host.
    private_values.add(str(home))
else:
    private_values.update((home.name, hostname, hostname.partition(".")[0]))
if sys.platform == "darwin" and not hosted_runner:
    for key in ("ComputerName", "LocalHostName", "HostName"):
        value = subprocess.run(["/usr/sbin/scutil", "--get", key], capture_output=True, text=True)
        if value.returncode == 0:
            private_values.add(value.stdout.strip())
elif sys.platform == "win32":
    private_values.update(env.get(key, "") for key in ("USERNAME", "COMPUTERNAME"))
if scan_file := env.get("MONARIO_PRIVATE_SCAN_FILE"):
    private_values.update(Path(scan_file).read_text(encoding="utf-8").splitlines())
for path, mapped in prefixes:
    # Linux's generic /tmp is already the intended normalized release prefix.
    # Forbidding the replacement itself rejects standard-library temp defaults.
    if str(path) == mapped:
        continue
    private_values.add(str(path))
needles = {
    variant.encode(encoding).lower()
    for value in private_values if value
    for variant in {value, value.replace("\\", "/"), value.replace("/", "\\")}
    for encoding in ("utf-8", "utf-16le", "utf-16be")
}
if not artifacts:
    raise SystemExit("No release artifacts to inspect")
if sys.argv[1:] == ["--desktop"]:
    target = (root / env.get("CARGO_TARGET_DIR", "target")).resolve()
    suffix = ".exe" if sys.platform == "win32" else ""
    scanned = {artifact.resolve() for artifact in artifacts}
    for name in ("monario-wallet-gui", "monario-wallet", "monario-node", "monario-launch"):
        if target / "release" / (name + suffix) not in scanned:
            raise SystemExit(f"Missing native release output for {name}")
for artifact in artifacts:
    data = artifact.read_bytes().lower()
    if any(needle in data for needle in needles):
        # Native MSVC object-name records can survive path remapping. Strip
        # offending archives only: metadata-only Rust rlibs need no stripping
        # and are not all supported by the installed LLVM object reader.
        if subprocess.run([*strip, str(artifact)]).returncode != 0:
            raise SystemExit(f"Could not remove local metadata from {artifact.name}")
        data = artifact.read_bytes().lower()
        if any(needle in data for needle in needles):
            raise SystemExit(f"Local identifying text found in {artifact.name}; do not distribute it")
print(f"Checked {len(artifacts)} release artifacts for local paths and identifying text")
if sys.argv[1:] == ["--test"]:
    # Execute the exact stripped/scanned binaries. A second cargo test here
    # could relink after archive timestamps change and bypass that scan.
    for executable, working_dir in sorted(test_executables.items()):
        subprocess.run([str(executable)], cwd=working_dir, env=env, check=True)
