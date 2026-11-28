"""Run the dedicated validating peer and refresh the public explorer snapshot."""

import json
import re
import signal
import subprocess
import sys
from pathlib import Path
from threading import Event


private = Path("/replica")
with (private / "receipt.json").open(encoding="utf-8") as stream:
    receipt = json.load(stream)
profile = receipt["profile"]
public_key = receipt["public_key"]
revision = receipt["revision"]
if not all(re.fullmatch(r"[0-9a-f]{64}", value) for value in (profile, public_key)):
    raise ValueError("invalid replica receipt")
if type(revision) is not int or not 0 <= revision < 2**64:
    raise ValueError("invalid replica revision")

stop = Event()
for notice in (signal.SIGINT, signal.SIGTERM):
    signal.signal(notice, lambda signum, frame: stop.set())

with (private / "credential.frame").open("rb") as credential:
    peer = subprocess.Popen([
        "/replica/monario-node", "run", "--directory", "/replica/identity",
        "--profile", profile, "--public-key", public_key, "--revision", str(revision),
        "--password-stdin", "--manifest", "node.json", "--enable-network",
        "--enable-rpc", "--rpc-bind", "127.0.0.1:9100", "--rpc-token-file", "explorer.token",
    ], stdin=credential, stdout=subprocess.DEVNULL)

try:
    while not stop.is_set() and peer.poll() is None:
        try:
            subprocess.run([
                sys.executable, "-B", "/opt/explorer/publish.py", "--port", "9100",
                "--profile", profile, "--token-file", "/replica/identity/explorer.token",
                "--output", "/snapshots/snapshot.json",
            ], timeout=12, check=False)
        except subprocess.TimeoutExpired:
            print("Explorer snapshot timed out.", file=sys.stderr)
        for _ in range(30):
            if stop.wait(1) or peer.poll() is not None:
                break
finally:
    if peer.poll() is None:
        peer.terminate()
        try:
            peer.wait(timeout=20)
        except subprocess.TimeoutExpired:
            peer.kill()
            peer.wait()

sys.exit(0 if stop.is_set() and peer.returncode == 0 else 1)
