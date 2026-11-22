"""Verify the pinned RandomX source manifest using Python's standard library."""
from pathlib import Path
import hashlib
import json

root = Path(__file__).resolve().parents[1]
vendor = root / "vendor/randomx"
expected = json.loads((root / "vendor/randomx-sha256.json").read_text())
actual = {p.relative_to(vendor).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
          for p in sorted(vendor.rglob("*")) if p.is_file()}
if actual != expected:
    raise SystemExit("RandomX source manifest mismatch")
print(f"Verified {len(actual)} pinned RandomX source files")
