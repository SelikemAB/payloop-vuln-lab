#!/usr/bin/env python3
"""Apply each patch ALONE to a fresh copy of the baseline and prove it closes exactly its finding.

Exit 0 only if, for every Fn: with patches/Fn-*.patch applied the Fn exploit is MITIGATED.
"""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import lab  # noqa: E402

root = Path(__file__).resolve().parent.parent
ok = True
print(f"{'PATCH':<26} {'EXPLOIT AFTER PATCH':<20}")
for patch in sorted((root / "patches").glob("F*.patch")):
    fid = patch.name.split("-")[0]
    tmp = Path(tempfile.mkdtemp(prefix="patchmx-"))
    try:
        shutil.copytree(root / "app", tmp / "app")
        subprocess.run(["patch", "-p1", "-d", str(tmp / "app"), "--quiet"], stdin=patch.open(), check=True)
        res = lab.run(tmp / "app", [fid])[0]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    status = "VULNERABLE (patch insufficient)" if res.vulnerable else "MITIGATED"
    ok &= not res.vulnerable
    print(f"{patch.name:<26} {status}")
sys.exit(0 if ok else 1)
