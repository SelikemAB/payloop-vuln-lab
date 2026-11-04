#!/usr/bin/env python3
"""Assert a Semgrep JSON run scanned at least one file and found nothing.

Used by `make sast` for the fixed tree. Semgrep's built-in ignore list excludes any
`build/` directory, so pointing it straight at build/fixed scans zero files and
"passes" regardless of the code. This check fails loudly when nothing was scanned,
so the step can actually fail if the fixed tree ever regresses.
"""
import json
import sys


def main(path):
    with open(path) as f:
        data = json.load(f)
    scanned = data.get("paths", {}).get("scanned", [])
    findings = data.get("results", [])
    if not scanned:
        print("sast FAIL: semgrep scanned 0 files on the fixed tree (nothing proven)")
        return 1
    if findings:
        print(f"sast FAIL: {len(findings)} finding(s) on the fixed tree:")
        for r in findings:
            loc = r.get("path", "?")
            line = r.get("start", {}).get("line", "?")
            rule = r.get("check_id", "?")
            print(f"  {loc}:{line}  {rule}")
        return 1
    print(f"sast ok: fixed tree scanned {len(scanned)} files, 0 findings")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: check_sast_clean.py <semgrep-json>")
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
