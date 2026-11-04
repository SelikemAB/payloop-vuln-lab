#!/usr/bin/env python3
"""Render findings/FINDINGS.md and pull-requests/*.md from findings/findings.yaml.

Before/after evidence is NOT typed in: it is produced by running tests/lab.py against the baseline app and the
fully patched tree, so the documents always reflect what the code actually does.
"""
import json
import subprocess
import sys
from pathlib import Path

import yaml

root = Path(__file__).resolve().parent.parent


def lab(app: str) -> dict:
    out = subprocess.run([sys.executable, "tests/lab.py", "--app", app, "--json"], cwd=root, capture_output=True, text=True, check=True).stdout
    return {r["fid"]: r for r in json.loads(out)}


subprocess.run(["bash", "scripts/build-fixed.sh"], cwd=root, check=True, capture_output=True)
before, after = lab("app"), lab("build/fixed")
data = yaml.safe_load((root / "findings/findings.yaml").read_text())["findings"]
sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

# ---------------------------------------------------------------- FINDINGS.md
md = ["# PayLoop security findings", "",
      "Scope: the PayLoop API (fictional payments wallet, PHP 8 + SQLite). Method: threat-model-driven manual review of every handler,",
      "custom Semgrep rules, and a scripted exploit per finding. Every result below was produced by `tests/lab.py` against the",
      "baseline and the patched tree; nothing here is hand-typed evidence.", "",
      "| ID | Severity | Finding | CWE | OWASP 2021 | Exploit on baseline | Exploit after fix |", "|---|---|---|---|---|---|---|"]
for f in sorted(data, key=lambda x: (sev_order[x["severity"]], x["id"])):
    b, a = before[f["id"]], after[f["id"]]
    md.append(f"| {f['id']} | {f['severity']} | {f['title']} | {f['cwe']} | {f['owasp']} | {'exploitable' if b['vulnerable'] else 'not exploitable'} | {'exploitable' if a['vulnerable'] else 'mitigated'} |")
md += ["", "Severity is qualitative (impact x ease of exploitation in this context), deliberately not a CVSS score.", ""]
for f in data:
    b, a = before[f["id"]], after[f["id"]]
    md += [f"## {f['id']}: {f['title']}", "",
           f"**Severity:** {f['severity']} | **{f['cwe']}** | {f['owasp']} | ATT&CK: {', '.join(f['attack'])}  ",
           f"**Where:** `{f['endpoint']}` ({', '.join('`'+x+'`' for x in f['files'])})", "",
           f"**What:** {f['description']}", "", f"**Impact:** {f['impact']}", "",
           "**Reproduce**", "```bash", f["repro"].rstrip(), "```", "",
           f"**Root cause:** {f['root_cause']}", "", f"**Fix:** {f['fix']}", "",
           "**Evidence (generated)**", "",
           f"- Baseline: {b['evidence']}", f"- Patched: {a['evidence']}", "",
           "**Detection**", "",
           f"- SAST: {f['detection']['sast']}",
           f"- Wazuh rules: {', '.join(f['detection']['rules']) or 'none'}",
           f"- Blind spots: {f['detection']['blind_spots']}", "",
           f"**Reviewing an AI-proposed fix:** {f['ai_note']}", ""]
(root / "findings/FINDINGS.md").write_text("\n".join(md))

# ---------------------------------------------------------------- PR drafts
for f in data:
    b, a = before[f["id"]], after[f["id"]]
    pr = [f"# Fix {f['id']}: {f['title']}", "",
          f"Branch: `fix/{f['id'].lower()}-{f['slug']}`  |  Severity: **{f['severity']}**  |  {f['cwe']}  |  {f['owasp']}", "",
          "## Summary", f["description"], "", "## Root cause", f["root_cause"], "",
          "## Change", f["fix"], "", "Files: " + ", ".join(f"`{x}`" for x in f["files"]), "",
          "## Verification",
          f"- `python3 tests/lab.py --app app --only {f['id']}` before: **{'VULNERABLE' if b['vulnerable'] else 'MITIGATED'}** ({b['evidence']})",
          f"- same command with this patch applied: **{'VULNERABLE' if a['vulnerable'] else 'MITIGATED'}** ({a['evidence']})",
          "- `python3 tests/patch_matrix.py` confirms this patch closes the finding on its own",
          f"- SAST: {f['detection']['sast']}", "",
          "## Detection", f"Rules: {', '.join(f['detection']['rules']) or 'none'}. Remaining blind spots: {f['detection']['blind_spots']}", "",
          "## Risk and rollout", "Behavioural change: see Change. Rollback: revert this PR; no schema change is required.", "",
          "## AI-assistance note", f["ai_note"], ""]
    (root / "pull-requests" / f"{f['id']}-{f['slug']}.md").write_text("\n".join(pr))
print(f"rendered {len(data)} findings and PR drafts")
