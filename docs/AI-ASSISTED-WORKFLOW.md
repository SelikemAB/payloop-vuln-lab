# Using AI to find and fix vulnerabilities, without trusting it blindly

Hiring managers now expect you to use AI. What they test is whether you can verify it. This is the loop to follow and narrate.

1. **Scope the model's job.** Give it one handler at a time plus the access-control matrix from the threat model. Ask for findings with CWE, exploit steps and a fix, and ask it to list what it could not assess.
2. **Reproduce before believing.** For every claimed finding write the exploit first (`tests/lab.py` pattern). A finding without a failing exploit stays "unconfirmed".
3. **Ask for the fix and the bypasses.** Prompt: "Propose a minimal patch. Then list five ways an attacker could still bypass it." Turn each bypass into a test (this is how `tests/ssrf_guard_test.php` was shaped; it caught an IPv4-mapped IPv6 hole).
4. **Verify mechanically.** Patch applies cleanly, exploit now fails, other exploits unaffected (`tests/patch_matrix.py`), Semgrep quiet, no new SQL/regex/crypto invented by the model without review.
5. **Review like a human PR.** Read the diff for scope creep, swallowed errors, logging of secrets, and "fixes" that only move the bug (for example stripping `../` instead of validating the path).
6. **Record it.** Keep the prompt, the model's claim, your verdict and the evidence next to the PR (`pull-requests/*.md` has an AI-assistance note per finding).

## Prompt templates
```
You are reviewing one PHP handler for a payments API. Context: <access-control matrix>.
List vulnerabilities with CWE, a one-line exploit, and severity. Then list assumptions you made and what you could not check.
```
```
Here is the exploit that proves finding F4 and the current patch. List ways the patch can still be bypassed
(redirects, DNS rebinding, encoding tricks, IPv6, parser differentials). Output each as a testable case.
```

## What to say in the interview
"I use AI to widen coverage and draft fixes, and I never accept a finding or a patch without an exploit that fails before and passes after. It was weakest on business logic: nothing flagged negative transfer amounts until I derived them from the threat model."

Only claim in an interview what you actually did. Add your own run log here (model used, what it got right and wrong). A real log beats a generic one.
