# Fix F3: Path traversal in receipt download

Branch: `fix/f3-path-traversal`  |  Severity: **High**  |  CWE-22  |  A01:2021 Broken Access Control

## Summary
The file parameter is appended to the receipts directory, so ../ sequences read files elsewhere on disk.

## Root cause
No validation of a user-controlled path segment.

## Change
Strict allow-list regex on the file name, then realpath() containment check against the receipts directory. Blocked attempts are logged.

Files: `src/Handlers/ReceiptHandler.php`

## Verification
- `python3 tests/lab.py --app app --only F3` before: **VULNERABLE** (file=../internal/notes.txt -> HTTP 200, internal file read: True)
- same command with this patch applied: **MITIGATED** (file=../internal/notes.txt -> HTTP 404, internal file read: False)
- `python3 tests/patch_matrix.py` confirms this patch closes the finding on its own
- SAST: payloop.php.taint-to-file-path

## Detection
Rules: 110121, 110122. Remaining blind spots: Double-encoded sequences can slip past the request-line regex; the app-level path_blocked event (110122) covers them once the fix is in.

## Risk and rollout
Behavioural change: see Change. Rollback: revert this PR; no schema change is required.

## AI-assistance note
Check the AI did not just strip '../' (bypassable with ....// or encoding); the allow-list plus realpath combination is the robust pattern.
