# Fix F9: Stack traces returned to clients

Branch: `fix/f9-error-disclosure`  |  Severity: **Low**  |  CWE-209  |  A05:2021 Security Misconfiguration

## Summary
Unhandled exceptions return the message, file path, line number and full stack trace to the caller.

## Root cause
Debug-style error output left enabled in the request path.

## Change
Client sees a generic error and a request id. Details are logged as an app_error event keyed by the same id. Malformed JSON maps to 400.

Files: `public/index.php`

## Verification
- `python3 tests/lab.py --app app --only F9` before: **VULNERABLE** (malformed JSON -> HTTP 500; stack trace / file paths in body: True)
- same command with this patch applied: **MITIGATED** (malformed JSON -> HTTP 400; stack trace / file paths in body: False)
- `python3 tests/patch_matrix.py` confirms this patch closes the finding on its own
- SAST: payloop.php.exception-detail-to-client

## Detection
Rules: 110123, 110124, 110180. Remaining blind spots: None significant; error bursts are a reliable fuzzing signal.

## Risk and rollout
Behavioural change: see Change. Rollback: revert this PR; no schema change is required.

## AI-assistance note
Low severity, but cheap to fix and it multiplies the value of every other bug. Good example for explaining severity versus exploitability.
