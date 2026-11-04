# Fix F7: No login throttling and user enumeration

Branch: `fix/f7-login-throttling`  |  Severity: **Medium**  |  CWE-307  |  A07:2021 Identification and Authentication Failures

## Summary
Unlimited password guesses are accepted, and the error text differs for unknown users versus wrong passwords.

## Root cause
No attempt accounting and verbose authentication errors.

## Change
Failure counters per username (5 / 5 min) and per source IP (20 / 5 min) stored in the database, HTTP 429 with Retry-After, one generic error for every failure, dummy hash verification so unknown users take similar time.

Files: `src/Handlers/LoginHandler.php`, `src/RateLimiter.php (new)`

## Verification
- `python3 tests/lab.py --app app --only F7` before: **VULNERABLE** (12 wrong passwords -> [401] (429 seen: False); enumeration via error text: True)
- same command with this patch applied: **MITIGATED** (12 wrong passwords -> [401, 429] (429 seen: True); enumeration via error text: False)
- `python3 tests/patch_matrix.py` confirms this patch closes the finding on its own
- SAST: none (missing control)

## Detection
Rules: 110101, 110111, 110112, 110103, 110113. Remaining blind spots: Low-and-slow attacks below the thresholds and botnet-distributed guessing need longer-window behavioural analytics.

## Risk and rollout
Behavioural change: see Change. Rollback: revert this PR; no schema change is required.

## AI-assistance note
Check the limiter keys on both identity and source, otherwise spraying across usernames bypasses it. Decide what source IP means behind a proxy (trusted proxy only).
