# Fix F6: Hard-coded token signing secret

Branch: `fix/f6-hardcoded-secret`  |  Severity: **Critical**  |  CWE-798  |  A02:2021 Cryptographic Failures

## Summary
Session tokens are HMAC-signed with a secret committed to source. Anyone with repository access can mint a token for any user, including admin.

## Root cause
Secret material stored in source control; token comparison not constant-time.

## Change
Secret read from PAYLOOP_TOKEN_SECRET (min 32 chars), application fails closed if absent; hash_equals() for the signature check. Existing secret must be treated as burned and rotated.

Files: `src/Config.php`, `src/Auth.php`

## Verification
- `python3 tests/lab.py --app app --only F6` before: **VULNERABLE** (admin token forged with the committed secret -> HTTP 200, 5 users listed)
- same command with this patch applied: **MITIGATED** (admin token forged with the committed secret -> HTTP 401)
- `python3 tests/patch_matrix.py` confirms this patch closes the finding on its own
- SAST: payloop.php.hardcoded-secret, payloop.php.non-constant-time-mac-compare

## Detection
Rules: 110160, 110161, 110170. Remaining blind spots: A token forged with the real secret is cryptographically valid, so no 'invalid token' event is produced. Only behavioural signals (110170 admin access from a new source) remain. This is why the secret must never leak.

## Risk and rollout
Behavioural change: see Change. Rollback: revert this PR; no schema change is required.

## AI-assistance note
Fixing the code does not undo the leak: the old value stays in git history. Rotation and history scrubbing are part of the remediation, not optional.
