# Fix F5: Unsalted MD5 password storage

Branch: `fix/f5-password-hashing`  |  Severity: **Medium**  |  CWE-328  |  A02:2021 Cryptographic Failures

## Summary
Passwords are stored as unsalted MD5, a fast hash that is reversed with rainbow tables or GPU cracking.

## Root cause
General-purpose hash used where a slow, salted password hash is required.

## Change
password_hash() with Argon2id (bcrypt fallback). Existing hashes need a rollout plan, see docs/REMEDIATION-NOTES.md.

Files: `src/PasswordHasher.php`

## Verification
- `python3 tests/lab.py --app app --only F5` before: **VULNERABLE** (stored hash format: 32-hex (unsalted MD5))
- same command with this patch applied: **MITIGATED** (stored hash format: argon2id (salted, memory-hard))
- `python3 tests/patch_matrix.py` confirms this patch closes the finding on its own
- SAST: payloop.php.weak-password-hash

## Detection
Rules: none. Remaining blind spots: No runtime signal. Compensating controls: database access monitoring and credential-stuffing detection (110111).

## Risk and rollout
Behavioural change: see Change. Rollback: revert this PR; no schema change is required.

## AI-assistance note
AI will often suggest bcrypt; accept it if Argon2id is unavailable, but make sure verification uses password_verify() and that migration of existing hashes is addressed.
