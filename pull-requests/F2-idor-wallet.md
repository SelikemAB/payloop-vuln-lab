# Fix F2: IDOR on wallet lookup

Branch: `fix/f2-idor-wallet`  |  Severity: **High**  |  CWE-639  |  A01:2021 Broken Access Control

## Summary
The endpoint authenticates the caller but never checks that the wallet belongs to them. Changing id returns any customer's balance and owner.

## Root cause
Authentication without object-level authorisation.

## Change
Reuse the shared Wallets::assertAccess() guard (owner or admin). Non-owners get 404 so existence is not revealed, and the denial is logged.

Files: `src/Handlers/WalletHandler.php`

## Verification
- `python3 tests/lab.py --app app --only F2` before: **VULNERABLE** (alice reads wallet 2 -> HTTP 200, owner=bob, balance=50000)
- same command with this patch applied: **MITIGATED** (alice reads wallet 2 -> HTTP 404)
- `python3 tests/patch_matrix.py` confirms this patch closes the finding on its own
- SAST: none (logic flaw)

## Detection
Rules: 110140, 110141. Remaining blind spots: A single targeted read of a guessable id looks like normal traffic; detection relies on enumeration volume. Prevention is the real control.

## Risk and rollout
Behavioural change: see Change. Rollback: revert this PR; no schema change is required.

## AI-assistance note
SAST and many AI reviewers miss this class because the code is 'correct' but incomplete. It was found by reading every handler against the access-control matrix in the threat model.
