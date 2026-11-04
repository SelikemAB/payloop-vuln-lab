# Fix F8: Transfer integrity (negative amount, overdraft, replay)

Branch: `fix/f8-transfer-integrity`  |  Severity: **High**  |  CWE-840  |  A04:2021 Insecure Design

## Summary
Amounts are not validated (negative values reverse the direction of the transfer), balances can go below zero, and the Idempotency-Key header is ignored so a retried request pays twice.

## Root cause
Business rules not enforced server-side; no atomicity; client-controlled retries unhandled.

## Change
Integer-only, bounded, positive amounts; distinct wallets; mandatory idempotency key with a unique index; BEGIN IMMEDIATE transaction around check and update; insufficient funds rejected; replay returns the original result.

Files: `src/Handlers/TransferHandler.php`

## Verification
- `python3 tests/lab.py --app app --only F8` before: **VULNERABLE** (negative amount -> HTTP 201; overdraft -> HTTP 201; same key sent twice moved GHS 20.00 (expected 10.00))
- same command with this patch applied: **MITIGATED** (negative amount -> HTTP 422; overdraft -> HTTP 422; same key sent twice moved GHS 10.00 (expected 10.00))
- `python3 tests/patch_matrix.py` confirms this patch closes the finding on its own
- SAST: none (business logic)

## Detection
Rules: 110150, 110153, 110151, 110152. Remaining blind spots: Detection after the fact only; money has already moved when 110150 fires on the baseline. Prevention and reconciliation are the primary controls.

## Risk and rollout
Behavioural change: see Change. Rollback: revert this PR; no schema change is required.

## AI-assistance note
This is where AI review is weakest: no scanner has a rule for 'negative amount'. Derive the checks from the threat model (financial theft), then write the exploit test first.
