# Fix F1: SQL injection in statement search

Branch: `fix/f1-sql-injection`  |  Severity: **Critical**  |  CWE-89  |  A03:2021 Injection

## Summary
The search term q is concatenated into the SQL string. A user who owns any wallet can append a UNION SELECT and read arbitrary tables, including the users table with password hashes.

## Root cause
String interpolation of untrusted input into a query; no parameter binding.

## Change
Prepared statement with bound parameters. LIKE wildcards in user input are escaped so they match literally; input length capped.

Files: `src/Handlers/StatementHandler.php`

## Verification
- `python3 tests/lab.py --app app --only F1` before: **VULNERABLE** (HTTP 200; users table rows in statement: True)
- same command with this patch applied: **MITIGATED** (HTTP 200; users table rows in statement: False)
- `python3 tests/patch_matrix.py` confirms this patch closes the finding on its own
- SAST: payloop.php.taint-to-sql

## Detection
Rules: 110120. Remaining blind spots: Regex on the query string misses payloads in JSON bodies and heavily obfuscated/encoded forms. Pair with DB-level audit logging and a WAF.

## Risk and rollout
Behavioural change: see Change. Rollback: revert this PR; no schema change is required.

## AI-assistance note
Typical AI-suggested fix is correct here (bind parameters). Verify it also handles LIKE wildcards and keeps ORDER BY/LIMIT out of user control.
