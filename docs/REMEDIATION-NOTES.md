# Remediation notes: the parts a patch does not cover

A diff closes the code path. These are the operational steps that decide whether the risk is actually gone.

| Finding | After the code fix you still need to... |
|---|---|
| F5 password hashing | Choose a migration path for existing MD5 hashes: rehash on next successful login (verify MD5, then store `password_hash`), then force a reset for accounts that have not logged in within N days. Remove the MD5 verifier once the tail is empty. |
| F6 hard-coded secret | Treat the committed secret as compromised. Generate a new one, inject it through the secret manager or orchestrator, rotate on a schedule, and invalidate every outstanding token. Scrub git history (`git filter-repo`) only after rotation; the old value stays valid for anyone who already cloned. |
| F4 SSRF | Add egress filtering at the network layer so the app host cannot reach metadata or internal ranges even if a bug reappears. On cloud, enforce IMDSv2 with a hop limit of 1. |
| F1 SQL injection | Run the app with a least-privilege database account (no DDL, only the tables it needs) so a future injection has a smaller blast radius. |
| F8 transfer integrity | Add a nightly reconciliation job (sum of ledger movements equals balance deltas) and alert on drift. Detection rules fire after money moved; reconciliation catches what logic checks missed. |
| F7 login throttling | Decide what "source IP" means behind your proxy and configure only that proxy as trusted. Consider MFA for high-value actions; throttling alone does not stop credential stuffing with valid passwords. |
| All | Add the exploit that proved each finding to the regression suite (done here in `tests/lab.py`) so the bug cannot return silently. |

## What this lab does not prove
- The Wazuh rules were exercised with an offline simulator, not a live manager. Run `wazuh-logtest` against a real Wazuh manager before relying on them (see `docs/WAZUH-VALIDATION.md`).
- SAST rules are intentionally narrow, tuned to this codebase. They show the technique, not a general PHP ruleset.
- F2, F7 and F8 are not detectable by static analysis. They were found by reading handlers against the intended access-control and business rules.
