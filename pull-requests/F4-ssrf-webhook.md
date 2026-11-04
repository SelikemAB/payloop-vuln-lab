# Fix F4: SSRF in partner webhook test

Branch: `fix/f4-ssrf-webhook`  |  Severity: **High**  |  CWE-918  |  A10:2021 Server-Side Request Forgery

## Summary
The server fetches any URL a caller supplies, follows redirects, accepts file:// and returns the response body.

## Root cause
No destination policy on an outbound request made on behalf of a user.

## Change
New SsrfGuard: http/https only, no userinfo or IP literals, ports 80/443, host must be on an allow-list (deny-all by default), every resolved address must be public IPv4 (RFC1918, loopback, link-local, CGNAT and documentation ranges rejected; IPv6 and IPv4-mapped forms rejected outright), connection is pinned to the vetted IP, redirects disabled, response body not reflected.

Files: `src/Handlers/WebhookTestHandler.php`, `src/SsrfGuard.php (new)`

## Verification
- `python3 tests/lab.py --app app --only F4` before: **VULNERABLE** (loopback http -> HTTP 200 (internal data reflected: True); file:// -> HTTP 200 (read: True))
- same command with this patch applied: **MITIGATED** (loopback http -> HTTP 400 (internal data reflected: False); file:// -> HTTP 400 (read: False))
- `python3 tests/patch_matrix.py` confirms this patch closes the finding on its own
- SAST: payloop.php.taint-to-outbound-request

## Detection
Rules: 110130, 110131, 110132. Remaining blind spots: DNS rebinding is closed by IP pinning, not by detection. Egress filtering at the network layer is the independent backstop.

## Risk and rollout
Behavioural change: see Change. Rollback: revert this PR; no schema change is required.

## AI-assistance note
Ask the AI for the bypass list too (DNS rebinding, redirects, decimal/octal IPs, IPv6, userinfo tricks) and turn each into a test. See tests/ssrf_guard_test.php.
