# PayLoop security findings

Scope: the PayLoop API (fictional payments wallet, PHP 8 + SQLite). Method: threat-model-driven manual review of every handler,
custom Semgrep rules, and a scripted exploit per finding. Every result below was produced by `tests/lab.py` against the
baseline and the patched tree; nothing here is hand-typed evidence.

| ID | Severity | Finding | CWE | OWASP 2021 | Exploit on baseline | Exploit after fix |
|---|---|---|---|---|---|---|
| F1 | Critical | SQL injection in statement search | CWE-89 | A03:2021 Injection | exploitable | mitigated |
| F6 | Critical | Hard-coded token signing secret | CWE-798 | A02:2021 Cryptographic Failures | exploitable | mitigated |
| F2 | High | IDOR on wallet lookup | CWE-639 | A01:2021 Broken Access Control | exploitable | mitigated |
| F3 | High | Path traversal in receipt download | CWE-22 | A01:2021 Broken Access Control | exploitable | mitigated |
| F4 | High | SSRF in partner webhook test | CWE-918 | A10:2021 Server-Side Request Forgery | exploitable | mitigated |
| F8 | High | Transfer integrity (negative amount, overdraft, replay) | CWE-840 | A04:2021 Insecure Design | exploitable | mitigated |
| F5 | Medium | Unsalted MD5 password storage | CWE-328 | A02:2021 Cryptographic Failures | exploitable | mitigated |
| F7 | Medium | No login throttling and user enumeration | CWE-307 | A07:2021 Identification and Authentication Failures | exploitable | mitigated |
| F9 | Low | Stack traces returned to clients | CWE-209 | A05:2021 Security Misconfiguration | exploitable | mitigated |

Severity is qualitative (impact x ease of exploitation in this context), deliberately not a CVSS score.

## F1: SQL injection in statement search

**Severity:** Critical | **CWE-89** | A03:2021 Injection | ATT&CK: T1190  
**Where:** `GET /statement?wallet=&q=` (`src/Handlers/StatementHandler.php`)

**What:** The search term q is concatenated into the SQL string. A user who owns any wallet can append a UNION SELECT and read arbitrary tables, including the users table with password hashes.

**Impact:** Full read of the database; combined with F5 the hashes are cracked offline in minutes.

**Reproduce**
```bash
TOKEN=$(curl -s $BASE/login -d '{"username":"alice","password":"alice-demo-pw"}' | jq -r .token)
curl -sG $BASE/statement -H "Authorization: Bearer $TOKEN" --data-urlencode "wallet=1" \
  --data-urlencode "q=zzz%' UNION SELECT id,1,1,1,username||':'||pass_hash,'x' FROM users--"
```

**Root cause:** String interpolation of untrusted input into a query; no parameter binding.

**Fix:** Prepared statement with bound parameters. LIKE wildcards in user input are escaped so they match literally; input length capped.

**Evidence (generated)**

- Baseline: HTTP 200; users table rows in statement: True
- Patched: HTTP 200; users table rows in statement: False

**Detection**

- SAST: payloop.php.taint-to-sql
- Wazuh rules: 110120
- Blind spots: Regex on the query string misses payloads in JSON bodies and heavily obfuscated/encoded forms. Pair with DB-level audit logging and a WAF.

**Reviewing an AI-proposed fix:** Typical AI-suggested fix is correct here (bind parameters). Verify it also handles LIKE wildcards and keeps ORDER BY/LIMIT out of user control.

## F2: IDOR on wallet lookup

**Severity:** High | **CWE-639** | A01:2021 Broken Access Control | ATT&CK: T1213  
**Where:** `GET /wallet?id=` (`src/Handlers/WalletHandler.php`)

**What:** The endpoint authenticates the caller but never checks that the wallet belongs to them. Changing id returns any customer's balance and owner.

**Impact:** Disclosure of every customer's balance and identity; trivially enumerable because ids are sequential.

**Reproduce**
```bash
curl -s "$BASE/wallet?id=2" -H "Authorization: Bearer $ALICE_TOKEN"   # bob's wallet
```

**Root cause:** Authentication without object-level authorisation.

**Fix:** Reuse the shared Wallets::assertAccess() guard (owner or admin). Non-owners get 404 so existence is not revealed, and the denial is logged.

**Evidence (generated)**

- Baseline: alice reads wallet 2 -> HTTP 200, owner=bob, balance=50000
- Patched: alice reads wallet 2 -> HTTP 404

**Detection**

- SAST: none (logic flaw)
- Wazuh rules: 110140, 110141
- Blind spots: A single targeted read of a guessable id looks like normal traffic; detection relies on enumeration volume. Prevention is the real control.

**Reviewing an AI-proposed fix:** SAST and many AI reviewers miss this class because the code is 'correct' but incomplete. It was found by reading every handler against the access-control matrix in the threat model.

## F3: Path traversal in receipt download

**Severity:** High | **CWE-22** | A01:2021 Broken Access Control | ATT&CK: T1005  
**Where:** `GET /receipt?file=` (`src/Handlers/ReceiptHandler.php`)

**What:** The file parameter is appended to the receipts directory, so ../ sequences read files elsewhere on disk.

**Impact:** Arbitrary file read as the web user: configuration, keys, source.

**Reproduce**
```bash
curl -sG $BASE/receipt -H "Authorization: Bearer $TOKEN" --data-urlencode "file=../internal/notes.txt"
```

**Root cause:** No validation of a user-controlled path segment.

**Fix:** Strict allow-list regex on the file name, then realpath() containment check against the receipts directory. Blocked attempts are logged.

**Evidence (generated)**

- Baseline: file=../internal/notes.txt -> HTTP 200, internal file read: True
- Patched: file=../internal/notes.txt -> HTTP 404, internal file read: False

**Detection**

- SAST: payloop.php.taint-to-file-path
- Wazuh rules: 110121, 110122
- Blind spots: Double-encoded sequences can slip past the request-line regex; the app-level path_blocked event (110122) covers them once the fix is in.

**Reviewing an AI-proposed fix:** Check the AI did not just strip '../' (bypassable with ....// or encoding); the allow-list plus realpath combination is the robust pattern.

## F4: SSRF in partner webhook test

**Severity:** High | **CWE-918** | A10:2021 Server-Side Request Forgery | ATT&CK: T1190, T1552.005  
**Where:** `POST /partner/webhook-test` (`src/Handlers/WebhookTestHandler.php`, `src/SsrfGuard.php (new)`)

**What:** The server fetches any URL a caller supplies, follows redirects, accepts file:// and returns the response body.

**Impact:** Reach internal services and, in cloud environments, the instance metadata endpoint; read local files.

**Reproduce**
```bash
curl -s $BASE/partner/webhook-test -H "Authorization: Bearer $TOKEN" -d '{"url":"http://127.0.0.1:9000/internal"}'
```

**Root cause:** No destination policy on an outbound request made on behalf of a user.

**Fix:** New SsrfGuard: http/https only, no userinfo or IP literals, ports 80/443, host must be on an allow-list (deny-all by default), every resolved address must be public IPv4 (RFC1918, loopback, link-local, CGNAT and documentation ranges rejected; IPv6 and IPv4-mapped forms rejected outright), connection is pinned to the vetted IP, redirects disabled, response body not reflected.

**Evidence (generated)**

- Baseline: loopback http -> HTTP 200 (internal data reflected: True); file:// -> HTTP 200 (read: True)
- Patched: loopback http -> HTTP 400 (internal data reflected: False); file:// -> HTTP 400 (read: False)

**Detection**

- SAST: payloop.php.taint-to-outbound-request
- Wazuh rules: 110130, 110131, 110132
- Blind spots: DNS rebinding is closed by IP pinning, not by detection. Egress filtering at the network layer is the independent backstop.

**Reviewing an AI-proposed fix:** Ask the AI for the bypass list too (DNS rebinding, redirects, decimal/octal IPs, IPv6, userinfo tricks) and turn each into a test. See tests/ssrf_guard_test.php.

## F5: Unsalted MD5 password storage

**Severity:** Medium | **CWE-328** | A02:2021 Cryptographic Failures | ATT&CK: T1110  
**Where:** `users.pass_hash` (`src/PasswordHasher.php`)

**What:** Passwords are stored as unsalted MD5, a fast hash that is reversed with rainbow tables or GPU cracking.

**Impact:** Any database read (see F1) becomes mass credential compromise, including reuse on other services.

**Reproduce**
```bash
sqlite3 var/payloop.sqlite "select username, pass_hash from users"   # 32 hex characters each
```

**Root cause:** General-purpose hash used where a slow, salted password hash is required.

**Fix:** password_hash() with Argon2id (bcrypt fallback). Existing hashes need a rollout plan, see docs/REMEDIATION-NOTES.md.

**Evidence (generated)**

- Baseline: stored hash format: 32-hex (unsalted MD5)
- Patched: stored hash format: argon2id (salted, memory-hard)

**Detection**

- SAST: payloop.php.weak-password-hash
- Wazuh rules: none
- Blind spots: No runtime signal. Compensating controls: database access monitoring and credential-stuffing detection (110111).

**Reviewing an AI-proposed fix:** AI will often suggest bcrypt; accept it if Argon2id is unavailable, but make sure verification uses password_verify() and that migration of existing hashes is addressed.

## F6: Hard-coded token signing secret

**Severity:** Critical | **CWE-798** | A02:2021 Cryptographic Failures | ATT&CK: T1606, T1552.001  
**Where:** `Config::tokenSecret()` (`src/Config.php`, `src/Auth.php`)

**What:** Session tokens are HMAC-signed with a secret committed to source. Anyone with repository access can mint a token for any user, including admin.

**Impact:** Authentication bypass and privilege escalation; the secret is in every clone, fork and CI log.

**Reproduce**
```bash
python3 - <<'PY'
import base64, hmac, hashlib, json, time
b = lambda x: base64.urlsafe_b64encode(x).rstrip(b"=").decode()
p = b(json.dumps({"sub": 5, "usr": "admin", "role": "admin", "exp": int(time.time()) + 600}).encode())
print(p + "." + hmac.new(b"payloop-dev-secret-2024", p.encode(), hashlib.sha256).hexdigest())
PY
# then: curl -s $BASE/admin/users -H "Authorization: Bearer <printed token>"
```

**Root cause:** Secret material stored in source control; token comparison not constant-time.

**Fix:** Secret read from PAYLOOP_TOKEN_SECRET (min 32 chars), application fails closed if absent; hash_equals() for the signature check. Existing secret must be treated as burned and rotated.

**Evidence (generated)**

- Baseline: admin token forged with the committed secret -> HTTP 200, 5 users listed
- Patched: admin token forged with the committed secret -> HTTP 401

**Detection**

- SAST: payloop.php.hardcoded-secret, payloop.php.non-constant-time-mac-compare
- Wazuh rules: 110160, 110161, 110170
- Blind spots: A token forged with the real secret is cryptographically valid, so no 'invalid token' event is produced. Only behavioural signals (110170 admin access from a new source) remain. This is why the secret must never leak.

**Reviewing an AI-proposed fix:** Fixing the code does not undo the leak: the old value stays in git history. Rotation and history scrubbing are part of the remediation, not optional.

## F7: No login throttling and user enumeration

**Severity:** Medium | **CWE-307** | A07:2021 Identification and Authentication Failures | ATT&CK: T1110  
**Where:** `POST /login` (`src/Handlers/LoginHandler.php`, `src/RateLimiter.php (new)`)

**What:** Unlimited password guesses are accepted, and the error text differs for unknown users versus wrong passwords.

**Impact:** Online brute force, password spraying and username harvesting.

**Reproduce**
```bash
for i in $(seq 1 50); do curl -s -o /dev/null -w "%{http_code} " $BASE/login -d "{\"username\":\"dave\",\"password\":\"x$i\"}"; done
```

**Root cause:** No attempt accounting and verbose authentication errors.

**Fix:** Failure counters per username (5 / 5 min) and per source IP (20 / 5 min) stored in the database, HTTP 429 with Retry-After, one generic error for every failure, dummy hash verification so unknown users take similar time.

**Evidence (generated)**

- Baseline: 12 wrong passwords -> [401] (429 seen: False); enumeration via error text: True
- Patched: 12 wrong passwords -> [401, 429] (429 seen: True); enumeration via error text: False

**Detection**

- SAST: none (missing control)
- Wazuh rules: 110101, 110111, 110112, 110103, 110113
- Blind spots: Low-and-slow attacks below the thresholds and botnet-distributed guessing need longer-window behavioural analytics.

**Reviewing an AI-proposed fix:** Check the limiter keys on both identity and source, otherwise spraying across usernames bypasses it. Decide what source IP means behind a proxy (trusted proxy only).

## F8: Transfer integrity (negative amount, overdraft, replay)

**Severity:** High | **CWE-840** | A04:2021 Insecure Design | ATT&CK: T1657  
**Where:** `POST /transfer` (`src/Handlers/TransferHandler.php`)

**What:** Amounts are not validated (negative values reverse the direction of the transfer), balances can go below zero, and the Idempotency-Key header is ignored so a retried request pays twice.

**Impact:** Direct financial loss: free money, overdrafts and duplicate payments.

**Reproduce**
```bash
curl -s $BASE/transfer -H "Authorization: Bearer $ALICE_TOKEN" -H "Idempotency-Key: demo-0001" \
  -d '{"from_wallet":1,"to_wallet":2,"amount_minor":-5000}'
```

**Root cause:** Business rules not enforced server-side; no atomicity; client-controlled retries unhandled.

**Fix:** Integer-only, bounded, positive amounts; distinct wallets; mandatory idempotency key with a unique index; BEGIN IMMEDIATE transaction around check and update; insufficient funds rejected; replay returns the original result.

**Evidence (generated)**

- Baseline: negative amount -> HTTP 201; overdraft -> HTTP 201; same key sent twice moved GHS 20.00 (expected 10.00)
- Patched: negative amount -> HTTP 422; overdraft -> HTTP 422; same key sent twice moved GHS 10.00 (expected 10.00)

**Detection**

- SAST: none (business logic)
- Wazuh rules: 110150, 110153, 110151, 110152
- Blind spots: Detection after the fact only; money has already moved when 110150 fires on the baseline. Prevention and reconciliation are the primary controls.

**Reviewing an AI-proposed fix:** This is where AI review is weakest: no scanner has a rule for 'negative amount'. Derive the checks from the threat model (financial theft), then write the exploit test first.

## F9: Stack traces returned to clients

**Severity:** Low | **CWE-209** | A05:2021 Security Misconfiguration | ATT&CK: T1190  
**Where:** `global exception handler` (`public/index.php`)

**What:** Unhandled exceptions return the message, file path, line number and full stack trace to the caller.

**Impact:** Internal paths and code structure help attackers refine other exploits.

**Reproduce**
```bash
curl -s $BASE/login -d '{'
```

**Root cause:** Debug-style error output left enabled in the request path.

**Fix:** Client sees a generic error and a request id. Details are logged as an app_error event keyed by the same id. Malformed JSON maps to 400.

**Evidence (generated)**

- Baseline: malformed JSON -> HTTP 500; stack trace / file paths in body: True
- Patched: malformed JSON -> HTTP 400; stack trace / file paths in body: False

**Detection**

- SAST: payloop.php.exception-detail-to-client
- Wazuh rules: 110123, 110124, 110180
- Blind spots: None significant; error bursts are a reliable fuzzing signal.

**Reviewing an AI-proposed fix:** Low severity, but cheap to fix and it multiplies the value of every other bug. Good example for explaining severity versus exploitability.
