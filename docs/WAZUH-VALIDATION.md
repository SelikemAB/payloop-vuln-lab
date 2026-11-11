# Validating the rules on a real Wazuh manager

The offline simulator (`tools/ruletest.py`) is fast and deterministic but it is not the Wazuh engine. Before production:

1. Collect the log: on the agent add
   ```xml
   <localfile>
     <log_format>json</log_format>
     <location>/var/log/payloop/payloop.jsonl</location>
   </localfile>
   ```
2. Copy `detections/wazuh/payloop_rules.xml` to `/var/ossec/etc/rules/` on the manager and restart it.
3. Replay a captured line through the real engine:
   ```bash
   /var/ossec/bin/wazuh-logtest < tests/samples/brute-force.jsonl
   ```
   For each phase confirm the decoder is `json`, the expected rule id fires, and the frequency rules trigger at the threshold.
4. Check these assumptions explicitly, they are where the simulator and the engine can differ:
   - `same_field` on `srcip` behaves the same whether `srcip` lands in the static field or a dynamic field.
   - `frequency` counts the triggering event the way the simulator assumes (off-by-one at the threshold).
   - `if_sid` combined with `if_matched_sid` in rule 110112 is accepted.
   - Sibling rule ordering: the first matching child wins (this bit rule 110150 during development).
5. Record the real `wazuh-logtest` output in your repo; that transcript is better evidence than the simulator.

## Validated on a real manager (2026-11-11)

Ran against a disposable **Wazuh 4.12.0 manager** container (`wazuh/wazuh-manager:4.12.0`), not the production
SOC. The rules were copied to `/var/ossec/etc/rules/`, the manager restarted, and sample lines replayed through
`/var/ossec/bin/wazuh-logtest`. This is exactly where the offline simulator and the real engine diverged, and it
found two rule defects that the simulator did not:

**Finding 1 - rule 110123 would not load (`status` is a static field).**
`analysisd` refused to start: `ERROR: Failure to read rule 110123. Field 'status' is static.` In Wazuh, the JSON
decoder maps the `status` key to a reserved static field, so it cannot be matched with `<field name="status">`.
Fix: use the dedicated static-field tag, `<status type="pcre2">^5\d\d$</status>`.

**Finding 2 - the srcip frequency rules never fired (`same_field` vs a static field).**
This is assumption #1 above, and it is **false**: with `<same_field>srcip</same_field>` the frequency rules
(110111, 110112, 110113, 110124, 110161) never correlated, because `srcip` decodes to a static field and
`same_field` correlates on dynamic fields. The base rule 110101 fired on every event but the brute-force rule
never did. Fix: correlate with the dedicated tag `<same_source_ip />`. The `user` and `idem_key` frequency rules
(110140, 110141, 110151) keep `<same_field>` - those keys stay dynamic and correlate correctly.

After both fixes, `wazuh-analysisd -t` is clean and every rule fires on the real engine. `if_matched_sid` in
rule 110112 is accepted (assumption #3 holds), and the decoder is `json` as expected. The offline simulator
(`make detect`, 21 cases) still passes with the corrected rules.

### Transcript excerpts

Failed login -> 110101, decoder `json`, fields parsed:

```
**Phase 2: Completed decoding.
	name: 'json'
	app: 'payloop'   event: 'login_failed'   srcip: '203.0.113.50'   username: 'dave'
**Phase 3: Completed filtering (rules).
	id: '110101'  level: '5'
	description: 'PayLoop: failed login for dave from 203.0.113.50.'
	mitre.id: '['T1110']'  mitre.technique: '['Brute Force']'
```

Brute force (8+ failures in 60s from one source) -> 110111 frequency rule fires:

```
	id: '110111'  level: '10'  frequency: '8'
	description: 'PayLoop: possible brute force or password spraying, 8+ failed logins in 60s from 203.0.113.50.'
	mitre.id: '['T1110']'
```

SSRF to the cloud metadata endpoint -> 110132, level 14:

```
	id: '110132'  level: '14'
	description: 'PayLoop: server fetched the cloud instance metadata endpoint on behalf of alice.'
	mitre.id: '['T1552.005']'  mitre.technique: '['Cloud Instance Metadata API']'
```

Rules confirmed firing on the real engine: 110101, 110111, 110112, 110113, 110120, 110121, 110123 (the fixed
`<status>` rule), 110130/110132, 110140, 110141, 110151, 110160/110161.
