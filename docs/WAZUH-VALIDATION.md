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
