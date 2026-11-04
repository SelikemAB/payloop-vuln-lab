PY ?= python3
.PHONY: mutate all baseline fixed matrix ssrf sast detect docs clean
all: baseline fixed matrix ssrf sast detect   ## everything CI runs

build/fixed: app patches/*.patch
	./scripts/build-fixed.sh

baseline:            ## every exploit must work on the vulnerable app
	$(PY) tests/lab.py --app app --expect vulnerable

fixed: build/fixed   ## every exploit must fail on the patched app
	$(PY) tests/lab.py --app build/fixed --expect mitigated

matrix: build/fixed  ## each patch alone closes its own finding
	$(PY) tests/patch_matrix.py

ssrf: build/fixed    ## SSRF guard bypass unit tests
	php tests/ssrf_guard_test.php build/fixed

sast: build/fixed    ## Semgrep: must flag the baseline and be clean on the fix
	semgrep --config semgrep/payloop-php.yml --metrics=off --disable-version-check --error app/src app/public; test $$? -eq 1
	@# semgrep's built-in ignore excludes any build/ dir, so scanning build/fixed directly skips
	@# every file and passes vacuously. Stage the fixed tree outside build/ and require that it was
	@# really scanned (>0 files) with 0 findings, so this step can actually fail on a regression.
	@d=$$(mktemp -d); \
	  cp -r build/fixed/src build/fixed/public "$$d"/ && \
	  semgrep --config semgrep/payloop-php.yml --metrics=off --disable-version-check --json --output "$$d/out.json" "$$d/src" "$$d/public" >/dev/null && \
	  $(PY) scripts/check_sast_clean.py "$$d/out.json"; \
	  rc=$$?; rm -rf "$$d"; exit $$rc

detect:              ## lint rules and replay the detection regression suite
	$(PY) tools/ruletest.py lint detections/wazuh/payloop_rules.xml
	$(PY) tools/ruletest.py suite tests/detections.yml

docs: build/fixed    ## regenerate FINDINGS.md and PR drafts from findings.yaml
	$(PY) scripts/gen_docs.py

clean:
	rm -rf build app/var/*.sqlite* app/var/log

mutate:              ## prove the detection suite can fail
	$(PY) tools/mutation_check.py tests/detections.yml
