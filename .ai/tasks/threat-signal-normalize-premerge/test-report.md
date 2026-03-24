# Test Report

## Runtime Environment

- Unit validation: container-matched Docker images
- Integration target: `local-dev` k3s cluster

## Tests Run

1. `docker build -f riskstream/services/normalization/threat-signal/Dockerfile -t threat-signal-normalizer:test-preflight .`
2. `docker run --rm -v "$PWD:/app" -w /app threat-signal-normalizer:test-preflight sh -lc "python -m pip install --quiet pytest jsonschema && pytest -q riskstream/tests/unit/test_threat_signal_normalizer.py"`
3. `docker build -f riskstream/services/ingestion/urlhaus/Dockerfile -t urlhaus-ingestion:test-preflight .`
4. `docker run --rm -v "$PWD:/app" -w /app urlhaus-ingestion:test-preflight sh -lc "python -m pip install --quiet pytest && pytest -q riskstream/tests/unit/test_urlhaus_ingestion.py"`
5. `./scripts/run-threat-signal-normalization-integration-test.sh`

## Results

- Threat-signal normalizer unit tests: `passed` (`9 passed`)
- URLhaus ingestion unit tests: `passed` (`22 passed`)
- Threat-signal normalization integration rerun: `blocked`

## Blocked Command

- Command: `./scripts/run-threat-signal-normalization-integration-test.sh`
- Blocking step: `docker save "${IMAGE_NAME}:${IMAGE_TAG}" | sudo k3s ctr images import -`
- Observed error: `sudo: a terminal is required to read the password` and `sudo: a password is required`
- Required access: non-interactive permission to run `k3s ctr images import` or an approved alternative image-import path
- Confidence impact: cluster rerun could not confirm the fix in the exact merge-gate environment

## Existing Cluster Signal

- The prior `local-dev` Job `threat-signal-normalization-integration-test` failed before this fix with `NoSuchKey` on a just-written raw object.
- That failure mode is the issue targeted by the new retry logic.

## Remaining Uncertainty

- The code fix is unit-tested, but the integration proof is incomplete until the rebuilt image can be imported into k3s and the job rerun.
