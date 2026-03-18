---
name: riskstream-integration-test-runner
description: Run and triage RiskStream integration tests with the repository's in-cluster Kubernetes workflow. Use when working on ThreatFox or CISA KEV integration coverage, cluster test jobs, rollout-related test failures, service-level regressions, or any task that should follow the repo's local-dev integration scripts instead of generic local pytest.
---

# RiskStream Integration Test Runner

## Overview

Use this skill to keep integration work aligned with RiskStream's `local-dev` Kubernetes workflow. Treat in-cluster execution as the default and use service-matched unit tests as the preflight and regression check around code changes.

## Repo Defaults

- Use `local-dev` unless the user explicitly names another namespace.
- Use `README.md` and `riskstream/tests/integration/README.md` as workflow references.
- Use the existing scripts instead of ad hoc cluster commands when they fit:
  - `./scripts/build-and-deploy-local.sh`
  - `./scripts/run-threatfox-integration-test.sh`
  - `./scripts/run-cisa-kev-integration-test.sh`

## Workflow

1. Identify the affected ingestion service.
2. Run the matching unit-test preflight inside the same service image environment.
3. If the unit baseline is already failing, report that before attributing failures to new work.
4. Run the matching in-cluster integration script.
5. If the integration test fails, inspect rollout status, Job state, and logs before proposing code changes.
6. After any code change, rerun the matching container-based unit test and then rerun the in-cluster integration script.

## Container-Matched Unit-Test Preflight

Build the service image from the repo root, then run only the relevant unit test inside that image with a transient `pytest` install.

ThreatFox:

```bash
docker build -f riskstream/services/ingestion/threatfox/Dockerfile \
  -t threatfox-ingestion:test-preflight \
  .
docker run --rm \
  -v "$PWD:/app" \
  -w /app \
  threatfox-ingestion:test-preflight \
  sh -lc "python -m pip install --quiet pytest && pytest -q riskstream/tests/unit/test_threatfox_ingestion.py"
```

CISA KEV:

```bash
docker build -f riskstream/services/ingestion/cisa-kev/Dockerfile \
  -t cisa-kev-ingestion:test-preflight \
  .
docker run --rm \
  -v "$PWD:/app" \
  -w /app \
  cisa-kev-ingestion:test-preflight \
  sh -lc "python -m pip install --quiet pytest && pytest -q riskstream/tests/unit/test_cisa_kev_ingestion.py"
```

If both ingestion services are touched, run both unit tests.

## Preferred Integration Commands

ThreatFox:

```bash
./scripts/run-threatfox-integration-test.sh
```

CISA KEV:

```bash
./scripts/run-cisa-kev-integration-test.sh
```

These scripts already rebuild the service image, import it into k3s, redeploy the `local-dev` overlay, refresh the test ConfigMap, recreate the test Job, wait for completion, and print logs.

## Failure Classification

- Deployment or rollout failure:
  - Check `kubectl rollout status deployment/<service> -n local-dev`
  - Check pod readiness, restarts, and events
- Test Job failure:
  - Check `kubectl get jobs -n local-dev`
  - Check `kubectl logs -n local-dev job/<job-name>`
- Assertion failure:
  - Distinguish a service regression from live upstream data changes
- Upstream connectivity failure:
  - Treat DNS, timeout, TLS, or remote API issues as environment or dependency problems first

## What Not To Do

- Do not default to direct host `pytest` for integration tests.
- Do not skip the container-matched unit-test preflight for ingestion code changes.
- Do not assume staging or production when the user asks for local integration work.
- Do not edit tests first when rollout, Job, or upstream failures have not been checked.
