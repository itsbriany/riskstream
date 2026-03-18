# Integration Tests

This directory contains integration tests that verify the interaction between multiple RiskStream services.

## Overview

Integration tests ensure that services work correctly together, testing:
- Service-to-service communication
- API contracts and data formats
- Error handling across service boundaries
- End-to-end data flow

## Running Tests

### Run both ingestion integration tests

Deploy the local-dev environment first:

```bash
./scripts/build-and-deploy-local.sh
```

Then run both in-cluster ingestion integration tests sequentially:

```bash
./scripts/run-ingestion-integration-tests.sh
```

You can also target a single service through the wrapper by passing its name:

```bash
./scripts/run-ingestion-integration-tests.sh <service>
```

Use the per-service scripts below when you want the most direct, targeted failure signal.

### ThreatFox in-cluster test

Deploy the local-dev environment first:

```bash
./scripts/build-and-deploy-local.sh
```

Then run the ThreatFox integration test from inside the cluster:

```bash
./scripts/run-threatfox-integration-test.sh
```

The script will:
- wait for the `threatfox-ingestion` deployment to become ready
- create a ConfigMap from `riskstream/tests/integration/test_threatfox_ingestion.py`
- start a short-lived Kubernetes Job in `local-dev`
- wait for the Job to complete and print the pytest logs

### CISA KEV in-cluster test

Deploy the local-dev environment first:

```bash
./scripts/build-and-deploy-local.sh
```

Then run the CISA KEV integration test from inside the cluster:

```bash
./scripts/run-cisa-kev-integration-test.sh
```

The script will:
- wait for the `cisa-kev-ingestion` deployment to become ready
- create a ConfigMap from `riskstream/tests/integration/test_cisa_kev_ingestion.py`
- start a short-lived Kubernetes Job in `local-dev`
- wait for the Job to complete and print the pytest logs
- accept either a changed snapshot write or a no-change response that references the latest stored snapshot

### Manual pytest override

The ThreatFox test still accepts `THREATFOX_BASE_URL` for non-cluster targets:

```bash
THREATFOX_BASE_URL=http://threatfox-ingestion pytest riskstream/tests/integration/test_threatfox_ingestion.py -v
```

The CISA KEV test accepts `CISA_KEV_BASE_URL` for non-cluster targets:

```bash
CISA_KEV_BASE_URL=http://cisa-kev-ingestion pytest riskstream/tests/integration/test_cisa_kev_ingestion.py -v
```

## Test Structure

```text
integration/
├── test_cisa_kev_ingestion.py    # CISA KEV live integration test
├── test_threatfox_ingestion.py   # ThreatFox live integration test
└── README.md                     # Integration test workflow
```

## Requirements

Integration tests require:
- the `local-dev` namespace to be deployed
- `kubectl` access to the cluster
- outbound network access from the ThreatFox service to the live ThreatFox API
- outbound network access from the CISA KEV service to the official CISA KEV JSON feed

## Best Practices

1. Keep integration tests focused on service boundaries.
2. Prefer in-cluster execution for Kubernetes services.
3. Verify live contracts without mocking when the goal is true integration coverage.
4. Use the combined wrapper for convenience, and the per-service scripts for targeted troubleshooting.
