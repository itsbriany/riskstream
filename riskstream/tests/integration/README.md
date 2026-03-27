# Integration Tests

This directory contains integration tests that verify the interaction between multiple RiskStream services.

## Overview

Integration tests ensure that services work correctly together, testing:
- Service-to-service communication
- API contracts and data formats
- Error handling across service boundaries
- End-to-end data flow

## Running Tests

### Run all ingestion integration tests

Deploy the local-dev environment first:

```bash
./scripts/build-and-deploy-local.sh
```

Then run all in-cluster ingestion integration tests sequentially:

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

### URLhaus in-cluster test

Deploy the local-dev environment first:

```bash
./scripts/build-and-deploy-local.sh
```

Then run the URLhaus integration test from inside the cluster:

```bash
./scripts/run-urlhaus-integration-test.sh
```

The script will:
- wait for the `urlhaus-ingestion` deployment to become ready
- create a ConfigMap from `riskstream/tests/integration/test_urlhaus_ingestion.py`
- start a short-lived Kubernetes Job in `local-dev`
- wait for the Job to complete and print the pytest logs
- accept either a changed delta write or a no-change response that still reports the current checkpoint/delta contract

### URLhaus archive lifecycle in-cluster test

Deploy the local-dev environment first:

```bash
./scripts/build-and-deploy-local.sh
```

Then run the URLhaus archive lifecycle integration test:

```bash
./scripts/run-urlhaus-archive-lifecycle-integration-test.sh
```

The script will:
- deploy the local-dev overlay and wait for MinIO
- create a ConfigMap from `riskstream/tests/integration/test_urlhaus_archive_lifecycle.py`
- start a short-lived Kubernetes Job in `local-dev`
- verify that old URLhaus checkpoint and delta objects are archived while `state/latest` remains hot

### Threat signal normalization in-cluster test

Deploy the local-dev environment first:

```bash
./scripts/build-and-deploy-local.sh
```

Then run the threat signal normalization integration test:

```bash
./scripts/run-threat-signal-normalization-integration-test.sh
```

The script will:
- build and import the `threat-signal-normalizer` image
- deploy the local-dev overlay and wait for MinIO initialization
- create a ConfigMap from `riskstream/tests/integration/test_threat_signal_normalization.py`
- start a short-lived Kubernetes Job in `local-dev`
- verify that the normalizer can read seeded raw artifacts from `raw-feeds` and write normalized outputs to `processed-data`

### Manual pytest override

The ThreatFox test still accepts `THREATFOX_BASE_URL` for non-cluster targets:

```bash
THREATFOX_BASE_URL=http://threatfox-ingestion pytest riskstream/tests/integration/test_threatfox_ingestion.py -v
```

The CISA KEV test accepts `CISA_KEV_BASE_URL` for non-cluster targets:

```bash
CISA_KEV_BASE_URL=http://cisa-kev-ingestion pytest riskstream/tests/integration/test_cisa_kev_ingestion.py -v
```

The URLhaus test accepts `URLHAUS_BASE_URL` for non-cluster targets:

```bash
URLHAUS_BASE_URL=http://urlhaus-ingestion pytest riskstream/tests/integration/test_urlhaus_ingestion.py -v
```

## Test Structure

```text
integration/
├── test_cisa_kev_ingestion.py    # CISA KEV live integration test
├── test_threatfox_ingestion.py   # ThreatFox live integration test
├── test_threat_signal_normalization.py  # Threat-signal normalization in-cluster test
├── test_urlhaus_ingestion.py     # URLhaus live integration test
├── test_urlhaus_archive_lifecycle.py  # URLhaus archive lifecycle test
└── README.md                     # Integration test workflow
```

## Requirements

Integration tests require:
- the `local-dev` namespace to be deployed
- `kubectl` access to the cluster
- outbound network access from the ThreatFox service to the live ThreatFox API
- outbound network access from the CISA KEV service to the official CISA KEV JSON feed
- outbound network access from the URLhaus service to the live URLhaus recent CSV export

## Best Practices

1. Keep integration tests focused on service boundaries.
2. Prefer in-cluster execution for Kubernetes services.
3. Verify live contracts without mocking when the goal is true integration coverage.
4. Use the combined wrapper for convenience, and the per-service scripts for targeted troubleshooting.
