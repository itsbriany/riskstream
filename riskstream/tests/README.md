# Tests

This directory contains the RiskStream test suites:

- `unit/` for service-level unit tests
- `integration/` for service integration tests
- `e2e/` for end-to-end workflow tests

## Running Unit Tests

Run the ThreatFox unit tests directly with `pytest`:

```bash
pytest riskstream/tests/unit/test_threatfox_ingestion.py -q
```

Run all unit tests under the directory:

```bash
pytest riskstream/tests/unit/ -q
```

## Running Unit Tests In The Service Base Image

To keep unit testing consistent with the ThreatFox service runtime, run the tests in the same base image family used by `riskstream/services/ingestion/threatfox/Dockerfile`:

```bash
docker run --rm \
  -v "$PWD:/work" \
  -w /work \
  python:3.11-slim \
  sh -lc "python -m pip install --quiet pytest && pytest -q riskstream/tests/unit/test_threatfox_ingestion.py"
```

## Other Test Suites

- Integration test guidance: `riskstream/tests/integration/README.md`
- End-to-end test guidance: `riskstream/tests/e2e/README.md`
