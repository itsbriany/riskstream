---
name: riskstream-ci-triage
description: Diagnose RiskStream CI failures with the smallest safe fix. Use when GitHub Actions fails on Ruff or Black checks, app tests, ThreatFox or CISA KEV unit tests, Docker image builds, GHCR publishing, or when a code change should be checked against the repo's current CI workflow before or after editing.
---

# RiskStream CI Triage

## Overview

Use this skill to map a failing CI signal to the smallest useful local reproduction and fix. Treat `.github/workflows/ci.yml` as the current CI source of truth, but reproduce ingestion-unit behavior locally with the service image environment rather than with generic host commands.

## Repo Defaults

- Start with `.github/workflows/ci.yml`.
- Use `docs/CONTRIBUTING.md` and `docs/CI-CD.md` for local verification expectations.
- Classify the failure before proposing changes:
  - Ruff or Black on `app/`
  - `pytest ./app`
  - ThreatFox unit test
  - CISA KEV unit test
  - Docker image build
  - GHCR login or push

## Workflow

1. Identify the failing CI step exactly.
2. Reproduce only that step locally.
3. If the failure is in an ingestion unit test, reproduce it in the matching service image environment.
4. Check for a pre-existing baseline failure before blaming the new diff.
5. Propose the smallest fix that addresses the failing step without widening scope.
6. Rerun the affected local reproduction after the fix.

## Local Reproduction Commands

App lint and format:

```bash
ruff check ./app
black --check ./app
```

App tests:

```bash
pytest ./app --tb=short
```

ThreatFox unit test in service image environment:

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

CISA KEV unit test in service image environment:

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

## Build and Registry Triage

For container-step failures, keep the investigation narrow:

- App image:
  - `docker build -t riskstream:test ./app`
- ThreatFox image:
  - `docker build -f riskstream/services/ingestion/threatfox/Dockerfile -t threatfox-ingestion:test .`
- CISA KEV image:
  - `docker build -f riskstream/services/ingestion/cisa-kev/Dockerfile -t cisa-kev-ingestion:test .`

Treat GHCR failures as auth, permission, or tag-generation issues first. Do not change application code to solve a registry or workflow problem.

## Current CI Notes

- CI currently runs the ingestion unit tests inside `python:3.11-slim` containers with a transient `pytest` install.
- For local preflight and regression checks, prefer the matching service image environment because it is closer to the microservice runtime.
- If CI and local results differ, compare the service image assumptions against the simpler CI container before expanding the fix.

## What Not To Do

- Do not run the full workflow locally when only one CI step failed.
- Do not use host-only `pytest` as the ingestion-unit authority.
- Do not refactor unrelated code to make a single CI step pass.
- Do not conflate Docker build failures with test failures.
