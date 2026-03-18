---
name: riskstream-k8s-deploy-debug
description: Debug RiskStream Kubernetes deployments, Kustomize overlays, and local-dev rollout issues. Use when working in k8s manifests, Argo CD or GitOps deployment flow, local cluster rollout failures, pod readiness problems, MinIO bootstrap issues, or deployment tasks that combine Python service changes with Kubernetes verification.
---

# RiskStream K8s Deploy Debug

## Overview

Use this skill to keep deploy and rollout work aligned with the repo's Kustomize and `local-dev` cluster workflow. Default to local verification, keep changes narrow, and separate manifest issues from service-code regressions.

## Repo Defaults

- Treat `k8s/base` as shared configuration and `k8s/overlays/<env>` as environment-specific customization.
- Default to `local-dev` unless the user explicitly names `staging` or `production`.
- Use `README.md`, `docs/ARCHITECTURE.md`, and `docs/CI-CD.md` as the main references.
- Prefer the existing deploy script:

```bash
./scripts/build-and-deploy-local.sh
```

## Workflow

1. Determine whether the task is manifest-only, deploy-only, or code-plus-deploy.
2. If Python ingestion code changes are in scope, run the matching container-based unit-test preflight before cluster verification.
3. Render or apply the relevant overlay.
4. Check rollout status, pod readiness, and logs before proposing YAML changes.
5. If MinIO or init Jobs are involved, inspect them explicitly instead of treating them as generic app failures.
6. Keep `staging` and `production` changes opt-in.

## Manifest and Overlay Checks

Render overlays before editing or when debugging patch behavior:

```bash
kubectl kustomize k8s/overlays/local-dev
kubectl kustomize k8s/overlays/staging
kubectl kustomize k8s/overlays/production
```

Use `local-dev` as the first verification target:

```bash
kubectl apply -k k8s/overlays/local-dev -n local-dev
kubectl get pods -n local-dev
kubectl get jobs -n local-dev
```

## Code-Plus-Deploy Preflight

Only require this when the task changes ingestion service code in addition to deploy behavior.

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

## Rollout Triage

Use the existing deploy script when the goal is to rebuild and redeploy the full local stack:

```bash
./scripts/build-and-deploy-local.sh
```

Then check:

```bash
kubectl rollout status deployment/riskstream -n local-dev --timeout=180s
kubectl rollout status deployment/threatfox-ingestion -n local-dev --timeout=180s
kubectl rollout status deployment/cisa-kev-ingestion -n local-dev --timeout=180s
kubectl logs -n local-dev -l app.kubernetes.io/name=riskstream --tail=100
kubectl logs -n local-dev deployment/threatfox-ingestion --tail=100
kubectl logs -n local-dev deployment/cisa-kev-ingestion --tail=100
kubectl logs -n local-dev job/minio-init --tail=100
```

## What Not To Do

- Do not jump straight to editing `k8s/base` when the issue is local-only.
- Do not require unit tests for pure manifest inspection or rollout observation.
- Do not treat MinIO bootstrap failures as the same thing as service rollout failures.
- Do not assume Argo CD sync behavior matters for a purely local-dev issue unless the user asks.
