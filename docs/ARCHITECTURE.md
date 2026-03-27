# Architecture

## Overview

Riskstream uses a Kubernetes-native GitOps architecture with Argo CD for declarative deployments and Kustomize for environment-specific manifests.

## Kubernetes Structure

### Namespaces

- **`argocd`** - Argo CD control plane
- **`observability`** - Shared logging stack for staging-first log aggregation
- **`staging`** - Auto-synced from main branch
- **`production`** - Manual sync (intentional separation)
- **`local-dev`** - Local development on k3s

### Kubernetes Layout

- `k8s/base/` - Shared manifests for the platform and application workloads
- `k8s/overlays/` - Environment-specific customization for local-dev, staging, and production
- `k8s/argocd/` - GitOps application definitions and project configuration
- `k8s/namespaces/` - Namespace resources
- `k8s/observability/` - Observability stack values and related config

The exact manifest set under `k8s/base/` grows as new services are added, so this doc intentionally describes responsibilities instead of maintaining a file inventory.

## Kustomize Strategy

**Base** (`k8s/base/`) contains the core application manifests:
- Generic `Deployment` with GHCR image reference
- `Service` for network access
- MinIO deployment and bucket-init job
- ThreatFox, CISA KEV, and URLhaus ingestion deployments, services, and CronJobs
- Threat-signal normalization CronJobs for ThreatFox, URLhaus, and CISA KEV

**Overlays** apply environment-specific changes:
- `staging`: environment patching and image/tag selection for shared services and ingestion workloads
- `production`: environment patching and stable app promotion
- `local-dev`: local image names, Never pull policy, and local-dev environment overrides for ingestion services

## Argo CD Behavior

### Staging (Auto-sync)

```yaml
riskstream-staging Application:
  - source: https://github.com/itsbriany/riskstream (main branch)
  - path: k8s/overlays/staging
  - syncPolicy: automated (prune + selfHeal)
  - destination: staging namespace
```

**Result:** Any commit to `main` automatically syncs to staging.

### Production (Manual sync)

```yaml
riskstream-production Application:
  - source: https://github.com/itsbriany/riskstream (main branch)
  - path: k8s/overlays/production
  - syncPolicy: manual (requires explicit approval)
  - destination: production namespace
```

**Result:** Production deployments are intentionally manual for safety.

## Image Tagging

- **Staging:** `ghcr.io/itsbriany/riskstream:main` (latest from `main` branch)
- **Production:** `ghcr.io/itsbriany/riskstream:stable` (requires manual tag/promotion)
- **Local-dev:** `riskstream:local` (local docker registry)
- **Ingestion images:** ThreatFox and CISA KEV are built and published as separate GHCR images, with local-dev using local image names via overlay remapping

## Threat Data Flow

Threat intelligence flows through three layers:

1. Ingestion services write immutable raw artifacts into MinIO under `raw-feeds/...`
2. Threat-signal normalization CronJobs read those raw artifacts and write schema-versioned normalized JSONL batches into `processed-data/normalized/threat-signals/threat_signal.v1/...`
3. The normalizer stores per-stream checkpoint state in `processed-data/normalization-state/threat-signal/threat_signal.v1/...`

Current normalization CronJobs:

- `threatfox-recent-normalization`
- `urlhaus-recent-normalization`
- `cisa-kev-catalog-normalization`

Current tracked raw streams:

- `threatfox/recent`
- `cisa-kev/catalog`
- `urlhaus/checkpoints`
- `urlhaus/deltas`
