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

### Repository Layout

```
k8s/
├── base/                           # Shared manifests
│   ├── deployment.yaml
│   ├── service.yaml
│   └── kustomization.yaml
│
├── overlays/                       # Environment-specific configs
│   ├── local-dev/                  # Local k3s dev
│   │   ├── kustomization.yaml
│   │   └── patch.yaml
│   ├── staging/                    # Auto-synced from main
│   │   ├── kustomization.yaml
│   │   └── patch.yaml
│   └── production/                 # Manual sync
│       ├── kustomization.yaml
│       └── patch.yaml
│
├── argocd/                         # Argo CD configuration
│   ├── project.yaml                # AppProject definition
│   ├── staging-application.yaml    # Auto-sync to staging
│   ├── staging-observability-application.yaml # Staging observability stack
│   ├── production-application.yaml # Manual sync to production
│   └── kustomization.yaml
│
├── observability/                  # Observability Helm values
│   └── staging/
│       ├── fluent-bit-values.yaml
│       ├── grafana-values.yaml
│       └── loki-values.yaml
│
└── namespaces/                     # Namespace definitions
    ├── argocd.yaml
    ├── observability.yaml
    ├── staging.yaml
    ├── production.yaml
    └── kustomization.yaml
```

## Kustomize Strategy

**Base** (`k8s/base/`) contains the core application manifests:
- Generic `Deployment` with GHCR image reference
- `Service` for network access
- MinIO deployment and bucket-init job
- ThreatFox and CISA KEV ingestion deployments, services, and CronJobs

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
