# CI/CD Pipeline

## GitHub Actions Workflow

Workflow file: `.github/workflows/ci.yml`

### Trigger Events

- **Pull Request to `main`**: Build image, no push
- **Push to `main`**: Build and push image to GHCR
- **Manual dispatch** (`workflow_dispatch`)

### Build & Push Job

```
ubuntu-latest runner
├── Checkout code
├── Set up Docker Buildx (for multi-platform builds)
├── Log in to GHCR (on push to main)
├── Generate tags
│   ├── ghcr.io/r0kit-sec/riskstream:<sha>
│   ├── ghcr.io/r0kit-sec/riskstream:main
│   └── ghcr.io/r0kit-sec/riskstream:latest
└── Build & push image (push only on main)
```

### Permissions

The job requires:
- `contents: read` - Read repository code
- `packages: write` - Push to GHCR

These permissions use the auto-generated `GITHUB_TOKEN` (no manual setup needed).

## Image Publishing

### Build Context

- **Dockerfile:** `./app/Dockerfile`
- **Base image:** `python:3.12-slim`

### Image Tags (on push to main)

| Tag | Purpose |
|-----|---------|
| `ghcr.io/r0kit-sec/riskstream:main` | Latest from `main` branch; used by Argo CD for staging |
| `ghcr.io/r0kit-sec/riskstream:latest` | Latest release alias |
| `ghcr.io/r0kit-sec/riskstream:<sha>` | Commit-specific digest for traceability |

### GHCR Setup

1. Ensure your GitHub org/repo allows publishing to GHCR
2. Workflow uses `${{ secrets.GITHUB_TOKEN }}` (auto-provided by GitHub Actions)
3. No manual token creation needed

### Private Container Images

If your GHCR package is private:

1. Create an image pull secret in `staging` and `production`:
   ```bash
   kubectl create secret docker-registry ghcr-secret \
     --docker-server=ghcr.io \
     --docker-username=<gh-username> \
     --docker-password=<ghcr-token> \
     -n staging
   ```

2. Attach to service account:
   ```yaml
   apiVersion: v1
   kind: ServiceAccount
   metadata:
     name: default
     namespace: staging
   imagePullSecrets:
     - name: ghcr-secret
   ```

## Deployment Flow

```
Developer push to main
        ↓
GitHub Actions CI
├── Build Docker image
├── Push tags to GHCR
└── Report status
        ↓
Argo CD (watches main)
├── Detects new image tags
├── Syncs k8s/overlays/staging
└── Staging auto-updates within minutes
        ↓
Production (manual sync)
├── DevOps team reviews
├── Manually triggers sync
└── Production updates
```

## Caching

The workflow uses GitHub Actions build cache (`type=gha`) to speed up rebuilds:
- Layer cache persists across builds
- Subsequent builds skip unchanged layers
- Significantly reduces build time on repeated pushes
