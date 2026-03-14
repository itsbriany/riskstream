# CI/CD Pipeline

## GitHub Actions Workflow

Workflow file: `.github/workflows/ci.yml`

### Trigger Events

- **Pull Request to `main`**: Run lint/tests, build image (no push)
- **Push to `main`**: Run lint/tests, build and push image to GHCR
- **Manual dispatch** (`workflow_dispatch`)

### Jobs

#### 1. Lint and Test Job

```
ubuntu-latest runner
├── Checkout code
├── Set up Python 3.12
├── Install dependencies (ruff, black, pytest)
├── Run ruff linting
├── Run black format check
└── Run pytest tests
```

**Quality gates:**
- Ruff must pass (no linting errors)
- Black format check must pass
- Tests run (soft-fail if no tests exist)

Container build **only proceeds if this job succeeds**.

#### 2. Container Build Job

```
ubuntu-latest runner
├── Checkout code
├── Set up Docker Buildx (for multi-platform builds)
├── Log in to GHCR (on push to main)
├── Generate tags
│   ├── ghcr.io/itsbriany/riskstream:<sha>
│   ├── ghcr.io/itsbriany/riskstream:main
│   └── ghcr.io/itsbriany/riskstream:latest
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
| `ghcr.io/itsbriany/riskstream:main` | Latest from `main` branch; used by Argo CD for staging |
| `ghcr.io/itsbriany/riskstream:latest` | Latest release alias |
| `ghcr.io/itsbriany/riskstream:<sha>` | Commit-specific digest for traceability |

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

![Riskstream CI/CD Pipeline](https://raw.githubusercontent.com/itsbriany/riskstream/refs/heads/main/docs/riskstream%20CI_CD.svg)

## Caching

The workflow uses GitHub Actions build cache (`type=gha`) to speed up rebuilds:
- Layer cache persists across builds
- Subsequent builds skip unchanged layers
- Significantly reduces build time on repeated pushes

## Developer Workflow

For local development setup, quality checks, and contribution guidelines, see [CONTRIBUTING.md](CONTRIBUTING.md).
