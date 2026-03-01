# riskstream

Riskstream is a streaming ML ranking system that prioritizes security signals based on contextual relevance, enabling consumers to focus on the highest-risk threats in near real time.

Built on Kubernetes with Argo CD GitOps and GitHub Actions CI/CD.

## Quick Start

### Prerequisites

- k3s cluster running locally (`kubectl` context pointing to it)
- `kubectl` and `kustomize`
- Docker (for local builds)

### Bootstrap Argo CD on k3s

```bash
chmod +x scripts/bootstrap-k3s.sh scripts/port-forward-argocd.sh
./scripts/bootstrap-k3s.sh
```

Access Argo CD:

```bash
./scripts/port-forward-argocd.sh
```

Get initial admin password:

```bash
kubectl -n argocd get secret argocd-initial-admin-secret \
  -o jsonpath="{.data.password}" | base64 -d; echo
```

Visit `https://localhost:8080` (username: `admin`, password from above)

### Local Development

Build and deploy locally to `local-dev` namespace:

```bash
./scripts/build-and-deploy-local.sh
```

Access the app:

```bash
# Check pods
kubectl get pods -n local-dev

# Stream logs
kubectl logs -n local-dev -l app.kubernetes.io/name=riskstream --tail=50 -f

# Port forward
kubectl port-forward -n local-dev svc/local-riskstream 8081:80

# Visit http://localhost:8081
```

Clean up:

```bash
kubectl delete namespace local-dev
```

## Contributing

See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for:
- Development setup (Python, VSCode, extensions)
- Local quality checks (Ruff, Black, pytest)
- Pre-push checklist
- CI quality gates

## Roadmap

- [X] GitOps CI/CD (Argo CD + Kustomize overlays)
- [ ] Stream ingestion + normalization
- [ ] Ranking API (baseline)
- [ ] Evaluation + feedback loop
- [ ] Continual training + monitoring

## Documentation

- [**Architecture**](docs/ARCHITECTURE.md) - Kubernetes structure, namespaces, Argo CD behavior, image tagging
- [**CI/CD Pipeline**](docs/CI-CD.md) - GitHub Actions, GHCR, deployment flow
- [**Contributing**](docs/CONTRIBUTING.md) - Development setup, tooling, quality standards

## Tech Stack

| Component | Tool |
|-----------|------|
| Container Orchestration | Kubernetes (k3s for local) |
| GitOps | Argo CD |
| Config Management | Kustomize |
| Registry | GitHub Container Registry (GHCR) |
| CI/CD | GitHub Actions |

## Repository Layout

```
.
├── .github/workflows/ci.yml
├── .vscode/
│   ├── extensions.json
│   └── settings.json
├── app/
│   ├── Dockerfile
│   └── main.py
├── docs/
│   ├── ARCHITECTURE.md
│   ├── CI-CD.md
│   └── CONTRIBUTING.md
├── k8s/
│   ├── argocd/
│   ├── base/
│   ├── namespaces/
│   └── overlays/
└── scripts/
    ├── bootstrap-k3s.sh
    ├── build-and-deploy-local.sh
    └── port-forward-argocd.sh
```

## Notes

- **Staging** environment auto-syncs from `main` branch
- **Production** environment requires manual sync for safety
- Demo app in `app/` serves for CI image publishing
- Local development uses `local-dev` overlay to isolate from staging/prod
