# Contributing to Riskstream

Thank you for contributing! This guide covers development setup, tooling, and quality standards.

## Development Setup

### Prerequisites

- Python 3.12+
- Docker (for local container builds)
- k3s cluster (for testing deployments)
- VSCode (recommended)

### Getting Started

1. Clone the repository:
   ```bash
   git clone https://github.com/itsbriany/riskstream.git
   cd riskstream
   ```

2. Install development dependencies:
   ```bash
   pip install ruff black pytest
   ```

3. Install VSCode extensions (if using VSCode)

## VSCode Setup (Recommended)

The project includes VSCode configuration for automatic linting and formatting.

### Recommended Extensions

When you open the project in VSCode, you'll be prompted to install:

- **Ruff** (`charliermarsh.ruff`) - Fast Python linter
- **Black Formatter** (`ms-python.black-formatter`) - Code formatter
- **Python** (`ms-python.python`) - Language support
- **Pylance** (`ms-python.vscode-pylance`) - Type checking

**Quick install via Command Palette:**
1. Press `Ctrl+Shift+P` (or `Cmd+Shift+P` on Mac)
2. Type `Extensions: Show Recommended Extensions`
3. Click to install all

### Auto-formatting Behavior

With the included `.vscode/settings.json`, VSCode will automatically:

- Format code with Black on save
- Fix linting issues with Ruff on save
- Organize imports automatically
- Display an 88-character line ruler (Black's default)

## Code Quality Standards

### Linting with Ruff

Ruff is a fast Python linter that catches common issues:

```bash
# Check for issues
ruff check ./app

# Auto-fix issues
ruff check --fix ./app
```

### Formatting with Black

Black enforces consistent code style:

```bash
# Check formatting
black --check ./app

# Format code
black ./app
```

### Running Tests

```bash
# Run all tests
pytest ./app

# Run with verbose output
pytest ./app -v

# Run specific test file
pytest ./app/test_main.py
```

## CI Quality Gates

All pull requests and pushes to `main` run automated checks:

### Workflow Jobs

1. **Lint and Test Job** (must pass before container build)
   - Ruff linting (`ruff check`)
   - Black format validation (`black --check`)
   - pytest tests

2. **Container Build Job** (only runs if lint/test passes)
   - Build Docker image
   - Push to GHCR (on push to `main` only)

## Documentation Ownership

To keep docs maintainable, prefer one canonical document per topic:

- **Service behavior** lives in the service README beside the code
  - endpoints
  - environment variables
  - ports
  - schedules
  - persistence behavior
  - service-specific troubleshooting
- **Cross-cutting platform topics** live under `docs/`
  - architecture
  - CI/CD
  - MinIO/storage conventions
  - observability
- **Top-level READMEs** should stay navigational
  - overview
  - high-level structure
  - links to the canonical docs

When a feature changes a service, update the canonical service README first. Update overview or platform docs only when shared behavior actually changed. In general, prefer stable role-based descriptions in overview docs over detailed file inventories that are already discoverable from the repository itself.

### Pre-push Checklist

Before pushing, ensure your changes pass all checks locally:

```bash
# Run the same checks CI uses
ruff check ./app
black --check ./app
pytest ./app
```

**Tip:** If you're using VSCode with auto-formatting enabled, most issues will be caught and fixed automatically on save.

## Local Development Workflow

### 1. Make your changes

Edit files in `app/` or `k8s/`

### 2. Test locally

Build and deploy to local k3s:

```bash
./scripts/build-and-deploy-local.sh
```

Access the app:

```bash
kubectl port-forward -n local-dev svc/riskstream 8081:80
# Visit http://localhost:8081
```

### 3. Run quality checks

```bash
ruff check ./app
black --check ./app
pytest ./app
```

### 4. Commit and push

```bash
git add .
git commit -m "feat: your change description"
git push origin your-branch
```

### 5. Open a Pull Request

CI will automatically run lint, tests, and build checks.

## Kubernetes Changes

When modifying Kubernetes manifests in `k8s/`:

- **Base changes** (`k8s/base/`) affect all environments
- **Overlay changes** (`k8s/overlays/{staging,production,local-dev}`) are environment-specific
- Test with `kubectl kustomize k8s/overlays/<env>` before committing
- Deploy locally to verify: `kubectl apply -k k8s/overlays/local-dev -n local-dev`

## Questions?

- Check [Architecture docs](ARCHITECTURE.md) for system design
- Check [CI/CD docs](CI-CD.md) for pipeline details
- Open an issue for bugs or feature requests
