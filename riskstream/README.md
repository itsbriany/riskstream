# RiskStream

A microservices-based threat intelligence platform for ingesting, processing, and analyzing security threat data from multiple sources.

## Architecture

RiskStream is organized into a few stable groups:

- `services/` - API and ingestion microservices
- `shared/` - shared libraries used across services
- `tests/` - integration and end-to-end test suites

Use the service index in [services/README.md](/home/r0kit/projects/interview_prep/riskstream/riskstream/services/README.md) to find the canonical README for a specific service.

## Services

### API Gateway
Main entry point for external clients. See `services/api/README.md` for service-specific details.

### Ingestion Services
- **ThreatFox**: See `services/ingestion/threatfox/README.md`
- **CISA KEV**: See `services/ingestion/cisa-kev/README.md`

## Getting Started

### Prerequisites
- Python 3.11+
- Docker (optional)
- Kubernetes cluster (for production deployment)

### Running Locally

#### Individual Services
```bash
cd services/<service>/src
python main.py
```

See the individual service README for required environment variables, ports, endpoints, and runtime behavior.

#### With Docker
```bash
cd services/<service>
docker build -t riskstream-<service> .
docker run -p <port>:<port> riskstream-<service>
```

Use the service README as the source of truth for concrete image names, env vars, and local commands.

## Testing

```bash
# Integration tests
pytest tests/integration/

# End-to-end tests
pytest tests/e2e/
```

## Deployment

Kubernetes manifests are available in the `/k8s` directory at the project root. Services can be deployed using kubectl or ArgoCD.

## Adding New Services

See [services/README.md](services/README.md) for guidelines on adding new microservices.

## Documentation

- Service-specific documentation: See individual service README files
- Architecture: `/docs/ARCHITECTURE.md` (project root)
- Contributing: `/docs/CONTRIBUTING.md` (project root)

## License

See LICENSE file in project root.
