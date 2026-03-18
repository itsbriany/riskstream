# RiskStream

A microservices-based threat intelligence platform for ingesting, processing, and analyzing security threat data from multiple sources.

## Architecture

RiskStream is built as a collection of microservices organized into logical groups:

```
riskstream/
├── services/          # Microservices
│   ├── api/           # API gateway
│   └── ingestion/     # Data ingestion services
│       ├── cisa-kev/  # CISA KEV catalog ingestion
│       └── threatfox/ # ThreatFox IOC ingestion
├── shared/            # Shared libraries
├── tests/             # Integration and E2E tests
│   ├── integration/
│   └── e2e/
```

## Services

### API Gateway (Port 8080)
Main entry point for external clients. Provides a unified interface to access threat intelligence.

### Ingestion Services
- **ThreatFox** (Port 8081): Ingests indicators of compromise from abuse.ch ThreatFox API
- **CISA KEV** (Port 8082): Ingests the CISA Known Exploited Vulnerabilities catalog and writes changed raw snapshots to MinIO

## Getting Started

### Prerequisites
- Python 3.11+
- Docker (optional)
- Kubernetes cluster (for production deployment)

### Running Locally

#### Individual Services
```bash
# API Gateway
cd services/api/src
python main.py

# ThreatFox Ingestion
cd services/ingestion/threatfox/src
python main.py

# CISA KEV Ingestion
cd services/ingestion/cisa-kev/src
python main.py
```

#### With Docker
```bash
# Build and run API gateway
cd services/api
docker build -t riskstream-api .
docker run -p 8080:8080 riskstream-api

# Build and run ThreatFox ingestion
cd services/ingestion/threatfox
docker build -t riskstream-threatfox .
docker run -p 8081:8081 riskstream-threatfox

# Build and run CISA KEV ingestion
cd services/ingestion/cisa-kev
docker build -t riskstream-cisa-kev .
docker run -p 8082:8082 riskstream-cisa-kev
```

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
