# RiskStream Services

This directory contains all microservices that comprise the RiskStream threat intelligence platform.

## Service Groups

### API
Main API gateway that provides a unified interface for external clients.
- Canonical doc: `api/README.md`

### Ingestion
Services that collect threat intelligence from external sources.
- **ThreatFox**: `ingestion/threatfox/README.md`
- **CISA KEV**: `ingestion/cisa-kev/README.md`

## Service Architecture

Each service is independently deployable and follows these principles:

1. **Self-contained**: Each service has its own dependencies and can run standalone
2. **Single responsibility**: Each service focuses on one specific domain
3. **API-first**: Services expose RESTful APIs for communication
4. **Health monitoring**: All services implement `/healthz` endpoints
5. **Configuration**: Environment-based configuration via environment variables

## Structure

- `api/` contains gateway services
- `ingestion/` contains source-specific ingestion services

Each service is expected to keep its code, container definition, and canonical README together in its own directory.

## Running Services

### Development
Run individual services directly:
```bash
cd services/<service-name>/src
python main.py
```

Use the service README as the source of truth for environment variables, ports, endpoints, and local examples.

### Docker
Build and run with Docker:
```bash
cd services/<service-name>
docker build -t riskstream-<service-name> .
docker run -p <port>:<port> riskstream-<service-name>
```

### Production
Deploy using Kubernetes manifests in the `/k8s` directory.

## Adding New Services

To add a new service:

1. Create a directory under the appropriate group (`api`, `ingestion`, etc.)
2. Implement the service following the established patterns
3. Add a `Dockerfile` for containerization
4. Create a `README.md` documenting the service as the canonical source of truth
5. Add Kubernetes manifests if needed
6. Update this README with a short index entry and link
