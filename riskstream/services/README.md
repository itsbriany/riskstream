# RiskStream Services

This directory contains all microservices that comprise the RiskStream threat intelligence platform.

## Service Groups

### API
Main API gateway that provides a unified interface for external clients.
- **Port**: 8080

### Ingestion
Services that collect threat intelligence from external sources.
- **ThreatFox**: abuse.ch ThreatFox IOC ingestion (Port: 8081)

## Service Architecture

Each service is independently deployable and follows these principles:

1. **Self-contained**: Each service has its own dependencies and can run standalone
2. **Single responsibility**: Each service focuses on one specific domain
3. **API-first**: Services expose RESTful APIs for communication
4. **Health monitoring**: All services implement `/healthz` endpoints
5. **Configuration**: Environment-based configuration via environment variables

## Directory Structure

```
services/
├── api/                    # API gateway service
│   ├── src/
│   ├── Dockerfile
│   └── README.md
└── ingestion/             # Data ingestion services
    ├── threatfox/         # ThreatFox IOC ingestion
    │   ├── src/
    │   ├── Dockerfile
    │   ├── requirements.txt
    │   └── README.md
    └── README.md
```

## Running Services

### Development
Run individual services directly:
```bash
cd services/<service-name>/src
python main.py
```

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
4. Create a `README.md` documenting the service
5. Add Kubernetes manifests if needed
6. Update this README with the new service information
