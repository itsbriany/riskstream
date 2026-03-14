# API Service

The main API gateway service for RiskStream. This service provides a unified interface for accessing threat intelligence data from various ingestion sources.

## Overview

This service acts as the primary entry point for external clients and orchestrates requests to backend microservices.

## API Endpoints

### Health Check
```
GET /healthz
```
Returns service health status.

### Service Info
```
GET /
```
Returns service metadata and environment information.

## Running Locally

### Using Python
```bash
cd src
python main.py
```

### Using Docker
```bash
docker build -t riskstream-api .
docker run -p 8080:8080 riskstream-api
```

## Environment Variables

- `PORT`: Service port (default: 8080)
- `ENVIRONMENT`: Deployment environment (default: unknown)

## Future Enhancements

- Service discovery for ingestion microservices
- Request routing and aggregation
- Authentication and authorization
- Rate limiting
- API documentation (OpenAPI/Swagger)
- Response caching
