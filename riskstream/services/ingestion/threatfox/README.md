# ThreatFox Ingestion Service

This microservice ingests threat intelligence data from the [abuse.ch ThreatFox](https://threatfox.abuse.ch/) community API.

## Overview

ThreatFox is a free platform for sharing indicators of compromise (IOCs) associated with malware. This service provides:

- Real-time threat data ingestion
- IOC search capabilities
- Malware family tagging
- RESTful API for threat data access

## API Endpoints

### Health Check
```
GET /healthz
```
Returns service health status.

### Recent Threats
```
GET /recent
```
Fetches IOCs from the last 24 hours.

### Ingest Recent Threats
```
POST /ingest/recent
```
Fetches the latest ThreatFox feed and persists a timestamped raw snapshot to the `raw-feeds` MinIO bucket under `threatfox/recent/...`.

### Service Info
```
GET /
```
Returns service metadata.

## Running Locally

### Using Python
```bash
cd src
export THREATFOX_AUTH_KEY=your-threatfox-auth-key
python main.py
```

### Using Docker
```bash
docker build -t threatfox-ingestion .
docker run -e THREATFOX_AUTH_KEY=your-threatfox-auth-key -p 8081:8081 threatfox-ingestion
```

## Environment Variables

- `PORT`: Service port (default: 8081)
- `ENVIRONMENT`: Deployment environment (default: unknown)
- `THREATFOX_AUTH_KEY`: ThreatFox API auth key required for upstream requests
- `S3_ENDPOINT`: MinIO/S3 endpoint for raw feed storage
- `S3_ACCESS_KEY`: MinIO/S3 access key for raw feed storage
- `S3_SECRET_KEY`: MinIO/S3 secret key for raw feed storage
- `S3_USE_SSL`: Whether to use TLS for MinIO/S3 connections

## Kubernetes Secret Setup

The ThreatFox auth key should be created out-of-band as a Kubernetes Secret and not committed to git.

Create the secret in each namespace where `threatfox-ingestion` runs:

```bash
kubectl create secret generic threatfox-secret \
  --from-literal=auth-key='your-threatfox-auth-key' \
  -n local-dev
```

For staging or production, run the same command in the target namespace:

```bash
kubectl create secret generic threatfox-secret \
  --from-literal=auth-key='your-threatfox-auth-key' \
  -n staging
```

If the secret already exists, replace it with:

```bash
kubectl create secret generic threatfox-secret \
  --from-literal=auth-key='your-threatfox-auth-key' \
  -n local-dev \
  --dry-run=client -o yaml | kubectl apply -f -
```

## Troubleshooting

Use structured logs and tests as the primary troubleshooting workflow for ThreatFox:

```bash
# Follow ThreatFox logs in local-dev
kubectl logs -n local-dev -l app=threatfox-ingestion -f
```

For isolated behavior checks, run the ThreatFox unit tests:

```bash
pytest riskstream/tests/unit/test_threatfox_ingestion.py -q
```

For service-level validation inside Kubernetes, run the in-cluster integration test:

```bash
./scripts/run-threatfox-integration-test.sh
```

To run both ingestion integration tests in sequence from one entrypoint:

```bash
./scripts/run-ingestion-integration-tests.sh
```

## ThreatFox API

The service uses the [ThreatFox API v1](https://threatfox.abuse.ch/api/) which provides:
- Recent IOCs (last N days)
- IOC search by value
- IOC lookup by ID
- Tag-based queries (malware families)

## Architecture

```
src/
├── main.py     # HTTP server and request handling
├── client.py   # ThreatFox API client
└── models.py   # Data models for threat indicators
```

## Future Enhancements

- Scheduled polling of ThreatFox API
- Data persistence (database integration)
- Message queue for downstream processing
- Advanced filtering and enrichment
- Metrics and monitoring
