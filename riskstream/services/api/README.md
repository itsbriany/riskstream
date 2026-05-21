# API Service

The main API gateway service for RiskStream. This service provides a unified interface for accessing threat intelligence data from various ingestion sources.

## Overview

This service acts as the primary entry point for external clients. It exposes
health and service metadata plus a deterministic ranking API over normalized
`threat_signal.v1` records stored in MinIO.

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

### Ranking Options
```
GET /v1/threats/ranking-options
```
Returns the supported ranking vocabulary for clients, including priorities,
environment scopes, signal kinds, artifact types, actions, and limit bounds.

### Rank Threats
```
POST /v1/threats:rank
```

Ranks normalized threat signals for SOC triage. The endpoint reads
`processed-data/normalized/threat-signals/threat_signal.v1/...`, deduplicates
records by signal identity, and returns top-N ranked cards.

Example request:

```json
{
  "tenant_id": "acme",
  "context": {
    "environment_scope": "all",
    "priorities": ["malware_delivery", "active_exploitation"]
  },
  "filters": {
    "signal_kinds": ["indicator", "vulnerability"],
    "artifact_types": ["url", "domain", "cve"],
    "actions": ["observed", "updated"],
    "min_score": 50
  },
  "limit": 25
}
```

If `time_window` is omitted, the API ranks records from the last 24 hours.
`limit` defaults to 25 and is capped at 100. Source filtering is intentionally
not part of the main client contract; ranking runs across all normalized
sources by default.

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
- `S3_ENDPOINT`: MinIO/S3 endpoint (default from shared storage client)
- `S3_ACCESS_KEY`: MinIO/S3 access key
- `S3_SECRET_KEY`: MinIO/S3 secret key
- `S3_USE_SSL`: Whether to use SSL/TLS for S3-compatible storage

## Future Enhancements

- Authentication and authorization
- Rate limiting
- API documentation (OpenAPI/Swagger)
- Stored tenant or asset context
- Analyst feedback capture
