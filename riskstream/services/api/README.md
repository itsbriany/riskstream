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
Consumers should call this endpoint when building request forms or validating
ranking filters client-side.

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


## Consumer Access

The API is exposed inside Kubernetes as the `riskstream` Service. For manual
testing from your host, port-forward the service:

```bash
kubectl port-forward -n local-dev svc/riskstream 3001:80
```

Then call the API at `http://localhost:3001`.

If you need to reach the API from a remote workstation on a trusted network,
bind the forwarded port to the host network interface:

```bash
kubectl port-forward --address 0.0.0.0 -n local-dev svc/riskstream 3001:80
```

Then call `http://<remote-host-ip>:3001` from the remote machine.

### Manual Smoke Test

Run the host-side smoke test after starting the port-forward:

```bash
./scripts/manual-test-api.sh
```

Override the target base URL when testing through a remote host:

```bash
API_BASE_URL=http://<remote-host-ip>:3001 ./scripts/manual-test-api.sh
```

The script verifies consumer-facing reachability and request shape. It does not
seed normalized threat data, so a successful ranking request may return
`result_count: 0` in a fresh environment.

### cURL Examples

Health check:

```bash
curl -sS http://localhost:3001/healthz
```

Service metadata:

```bash
curl -sS http://localhost:3001/
```

Supported ranking values:

```bash
curl -sS http://localhost:3001/v1/threats/ranking-options
```

Rank recent production-relevant malware and exploitation signals:

```bash
curl -sS http://localhost:3001/v1/threats:rank \
  -H 'Content-Type: application/json' \
  -d '{
    "tenant_id": "acme",
    "context": {
      "environment_scope": "production",
      "priorities": ["malware_delivery", "active_exploitation"]
    },
    "filters": {
      "signal_kinds": ["indicator", "vulnerability"],
      "artifact_types": ["url", "domain", "cve"],
      "actions": ["observed", "updated"],
      "min_score": 50
    },
    "limit": 25
  }'
```

Use an explicit time window when you need reproducible queries:

```bash
curl -sS http://localhost:3001/v1/threats:rank \
  -H 'Content-Type: application/json' \
  -d '{
    "time_window": {
      "since": "2026-04-24T00:00:00Z",
      "until": "2026-04-25T00:00:00Z"
    },
    "filters": {
      "artifact_types": ["url"],
      "tags_any": ["Mozi"],
      "min_score": 70
    },
    "limit": 10
  }'
```

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
- Stored tenant or asset context
- Analyst feedback capture
