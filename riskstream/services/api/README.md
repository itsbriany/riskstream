# API Service

The RiskStream API service exposes health, service metadata, and deterministic
threat ranking over normalized `threat_signal.v1` records.

## Overview

This service is the direct HTTP interface for consumers that need ranked threat
signals. It reads normalized JSONL objects from the `processed-data` MinIO
bucket, scores and deduplicates records by signal identity, and returns ranked
cards for SOC triage.

## API Endpoints

### Health Check
```text
GET /healthz
```
Returns:

```json
{"status": "ok"}
```

### Service Info
```text
GET /
```
Returns the service name and deployment environment:

```json
{
  "service": "riskstream-api",
  "environment": "local-dev"
}
```

### Ranking Options
```text
GET /v1/threats/ranking-options
```
Returns the supported ranking vocabulary for clients, including priorities,
environment scopes, signal kinds, artifact types, actions, defaults, and limit
bounds. Consumers should call this endpoint when building request forms or
validating ranking filters client-side.

### Rank Threats
```text
POST /v1/threats:rank
```

Ranks normalized threat signals for SOC triage. The endpoint reads
`processed-data/normalized/threat-signals/threat_signal.v1/...`, deduplicates
records by signal identity, and returns top-N ranked cards.

The API currently ranks across all normalized sources. Source filtering is
intentionally not part of the public request contract.

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
`limit` defaults to 25 and is capped at 100.

## Rank Request Contract

`POST /v1/threats:rank` accepts a JSON object with these fields:

- `tenant_id`: Optional string. Defaults to `"default"`.
- `time_window`: Optional object with `since` and `until` ISO 8601 timestamps. If provided, both timestamps must include a timezone and `since` must be before or equal to `until`.
- `context.environment_scope`: Optional string. Defaults to `"all"`. Supported values are returned by `/v1/threats/ranking-options`.
- `context.priorities`: Optional array of strings. Values must be from the supported priorities list.
- `filters.signal_kinds`: Optional array of strings. Supported values: `indicator`, `vulnerability`.
- `filters.artifact_types`: Optional array of strings. Supported values: `url`, `domain`, `ip`, `hash`, `cve`.
- `filters.actions`: Optional array of strings. Supported values: `observed`, `updated`, `removed`. Defaults to `["observed", "updated"]`.
- `filters.tags_any`: Optional array of strings. Matches against normalized labels and source detail text.
- `filters.min_score`: Optional integer from `0` to `100`.
- `limit`: Optional positive integer. Defaults to `25`; values above `100` are capped to `100`.

Invalid request bodies return `400` with:

```json
{"error": "request body must be valid JSON"}
```

Validation failures also return `400` with an `error` message. Unexpected
ranking failures return `500` with an `error` message.

## Rank Response Contract

Successful ranking responses include:

```json
{
  "request_id": "req_20260521_153453_11e9d63c",
  "tenant_id": "acme",
  "ranker_version": "deterministic-v1",
  "generated_at": "2026-05-21T15:34:53Z",
  "time_window": {
    "since": "2026-05-20T15:34:53Z",
    "until": "2026-05-21T15:34:53Z"
  },
  "result_count": 1,
  "results": [
    {
      "rank": 1,
      "score": 95,
      "severity": "critical",
      "signal": {
        "signal_kind": "indicator",
        "artifact_type": "url",
        "artifact_value": "https://example.test/payload"
      },
      "summary": "Online malware delivery URL observed in recent threat intelligence.",
      "sources": ["urlhaus"],
      "labels": ["Mozi", "malware_download", "online"],
      "reasons": [
        {
          "code": "active_malware_delivery",
          "message": "The signal is associated with online malware delivery infrastructure."
        }
      ],
      "raw_refs": [
        {
          "bucket": "raw-feeds",
          "object_key": "urlhaus/checkpoints/2026/04/24/example.json.gz",
          "row_number": 1
        }
      ]
    }
  ]
}
```

Each result may also include `evidence_url`, `first_seen_at`, and
`last_seen_at` when those values exist in the normalized records.

Severity is derived from score:

- `critical`: score `>= 90`
- `high`: score `>= 70`
- `medium`: score `>= 40`
- `low`: score `< 40`

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
python -m pip install minio
PYTHONPATH=. python riskstream/services/api/src/main.py
```

### Using Docker
```bash
docker build -f riskstream/services/api/Dockerfile -t riskstream-api .
docker run -p 8080:8080 riskstream-api
```

## Environment Variables

- `PORT`: Service port (default: 8080)
- `ENVIRONMENT`: Deployment environment (default: unknown)
- `LOG_LEVEL`: Structured log level (default: INFO)
- `S3_ENDPOINT`: MinIO/S3 endpoint (default: localhost:9000 through the shared storage client; Kubernetes sets this to minio:9000)
- `S3_ACCESS_KEY`: MinIO/S3 access key
- `S3_SECRET_KEY`: MinIO/S3 secret key
- `S3_USE_SSL`: Whether to use SSL/TLS for S3-compatible storage
- `S3_REGION`: S3 region (default: us-east-1)

## Future Enhancements

- Authentication and authorization
- Rate limiting
- Stored tenant or asset context
- Analyst feedback capture
