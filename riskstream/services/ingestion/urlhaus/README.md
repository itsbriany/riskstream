# URLhaus Ingestion Service

This microservice ingests the recent malware URL export from [abuse.ch URLhaus](https://urlhaus.abuse.ch/about/).

## API Endpoints

### Health Check
```text
GET /healthz
```

### Recent URLs
```text
GET /recent
```
Fetches the current URLhaus recent CSV export, parses it into JSON records, and returns it without persisting it.

### Ingest Recent URLs
```text
POST /ingestion/recent
```
Fetches the current URLhaus recent CSV export, writes a daily checkpoint when needed, writes an immutable delta when the feed content changes, and updates a mutable latest-state object used for diffing.

### Service Info
```text
GET /
```

## Environment Variables

- `PORT`: Service port (default: `8083`)
- `ENVIRONMENT`: Deployment environment (default: `unknown`)
- `URLHAUS_RECENT_URL`: URLhaus recent CSV export URL
- `URLHAUS_AUTH_KEY`: Optional URLhaus community auth key for upstream requests
- `S3_ENDPOINT`: MinIO/S3 endpoint for raw feed storage
- `S3_ACCESS_KEY`: MinIO/S3 access key for raw feed storage
- `S3_SECRET_KEY`: MinIO/S3 secret key for raw feed storage
- `S3_USE_SSL`: Whether to use TLS for MinIO/S3 connections
- `URLHAUS_HOT_RETENTION_DAYS`: Hot retention window before archive move (default: `30`)
- `URLHAUS_ARCHIVE_RETENTION_DAYS`: Archive retention window before delete (default: `180`)
- `URLHAUS_ARCHIVE_REFERENCE_TIME`: Optional ISO-8601 reference time override for archive testing

## Ingestion Behavior

- The Kubernetes CronJob triggers `POST /ingestion/recent` every 5 minutes
- The service fetches the current URLhaus recent CSV export on each run
- The first successful poll each UTC day writes `raw-feeds/urlhaus/checkpoints/YYYY/MM/DD/000000Z.json.gz`
- Changed polls write `raw-feeds/urlhaus/deltas/YYYY/MM/DD/<content_hash>.json.gz`
- The latest parsed feed state is maintained at `raw-feeds/urlhaus/state/latest.json.gz`
- Successful ingest responses include `changed`, `checkpoint_written`, `delta_written`, `delta_counts`, `checked_at`, and `content_hash`

## How MinIO Writes Work

Only `POST /ingestion/recent` writes to MinIO. `GET /recent` fetches and parses the current URLhaus feed, but does not persist anything.

Each `POST /ingestion/recent` run follows this sequence:

1. Fetch the current `csv_recent` export from URLhaus
2. Compute a content hash from the raw CSV
3. Read `raw-feeds/urlhaus/state/latest.json.gz` if it exists
4. Write the daily checkpoint if that UTC day does not already have one
5. If the content hash changed, write a delta and then overwrite `state/latest`

### What Gets Written

- `raw-feeds/urlhaus/checkpoints/YYYY/MM/DD/000000Z.json.gz`
  - Written once per UTC day on the first successful poll for that day
  - Contains metadata plus the full raw CSV payload
- `raw-feeds/urlhaus/deltas/YYYY/MM/DD/<content_hash>.json.gz`
  - Written only when the current feed differs from `state/latest`
  - Contains metadata plus `added`, `updated`, and `removed` records keyed by URLhaus `id`
- `raw-feeds/urlhaus/state/latest.json.gz`
  - Overwritten only when the current feed differs from the previous latest state
  - Contains the current parsed feed as `records_by_id`
  - Used for diffing on the next poll, not as a historical checkpoint

### Common Poll Scenarios

- First successful poll of a new UTC day:
  - writes a daily checkpoint
  - writes a delta
  - writes `state/latest`
- A poll 5 minutes later with no upstream changes:
  - writes nothing
  - returns `changed: false`
- A poll 5 minutes later with upstream changes:
  - writes a delta
  - overwrites `state/latest`
  - does not write another checkpoint if that day already has one

### Why You See Metadata

Each stored object is a small JSON envelope around the payload. The envelope includes fields such as:

- `source`
- `feed`
- `service`
- `content_hash`
- `fetched_at` or `updated_at`

The actual URLhaus data is then stored under `data` for checkpoints and deltas, or under `records_by_id` for `state/latest`.

## Archive Lifecycle

- A dedicated `urlhaus-archive-lifecycle` CronJob moves URLhaus checkpoints and deltas older than the hot retention window from `raw-feeds` into `archives`
- The lifecycle job never archives or deletes `raw-feeds/urlhaus/state/latest.json.gz`
- Archived URLhaus artifacts older than the archive retention window are deleted
- Lowering `URLHAUS_HOT_RETENTION_DAYS` alone is not enough to archive today's objects, because the lifecycle compares the date embedded in each object key to the current reference date

### Immediate Local-Dev Testing

To test archive behavior against live local-dev URLhaus data without waiting 30 days, run a one-off archive Job with a future reference time.

Recommended flow:

1. Trigger `POST /ingestion/recent` so the current day has live checkpoint and delta objects in `raw-feeds`
2. Deploy the updated `urlhaus-ingestion` image to local k3s
3. Create a one-off Job from the `urlhaus-archive-lifecycle` CronJob
4. Set `URLHAUS_ARCHIVE_REFERENCE_TIME` to at least 31 days after the object partition date
5. Stream the Job logs and inspect `raw-feeds` and `archives`

Example:

```bash
kubectl create job urlhaus-archive-lifecycle-now \
  --from=cronjob/urlhaus-archive-lifecycle \
  -n local-dev

kubectl set env job/urlhaus-archive-lifecycle-now \
  URLHAUS_ARCHIVE_REFERENCE_TIME=2026-04-19T00:00:00+00:00 \
  -n local-dev

kubectl logs -n local-dev job/urlhaus-archive-lifecycle-now -f
```

Expected result:

- `raw-feeds/urlhaus/checkpoints/...` and `raw-feeds/urlhaus/deltas/...` objects old enough relative to the override move into `archives/urlhaus/...`
- `raw-feeds/urlhaus/state/latest.json.gz` remains in place
- archive deletion does not occur unless the override is also beyond the archive retention window

## Running Locally

```bash
docker build -f riskstream/services/ingestion/urlhaus/Dockerfile -t urlhaus-ingestion .
docker run -p 8083:8083 -e URLHAUS_AUTH_KEY=your-urlhaus-auth-key urlhaus-ingestion
```

## Kubernetes Secret Setup

If you are using an auth key, create it out-of-band as a Kubernetes Secret and do not commit it to git.

Create the secret in each namespace where `urlhaus-ingestion` runs:

```bash
kubectl create secret generic urlhaus-secret \
  --from-literal=auth-key='your-urlhaus-auth-key' \
  -n local-dev
```

For staging or production, run the same command in the target namespace:

```bash
kubectl create secret generic urlhaus-secret \
  --from-literal=auth-key='your-urlhaus-auth-key' \
  -n staging
```

If the secret already exists, replace it with:

```bash
kubectl create secret generic urlhaus-secret \
  --from-literal=auth-key='your-urlhaus-auth-key' \
  -n local-dev \
  --dry-run=client -o yaml | kubectl apply -f -
```

## Troubleshooting

```bash
kubectl logs -n local-dev -l app=urlhaus-ingestion -f
pytest riskstream/tests/unit/test_urlhaus_ingestion.py -q
./scripts/run-urlhaus-integration-test.sh
./scripts/run-urlhaus-archive-lifecycle-integration-test.sh
```

To run all ingestion integration tests in sequence from one entrypoint:

```bash
./scripts/run-ingestion-integration-tests.sh
```
