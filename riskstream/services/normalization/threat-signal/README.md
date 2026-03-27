# Threat Signal Normalization Service

This batch component normalizes raw feed artifacts from `raw-feeds` into schema-versioned `threat_signal.v1` JSONL batches under `processed-data`.

It is intended to run as Kubernetes Jobs or CronJobs rather than as a long-running HTTP service.

## Schema contract

The canonical normalized-output contract lives under [`schemas/`](./schemas):

- [`threat_signal.v1.schema.json`](./schemas/threat_signal.v1.schema.json) is the machine-readable JSON Schema
- [`threat_signal.v1.md`](./schemas/threat_signal.v1.md) is the human-readable field guide

`threat_signal.v1` uses a strict top-level schema with sparse optional fields. Feed-specific metadata belongs under `source_details`.

Normalized outputs are written under:

- `processed-data/normalized/threat-signals/threat_signal.v1/...`

Normalization progress is tracked under:

- `processed-data/normalization-state/threat-signal/threat_signal.v1/...`

Checkpoint state is kept per raw stream:

- `threatfox/recent`
- `cisa-kev/catalog`
- `urlhaus/checkpoints`
- `urlhaus/deltas`

## Entrypoints

This component is meant to run inside Kubernetes, not as an ad hoc local Python command.

To run a one-off normalization pass in the cluster, create a Job from the existing CronJob template.

ThreatFox:

```bash
kubectl delete job threatfox-recent-normalization-now -n local-dev --ignore-not-found
kubectl create job threatfox-recent-normalization-now \
  --from=cronjob/threatfox-recent-normalization \
  -n local-dev
kubectl logs -n local-dev job/threatfox-recent-normalization-now -f
```

URLhaus:

```bash
kubectl delete job urlhaus-recent-normalization-now -n local-dev --ignore-not-found
kubectl create job urlhaus-recent-normalization-now \
  --from=cronjob/urlhaus-recent-normalization \
  -n local-dev
kubectl logs -n local-dev job/urlhaus-recent-normalization-now -f
```

These Jobs run the same container entrypoint defined in the CronJobs:

- `python riskstream/services/normalization/threat-signal/src/main.py --source threatfox`
- `python riskstream/services/normalization/threat-signal/src/main.py --source urlhaus`
- `python riskstream/services/normalization/threat-signal/src/main.py --source cisa-kev --feed catalog`

## Incremental processing and replay

Normal source/feed runs are incremental.

- The normalizer stores a checkpoint per raw stream in MinIO.
- On first run for a stream, it bootstraps by reconciling already-normalized raw artifacts.
- Later runs resume from the last processed raw object key instead of scanning for missing normalized outputs across the full history.

For recovery or schema backfill, use bounded replay:

```bash
python riskstream/services/normalization/threat-signal/src/main.py \
  --source threatfox \
  --replay-from-raw-object-key threatfox/recent/2026/03/14/173753Z.json \
  --replay-limit 10
```

Replay reads a bounded range of raw artifacts without advancing the normal checkpoint.
