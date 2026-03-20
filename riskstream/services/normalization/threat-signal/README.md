# Threat Signal Normalization Service

This batch component normalizes raw feed artifacts from `raw-feeds` into `threat_signal.v1` JSONL batches under `processed-data`.

It is intended to run as Kubernetes Jobs or CronJobs rather than as a long-running HTTP service.

## Schema contract

The canonical normalized-output contract lives under [`schemas/`](./schemas):

- [`threat_signal.v1.schema.json`](./schemas/threat_signal.v1.schema.json) is the machine-readable JSON Schema
- [`threat_signal.v1.md`](./schemas/threat_signal.v1.md) is the human-readable field guide

`threat_signal.v1` uses a strict top-level schema with sparse optional fields. Feed-specific metadata belongs under `source_details`.

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
