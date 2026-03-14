# Staging Observability

This directory contains Helm values for the staging-first observability stack:

- `loki-values.yaml`
- `grafana-values.yaml`
- `fluent-bit-values.yaml`

The stack is deployed by Argo CD into the `observability` namespace and is intended to collect logs from the `staging` namespace.

After sync, access Grafana with:

```bash
kubectl port-forward -n observability svc/grafana 3000:80
```

Then open `http://localhost:3000`.
