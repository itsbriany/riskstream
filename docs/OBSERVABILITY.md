# Observability

RiskStream uses a staging-first log aggregation stack built from:

- Fluent Bit
- Loki
- Grafana

The stack is deployed into the `observability` namespace and collects logs from the `staging`, `production`, and `local-dev` namespaces.

## Accessing Grafana

```bash
kubectl port-forward -n observability svc/grafana 3000:80
```

Open `http://localhost:3000`.

## Suggested LogQL Queries

All staging logs:

```logql
{namespace="staging"}
```

All local-dev logs:

```logql
{namespace="local-dev"}
```

All production logs:

```logql
{namespace="production"}
```

ThreatFox ingestion logs:

```logql
{namespace="staging", container="threatfox-ingestion"}
```

ThreatFox ingestion logs in local-dev:

```logql
{namespace="local-dev", container="threatfox-ingestion"}
```

ThreatFox ingestion logs in production:

```logql
{namespace="production", container="threatfox-ingestion"}
```

ThreatFox structured JSON logs:

```logql
{namespace="staging", container="threatfox-ingestion"} | json
```

ThreatFox failed requests:

```logql
{namespace="staging", container="threatfox-ingestion"} | json | event="request_failed"
```

All RiskStream app logs by pod:

```logql
{namespace="staging"} |= "riskstream"
```

All RiskStream logs across all application namespaces:

```logql
{namespace=~"staging|production|local-dev"}
```
