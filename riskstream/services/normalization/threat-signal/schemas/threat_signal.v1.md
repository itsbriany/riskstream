# Threat Signal v1

This document defines the normalized `threat_signal.v1` contract emitted by the threat-signal normalizer into `processed-data`.

The machine-readable schema lives in [threat_signal.v1.schema.json](./threat_signal.v1.schema.json).

## Contract shape

Required top-level fields:

- `schema_version`
- `source`
- `feed`
- `signal_kind`
- `action`
- `artifact_type`
- `artifact_value`
- `external_id`
- `raw_ref`

Optional top-level fields:

- `first_seen_at`
- `last_seen_at`
- `classification`
- `confidence`
- `family`
- `reporter`
- `evidence_url`
- `status`
- `tags`
- `source_details`

## Sparse records

`threat_signal.v1` is intentionally sparse.

- Optional fields are omitted when the source feed cannot provide them.
- The normalizer does not emit `null` placeholders for unknown values.
- Consumers must treat missing optional fields as unknown, not invalid.

Examples:

- ThreatFox may emit `confidence` and `family`.
- URLhaus may emit `status` and `evidence_url`.
- Both use the same required core fields.

## Field notes

- `signal_kind` is `indicator` for ThreatFox and URLhaus today. `vulnerability` is reserved for later feeds such as CISA KEV.
- `artifact_type` is the normalized entity type used by downstream ranking and filtering.
- `raw_ref` points back to the exact raw object and row that produced the normalized record.
- `source_details` is the only intentionally flexible part of the schema. Top-level fields are strict, but feed-specific metadata may evolve inside `source_details.<source>`.

## Versioning

- Additive changes that only introduce new optional fields remain within `threat_signal.v1`.
- Breaking changes to required fields, field meaning, or structural rules require a new schema version such as `threat_signal.v2`.

## Examples

ThreatFox:

```json
{
  "schema_version": "threat_signal.v1",
  "source": "threatfox",
  "feed": "recent",
  "signal_kind": "indicator",
  "action": "observed",
  "artifact_type": "domain",
  "artifact_value": "cache-dist-5.vitagrazia.in.net",
  "external_id": "1765567",
  "first_seen_at": "2026-03-13T21:47:34+00:00",
  "last_seen_at": "2026-03-13T21:47:41+00:00",
  "classification": "payload_delivery",
  "confidence": 100,
  "family": "ClearFake",
  "reporter": "anonymous",
  "tags": ["ClearFake"],
  "raw_ref": {
    "bucket": "raw-feeds",
    "object_key": "threatfox/recent/2026/03/14/173753Z.json",
    "row_number": 1
  },
  "source_details": {
    "threatfox": {
      "malware": "js.clearfake"
    }
  }
}
```

URLhaus:

```json
{
  "schema_version": "threat_signal.v1",
  "source": "urlhaus",
  "feed": "recent",
  "signal_kind": "indicator",
  "action": "observed",
  "artifact_type": "url",
  "artifact_value": "http://221.200.214.87:54591/i",
  "external_id": "3799807",
  "first_seen_at": "2026-03-19T14:49:13+00:00",
  "last_seen_at": "2026-03-19T14:49:13+00:00",
  "classification": "malware_download",
  "status": "online",
  "reporter": "geenensp",
  "tags": ["32-bit", "elf", "mips", "Mozi"],
  "evidence_url": "https://urlhaus.abuse.ch/url/3799807/",
  "raw_ref": {
    "bucket": "raw-feeds",
    "object_key": "urlhaus/deltas/2026/03/19/abc123.json.gz",
    "row_number": 1,
    "section": "added"
  },
  "source_details": {
    "urlhaus": {
      "url_status": "online",
      "urlhaus_link": "https://urlhaus.abuse.ch/url/3799807/"
    }
  }
}
```
