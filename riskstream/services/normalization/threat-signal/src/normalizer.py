from __future__ import annotations

import argparse
import csv
import gzip
import json
import time
from datetime import datetime, timezone
from io import BytesIO, StringIO
from typing import Any

from riskstream.shared.utils.storage import StorageClient


RAW_FEEDS_BUCKET = "raw-feeds"
PROCESSED_DATA_BUCKET = "processed-data"
THREAT_SIGNAL_SCHEMA_VERSION = "threat_signal.v1"
NORMALIZED_PREFIX = "normalized/threat-signals"
RAW_OBJECT_READ_RETRY_ATTEMPTS = 10
RAW_OBJECT_READ_RETRY_DELAY_SECONDS = 0.5
SOURCE_PREFIXES = {
    "threatfox": {"recent": ["threatfox/recent/"]},
    "urlhaus": {"recent": ["urlhaus/checkpoints/", "urlhaus/deltas/"]},
}


def parse_threatfox_timestamp(value: str | None) -> str | None:
    if not value:
        return None
    return (
        datetime.strptime(value, "%Y-%m-%d %H:%M:%S UTC")
        .replace(tzinfo=timezone.utc)
        .isoformat()
    )


def parse_urlhaus_timestamp(value: str | None) -> str | None:
    if not value:
        return None
    return datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(
        tzinfo=timezone.utc
    ).isoformat()


def split_urlhaus_tags(raw_tags: str | None) -> list[str]:
    if not raw_tags:
        return []
    return [tag.strip() for tag in raw_tags.split(",") if tag.strip()]


def decode_json_bytes(raw_bytes: bytes) -> dict:
    if raw_bytes[:2] == b"\x1f\x8b":
        raw_bytes = gzip.decompress(raw_bytes)
    return json.loads(raw_bytes.decode("utf-8"))


def read_json_object(storage: StorageClient, bucket: str, object_key: str) -> dict:
    # Retry briefly when a just-written object is visible to one client before another.
    for attempt in range(RAW_OBJECT_READ_RETRY_ATTEMPTS):
        try:
            response = storage.get_client().get_object(bucket, object_key)
            try:
                return decode_json_bytes(response.read())
            finally:
                close = getattr(response, "close", None)
                if callable(close):
                    close()

                release_conn = getattr(response, "release_conn", None)
                if callable(release_conn):
                    release_conn()
        except Exception as exc:
            if (
                getattr(exc, "code", None) != "NoSuchKey"
                or attempt == RAW_OBJECT_READ_RETRY_ATTEMPTS - 1
            ):
                raise
            time.sleep(RAW_OBJECT_READ_RETRY_DELAY_SECONDS)

    raise RuntimeError(f"Unable to read raw object after retries: {bucket}/{object_key}")


def encode_jsonl_gzip(records: list[dict]) -> bytes:
    payload = "\n".join(json.dumps(record, sort_keys=True) for record in records)
    return gzip.compress(payload.encode("utf-8"))


def write_normalized_records(
    storage: StorageClient,
    object_key: str,
    records: list[dict],
) -> None:
    compressed_payload = encode_jsonl_gzip(records)
    storage.get_client().put_object(
        PROCESSED_DATA_BUCKET,
        object_key,
        BytesIO(compressed_payload),
        len(compressed_payload),
        content_type="application/gzip",
    )


def list_object_names(storage: StorageClient, bucket: str, prefix: str) -> list[str]:
    names = []
    for obj in storage.get_client().list_objects(bucket, prefix=prefix, recursive=True):
        object_name = getattr(obj, "object_name", None)
        if object_name:
            names.append(object_name)
    return sorted(names)


def object_exists(storage: StorageClient, bucket: str, object_key: str) -> bool:
    return object_key in list_object_names(storage, bucket, object_key)


def build_raw_ref(
    bucket: str,
    object_key: str,
    row_number: int,
    section: str | None = None,
) -> dict:
    raw_ref = {
        "bucket": bucket,
        "object_key": object_key,
        "row_number": row_number,
    }
    if section:
        raw_ref["section"] = section
    return raw_ref


def compact_record(record: dict[str, Any]) -> dict[str, Any]:
    compacted: dict[str, Any] = {}
    for key, value in record.items():
        if value is None:
            continue
        if value == "":
            continue
        if isinstance(value, list) and not value:
            continue
        if isinstance(value, dict) and not value:
            continue
        compacted[key] = value
    return compacted


def normalize_threatfox_snapshot(
    snapshot: dict,
    raw_bucket: str,
    raw_object_key: str,
) -> list[dict]:
    feed_payload = snapshot.get("data", {})
    rows = feed_payload.get("data", [])
    normalized_rows = []

    for row_number, row in enumerate(rows, start=1):
        family = row.get("malware_printable") or row.get("malware")
        normalized_rows.append(
            compact_record(
                {
                    "schema_version": THREAT_SIGNAL_SCHEMA_VERSION,
                    "source": "threatfox",
                    "feed": "recent",
                    "signal_kind": "indicator",
                    "action": "observed",
                    "artifact_type": row.get("ioc_type"),
                    "artifact_value": row.get("ioc"),
                    "external_id": str(row.get("id", "")).strip(),
                    "first_seen_at": parse_threatfox_timestamp(row.get("first_seen")),
                    "last_seen_at": parse_threatfox_timestamp(row.get("last_seen")),
                    "classification": row.get("threat_type"),
                    "confidence": row.get("confidence_level"),
                    "family": family,
                    "reporter": row.get("reporter"),
                    "tags": row.get("tags") or [],
                    "evidence_url": row.get("reference"),
                    "raw_ref": build_raw_ref(raw_bucket, raw_object_key, row_number),
                    "source_details": compact_record(
                        {
                            "threatfox": compact_record(
                                {
                                    "threat_type_desc": row.get("threat_type_desc"),
                                    "ioc_type_desc": row.get("ioc_type_desc"),
                                    "malware": row.get("malware"),
                                    "malware_alias": row.get("malware_alias"),
                                    "malware_malpedia": row.get("malware_malpedia"),
                                    "is_compromised": row.get("is_compromised"),
                                }
                            )
                        }
                    ),
                }
            )
        )

    return normalized_rows


def normalize_urlhaus_row(
    row: dict,
    raw_bucket: str,
    raw_object_key: str,
    row_number: int,
    action: str,
    section: str | None = None,
) -> dict:
    return compact_record(
        {
            "schema_version": THREAT_SIGNAL_SCHEMA_VERSION,
            "source": "urlhaus",
            "feed": "recent",
            "signal_kind": "indicator",
            "action": action,
            "artifact_type": "url",
            "artifact_value": row.get("url"),
            "external_id": str(row.get("id", "")).strip(),
            "first_seen_at": parse_urlhaus_timestamp(row.get("dateadded")),
            "last_seen_at": parse_urlhaus_timestamp(row.get("last_online")),
            "classification": row.get("threat"),
            "status": row.get("url_status") or row.get("status"),
            "reporter": row.get("reporter"),
            "tags": split_urlhaus_tags(row.get("tags")),
            "evidence_url": row.get("urlhaus_link"),
            "raw_ref": build_raw_ref(raw_bucket, raw_object_key, row_number, section),
            "source_details": compact_record(
                {
                    "urlhaus": compact_record(
                        {
                            "dateadded": row.get("dateadded"),
                            "last_online": row.get("last_online"),
                            "url_status": row.get("url_status") or row.get("status"),
                            "urlhaus_link": row.get("urlhaus_link"),
                            "reason": row.get("reason"),
                        }
                    )
                }
            ),
        }
    )


def parse_urlhaus_checkpoint_rows(snapshot: dict) -> list[dict[str, str]]:
    data = snapshot.get("data", {})
    raw_csv = data.get("raw_csv", "")
    data_lines = []
    for line in raw_csv.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            candidate = stripped.removeprefix("#").strip()
            if candidate.startswith("id,"):
                data_lines.append(candidate)
            continue
        data_lines.append(line)
    if not data_lines:
        return []

    reader = csv.DictReader(StringIO("\n".join(data_lines)))
    rows = []
    for row in reader:
        rows.append(
            {
                str(key): value.strip() if isinstance(value, str) else value
                for key, value in row.items()
            }
        )
    return rows


def normalize_urlhaus_checkpoint(
    snapshot: dict,
    raw_bucket: str,
    raw_object_key: str,
) -> list[dict]:
    rows = parse_urlhaus_checkpoint_rows(snapshot)
    return [
        normalize_urlhaus_row(
            row,
            raw_bucket=raw_bucket,
            raw_object_key=raw_object_key,
            row_number=row_number,
            action="observed",
        )
        for row_number, row in enumerate(rows, start=1)
    ]


def normalize_urlhaus_delta(
    delta_payload: dict,
    raw_bucket: str,
    raw_object_key: str,
) -> list[dict]:
    normalized_rows = []
    row_number = 0
    data = delta_payload.get("data", {})
    for section, action in (
        ("added", "observed"),
        ("updated", "updated"),
        ("removed", "removed"),
    ):
        for row in data.get(section, []):
            row_number += 1
            normalized_rows.append(
                normalize_urlhaus_row(
                    row,
                    raw_bucket=raw_bucket,
                    raw_object_key=raw_object_key,
                    row_number=row_number,
                    action=action,
                    section=section,
                )
            )
    return normalized_rows


def build_normalized_object_key(raw_object_key: str, source: str) -> str:
    if source == "threatfox" and raw_object_key.startswith("threatfox/recent/"):
        suffix = raw_object_key.removeprefix("threatfox/recent/").removesuffix(".json")
        return f"{NORMALIZED_PREFIX}/threatfox/recent/{suffix}.jsonl.gz"

    if raw_object_key.startswith("urlhaus/checkpoints/"):
        suffix = raw_object_key.removeprefix("urlhaus/checkpoints/")
        return f"{NORMALIZED_PREFIX}/urlhaus/recent/checkpoints/{suffix.removesuffix('.json.gz')}.jsonl.gz"

    if raw_object_key.startswith("urlhaus/deltas/"):
        suffix = raw_object_key.removeprefix("urlhaus/deltas/")
        return f"{NORMALIZED_PREFIX}/urlhaus/recent/deltas/{suffix.removesuffix('.json.gz')}.jsonl.gz"

    raise ValueError(f"Unsupported raw object key: {raw_object_key}")


def build_raw_artifact_event(payload: dict, raw_bucket: str, raw_object_key: str) -> dict:
    return compact_record(
        {
            "event_type": "raw_artifact_written",
            "source": payload.get("source"),
            "feed": payload.get("feed"),
            "bucket": raw_bucket,
            "object_key": raw_object_key,
            "content_hash": payload.get("content_hash"),
            "written_at": payload.get("fetched_at") or payload.get("updated_at"),
        }
    )


def normalize_raw_artifact(
    raw_object_key: str,
    raw_bucket: str = RAW_FEEDS_BUCKET,
    storage: StorageClient | None = None,
) -> dict:
    storage = storage or StorageClient()
    payload = read_json_object(storage, raw_bucket, raw_object_key)
    source = payload.get("source")

    if source == "threatfox":
        records = normalize_threatfox_snapshot(payload, raw_bucket, raw_object_key)
    elif source == "urlhaus" and raw_object_key.startswith("urlhaus/checkpoints/"):
        records = normalize_urlhaus_checkpoint(payload, raw_bucket, raw_object_key)
    elif source == "urlhaus" and raw_object_key.startswith("urlhaus/deltas/"):
        records = normalize_urlhaus_delta(payload, raw_bucket, raw_object_key)
    else:
        raise ValueError(f"Unsupported raw artifact: {raw_object_key}")

    trigger_event = build_raw_artifact_event(payload, raw_bucket, raw_object_key)
    normalized_object_key = build_normalized_object_key(raw_object_key, source)
    write_normalized_records(storage, normalized_object_key, records)
    return {
        "source": source,
        "raw_bucket": raw_bucket,
        "raw_object_key": raw_object_key,
        "normalized_bucket": PROCESSED_DATA_BUCKET,
        "normalized_object_key": normalized_object_key,
        "records_count": len(records),
        "trigger_event": trigger_event,
    }


def get_source_prefixes(source: str, feed: str) -> list[str]:
    try:
        return SOURCE_PREFIXES[source][feed]
    except KeyError as exc:
        raise ValueError(f"Unsupported source/feed combination: {source}/{feed}") from exc


def list_pending_raw_object_keys(
    source: str,
    feed: str = "recent",
    raw_bucket: str = RAW_FEEDS_BUCKET,
    normalized_bucket: str = PROCESSED_DATA_BUCKET,
    storage: StorageClient | None = None,
) -> list[str]:
    storage = storage or StorageClient()
    pending = []

    for prefix in get_source_prefixes(source, feed):
        for raw_object_key in list_object_names(storage, raw_bucket, prefix):
            normalized_object_key = build_normalized_object_key(raw_object_key, source)
            if not object_exists(storage, normalized_bucket, normalized_object_key):
                pending.append(raw_object_key)

    return pending


def normalize_pending_artifacts(
    source: str,
    feed: str = "recent",
    raw_bucket: str = RAW_FEEDS_BUCKET,
    storage: StorageClient | None = None,
) -> list[dict]:
    storage = storage or StorageClient()
    results = []

    for raw_object_key in list_pending_raw_object_keys(
        source=source,
        feed=feed,
        raw_bucket=raw_bucket,
        storage=storage,
    ):
        results.append(
            normalize_raw_artifact(
                raw_object_key=raw_object_key,
                raw_bucket=raw_bucket,
                storage=storage,
            )
        )

    return results


def run() -> None:
    parser = argparse.ArgumentParser(
        description="Normalize RiskStream raw artifacts into threat-signal JSONL batches."
    )
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "--raw-object-key",
        help="Normalize a single raw artifact by exact object key.",
    )
    target_group.add_argument(
        "--source",
        choices=sorted(SOURCE_PREFIXES.keys()),
        help="Normalize all pending raw artifacts for a source/feed.",
    )
    parser.add_argument(
        "--feed",
        default="recent",
        help="Feed name to normalize when using --source. Defaults to recent.",
    )
    parser.add_argument(
        "--raw-bucket",
        default=RAW_FEEDS_BUCKET,
        help="Raw object bucket. Defaults to raw-feeds.",
    )
    args = parser.parse_args()

    if args.raw_object_key:
        result = normalize_raw_artifact(
            raw_object_key=args.raw_object_key,
            raw_bucket=args.raw_bucket,
        )
        print(json.dumps(result, sort_keys=True))
        return

    results = normalize_pending_artifacts(
        source=args.source,
        feed=args.feed,
        raw_bucket=args.raw_bucket,
    )
    print(
        json.dumps(
            {
                "source": args.source,
                "feed": args.feed,
                "processed_artifacts": len(results),
                "results": results,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    run()
