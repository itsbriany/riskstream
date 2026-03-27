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
NORMALIZED_SCHEMA_PREFIX = f"{NORMALIZED_PREFIX}/{THREAT_SIGNAL_SCHEMA_VERSION}"
CHECKPOINT_PREFIX = f"normalization-state/threat-signal/{THREAT_SIGNAL_SCHEMA_VERSION}"
RAW_OBJECT_READ_RETRY_ATTEMPTS = 10
RAW_OBJECT_READ_RETRY_DELAY_SECONDS = 0.5
SOURCE_STREAMS = {
    "cisa-kev": {
        "catalog": [{"stream": "catalog", "raw_prefix": "cisa-kev/catalog/"}]
    },
    "threatfox": {
        "recent": [{"stream": "recent", "raw_prefix": "threatfox/recent/"}]
    },
    "urlhaus": {
        "recent": [
            {"stream": "checkpoints", "raw_prefix": "urlhaus/checkpoints/"},
            {"stream": "deltas", "raw_prefix": "urlhaus/deltas/"},
        ]
    },
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


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


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


def read_optional_json_object(
    storage: StorageClient,
    bucket: str,
    object_key: str,
) -> dict[str, Any] | None:
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
        if getattr(exc, "code", None) in {"NoSuchKey", "NoSuchObject", "NoSuchVersion"}:
            return None
        raise


def encode_jsonl_gzip(records: list[dict]) -> bytes:
    payload = "\n".join(json.dumps(record, sort_keys=True) for record in records)
    return gzip.compress(payload.encode("utf-8"))


def encode_json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True).encode("utf-8")


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


def write_json_object(
    storage: StorageClient,
    bucket: str,
    object_key: str,
    payload: dict[str, Any],
) -> None:
    raw_payload = encode_json_bytes(payload)
    storage.get_client().put_object(
        bucket,
        object_key,
        BytesIO(raw_payload),
        len(raw_payload),
        content_type="application/json",
    )


def list_object_names(
    storage: StorageClient,
    bucket: str,
    prefix: str,
    start_after: str | None = None,
) -> list[str]:
    client = storage.get_client()
    kwargs: dict[str, Any] = {"prefix": prefix, "recursive": True}
    if start_after is not None:
        kwargs["start_after"] = start_after

    try:
        objects = client.list_objects(bucket, **kwargs)
    except TypeError:
        objects = client.list_objects(bucket, prefix=prefix, recursive=True)

    names = []
    for obj in objects:
        object_name = getattr(obj, "object_name", None)
        if object_name:
            names.append(object_name)

    if start_after is not None:
        names = [name for name in names if name > start_after]

    return sorted(names)


def object_exists(storage: StorageClient, bucket: str, object_key: str) -> bool:
    stat_object = getattr(storage.get_client(), "stat_object", None)
    if callable(stat_object):
        try:
            stat_object(bucket, object_key)
            return True
        except Exception as exc:
            if getattr(exc, "code", None) in {
                "NoSuchKey",
                "NoSuchObject",
                "NoSuchVersion",
            }:
                return False
            raise

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


def normalize_cisa_kev_catalog(
    snapshot: dict,
    raw_bucket: str,
    raw_object_key: str,
) -> list[dict]:
    rows = snapshot.get("data", {}).get("vulnerabilities", [])
    normalized_rows = []

    for row_number, row in enumerate(rows, start=1):
        cve_id = str(row.get("cveID", "")).strip()
        normalized_rows.append(
            compact_record(
                {
                    "schema_version": THREAT_SIGNAL_SCHEMA_VERSION,
                    "source": "cisa-kev",
                    "feed": "catalog",
                    "signal_kind": "vulnerability",
                    "action": "observed",
                    "artifact_type": "cve",
                    "artifact_value": cve_id,
                    "external_id": cve_id,
                    "raw_ref": build_raw_ref(raw_bucket, raw_object_key, row_number),
                    "source_details": compact_record(
                        {
                            "cisa-kev": compact_record(
                                {
                                    "vendorProject": row.get("vendorProject"),
                                    "product": row.get("product"),
                                    "vulnerabilityName": row.get("vulnerabilityName"),
                                    "dateAdded": row.get("dateAdded"),
                                    "shortDescription": row.get("shortDescription"),
                                    "requiredAction": row.get("requiredAction"),
                                    "dueDate": row.get("dueDate"),
                                    "knownRansomwareCampaignUse": row.get(
                                        "knownRansomwareCampaignUse"
                                    ),
                                    "notes": row.get("notes"),
                                    "cwes": row.get("cwes"),
                                }
                            )
                        }
                    ),
                }
            )
        )

    return normalized_rows


def build_normalized_object_key(raw_object_key: str, source: str) -> str:
    if source == "cisa-kev" and raw_object_key.startswith("cisa-kev/catalog/"):
        suffix = raw_object_key.removeprefix("cisa-kev/catalog/").removesuffix(".json")
        return f"{NORMALIZED_SCHEMA_PREFIX}/cisa-kev/catalog/{suffix}.jsonl.gz"

    if source == "threatfox" and raw_object_key.startswith("threatfox/recent/"):
        suffix = raw_object_key.removeprefix("threatfox/recent/").removesuffix(".json")
        return f"{NORMALIZED_SCHEMA_PREFIX}/threatfox/recent/{suffix}.jsonl.gz"

    if raw_object_key.startswith("urlhaus/checkpoints/"):
        suffix = raw_object_key.removeprefix("urlhaus/checkpoints/")
        return f"{NORMALIZED_SCHEMA_PREFIX}/urlhaus/recent/checkpoints/{suffix.removesuffix('.json.gz')}.jsonl.gz"

    if raw_object_key.startswith("urlhaus/deltas/"):
        suffix = raw_object_key.removeprefix("urlhaus/deltas/")
        return f"{NORMALIZED_SCHEMA_PREFIX}/urlhaus/recent/deltas/{suffix.removesuffix('.json.gz')}.jsonl.gz"

    raise ValueError(f"Unsupported raw object key: {raw_object_key}")


def build_checkpoint_object_key(raw_bucket: str, source: str, stream: str) -> str:
    return f"{CHECKPOINT_PREFIX}/{raw_bucket}/{source}/{stream}.json"


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


def get_source_streams(source: str, feed: str) -> list[dict[str, str]]:
    try:
        return SOURCE_STREAMS[source][feed]
    except KeyError as exc:
        raise ValueError(f"Unsupported source/feed combination: {source}/{feed}") from exc


def get_stream_for_raw_object_key(
    source: str,
    feed: str,
    raw_object_key: str,
) -> dict[str, str]:
    for stream in get_source_streams(source, feed):
        if raw_object_key.startswith(stream["raw_prefix"]):
            return stream
    raise ValueError(
        f"Raw object key does not match source/feed streams: {source}/{feed} {raw_object_key}"
    )


def get_raw_prefix_for_stream(source: str, feed: str, stream: str) -> str:
    for candidate in get_source_streams(source, feed):
        if candidate["stream"] == stream:
            return candidate["raw_prefix"]
    raise ValueError(f"Unsupported stream for source/feed: {source}/{feed}/{stream}")


def load_stream_checkpoint(
    storage: StorageClient,
    raw_bucket: str,
    source: str,
    stream: str,
) -> dict[str, Any] | None:
    return read_optional_json_object(
        storage,
        PROCESSED_DATA_BUCKET,
        build_checkpoint_object_key(raw_bucket, source, stream),
    )


def write_stream_checkpoint(
    storage: StorageClient,
    raw_bucket: str,
    source: str,
    feed: str,
    stream: str,
    last_processed_raw_object_key: str | None,
    last_processed_normalized_object_key: str | None,
    processed_artifacts_count: int,
    last_run_started_at: str,
    last_run_completed_at: str,
    last_error: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = compact_record(
        {
            "schema_version": THREAT_SIGNAL_SCHEMA_VERSION,
            "raw_bucket": raw_bucket,
            "raw_prefix": get_raw_prefix_for_stream(source, feed, stream),
            "source": source,
            "feed": feed,
            "stream": stream,
            "last_processed_raw_object_key": last_processed_raw_object_key,
            "last_processed_normalized_object_key": last_processed_normalized_object_key,
            "last_run_started_at": last_run_started_at,
            "last_run_completed_at": last_run_completed_at,
            "processed_artifacts_count": processed_artifacts_count,
            "last_error": last_error,
        }
    )
    write_json_object(
        storage,
        PROCESSED_DATA_BUCKET,
        build_checkpoint_object_key(raw_bucket, source, stream),
        payload,
    )
    return payload


def bootstrap_stream_checkpoint(
    storage: StorageClient,
    source: str,
    feed: str,
    stream: str,
    raw_prefix: str,
    raw_bucket: str,
    normalized_bucket: str = PROCESSED_DATA_BUCKET,
) -> dict[str, Any] | None:
    last_processed_raw_object_key = None
    last_processed_normalized_object_key = None
    processed_artifacts_count = 0

    for raw_object_key in list_object_names(storage, raw_bucket, raw_prefix):
        normalized_object_key = build_normalized_object_key(raw_object_key, source)
        if not object_exists(storage, normalized_bucket, normalized_object_key):
            break
        last_processed_raw_object_key = raw_object_key
        last_processed_normalized_object_key = normalized_object_key
        processed_artifacts_count += 1

    if last_processed_raw_object_key is None:
        return None

    started_at = utcnow_iso()
    return write_stream_checkpoint(
        storage=storage,
        raw_bucket=raw_bucket,
        source=source,
        feed=feed,
        stream=stream,
        last_processed_raw_object_key=last_processed_raw_object_key,
        last_processed_normalized_object_key=last_processed_normalized_object_key,
        processed_artifacts_count=processed_artifacts_count,
        last_run_started_at=started_at,
        last_run_completed_at=started_at,
    )


def list_stream_pending_raw_object_keys(
    storage: StorageClient,
    raw_bucket: str,
    raw_prefix: str,
    checkpoint_raw_object_key: str | None = None,
    replay_from_raw_object_key: str | None = None,
    replay_limit: int | None = None,
) -> list[str]:
    if replay_from_raw_object_key is not None and not replay_from_raw_object_key.startswith(
        raw_prefix
    ):
        return []

    raw_object_keys = list_object_names(
        storage,
        raw_bucket,
        raw_prefix,
        start_after=checkpoint_raw_object_key if replay_from_raw_object_key is None else None,
    )
    if replay_from_raw_object_key is not None:
        raw_object_keys = [
            object_key
            for object_key in raw_object_keys
            if object_key >= replay_from_raw_object_key
        ]
    if replay_limit is not None:
        raw_object_keys = raw_object_keys[:replay_limit]
    return raw_object_keys


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
    elif source == "cisa-kev" and raw_object_key.startswith("cisa-kev/catalog/"):
        records = normalize_cisa_kev_catalog(payload, raw_bucket, raw_object_key)
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
        "schema_version": THREAT_SIGNAL_SCHEMA_VERSION,
        "source": source,
        "raw_bucket": raw_bucket,
        "raw_object_key": raw_object_key,
        "normalized_bucket": PROCESSED_DATA_BUCKET,
        "normalized_object_key": normalized_object_key,
        "records_count": len(records),
        "trigger_event": trigger_event,
    }


def list_pending_raw_object_keys(
    source: str,
    feed: str = "recent",
    raw_bucket: str = RAW_FEEDS_BUCKET,
    storage: StorageClient | None = None,
    replay_from_raw_object_key: str | None = None,
    replay_limit: int | None = None,
) -> list[str]:
    storage = storage or StorageClient()
    pending = []
    replay_stream = None
    if replay_from_raw_object_key is not None:
        replay_stream = get_stream_for_raw_object_key(source, feed, replay_from_raw_object_key)

    for stream in get_source_streams(source, feed):
        if replay_stream is not None and stream["stream"] != replay_stream["stream"]:
            continue

        checkpoint = None
        if replay_from_raw_object_key is None:
            checkpoint = load_stream_checkpoint(
                storage,
                raw_bucket=raw_bucket,
                source=source,
                stream=stream["stream"],
            )
            if checkpoint is None:
                checkpoint = bootstrap_stream_checkpoint(
                    storage=storage,
                    source=source,
                    feed=feed,
                    stream=stream["stream"],
                    raw_prefix=stream["raw_prefix"],
                    raw_bucket=raw_bucket,
                )

        pending.extend(
            list_stream_pending_raw_object_keys(
                storage=storage,
                raw_bucket=raw_bucket,
                raw_prefix=stream["raw_prefix"],
                checkpoint_raw_object_key=(
                    checkpoint.get("last_processed_raw_object_key") if checkpoint else None
                ),
                replay_from_raw_object_key=replay_from_raw_object_key,
                replay_limit=replay_limit,
            )
        )

    return pending


def normalize_pending_artifacts(
    source: str,
    feed: str = "recent",
    raw_bucket: str = RAW_FEEDS_BUCKET,
    storage: StorageClient | None = None,
    replay_from_raw_object_key: str | None = None,
    replay_limit: int | None = None,
) -> list[dict]:
    storage = storage or StorageClient()
    results = []
    replay_stream = None
    if replay_from_raw_object_key is not None:
        replay_stream = get_stream_for_raw_object_key(source, feed, replay_from_raw_object_key)

    for stream in get_source_streams(source, feed):
        if replay_stream is not None and stream["stream"] != replay_stream["stream"]:
            continue

        checkpoint = None
        if replay_from_raw_object_key is None:
            checkpoint = load_stream_checkpoint(
                storage,
                raw_bucket=raw_bucket,
                source=source,
                stream=stream["stream"],
            )
            if checkpoint is None:
                checkpoint = bootstrap_stream_checkpoint(
                    storage=storage,
                    source=source,
                    feed=feed,
                    stream=stream["stream"],
                    raw_prefix=stream["raw_prefix"],
                    raw_bucket=raw_bucket,
                )

        last_processed_raw_object_key = (
            checkpoint.get("last_processed_raw_object_key") if checkpoint else None
        )
        last_processed_normalized_object_key = (
            checkpoint.get("last_processed_normalized_object_key") if checkpoint else None
        )
        started_at = utcnow_iso()
        processed_artifacts_count = 0

        for raw_object_key in list_stream_pending_raw_object_keys(
            storage=storage,
            raw_bucket=raw_bucket,
            raw_prefix=stream["raw_prefix"],
            checkpoint_raw_object_key=last_processed_raw_object_key,
            replay_from_raw_object_key=replay_from_raw_object_key,
            replay_limit=replay_limit,
        ):
            try:
                result = normalize_raw_artifact(
                    raw_object_key=raw_object_key,
                    raw_bucket=raw_bucket,
                    storage=storage,
                )
            except Exception as exc:
                if replay_from_raw_object_key is None:
                    write_stream_checkpoint(
                        storage=storage,
                        raw_bucket=raw_bucket,
                        source=source,
                        feed=feed,
                        stream=stream["stream"],
                        last_processed_raw_object_key=last_processed_raw_object_key,
                        last_processed_normalized_object_key=last_processed_normalized_object_key,
                        processed_artifacts_count=processed_artifacts_count,
                        last_run_started_at=started_at,
                        last_run_completed_at=utcnow_iso(),
                        last_error={
                            "raw_object_key": raw_object_key,
                            "error": str(exc),
                            "at": utcnow_iso(),
                        },
                    )
                raise

            results.append(result)
            processed_artifacts_count += 1
            last_processed_raw_object_key = raw_object_key
            last_processed_normalized_object_key = result["normalized_object_key"]

            if replay_from_raw_object_key is None:
                write_stream_checkpoint(
                    storage=storage,
                    raw_bucket=raw_bucket,
                    source=source,
                    feed=feed,
                    stream=stream["stream"],
                    last_processed_raw_object_key=last_processed_raw_object_key,
                    last_processed_normalized_object_key=last_processed_normalized_object_key,
                    processed_artifacts_count=processed_artifacts_count,
                    last_run_started_at=started_at,
                    last_run_completed_at=utcnow_iso(),
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
        choices=sorted(SOURCE_STREAMS.keys()),
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
    parser.add_argument(
        "--replay-from-raw-object-key",
        help="Replay normalization from a specific raw object key for the selected source/feed.",
    )
    parser.add_argument(
        "--replay-limit",
        type=int,
        help="Maximum number of raw artifacts to replay when using --replay-from-raw-object-key.",
    )
    args = parser.parse_args()

    if args.replay_limit is not None and args.replay_limit < 1:
        parser.error("--replay-limit must be greater than zero.")
    if args.replay_limit is not None and not args.replay_from_raw_object_key:
        parser.error("--replay-limit requires --replay-from-raw-object-key.")
    if args.raw_object_key and args.replay_from_raw_object_key:
        parser.error("--replay-from-raw-object-key cannot be used with --raw-object-key.")

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
        replay_from_raw_object_key=args.replay_from_raw_object_key,
        replay_limit=args.replay_limit,
    )
    print(
        json.dumps(
            {
                "schema_version": THREAT_SIGNAL_SCHEMA_VERSION,
                "source": args.source,
                "feed": args.feed,
                "raw_bucket": args.raw_bucket,
                "replay_from_raw_object_key": args.replay_from_raw_object_key,
                "replay_limit": args.replay_limit,
                "processed_artifacts": len(results),
                "results": results,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    run()
