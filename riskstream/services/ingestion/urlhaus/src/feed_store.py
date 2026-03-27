import gzip
import hashlib
import json
from datetime import datetime, timedelta, timezone
from io import BytesIO
from typing import Any

from riskstream.shared.utils.storage import StorageClient


RAW_FEEDS_BUCKET = "raw-feeds"
ARCHIVES_BUCKET = "archives"
CHECKPOINT_PREFIX = "urlhaus/checkpoints/"
DELTA_PREFIX = "urlhaus/deltas/"
STATE_OBJECT_KEY = "urlhaus/state/latest.json.gz"
REMOVED_REASON = "missing_from_recent_feed"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def canonicalize_recent_data(recent_data: dict) -> str:
    return json.dumps(recent_data, sort_keys=True, separators=(",", ":"))


def compute_recent_hash(recent_data: dict) -> str:
    raw_csv = recent_data.get("raw_csv")
    if isinstance(raw_csv, str):
        return hashlib.sha256(raw_csv.encode("utf-8")).hexdigest()

    canonical_payload = canonicalize_recent_data(recent_data).encode("utf-8")
    return hashlib.sha256(canonical_payload).hexdigest()


def build_checkpoint_object_key(timestamp: datetime) -> str:
    return f"{CHECKPOINT_PREFIX}{timestamp.strftime('%Y/%m/%d')}/000000Z.json.gz"


def build_delta_object_key(timestamp: datetime, content_hash: str) -> str:
    return f"{DELTA_PREFIX}{timestamp.strftime('%Y/%m/%d')}/{content_hash}.json.gz"


def build_records_by_id(recent_data: dict) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for record in recent_data.get("urls", []):
        record_id = str(record.get("id", "")).strip()
        if not record_id:
            continue
        records[record_id] = record
    return records


def build_checkpoint_payload(
    recent_data: dict, fetched_at: datetime, content_hash: str
) -> dict:
    return {
        "source": "urlhaus",
        "feed": "recent",
        "fetched_at": fetched_at.isoformat(),
        "service": "urlhaus-ingestion",
        "content_hash": content_hash,
        "data": {
            "source_url": recent_data.get("source_url"),
            "raw_csv": recent_data.get("raw_csv", ""),
        },
    }


def build_latest_state_payload(
    recent_data: dict, fetched_at: datetime, content_hash: str
) -> dict:
    return {
        "source": "urlhaus",
        "feed": "recent",
        "updated_at": fetched_at.isoformat(),
        "service": "urlhaus-ingestion",
        "content_hash": content_hash,
        "source_url": recent_data.get("source_url"),
        "records_by_id": build_records_by_id(recent_data),
    }


def build_delta_payload(
    previous_state: dict | None,
    recent_data: dict,
    fetched_at: datetime,
    content_hash: str,
) -> tuple[dict, dict]:
    previous_records = {}
    previous_content_hash = None
    if previous_state:
        previous_records = previous_state.get("records_by_id", {})
        previous_content_hash = previous_state.get("content_hash")

    current_records = build_records_by_id(recent_data)
    added = []
    updated = []
    removed = []

    for record_id in sorted(current_records):
        record = current_records[record_id]
        previous_record = previous_records.get(record_id)
        if previous_record is None:
            added.append(record)
        elif previous_record != record:
            updated.append(record)

    for record_id in sorted(previous_records):
        if record_id not in current_records:
            removed_record = dict(previous_records[record_id])
            removed_record["reason"] = REMOVED_REASON
            removed.append(removed_record)

    payload = {
        "source": "urlhaus",
        "feed": "recent",
        "fetched_at": fetched_at.isoformat(),
        "service": "urlhaus-ingestion",
        "content_hash": content_hash,
        "previous_content_hash": previous_content_hash,
        "data": {
            "source_url": recent_data.get("source_url"),
            "added": added,
            "updated": updated,
            "removed": removed,
        },
    }
    counts = {
        "added": len(added),
        "updated": len(updated),
        "removed": len(removed),
    }
    return payload, counts


def encode_gzip_json(payload: dict) -> bytes:
    return gzip.compress(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


def decode_json_bytes(raw_bytes: bytes) -> dict:
    if raw_bytes[:2] == b"\x1f\x8b":
        raw_bytes = gzip.decompress(raw_bytes)
    return json.loads(raw_bytes.decode("utf-8"))


def read_object_bytes(response) -> bytes:
    try:
        return response.read()
    finally:
        close = getattr(response, "close", None)
        if callable(close):
            close()

        release_conn = getattr(response, "release_conn", None)
        if callable(release_conn):
            release_conn()


def read_json_object(storage: StorageClient, bucket: str, object_key: str) -> dict:
    response = storage.get_client().get_object(bucket, object_key)
    return decode_json_bytes(read_object_bytes(response))


def write_json_object(
    storage: StorageClient, bucket: str, object_key: str, payload: dict
) -> None:
    compressed_payload = encode_gzip_json(payload)
    storage.get_client().put_object(
        bucket,
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


def get_latest_state(storage: StorageClient) -> dict | None:
    if not object_exists(storage, RAW_FEEDS_BUCKET, STATE_OBJECT_KEY):
        return None

    state = read_json_object(storage, RAW_FEEDS_BUCKET, STATE_OBJECT_KEY)
    state["object_key"] = STATE_OBJECT_KEY
    return state


def write_checkpoint_if_needed(
    storage: StorageClient, recent_data: dict, fetched_at: datetime, content_hash: str
) -> str | None:
    object_key = build_checkpoint_object_key(fetched_at)
    if object_exists(storage, RAW_FEEDS_BUCKET, object_key):
        return None

    payload = build_checkpoint_payload(recent_data, fetched_at, content_hash)
    write_json_object(storage, RAW_FEEDS_BUCKET, object_key, payload)
    return object_key


def write_delta(
    storage: StorageClient,
    previous_state: dict | None,
    recent_data: dict,
    fetched_at: datetime,
    content_hash: str,
) -> tuple[str, dict]:
    object_key = build_delta_object_key(fetched_at, content_hash)
    payload, counts = build_delta_payload(previous_state, recent_data, fetched_at, content_hash)
    write_json_object(storage, RAW_FEEDS_BUCKET, object_key, payload)
    return object_key, counts


def write_latest_state(
    storage: StorageClient, recent_data: dict, fetched_at: datetime, content_hash: str
) -> str:
    payload = build_latest_state_payload(recent_data, fetched_at, content_hash)
    write_json_object(storage, RAW_FEEDS_BUCKET, STATE_OBJECT_KEY, payload)
    return STATE_OBJECT_KEY


def ingest_recent_feed(
    recent_data: dict,
    storage: StorageClient | None = None,
    now: datetime | None = None,
) -> dict:
    storage = storage or StorageClient()
    fetched_at = now or utcnow()
    content_hash = compute_recent_hash(recent_data)
    latest_state = get_latest_state(storage)
    changed = latest_state is None or latest_state.get("content_hash") != content_hash
    checked_at = fetched_at.isoformat()

    checkpoint_object_key = write_checkpoint_if_needed(
        storage, recent_data, fetched_at, content_hash
    )

    delta_object_key = None
    delta_counts = {"added": 0, "updated": 0, "removed": 0}
    state_object_key = None

    if changed:
        delta_object_key, delta_counts = write_delta(
            storage, latest_state, recent_data, fetched_at, content_hash
        )
        state_object_key = write_latest_state(
            storage, recent_data, fetched_at, content_hash
        )

    response = {
        "changed": changed,
        "checkpoint_written": checkpoint_object_key is not None,
        "delta_written": delta_object_key is not None,
        "delta_counts": delta_counts,
        "checked_at": checked_at,
        "content_hash": content_hash,
        "urls_count": len(recent_data.get("urls", [])),
    }
    if checkpoint_object_key is not None:
        response["checkpoint_object_key"] = checkpoint_object_key
    if delta_object_key is not None:
        response["delta_object_key"] = delta_object_key
        response["state_object_key"] = state_object_key

    return response


def parse_partition_date(object_key: str, prefix: str) -> datetime.date:
    relative_path = object_key.removeprefix(prefix)
    year, month, day = relative_path.split("/", 3)[:3]
    return datetime(int(year), int(month), int(day), tzinfo=timezone.utc).date()


def copy_object(
    storage: StorageClient,
    source_bucket: str,
    source_key: str,
    destination_bucket: str,
    destination_key: str,
) -> None:
    response = storage.get_client().get_object(source_bucket, source_key)
    payload = read_object_bytes(response)
    storage.get_client().put_object(
        destination_bucket,
        destination_key,
        BytesIO(payload),
        len(payload),
        content_type="application/gzip",
    )


def run_archive_lifecycle(
    storage: StorageClient | None = None,
    now: datetime | None = None,
    hot_retention_days: int = 30,
    archive_retention_days: int = 180,
) -> dict:
    storage = storage or StorageClient()
    reference_date = (now or utcnow()).date()
    hot_cutoff = reference_date - timedelta(days=hot_retention_days)
    archive_cutoff = reference_date - timedelta(days=archive_retention_days)

    archived_object_count = 0
    pruned_hot_object_count = 0
    deleted_archive_object_count = 0

    for prefix in (CHECKPOINT_PREFIX, DELTA_PREFIX):
        for object_key in list_object_names(storage, RAW_FEEDS_BUCKET, prefix):
            object_date = parse_partition_date(object_key, prefix)
            if object_date >= hot_cutoff:
                continue

            copy_object(storage, RAW_FEEDS_BUCKET, object_key, ARCHIVES_BUCKET, object_key)
            archived_object_count += 1
            storage.get_client().remove_object(RAW_FEEDS_BUCKET, object_key)
            pruned_hot_object_count += 1

    for prefix in (CHECKPOINT_PREFIX, DELTA_PREFIX):
        for object_key in list_object_names(storage, ARCHIVES_BUCKET, prefix):
            object_date = parse_partition_date(object_key, prefix)
            if object_date >= archive_cutoff:
                continue

            storage.get_client().remove_object(ARCHIVES_BUCKET, object_key)
            deleted_archive_object_count += 1

    return {
        "hot_retention_days": hot_retention_days,
        "archive_retention_days": archive_retention_days,
        "archived_object_count": archived_object_count,
        "pruned_hot_object_count": pruned_hot_object_count,
        "deleted_archive_object_count": deleted_archive_object_count,
        "checked_at": (now or utcnow()).isoformat(),
    }
