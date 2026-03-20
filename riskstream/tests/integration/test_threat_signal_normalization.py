import gzip
import json
import os
import subprocess
import time
import uuid
from io import BytesIO

from minio import Minio
from minio.error import S3Error


RAW_BUCKET = "raw-feeds"
PROCESSED_BUCKET = "processed-data"


def _storage_client() -> Minio:
    return Minio(
        os.getenv("S3_ENDPOINT", "minio:9000"),
        access_key=os.getenv("S3_ACCESS_KEY", "minioadmin"),
        secret_key=os.getenv("S3_SECRET_KEY", "minioadmin"),
        secure=os.getenv("S3_USE_SSL", "false").lower() == "true",
    )


def _main_path() -> str:
    return "/app/riskstream/services/normalization/threat-signal/src/main.py"


def _read_json_gzip_object(client: Minio, bucket: str, object_key: str) -> list[dict]:
    response = client.get_object(bucket, object_key)
    try:
        payload = gzip.decompress(response.read()).decode("utf-8").splitlines()
    finally:
        response.close()
        response.release_conn()
    return [json.loads(line) for line in payload if line.strip()]


def _write_json_object(client: Minio, bucket: str, object_key: str, payload: dict) -> None:
    raw_payload = json.dumps(payload).encode("utf-8")
    client.put_object(
        bucket,
        object_key,
        BytesIO(raw_payload),
        len(raw_payload),
        content_type="application/json",
    )


def _write_gzip_json_object(client: Minio, bucket: str, object_key: str, payload: dict) -> None:
    raw_payload = gzip.compress(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    client.put_object(
        bucket,
        object_key,
        BytesIO(raw_payload),
        len(raw_payload),
        content_type="application/gzip",
    )


def _wait_for_object(client: Minio, bucket: str, object_key: str, timeout_seconds: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            client.stat_object(bucket, object_key)
            return
        except S3Error as exc:
            if exc.code != "NoSuchKey" or time.monotonic() >= deadline:
                raise
            time.sleep(0.1)


def _run_normalizer(*args: str) -> dict:
    completed = subprocess.run(
        ["python", _main_path(), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout.strip())


def test_threatfox_normalization_runs_in_cluster():
    client = _storage_client()

    raw_object_key = f"threatfox/recent/2099/12/31/235959Z-{uuid.uuid4().hex[:8]}.json"
    normalized_object_key = (
        raw_object_key.replace("threatfox/recent/", "normalized/threat-signals/threatfox/recent/")
        .removesuffix(".json")
        + ".jsonl.gz"
    )
    payload = {
        "source": "threatfox",
        "feed": "recent",
        "fetched_at": "2026-03-19T14:05:00+00:00",
        "service": "threatfox-ingestion",
        "data": {
            "query_status": "ok",
            "data": [
                {
                    "id": "1765567",
                    "ioc": "cache-dist-5.vitagrazia.in.net",
                    "threat_type": "payload_delivery",
                    "ioc_type": "domain",
                    "malware": "js.clearfake",
                    "malware_printable": "ClearFake",
                    "confidence_level": 100,
                    "first_seen": "2026-03-13 21:47:34 UTC",
                    "last_seen": "2026-03-13 21:47:41 UTC",
                    "reporter": "anonymous",
                    "tags": ["ClearFake"],
                }
            ],
        },
    }
    _write_json_object(client, RAW_BUCKET, raw_object_key, payload)
    _wait_for_object(client, RAW_BUCKET, raw_object_key)

    first_run = _run_normalizer(
        "--raw-object-key",
        raw_object_key,
        "--raw-bucket",
        RAW_BUCKET,
    )
    assert first_run["source"] == "threatfox"
    assert first_run["raw_object_key"] == raw_object_key
    assert first_run["normalized_object_key"] == normalized_object_key

    normalized_rows = _read_json_gzip_object(client, PROCESSED_BUCKET, normalized_object_key)
    assert len(normalized_rows) == 1
    assert normalized_rows[0]["artifact_type"] == "domain"
    assert normalized_rows[0]["artifact_value"] == "cache-dist-5.vitagrazia.in.net"
    assert normalized_rows[0]["source"] == "threatfox"


def test_urlhaus_delta_normalization_runs_in_cluster():
    client = _storage_client()

    raw_object_key = f"urlhaus/deltas/2099/12/31/{uuid.uuid4().hex}.json.gz"
    normalized_object_key = (
        raw_object_key.replace("urlhaus/deltas/", "normalized/threat-signals/urlhaus/recent/deltas/")
        .removesuffix(".json.gz")
        + ".jsonl.gz"
    )
    payload = {
        "source": "urlhaus",
        "feed": "recent",
        "fetched_at": "2026-03-19T15:00:00+00:00",
        "service": "urlhaus-ingestion",
        "content_hash": "abc123",
        "data": {
            "source_url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
            "added": [
                {
                    "id": "3799807",
                    "dateadded": "2026-03-19 14:49:13",
                    "url": "http://221.200.214.87:54591/i",
                    "url_status": "online",
                    "last_online": "2026-03-19 14:49:13",
                    "threat": "malware_download",
                    "tags": "32-bit,elf,mips,Mozi",
                    "urlhaus_link": "https://urlhaus.abuse.ch/url/3799807/",
                    "reporter": "geenensp",
                }
            ],
            "updated": [],
            "removed": [],
        },
    }
    _write_gzip_json_object(client, RAW_BUCKET, raw_object_key, payload)
    _wait_for_object(client, RAW_BUCKET, raw_object_key)

    run_result = _run_normalizer(
        "--raw-object-key",
        raw_object_key,
        "--raw-bucket",
        RAW_BUCKET,
    )
    assert run_result["source"] == "urlhaus"
    assert run_result["raw_object_key"] == raw_object_key
    assert run_result["normalized_object_key"] == normalized_object_key

    normalized_rows = _read_json_gzip_object(client, PROCESSED_BUCKET, normalized_object_key)
    assert len(normalized_rows) == 1
    assert normalized_rows[0]["source"] == "urlhaus"
    assert normalized_rows[0]["artifact_type"] == "url"
    assert normalized_rows[0]["artifact_value"] == "http://221.200.214.87:54591/i"
    assert normalized_rows[0]["action"] == "observed"
