import gzip
import json
import os
import subprocess
import time
import uuid
from io import BytesIO
from pathlib import Path

from jsonschema import Draft202012Validator
from minio.error import S3Error

from riskstream.shared.utils.storage import StorageClient


RAW_BUCKET = "raw-feeds"
PROCESSED_BUCKET = "processed-data"
SCHEMA_PATH = Path("/app/riskstream/services/normalization/threat-signal/schemas/threat_signal.v1.schema.json")


def _storage_client() -> StorageClient:
    return StorageClient(
        endpoint=os.getenv("S3_ENDPOINT", "minio:9000"),
        access_key=os.getenv("S3_ACCESS_KEY", "minioadmin"),
        secret_key=os.getenv("S3_SECRET_KEY", "minioadmin"),
        use_ssl=os.getenv("S3_USE_SSL", "false").lower() == "true",
    )


def _main_path() -> str:
    return "/app/riskstream/services/normalization/threat-signal/src/main.py"


def _validator() -> Draft202012Validator:
    return Draft202012Validator(
        json.loads(SCHEMA_PATH.read_text()),
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )


def _assert_schema_valid(records: list[dict]) -> None:
    validator = _validator()
    for record in records:
        errors = sorted(validator.iter_errors(record), key=lambda err: list(err.path))
        assert errors == []


def _read_json_gzip_object(client: StorageClient, bucket: str, object_key: str) -> list[dict]:
    response = client.get_client().get_object(bucket, object_key)
    try:
        payload = gzip.decompress(response.read()).decode("utf-8").splitlines()
    finally:
        response.close()
        response.release_conn()
    return [json.loads(line) for line in payload if line.strip()]


def _write_json_object(
    client: StorageClient, bucket: str, object_key: str, payload: dict
) -> None:
    raw_payload = json.dumps(payload).encode("utf-8")
    client.get_client().put_object(
        bucket,
        object_key,
        BytesIO(raw_payload),
        len(raw_payload),
        content_type="application/json",
    )


def _write_gzip_json_object(
    client: StorageClient, bucket: str, object_key: str, payload: dict
) -> None:
    raw_payload = gzip.compress(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    client.get_client().put_object(
        bucket,
        object_key,
        BytesIO(raw_payload),
        len(raw_payload),
        content_type="application/gzip",
    )


def _read_json_object(client: StorageClient, bucket: str, object_key: str) -> dict:
    response = client.get_client().get_object(bucket, object_key)
    try:
        return json.loads(response.read().decode("utf-8"))
    finally:
        response.close()
        response.release_conn()


def _wait_for_object(bucket: str, object_key: str, timeout_seconds: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            response = _storage_client().get_client().get_object(bucket, object_key)
            try:
                response.read()
            finally:
                response.close()
                response.release_conn()
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
        raw_object_key.replace(
            "threatfox/recent/",
            "normalized/threat-signals/threat_signal.v1/threatfox/recent/",
        )
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
    _wait_for_object(RAW_BUCKET, raw_object_key)

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
    _assert_schema_valid(normalized_rows)
    assert normalized_rows[0]["artifact_type"] == "domain"
    assert normalized_rows[0]["artifact_value"] == "cache-dist-5.vitagrazia.in.net"
    assert normalized_rows[0]["source"] == "threatfox"


def test_cisa_kev_catalog_normalization_runs_in_cluster():
    client = _storage_client()

    raw_object_key = f"cisa-kev/catalog/2099/12/31/235959Z-{uuid.uuid4().hex[:8]}.json"
    normalized_object_key = (
        raw_object_key.replace(
            "cisa-kev/catalog/",
            "normalized/threat-signals/threat_signal.v1/cisa-kev/catalog/",
        ).removesuffix(".json")
        + ".jsonl.gz"
    )
    payload = {
        "source": "cisa-kev",
        "feed": "catalog",
        "fetched_at": "2099-12-31T23:59:59+00:00",
        "service": "cisa-kev-ingestion",
        "content_hash": "abc123",
        "data": {
            "title": "CISA Known Exploited Vulnerabilities Catalog",
            "catalogVersion": "2099.12.31",
            "vulnerabilities": [
                {
                    "cveID": "CVE-2099-0001",
                    "vendorProject": "Acme",
                    "product": "Widget",
                    "vulnerabilityName": "Widget auth bypass",
                    "dateAdded": "2099-12-31",
                    "shortDescription": "Authentication bypass in Widget admin interface.",
                    "requiredAction": "Apply the vendor patch.",
                    "dueDate": "2100-01-15",
                    "knownRansomwareCampaignUse": "Known",
                    "notes": "Observed in active exploitation.",
                    "cwes": ["CWE-287"],
                }
            ],
        },
    }
    _write_json_object(client, RAW_BUCKET, raw_object_key, payload)
    _wait_for_object(RAW_BUCKET, raw_object_key)

    run_result = _run_normalizer(
        "--raw-object-key",
        raw_object_key,
        "--raw-bucket",
        RAW_BUCKET,
    )
    assert run_result["source"] == "cisa-kev"
    assert run_result["raw_object_key"] == raw_object_key
    assert run_result["normalized_object_key"] == normalized_object_key

    normalized_rows = _read_json_gzip_object(client, PROCESSED_BUCKET, normalized_object_key)
    assert len(normalized_rows) == 1
    _assert_schema_valid(normalized_rows)
    assert normalized_rows[0]["source"] == "cisa-kev"
    assert normalized_rows[0]["signal_kind"] == "vulnerability"
    assert normalized_rows[0]["artifact_type"] == "cve"
    assert normalized_rows[0]["artifact_value"] == "CVE-2099-0001"
    assert normalized_rows[0]["source_details"]["cisa-kev"]["requiredAction"] == "Apply the vendor patch."


def test_urlhaus_checkpoint_normalization_runs_in_cluster():
    client = _storage_client()

    raw_object_key = f"urlhaus/checkpoints/2099/12/31/{uuid.uuid4().hex}.json.gz"
    normalized_object_key = (
        raw_object_key.replace(
            "urlhaus/checkpoints/",
            "normalized/threat-signals/threat_signal.v1/urlhaus/recent/checkpoints/",
        ).removesuffix(".json.gz")
        + ".jsonl.gz"
    )
    payload = {
        "source": "urlhaus",
        "feed": "recent",
        "fetched_at": "2026-03-19T14:49:13+00:00",
        "service": "urlhaus-ingestion",
        "content_hash": "abc123",
        "data": {
            "source_url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
            "raw_csv": (
                "# generated every 5 minutes\n"
                "# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"
                '"3799807","2026-03-19 14:49:13","http://221.200.214.87:54591/i","online","2026-03-19 14:49:13","malware_download","32-bit,elf,mips,Mozi","https://urlhaus.abuse.ch/url/3799807/","geenensp"\n'
            ),
        },
    }
    _write_gzip_json_object(client, RAW_BUCKET, raw_object_key, payload)
    _wait_for_object(RAW_BUCKET, raw_object_key)

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
    _assert_schema_valid(normalized_rows)
    assert normalized_rows[0]["source"] == "urlhaus"
    assert normalized_rows[0]["artifact_type"] == "url"
    assert normalized_rows[0]["artifact_value"] == "http://221.200.214.87:54591/i"
    assert normalized_rows[0]["action"] == "observed"


def test_urlhaus_delta_normalization_runs_in_cluster():
    client = _storage_client()

    raw_object_key = f"urlhaus/deltas/2099/12/31/{uuid.uuid4().hex}.json.gz"
    normalized_object_key = (
        raw_object_key.replace(
            "urlhaus/deltas/",
            "normalized/threat-signals/threat_signal.v1/urlhaus/recent/deltas/",
        )
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
    _wait_for_object(RAW_BUCKET, raw_object_key)

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
    _assert_schema_valid(normalized_rows)
    assert normalized_rows[0]["source"] == "urlhaus"
    assert normalized_rows[0]["artifact_type"] == "url"
    assert normalized_rows[0]["artifact_value"] == "http://221.200.214.87:54591/i"
    assert normalized_rows[0]["action"] == "observed"


def test_threatfox_checkpoint_bootstrap_and_rerun_are_incremental():
    client = _storage_client()
    bootstrap_bucket = f"raw-bootstrap-{uuid.uuid4().hex[:8]}"
    client.ensure_bucket(bootstrap_bucket)
    run_id = uuid.uuid4().hex[:8]

    first_raw_object_key = f"threatfox/recent/2099/12/30/235959Z-{run_id}-bootstrap-a.json"
    second_raw_object_key = f"threatfox/recent/2099/12/31/235959Z-{run_id}-bootstrap-b.json"
    first_normalized_object_key = (
        f"normalized/threat-signals/threat_signal.v1/threatfox/recent/2099/12/30/235959Z-{run_id}-bootstrap-a.jsonl.gz"
    )
    second_normalized_object_key = (
        f"normalized/threat-signals/threat_signal.v1/threatfox/recent/2099/12/31/235959Z-{run_id}-bootstrap-b.jsonl.gz"
    )
    checkpoint_object_key = (
        f"normalization-state/threat-signal/threat_signal.v1/{bootstrap_bucket}/threatfox/recent.json"
    )

    first_payload = {
        "source": "threatfox",
        "feed": "recent",
        "fetched_at": "2099-12-30T23:59:59+00:00",
        "service": "threatfox-ingestion",
        "data": {
            "query_status": "ok",
            "data": [
                {
                    "id": "1765567",
                    "ioc": "bootstrap-a.example",
                    "threat_type": "payload_delivery",
                    "ioc_type": "domain",
                    "first_seen": "2099-12-30 21:47:34 UTC",
                    "last_seen": "2099-12-30 21:47:41 UTC",
                }
            ],
        },
    }
    second_payload = {
        "source": "threatfox",
        "feed": "recent",
        "fetched_at": "2099-12-31T23:59:59+00:00",
        "service": "threatfox-ingestion",
        "data": {
            "query_status": "ok",
            "data": [
                {
                    "id": "1765568",
                    "ioc": "bootstrap-b.example",
                    "threat_type": "payload_delivery",
                    "ioc_type": "domain",
                    "first_seen": "2099-12-31 21:47:34 UTC",
                    "last_seen": "2099-12-31 21:47:41 UTC",
                }
            ],
        },
    }
    _write_json_object(client, bootstrap_bucket, first_raw_object_key, first_payload)
    _write_json_object(client, bootstrap_bucket, second_raw_object_key, second_payload)
    _wait_for_object(bootstrap_bucket, first_raw_object_key)
    _wait_for_object(bootstrap_bucket, second_raw_object_key)

    _run_normalizer(
        "--raw-object-key",
        first_raw_object_key,
        "--raw-bucket",
        bootstrap_bucket,
    )

    run_result = _run_normalizer(
        "--source",
        "threatfox",
        "--raw-bucket",
        bootstrap_bucket,
    )
    assert run_result["processed_artifacts"] == 1
    assert [result["raw_object_key"] for result in run_result["results"]] == [
        second_raw_object_key
    ]

    checkpoint = _read_json_object(client, PROCESSED_BUCKET, checkpoint_object_key)
    assert checkpoint["last_processed_raw_object_key"] == second_raw_object_key
    assert checkpoint["last_processed_normalized_object_key"] == second_normalized_object_key

    normalized_rows = _read_json_gzip_object(client, PROCESSED_BUCKET, second_normalized_object_key)
    assert len(normalized_rows) == 1
    _assert_schema_valid(normalized_rows)

    rerun_result = _run_normalizer(
        "--source",
        "threatfox",
        "--raw-bucket",
        bootstrap_bucket,
    )
    assert rerun_result["processed_artifacts"] == 0
