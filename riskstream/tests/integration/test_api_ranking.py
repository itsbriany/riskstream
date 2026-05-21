import gzip
import json
import os
import uuid
from io import BytesIO
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from riskstream.shared.utils.storage import StorageClient

PROCESSED_BUCKET = "processed-data"


def _base_url() -> str:
    return os.getenv("API_BASE_URL", "http://riskstream").rstrip("/")


def _storage_client() -> StorageClient:
    return StorageClient(
        endpoint=os.getenv("S3_ENDPOINT", "minio:9000"),
        access_key=os.getenv("S3_ACCESS_KEY", "minioadmin"),
        secret_key=os.getenv("S3_SECRET_KEY", "minioadmin"),
        use_ssl=os.getenv("S3_USE_SSL", "false").lower() == "true",
    )


def _write_jsonl_gzip_object(
    client: StorageClient,
    object_key: str,
    records: list[dict],
) -> None:
    payload = gzip.compress(
        "\n".join(json.dumps(record, sort_keys=True) for record in records).encode(
            "utf-8"
        )
    )
    client.get_client().put_object(
        PROCESSED_BUCKET,
        object_key,
        BytesIO(payload),
        len(payload),
        content_type="application/gzip",
    )


def _post_json(path: str, payload: dict) -> tuple[int, dict]:
    raw_payload = json.dumps(payload).encode("utf-8")
    request = Request(
        f"{_base_url()}{path}",
        data=raw_payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=30) as response:
        return response.status, json.loads(response.read().decode("utf-8"))


def _urlhaus_record(run_id: str, action: str, object_key: str) -> dict:
    return {
        "schema_version": "threat_signal.v1",
        "source": "urlhaus",
        "feed": "recent",
        "signal_kind": "indicator",
        "action": action,
        "artifact_type": "url",
        "artifact_value": f"https://api-ranking-{run_id}.example/payload",
        "external_id": f"urlhaus-{run_id}",
        "first_seen_at": "2099-12-31T11:00:00+00:00",
        "last_seen_at": "2099-12-31T11:05:00+00:00",
        "classification": "malware_download",
        "status": "online",
        "tags": [f"api-ranking-{run_id}", "Mozi"],
        "evidence_url": f"https://urlhaus.abuse.ch/url/{run_id}/",
        "raw_ref": {
            "bucket": "raw-feeds",
            "object_key": object_key,
            "row_number": 1,
        },
    }


def _cisa_kev_record(run_id: str, object_key: str) -> dict:
    return {
        "schema_version": "threat_signal.v1",
        "source": "cisa-kev",
        "feed": "catalog",
        "signal_kind": "vulnerability",
        "action": "observed",
        "artifact_type": "cve",
        "artifact_value": f"CVE-2099-{run_id[:4]}",
        "external_id": f"CVE-2099-{run_id[:4]}",
        "tags": [f"api-ranking-{run_id}"],
        "raw_ref": {
            "bucket": "raw-feeds",
            "object_key": object_key,
            "row_number": 1,
        },
        "source_details": {
            "cisa-kev": {
                "requiredAction": "Apply the vendor patch.",
                "knownRansomwareCampaignUse": "Known",
            }
        },
    }


def test_ranking_options_endpoint_returns_supported_values():
    with urlopen(f"{_base_url()}/v1/threats/ranking-options", timeout=30) as response:
        assert response.status == 200
        assert response.headers.get("Content-Type") == "application/json"
        payload = json.loads(response.read().decode("utf-8"))

    assert payload["ranker_version"] == "deterministic-v1"
    assert payload["defaults"]["limit"] == 25
    assert payload["limits"]["max_limit"] == 100
    assert "malware_delivery" in payload["priorities"]
    assert "vulnerability" in payload["signal_kinds"]
    assert "cve" in payload["artifact_types"]


def test_rank_endpoint_returns_seeded_ranked_cards():
    run_id = uuid.uuid4().hex[:8]
    client = _storage_client()
    observed_raw_key = f"urlhaus/checkpoints/2099/12/31/{run_id}.json.gz"
    updated_raw_key = f"urlhaus/deltas/2099/12/31/{run_id}.json.gz"
    cisa_raw_key = f"cisa-kev/catalog/2099/12/31/{run_id}.json"
    seeded_keys = [
        f"normalized/threat-signals/threat_signal.v1/urlhaus/recent/checkpoints/2099/12/31/{run_id}-observed.jsonl.gz",
        f"normalized/threat-signals/threat_signal.v1/urlhaus/recent/deltas/2099/12/31/{run_id}-updated.jsonl.gz",
        f"normalized/threat-signals/threat_signal.v1/cisa-kev/catalog/2099/12/31/{run_id}.jsonl.gz",
    ]

    try:
        _write_jsonl_gzip_object(
            client,
            seeded_keys[0],
            [_urlhaus_record(run_id, "observed", observed_raw_key)],
        )
        _write_jsonl_gzip_object(
            client,
            seeded_keys[1],
            [_urlhaus_record(run_id, "updated", updated_raw_key)],
        )
        _write_jsonl_gzip_object(
            client,
            seeded_keys[2],
            [_cisa_kev_record(run_id, cisa_raw_key)],
        )

        status, payload = _post_json(
            "/v1/threats:rank",
            {
                "tenant_id": "api-integration",
                "time_window": {
                    "since": "2099-12-31T00:00:00Z",
                    "until": "2100-01-01T00:00:00Z",
                },
                "context": {
                    "environment_scope": "production",
                    "priorities": ["malware_delivery", "active_exploitation"],
                },
                "filters": {
                    "signal_kinds": ["indicator", "vulnerability"],
                    "artifact_types": ["url", "cve"],
                    "tags_any": [f"api-ranking-{run_id}"],
                    "min_score": 50,
                },
                "limit": 10,
            },
        )
    finally:
        for object_key in seeded_keys:
            client.get_client().remove_object(PROCESSED_BUCKET, object_key)

    assert status == 200
    assert payload["tenant_id"] == "api-integration"
    assert payload["ranker_version"] == "deterministic-v1"
    assert payload["result_count"] == 2

    url_card = next(
        result
        for result in payload["results"]
        if result["signal"]["artifact_type"] == "url"
    )
    assert url_card["signal"]["artifact_value"] == (
        f"https://api-ranking-{run_id}.example/payload"
    )
    assert url_card["severity"] == "critical"
    assert url_card["sources"] == ["urlhaus"]
    assert set(url_card["labels"]) >= {"Mozi", "malware_download", "online"}
    assert len(url_card["raw_refs"]) == 2
    assert "evidence_url" in url_card
    assert {reason["code"] for reason in url_card["reasons"]} >= {
        "active_malware_delivery",
        "priority_match",
        "recently_updated",
    }

    cve_card = next(
        result
        for result in payload["results"]
        if result["signal"]["artifact_type"] == "cve"
    )
    assert cve_card["signal"]["signal_kind"] == "vulnerability"
    assert "known_exploited_vulnerability" in {
        reason["code"] for reason in cve_card["reasons"]
    }


def test_rank_endpoint_rejects_invalid_priority():
    request = Request(
        f"{_base_url()}/v1/threats:rank",
        data=json.dumps(
            {"context": {"priorities": ["not-a-supported-priority"]}}
        ).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        urlopen(request, timeout=30)
    except HTTPError as exc:
        assert exc.code == 400
        payload = json.loads(exc.read().decode("utf-8"))
    else:
        raise AssertionError("Expected ranking request to fail")

    assert "unsupported" in payload["error"]
