import json
import os
from urllib.request import Request, urlopen


def _base_url() -> str:
    return os.getenv("CISA_KEV_BASE_URL", "http://cisa-kev-ingestion").rstrip("/")


def test_cisa_kev_catalog_endpoint_returns_live_data():
    with urlopen(f"{_base_url()}/catalog", timeout=30) as response:
        assert response.status == 200
        assert response.headers.get("Content-Type") == "application/json"

        payload = json.loads(response.read().decode("utf-8"))

    assert payload["service"] == "cisa-kev-ingestion"
    assert "vulnerabilities_count" in payload
    assert "data" in payload

    data = payload["data"]
    assert isinstance(data, dict)

    vulnerabilities = data.get("vulnerabilities")
    if vulnerabilities is not None:
        assert isinstance(vulnerabilities, list)
        assert payload["vulnerabilities_count"] == len(vulnerabilities)


def test_cisa_kev_ingest_catalog_endpoint_persists_live_data():
    request = Request(f"{_base_url()}/ingest/catalog", method="POST")

    with urlopen(request, timeout=30) as response:
        assert response.status == 200
        assert response.headers.get("Content-Type") == "application/json"

        payload = json.loads(response.read().decode("utf-8"))

    assert payload["service"] == "cisa-kev-ingestion"
    assert payload["feed"] == "catalog"
    assert "changed" in payload
    assert "snapshot_written" in payload
    assert payload["checked_at"]
    assert "vulnerabilities_count" in payload
    if payload["snapshot_written"]:
        assert payload["changed"] is True
        assert payload["bucket"] == "raw-feeds"
        assert payload["object_key"].startswith("cisa-kev/catalog/")
        assert payload["fetched_at"]
    else:
        assert payload["changed"] is False
        assert payload["last_object_key"].startswith("cisa-kev/catalog/")
