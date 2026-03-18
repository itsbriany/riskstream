import io
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError

import pytest


CISA_KEV_SRC = (
    Path(__file__).resolve().parents[2] / "services" / "ingestion" / "cisa-kev" / "src"
)
if str(CISA_KEV_SRC) not in sys.path:
    sys.path.insert(0, str(CISA_KEV_SRC))

import client  # noqa: E402
import main  # noqa: E402


class FakeResponse:
    def __init__(self, payload, status=200):
        self.payload = payload
        self.status = status

    def read(self):
        return json.dumps(self.payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def build_handler(path, cisa_kev_client, method="GET"):
    handler = main.Handler.__new__(main.Handler)
    handler.path = path
    handler.command = method
    handler.client = cisa_kev_client
    handler.wfile = io.BytesIO()
    handler.send_response = Mock()
    handler.send_header = Mock()
    handler.end_headers = Mock()
    return handler


def response_body(handler):
    return json.loads(handler.wfile.getvalue().decode("utf-8"))


def test_get_catalog_uses_default_url(monkeypatch):
    monkeypatch.delenv("CISA_KEV_URL", raising=False)
    cisa_kev_client = client.CisaKevClient(timeout=12)

    with patch.object(client, "urlopen", return_value=FakeResponse({"vulnerabilities": []})) as mock_urlopen:
        response = cisa_kev_client.get_catalog()

    request = mock_urlopen.call_args.args[0]
    assert request.full_url == client.CisaKevClient.DEFAULT_URL
    assert request.headers["Accept"] == "application/json"
    assert mock_urlopen.call_args.kwargs["timeout"] == 12
    assert response == {"vulnerabilities": []}


def test_get_catalog_uses_env_override(monkeypatch):
    monkeypatch.setenv("CISA_KEV_URL", "https://example.com/kev.json")
    cisa_kev_client = client.CisaKevClient()

    with patch.object(client, "urlopen", return_value=FakeResponse({"vulnerabilities": []})) as mock_urlopen:
        cisa_kev_client.get_catalog()

    request = mock_urlopen.call_args.args[0]
    assert request.full_url == "https://example.com/kev.json"


def test_get_catalog_wraps_http_error():
    cisa_kev_client = client.CisaKevClient()
    error = HTTPError(
        cisa_kev_client.url,
        503,
        "Service Unavailable",
        hdrs=None,
        fp=None,
    )

    with patch.object(client, "urlopen", side_effect=error):
        with pytest.raises(Exception, match="HTTP error: 503 - Service Unavailable"):
            cisa_kev_client.get_catalog()


def test_get_catalog_wraps_url_error():
    cisa_kev_client = client.CisaKevClient()

    with patch.object(client, "urlopen", side_effect=URLError("timeout")):
        with pytest.raises(Exception, match="URL error: timeout"):
            cisa_kev_client.get_catalog()


def test_healthz_returns_ok_payload(monkeypatch):
    handler = build_handler("/healthz", Mock())
    monkeypatch.setattr(main, "log_event", Mock())

    handler.do_GET()

    handler.send_response.assert_called_once_with(200)
    assert response_body(handler) == {"status": "ok"}


def test_catalog_returns_data(monkeypatch):
    cisa_kev_client = Mock()
    cisa_kev_client.get_catalog.return_value = {
        "title": "CISA KEV",
        "vulnerabilities": [{"cveID": "CVE-2026-0001"}, {"cveID": "CVE-2026-0002"}],
    }
    handler = build_handler("/catalog", cisa_kev_client)
    monkeypatch.setattr(main, "log_event", Mock())

    handler.do_GET()

    cisa_kev_client.get_catalog.assert_called_once_with()
    handler.send_response.assert_called_once_with(200)
    assert response_body(handler) == {
        "service": "cisa-kev-ingestion",
        "vulnerabilities_count": 2,
        "data": {
            "title": "CISA KEV",
            "vulnerabilities": [
                {"cveID": "CVE-2026-0001"},
                {"cveID": "CVE-2026-0002"},
            ],
        },
    }


def test_catalog_returns_500_on_client_error(monkeypatch):
    cisa_kev_client = Mock()
    cisa_kev_client.get_catalog.side_effect = Exception("upstream failure")
    log_event = Mock()
    handler = build_handler("/catalog", cisa_kev_client)
    monkeypatch.setattr(main, "log_event", log_event)

    handler.do_GET()

    handler.send_response.assert_called_once_with(500)
    assert response_body(handler) == {"error": "upstream failure"}
    assert log_event.call_args_list[1].kwargs["event"] == "request_failed"


def test_build_catalog_object_key_uses_timestamp_path():
    timestamp = datetime(2026, 3, 14, 17, 37, 53, tzinfo=timezone.utc)

    assert (
        main.build_catalog_object_key(timestamp)
        == "cisa-kev/catalog/2026/03/14/173753Z.json"
    )


def test_compute_catalog_hash_is_deterministic_for_key_order():
    first_payload = {
        "catalogVersion": "2026.03.17",
        "vulnerabilities": [{"cveID": "CVE-2026-0001", "vendorProject": "Acme"}],
    }
    second_payload = {
        "vulnerabilities": [{"vendorProject": "Acme", "cveID": "CVE-2026-0001"}],
        "catalogVersion": "2026.03.17",
    }

    assert main.compute_catalog_hash(first_payload) == main.compute_catalog_hash(
        second_payload
    )


def test_persist_catalog_snapshot_writes_to_raw_feeds(monkeypatch):
    fixed_time = datetime(2026, 3, 14, 17, 37, 53, 689616, tzinfo=timezone.utc)
    minio_client = Mock()
    storage_client = Mock()
    storage_client.get_client.return_value = minio_client
    monkeypatch.setattr(main, "utcnow", lambda: fixed_time)
    monkeypatch.setattr(main, "StorageClient", Mock(return_value=storage_client))

    result = main.persist_catalog_snapshot(
        {
            "title": "CISA KEV",
            "vulnerabilities": [{"cveID": "CVE-2026-0001"}],
        }
    )

    put_call = minio_client.put_object.call_args
    assert put_call.args[0] == "raw-feeds"
    assert put_call.args[1] == "cisa-kev/catalog/2026/03/14/173753Z.json"
    assert put_call.kwargs["content_type"] == "application/json"
    payload = json.loads(put_call.args[2].read().decode("utf-8"))
    assert payload == {
        "source": "cisa-kev",
        "feed": "catalog",
        "fetched_at": "2026-03-14T17:37:53.689616+00:00",
        "service": "cisa-kev-ingestion",
        "content_hash": main.compute_catalog_hash(
            {
                "title": "CISA KEV",
                "vulnerabilities": [{"cveID": "CVE-2026-0001"}],
            }
        ),
        "data": {
            "title": "CISA KEV",
            "vulnerabilities": [{"cveID": "CVE-2026-0001"}],
        },
    }
    assert result == {
        "changed": True,
        "snapshot_written": True,
        "bucket": "raw-feeds",
        "object_key": "cisa-kev/catalog/2026/03/14/173753Z.json",
        "content_hash": main.compute_catalog_hash(
            {
                "title": "CISA KEV",
                "vulnerabilities": [{"cveID": "CVE-2026-0001"}],
            }
        ),
        "checked_at": "2026-03-14T17:37:53.689616+00:00",
        "fetched_at": "2026-03-14T17:37:53.689616+00:00",
        "vulnerabilities_count": 1,
    }


def test_get_latest_catalog_snapshot_returns_latest_object(monkeypatch):
    first_object = Mock()
    first_object.object_name = "cisa-kev/catalog/2026/03/16/020500Z.json"
    second_object = Mock()
    second_object.object_name = "cisa-kev/catalog/2026/03/17/020500Z.json"
    minio_client = Mock()
    minio_client.list_objects.return_value = [first_object, second_object]
    response = Mock()
    response.read.return_value = json.dumps(
        {
            "source": "cisa-kev",
            "feed": "catalog",
            "fetched_at": "2026-03-17T02:05:00+00:00",
            "service": "cisa-kev-ingestion",
            "content_hash": "abc123",
            "data": {"vulnerabilities": [{"cveID": "CVE-2026-0002"}]},
        }
    ).encode("utf-8")
    minio_client.get_object.return_value = response
    storage_client = Mock()
    storage_client.get_client.return_value = minio_client

    snapshot = main.get_latest_catalog_snapshot(storage_client)

    minio_client.list_objects.assert_called_once_with(
        "raw-feeds",
        prefix="cisa-kev/catalog/",
        recursive=True,
    )
    minio_client.get_object.assert_called_once_with(
        "raw-feeds", "cisa-kev/catalog/2026/03/17/020500Z.json"
    )
    assert snapshot["object_key"] == "cisa-kev/catalog/2026/03/17/020500Z.json"
    assert snapshot["content_hash"] == "abc123"
    response.close.assert_called_once_with()
    response.release_conn.assert_called_once_with()


def test_ingest_catalog_snapshot_writes_first_snapshot(monkeypatch):
    fixed_time = datetime(2026, 3, 17, 2, 5, 0, tzinfo=timezone.utc)
    minio_client = Mock()
    minio_client.list_objects.return_value = []
    storage_client = Mock()
    storage_client.get_client.return_value = minio_client
    monkeypatch.setattr(main, "StorageClient", Mock(return_value=storage_client))
    monkeypatch.setattr(main, "utcnow", lambda: fixed_time)

    result = main.ingest_catalog_snapshot(
        {"vulnerabilities": [{"cveID": "CVE-2026-0001"}]}
    )

    assert result == {
        "changed": True,
        "snapshot_written": True,
        "bucket": "raw-feeds",
        "object_key": "cisa-kev/catalog/2026/03/17/020500Z.json",
        "content_hash": main.compute_catalog_hash(
            {"vulnerabilities": [{"cveID": "CVE-2026-0001"}]}
        ),
        "checked_at": "2026-03-17T02:05:00+00:00",
        "fetched_at": "2026-03-17T02:05:00+00:00",
        "vulnerabilities_count": 1,
    }


def test_ingest_catalog_snapshot_writes_new_snapshot_when_changed(monkeypatch):
    first_time = datetime(2026, 3, 17, 2, 5, 0, tzinfo=timezone.utc)
    second_time = datetime(2026, 3, 17, 2, 5, 5, tzinfo=timezone.utc)
    minio_client = Mock()
    existing_object = Mock()
    existing_object.object_name = "cisa-kev/catalog/2026/03/16/020500Z.json"
    minio_client.list_objects.return_value = [existing_object]
    response = Mock()
    response.read.return_value = json.dumps(
        {
            "data": {"vulnerabilities": [{"cveID": "CVE-2026-0001"}]},
            "content_hash": main.compute_catalog_hash(
                {"vulnerabilities": [{"cveID": "CVE-2026-0001"}]}
            ),
        }
    ).encode("utf-8")
    minio_client.get_object.return_value = response
    storage_client = Mock()
    storage_client.get_client.return_value = minio_client
    monkeypatch.setattr(main, "StorageClient", Mock(return_value=storage_client))
    timestamps = iter([first_time, second_time])
    monkeypatch.setattr(main, "utcnow", lambda: next(timestamps))

    result = main.ingest_catalog_snapshot(
        {"vulnerabilities": [{"cveID": "CVE-2026-0002"}]}
    )

    assert result["changed"] is True
    assert result["snapshot_written"] is True
    assert result["object_key"] == "cisa-kev/catalog/2026/03/17/020505Z.json"
    assert result["checked_at"] == "2026-03-17T02:05:00+00:00"
    assert result["fetched_at"] == "2026-03-17T02:05:05+00:00"
    assert result["vulnerabilities_count"] == 1


def test_ingest_catalog_snapshot_skips_write_when_unchanged(monkeypatch):
    fixed_time = datetime(2026, 3, 17, 2, 5, 0, tzinfo=timezone.utc)
    minio_client = Mock()
    existing_object = Mock()
    existing_object.object_name = "cisa-kev/catalog/2026/03/16/020500Z.json"
    minio_client.list_objects.return_value = [existing_object]
    latest_payload = {"vulnerabilities": [{"cveID": "CVE-2026-0001"}]}
    response = Mock()
    response.read.return_value = json.dumps(
        {
            "data": latest_payload,
            "content_hash": main.compute_catalog_hash(latest_payload),
        }
    ).encode("utf-8")
    minio_client.get_object.return_value = response
    storage_client = Mock()
    storage_client.get_client.return_value = minio_client
    monkeypatch.setattr(main, "StorageClient", Mock(return_value=storage_client))
    monkeypatch.setattr(main, "utcnow", lambda: fixed_time)

    result = main.ingest_catalog_snapshot(latest_payload)

    assert result == {
        "changed": False,
        "snapshot_written": False,
        "checked_at": "2026-03-17T02:05:00+00:00",
        "content_hash": main.compute_catalog_hash(latest_payload),
        "last_object_key": "cisa-kev/catalog/2026/03/16/020500Z.json",
        "vulnerabilities_count": 1,
    }
    minio_client.put_object.assert_not_called()


def test_ingest_catalog_persists_snapshot(monkeypatch):
    cisa_kev_client = Mock()
    cisa_kev_client.get_catalog.return_value = {
        "vulnerabilities": [{"cveID": "CVE-2026-0001"}]
    }
    handler = build_handler("/ingest/catalog", cisa_kev_client, method="POST")
    monkeypatch.setattr(main, "log_event", Mock())
    monkeypatch.setattr(
        main,
        "ingest_catalog_snapshot",
        Mock(
            return_value={
                "changed": True,
                "snapshot_written": True,
                "bucket": "raw-feeds",
                "object_key": "cisa-kev/catalog/2026/03/14/173753Z.json",
                "content_hash": "abc123",
                "checked_at": "2026-03-14T17:37:54+00:00",
                "fetched_at": "2026-03-14T17:37:53.689616+00:00",
                "vulnerabilities_count": 1,
            }
        ),
    )

    handler.do_POST()

    cisa_kev_client.get_catalog.assert_called_once_with()
    handler.send_response.assert_called_once_with(200)
    assert response_body(handler) == {
        "service": "cisa-kev-ingestion",
        "feed": "catalog",
        "changed": True,
        "snapshot_written": True,
        "bucket": "raw-feeds",
        "object_key": "cisa-kev/catalog/2026/03/14/173753Z.json",
        "content_hash": "abc123",
        "checked_at": "2026-03-14T17:37:54+00:00",
        "fetched_at": "2026-03-14T17:37:53.689616+00:00",
        "vulnerabilities_count": 1,
    }


def test_ingest_catalog_returns_unchanged_response(monkeypatch):
    cisa_kev_client = Mock()
    cisa_kev_client.get_catalog.return_value = {"vulnerabilities": []}
    handler = build_handler("/ingest/catalog", cisa_kev_client, method="POST")
    monkeypatch.setattr(main, "log_event", Mock())
    monkeypatch.setattr(
        main,
        "ingest_catalog_snapshot",
        Mock(
            return_value={
                "changed": False,
                "snapshot_written": False,
                "checked_at": "2026-03-17T02:05:00+00:00",
                "content_hash": "same-hash",
                "last_object_key": "cisa-kev/catalog/2026/03/16/020500Z.json",
                "vulnerabilities_count": 0,
            }
        ),
    )

    handler.do_POST()

    handler.send_response.assert_called_once_with(200)
    assert response_body(handler) == {
        "service": "cisa-kev-ingestion",
        "feed": "catalog",
        "changed": False,
        "snapshot_written": False,
        "checked_at": "2026-03-17T02:05:00+00:00",
        "content_hash": "same-hash",
        "last_object_key": "cisa-kev/catalog/2026/03/16/020500Z.json",
        "vulnerabilities_count": 0,
    }


def test_ingest_catalog_returns_500_on_persist_error(monkeypatch):
    cisa_kev_client = Mock()
    cisa_kev_client.get_catalog.return_value = {"vulnerabilities": []}
    log_event = Mock()
    handler = build_handler("/ingest/catalog", cisa_kev_client, method="POST")
    monkeypatch.setattr(main, "log_event", log_event)
    monkeypatch.setattr(
        main,
        "ingest_catalog_snapshot",
        Mock(side_effect=Exception("storage failure")),
    )

    handler.do_POST()

    handler.send_response.assert_called_once_with(500)
    assert response_body(handler) == {"error": "storage failure"}
    assert log_event.call_args_list[1].kwargs["method"] == "POST"
