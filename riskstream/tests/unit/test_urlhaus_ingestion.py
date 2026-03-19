import io
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError

import pytest


URLHAUS_SRC = (
    Path(__file__).resolve().parents[2] / "services" / "ingestion" / "urlhaus" / "src"
)
if str(URLHAUS_SRC) not in sys.path:
    sys.path.insert(0, str(URLHAUS_SRC))

import client  # noqa: E402
import main  # noqa: E402


class FakeResponse:
    def __init__(self, payload: str, status: int = 200):
        self.payload = payload
        self.status = status

    def read(self):
        return self.payload.encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def build_handler(path, urlhaus_client, method="GET"):
    handler = main.Handler.__new__(main.Handler)
    handler.path = path
    handler.command = method
    handler.client = urlhaus_client
    handler.wfile = io.BytesIO()
    handler.send_response = Mock()
    handler.send_header = Mock()
    handler.end_headers = Mock()
    return handler


def response_body(handler):
    return json.loads(handler.wfile.getvalue().decode("utf-8"))


def test_get_recent_urls_uses_default_url(monkeypatch):
    monkeypatch.delenv("URLHAUS_RECENT_URL", raising=False)
    monkeypatch.delenv("URLHAUS_AUTH_KEY", raising=False)
    urlhaus_client = client.UrlhausClient(timeout=12)

    csv_payload = "# comment\nurl,status\nhttps://bad.example,online\n"
    with patch.object(client, "urlopen", return_value=FakeResponse(csv_payload)) as mock_urlopen:
        response = urlhaus_client.get_recent_urls()

    request = mock_urlopen.call_args.args[0]
    assert request.full_url == client.UrlhausClient.DEFAULT_RECENT_URL
    assert request.headers["Accept"] == "text/csv"
    assert mock_urlopen.call_args.kwargs["timeout"] == 12
    assert response["urls"] == [
        {"url": "https://bad.example", "status": "online"},
    ]


def test_get_recent_urls_uses_env_override_and_auth(monkeypatch):
    monkeypatch.setenv("URLHAUS_RECENT_URL", "https://example.com/recent.csv")
    monkeypatch.setenv("URLHAUS_AUTH_KEY", "secret-key")
    urlhaus_client = client.UrlhausClient()

    csv_payload = "url,status\nhttps://bad.example,online\n"
    with patch.object(client, "urlopen", return_value=FakeResponse(csv_payload)) as mock_urlopen:
        urlhaus_client.get_recent_urls()

    request = mock_urlopen.call_args.args[0]
    assert request.full_url == "https://example.com/recent.csv?auth-key=secret-key"
    assert request.headers["Auth-key"] == "secret-key"


def test_parse_recent_csv_ignores_comments():
    urlhaus_client = client.UrlhausClient()
    csv_payload = (
        "# generated every 5 minutes\n"
        "# another comment\n"
        "url,status,threat\n"
        "https://bad.example,online,payload_delivery\n"
    )

    assert urlhaus_client.parse_recent_csv(csv_payload) == [
        {
            "url": "https://bad.example",
            "status": "online",
            "threat": "payload_delivery",
        }
    ]


def test_get_recent_urls_wraps_http_error():
    urlhaus_client = client.UrlhausClient()
    error = HTTPError(
        urlhaus_client.url,
        503,
        "Service Unavailable",
        hdrs=None,
        fp=None,
    )

    with patch.object(client, "urlopen", side_effect=error):
        with pytest.raises(Exception, match="HTTP error: 503 - Service Unavailable"):
            urlhaus_client.get_recent_urls()


def test_get_recent_urls_wraps_url_error():
    urlhaus_client = client.UrlhausClient()

    with patch.object(client, "urlopen", side_effect=URLError("timeout")):
        with pytest.raises(Exception, match="URL error: timeout"):
            urlhaus_client.get_recent_urls()


def test_healthz_returns_ok_payload(monkeypatch):
    handler = build_handler("/healthz", Mock())
    monkeypatch.setattr(main, "log_event", Mock())

    handler.do_GET()

    handler.send_response.assert_called_once_with(200)
    assert response_body(handler) == {"status": "ok"}


def test_recent_returns_urlhaus_data(monkeypatch):
    urlhaus_client = Mock()
    urlhaus_client.get_recent_urls.return_value = {
        "content_hash": "abc123",
        "raw_csv": "url,status\nhttps://bad.example,online\n",
        "urls": [{"url": "https://bad.example", "status": "online"}],
    }
    handler = build_handler("/recent", urlhaus_client)
    monkeypatch.setattr(main, "log_event", Mock())

    handler.do_GET()

    urlhaus_client.get_recent_urls.assert_called_once_with()
    handler.send_response.assert_called_once_with(200)
    assert response_body(handler) == {
        "service": "urlhaus-ingestion",
        "content_hash": "abc123",
        "urls_count": 1,
        "data": {
            "content_hash": "abc123",
            "raw_csv": "url,status\nhttps://bad.example,online\n",
            "urls": [{"url": "https://bad.example", "status": "online"}],
        },
    }


def test_recent_returns_500_on_client_error(monkeypatch):
    urlhaus_client = Mock()
    urlhaus_client.get_recent_urls.side_effect = Exception("upstream failure")
    log_event = Mock()
    handler = build_handler("/recent", urlhaus_client)
    monkeypatch.setattr(main, "log_event", log_event)

    handler.do_GET()

    handler.send_response.assert_called_once_with(500)
    assert response_body(handler) == {"error": "upstream failure"}
    assert log_event.call_args_list[1].kwargs["event"] == "request_failed"


def test_build_recent_object_key_uses_timestamp_path():
    timestamp = datetime(2026, 3, 14, 17, 37, 53, tzinfo=timezone.utc)

    assert (
        main.build_recent_object_key(timestamp)
        == "urlhaus/recent/2026/03/14/173753Z.json"
    )


def test_compute_recent_hash_is_deterministic_for_raw_csv():
    payload = {
        "raw_csv": "url,status\nhttps://bad.example,online\n",
        "urls": [{"url": "https://bad.example", "status": "online"}],
    }

    assert main.compute_recent_hash(payload) == main.compute_recent_hash(payload)


def test_persist_recent_snapshot_writes_to_raw_feeds(monkeypatch):
    fixed_time = datetime(2026, 3, 14, 17, 37, 53, 689616, tzinfo=timezone.utc)
    minio_client = Mock()
    storage_client = Mock()
    storage_client.get_client.return_value = minio_client
    monkeypatch.setattr(main, "utcnow", lambda: fixed_time)
    monkeypatch.setattr(main, "StorageClient", Mock(return_value=storage_client))

    result = main.persist_recent_snapshot(
        {
            "content_hash": "ignored-by-persist",
            "source_url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
            "raw_csv": "url,status\nhttps://bad.example,online\n",
            "urls": [{"url": "https://bad.example", "status": "online"}],
        }
    )

    put_call = minio_client.put_object.call_args
    assert put_call.args[0] == "raw-feeds"
    assert put_call.args[1] == "urlhaus/recent/2026/03/14/173753Z.json"
    assert put_call.kwargs["content_type"] == "application/json"
    payload = json.loads(put_call.args[2].read().decode("utf-8"))
    assert payload == {
        "source": "urlhaus",
        "feed": "recent",
        "fetched_at": "2026-03-14T17:37:53.689616+00:00",
        "service": "urlhaus-ingestion",
        "content_hash": main.compute_recent_hash(
            {
                "content_hash": "ignored-by-persist",
                "source_url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
                "raw_csv": "url,status\nhttps://bad.example,online\n",
                "urls": [{"url": "https://bad.example", "status": "online"}],
            }
        ),
        "data": {
            "source_url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
            "raw_csv": "url,status\nhttps://bad.example,online\n",
        },
    }
    assert result == {
        "changed": True,
        "snapshot_written": True,
        "bucket": "raw-feeds",
        "object_key": "urlhaus/recent/2026/03/14/173753Z.json",
        "content_hash": main.compute_recent_hash(
            {
                "content_hash": "ignored-by-persist",
                "source_url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
                "raw_csv": "url,status\nhttps://bad.example,online\n",
                "urls": [{"url": "https://bad.example", "status": "online"}],
            }
        ),
        "checked_at": "2026-03-14T17:37:53.689616+00:00",
        "fetched_at": "2026-03-14T17:37:53.689616+00:00",
        "urls_count": 1,
    }


def test_get_latest_recent_snapshot_returns_latest_object():
    first_object = Mock()
    first_object.object_name = "urlhaus/recent/2026/03/16/020500Z.json"
    second_object = Mock()
    second_object.object_name = "urlhaus/recent/2026/03/17/020500Z.json"
    minio_client = Mock()
    minio_client.list_objects.return_value = [first_object, second_object]
    response = Mock()
    response.read.return_value = json.dumps(
        {
            "source": "urlhaus",
            "feed": "recent",
            "fetched_at": "2026-03-17T02:05:00+00:00",
            "service": "urlhaus-ingestion",
            "content_hash": "abc123",
            "data": {
                "raw_csv": "url,status\nhttps://bad.example,online\n",
                "urls": [{"url": "https://bad.example", "status": "online"}],
            },
        }
    ).encode("utf-8")
    minio_client.get_object.return_value = response
    storage_client = Mock()
    storage_client.get_client.return_value = minio_client

    snapshot = main.get_latest_recent_snapshot(storage_client)

    minio_client.list_objects.assert_called_once_with(
        "raw-feeds",
        prefix="urlhaus/recent/",
        recursive=True,
    )
    minio_client.get_object.assert_called_once_with(
        "raw-feeds", "urlhaus/recent/2026/03/17/020500Z.json"
    )
    assert snapshot["object_key"] == "urlhaus/recent/2026/03/17/020500Z.json"


def test_ingest_recent_snapshot_returns_no_change_when_hash_matches(monkeypatch):
    recent_data = {
        "raw_csv": "url,status\nhttps://bad.example,online\n",
        "urls": [{"url": "https://bad.example", "status": "online"}],
    }
    content_hash = main.compute_recent_hash(recent_data)
    storage_client = Mock()
    monkeypatch.setattr(
        main,
        "get_latest_recent_snapshot",
        Mock(
            return_value={
                "object_key": "urlhaus/recent/2026/03/17/020500Z.json",
                "content_hash": content_hash,
            }
        ),
    )
    monkeypatch.setattr(main, "utcnow", lambda: datetime(2026, 3, 18, tzinfo=timezone.utc))

    result = main.ingest_recent_snapshot(recent_data, storage=storage_client)

    assert result == {
        "changed": False,
        "snapshot_written": False,
        "checked_at": "2026-03-18T00:00:00+00:00",
        "content_hash": content_hash,
        "last_object_key": "urlhaus/recent/2026/03/17/020500Z.json",
        "urls_count": 1,
    }


def test_ingest_recent_persists_snapshot(monkeypatch):
    urlhaus_client = Mock()
    urlhaus_client.get_recent_urls.return_value = {
        "raw_csv": "url,status\nhttps://bad.example,online\n",
        "content_hash": "abc123",
        "urls": [{"url": "https://bad.example", "status": "online"}],
    }
    handler = build_handler("/ingestion/recent", urlhaus_client, method="POST")
    monkeypatch.setattr(main, "log_event", Mock())
    monkeypatch.setattr(
        main,
        "ingest_recent_snapshot",
        Mock(
            return_value={
                "changed": True,
                "snapshot_written": True,
                "bucket": "raw-feeds",
                "object_key": "urlhaus/recent/2026/03/14/173753Z.json",
                "content_hash": "abc123",
                "checked_at": "2026-03-14T17:37:53.689616+00:00",
                "fetched_at": "2026-03-14T17:37:53.689616+00:00",
                "urls_count": 1,
            }
        ),
    )

    handler.do_POST()

    urlhaus_client.get_recent_urls.assert_called_once_with()
    handler.send_response.assert_called_once_with(200)
    assert response_body(handler) == {
        "service": "urlhaus-ingestion",
        "feed": "recent",
        "changed": True,
        "snapshot_written": True,
        "bucket": "raw-feeds",
        "object_key": "urlhaus/recent/2026/03/14/173753Z.json",
        "content_hash": "abc123",
        "checked_at": "2026-03-14T17:37:53.689616+00:00",
        "fetched_at": "2026-03-14T17:37:53.689616+00:00",
        "urls_count": 1,
    }


def test_ingest_recent_returns_500_on_persist_error(monkeypatch):
    urlhaus_client = Mock()
    urlhaus_client.get_recent_urls.return_value = {
        "raw_csv": "url,status\nhttps://bad.example,online\n",
        "content_hash": "abc123",
        "urls": [{"url": "https://bad.example", "status": "online"}],
    }
    log_event = Mock()
    handler = build_handler("/ingestion/recent", urlhaus_client, method="POST")
    monkeypatch.setattr(main, "log_event", log_event)
    monkeypatch.setattr(
        main,
        "ingest_recent_snapshot",
        Mock(side_effect=Exception("storage failure")),
    )

    handler.do_POST()

    handler.send_response.assert_called_once_with(500)
    assert response_body(handler) == {"error": "storage failure"}
    assert log_event.call_args_list[1].kwargs["method"] == "POST"
