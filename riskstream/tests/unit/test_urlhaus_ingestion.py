import gzip
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
import archive_main  # noqa: E402
import feed_store  # noqa: E402
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


class FakeBinaryResponse:
    def __init__(self, payload: bytes):
        self.payload = payload

    def read(self):
        return self.payload

    def close(self):
        return None

    def release_conn(self):
        return None


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
        "id,url,status,threat\n"
        "1,https://bad.example,online,payload_delivery\n"
    )

    assert urlhaus_client.parse_recent_csv(csv_payload) == [
        {
            "id": "1",
            "url": "https://bad.example",
            "status": "online",
            "threat": "payload_delivery",
        }
    ]


def test_parse_recent_csv_accepts_commented_header_row():
    urlhaus_client = client.UrlhausClient()
    csv_payload = (
        "# generated every 5 minutes\n"
        "# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"
        '"3799807","2026-03-19 14:49:13","http://221.200.214.87:54591/i","online","2026-03-19 14:49:13","malware_download","32-bit,elf,mips,Mozi","https://urlhaus.abuse.ch/url/3799807/","geenensp"\n'
    )

    assert urlhaus_client.parse_recent_csv(csv_payload) == [
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
        "raw_csv": "id,url,status\n1,https://bad.example,online\n",
        "urls": [{"id": "1", "url": "https://bad.example", "status": "online"}],
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
            "raw_csv": "id,url,status\n1,https://bad.example,online\n",
            "urls": [{"id": "1", "url": "https://bad.example", "status": "online"}],
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


def test_build_checkpoint_object_key_uses_daily_path():
    timestamp = datetime(2026, 3, 14, 17, 37, 53, tzinfo=timezone.utc)

    assert (
        feed_store.build_checkpoint_object_key(timestamp)
        == "urlhaus/checkpoints/2026/03/14/000000Z.json.gz"
    )


def test_build_delta_object_key_uses_hash_partition_path():
    timestamp = datetime(2026, 3, 14, 17, 37, 53, tzinfo=timezone.utc)

    assert (
        feed_store.build_delta_object_key(timestamp, "abc123")
        == "urlhaus/deltas/2026/03/14/abc123.json.gz"
    )


def test_compute_recent_hash_is_deterministic_for_raw_csv():
    payload = {
        "raw_csv": "id,url,status\n1,https://bad.example,online\n",
        "urls": [{"id": "1", "url": "https://bad.example", "status": "online"}],
    }

    assert feed_store.compute_recent_hash(payload) == feed_store.compute_recent_hash(
        payload
    )


def test_write_checkpoint_if_needed_writes_gzip_payload(monkeypatch):
    fixed_time = datetime(2026, 3, 14, 17, 37, 53, tzinfo=timezone.utc)
    minio_client = Mock()
    storage_client = Mock()
    storage_client.get_client.return_value = minio_client
    monkeypatch.setattr(feed_store, "list_object_names", Mock(return_value=[]))

    object_key = feed_store.write_checkpoint_if_needed(
        storage_client,
        {
            "source_url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
            "raw_csv": "id,url,status\n1,https://bad.example,online\n",
            "urls": [{"id": "1", "url": "https://bad.example", "status": "online"}],
        },
        fixed_time,
        "abc123",
    )

    assert object_key == "urlhaus/checkpoints/2026/03/14/000000Z.json.gz"
    put_call = minio_client.put_object.call_args
    assert put_call.args[0] == "raw-feeds"
    assert put_call.args[1] == object_key
    assert put_call.kwargs["content_type"] == "application/gzip"
    payload = json.loads(gzip.decompress(put_call.args[2].read()).decode("utf-8"))
    assert payload == {
        "source": "urlhaus",
        "feed": "recent",
        "fetched_at": "2026-03-14T17:37:53+00:00",
        "service": "urlhaus-ingestion",
        "content_hash": "abc123",
        "data": {
            "source_url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
            "raw_csv": "id,url,status\n1,https://bad.example,online\n",
        },
    }


def test_build_delta_payload_classifies_added_updated_removed():
    previous_state = {
        "content_hash": "oldhash",
        "records_by_id": {
            "1": {"id": "1", "url": "https://one.example", "url_status": "online"},
            "2": {"id": "2", "url": "https://two.example", "url_status": "online"},
        },
    }
    payload, counts = feed_store.build_delta_payload(
        previous_state,
        {
            "source_url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
            "raw_csv": "ignored",
            "urls": [
                {"id": "1", "url": "https://one.example", "url_status": "offline"},
                {"id": "3", "url": "https://three.example", "url_status": "online"},
            ],
        },
        datetime(2026, 3, 14, tzinfo=timezone.utc),
        "newhash",
    )

    assert counts == {"added": 1, "updated": 1, "removed": 1}
    assert payload["previous_content_hash"] == "oldhash"
    assert payload["data"]["added"] == [
        {"id": "3", "url": "https://three.example", "url_status": "online"}
    ]
    assert payload["data"]["updated"] == [
        {"id": "1", "url": "https://one.example", "url_status": "offline"}
    ]
    assert payload["data"]["removed"] == [
        {
            "id": "2",
            "url": "https://two.example",
            "url_status": "online",
            "reason": "missing_from_recent_feed",
        }
    ]


def test_ingest_recent_feed_first_run_writes_checkpoint_delta_and_state(monkeypatch):
    storage_client = Mock()
    monkeypatch.setattr(feed_store, "get_latest_state", Mock(return_value=None))
    monkeypatch.setattr(
        feed_store,
        "write_checkpoint_if_needed",
        Mock(return_value="urlhaus/checkpoints/2026/03/14/000000Z.json.gz"),
    )
    monkeypatch.setattr(
        feed_store,
        "write_delta",
        Mock(
            return_value=(
                "urlhaus/deltas/2026/03/14/abc123.json.gz",
                {"added": 1, "updated": 0, "removed": 0},
            )
        ),
    )
    monkeypatch.setattr(
        feed_store,
        "write_latest_state",
        Mock(return_value=feed_store.STATE_OBJECT_KEY),
    )

    result = feed_store.ingest_recent_feed(
        {
            "source_url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
            "raw_csv": "id,url,status\n1,https://bad.example,online\n",
            "urls": [{"id": "1", "url": "https://bad.example", "status": "online"}],
        },
        storage=storage_client,
        now=datetime(2026, 3, 14, 17, 37, 53, tzinfo=timezone.utc),
    )

    assert result == {
        "changed": True,
        "checkpoint_written": True,
        "delta_written": True,
        "delta_counts": {"added": 1, "updated": 0, "removed": 0},
        "checked_at": "2026-03-14T17:37:53+00:00",
        "content_hash": feed_store.compute_recent_hash(
            {
                "source_url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
                "raw_csv": "id,url,status\n1,https://bad.example,online\n",
                "urls": [
                    {"id": "1", "url": "https://bad.example", "status": "online"}
                ],
            }
        ),
        "urls_count": 1,
        "checkpoint_object_key": "urlhaus/checkpoints/2026/03/14/000000Z.json.gz",
        "delta_object_key": "urlhaus/deltas/2026/03/14/abc123.json.gz",
        "state_object_key": "urlhaus/state/latest.json.gz",
    }


def test_ingest_recent_feed_no_change_writes_only_daily_checkpoint(monkeypatch):
    recent_data = {
        "source_url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "raw_csv": "id,url,status\n1,https://bad.example,online\n",
        "urls": [{"id": "1", "url": "https://bad.example", "status": "online"}],
    }
    content_hash = feed_store.compute_recent_hash(recent_data)
    storage_client = Mock()
    monkeypatch.setattr(
        feed_store,
        "get_latest_state",
        Mock(return_value={"content_hash": content_hash, "records_by_id": {}}),
    )
    monkeypatch.setattr(
        feed_store,
        "write_checkpoint_if_needed",
        Mock(return_value="urlhaus/checkpoints/2026/03/15/000000Z.json.gz"),
    )
    monkeypatch.setattr(feed_store, "write_delta", Mock())
    monkeypatch.setattr(feed_store, "write_latest_state", Mock())

    result = feed_store.ingest_recent_feed(
        recent_data,
        storage=storage_client,
        now=datetime(2026, 3, 15, 0, 1, tzinfo=timezone.utc),
    )

    assert result == {
        "changed": False,
        "checkpoint_written": True,
        "delta_written": False,
        "delta_counts": {"added": 0, "updated": 0, "removed": 0},
        "checked_at": "2026-03-15T00:01:00+00:00",
        "content_hash": content_hash,
        "urls_count": 1,
        "checkpoint_object_key": "urlhaus/checkpoints/2026/03/15/000000Z.json.gz",
    }


def test_run_archive_lifecycle_moves_old_hot_objects_and_deletes_old_archives(monkeypatch):
    old_raw_checkpoint = Mock()
    old_raw_checkpoint.object_name = "urlhaus/checkpoints/2026/01/01/000000Z.json.gz"
    old_raw_delta = Mock()
    old_raw_delta.object_name = "urlhaus/deltas/2026/01/01/abc123.json.gz"
    recent_raw_delta = Mock()
    recent_raw_delta.object_name = "urlhaus/deltas/2026/03/10/abc123.json.gz"
    old_archive_delta = Mock()
    old_archive_delta.object_name = "urlhaus/deltas/2025/01/01/abc123.json.gz"
    recent_archive_checkpoint = Mock()
    recent_archive_checkpoint.object_name = "urlhaus/checkpoints/2026/01/15/000000Z.json.gz"

    minio_client = Mock()

    def list_objects(bucket, prefix, recursive):
        assert recursive is True
        if bucket == "raw-feeds" and prefix == "urlhaus/checkpoints/":
            return [old_raw_checkpoint]
        if bucket == "raw-feeds" and prefix == "urlhaus/deltas/":
            return [old_raw_delta, recent_raw_delta]
        if bucket == "archives" and prefix == "urlhaus/checkpoints/":
            return [recent_archive_checkpoint]
        if bucket == "archives" and prefix == "urlhaus/deltas/":
            return [old_archive_delta]
        return []

    minio_client.list_objects.side_effect = list_objects
    minio_client.get_object.return_value = FakeBinaryResponse(b"payload")
    storage_client = Mock()
    storage_client.get_client.return_value = minio_client

    result = feed_store.run_archive_lifecycle(
        storage=storage_client,
        now=datetime(2026, 3, 20, tzinfo=timezone.utc),
        hot_retention_days=30,
        archive_retention_days=180,
    )

    assert result == {
        "hot_retention_days": 30,
        "archive_retention_days": 180,
        "archived_object_count": 2,
        "pruned_hot_object_count": 2,
        "deleted_archive_object_count": 1,
        "checked_at": "2026-03-20T00:00:00+00:00",
    }
    minio_client.remove_object.assert_any_call(
        "raw-feeds", "urlhaus/checkpoints/2026/01/01/000000Z.json.gz"
    )
    minio_client.remove_object.assert_any_call(
        "raw-feeds", "urlhaus/deltas/2026/01/01/abc123.json.gz"
    )
    minio_client.remove_object.assert_any_call(
        "archives", "urlhaus/deltas/2025/01/01/abc123.json.gz"
    )


def test_archive_main_reads_reference_time_override(monkeypatch):
    reference_time = "2026-04-19T00:00:00+00:00"
    monkeypatch.setenv("URLHAUS_ARCHIVE_REFERENCE_TIME", reference_time)

    assert archive_main.get_reference_time() == datetime.fromisoformat(reference_time)


def test_archive_main_rejects_invalid_reference_time(monkeypatch):
    monkeypatch.setenv("URLHAUS_ARCHIVE_REFERENCE_TIME", "not-a-timestamp")

    with pytest.raises(
        ValueError,
        match="Invalid URLHAUS_ARCHIVE_REFERENCE_TIME; expected ISO-8601 timestamp",
    ):
        archive_main.get_reference_time()


def test_archive_main_passes_reference_time_to_lifecycle(monkeypatch):
    reference_time = datetime(2026, 4, 19, tzinfo=timezone.utc)
    run_archive = Mock(
        return_value={
            "hot_retention_days": 30,
            "archive_retention_days": 180,
            "archived_object_count": 1,
            "pruned_hot_object_count": 1,
            "deleted_archive_object_count": 0,
            "checked_at": "2026-04-19T00:00:00+00:00",
        }
    )
    monkeypatch.setenv("URLHAUS_ARCHIVE_REFERENCE_TIME", "2026-04-19T00:00:00+00:00")
    monkeypatch.setattr(archive_main, "configure_logging", Mock())
    monkeypatch.setattr(archive_main, "log_event", Mock())
    monkeypatch.setattr(archive_main, "run_archive_lifecycle", run_archive)

    archive_main.run()

    run_archive.assert_called_once_with(
        now=reference_time,
        hot_retention_days=30,
        archive_retention_days=180,
    )


def test_ingest_recent_endpoint_returns_checkpoint_delta_contract(monkeypatch):
    urlhaus_client = Mock()
    urlhaus_client.get_recent_urls.return_value = {
        "raw_csv": "id,url,status\n1,https://bad.example,online\n",
        "content_hash": "abc123",
        "urls": [{"id": "1", "url": "https://bad.example", "status": "online"}],
    }
    handler = build_handler("/ingestion/recent", urlhaus_client, method="POST")
    monkeypatch.setattr(main, "log_event", Mock())
    monkeypatch.setattr(
        main,
        "ingest_recent_snapshot",
        Mock(
            return_value={
                "changed": True,
                "checkpoint_written": True,
                "delta_written": True,
                "delta_counts": {"added": 1, "updated": 0, "removed": 0},
                "checked_at": "2026-03-14T17:37:53+00:00",
                "content_hash": "abc123",
                "urls_count": 1,
                "checkpoint_object_key": "urlhaus/checkpoints/2026/03/14/000000Z.json.gz",
                "delta_object_key": "urlhaus/deltas/2026/03/14/abc123.json.gz",
                "state_object_key": "urlhaus/state/latest.json.gz",
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
        "checkpoint_written": True,
        "delta_written": True,
        "delta_counts": {"added": 1, "updated": 0, "removed": 0},
        "checked_at": "2026-03-14T17:37:53+00:00",
        "content_hash": "abc123",
        "urls_count": 1,
        "checkpoint_object_key": "urlhaus/checkpoints/2026/03/14/000000Z.json.gz",
        "delta_object_key": "urlhaus/deltas/2026/03/14/abc123.json.gz",
        "state_object_key": "urlhaus/state/latest.json.gz",
    }


def test_ingest_recent_returns_500_on_storage_error(monkeypatch):
    urlhaus_client = Mock()
    urlhaus_client.get_recent_urls.return_value = {
        "raw_csv": "id,url,status\n1,https://bad.example,online\n",
        "content_hash": "abc123",
        "urls": [{"id": "1", "url": "https://bad.example", "status": "online"}],
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
