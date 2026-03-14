import io
import json
import sys
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError

import pytest


THREATFOX_SRC = (
    Path(__file__).resolve().parents[2] / "services" / "ingestion" / "threatfox" / "src"
)
if str(THREATFOX_SRC) not in sys.path:
    sys.path.insert(0, str(THREATFOX_SRC))

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


def build_handler(path, threatfox_client):
    handler = main.Handler.__new__(main.Handler)
    handler.path = path
    handler.command = "GET"
    handler.client = threatfox_client
    handler.wfile = io.BytesIO()
    handler.send_response = Mock()
    handler.send_header = Mock()
    handler.end_headers = Mock()
    return handler


def response_body(handler):
    return json.loads(handler.wfile.getvalue().decode("utf-8"))


def test_make_request_requires_auth_key(monkeypatch):
    monkeypatch.delenv("THREATFOX_AUTH_KEY", raising=False)

    threatfox_client = client.ThreatFoxClient()

    with pytest.raises(Exception, match="THREATFOX_AUTH_KEY"):
        threatfox_client.get_recent_threats()


def test_make_request_sends_auth_header(monkeypatch):
    monkeypatch.setenv("THREATFOX_AUTH_KEY", "secret-key")
    threatfox_client = client.ThreatFoxClient(timeout=12)

    with patch.object(client, "urlopen", return_value=FakeResponse({"data": []})) as mock_urlopen:
        response = threatfox_client.get_recent_threats(days=3)

    request = mock_urlopen.call_args.args[0]
    assert request.headers["Auth-key"] == "secret-key"
    assert mock_urlopen.call_args.kwargs["timeout"] == 12
    assert response == {"data": []}


def test_make_request_wraps_http_error(monkeypatch):
    monkeypatch.setenv("THREATFOX_AUTH_KEY", "secret-key")
    threatfox_client = client.ThreatFoxClient()
    error = HTTPError(
        threatfox_client.BASE_URL,
        401,
        "Unauthorized",
        hdrs=None,
        fp=None,
    )

    with patch.object(client, "urlopen", side_effect=error):
        with pytest.raises(Exception, match="HTTP error: 401 - Unauthorized"):
            threatfox_client.get_recent_threats()


def test_make_request_wraps_url_error(monkeypatch):
    monkeypatch.setenv("THREATFOX_AUTH_KEY", "secret-key")
    threatfox_client = client.ThreatFoxClient()

    with patch.object(client, "urlopen", side_effect=URLError("timeout")):
        with pytest.raises(Exception, match="URL error: timeout"):
            threatfox_client.get_recent_threats()


def test_healthz_returns_ok_payload(monkeypatch):
    handler = build_handler("/healthz", Mock())
    monkeypatch.setattr(main, "log_event", Mock())

    handler.do_GET()

    handler.send_response.assert_called_once_with(200)
    assert response_body(handler) == {"status": "ok"}


def test_recent_returns_threat_data(monkeypatch):
    threatfox_client = Mock()
    threatfox_client.get_recent_threats.return_value = {
        "data": [{"ioc": "1.2.3.4"}, {"ioc": "5.6.7.8"}]
    }
    handler = build_handler("/recent", threatfox_client)
    monkeypatch.setattr(main, "log_event", Mock())

    handler.do_GET()

    threatfox_client.get_recent_threats.assert_called_once_with(days=1)
    handler.send_response.assert_called_once_with(200)
    assert response_body(handler) == {
        "service": "threatfox-ingestion",
        "threats_count": 2,
        "data": {"data": [{"ioc": "1.2.3.4"}, {"ioc": "5.6.7.8"}]},
    }


def test_recent_returns_500_on_client_error(monkeypatch):
    threatfox_client = Mock()
    threatfox_client.get_recent_threats.side_effect = Exception("upstream failure")
    log_event = Mock()
    handler = build_handler("/recent", threatfox_client)
    monkeypatch.setattr(main, "log_event", log_event)

    handler.do_GET()

    handler.send_response.assert_called_once_with(500)
    assert response_body(handler) == {"error": "upstream failure"}
    assert log_event.call_args_list[1].kwargs["event"] == "request_failed"
