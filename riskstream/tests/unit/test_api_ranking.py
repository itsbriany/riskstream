import gzip
import importlib.util
import io
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock

import pytest

API_MAIN_PATH = (
    Path(__file__).resolve().parents[2] / "services" / "api" / "src" / "main.py"
)
SPEC = importlib.util.spec_from_file_location("api_main", API_MAIN_PATH)
api_main = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(api_main)


class FakeListObject:
    def __init__(self, object_name):
        self.object_name = object_name


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def read(self):
        return self.payload

    def close(self):
        pass

    def release_conn(self):
        pass


class FakeMinioClient:
    def __init__(self, objects):
        self.objects = objects
        self.listed_prefixes = []

    def list_objects(self, bucket, prefix, recursive):
        assert bucket == "processed-data"
        assert recursive is True
        self.listed_prefixes.append(prefix)
        return [
            FakeListObject(object_name)
            for object_name in self.objects
            if object_name.startswith(prefix)
        ]

    def get_object(self, bucket, object_key):
        assert bucket == "processed-data"
        lines = "\n".join(json.dumps(record) for record in self.objects[object_key])
        return FakeResponse(gzip.compress(lines.encode("utf-8")))


class FakeStorageClient:
    def __init__(self, objects):
        self.minio_client = FakeMinioClient(objects)

    def get_client(self):
        return self.minio_client


def threatfox_record():
    return {
        "schema_version": "threat_signal.v1",
        "source": "threatfox",
        "feed": "recent",
        "signal_kind": "indicator",
        "action": "observed",
        "artifact_type": "domain",
        "artifact_value": "cache-dist-5.vitagrazia.in.net",
        "external_id": "1765567",
        "first_seen_at": "2026-04-24T10:00:00+00:00",
        "last_seen_at": "2026-04-24T10:05:00+00:00",
        "classification": "payload_delivery",
        "confidence": 100,
        "family": "ClearFake",
        "tags": ["ClearFake"],
        "raw_ref": {
            "bucket": "raw-feeds",
            "object_key": "threatfox/recent/2026/04/24/100500Z.json",
            "row_number": 1,
        },
    }


def urlhaus_record(action="observed"):
    return {
        "schema_version": "threat_signal.v1",
        "source": "urlhaus",
        "feed": "recent",
        "signal_kind": "indicator",
        "action": action,
        "artifact_type": "url",
        "artifact_value": "http://221.200.214.87:54591/i",
        "external_id": "3799807",
        "first_seen_at": "2026-04-24T11:00:00+00:00",
        "last_seen_at": "2026-04-24T11:05:00+00:00",
        "classification": "malware_download",
        "status": "online",
        "tags": ["Mozi"],
        "evidence_url": "https://urlhaus.abuse.ch/url/3799807/",
        "raw_ref": {
            "bucket": "raw-feeds",
            "object_key": "urlhaus/checkpoints/2026/04/24/110500Z.json.gz",
            "row_number": 1,
        },
    }


def cisa_kev_record():
    return {
        "schema_version": "threat_signal.v1",
        "source": "cisa-kev",
        "feed": "catalog",
        "signal_kind": "vulnerability",
        "action": "observed",
        "artifact_type": "cve",
        "artifact_value": "CVE-2026-0001",
        "external_id": "CVE-2026-0001",
        "raw_ref": {
            "bucket": "raw-feeds",
            "object_key": "cisa-kev/catalog/2026/04/24/090000Z.json",
            "row_number": 1,
        },
        "source_details": {
            "cisa-kev": {
                "requiredAction": "Apply the vendor patch.",
                "knownRansomwareCampaignUse": "Known",
            }
        },
    }


def test_ranking_options_returns_supported_vocabulary():
    options = api_main.ranking_options()

    assert options["ranker_version"] == "deterministic-v1"
    assert options["defaults"]["limit"] == 25
    assert options["limits"]["max_limit"] == 100
    assert "malware_delivery" in options["priorities"]
    assert "vulnerability" in options["signal_kinds"]


def test_parse_rank_request_defaults_and_caps_limit(monkeypatch):
    fixed_now = datetime(2026, 4, 24, 12, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(api_main, "utcnow", lambda: fixed_now)

    request = api_main.parse_rank_request({"limit": 250})

    assert request["tenant_id"] == "default"
    assert request["limit"] == 100
    assert request["context"] == {"environment_scope": "all", "priorities": []}
    assert request["filters"]["actions"] == ["observed", "updated"]
    assert (
        api_main.isoformat_z(request["time_window"]["since"]) == "2026-04-23T12:00:00Z"
    )
    assert (
        api_main.isoformat_z(request["time_window"]["until"]) == "2026-04-24T12:00:00Z"
    )


def test_parse_rank_request_rejects_unsupported_priority():
    with pytest.raises(api_main.RequestError, match="unsupported"):
        api_main.parse_rank_request({"context": {"priorities": ["made_up_priority"]}})


def test_parse_datetime_from_normalized_object_key():
    assert api_main.parse_datetime_from_object_key(
        "normalized/threat-signals/threat_signal.v1/threatfox/recent/2026/04/24/100500Z.jsonl.gz"
    ) == datetime(2026, 4, 24, 10, 5, tzinfo=timezone.utc)


def test_normalized_prefixes_for_time_window_are_stream_and_year_scoped():
    prefixes = api_main.normalized_prefixes_for_time_window(
        {
            "since": datetime(2026, 12, 31, tzinfo=timezone.utc),
            "until": datetime(2027, 1, 1, tzinfo=timezone.utc),
        }
    )

    assert (
        "normalized/threat-signals/threat_signal.v1/threatfox/recent/2026/" in prefixes
    )
    assert (
        "normalized/threat-signals/threat_signal.v1/urlhaus/recent/deltas/2027/"
        in prefixes
    )


def test_rank_threats_deduplicates_and_returns_ranked_cards(monkeypatch):
    fixed_now = datetime(2026, 4, 24, 12, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(api_main, "utcnow", lambda: fixed_now)
    objects = {
        "normalized/threat-signals/threat_signal.v1/urlhaus/recent/checkpoints/2026/04/24/a.jsonl.gz": [
            urlhaus_record("observed")
        ],
        "normalized/threat-signals/threat_signal.v1/urlhaus/recent/deltas/2026/04/24/b.jsonl.gz": [
            urlhaus_record("updated")
        ],
        "normalized/threat-signals/threat_signal.v1/threatfox/recent/2026/04/24/c.jsonl.gz": [
            threatfox_record()
        ],
        "normalized/threat-signals/threat_signal.v1/cisa-kev/catalog/2026/04/24/d.jsonl.gz": [
            cisa_kev_record()
        ],
    }

    response = api_main.rank_threats(
        {
            "tenant_id": "acme",
            "time_window": {
                "since": "2026-04-24T00:00:00Z",
                "until": "2026-04-24T12:00:00Z",
            },
            "context": {
                "environment_scope": "production",
                "priorities": ["malware_delivery", "active_exploitation"],
            },
            "limit": 10,
        },
        storage_client=FakeStorageClient(objects),
    )

    assert response["ranker_version"] == "deterministic-v1"
    assert response["tenant_id"] == "acme"
    assert response["result_count"] == 3
    assert response["results"][0]["signal"] == {
        "signal_kind": "indicator",
        "artifact_type": "url",
        "artifact_value": "http://221.200.214.87:54591/i",
    }
    assert response["results"][0]["severity"] == "critical"
    assert response["results"][0]["sources"] == ["urlhaus"]
    assert len(response["results"][0]["raw_refs"]) == 2
    assert "evidence_url" in response["results"][0]
    reason_codes = {reason["code"] for reason in response["results"][0]["reasons"]}
    assert "priority_match" in reason_codes
    assert "recently_updated" in reason_codes


def test_rank_threats_filters_by_tags_and_min_score(monkeypatch):
    fixed_now = datetime(2026, 4, 24, 12, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(api_main, "utcnow", lambda: fixed_now)
    objects = {
        "normalized/threat-signals/threat_signal.v1/urlhaus/recent/checkpoints/2026/04/24/a.jsonl.gz": [
            urlhaus_record()
        ],
        "normalized/threat-signals/threat_signal.v1/threatfox/recent/2026/04/24/b.jsonl.gz": [
            threatfox_record()
        ],
    }

    response = api_main.rank_threats(
        {
            "time_window": {
                "since": "2026-04-24T00:00:00Z",
                "until": "2026-04-24T12:00:00Z",
            },
            "filters": {"tags_any": ["Mozi"], "min_score": 80},
        },
        storage_client=FakeStorageClient(objects),
    )

    assert response["result_count"] == 1
    assert response["results"][0]["signal"]["artifact_type"] == "url"


def build_handler(path):
    handler = api_main.Handler.__new__(api_main.Handler)
    handler.path = path
    handler.command = "GET"
    handler.wfile = io.BytesIO()
    handler.send_response = Mock()
    handler.send_header = Mock()
    handler.end_headers = Mock()
    return handler


def response_body(handler):
    return json.loads(handler.wfile.getvalue().decode("utf-8"))


def test_json_formatter_merges_structured_fields():
    record = logging.LogRecord(
        "riskstream.api",
        logging.INFO,
        __file__,
        1,
        "HTTP request completed",
        (),
        None,
    )
    record.fields = {
        "service": "riskstream-api",
        "event": "request_completed",
        "status_code": 200,
    }

    payload = json.loads(api_main.JsonFormatter().format(record))

    assert payload["level"] == "INFO"
    assert payload["logger"] == "riskstream.api"
    assert payload["service"] == "riskstream-api"
    assert payload["event"] == "request_completed"
    assert payload["status_code"] == 200


def test_write_json_logs_request_completed(monkeypatch):
    events = []
    handler = build_handler("/healthz")

    def capture_log_event(level, message, **fields):
        events.append({"level": level, "message": message, **fields})

    monkeypatch.setattr(api_main, "log_event", capture_log_event)

    handler.write_json(200, {"status": "ok"})

    assert events == [
        {
            "level": logging.INFO,
            "message": "HTTP request completed",
            "service": "riskstream-api",
            "event": "request_completed",
            "path": "/healthz",
            "method": "GET",
            "environment": "unknown",
            "status_code": 200,
        }
    ]


def test_get_ranking_options_endpoint_returns_json():
    handler = build_handler("/v1/threats/ranking-options")

    handler.do_GET()

    handler.send_response.assert_called_once_with(200)
    assert response_body(handler)["ranker_version"] == "deterministic-v1"
