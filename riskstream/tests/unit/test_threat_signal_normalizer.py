import gzip
import json
import sys
from pathlib import Path
from unittest.mock import Mock, patch

from jsonschema import Draft202012Validator

REPO_ROOT = Path(__file__).resolve().parents[3]
NORMALIZER_SRC = (
    Path(__file__).resolve().parents[2]
    / "services"
    / "normalization"
    / "threat-signal"
    / "src"
)
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(NORMALIZER_SRC) not in sys.path:
    sys.path.insert(0, str(NORMALIZER_SRC))

SCHEMA_PATH = NORMALIZER_SRC.parent / "schemas" / "threat_signal.v1.schema.json"

import normalizer


def _validator() -> Draft202012Validator:
    return Draft202012Validator(
        json.loads(SCHEMA_PATH.read_text()),
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )


def _assert_schema_valid(record: dict) -> None:
    errors = sorted(_validator().iter_errors(record), key=lambda err: list(err.path))
    assert errors == []


def test_normalize_threatfox_snapshot_maps_expected_fields():
    snapshot = {
        "source": "threatfox",
        "feed": "recent",
        "fetched_at": "2026-03-14T17:37:53+00:00",
        "data": {
            "query_status": "ok",
            "data": [
                {
                    "id": "1765567",
                    "ioc": "cache-dist-5.vitagrazia.in.net",
                    "threat_type": "payload_delivery",
                    "threat_type_desc": "Indicator that identifies a malware distribution server (payload delivery)",
                    "ioc_type": "domain",
                    "ioc_type_desc": "Domain name that delivers a malware payload",
                    "malware": "js.clearfake",
                    "malware_printable": "ClearFake",
                    "malware_alias": None,
                    "malware_malpedia": "https://malpedia.caad.fkie.fraunhofer.de/details/js.clearfake",
                    "confidence_level": 100,
                    "is_compromised": False,
                    "first_seen": "2026-03-13 21:47:34 UTC",
                    "last_seen": "2026-03-13 21:47:41 UTC",
                    "reference": None,
                    "reporter": "anonymous",
                    "tags": ["ClearFake"],
                }
            ],
        },
    }

    records = normalizer.normalize_threatfox_snapshot(
        snapshot,
        raw_bucket="raw-feeds",
        raw_object_key="threatfox/recent/2026/03/14/173753Z.json",
    )

    assert records == [
        {
            "schema_version": "threat_signal.v1",
            "source": "threatfox",
            "feed": "recent",
            "signal_kind": "indicator",
            "action": "observed",
            "artifact_type": "domain",
            "artifact_value": "cache-dist-5.vitagrazia.in.net",
            "external_id": "1765567",
            "first_seen_at": "2026-03-13T21:47:34+00:00",
            "last_seen_at": "2026-03-13T21:47:41+00:00",
            "classification": "payload_delivery",
            "confidence": 100,
            "family": "ClearFake",
            "reporter": "anonymous",
            "tags": ["ClearFake"],
            "raw_ref": {
                "bucket": "raw-feeds",
                "object_key": "threatfox/recent/2026/03/14/173753Z.json",
                "row_number": 1,
            },
            "source_details": {
                "threatfox": {
                    "threat_type_desc": "Indicator that identifies a malware distribution server (payload delivery)",
                    "ioc_type_desc": "Domain name that delivers a malware payload",
                    "malware": "js.clearfake",
                    "malware_malpedia": "https://malpedia.caad.fkie.fraunhofer.de/details/js.clearfake",
                    "is_compromised": False,
                }
            },
        }
    ]
    _assert_schema_valid(records[0])


def test_normalize_urlhaus_checkpoint_maps_expected_fields():
    snapshot = {
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

    records = normalizer.normalize_urlhaus_checkpoint(
        snapshot,
        raw_bucket="raw-feeds",
        raw_object_key="urlhaus/checkpoints/2026/03/19/000000Z.json.gz",
    )

    assert records == [
        {
            "schema_version": "threat_signal.v1",
            "source": "urlhaus",
            "feed": "recent",
            "signal_kind": "indicator",
            "action": "observed",
            "artifact_type": "url",
            "artifact_value": "http://221.200.214.87:54591/i",
            "external_id": "3799807",
            "first_seen_at": "2026-03-19T14:49:13+00:00",
            "last_seen_at": "2026-03-19T14:49:13+00:00",
            "classification": "malware_download",
            "status": "online",
            "reporter": "geenensp",
            "tags": ["32-bit", "elf", "mips", "Mozi"],
            "evidence_url": "https://urlhaus.abuse.ch/url/3799807/",
            "raw_ref": {
                "bucket": "raw-feeds",
                "object_key": "urlhaus/checkpoints/2026/03/19/000000Z.json.gz",
                "row_number": 1,
            },
            "source_details": {
                "urlhaus": {
                    "dateadded": "2026-03-19 14:49:13",
                    "last_online": "2026-03-19 14:49:13",
                    "url_status": "online",
                    "urlhaus_link": "https://urlhaus.abuse.ch/url/3799807/",
                }
            },
        }
    ]
    _assert_schema_valid(records[0])


def test_normalize_urlhaus_delta_maps_actions():
    payload = {
        "source": "urlhaus",
        "feed": "recent",
        "data": {
            "added": [
                {
                    "id": "1",
                    "url": "https://one.example",
                    "url_status": "online",
                }
            ],
            "updated": [
                {
                    "id": "2",
                    "url": "https://two.example",
                    "url_status": "offline",
                }
            ],
            "removed": [
                {
                    "id": "3",
                    "url": "https://three.example",
                    "url_status": "offline",
                    "reason": "missing_from_recent_feed",
                }
            ],
        },
    }

    records = normalizer.normalize_urlhaus_delta(
        payload,
        raw_bucket="raw-feeds",
        raw_object_key="urlhaus/deltas/2026/03/19/abc123.json.gz",
    )

    assert [record["action"] for record in records] == ["observed", "updated", "removed"]
    assert records[2]["artifact_value"] == "https://three.example"
    assert records[2]["source_details"]["urlhaus"]["reason"] == "missing_from_recent_feed"
    assert records[2]["raw_ref"]["section"] == "removed"
    _assert_schema_valid(records[2])


def test_normalize_cisa_kev_catalog_maps_expected_fields():
    snapshot = {
        "source": "cisa-kev",
        "feed": "catalog",
        "fetched_at": "2026-03-21T02:05:00+00:00",
        "data": {
            "catalogVersion": "2026.03.21",
            "vulnerabilities": [
                {
                    "cveID": "CVE-2026-0001",
                    "vendorProject": "Acme",
                    "product": "Widget",
                    "vulnerabilityName": "Widget auth bypass",
                    "dateAdded": "2026-03-21",
                    "shortDescription": "Authentication bypass in Widget admin interface.",
                    "requiredAction": "Apply the vendor patch.",
                    "dueDate": "2026-04-11",
                    "knownRansomwareCampaignUse": "Known",
                    "notes": "Observed in active exploitation.",
                    "cwes": ["CWE-287"],
                }
            ],
        },
    }

    records = normalizer.normalize_cisa_kev_catalog(
        snapshot,
        raw_bucket="raw-feeds",
        raw_object_key="cisa-kev/catalog/2026/03/21/020500Z.json",
    )

    assert records == [
        {
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
                "object_key": "cisa-kev/catalog/2026/03/21/020500Z.json",
                "row_number": 1,
            },
            "source_details": {
                "cisa-kev": {
                    "vendorProject": "Acme",
                    "product": "Widget",
                    "vulnerabilityName": "Widget auth bypass",
                    "dateAdded": "2026-03-21",
                    "shortDescription": "Authentication bypass in Widget admin interface.",
                    "requiredAction": "Apply the vendor patch.",
                    "dueDate": "2026-04-11",
                    "knownRansomwareCampaignUse": "Known",
                    "notes": "Observed in active exploitation.",
                    "cwes": ["CWE-287"],
                }
            },
        }
    ]
    _assert_schema_valid(records[0])


def test_threat_signal_schema_rejects_missing_required_core_field():
    record = {
        "schema_version": "threat_signal.v1",
        "source": "threatfox",
        "feed": "recent",
        "signal_kind": "indicator",
        "action": "observed",
        "artifact_type": "domain",
        "external_id": "1765567",
        "raw_ref": {
            "bucket": "raw-feeds",
            "object_key": "threatfox/recent/2026/03/14/173753Z.json",
            "row_number": 1,
        },
    }

    errors = list(_validator().iter_errors(record))

    assert any(error.validator == "required" for error in errors)
    assert any("artifact_value" in error.message for error in errors)


def test_build_normalized_object_key_matches_phase1_layout():
    assert (
        normalizer.build_normalized_object_key(
            "cisa-kev/catalog/2026/03/21/020500Z.json",
            "cisa-kev",
        )
        == "normalized/threat-signals/threat_signal.v1/cisa-kev/catalog/2026/03/21/020500Z.jsonl.gz"
    )
    assert (
        normalizer.build_normalized_object_key(
            "threatfox/recent/2026/03/14/173753Z.json",
            "threatfox",
        )
        == "normalized/threat-signals/threat_signal.v1/threatfox/recent/2026/03/14/173753Z.jsonl.gz"
    )
    assert (
        normalizer.build_normalized_object_key(
            "urlhaus/checkpoints/2026/03/19/000000Z.json.gz",
            "urlhaus",
        )
        == "normalized/threat-signals/threat_signal.v1/urlhaus/recent/checkpoints/2026/03/19/000000Z.jsonl.gz"
    )
    assert (
        normalizer.build_normalized_object_key(
            "urlhaus/deltas/2026/03/19/abc123.json.gz",
            "urlhaus",
        )
        == "normalized/threat-signals/threat_signal.v1/urlhaus/recent/deltas/2026/03/19/abc123.jsonl.gz"
    )


def test_build_checkpoint_object_key_uses_versioned_storage_prefix():
    assert (
        normalizer.build_checkpoint_object_key(
            "raw-feeds-bootstrap-test",
            "threatfox",
            "recent",
        )
        == "normalization-state/threat-signal/threat_signal.v1/raw-feeds-bootstrap-test/threatfox/recent.json"
    )


def test_normalize_raw_artifact_writes_gzipped_jsonl():
    storage = Mock()
    minio_client = Mock()
    storage.get_client.return_value = minio_client
    response = Mock()
    response.read.return_value = json.dumps(
        {
            "source": "threatfox",
            "feed": "recent",
            "data": {
                "data": [
                    {
                        "id": "1765567",
                        "ioc": "cache-dist-5.vitagrazia.in.net",
                        "threat_type": "payload_delivery",
                        "ioc_type": "domain",
                        "confidence_level": 100,
                        "first_seen": "2026-03-13 21:47:34 UTC",
                        "last_seen": "2026-03-13 21:47:41 UTC",
                        "reporter": "anonymous",
                        "tags": ["ClearFake"],
                    }
                ]
            },
        }
    ).encode("utf-8")
    minio_client.get_object.return_value = response

    result = normalizer.normalize_raw_artifact(
        raw_object_key="threatfox/recent/2026/03/14/173753Z.json",
        storage=storage,
    )

    assert result == {
        "schema_version": "threat_signal.v1",
        "source": "threatfox",
        "raw_bucket": "raw-feeds",
        "raw_object_key": "threatfox/recent/2026/03/14/173753Z.json",
        "normalized_bucket": "processed-data",
        "normalized_object_key": "normalized/threat-signals/threat_signal.v1/threatfox/recent/2026/03/14/173753Z.jsonl.gz",
        "records_count": 1,
        "trigger_event": {
            "event_type": "raw_artifact_written",
            "source": "threatfox",
            "feed": "recent",
            "bucket": "raw-feeds",
            "object_key": "threatfox/recent/2026/03/14/173753Z.json",
        },
    }
    put_call = minio_client.put_object.call_args
    assert put_call.args[0] == "processed-data"
    assert put_call.args[1] == "normalized/threat-signals/threat_signal.v1/threatfox/recent/2026/03/14/173753Z.jsonl.gz"
    assert put_call.kwargs["content_type"] == "application/gzip"
    payload = gzip.decompress(put_call.args[2].read()).decode("utf-8").splitlines()
    assert len(payload) == 1
    assert json.loads(payload[0])["artifact_value"] == "cache-dist-5.vitagrazia.in.net"


def test_read_json_object_retries_nosuchkey_before_succeeding():
    storage = Mock()
    minio_client = Mock()
    storage.get_client.return_value = minio_client
    response = Mock()
    response.read.return_value = json.dumps({"source": "threatfox"}).encode("utf-8")

    class FakeNoSuchKeyError(Exception):
        code = "NoSuchKey"

    minio_client.get_object.side_effect = [FakeNoSuchKeyError(), response]

    with patch.object(normalizer.time, "sleep") as sleep:
        payload = normalizer.read_json_object(
            storage,
            bucket="raw-feeds",
            object_key="threatfox/recent/2026/03/14/173753Z.json",
        )

    assert payload == {"source": "threatfox"}
    assert minio_client.get_object.call_count == 2
    sleep.assert_called_once_with(normalizer.RAW_OBJECT_READ_RETRY_DELAY_SECONDS)
    response.close.assert_called_once()
    response.release_conn.assert_called_once()


def test_normalize_raw_artifact_writes_cisa_kev_jsonl():
    storage = Mock()
    minio_client = Mock()
    storage.get_client.return_value = minio_client
    response = Mock()
    response.read.return_value = json.dumps(
        {
            "source": "cisa-kev",
            "feed": "catalog",
            "data": {
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2026-0001",
                        "vendorProject": "Acme",
                        "product": "Widget",
                    }
                ]
            },
        }
    ).encode("utf-8")
    minio_client.get_object.return_value = response

    result = normalizer.normalize_raw_artifact(
        raw_object_key="cisa-kev/catalog/2026/03/21/020500Z.json",
        storage=storage,
    )

    assert result == {
        "schema_version": "threat_signal.v1",
        "source": "cisa-kev",
        "raw_bucket": "raw-feeds",
        "raw_object_key": "cisa-kev/catalog/2026/03/21/020500Z.json",
        "normalized_bucket": "processed-data",
        "normalized_object_key": "normalized/threat-signals/threat_signal.v1/cisa-kev/catalog/2026/03/21/020500Z.jsonl.gz",
        "records_count": 1,
        "trigger_event": {
            "event_type": "raw_artifact_written",
            "source": "cisa-kev",
            "feed": "catalog",
            "bucket": "raw-feeds",
            "object_key": "cisa-kev/catalog/2026/03/21/020500Z.json",
        },
    }
    put_call = minio_client.put_object.call_args
    assert put_call.args[0] == "processed-data"
    assert (
        put_call.args[1]
        == "normalized/threat-signals/threat_signal.v1/cisa-kev/catalog/2026/03/21/020500Z.jsonl.gz"
    )
    assert put_call.kwargs["content_type"] == "application/gzip"
    payload = gzip.decompress(put_call.args[2].read()).decode("utf-8").splitlines()
    assert len(payload) == 1
    assert json.loads(payload[0])["artifact_value"] == "CVE-2026-0001"


def test_bootstrap_stream_checkpoint_uses_highest_contiguous_normalized_output():
    storage = Mock()
    minio_client = Mock()
    storage.get_client.return_value = minio_client
    minio_client.stat_object.side_effect = [
        Mock(),
        Mock(),
        type("NoSuchKeyError", (Exception,), {"code": "NoSuchKey"})(),
    ]

    def list_objects(bucket, prefix, recursive):
        assert recursive is True
        if bucket == "raw-feeds" and prefix == "threatfox/recent/":
            first = Mock()
            first.object_name = "threatfox/recent/2026/03/14/173753Z.json"
            second = Mock()
            second.object_name = "threatfox/recent/2026/03/14/183753Z.json"
            third = Mock()
            third.object_name = "threatfox/recent/2026/03/14/193753Z.json"
            return [first, second, third]
        return []

    minio_client.list_objects.side_effect = list_objects
    minio_client.put_object = Mock()

    checkpoint = normalizer.bootstrap_stream_checkpoint(
        storage=storage,
        source="threatfox",
        feed="recent",
        stream="recent",
        raw_prefix="threatfox/recent/",
        raw_bucket="raw-feeds",
    )

    assert checkpoint["last_processed_raw_object_key"] == "threatfox/recent/2026/03/14/183753Z.json"
    assert (
        checkpoint["last_processed_normalized_object_key"]
        == "normalized/threat-signals/threat_signal.v1/threatfox/recent/2026/03/14/183753Z.jsonl.gz"
    )
    put_call = minio_client.put_object.call_args
    assert put_call.args[1] == "normalization-state/threat-signal/threat_signal.v1/raw-feeds/threatfox/recent.json"


def test_list_pending_raw_object_keys_uses_checkpoint_progress():
    storage = Mock()
    minio_client = Mock()
    storage.get_client.return_value = minio_client

    def list_objects(bucket, prefix, recursive, start_after=None):
        assert recursive is True
        if (
            bucket == "raw-feeds"
            and prefix == "threatfox/recent/"
            and start_after == "threatfox/recent/2026/03/14/173753Z.json"
        ):
            first = Mock()
            first.object_name = "threatfox/recent/2026/03/14/183753Z.json"
            second = Mock()
            second.object_name = "threatfox/recent/2026/03/14/193753Z.json"
            return [first, second]
        return []

    minio_client.list_objects.side_effect = list_objects

    with patch.object(
        normalizer,
        "load_stream_checkpoint",
        return_value={
            "last_processed_raw_object_key": "threatfox/recent/2026/03/14/173753Z.json"
        },
    ):
        pending = normalizer.list_pending_raw_object_keys(
            source="threatfox",
            storage=storage,
        )

    assert pending == [
        "threatfox/recent/2026/03/14/183753Z.json",
        "threatfox/recent/2026/03/14/193753Z.json",
    ]


def test_list_pending_raw_object_keys_supports_cisa_kev_catalog_feed():
    storage = Mock()
    minio_client = Mock()
    storage.get_client.return_value = minio_client

    def list_objects(bucket, prefix, recursive, start_after=None):
        assert recursive is True
        if (
            bucket == "raw-feeds"
            and prefix == "cisa-kev/catalog/"
            and start_after == "cisa-kev/catalog/2026/03/21/020500Z.json"
        ):
            first = Mock()
            first.object_name = "cisa-kev/catalog/2026/03/22/020500Z.json"
            return [first]
        return []

    minio_client.list_objects.side_effect = list_objects

    with patch.object(
        normalizer,
        "load_stream_checkpoint",
        return_value={
            "last_processed_raw_object_key": "cisa-kev/catalog/2026/03/21/020500Z.json"
        },
    ):
        pending = normalizer.list_pending_raw_object_keys(
            source="cisa-kev",
            feed="catalog",
            storage=storage,
        )

    assert pending == ["cisa-kev/catalog/2026/03/22/020500Z.json"]


def test_normalize_pending_artifacts_processes_all_missing_objects():
    with patch.object(
        normalizer,
        "get_source_streams",
        return_value=[
            {"stream": "checkpoints", "raw_prefix": "urlhaus/checkpoints/"},
            {"stream": "deltas", "raw_prefix": "urlhaus/deltas/"},
        ],
    ), patch.object(
        normalizer,
        "load_stream_checkpoint",
        return_value=None,
    ), patch.object(
        normalizer,
        "bootstrap_stream_checkpoint",
        return_value=None,
    ), patch.object(
        normalizer,
        "list_stream_pending_raw_object_keys",
        side_effect=[
            ["urlhaus/checkpoints/2026/03/19/000000Z.json.gz"],
            ["urlhaus/deltas/2026/03/19/abc123.json.gz"],
        ],
    ), patch.object(
        normalizer,
        "normalize_raw_artifact",
        side_effect=[
            {"raw_object_key": "urlhaus/checkpoints/2026/03/19/000000Z.json.gz", "normalized_object_key": "normalized/threat-signals/threat_signal.v1/urlhaus/recent/checkpoints/2026/03/19/000000Z.jsonl.gz"},
            {"raw_object_key": "urlhaus/deltas/2026/03/19/abc123.json.gz", "normalized_object_key": "normalized/threat-signals/threat_signal.v1/urlhaus/recent/deltas/2026/03/19/abc123.jsonl.gz"},
        ],
    ) as normalize_raw_artifact, patch.object(
        normalizer,
        "write_stream_checkpoint",
    ) as write_stream_checkpoint:
        results = normalizer.normalize_pending_artifacts(
            source="urlhaus",
            storage=Mock(),
        )

    assert results == [
        {
            "raw_object_key": "urlhaus/checkpoints/2026/03/19/000000Z.json.gz",
            "normalized_object_key": "normalized/threat-signals/threat_signal.v1/urlhaus/recent/checkpoints/2026/03/19/000000Z.jsonl.gz",
        },
        {
            "raw_object_key": "urlhaus/deltas/2026/03/19/abc123.json.gz",
            "normalized_object_key": "normalized/threat-signals/threat_signal.v1/urlhaus/recent/deltas/2026/03/19/abc123.jsonl.gz",
        },
    ]
    assert normalize_raw_artifact.call_count == 2
    assert write_stream_checkpoint.call_count == 2


def test_normalize_pending_artifacts_replay_limit_skips_checkpoint_updates():
    with patch.object(
        normalizer,
        "get_source_streams",
        return_value=[{"stream": "recent", "raw_prefix": "threatfox/recent/"}],
    ), patch.object(
        normalizer,
        "list_stream_pending_raw_object_keys",
        return_value=["threatfox/recent/2026/03/14/173753Z.json"],
    ), patch.object(
        normalizer,
        "normalize_raw_artifact",
        return_value={
            "raw_object_key": "threatfox/recent/2026/03/14/173753Z.json",
            "normalized_object_key": "normalized/threat-signals/threat_signal.v1/threatfox/recent/2026/03/14/173753Z.jsonl.gz",
        },
    ), patch.object(
        normalizer,
        "write_stream_checkpoint",
    ) as write_stream_checkpoint:
        results = normalizer.normalize_pending_artifacts(
            source="threatfox",
            replay_from_raw_object_key="threatfox/recent/2026/03/14/173753Z.json",
            replay_limit=1,
            storage=Mock(),
        )

    assert results == [
        {
            "raw_object_key": "threatfox/recent/2026/03/14/173753Z.json",
            "normalized_object_key": "normalized/threat-signals/threat_signal.v1/threatfox/recent/2026/03/14/173753Z.jsonl.gz",
        }
    ]
    write_stream_checkpoint.assert_not_called()
