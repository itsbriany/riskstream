from __future__ import annotations

import gzip
import json
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

try:
    from riskstream.shared.utils.storage import StorageClient
except ImportError:  # pragma: no cover - local ad hoc runs may not include repo root.
    StorageClient = None


PROCESSED_BUCKET = "processed-data"
NORMALIZED_PREFIX = "normalized/threat-signals/threat_signal.v1/"
NORMALIZED_STREAM_PREFIXES = [
    "threatfox/recent",
    "cisa-kev/catalog",
    "urlhaus/recent/checkpoints",
    "urlhaus/recent/deltas",
]
RANKER_VERSION = "deterministic-v1"
MAX_LIMIT = 100
DEFAULT_LIMIT = 25
SUPPORTED_ENVIRONMENT_SCOPES = [
    "all",
    "production",
    "corporate",
    "dmz",
    "cloud",
    "development",
]
SUPPORTED_PRIORITIES = [
    "ransomware",
    "credential_theft",
    "malware_delivery",
    "active_exploitation",
    "c2_infrastructure",
    "vulnerability_remediation",
]
SUPPORTED_SIGNAL_KINDS = ["indicator", "vulnerability"]
SUPPORTED_ARTIFACT_TYPES = ["url", "domain", "ip", "hash", "cve"]
SUPPORTED_ACTIONS = ["observed", "updated", "removed"]
DEFAULT_ACTIONS = ["observed", "updated"]
SERVICE_NAME = "riskstream-api"


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            payload.update(fields)

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload)


logger = logging.getLogger("riskstream.api")


def configure_logging() -> None:
    level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())

    root_logger = logging.getLogger()
    root_logger.handlers = [handler]
    root_logger.setLevel(level)


def log_event(level: int, message: str, **fields: Any) -> None:
    logger.log(level, message, extra={"fields": fields})


class RequestError(Exception):
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def parse_datetime(value: str, field_name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RequestError(f"{field_name} must be an ISO 8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise RequestError(f"{field_name} must include a timezone")
    return parsed.astimezone(timezone.utc)


def parse_optional_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def isoformat_z(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def get_time_window(
    payload: dict[str, Any], now: datetime | None = None
) -> dict[str, datetime]:
    now = now or utcnow()
    time_window = payload.get("time_window")
    if time_window is None:
        return {"since": now - timedelta(hours=24), "until": now}
    if not isinstance(time_window, dict):
        raise RequestError("time_window must be an object")

    since = parse_datetime(time_window.get("since", ""), "time_window.since")
    until = parse_datetime(time_window.get("until", ""), "time_window.until")
    if since > until:
        raise RequestError("time_window.since must be before time_window.until")
    return {"since": since, "until": until}


def require_string_list(
    value: Any,
    field_name: str,
    supported_values: list[str] | None = None,
) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise RequestError(f"{field_name} must be an array of strings")
    if supported_values is not None:
        unsupported = sorted(set(value) - set(supported_values))
        if unsupported:
            raise RequestError(
                f"{field_name} contains unsupported values: {', '.join(unsupported)}"
            )
    return value


def parse_rank_request(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise RequestError("request body must be a JSON object")

    context = payload.get("context") or {}
    if not isinstance(context, dict):
        raise RequestError("context must be an object")
    filters = payload.get("filters") or {}
    if not isinstance(filters, dict):
        raise RequestError("filters must be an object")

    environment_scope = context.get("environment_scope", "all")
    if environment_scope not in SUPPORTED_ENVIRONMENT_SCOPES:
        raise RequestError("context.environment_scope is not supported")

    priorities = require_string_list(
        context.get("priorities"),
        "context.priorities",
        SUPPORTED_PRIORITIES,
    )
    signal_kinds = require_string_list(
        filters.get("signal_kinds"),
        "filters.signal_kinds",
        SUPPORTED_SIGNAL_KINDS,
    )
    artifact_types = require_string_list(
        filters.get("artifact_types"),
        "filters.artifact_types",
        SUPPORTED_ARTIFACT_TYPES,
    )
    actions = (
        require_string_list(
            filters.get("actions"),
            "filters.actions",
            SUPPORTED_ACTIONS,
        )
        or DEFAULT_ACTIONS
    )
    tags_any = [
        tag.lower()
        for tag in require_string_list(filters.get("tags_any"), "filters.tags_any")
    ]

    min_score = filters.get("min_score")
    if min_score is not None:
        if not isinstance(min_score, int) or min_score < 0 or min_score > 100:
            raise RequestError("filters.min_score must be an integer from 0 to 100")

    limit = payload.get("limit", DEFAULT_LIMIT)
    if not isinstance(limit, int) or limit < 1:
        raise RequestError("limit must be a positive integer")

    return {
        "tenant_id": payload.get("tenant_id") or "default",
        "time_window": get_time_window(payload),
        "context": {
            "environment_scope": environment_scope,
            "priorities": priorities,
        },
        "filters": {
            "signal_kinds": signal_kinds,
            "artifact_types": artifact_types,
            "actions": actions,
            "tags_any": tags_any,
            "min_score": min_score,
        },
        "limit": min(limit, MAX_LIMIT),
    }


def ranking_options() -> dict[str, Any]:
    return {
        "ranker_version": RANKER_VERSION,
        "environment_scopes": SUPPORTED_ENVIRONMENT_SCOPES,
        "priorities": SUPPORTED_PRIORITIES,
        "signal_kinds": SUPPORTED_SIGNAL_KINDS,
        "artifact_types": SUPPORTED_ARTIFACT_TYPES,
        "actions": SUPPORTED_ACTIONS,
        "defaults": {
            "environment_scope": "all",
            "actions": DEFAULT_ACTIONS,
            "limit": DEFAULT_LIMIT,
            "time_window_hours": 24,
        },
        "limits": {"max_limit": MAX_LIMIT},
    }


def normalized_text_values(record: dict[str, Any]) -> set[str]:
    values = {
        str(record.get("classification", "")),
        str(record.get("family", "")),
        str(record.get("status", "")),
    }
    values.update(str(tag) for tag in record.get("tags", []))
    source_details = record.get("source_details", {})
    if isinstance(source_details, dict):
        for details in source_details.values():
            if isinstance(details, dict):
                values.update(str(value) for value in details.values() if value)
    return {value.lower() for value in values if value}


def record_event_time(record: dict[str, Any], object_key: str) -> datetime | None:
    return (
        parse_optional_datetime(record.get("last_seen_at"))
        or parse_optional_datetime(record.get("first_seen_at"))
        or parse_datetime_from_object_key(object_key)
        or parse_datetime_from_object_key(
            record.get("raw_ref", {}).get("object_key", "")
        )
    )


def parse_datetime_from_object_key(object_key: str) -> datetime | None:
    parts = object_key.split("/")
    for index in range(len(parts) - 3):
        year, month, day, filename = parts[index : index + 4]
        if not (year.isdigit() and month.isdigit() and day.isdigit()):
            continue
        stamp = filename.split("-")[0]
        for suffix in (".gz", ".jsonl", ".json"):
            stamp = stamp.removesuffix(suffix)
        if not stamp.endswith("Z"):
            continue
        try:
            return datetime.strptime(
                f"{year}-{month}-{day} {stamp}", "%Y-%m-%d %H%M%SZ"
            ).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def record_matches_filters(
    record: dict[str, Any],
    object_key: str,
    filters: dict[str, Any],
    time_window: dict[str, datetime],
) -> bool:
    if (
        filters["signal_kinds"]
        and record.get("signal_kind") not in filters["signal_kinds"]
    ):
        return False
    if (
        filters["artifact_types"]
        and record.get("artifact_type") not in filters["artifact_types"]
    ):
        return False
    if record.get("action") not in filters["actions"]:
        return False
    if filters["tags_any"] and not (
        set(filters["tags_any"]) & normalized_text_values(record)
    ):
        return False

    event_time = record_event_time(record, object_key)
    if event_time is None:
        return True
    return time_window["since"] <= event_time <= time_window["until"]


def normalized_prefixes_for_time_window(time_window: dict[str, datetime]) -> list[str]:
    years = range(time_window["since"].year, time_window["until"].year + 1)
    return [
        f"{NORMALIZED_PREFIX}{stream}/{year:04d}/"
        for stream in NORMALIZED_STREAM_PREFIXES
        for year in years
    ]


def read_normalized_records(
    storage_client: Any,
    time_window: dict[str, datetime],
) -> list[dict[str, Any]]:
    minio_client = storage_client.get_client()
    records = []
    for prefix in normalized_prefixes_for_time_window(time_window):
        objects = minio_client.list_objects(
            PROCESSED_BUCKET,
            prefix=prefix,
            recursive=True,
        )
        for item in objects:
            object_key = item.object_name
            if not object_key.endswith(".jsonl.gz"):
                continue
            response = minio_client.get_object(PROCESSED_BUCKET, object_key)
            try:
                lines = gzip.decompress(response.read()).decode("utf-8").splitlines()
            finally:
                response.close()
                response.release_conn()
            for line in lines:
                if not line.strip():
                    continue
                record = json.loads(line)
                record["_normalized_object_key"] = object_key
                records.append(record)
    return records


def group_records(
    records: list[dict[str, Any]],
) -> dict[tuple[str, str, str], list[dict[str, Any]]]:
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for record in records:
        identity = (
            record["signal_kind"],
            record["artifact_type"],
            record["artifact_value"],
        )
        grouped.setdefault(identity, []).append(record)
    return grouped


def score_group(
    identity: tuple[str, str, str],
    records: list[dict[str, Any]],
    context: dict[str, Any],
    now: datetime,
) -> tuple[int, list[dict[str, str]]]:
    signal_kind, artifact_type, _artifact_value = identity
    sources = {record.get("source") for record in records}
    texts = set()
    confidence_values = []
    statuses = set()
    actions = set()
    event_times = []
    for record in records:
        texts.update(normalized_text_values(record))
        statuses.add(str(record.get("status", "")).lower())
        actions.add(record.get("action"))
        if isinstance(record.get("confidence"), int):
            confidence_values.append(record["confidence"])
        event_time = record_event_time(record, record.get("_normalized_object_key", ""))
        if event_time is not None:
            event_times.append(event_time)

    score = 40
    reasons: list[dict[str, str]] = []

    if signal_kind == "vulnerability":
        score += 20
        reasons.append(
            {
                "code": "known_exploited_vulnerability",
                "message": "The signal is a known exploited vulnerability from CISA KEV.",
            }
        )
    if "urlhaus" in sources and artifact_type == "url":
        score += 12
        reasons.append(
            {
                "code": "malware_url_source",
                "message": "URLhaus reported this URL in recent malware infrastructure.",
            }
        )
    if "threatfox" in sources:
        score += 8
        reasons.append(
            {
                "code": "threatfox_indicator",
                "message": "ThreatFox reported this indicator in recent abuse.ch intelligence.",
            }
        )
    if len(sources) > 1:
        score += 10
        reasons.append(
            {
                "code": "source_corroboration",
                "message": "Multiple normalized sources contributed evidence for this signal.",
            }
        )

    if confidence_values:
        score += round(max(confidence_values) * 0.15)
        reasons.append(
            {
                "code": "source_confidence",
                "message": "The source provided a confidence score for this signal.",
            }
        )
    if "online" in statuses:
        score += 15
        reasons.append(
            {
                "code": "active_malware_delivery",
                "message": "The signal is associated with online malware delivery infrastructure.",
            }
        )
    if "updated" in actions:
        score += 5
        reasons.append(
            {
                "code": "recently_updated",
                "message": "The signal was updated in the normalized feed data.",
            }
        )

    latest_event_time = max(event_times) if event_times else None
    if latest_event_time:
        age = now - latest_event_time
        if age <= timedelta(days=1):
            score += 15
            reasons.append(
                {
                    "code": "recent_signal",
                    "message": "The signal was observed within the last 24 hours.",
                }
            )
        elif age <= timedelta(days=7):
            score += 10
        elif age <= timedelta(days=30):
            score += 5

    for priority in context["priorities"]:
        if priority_matches(priority, texts, signal_kind):
            score += 12
            reasons.append(
                {
                    "code": "priority_match",
                    "message": f"The signal matches the requested {priority.replace('_', ' ')} priority.",
                }
            )

    if context["environment_scope"] in {"production", "dmz"}:
        score += 5
        reasons.append(
            {
                "code": "sensitive_environment_scope",
                "message": f"The request targets the {context['environment_scope']} environment scope.",
            }
        )

    return min(score, 100), unique_reasons(reasons)


def priority_matches(priority: str, texts: set[str], signal_kind: str) -> bool:
    matchers = {
        "ransomware": ["ransomware"],
        "credential_theft": ["credential", "phishing", "stealer"],
        "malware_delivery": ["malware", "payload", "download", "delivery"],
        "active_exploitation": ["exploited", "known", "active exploitation"],
        "c2_infrastructure": ["c2", "command", "control", "botnet"],
        "vulnerability_remediation": ["requiredaction", "duedate", "patch"],
    }
    if priority == "active_exploitation" and signal_kind == "vulnerability":
        return True
    return any(token in text for text in texts for token in matchers[priority])


def unique_reasons(reasons: list[dict[str, str]]) -> list[dict[str, str]]:
    seen = set()
    unique = []
    for reason in reasons:
        if reason["code"] in seen:
            continue
        seen.add(reason["code"])
        unique.append(reason)
    return unique


def severity_for_score(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def labels_for_records(records: list[dict[str, Any]]) -> list[str]:
    labels = []
    for record in records:
        for field in ("classification", "family", "status"):
            if record.get(field):
                labels.append(record[field])
        labels.extend(record.get("tags", []))
    return sorted(set(labels))


def timestamp_bounds(records: list[dict[str, Any]]) -> tuple[str | None, str | None]:
    first_seen = [
        parse_optional_datetime(record.get("first_seen_at"))
        for record in records
        if record.get("first_seen_at")
    ]
    last_seen = [
        parse_optional_datetime(record.get("last_seen_at"))
        for record in records
        if record.get("last_seen_at")
    ]
    first_seen = [value for value in first_seen if value is not None]
    last_seen = [value for value in last_seen if value is not None]
    return (
        isoformat_z(min(first_seen)) if first_seen else None,
        isoformat_z(max(last_seen)) if last_seen else None,
    )


def build_summary(identity: tuple[str, str, str], records: list[dict[str, Any]]) -> str:
    signal_kind, artifact_type, _artifact_value = identity
    if signal_kind == "vulnerability":
        return (
            "Known exploited vulnerability observed in normalized threat intelligence."
        )
    if artifact_type == "url" and any(
        record.get("status") == "online" for record in records
    ):
        return "Online malware delivery URL observed in recent threat intelligence."
    return (
        f"{artifact_type.upper()} indicator observed in normalized threat intelligence."
    )


def build_ranked_card(
    rank: int,
    identity: tuple[str, str, str],
    records: list[dict[str, Any]],
    score: int,
    reasons: list[dict[str, str]],
) -> dict[str, Any]:
    first_seen_at, last_seen_at = timestamp_bounds(records)
    evidence_url = next(
        (
            record.get("evidence_url")
            for record in records
            if record.get("evidence_url")
        ),
        None,
    )
    card = {
        "rank": rank,
        "score": score,
        "severity": severity_for_score(score),
        "signal": {
            "signal_kind": identity[0],
            "artifact_type": identity[1],
            "artifact_value": identity[2],
        },
        "summary": build_summary(identity, records),
        "sources": sorted({record["source"] for record in records}),
        "labels": labels_for_records(records),
        "reasons": reasons,
        "raw_refs": [record["raw_ref"] for record in records],
    }
    if evidence_url:
        card["evidence_url"] = evidence_url
    if first_seen_at:
        card["first_seen_at"] = first_seen_at
    if last_seen_at:
        card["last_seen_at"] = last_seen_at
    return card


def rank_records(
    records: list[dict[str, Any]],
    request: dict[str, Any],
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    now = now or utcnow()
    candidates = [
        record
        for record in records
        if record_matches_filters(
            record,
            record.get("_normalized_object_key", ""),
            request["filters"],
            request["time_window"],
        )
    ]
    scored = []
    for identity, group in group_records(candidates).items():
        score, reasons = score_group(identity, group, request["context"], now)
        if (
            request["filters"]["min_score"] is not None
            and score < request["filters"]["min_score"]
        ):
            continue
        scored.append((score, identity, group, reasons))

    scored.sort(key=lambda item: (-item[0], item[1]))
    return [
        build_ranked_card(index + 1, identity, group, score, reasons)
        for index, (score, identity, group, reasons) in enumerate(
            scored[: request["limit"]]
        )
    ]


def rank_threats(
    payload: dict[str, Any], storage_client: Any | None = None
) -> dict[str, Any]:
    request = parse_rank_request(payload)
    storage_client = storage_client or build_storage_client()
    records = read_normalized_records(storage_client, request["time_window"])
    results = rank_records(records, request)
    return {
        "request_id": f"req_{utcnow().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}",
        "tenant_id": request["tenant_id"],
        "ranker_version": RANKER_VERSION,
        "generated_at": isoformat_z(utcnow()),
        "time_window": {
            "since": isoformat_z(request["time_window"]["since"]),
            "until": isoformat_z(request["time_window"]["until"]),
        },
        "result_count": len(results),
        "results": results,
    }


def build_storage_client() -> Any:
    if StorageClient is None:
        raise RuntimeError(
            "StorageClient is unavailable; ensure riskstream.shared is on PYTHONPATH"
        )
    return StorageClient()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlparse(self.path).path
        self.log_request_started("GET", path)
        if path == "/healthz":
            self.write_json(200, {"status": "ok"})
        elif path == "/v1/threats/ranking-options":
            self.write_json(200, ranking_options())
        elif path == "/":
            self.write_json(
                200,
                {
                    "service": SERVICE_NAME,
                    "environment": os.getenv("ENVIRONMENT", "unknown"),
                },
            )
        else:
            self.write_json(404, {"error": "not found"})

    def do_POST(self):
        path = urlparse(self.path).path
        self.log_request_started("POST", path)
        if path != "/v1/threats:rank":
            self.write_json(404, {"error": "not found"})
            return

        try:
            payload = self.read_json_body()
            self.write_json(200, rank_threats(payload))
        except RequestError as exc:
            self.log_request_failed(path, "POST", 400, exc.message)
            self.write_json(400, {"error": exc.message})
        except json.JSONDecodeError:
            message = "request body must be valid JSON"
            self.log_request_failed(path, "POST", 400, message)
            self.write_json(400, {"error": message})
        except Exception as exc:
            self.log_request_failed(path, "POST", 500, str(exc))
            self.write_json(500, {"error": str(exc)})

    def read_json_body(self) -> dict[str, Any]:
        content_length = int(self.headers.get("Content-Length", "0"))
        return json.loads(self.rfile.read(content_length).decode("utf-8"))

    def write_json(self, status_code: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self.log_request_completed(status_code)

    def log_request_started(self, method: str, path: str) -> None:
        log_event(
            logging.INFO,
            "Handling HTTP request",
            service=SERVICE_NAME,
            event="request_started",
            path=path,
            method=method,
            environment=os.getenv("ENVIRONMENT", "unknown"),
        )

    def log_request_completed(self, status_code: int) -> None:
        log_event(
            logging.INFO,
            "HTTP request completed",
            service=SERVICE_NAME,
            event="request_completed",
            path=urlparse(self.path).path,
            method=self.command,
            environment=os.getenv("ENVIRONMENT", "unknown"),
            status_code=status_code,
        )

    def log_request_failed(
        self, path: str, method: str, status_code: int, error: str
    ) -> None:
        log_event(
            logging.ERROR,
            "HTTP request failed",
            service=SERVICE_NAME,
            event="request_failed",
            path=path,
            method=method,
            environment=os.getenv("ENVIRONMENT", "unknown"),
            status_code=status_code,
            error=error,
        )

    def log_message(self, format, *args):
        return


def run() -> None:
    configure_logging()
    port = int(os.getenv("PORT", "8080"))
    environment = os.getenv("ENVIRONMENT", "unknown")
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    log_event(
        logging.INFO,
        "RiskStream API service listening",
        service=SERVICE_NAME,
        event="service_started",
        environment=environment,
        port=port,
    )
    server.serve_forever()


if __name__ == "__main__":
    run()
