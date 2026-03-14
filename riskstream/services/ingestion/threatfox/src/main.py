import json
import logging
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path

from client import JsonFormatter, ThreatFoxClient

REPO_ROOT = Path(__file__).resolve().parents[5]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from riskstream.shared.utils.storage import StorageClient


logger = logging.getLogger("threatfox.main")


def configure_logging() -> None:
    level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())

    root_logger = logging.getLogger()
    root_logger.handlers = [handler]
    root_logger.setLevel(level)


def log_event(level: int, message: str, **fields) -> None:
    logger.log(level, message, extra={"fields": fields})


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def build_recent_object_key(timestamp: datetime) -> str:
    return f"threatfox/recent/{timestamp.strftime('%Y/%m/%d/%H%M%SZ')}.json"


def build_recent_snapshot(
    threatfox_data: dict, fetched_at: datetime, requested_days: int = 1
) -> dict:
    return {
        "source": "threatfox",
        "feed": "recent",
        "fetched_at": fetched_at.isoformat(),
        "requested_days": requested_days,
        "service": "threatfox-ingestion",
        "data": threatfox_data,
    }


def persist_recent_snapshot(threatfox_data: dict, requested_days: int = 1) -> dict:
    fetched_at = utcnow()
    object_key = build_recent_object_key(fetched_at)
    snapshot = build_recent_snapshot(threatfox_data, fetched_at, requested_days)
    payload = json.dumps(snapshot).encode("utf-8")

    storage = StorageClient()
    storage.get_client().put_object(
        "raw-feeds",
        object_key,
        BytesIO(payload),
        len(payload),
        content_type="application/json",
    )

    return {
        "bucket": "raw-feeds",
        "object_key": object_key,
        "fetched_at": snapshot["fetched_at"],
        "requested_days": requested_days,
        "threats_count": len(threatfox_data.get("data", [])),
    }


class Handler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.client = ThreatFoxClient()
        super().__init__(*args, **kwargs)

    def do_GET(self):
        environment = os.getenv("ENVIRONMENT", "unknown")
        self.log_request_started("GET", environment)

        if self.path == "/healthz":
            payload = {"status": "ok"}
            self.send_json_response(200, payload)
        elif self.path == "/recent":
            try:
                data = self.client.get_recent_threats(days=1)
                payload = {
                    "service": "threatfox-ingestion",
                    "threats_count": len(data.get("data", [])),
                    "data": data,
                }
                self.send_json_response(200, payload)
            except Exception as e:
                log_event(
                    logging.ERROR,
                    "ThreatFox recent request failed",
                    service="threatfox-ingestion",
                    event="request_failed",
                    path=self.path,
                    method="GET",
                    environment=environment,
                    status_code=500,
                    error=str(e),
                    days=1,
                )
                payload = {"error": str(e)}
                self.send_json_response(500, payload)
        else:
            payload = {
                "service": "threatfox-ingestion",
                "environment": environment,
            }
            self.send_json_response(200, payload)

    def do_POST(self):
        environment = os.getenv("ENVIRONMENT", "unknown")
        self.log_request_started("POST", environment)

        if self.path == "/ingest/recent":
            try:
                data = self.client.get_recent_threats(days=1)
                ingestion = persist_recent_snapshot(data, requested_days=1)
                payload = {
                    "service": "threatfox-ingestion",
                    "feed": "recent",
                    **ingestion,
                }
                self.send_json_response(200, payload)
            except Exception as e:
                log_event(
                    logging.ERROR,
                    "ThreatFox recent ingestion failed",
                    service="threatfox-ingestion",
                    event="request_failed",
                    path=self.path,
                    method="POST",
                    environment=environment,
                    status_code=500,
                    error=str(e),
                    days=1,
                )
                payload = {"error": str(e)}
                self.send_json_response(500, payload)
        else:
            self.send_json_response(404, {"error": "not found"})

    def log_request_started(self, method, environment):
        log_event(
            logging.INFO,
            "Handling HTTP request",
            service="threatfox-ingestion",
            event="request_started",
            path=self.path,
            method=method,
            environment=environment,
        )

    def send_json_response(self, status_code, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        log_event(
            logging.INFO,
            "HTTP request completed",
            service="threatfox-ingestion",
            event="request_completed",
            path=self.path,
            method=self.command,
            environment=os.getenv("ENVIRONMENT", "unknown"),
            status_code=status_code,
        )

    def log_message(self, format, *args):
        return


def run() -> None:
    configure_logging()
    port = int(os.getenv("PORT", "8081"))
    environment = os.getenv("ENVIRONMENT", "unknown")

    server = HTTPServer(("0.0.0.0", port), Handler)
    log_event(
        logging.INFO,
        "ThreatFox ingestion service listening",
        service="threatfox-ingestion",
        event="service_started",
        environment=environment,
        port=port,
    )
    server.serve_forever()


if __name__ == "__main__":
    run()
