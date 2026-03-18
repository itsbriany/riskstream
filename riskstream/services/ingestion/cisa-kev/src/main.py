import json
import hashlib
import logging
import os
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from io import BytesIO
from pathlib import Path

from client import CisaKevClient, JsonFormatter

REPO_ROOT = Path(__file__).resolve().parents[5]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from riskstream.shared.utils.storage import StorageClient


logger = logging.getLogger("cisa_kev.main")
RAW_FEEDS_BUCKET = "raw-feeds"
CATALOG_PREFIX = "cisa-kev/catalog/"


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


def build_catalog_object_key(timestamp: datetime) -> str:
    return f"{CATALOG_PREFIX}{timestamp.strftime('%Y/%m/%d/%H%M%SZ')}.json"


def canonicalize_catalog_data(catalog_data: dict) -> str:
    return json.dumps(catalog_data, sort_keys=True, separators=(",", ":"))


def compute_catalog_hash(catalog_data: dict) -> str:
    canonical_payload = canonicalize_catalog_data(catalog_data).encode("utf-8")
    return hashlib.sha256(canonical_payload).hexdigest()


def build_catalog_snapshot(catalog_data: dict, fetched_at: datetime, content_hash: str) -> dict:
    return {
        "source": "cisa-kev",
        "feed": "catalog",
        "fetched_at": fetched_at.isoformat(),
        "service": "cisa-kev-ingestion",
        "content_hash": content_hash,
        "data": catalog_data,
    }


def read_snapshot_response(response) -> dict:
    try:
        return json.loads(response.read().decode("utf-8"))
    finally:
        close = getattr(response, "close", None)
        if callable(close):
            close()

        release_conn = getattr(response, "release_conn", None)
        if callable(release_conn):
            release_conn()


def get_latest_catalog_snapshot(storage: StorageClient) -> dict | None:
    objects = storage.get_client().list_objects(
        RAW_FEEDS_BUCKET,
        prefix=CATALOG_PREFIX,
        recursive=True,
    )
    latest_object = None
    for obj in objects:
        object_name = getattr(obj, "object_name", None)
        if not object_name:
            continue
        if latest_object is None or object_name > latest_object:
            latest_object = object_name

    if latest_object is None:
        return None

    response = storage.get_client().get_object(RAW_FEEDS_BUCKET, latest_object)
    snapshot = read_snapshot_response(response)
    snapshot["object_key"] = latest_object
    if not snapshot.get("content_hash") and isinstance(snapshot.get("data"), dict):
        snapshot["content_hash"] = compute_catalog_hash(snapshot["data"])
    return snapshot


def persist_catalog_snapshot(catalog_data: dict, storage: StorageClient | None = None) -> dict:
    fetched_at = utcnow()
    content_hash = compute_catalog_hash(catalog_data)
    object_key = build_catalog_object_key(fetched_at)
    snapshot = build_catalog_snapshot(catalog_data, fetched_at, content_hash)
    payload = json.dumps(snapshot).encode("utf-8")

    storage = storage or StorageClient()
    storage.get_client().put_object(
        RAW_FEEDS_BUCKET,
        object_key,
        BytesIO(payload),
        len(payload),
        content_type="application/json",
    )

    return {
        "changed": True,
        "snapshot_written": True,
        "bucket": RAW_FEEDS_BUCKET,
        "object_key": object_key,
        "content_hash": content_hash,
        "checked_at": snapshot["fetched_at"],
        "fetched_at": snapshot["fetched_at"],
        "vulnerabilities_count": len(catalog_data.get("vulnerabilities", [])),
    }


def ingest_catalog_snapshot(catalog_data: dict, storage: StorageClient | None = None) -> dict:
    storage = storage or StorageClient()
    content_hash = compute_catalog_hash(catalog_data)
    latest_snapshot = get_latest_catalog_snapshot(storage)
    checked_at = utcnow().isoformat()

    if latest_snapshot and latest_snapshot.get("content_hash") == content_hash:
        return {
            "changed": False,
            "snapshot_written": False,
            "checked_at": checked_at,
            "content_hash": content_hash,
            "last_object_key": latest_snapshot["object_key"],
            "vulnerabilities_count": len(catalog_data.get("vulnerabilities", [])),
        }

    ingestion = persist_catalog_snapshot(catalog_data, storage=storage)
    ingestion["checked_at"] = checked_at
    return ingestion


class Handler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.client = CisaKevClient()
        super().__init__(*args, **kwargs)

    def do_GET(self):
        environment = os.getenv("ENVIRONMENT", "unknown")
        self.log_request_started("GET", environment)

        if self.path == "/healthz":
            self.send_json_response(200, {"status": "ok"})
        elif self.path == "/catalog":
            try:
                data = self.client.get_catalog()
                payload = {
                    "service": "cisa-kev-ingestion",
                    "vulnerabilities_count": len(data.get("vulnerabilities", [])),
                    "data": data,
                }
                self.send_json_response(200, payload)
            except Exception as e:
                log_event(
                    logging.ERROR,
                    "CISA KEV catalog request failed",
                    service="cisa-kev-ingestion",
                    event="request_failed",
                    path=self.path,
                    method="GET",
                    environment=environment,
                    status_code=500,
                    error=str(e),
                )
                self.send_json_response(500, {"error": str(e)})
        else:
            payload = {
                "service": "cisa-kev-ingestion",
                "environment": environment,
            }
            self.send_json_response(200, payload)

    def do_POST(self):
        environment = os.getenv("ENVIRONMENT", "unknown")
        self.log_request_started("POST", environment)

        if self.path == "/ingest/catalog":
            try:
                data = self.client.get_catalog()
                ingestion = ingest_catalog_snapshot(data)
                log_event(
                    logging.INFO,
                    "CISA KEV catalog ingestion evaluated",
                    service="cisa-kev-ingestion",
                    event="catalog_ingestion_evaluated",
                    path=self.path,
                    method="POST",
                    environment=environment,
                    changed=ingestion["changed"],
                    snapshot_written=ingestion["snapshot_written"],
                    content_hash=ingestion["content_hash"],
                    vulnerabilities_count=ingestion["vulnerabilities_count"],
                )
                payload = {
                    "service": "cisa-kev-ingestion",
                    "feed": "catalog",
                    **ingestion,
                }
                self.send_json_response(200, payload)
            except Exception as e:
                log_event(
                    logging.ERROR,
                    "CISA KEV catalog ingestion failed",
                    service="cisa-kev-ingestion",
                    event="request_failed",
                    path=self.path,
                    method="POST",
                    environment=environment,
                    status_code=500,
                    error=str(e),
                )
                self.send_json_response(500, {"error": str(e)})
        else:
            self.send_json_response(404, {"error": "not found"})

    def log_request_started(self, method, environment):
        log_event(
            logging.INFO,
            "Handling HTTP request",
            service="cisa-kev-ingestion",
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
            service="cisa-kev-ingestion",
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
    port = int(os.getenv("PORT", "8082"))
    environment = os.getenv("ENVIRONMENT", "unknown")

    server = HTTPServer(("0.0.0.0", port), Handler)
    log_event(
        logging.INFO,
        "CISA KEV ingestion service listening",
        service="cisa-kev-ingestion",
        event="service_started",
        environment=environment,
        port=port,
    )
    server.serve_forever()


if __name__ == "__main__":
    run()
