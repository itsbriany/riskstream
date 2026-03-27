import csv
import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from io import StringIO
from typing import Any, Dict
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from urllib.request import Request, urlopen


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


logger = logging.getLogger("urlhaus.client")


class UrlhausClient:
    """Client for interacting with the URLhaus recent URL export."""

    DEFAULT_RECENT_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"

    def __init__(
        self,
        timeout: int = 30,
        url: str | None = None,
        auth_key: str | None = None,
    ):
        self.timeout = timeout
        self.url = url or os.getenv("URLHAUS_RECENT_URL", self.DEFAULT_RECENT_URL)
        self.auth_key = auth_key or os.getenv("URLHAUS_AUTH_KEY")

    def build_request_url(self) -> str:
        if not self.auth_key:
            return self.url

        parsed = urlparse(self.url)
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        query.setdefault("auth-key", self.auth_key)
        return urlunparse(parsed._replace(query=urlencode(query)))

    def parse_recent_csv(self, raw_csv: str) -> list[Dict[str, str]]:
        data_lines = []
        for line in raw_csv.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("#"):
                candidate = stripped.removeprefix("#").strip()
                if candidate.startswith("id,"):
                    data_lines.append(candidate)
                continue
            data_lines.append(line)
        if not data_lines:
            return []

        reader = csv.DictReader(StringIO("\n".join(data_lines)))
        records: list[Dict[str, str]] = []
        for row in reader:
            records.append(
                {str(key): value.strip() if isinstance(value, str) else value for key, value in row.items()}
            )
        return records

    def compute_content_hash(self, raw_csv: str) -> str:
        return hashlib.sha256(raw_csv.encode("utf-8")).hexdigest()

    def get_recent_urls(self) -> Dict[str, Any]:
        request_url = self.build_request_url()
        headers = {"Accept": "text/csv"}
        if self.auth_key:
            headers["Auth-Key"] = self.auth_key

        request = Request(request_url, headers=headers)

        logger.info(
            "Sending URLhaus request",
            extra={
                "fields": {
                    "service": "urlhaus-ingestion",
                    "event": "upstream_request_started",
                    "upstream": request_url,
                    "timeout_seconds": self.timeout,
                }
            },
        )

        try:
            with urlopen(request, timeout=self.timeout) as response:
                raw_csv = response.read().decode("utf-8")
                urls = self.parse_recent_csv(raw_csv)
                content_hash = self.compute_content_hash(raw_csv)
                logger.info(
                    "URLhaus request completed",
                    extra={
                        "fields": {
                            "service": "urlhaus-ingestion",
                            "event": "upstream_request_completed",
                            "upstream": request_url,
                            "status_code": response.status,
                            "urls_count": len(urls),
                            "content_hash": content_hash,
                        }
                    },
                )
                return {
                    "source_url": request_url,
                    "content_hash": content_hash,
                    "raw_csv": raw_csv,
                    "urls": urls,
                }
        except HTTPError as e:
            logger.exception(
                "URLhaus HTTP error",
                extra={
                    "fields": {
                        "service": "urlhaus-ingestion",
                        "event": "upstream_request_failed",
                        "upstream": request_url,
                        "status_code": e.code,
                        "error": f"HTTP error: {e.code} - {e.reason}",
                    }
                },
            )
            raise Exception(f"HTTP error: {e.code} - {e.reason}")
        except URLError as e:
            logger.exception(
                "URLhaus URL error",
                extra={
                    "fields": {
                        "service": "urlhaus-ingestion",
                        "event": "upstream_request_failed",
                        "upstream": request_url,
                        "error": f"URL error: {e.reason}",
                    }
                },
            )
            raise Exception(f"URL error: {e.reason}")
        except Exception as e:
            logger.exception(
                "URLhaus request failed",
                extra={
                    "fields": {
                        "service": "urlhaus-ingestion",
                        "event": "upstream_request_failed",
                        "upstream": request_url,
                        "error": f"Request failed: {str(e)}",
                    }
                },
            )
            raise Exception(f"Request failed: {str(e)}")
