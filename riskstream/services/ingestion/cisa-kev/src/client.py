import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict
from urllib.error import HTTPError, URLError
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


logger = logging.getLogger("cisa_kev.client")


class CisaKevClient:
    """Client for interacting with the CISA Known Exploited Vulnerabilities feed."""

    DEFAULT_URL = (
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json"
    )

    def __init__(self, timeout: int = 30, url: str | None = None):
        self.timeout = timeout
        self.url = url or os.getenv("CISA_KEV_URL", self.DEFAULT_URL)

    def get_catalog(self) -> Dict[str, Any]:
        request = Request(
            self.url,
            headers={
                "Accept": "application/json",
            },
        )

        logger.info(
            "Sending CISA KEV request",
            extra={
                "fields": {
                    "service": "cisa-kev-ingestion",
                    "event": "upstream_request_started",
                    "upstream": self.url,
                    "timeout_seconds": self.timeout,
                }
            },
        )

        try:
            with urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
                vulnerability_count = len(payload.get("vulnerabilities", []))
                logger.info(
                    "CISA KEV request completed",
                    extra={
                        "fields": {
                            "service": "cisa-kev-ingestion",
                            "event": "upstream_request_completed",
                            "upstream": self.url,
                            "status_code": response.status,
                            "vulnerabilities_count": vulnerability_count,
                        }
                    },
                )
                return payload
        except HTTPError as e:
            logger.exception(
                "CISA KEV HTTP error",
                extra={
                    "fields": {
                        "service": "cisa-kev-ingestion",
                        "event": "upstream_request_failed",
                        "upstream": self.url,
                        "status_code": e.code,
                        "error": f"HTTP error: {e.code} - {e.reason}",
                    }
                },
            )
            raise Exception(f"HTTP error: {e.code} - {e.reason}")
        except URLError as e:
            logger.exception(
                "CISA KEV URL error",
                extra={
                    "fields": {
                        "service": "cisa-kev-ingestion",
                        "event": "upstream_request_failed",
                        "upstream": self.url,
                        "error": f"URL error: {e.reason}",
                    }
                },
            )
            raise Exception(f"URL error: {e.reason}")
        except Exception as e:
            logger.exception(
                "CISA KEV request failed",
                extra={
                    "fields": {
                        "service": "cisa-kev-ingestion",
                        "event": "upstream_request_failed",
                        "upstream": self.url,
                        "error": f"Request failed: {str(e)}",
                    }
                },
            )
            raise Exception(f"Request failed: {str(e)}")
