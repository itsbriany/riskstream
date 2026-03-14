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


logger = logging.getLogger("threatfox.client")


class ThreatFoxClient:
    """Client for interacting with the abuse.ch ThreatFox API."""

    BASE_URL = "https://threatfox-api.abuse.ch/api/v1/"

    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.auth_key = os.getenv("THREATFOX_AUTH_KEY")

    def _make_request(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Make a request to the ThreatFox API."""
        if not self.auth_key:
            raise Exception(
                "ThreatFox auth key is not configured. Set THREATFOX_AUTH_KEY."
            )

        data = json.dumps(payload).encode("utf-8")
        query = payload.get("query", "unknown")

        request = Request(
            self.BASE_URL,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Auth-Key": self.auth_key,
            },
        )

        logger.info(
            "Sending ThreatFox API request",
            extra={
                "fields": {
                    "service": "threatfox-ingestion",
                    "event": "upstream_request_started",
                    "upstream": self.BASE_URL,
                    "query": query,
                    "timeout_seconds": self.timeout,
                }
            },
        )

        try:
            with urlopen(request, timeout=self.timeout) as response:
                payload_data = json.loads(response.read().decode("utf-8"))
                item_count = len(payload_data.get("data", []))
                logger.info(
                    "ThreatFox API request completed",
                    extra={
                        "fields": {
                            "service": "threatfox-ingestion",
                            "event": "upstream_request_completed",
                            "upstream": self.BASE_URL,
                            "query": query,
                            "status_code": response.status,
                            "item_count": item_count,
                        }
                    },
                )
                return payload_data
        except HTTPError as e:
            logger.exception(
                "ThreatFox API HTTP error",
                extra={
                    "fields": {
                        "service": "threatfox-ingestion",
                        "event": "upstream_request_failed",
                        "upstream": self.BASE_URL,
                        "query": query,
                        "status_code": e.code,
                        "error": f"HTTP error: {e.code} - {e.reason}",
                    }
                },
            )
            raise Exception(f"HTTP error: {e.code} - {e.reason}")
        except URLError as e:
            logger.exception(
                "ThreatFox API URL error",
                extra={
                    "fields": {
                        "service": "threatfox-ingestion",
                        "event": "upstream_request_failed",
                        "upstream": self.BASE_URL,
                        "query": query,
                        "error": f"URL error: {e.reason}",
                    }
                },
            )
            raise Exception(f"URL error: {e.reason}")
        except Exception as e:
            logger.exception(
                "ThreatFox API request failed",
                extra={
                    "fields": {
                        "service": "threatfox-ingestion",
                        "event": "upstream_request_failed",
                        "upstream": self.BASE_URL,
                        "query": query,
                        "error": f"Request failed: {str(e)}",
                    }
                },
            )
            raise Exception(f"Request failed: {str(e)}")

    def get_recent_threats(self, days: int = 1) -> Dict[str, Any]:
        """Get recent IOCs from the last N days."""
        payload = {"query": "get_iocs", "days": days}
        return self._make_request(payload)

    def search_ioc(self, search_term: str) -> Dict[str, Any]:
        """Search for a specific IOC."""
        payload = {"query": "search_ioc", "search_term": search_term}
        return self._make_request(payload)

    def get_ioc_by_id(self, ioc_id: str) -> Dict[str, Any]:
        """Get IOC details by ID."""
        payload = {"query": "ioc", "id": ioc_id}
        return self._make_request(payload)

    def get_tag_info(self, tag: str) -> Dict[str, Any]:
        """Get IOCs by tag (malware family)."""
        payload = {"query": "taginfo", "tag": tag, "limit": 100}
        return self._make_request(payload)
