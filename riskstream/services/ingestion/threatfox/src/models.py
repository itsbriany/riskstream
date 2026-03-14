from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional


@dataclass
class ThreatIndicator:
    """Represents a Threat Indicator of Compromise (IOC)."""

    id: str
    ioc: str
    ioc_type: str
    threat_type: str
    malware: Optional[str]
    malware_alias: Optional[str]
    malware_printable: Optional[str]
    first_seen: datetime
    last_seen: Optional[datetime]
    confidence_level: int
    reference: Optional[str]
    reporter: str
    tags: List[str]

    @classmethod
    def from_api_response(cls, data: dict) -> "ThreatIndicator":
        """Create a ThreatIndicator from ThreatFox API response."""
        return cls(
            id=data.get("id", ""),
            ioc=data.get("ioc", ""),
            ioc_type=data.get("ioc_type", ""),
            threat_type=data.get("threat_type", ""),
            malware=data.get("malware"),
            malware_alias=data.get("malware_alias"),
            malware_printable=data.get("malware_printable"),
            first_seen=datetime.fromisoformat(data.get("first_seen", "")),
            last_seen=(
                datetime.fromisoformat(data["last_seen"])
                if data.get("last_seen")
                else None
            ),
            confidence_level=data.get("confidence_level", 0),
            reference=data.get("reference"),
            reporter=data.get("reporter", ""),
            tags=data.get("tags", []),
        )


@dataclass
class ThreatFoxResponse:
    """Represents a response from the ThreatFox API."""

    query_status: str
    data: List[ThreatIndicator]

    @classmethod
    def from_api_response(cls, response: dict) -> "ThreatFoxResponse":
        """Create a ThreatFoxResponse from API response."""
        indicators = [
            ThreatIndicator.from_api_response(item) for item in response.get("data", [])
        ]
        return cls(query_status=response.get("query_status", ""), data=indicators)
