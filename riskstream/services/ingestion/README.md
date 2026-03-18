# Ingestion Services

This directory contains microservices responsible for ingesting threat intelligence data from various external sources.

## Services

### CISA KEV
Ingests the official CISA Known Exploited Vulnerabilities catalog.
- Canonical doc: `cisa-kev/README.md`

### ThreatFox
Ingests indicators of compromise (IOCs) from the abuse.ch ThreatFox community API.
- Canonical doc: `threatfox/README.md`

## Architecture Pattern

Each ingestion service follows a consistent pattern:
1. External API client implementation
2. Data model definitions
3. RESTful API for internal access
4. Health monitoring endpoints
5. Configurable polling/scheduling

Service-specific ports, schedules, upstream sources, persistence layout, and troubleshooting should be maintained in the service README beside the code, not repeated here.

## Planned Future Services

Additional ingestion services planned:
- **AlienVault OTX**: Open Threat Exchange platform
- **VirusTotal**: File and URL scanning
- **URLhaus**: Malicious URL database
- **MalwareBazaar**: Malware sample database
- **Custom feeds**: Organization-specific threat feeds

## Communication

Ingestion services can communicate with downstream services via:
- Direct HTTP APIs (current)
- Message queues (planned)
- Event streams (planned)
