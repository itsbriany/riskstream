# Ingestion Services

This directory contains microservices responsible for ingesting threat intelligence data from various external sources.

## Services

### CISA KEV
Ingests the official CISA Known Exploited Vulnerabilities catalog.
- **Port**: 8082
- **Source**: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- **Persistence**: Writes changed raw snapshots to `raw-feeds/cisa-kev/catalog/...`
- **Schedule**: Daily Kubernetes CronJob at `02:05 UTC`

### ThreatFox
Ingests indicators of compromise (IOCs) from the abuse.ch ThreatFox community API.
- **Port**: 8081
- **Source**: https://threatfox.abuse.ch/

## Architecture Pattern

Each ingestion service follows a consistent pattern:
1. External API client implementation
2. Data model definitions
3. RESTful API for internal access
4. Health monitoring endpoints
5. Configurable polling/scheduling

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
