# Ingestion Services

This directory contains microservices responsible for ingesting threat intelligence data from various external sources.

## Services

### ThreatFox
Ingests indicators of compromise (IOCs) from the abuse.ch ThreatFox community API.
- **Port**: 8081
- **Source**: https://threatfox.abuse.ch/

## Future Services

Additional ingestion services planned:
- **AlienVault OTX**: Open Threat Exchange platform
- **VirusTotal**: File and URL scanning
- **URLhaus**: Malicious URL database
- **MalwareBazaar**: Malware sample database
- **Custom feeds**: Organization-specific threat feeds

## Architecture Pattern

Each ingestion service follows a consistent pattern:
1. External API client implementation
2. Data model definitions
3. RESTful API for internal access
4. Health monitoring endpoints
5. Configurable polling/scheduling

## Communication

Ingestion services can communicate with downstream services via:
- Direct HTTP APIs (current)
- Message queues (planned)
- Event streams (planned)
