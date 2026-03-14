# End-to-End Tests

This directory contains end-to-end tests that verify complete user workflows across the entire RiskStream platform.

## Overview

E2E tests validate entire use cases from a user's perspective, including:
- Complete data ingestion pipelines
- Multi-service workflows
- External API interactions
- Database persistence
- User-facing functionality

## Running Tests

```bash
# Run all E2E tests
pytest e2e/

# Run specific test file
pytest e2e/test_threat_ingestion_flow.py

# Run with verbose output
pytest -v e2e/
```

## Test Structure

```
e2e/
├── test_threat_ingestion_flow.py  # Complete ingestion workflow
├── test_api_workflows.py          # User-facing API scenarios
└── conftest.py                     # Shared fixtures and setup
```

## Requirements

E2E tests require:
- Full deployment of all services
- Database and message queue infrastructure
- External API access or mocks
- Test data and fixtures

## Best Practices

1. Test complete user journeys
2. Use production-like configurations
3. Test with realistic data volumes
4. Include performance assertions
5. Document test scenarios clearly
6. Clean up all test data
