# Shared Libraries

This directory contains shared code, utilities, and definitions used across multiple RiskStream services.

## Structure

### proto/
Protocol buffer definitions for service-to-service communication (future use).

### utils/
Common utility functions and helpers shared across services.

#### storage.py
S3-compatible storage client for MinIO or AWS S3.

**Features:**
- Automatic bucket creation
- Environment-based configuration
- Works with both MinIO (local/k8s) and AWS S3
- Command-line utility for bucket management

**Usage:**

```python
from riskstream.shared.utils.storage import StorageClient, initialize_default_buckets

# Initialize with default buckets
client = initialize_default_buckets()

# Or create custom buckets
client = StorageClient()
client.ensure_buckets(["my-bucket", "another-bucket"])

# Get MinIO client for advanced operations
minio_client = client.get_client()
```

**Environment Variables:**
- `S3_ENDPOINT`: MinIO/S3 endpoint (default: localhost:9000)
- `S3_ACCESS_KEY`: Access key (default: minioadmin)
- `S3_SECRET_KEY`: Secret key (default: minioadmin)
- `S3_USE_SSL`: Use SSL/TLS (default: auto-detect)
- `S3_REGION`: AWS region (default: us-east-1)

**CLI:**
```bash
# Initialize default buckets
python -m riskstream.shared.utils.storage

# Create custom buckets
python -m riskstream.shared.utils.storage --buckets my-bucket another-bucket

# List existing buckets
python -m riskstream.shared.utils.storage --list
```

## Usage

Shared libraries can be imported by services as needed. In a production setup, these might be packaged as internal libraries or modules.

## Installation

```bash
pip install -r requirements.txt
```

## Future Additions

- Common data models
- Shared authentication/authorization utilities
- Logging and monitoring helpers
- Configuration management utilities
- Database connection pooling
- Message queue abstractions
