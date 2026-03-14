from __future__ import annotations

"""
Storage utility for MinIO/S3 bucket initialization and management.

This module provides a storage client that works with both MinIO (local/staging/production)
and AWS S3 (if needed in future). Buckets are automatically created on initialization.
"""

import os
import sys
from typing import List, Optional

try:
    from minio import Minio
    from minio.error import S3Error

    MINIO_AVAILABLE = True
except ImportError:
    MINIO_AVAILABLE = False
    print("Warning: minio package not installed. Install with: pip install minio")


class StorageClient:
    """
    S3-compatible storage client for MinIO or AWS S3.

    Configuration via environment variables:
    - S3_ENDPOINT: MinIO/S3 endpoint (e.g., "minio:9000" or "s3.amazonaws.com")
    - S3_ACCESS_KEY: Access key ID
    - S3_SECRET_KEY: Secret access key
    - S3_USE_SSL: Whether to use SSL/TLS (default: false for local, true for AWS)
    - S3_REGION: Region for AWS S3 (optional)
    """

    def __init__(
        self,
        endpoint: Optional[str] = None,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        use_ssl: Optional[bool] = None,
        region: Optional[str] = None,
    ):
        if not MINIO_AVAILABLE:
            raise ImportError(
                "minio package is required. Install with: pip install minio"
            )

        self.endpoint = endpoint or os.getenv("S3_ENDPOINT", "localhost:9000")
        self.access_key = access_key or os.getenv("S3_ACCESS_KEY", "minioadmin")
        self.secret_key = secret_key or os.getenv("S3_SECRET_KEY", "minioadmin")
        self.region = region or os.getenv("S3_REGION", "us-east-1")

        # Default use_ssl based on endpoint
        if use_ssl is None:
            use_ssl_env = os.getenv("S3_USE_SSL", "").lower()
            if use_ssl_env in ("true", "1", "yes"):
                self.use_ssl = True
            elif use_ssl_env in ("false", "0", "no"):
                self.use_ssl = False
            else:
                # Auto-detect: use SSL for AWS endpoints
                self.use_ssl = "amazonaws.com" in self.endpoint
        else:
            self.use_ssl = use_ssl

        self.client = Minio(
            self.endpoint,
            access_key=self.access_key,
            secret_key=self.secret_key,
            secure=self.use_ssl,
            region=self.region,
        )

    def ensure_bucket(self, bucket_name: str) -> bool:
        """
        Ensure a bucket exists, creating it if necessary.

        Args:
            bucket_name: Name of the bucket to ensure exists

        Returns:
            True if bucket was created, False if it already existed
        """
        try:
            if self.client.bucket_exists(bucket_name):
                print(f"Bucket '{bucket_name}' already exists")
                return False

            self.client.make_bucket(bucket_name)
            print(f"Created bucket '{bucket_name}'")
            return True
        except S3Error as e:
            print(f"Error ensuring bucket '{bucket_name}': {e}", file=sys.stderr)
            raise

    def ensure_buckets(self, bucket_names: List[str]) -> dict:
        """
        Ensure multiple buckets exist.

        Args:
            bucket_names: List of bucket names to ensure exist

        Returns:
            Dictionary with bucket names as keys and creation status as values
        """
        results = {}
        for bucket_name in bucket_names:
            try:
                results[bucket_name] = self.ensure_bucket(bucket_name)
            except S3Error:
                results[bucket_name] = None
        return results

    def list_buckets(self) -> List[str]:
        """List all buckets."""
        try:
            buckets = self.client.list_buckets()
            return [bucket.name for bucket in buckets]
        except S3Error as e:
            print(f"Error listing buckets: {e}", file=sys.stderr)
            raise

    def get_client(self) -> Minio:
        """Get the underlying MinIO client for advanced operations."""
        return self.client


def initialize_default_buckets() -> StorageClient:
    """
    Initialize default buckets for RiskStream.

    Default buckets:
    - threat-indicators: Processed threat indicators
    - raw-feeds: Raw data from threat feeds
    - processed-data: Analyzed and enriched data
    - archives: Historical data archives

    Returns:
        Configured StorageClient instance
    """
    client = StorageClient()

    default_buckets = ["threat-indicators", "raw-feeds", "processed-data", "archives"]

    print(f"Initializing storage at {client.endpoint}")
    results = client.ensure_buckets(default_buckets)

    created = [name for name, status in results.items() if status is True]
    existing = [name for name, status in results.items() if status is False]
    failed = [name for name, status in results.items() if status is None]

    if created:
        print(f"Created {len(created)} new bucket(s): {', '.join(created)}")
    if existing:
        print(f"Found {len(existing)} existing bucket(s): {', '.join(existing)}")
    if failed:
        print(
            f"Failed to create {len(failed)} bucket(s): {', '.join(failed)}",
            file=sys.stderr,
        )

    return client


if __name__ == "__main__":
    """Command-line utility for bucket initialization."""
    import argparse

    parser = argparse.ArgumentParser(description="Initialize MinIO/S3 storage buckets")
    parser.add_argument(
        "--buckets",
        nargs="+",
        help="Bucket names to create (default: threat-indicators, raw-feeds, processed-data, archives)",
    )
    parser.add_argument("--list", action="store_true", help="List existing buckets")

    args = parser.parse_args()

    try:
        client = StorageClient()

        if args.list:
            print("Existing buckets:")
            for bucket in client.list_buckets():
                print(f"  - {bucket}")
        else:
            if args.buckets:
                client.ensure_buckets(args.buckets)
            else:
                initialize_default_buckets()
    except ImportError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
