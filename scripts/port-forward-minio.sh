#!/bin/bash
# Port forward MinIO service for local access
# Usage: ./scripts/port-forward-minio.sh [environment]
# Environment can be: local-dev, staging, production (default: local-dev)

set -e

ENVIRONMENT=${1:-local-dev}

# Determine namespace based on environment
case $ENVIRONMENT in
  local-dev)
    NAMESPACE="local-dev"
    ;;
  staging)
    NAMESPACE="staging"
    ;;
  production)
    NAMESPACE="production"
    ;;
  *)
    echo "Error: Unknown environment '$ENVIRONMENT'"
    echo "Usage: $0 [local-dev|staging|production]"
    exit 1
    ;;
esac

  SERVICE_NAME="minio"

echo "🔧 Port forwarding MinIO from $ENVIRONMENT environment..."
echo "   Namespace: $NAMESPACE"
echo "   Service: $SERVICE_NAME"
echo ""
echo "   API:         http://localhost:9000"
echo "   Console UI:  http://localhost:9001"
echo ""
echo "   Credentials:"
echo "   - User: minioadmin (or environment-specific)"
echo "   - Pass: minioadmin (or environment-specific)"
echo ""
echo "Press Ctrl+C to stop port forwarding"
echo ""

kubectl port-forward -n "$NAMESPACE" "svc/$SERVICE_NAME" 9000:9000 9001:9001 --address 0.0.0.0
