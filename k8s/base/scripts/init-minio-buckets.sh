#!/bin/sh
set -e
set -x

# Configuration
if [ -z "${POD_NAMESPACE:-}" ]; then
  echo "ERROR: POD_NAMESPACE must be set"
  exit 1
fi

MINIO_ENDPOINT_RAW="${MINIO_ENDPOINT:-minio:9000}"
MINIO_ENDPOINT_RAW="${MINIO_ENDPOINT_RAW#http://}"
MINIO_ENDPOINT_RAW="${MINIO_ENDPOINT_RAW#https://}"

MINIO_HOST="${MINIO_ENDPOINT_RAW%%:*}"
MINIO_PORT="${MINIO_ENDPOINT_RAW##*:}"

if [ "${MINIO_PORT}" = "${MINIO_HOST}" ]; then
  MINIO_PORT="9000"
fi

# Convert short hostname to FQDN if needed
case "${MINIO_HOST}" in
  *.*.*)
    MINIO_FQDN="${MINIO_HOST}"
    ;;
  *)
    MINIO_FQDN="${MINIO_HOST}.${POD_NAMESPACE}.svc.cluster.local"
    ;;
esac

MINIO_ENDPOINT="${MINIO_FQDN}:${MINIO_PORT}"
MINIO_URL="http://${MINIO_ENDPOINT}"

echo "=========================================="
echo "🪣 MinIO Bucket Initialization"
echo "=========================================="
echo "Timestamp: $(date)"
echo "Namespace: ${POD_NAMESPACE}"
echo "MinIO Endpoint: ${MINIO_ENDPOINT}"
echo "MinIO URL: ${MINIO_URL}"
echo "=========================================="

# Wait for MinIO to be available
echo "⏳ Connecting to MinIO..."
ATTEMPTS=0
MAX_ATTEMPTS=30

until mc alias set myminio "${MINIO_URL}" "${MINIO_ROOT_USER}" "${MINIO_ROOT_PASSWORD}" 2>&1; do
  ATTEMPTS=$((ATTEMPTS + 1))
  
  if [ $ATTEMPTS -ge $MAX_ATTEMPTS ]; then
    echo ""
    echo "=========================================="
    echo "❌ ERROR: MinIO not available"
    echo "=========================================="
    echo "Failed to connect after ${MAX_ATTEMPTS} attempts"
    echo "MinIO URL: ${MINIO_URL}"
    echo "Namespace: ${POD_NAMESPACE}"
    echo ""
    echo "Troubleshooting:"
    echo "1. Check MinIO pod status:"
    echo "   kubectl get pods -n ${POD_NAMESPACE} -l app=minio"
    echo "2. Check MinIO service:"
    echo "   kubectl get svc -n ${POD_NAMESPACE} minio"
    echo "3. Check MinIO logs:"
    echo "   kubectl logs -n ${POD_NAMESPACE} -l app=minio"
    echo "=========================================="
    exit 1
  fi
  
  echo "Attempt ${ATTEMPTS}/${MAX_ATTEMPTS} failed, retrying in 2s..."
  sleep 2
done

echo "✅ Successfully connected to MinIO"
echo ""

# Step 3: Create buckets
echo "=========================================="
echo "📦 Creating Buckets"
echo "=========================================="

BUCKETS="threat-indicators raw-feeds processed-data archives"
for BUCKET in $BUCKETS; do
  echo ""
  echo "Creating bucket: ${BUCKET}"
  
  if mc mb --ignore-existing "myminio/${BUCKET}"; then
    echo "  ✓ ${BUCKET} ready"
  else
    EXIT_CODE=$?
    echo "  ⚠️  Warning: Failed to create ${BUCKET} (exit code: ${EXIT_CODE})"
  fi
  
  # Small delay to avoid potential race conditions
  sleep 3
done

echo ""
echo "📋 Final bucket list:"
if mc ls myminio 2>&1; then
  echo "✓ All buckets listed successfully"
else
  echo "❌ ERROR: Failed to list buckets"
  exit 1
fi

echo ""
echo "=========================================="
echo "✅ Initialization Complete"
echo "=========================================="

