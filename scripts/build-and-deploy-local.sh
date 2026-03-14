#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAMESPACE="local-dev"
IMAGE_NAME="riskstream"
THREATFOX_IMAGE_NAME="threatfox-ingestion"
IMAGE_TAG="${IMAGE_TAG:-local}"

echo "[1/7] Building app Docker image..."
docker build -t "${IMAGE_NAME}:${IMAGE_TAG}" "${ROOT_DIR}/app"

echo "[2/7] Building ThreatFox Docker image..."
docker build -f "${ROOT_DIR}/riskstream/services/ingestion/threatfox/Dockerfile" \
  -t "${THREATFOX_IMAGE_NAME}:${IMAGE_TAG}" \
  "${ROOT_DIR}"

echo "[3/7] Importing images to k3s..."
docker save "${IMAGE_NAME}:${IMAGE_TAG}" | sudo k3s ctr images import -
docker save "${THREATFOX_IMAGE_NAME}:${IMAGE_TAG}" | sudo k3s ctr images import -

echo "[4/7] Creating namespace: ${NAMESPACE}..."
kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

echo "[5/7] Deploying to ${NAMESPACE} using local-dev overlay..."
kubectl apply -k "${ROOT_DIR}/k8s/overlays/local-dev" -n "${NAMESPACE}"

echo "[6/7] Waiting for MinIO to be ready..."
kubectl wait --for=condition=ready pod -l app=minio -n "${NAMESPACE}" --timeout=120s

# Give MinIO a few extra seconds to fully start accepting connections
echo "Waiting for MinIO service to be fully available..."
sleep 10

echo "[7/7] Waiting for MinIO bucket initialization to complete..."
# Wait for the init job to complete (it should start automatically after MinIO is ready)
if kubectl wait --for=condition=complete job/minio-init -n "${NAMESPACE}" --timeout=120s; then
  echo "✓ MinIO initialization completed successfully"
  echo ""
  echo "View initialization logs:"
  kubectl logs -n "${NAMESPACE}" job/minio-init --tail=100
else
  echo "⚠ Warning: MinIO init job did not complete in time"
  echo ""
  echo "=== MinIO Init Job Status ==="
  kubectl get job/minio-init -n "${NAMESPACE}"
  echo ""
  echo "=== MinIO Init Job Logs ==="
  kubectl logs -n "${NAMESPACE}" job/minio-init --tail=100 2>&1 || echo "Could not retrieve logs"
  echo ""
  echo "=== MinIO Pod Status ==="
  kubectl get pods -n "${NAMESPACE}" -l app=minio
  echo ""
  echo "Manual check: kubectl logs -n ${NAMESPACE} job/minio-init"
fi

echo ""
echo "✓ Build and deployment complete!"
echo "  Image: ${IMAGE_NAME}:${IMAGE_TAG}"
echo "  ThreatFox Image: ${THREATFOX_IMAGE_NAME}:${IMAGE_TAG}"
echo "  MinIO: Buckets initialized"
echo ""
echo "Check status:"
echo "  kubectl get pods -n ${NAMESPACE}"
echo "  kubectl logs -n ${NAMESPACE} -l app.kubernetes.io/name=riskstream --tail=50 -f"
echo ""
echo "Port forward services:"
echo "  kubectl port-forward -n ${NAMESPACE} svc/riskstream 8081:80"
echo "  ${ROOT_DIR}/scripts/port-forward-minio.sh local-dev"
echo ""
echo "Access at:"
echo "  App:           http://localhost:8081"
echo "  MinIO Console: http://localhost:9001 (after port-forward)"
