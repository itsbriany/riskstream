#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAMESPACE="${NAMESPACE:-local-dev}"
IMAGE_NAME="${IMAGE_NAME:-riskstream}"
IMAGE_TAG="${IMAGE_TAG:-local}"
JOB_NAME="api-ranking-integration-test"
CONFIGMAP_NAME="api-ranking-integration-test-code"
TEST_FILE="${ROOT_DIR}/riskstream/tests/integration/test_api_ranking.py"
JOB_MANIFEST="${ROOT_DIR}/k8s/local-dev/api-ranking-integration-test-job.yaml"
DOCKERFILE_PATH="${ROOT_DIR}/riskstream/services/api/Dockerfile"

echo "Building API image ${IMAGE_NAME}:${IMAGE_TAG}..."
docker build -f "${DOCKERFILE_PATH}" -t "${IMAGE_NAME}:${IMAGE_TAG}" "${ROOT_DIR}"

echo "Importing API image into k3s..."
if [ -x "/usr/local/bin/k3s-image-import" ]; then
  docker save "${IMAGE_NAME}:${IMAGE_TAG}" | sudo -n /usr/local/bin/k3s-image-import
else
  docker save "${IMAGE_NAME}:${IMAGE_TAG}" | sudo k3s ctr images import -
fi

echo "Deploying local-dev overlay to ${NAMESPACE}..."
kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -k "${ROOT_DIR}/k8s/overlays/local-dev" -n "${NAMESPACE}"

echo "Rolling out updated API deployment..."
kubectl rollout restart deployment/riskstream -n "${NAMESPACE}"

echo "Waiting for API rollout to complete in ${NAMESPACE}..."
kubectl rollout status deployment/riskstream -n "${NAMESPACE}" --timeout=180s

echo "Waiting for MinIO to be ready in ${NAMESPACE}..."
kubectl wait --for=condition=ready pod -l app=minio -n "${NAMESPACE}" --timeout=180s

echo "Waiting for MinIO initialization job to complete..."
kubectl wait --for=condition=complete job/minio-init -n "${NAMESPACE}" --timeout=180s

echo "Refreshing test ConfigMap..."
kubectl create configmap "${CONFIGMAP_NAME}" \
  --from-file=test_api_ranking.py="${TEST_FILE}" \
  -n "${NAMESPACE}" \
  --dry-run=client \
  -o yaml | kubectl apply -f -

echo "Recreating integration test job..."
kubectl delete job "${JOB_NAME}" -n "${NAMESPACE}" --ignore-not-found
kubectl apply -f "${JOB_MANIFEST}"

echo "Waiting for test job to complete..."
if kubectl wait --for=condition=complete "job/${JOB_NAME}" -n "${NAMESPACE}" --timeout=300s; then
  kubectl logs -n "${NAMESPACE}" "job/${JOB_NAME}"
else
  kubectl logs -n "${NAMESPACE}" "job/${JOB_NAME}" || true
  exit 1
fi
