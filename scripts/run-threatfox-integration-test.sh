#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAMESPACE="${NAMESPACE:-local-dev}"
IMAGE_NAME="${IMAGE_NAME:-threatfox-ingestion}"
IMAGE_TAG="${IMAGE_TAG:-local}"
JOB_NAME="threatfox-integration-test"
CONFIGMAP_NAME="threatfox-integration-test-code"
TEST_FILE="${ROOT_DIR}/riskstream/tests/integration/test_threatfox_ingestion.py"
JOB_MANIFEST="${ROOT_DIR}/k8s/local-dev/threatfox-integration-test-job.yaml"
SERVICE_DIR="${ROOT_DIR}/riskstream/services/ingestion/threatfox"
DOCKERFILE_PATH="${ROOT_DIR}/riskstream/services/ingestion/threatfox/Dockerfile"

echo "Building ThreatFox image ${IMAGE_NAME}:${IMAGE_TAG}..."
docker build -f "${DOCKERFILE_PATH}" -t "${IMAGE_NAME}:${IMAGE_TAG}" "${ROOT_DIR}"

echo "Importing ThreatFox image into k3s..."
docker save "${IMAGE_NAME}:${IMAGE_TAG}" | sudo k3s ctr images import -

echo "Deploying local-dev overlay to ${NAMESPACE}..."
kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -k "${ROOT_DIR}/k8s/overlays/local-dev" -n "${NAMESPACE}"

echo "Rolling out updated ThreatFox deployment..."
kubectl rollout restart deployment/threatfox-ingestion -n "${NAMESPACE}"

echo "Waiting for ThreatFox rollout to complete in ${NAMESPACE}..."
kubectl rollout status deployment/threatfox-ingestion -n "${NAMESPACE}" --timeout=180s

echo "Refreshing test ConfigMap..."
kubectl create configmap "${CONFIGMAP_NAME}" \
  --from-file=test_threatfox_ingestion.py="${TEST_FILE}" \
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
