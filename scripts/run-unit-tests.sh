#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOCKER_CONFIG_DIR="$(mktemp -d)"

cleanup() {
  rm -rf "${DOCKER_CONFIG_DIR}"
}
trap cleanup EXIT

printf '{}' > "${DOCKER_CONFIG_DIR}/config.json"

run_in_python_container() {
  local image="$1"
  local command="$2"

  docker run --rm \
    -e DOCKER_CONFIG=/tmp/docker-anon \
    -v "${DOCKER_CONFIG_DIR}:/tmp/docker-anon:ro" \
    -v "${ROOT_DIR}:/work" \
    -w /work \
    "${image}" \
    sh -lc "${command}"
}

run_suite() {
  local name="$1"
  local image="$2"
  local command="$3"

  printf '\n'
  printf '%s\n' '================================================================'
  printf '== %s\n' "${name}"
  printf '== Image: %s\n' "${image}"
  printf '%s\n' '================================================================'

  run_in_python_container "${image}" "${command}"
}

run_suite "App lint, format, and tests" \
  python:3.12-slim \
  "python -m pip install --quiet ruff black pytest && ruff check ./app && black --check ./app && (pytest -v ./app --tb=short || true)"

run_suite "API unit tests" \
  python:3.12-slim \
  "python -m pip install --quiet pytest minio && pytest -v riskstream/tests/unit/test_api_ranking.py"

run_suite "ThreatFox unit tests" \
  python:3.11-slim \
  "python -m pip install --quiet pytest && pytest -v riskstream/tests/unit/test_threatfox_ingestion.py"

run_suite "CISA KEV unit tests" \
  python:3.11-slim \
  "python -m pip install --quiet pytest && pytest -v riskstream/tests/unit/test_cisa_kev_ingestion.py"

run_suite "URLhaus unit tests" \
  python:3.11-slim \
  "python -m pip install --quiet pytest && pytest -v riskstream/tests/unit/test_urlhaus_ingestion.py"

run_suite "Threat-signal normalizer unit tests" \
  python:3.11-slim \
  "python -m pip install --quiet pytest minio jsonschema && pytest -v riskstream/tests/unit/test_threat_signal_normalizer.py"

echo
echo "Unit test preflight completed."
