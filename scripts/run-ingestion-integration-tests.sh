#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${1:-all}"

usage() {
  cat <<'EOF'
Usage: ./scripts/run-ingestion-integration-tests.sh [threatfox|cisa-kev|all]

Run in-cluster ingestion integration tests for one service or both services.
Defaults to "all".
EOF
}

run_threatfox() {
  echo "Running ThreatFox integration test..."
  "${ROOT_DIR}/scripts/run-threatfox-integration-test.sh"
}

run_cisa_kev() {
  echo "Running CISA KEV integration test..."
  "${ROOT_DIR}/scripts/run-cisa-kev-integration-test.sh"
}

case "${TARGET}" in
  threatfox)
    run_threatfox
    ;;
  cisa-kev)
    run_cisa_kev
    ;;
  all)
    run_threatfox
    run_cisa_kev
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage >&2
    exit 1
    ;;
esac
