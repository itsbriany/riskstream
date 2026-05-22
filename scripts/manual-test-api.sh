#!/usr/bin/env bash

set -euo pipefail

API_BASE_URL="${API_BASE_URL:-http://localhost:3001}"
API_BASE_URL="${API_BASE_URL%/}"

require_command() {
  local command_name="$1"
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "Missing required command: ${command_name}" >&2
    exit 1
  fi
}

pretty_json() {
  python3 -m json.tool
}

get_json() {
  local path="$1"
  curl -fsS "${API_BASE_URL}${path}" | pretty_json
}

post_json() {
  local path="$1"
  local payload="$2"
  curl -fsS \
    -H "Content-Type: application/json" \
    -d "${payload}" \
    "${API_BASE_URL}${path}" | pretty_json
}

section() {
  local name="$1"
  printf '\n'
  printf '%s\n' '================================================================'
  printf '== %s\n' "${name}"
  printf '%s\n' '================================================================'
}

require_command curl
require_command python3

echo "Testing RiskStream API at ${API_BASE_URL}"

section "GET /healthz"
get_json "/healthz"

section "GET /"
get_json "/"

section "GET /v1/threats/ranking-options"
get_json "/v1/threats/ranking-options"

section "POST /v1/threats:rank"

# Yields results but currently, the platform is really slow to rank threats.
post_json "/v1/threats:rank" '{
  "time_window": {
    "since": "2026-01-24T00:00:00Z",
    "until": "2026-04-25T00:00:00Z"
  },
  "tenant_id": "manual-smoke-test",
  "filters": {
    "artifact_types": ["url"],
    "tags_any": ["Mozi"],
    "min_score": 70
  },
  "limit": 10
}'

# Currently yields no results
post_json "/v1/threats:rank" '{
  "tenant_id": "manual-smoke-test",
  "context": {
    "environment_scope": "production",
    "priorities": ["malware_delivery", "active_exploitation"]
  },
  "filters": {
    "signal_kinds": ["indicator", "vulnerability"],
    "artifact_types": ["url", "domain", "cve"],
    "actions": ["observed", "updated"],
    "min_score": 50
  },
  "limit": 10
}'

echo
echo "Manual API smoke test completed."
