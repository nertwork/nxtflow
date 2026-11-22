#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
elif [ -f .env.example ]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env.example
  set +a
fi

LOKI_PORT="${NXTFLOW_LOKI_PORT:-3100}"
GRAFANA_PORT="${NXTFLOW_GRAFANA_PORT:-3000}"
PROM_PORT="${NXTFLOW_PROMETHEUS_PORT:-9091}"
ENRICHER_HTTP_PORT="${NXTFLOW_ENRICHER_HTTP_PORT:-8081}"
MCP_PORT="${NXTFLOW_MCP_PORT:-8000}"
NETFLOW_PORT="${NXTFLOW_NETFLOW_PORT:-2055}"
SITE="${NXTFLOW_SITE:-default}"
JOB="${NXTFLOW_JOB:-nxtflow}"
GRAFANA_USER="${NXTFLOW_GRAFANA_ADMIN_USER:-admin}"
GRAFANA_PASS="${NXTFLOW_GRAFANA_ADMIN_PASSWORD:-nxtflow}"

wait_http() {
  local name="$1"
  local url="$2"
  local auth="${3:-}"
  local tries=30
  for ((i=1; i<=tries; i++)); do
    if [ -n "$auth" ]; then
      if curl -fsS --max-time 3 -u "$auth" "$url" >/dev/null 2>&1; then
        echo "[OK] $name ($url)"
        return 0
      fi
    else
      if curl -fsS --max-time 3 "$url" >/dev/null 2>&1; then
        echo "[OK] $name ($url)"
        return 0
      fi
    fi
    sleep 2
  done
  echo "[FAIL] Timed out waiting for $name ($url)" >&2
  return 1
}

echo "1. Checking service health endpoints..."
wait_http "Loki" "http://127.0.0.1:${LOKI_PORT}/loki/api/v1/label/site/values"
wait_http "Prometheus" "http://127.0.0.1:${PROM_PORT}/-/ready"
wait_http "Enricher" "http://127.0.0.1:${ENRICHER_HTTP_PORT}/readyz"
wait_http "nxtflow-mcp" "http://127.0.0.1:${MCP_PORT}/healthz"
wait_http "Grafana" "http://127.0.0.1:${GRAFANA_PORT}/api/health"

echo "2. Verifying Grafana datasources and dashboard provisioning..."
wait_http "Grafana Datasource (Loki)" "http://127.0.0.1:${GRAFANA_PORT}/api/datasources/uid/loki" "${GRAFANA_USER}:${GRAFANA_PASS}"
wait_http "Grafana Datasource (Prometheus)" "http://127.0.0.1:${GRAFANA_PORT}/api/datasources/uid/prometheus" "${GRAFANA_USER}:${GRAFANA_PASS}"
wait_http "Grafana Dashboard (nxtflow-overview)" "http://127.0.0.1:${GRAFANA_PORT}/api/dashboards/uid/nxtflow-overview" "${GRAFANA_USER}:${GRAFANA_PASS}"

echo "3. Sending synthetic NetFlow v9 burst to 127.0.0.1:${NETFLOW_PORT}..."
python3 scripts/demo-flows.py --host 127.0.0.1 --port "${NETFLOW_PORT}" --protocol netflow9 --batch-size 15 --once

echo "4. Waiting for enriched flows in Loki ({job=\"${JOB}\", site=\"${SITE}\"})..."
FOUND=false
for ((i=1; i<=15; i++)); do
  RESP="$(curl -fsS --max-time 5 -G "http://127.0.0.1:${LOKI_PORT}/loki/api/v1/query" \
    --data-urlencode "query=count_over_time({job=\"${JOB}\", site=\"${SITE}\"}[5m])" 2>/dev/null || true)"
  if python3 -c '
import json, sys
data = json.loads(sys.argv[1])
res = data.get("data", {}).get("result", [])
total = sum(float(item["value"][1]) for item in res if item.get("value"))
sys.exit(0 if total > 0 else 1)
' "$RESP" 2>/dev/null; then
    FOUND=true
    break
  fi
  sleep 2
done

if [ "$FOUND" != true ]; then
  echo "[FAIL] No enriched flows appeared in Loki within 30s" >&2
  exit 1
fi
echo "[OK] Enriched flows confirmed in Loki"

if command -v nxtflow >/dev/null 2>&1; then
  echo "5. Running nxtflow CLI summary..."
  NXTFLOW_LOKI_URL="http://127.0.0.1:${LOKI_PORT}" NXTFLOW_JOB="${JOB}" nxtflow status --range 5m
  NXTFLOW_LOKI_URL="http://127.0.0.1:${LOKI_PORT}" NXTFLOW_JOB="${JOB}" nxtflow summary --range 5m
elif [ -x .venv/bin/nxtflow ]; then
  echo "5. Running .venv/bin/nxtflow CLI summary..."
  NXTFLOW_LOKI_URL="http://127.0.0.1:${LOKI_PORT}" NXTFLOW_JOB="${JOB}" .venv/bin/nxtflow status --range 5m
  NXTFLOW_LOKI_URL="http://127.0.0.1:${LOKI_PORT}" NXTFLOW_JOB="${JOB}" .venv/bin/nxtflow summary --range 5m
fi

echo ""
echo "Verification PASSED! Open Grafana: http://localhost:${GRAFANA_PORT}/d/nxtflow-overview"
