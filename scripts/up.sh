#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DEMO_MODE=false
BUILD_FLAG=""

for arg in "$@"; do
  case "$arg" in
    --demo)
      DEMO_MODE=true
      ;;
    --build)
      BUILD_FLAG="--build"
      ;;
    -h|--help)
      echo "Usage: $0 [--demo] [--build]"
      echo "  --demo   Also start the synthetic NetFlow demo-generator profile"
      echo "  --build  Force rebuilding local enricher and mcp images"
      exit 0
      ;;
    *)
      echo "Unknown option: $arg" >&2
      exit 2
      ;;
  esac
done

if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from .env.example"
fi

set -a
# shellcheck disable=SC1091
. ./.env
set +a

COMPOSE_ARGS=()
if [ "$DEMO_MODE" = true ]; then
  COMPOSE_ARGS+=(--profile demo)
fi

docker compose "${COMPOSE_ARGS[@]}" up -d $BUILD_FLAG

GRAFANA_PORT="${NXTFLOW_GRAFANA_PORT:-3000}"
LOKI_PORT="${NXTFLOW_LOKI_PORT:-3100}"
PROM_PORT="${NXTFLOW_PROMETHEUS_PORT:-9091}"
MCP_PORT="${NXTFLOW_MCP_PORT:-8000}"
NF_PORT="${NXTFLOW_NETFLOW_PORT:-2055}"
SF_PORT="${NXTFLOW_SFLOW_PORT:-6343}"

echo ""
echo "nxtflow stack is starting:"
echo "  Grafana UI:     http://localhost:${GRAFANA_PORT}/d/nxtflow-overview  (user: ${NXTFLOW_GRAFANA_ADMIN_USER:-admin})"
echo "  Loki API:       http://localhost:${LOKI_PORT}"
echo "  Prometheus UI:  http://localhost:${PROM_PORT}"
echo "  MCP Endpoint:   http://localhost:${MCP_PORT}/mcp"
echo "  NetFlow/IPFIX:  UDP :${NF_PORT}"
echo "  sFlow v5:       UDP :${SF_PORT}"
echo ""
echo "Verify end-to-end with: ./scripts/verify-stack.sh"
