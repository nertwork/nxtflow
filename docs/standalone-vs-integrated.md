# Standalone vs. Integrated Deployment Modes

The `charts/nxtflow` Helm chart supports three deployment topologies controlled by `tags.standalone` and `externalLoki.url`.

## Mode Comparison

| Feature | Standalone (`tags.standalone=true`) | Integrated (`tags.standalone=false`) | Collector-Only (`tags.standalone=false`) |
|---|---|---|---|
| `goflow2` + `nxtflow-enricher` | Deployed | Deployed | Deployed |
| Bundled Loki (SingleBinary) | Deployed | Disabled | Disabled |
| Bundled Prometheus | Deployed (server only) | Disabled | Disabled |
| Bundled Grafana + Dashboard | Deployed (`volkovlabs-echarts-panel`) | Disabled | Disabled |
| `ServiceMonitor` & `PrometheusRule` | Optional | Enabled (`monitoring.*.enabled=true`) | Disabled |
| Grafana Dashboard ConfigMap | Auto-provisioned | Enabled (`grafana.dashboardConfigMap.enabled=true`) | Disabled |
| `nxtflow-mcp` Server | Enabled | Enabled | Disabled |
| Example Values File | `examples/values-standalone.yaml` | `examples/values-integrated.yaml` | `examples/values-collector-only.yaml` |

## 0. Docker Compose (Single-Host / Homelab)

For single-host Docker setups without Kubernetes, use the root `docker-compose.yml` and `.env.example`:

```bash
cp .env.example .env
./scripts/up.sh --demo
./scripts/verify-stack.sh
```

All host ports (`NXTFLOW_GRAFANA_PORT`, `NXTFLOW_LOKI_PORT`, `NXTFLOW_NETFLOW_PORT`, `NXTFLOW_SFLOW_PORT`, `NXTFLOW_PROMETHEUS_PORT`, `NXTFLOW_MCP_PORT`), `NXTFLOW_SITE`, `NXTFLOW_LOKI_RETENTION`, and Grafana admin credentials are configured in `.env`. Grafana automatically provisions the `Loki` and `Prometheus` datasources alongside `nxtflow-overview.json`.

## 1. Standalone Mode

Standalone mode is ideal for personal labs, test clusters, or dedicated monitoring namespaces without an existing observability stack:

```bash
helm install nxtflow oci://ghcr.io/nertwork/charts/nxtflow \
  --namespace nxtflow --create-namespace \
  -f examples/values-standalone.yaml
```

Bundled subcharts (`grafana-community/loki`, `prometheus-community/prometheus`, `grafana-community/grafana`) are automatically wired via `configmap-grafana-datasources.yaml` using your release name (`http://<release>-loki:3100` and `http://<release>-prometheus-server:80`).

## 2. Integrated Mode

Use Integrated mode when your cluster already runs Loki, `kube-prometheus-stack`, and Grafana with sidecar discovery:

```bash
helm install nxtflow oci://ghcr.io/nertwork/charts/nxtflow \
  --namespace monitoring \
  -f examples/values-integrated.yaml \
  --set externalLoki.url="https://loki.example.com"
```

### Configuration Guardrails

The chart enforces fail-fast checks in `_helpers.tpl`:
- Setting both `tags.standalone=true` and `externalLoki.url` fails immediately to prevent split-brain routing.
- Setting `tags.standalone=false` without `externalLoki.url` fails unless `enricher.shipper.mode="file"`.
- Enabling `mcp.enabled=true` without either bundled Loki or `externalLoki.url` fails immediately.

## 3. Collector-Only Mode (Multi-Site Edge)

Deploy lightweight collectors at remote clusters or branch sites shipping into a central Loki instance:

```bash
helm install nxtflow-branch oci://ghcr.io/nertwork/charts/nxtflow \
  --namespace nxtflow \
  -f examples/values-collector-only.yaml \
  --set collector.site="branch-west" \
  --set externalLoki.url="https://loki.example.com"
```

Every site registers dynamically in the Grafana `Site` dropdown via `label_values({job="nxtflow"}, site)` and appears in `nxtflow status`.

## Sankey Visualization Engine (`echarts` vs. `netsage`)

- **`echarts` (default):** Uses the signed `volkovlabs-echarts-panel` plugin with bipartite node IDs (`s:<src>` -> `d:<dst>`) so bidirectional traffic never triggers ECharts DAG cycle errors.
- **`netsage` (opt-in):** Set `grafana.sankey.engine=netsage` to render the `netsage-sankey-panel` panel JSON (requires `netsage-sankey-panel` installed and allowed under `GF_PLUGINS_ALLOW_LOADING_UNSIGNED_PLUGINS` in your Grafana deployment).

## Alloy Sidecar Mode

Set `enricher.shipper.mode=alloy` if you prefer `nxtflow-enricher` to write JSONL files to `/var/log/nxtflow/flows.jsonl` and delegate Loki shipping to a `grafana/alloy` sidecar container.
