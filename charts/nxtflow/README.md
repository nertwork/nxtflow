# `nxtflow` Helm Chart

<p align="center">
  <img src="https://raw.githubusercontent.com/nertwork/nxtflow/main/assets/nxtflow-icon.png" width="96" alt="nxtflow icon" />
</p>

Multi-protocol **NetFlow v5/v9, IPFIX, and sFlow v5** Kubernetes observability platform pairing upstream [`netsampler/goflow2`](https://github.com/netsampler/goflow2) with `nxtflow-enricher`, bounded-cardinality Grafana Loki streams (`{job, site, dir}`), Prometheus metrics & alerts, an 18-panel Grafana Sankey dashboard, and the read-only `nxtflow-mcp` server.

---

## Deployment Modes

| Mode | Flags | Components Deployed |
|---|---|---|
| **Standalone** | `tags.standalone=true` | `goflow2`, `nxtflow-enricher`, bundled `loki` (SingleBinary), bundled `prometheus`, bundled `grafana` + dashboard, `nxtflow-mcp` |
| **Integrated** | `tags.standalone=false`, `externalLoki.url=...` | `goflow2`, `nxtflow-enricher`, `nxtflow-mcp`, `ServiceMonitor`, `PrometheusRule`, Grafana dashboard `ConfigMap` |
| **Collector-Only** | `tags.standalone=false`, `externalLoki.url=...`, `mcp.enabled=false` | Lightweight remote edge collector (`goflow2` + `nxtflow-enricher`) shipping into a central Loki |

---

## Installation

### Standalone (All-in-One)

```bash
helm install nxtflow oci://ghcr.io/nertwork/charts/nxtflow \
  --version 0.1.0 \
  --namespace nxtflow --create-namespace \
  -f https://raw.githubusercontent.com/nertwork/nxtflow/main/examples/values-standalone.yaml
```

### Integrated (Existing Loki, Prometheus & Grafana)

```bash
helm install nxtflow oci://ghcr.io/nertwork/charts/nxtflow \
  --version 0.1.0 \
  --namespace monitoring \
  -f https://raw.githubusercontent.com/nertwork/nxtflow/main/examples/values-integrated.yaml \
  --set externalLoki.url="https://loki.example.com"
```

### Collector-Only (Remote Edge Site)

```bash
helm install nxtflow-edge oci://ghcr.io/nertwork/charts/nxtflow \
  --version 0.1.0 \
  --namespace nxtflow --create-namespace \
  -f https://raw.githubusercontent.com/nertwork/nxtflow/main/examples/values-collector-only.yaml \
  --set collector.site="edge-west" \
  --set externalLoki.url="https://loki.example.com"
```

> Keep `collector.service.externalTrafficPolicy=Local` on `LoadBalancer` / `NodePort` services so Kubernetes preserves exporter source IPs without node SNAT.

---

## Key Configuration Values

| Parameter | Default | Description |
|---|---|---|
| `tags.standalone` | `true` | Deploy bundled Loki, Prometheus, and Grafana subcharts (`false` for Integrated / Collector-Only) |
| `collector.site` | `"default"` | Site label attached to every Loki stream `{job, site, dir}` |
| `collector.job` | `"nxtflow"` | Loki `job` label queried by Grafana, `nxtflow` CLI, and `nxtflow-mcp` |
| `collector.service.type` | `LoadBalancer` | Kubernetes Service type exposing UDP `:2055` (NetFlow/IPFIX) and `:6343` (sFlow) |
| `collector.service.externalTrafficPolicy` | `Local` | Preserve router source IP on LoadBalancer/NodePort ingress |
| `enricher.image.repository` | `ghcr.io/nertwork/nxtflow-enricher` | Enricher container image (`tag` defaults to `v<appVersion>`) |
| `enricher.shipper.mode` | `"direct"` | Loki shipping mode: `"direct"` (gzip push), `"alloy"` (JSONL + Grafana Alloy sidecar), or `"file"` |
| `enricher.classification.localCidrs` | RFC1918 + `fc00::/7` | CIDRs classified as internal/LAN networks |
| `enricher.classification.wanIps` | `[]` | Router WAN IPs so NATed egress/ingress resolves as `up` / `down` |
| `enricher.classification.excludedHosts` | `["multicast", "link-local"]` | Hosts excluded from noisy top-N tables |
| `enricher.netbox.enabled` | `false` | Optional NetBox IPAM reverse resolution sync |
| `externalLoki.url` | `""` | Base URL for an external Loki instance when `tags.standalone=false` |
| `mcp.enabled` | `true` | Deploy `nxtflow-mcp` (`streamable-http` on `:8000/mcp`, `/healthz`) |
| `monitoring.serviceMonitor.enabled` | `false` | Create Prometheus Operator `ServiceMonitor` |
| `monitoring.prometheusRule.enabled` | `false` | Create Prometheus Operator `PrometheusRule` alerts |
| `grafana.dashboardConfigMap.enabled` | `false` | Create Grafana sidecar `ConfigMap` in Integrated mode |
| `grafana.sankey.engine` | `"echarts"` | Sankey panel renderer: `"echarts"` (`volkovlabs-echarts-panel`) or `"netsage"` |

See [`values.yaml`](values.yaml) and [`values.schema.json`](values.schema.json) for all supported options.

---

## Upgrade & Uninstall

```bash
helm upgrade nxtflow oci://ghcr.io/nertwork/charts/nxtflow --version 0.1.0 -n nxtflow -f values.yaml
helm uninstall nxtflow -n nxtflow
```
