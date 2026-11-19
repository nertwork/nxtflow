# Changelog

All notable changes to `nxtflow` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-17

### Added
- **Collector & Enricher (`nxtflow-enricher`)**:
  - Pairs upstream `netsampler/goflow2:v2.2.7` (`-transport=file`, NetFlow v5/v9, IPFIX, sFlow v5) with a Python enricher supporting concurrent file tailing, stdin, and HTTP `/ingest` (`POST /ingest`, `POST /ingest/goflow2`, `/healthz`, `/readyz`).
  - Scales bytes and packets using flow `sampling_rate` (or configurable `defaultSamplingRate`).
  - Classifies traffic direction (`up`, `down`, `lan`) across IPv4 and IPv6 using configurable `localCidrs`, `wanIps`, and `internalCidrs`.
  - Resolves hosts through a 7-tier pipeline (`staticHosts`, `internalCidrs`, `wanIps`, NetBox IPAM sync, public well-known IPs/CIDRs, and bounded LRU+TTL reverse DNS).
  - Ships enriched 11-field JSON logs in gzip batches to Loki using bounded `{job, site, dir}` stream labels, or writes JSONL for Grafana Alloy sidecars.
  - Exposes Prometheus metrics at `:9090/metrics` (`nxtflow_flows_received_total`, `nxtflow_bytes_total`, `nxtflow_loki_push_requests_total`, `nxtflow_loki_push_errors_total`, `nxtflow_dropped_flows_total`).
- **CLI & AI Integration (`nxtflow`, `nxtflow-mcp`, `skills/nxtflow/SKILL.md`)**:
  - 11-command `nxtflow` CLI (`status`, `summary`, `top-sources`, `top-destinations`, `top-connections`, `top-ports`, `host`, `sessions`, `search`, `directory`, `config`) with 5000-series-safe LogQL queries.
  - `nxtflow-mcp` FastMCP server (`stdio`, `streamable-http`, `sse`) exposing 10 read-only tools and `/healthz`.
- **Dual-Mode Helm Chart (`charts/nxtflow`) & Grafana Dashboard**:
  - Supports `standalone` (bundled Loki 21.3.1, Prometheus 29.47.2, Grafana 14.5.0), `integrated` (external Loki + `ServiceMonitor` + `PrometheusRule` + dashboard ConfigMap), and `collector-only` edge deployments.
  - Multi-site 18-panel Grafana dashboard (`nxtflow-overview.json`) with dynamic `site` discovery, bipartite ECharts Sankey (plus optional `netsage-sankey-panel`), and configurable excluded hosts.
- **CI/CD, Branding & Security Gate**:
  - Vector and PNG branding assets (`assets/nxtflow-icon.*`, `assets/nxtflow-logo.*`).
  - Automated security, credential, and syntax audit (`scripts/security_audit.py`), GitHub Actions CI/Release/Pages workflows, and Helm/Python test suites.
