# Security Policy

## Supported Versions

| Version | Supported |
| :--- | :--- |
| `0.1.x` (`main`) | :white_check_mark: |

## Security Architecture

- **Non-Root Containers:** `nxtflow-enricher` runs as UID/GID `100:65533` (`flow:nogroup`, matching upstream `netsampler/goflow2:v2.2.7`), and `nxtflow-mcp` runs as UID/GID `65532:65532` with `allowPrivilegeEscalation: false`.
- **LogQL Injection Prevention:** All user-supplied `site`, `dir`, `search`, and `host` inputs in `nxtflow` CLI and `nxtflow-mcp` pass through `validate_range()`, `validate_dir()`, `escape_logql_label()`, and `sanitize_logql_regex()`.
- **Bounded Memory & Query Cardinality:** Enricher queues use bounded ring buffers (`ringBufferMaxFlows`), rDNS uses a bounded LRU+TTL cache (`maxEntries`), Loki streams use strictly bounded labels (`{job, site, dir}`), and ephemeral ports (`>=10000`) are filtered from `top-ports` aggregations to prevent 5000-series exhaustion.
- **Secret Isolation:** Loki and NetBox credentials are injected via Kubernetes `Secret` environment variables (`NXTFLOW_LOKI_*`, `NXTFLOW_NETBOX_TOKEN`), never rendered into ConfigMaps, and redacted by `nxtflow config`.
- **Zero-PII Gate:** CI enforces `scripts/zero_pii_audit.py` across all source, chart, SVG, workflow, and documentation files.

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for sensitive security vulnerabilities.

Instead, report vulnerabilities via:
1. **GitHub Private Vulnerability Reporting:** [Open a security advisory on `nertwork/nxtflow`](https://github.com/nertwork/nxtflow/security/advisories/new)
2. **Email:** `james@nertwork.com`

We will acknowledge receipt within 48 hours and coordinate a fix and disclosure timeline.
