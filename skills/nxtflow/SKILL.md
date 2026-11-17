---
name: nxtflow
description: Query multi-site NetFlow v5/v9, IPFIX, and sFlow traffic telemetry from Loki using the nxtflow CLI or nxtflow-mcp server. Use whenever asked about network bandwidth, top talkers, destination services, active ports, site comparisons, host sessions, or collector health.
license: MIT
compatibility: Requires nxtflow Python CLI (Python 3.11+) or nxtflow-mcp connected to a Loki endpoint (NXTFLOW_LOKI_URL).
metadata:
  author: nertwork
  version: "0.1.0"
---

# nxtflow Skill

## CLI (`nxtflow`)
- Health & summary: `nxtflow status [--range 5m]` | `nxtflow summary [--site <site>] [--dir up|down|lan] [--range 1h] [--json]`
- Top talkers: `nxtflow top-sources [N]` | `nxtflow top-destinations [N]` | `nxtflow top-connections [N]` | `nxtflow top-ports [N]`
- Host & sessions: `nxtflow host <name>` | `nxtflow sessions <name> [N]` | `nxtflow search <term> [N]` | `nxtflow directory`
- Config: `nxtflow config` (`NXTFLOW_LOKI_URL`, `NXTFLOW_JOB`, `NXTFLOW_TLS_VERIFY`, `NXTFLOW_LOKI_TOKEN`, `~/.config/nxtflow/config.yaml`)

## MCP Tools (`nxtflow-mcp`, read-only)
`nxtflow_status`, `nxtflow_summary`, `nxtflow_top_sources`, `nxtflow_top_destinations`, `nxtflow_top_connections`, `nxtflow_top_ports`, `nxtflow_host_profile`, `nxtflow_sessions`, `nxtflow_search`, `nxtflow_directory`

## Guardrails
- `top-ports` restricts `dst_port =~ '.{1,4}'` (<10000) to avoid Loki 5000-series limits; use `sessions` or `search` for ephemeral ports >=10000.
- `range_str` must match `^[1-9]\d*[smhd]$` (max `30d`).
