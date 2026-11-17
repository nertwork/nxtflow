# CLI, MCP Server & AI Skill Integration

`nxtflow` provides a consistent query layer for terminal engineers and AI assistants (Gemini CLI, Claude Code, OpenCode, Codex, and Hermes).

## `nxtflow` CLI

### Configuration Precedence
1. Built-in defaults (`http://localhost:3100`, `job="nxtflow"`)
2. YAML file (`~/.config/nxtflow/config.yaml` or `--config` / `NXTFLOW_CONFIG_FILE`)
3. Environment variables (`NXTFLOW_LOKI_URL`, `NXTFLOW_JOB`, `NXTFLOW_TLS_VERIFY`, `NXTFLOW_LOKI_TOKEN`, `NXTFLOW_LOKI_USER`, `NXTFLOW_LOKI_PASSWORD`, `NXTFLOW_LOKI_TENANT_ID`, `NXTFLOW_EXCLUDED_HOSTS`)

### Subcommands & Aliases

| Command | Aliases | Description |
|---|---|---|
| `nxtflow status` | `health` | Collector stream registration and ingested bytes per site/direction |
| `nxtflow summary` | `traffic` | Bandwidth summary (`download`/`upload`/`lan`/`total`, avg & P95 bps, share %) |
| `nxtflow top-sources [N]` | `top-src`, `top-talkers` | Top source hosts by traffic volume |
| `nxtflow top-destinations [N]` | `top-dst` | Top destination hosts or external services |
| `nxtflow top-connections [N]` | `top-conn`, `flows` | Top `src_host -> dst_host` pairs |
| `nxtflow top-ports [N]` | — | Top destination service ports (`< 10000` for 5000-series safety) |
| `nxtflow host <target>` | — | Site breakdown, direction totals, top peers, and top ports for a host |
| `nxtflow sessions <target> [N]` | — | Active 5-tuple sessions for a host |
| `nxtflow search <term> [N]` | — | Search recent flows matching an IP, hostname, port, or protocol |
| `nxtflow directory` | — | Discovered IP-to-hostname directory |
| `nxtflow config` | — | Display active configuration with secrets redacted |

Common flags work before or after any subcommand: `--range 1h`, `--site <site>`, `--dir up|down|lan`, `-n <limit>`, `--json`, `--config <path>`.

---

## `nxtflow-mcp` (FastMCP Server)

`nxtflow-mcp` exposes 10 read-only tools over `stdio` (local workstations) or `streamable-http` (in-cluster Kubernetes Service with `GET /healthz`).

### Exposed Tools
- `nxtflow_status`
- `nxtflow_summary`
- `nxtflow_top_sources`
- `nxtflow_top_destinations`
- `nxtflow_top_connections`
- `nxtflow_top_ports`
- `nxtflow_host_profile`
- `nxtflow_sessions`
- `nxtflow_search`
- `nxtflow_directory`

### Local `stdio` Client Config (`mcp/nxtflow.mcp.json`)

```json
{
  "mcpServers": {
    "nxtflow": {
      "command": "nxtflow-mcp",
      "args": ["--transport", "stdio"],
      "env": {
        "NXTFLOW_LOKI_URL": "http://localhost:3100",
        "NXTFLOW_JOB": "nxtflow",
        "NXTFLOW_TLS_VERIFY": "true"
      }
    }
  }
}
```

### Kubernetes `streamable-http` Endpoint

When deployed with `mcp.enabled=true`, connect HTTP-capable MCP clients to:

```text
http://<release>-nxtflow-mcp.<namespace>.svc.cluster.local:8000/mcp
```

---

## Portable Agent Skill (`skills/nxtflow/SKILL.md`)

Copy `skills/nxtflow/` into your agent harness skill directory (for example `~/.gemini/config/skills/nxtflow/`) to give agents a compact `<150`-token command and MCP workflow.
