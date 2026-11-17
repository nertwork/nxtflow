"""nxtflow MCP Server — 10 read-only FastMCP tools over stdio or streamable-http."""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Sequence

from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse

from nxtflow.config import NxtflowConfig, clamp_limit, load_config, validate_dir, validate_range
from nxtflow.loki import LokiClient, LokiError


def create_server(
    host: str = "127.0.0.1",
    port: int = 8000,
    stateless_http: bool = False,
    config: NxtflowConfig | None = None,
) -> FastMCP:
    """Create and configure the nxtflow FastMCP server with host/port bound at init time."""
    mcp = FastMCP("nxtflow", host=host, port=port, stateless_http=stateless_http)
    cfg = config or load_config()

    def _client() -> LokiClient:
        return LokiClient(cfg)

    @mcp.custom_route("/healthz", methods=["GET"])
    async def healthz(_request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok", "service": "nxtflow-mcp"})

    @mcp.tool()
    def nxtflow_status(range_str: str = "5m") -> str:
        """Check Loki collector stream registration and recent ingested bytes per site and direction."""
        try:
            valid_range = validate_range(range_str)
            return json.dumps(_client().get_status_data(range_str=valid_range), indent=2)
        except (ValueError, TypeError, LokiError) as exc:
            return json.dumps({"error": str(exc)}, indent=2)

    @mcp.tool()
    def nxtflow_summary(
        range_str: str = "5m",
        dir_filter: str | None = None,
        site: str | None = None,
    ) -> str:
        """Return bandwidth summary (download/upload/lan/total, avg/p95 bps, share %, and per-site totals)."""
        try:
            valid_range = validate_range(range_str)
            valid_dir = validate_dir(dir_filter)
            return json.dumps(
                _client().get_summary_data(range_str=valid_range, dir_val=valid_dir, site_val=site),
                indent=2,
            )
        except (ValueError, TypeError, LokiError) as exc:
            return json.dumps({"error": str(exc)}, indent=2)

    @mcp.tool()
    def nxtflow_top_sources(
        limit: int = 10,
        range_str: str = "5m",
        dir_filter: str | None = None,
        site: str | None = None,
    ) -> str:
        """List top source hosts by traffic volume (bits/bytes/share %) sorted descending."""
        try:
            valid_range = validate_range(range_str)
            valid_dir = validate_dir(dir_filter)
            bounded_limit = clamp_limit(limit, 1, 100)
            return json.dumps(
                _client().get_top_data(
                    "src_host",
                    n=bounded_limit,
                    range_str=valid_range,
                    dir_val=valid_dir,
                    site_val=site,
                ),
                indent=2,
            )
        except (ValueError, TypeError, LokiError) as exc:
            return json.dumps({"error": str(exc)}, indent=2)

    @mcp.tool()
    def nxtflow_top_destinations(
        limit: int = 10,
        range_str: str = "5m",
        dir_filter: str | None = None,
        site: str | None = None,
    ) -> str:
        """List top destination hosts/services by traffic volume sorted descending."""
        try:
            valid_range = validate_range(range_str)
            valid_dir = validate_dir(dir_filter)
            bounded_limit = clamp_limit(limit, 1, 100)
            return json.dumps(
                _client().get_top_data(
                    "dst_host",
                    n=bounded_limit,
                    range_str=valid_range,
                    dir_val=valid_dir,
                    site_val=site,
                ),
                indent=2,
            )
        except (ValueError, TypeError, LokiError) as exc:
            return json.dumps({"error": str(exc)}, indent=2)

    @mcp.tool()
    def nxtflow_top_connections(
        limit: int = 15,
        range_str: str = "5m",
        dir_filter: str | None = None,
        site: str | None = None,
    ) -> str:
        """List top source -> destination pairs by traffic volume sorted descending."""
        try:
            valid_range = validate_range(range_str)
            valid_dir = validate_dir(dir_filter)
            bounded_limit = clamp_limit(limit, 1, 100)
            return json.dumps(
                _client().get_top_connections_data(
                    n=bounded_limit,
                    range_str=valid_range,
                    dir_val=valid_dir,
                    site_val=site,
                ),
                indent=2,
            )
        except (ValueError, TypeError, LokiError) as exc:
            return json.dumps({"error": str(exc)}, indent=2)

    @mcp.tool()
    def nxtflow_top_ports(
        limit: int = 10,
        range_str: str = "5m",
        dir_filter: str | None = None,
        site: str | None = None,
    ) -> str:
        """List top destination service ports (<10000) by traffic volume sorted descending."""
        try:
            valid_range = validate_range(range_str)
            valid_dir = validate_dir(dir_filter)
            bounded_limit = clamp_limit(limit, 1, 100)
            return json.dumps(
                _client().get_top_ports_data(
                    n=bounded_limit,
                    range_str=valid_range,
                    dir_val=valid_dir,
                    site_val=site,
                ),
                indent=2,
            )
        except (ValueError, TypeError, LokiError) as exc:
            return json.dumps({"error": str(exc)}, indent=2)

    @mcp.tool()
    def nxtflow_host_profile(
        host: str,
        range_str: str = "15m",
        site: str | None = None,
    ) -> str:
        """Inspect flows, sites, direction breakdown, top peers, and top ports for a specific host."""
        try:
            valid_range = validate_range(range_str)
            data = _client().get_host_data(name=host, range_str=valid_range, site_val=site)
            return json.dumps(data or {"host": host, "flows": 0}, indent=2)
        except (ValueError, TypeError, LokiError) as exc:
            return json.dumps({"error": str(exc)}, indent=2)

    @mcp.tool()
    def nxtflow_sessions(
        host: str,
        range_str: str = "5m",
        site: str | None = None,
        limit: int = 25,
    ) -> str:
        """List active 5-tuple sessions (site, src, dst, port, proto, flows, bytes) for a host."""
        try:
            valid_range = validate_range(range_str)
            bounded_limit = clamp_limit(limit, 1, 100)
            return json.dumps(
                _client().get_sessions_data(name=host, range_str=valid_range, site_val=site, limit=bounded_limit),
                indent=2,
            )
        except (ValueError, TypeError, LokiError) as exc:
            return json.dumps({"error": str(exc)}, indent=2)

    @mcp.tool()
    def nxtflow_search(
        term: str,
        range_str: str = "15m",
        site: str | None = None,
        limit: int = 20,
    ) -> str:
        """Search recent enriched flow logs matching an IP, hostname, port, or protocol."""
        try:
            valid_range = validate_range(range_str)
            bounded_limit = clamp_limit(limit, 1, 100)
            total, rows = _client().get_search_data(
                term=term,
                range_str=valid_range,
                n=bounded_limit,
                site_val=site,
            )
            return json.dumps({"term": term, "total_sampled": total, "flows": rows}, indent=2)
        except (ValueError, TypeError, LokiError) as exc:
            return json.dumps({"error": str(exc)}, indent=2)

    @mcp.tool()
    def nxtflow_directory(
        range_str: str = "5m",
        site: str | None = None,
    ) -> str:
        """Return IP -> resolved hostname directory discovered from recent flows."""
        try:
            valid_range = validate_range(range_str)
            return json.dumps(_client().get_directory_data(range_str=valid_range, site_val=site), indent=2)
        except (ValueError, TypeError, LokiError) as exc:
            return json.dumps({"error": str(exc)}, indent=2)

    return mcp


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    env_transport = os.environ.get("NXTFLOW_MCP_TRANSPORT", "stdio").strip() or "stdio"
    env_host = os.environ.get("NXTFLOW_MCP_HOST", "127.0.0.1").strip() or "127.0.0.1"
    env_port = int(os.environ.get("NXTFLOW_MCP_PORT", "8000"))
    env_stateless = os.environ.get("NXTFLOW_MCP_STATELESS_HTTP", "").strip().lower() in ("1", "true", "yes")

    parser = argparse.ArgumentParser(prog="nxtflow-mcp", description="nxtflow read-only FastMCP server")
    parser.add_argument(
        "--transport",
        choices=("stdio", "streamable-http", "sse"),
        default=env_transport,
        help="MCP transport mode (default: stdio)",
    )
    parser.add_argument("--host", default=env_host, help="HTTP bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=env_port, help="HTTP bind port (default: 8000)")
    parser.add_argument(
        "--stateless-http",
        action="store_true",
        default=env_stateless,
        help="Enable stateless streamable-http mode",
    )
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Sequence[str] | None = None) -> None:
    args = parse_args(argv)
    mcp = create_server(host=args.host, port=args.port, stateless_http=args.stateless_http)
    mcp.run(transport=args.transport)


if __name__ == "__main__":
    main()
