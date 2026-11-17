"""Unit tests for nxtflow-mcp FastMCP server (10 tools, bounds, args, /healthz)."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import MagicMock, patch

from starlette.testclient import TestClient

from nxtflow.config import NxtflowConfig
from nxtflow.loki import LokiError
from nxtflow.mcp_server import create_server, parse_args

EXPECTED_TOOLS = {
    "nxtflow_status",
    "nxtflow_summary",
    "nxtflow_top_sources",
    "nxtflow_top_destinations",
    "nxtflow_top_connections",
    "nxtflow_top_ports",
    "nxtflow_host_profile",
    "nxtflow_sessions",
    "nxtflow_search",
    "nxtflow_directory",
}


def test_mcp_registers_all_10_tools_and_healthz() -> None:
    mcp = create_server(host="0.0.0.0", port=8000, stateless_http=True, config=NxtflowConfig())
    tools = asyncio.run(mcp.list_tools())
    names = {t.name for t in tools}
    assert names == EXPECTED_TOOLS

    app = mcp.streamable_http_app()
    client = TestClient(app)
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_mcp_all_10_tools_and_input_bounds() -> None:
    mock_client = MagicMock()
    mock_client.get_status_data.return_value = {"active_streams": 3, "expected_streams": 3, "sites_registered": ["a"]}
    mock_client.get_summary_data.return_value = {"total": {"bytes": 1000}}
    mock_client.get_top_data.return_value = [{"name": "web-1", "bits": 8000, "bytes": 1000, "share_pct": 100.0}]
    mock_client.get_top_connections_data.return_value = [{"src": "web-1", "dst": "cloudflare", "bits": 8000, "bytes": 1000, "share_pct": 100.0}]
    mock_client.get_top_ports_data.return_value = [{"port": "443", "bits": 8000, "bytes": 1000, "share_pct": 100.0}]
    mock_client.get_host_data.return_value = {"host": "web-1", "flows": 5}
    mock_client.get_sessions_data.return_value = [{"site": "a", "src": "web-1", "dst": "cloudflare", "port": "443", "proto": "TCP", "flows": 5, "bytes": 1000}]
    mock_client.get_search_data.return_value = (1, [{"src_host": "web-1", "dst_host": "cloudflare"}])
    mock_client.get_directory_data.return_value = {"192.168.1.10": "web-1"}

    mcp = create_server(config=NxtflowConfig())

    async def call_tool(name: str, args: dict) -> dict | list:
        res = await mcp.call_tool(name, args)
        content_blocks = res[0] if isinstance(res, tuple) else res
        return json.loads(content_blocks[0].text)

    with patch("nxtflow.mcp_server.LokiClient", return_value=mock_client):
        assert asyncio.run(call_tool("nxtflow_status", {"range_str": "5m"}))["active_streams"] == 3
        assert asyncio.run(call_tool("nxtflow_summary", {"range_str": "5m"}))["total"]["bytes"] == 1000
        assert asyncio.run(call_tool("nxtflow_top_sources", {"limit": 0}))[0]["name"] == "web-1"
        assert mock_client.get_top_data.call_args.kwargs["n"] == 1

        assert asyncio.run(call_tool("nxtflow_top_destinations", {"limit": 9999}))[0]["name"] == "web-1"
        assert mock_client.get_top_data.call_args.kwargs["n"] == 100

        assert asyncio.run(call_tool("nxtflow_top_connections", {"limit": 500}))[0]["src"] == "web-1"
        assert mock_client.get_top_connections_data.call_args.kwargs["n"] == 100

        assert asyncio.run(call_tool("nxtflow_top_ports", {"limit": -5}))[0]["port"] == "443"
        assert mock_client.get_top_ports_data.call_args.kwargs["n"] == 1

        assert asyncio.run(call_tool("nxtflow_host_profile", {"host": "web-1"}))["flows"] == 5
        assert asyncio.run(call_tool("nxtflow_sessions", {"host": "web-1", "limit": 999}))[0]["port"] == "443"
        assert mock_client.get_sessions_data.call_args.kwargs["limit"] == 100

        search_res = asyncio.run(call_tool("nxtflow_search", {"term": "cloudflare", "limit": 200}))
        assert search_res["total_sampled"] == 1
        assert mock_client.get_search_data.call_args.kwargs["n"] == 100

        dir_res = asyncio.run(call_tool("nxtflow_directory", {"range_str": "15m"}))
        assert dir_res["192.168.1.10"] == "web-1"

        # Invalid range returns structured JSON error
        bad = asyncio.run(call_tool("nxtflow_summary", {"range_str": "99d"}))
        assert "error" in bad

        # LokiError returns structured JSON error
        mock_client.get_status_data.side_effect = LokiError("Loki down")
        down = asyncio.run(call_tool("nxtflow_status", {"range_str": "5m"}))
        assert "Loki down" in down["error"]


def test_mcp_parse_args() -> None:
    a1 = parse_args(["--transport", "stdio"])
    assert a1.transport == "stdio"
    a2 = parse_args(["--transport", "streamable-http", "--host", "0.0.0.0", "--port", "9001", "--stateless-http"])
    assert a2.transport == "streamable-http"
    assert a2.host == "0.0.0.0"
    assert a2.port == 9001
    assert a2.stateless_http is True


def test_mcp_30d_summary_and_non_dict_error() -> None:
    mock_client = MagicMock()
    mock_client.get_summary_data.return_value = {"window": {"range": "30d", "rate_window": "1h"}, "total": {"bytes": 0}}
    mock_client.get_status_data.side_effect = LokiError("Unexpected non-object JSON from Loki: list")

    mcp = create_server(config=NxtflowConfig())

    async def call_tool(name: str, args: dict) -> dict | list:
        res = await mcp.call_tool(name, args)
        content_blocks = res[0] if isinstance(res, tuple) else res
        return json.loads(content_blocks[0].text)

    with patch("nxtflow.mcp_server.LokiClient", return_value=mock_client):
        res = asyncio.run(call_tool("nxtflow_summary", {"range_str": "30d"}))
        assert res["window"]["range"] == "30d"
        err = asyncio.run(call_tool("nxtflow_status", {"range_str": "5m"}))
        assert "non-object JSON" in err["error"]


def test_tier5_mcp_bad_tls_returns_error_json_and_empty_port_env(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("NXTFLOW_MCP_PORT", "")
    args = parse_args([])
    assert args.port == 8000

    bad_cfg = NxtflowConfig(tls_verify=str(tmp_path / "missing-ca.pem"))
    mcp = create_server(config=bad_cfg)

    async def _invoke_all() -> None:
        calls = [
            ("nxtflow_status", {}),
            ("nxtflow_summary", {}),
            ("nxtflow_top_sources", {}),
            ("nxtflow_top_destinations", {}),
            ("nxtflow_top_connections", {}),
            ("nxtflow_top_ports", {}),
            ("nxtflow_host_profile", {"host": "web-1"}),
            ("nxtflow_sessions", {"host": "web-1"}),
            ("nxtflow_search", {"term": "web-1"}),
            ("nxtflow_directory", {}),
        ]
        for tool_name, params in calls:
            res = await mcp.call_tool(tool_name, params)
            blocks = res[0] if isinstance(res, tuple) else res
            text = blocks[0].text
            payload = json.loads(text)
            assert "error" in payload, f"Expected error JSON for {tool_name}, got {payload}"
            assert "Invalid TLS configuration" in payload["error"]

    asyncio.run(_invoke_all())
