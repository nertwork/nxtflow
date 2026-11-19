"""Unit and integration tests for nxtflow config, LokiClient, and CLI."""

from __future__ import annotations

import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Self

import pytest

from nxtflow.cli import main
from nxtflow.config import (
    escape_logql_label,
    load_config,
    sanitize_logql_regex,
    validate_dir,
    validate_range,
)
from nxtflow.loki import LokiClient, LokiError, _extract_metric_results, _rate_window_and_step


def test_config_precedence_and_validation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(
        "loki_url: http://yaml-loki.example.com:3100\njob: yamljob\nexcluded_hosts:\n  - multicast\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("NXTFLOW_CONFIG_FILE", str(cfg_path))
    monkeypatch.setenv("NXTFLOW_JOB", "envjob")
    cfg = load_config(loki_url="http://override.example.com:3100")
    assert cfg.loki_url == "http://override.example.com:3100"
    assert cfg.job == "envjob"
    assert cfg.excluded_hosts == ["multicast"]

    assert validate_range("5m") == "5m"
    assert validate_range("30d") == "30d"
    for bad in ("bad", "0m", "-1m", "31d", "5w", ""):
        with pytest.raises(ValueError):
            validate_range(bad)

    assert validate_dir("UP") == "up"
    assert validate_dir(None) is None
    with pytest.raises(ValueError):
        validate_dir("sideways")

    assert escape_logql_label('a"b\\c') == 'a\\"b\\\\c'
    assert "`" not in sanitize_logql_regex("host` | json")


class _MockLokiServer:
    def __init__(self) -> None:
        self.queries: list[str] = []
        self.paths: list[str] = []
        self.error_mode: bool = False
        parent = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                return

            def do_GET(self) -> None:
                parsed = urllib.parse.urlparse(self.path)
                parent.paths.append(parsed.path)
                qs = urllib.parse.parse_qs(parsed.query)
                if "query" in qs:
                    parent.queries.append(qs["query"][0])

                if parent.error_mode:
                    self.send_response(500)
                    self.send_header("Content-Length", "4")
                    self.end_headers()
                    self.wfile.write(b"boom")
                    return

                if parsed.path == "/loki/api/v1/label/site/values":
                    payload = {"status": "success", "data": ["edge-a", "edge-b"]}
                elif parsed.path == "/loki/api/v1/query":
                    q = qs.get("query", [""])[0]
                    if "sum by (site, dir)" in q:
                        payload = {
                            "status": "success",
                            "data": {
                                "result": [
                                    {"metric": {"site": "edge-a", "dir": "down"}, "value": [1700000000, "2048"]},
                                    {"metric": {"site": "edge-a", "dir": "up"}, "value": [1700000000, "1024"]},
                                ]
                            },
                        }
                    elif "sum by (site)" in q:
                        payload = {
                            "status": "success",
                            "data": {"result": [{"metric": {"site": "edge-a"}, "value": [1700000000, "3072"]}]},
                        }
                    elif "sum by (src_host, dst_host)" in q:
                        payload = {
                            "status": "success",
                            "data": {
                                "result": [
                                    {
                                        "metric": {"src_host": "web-1", "dst_host": "cloudflare"},
                                        "value": [1700000000, "8000"],
                                    }
                                ]
                            },
                        }
                    elif "sum by (src_host)" in q:
                        payload = {
                            "status": "success",
                            "data": {"result": [{"metric": {"src_host": "web-1"}, "value": [1700000000, "8000"]}]},
                        }
                    elif "sum by (dst_host)" in q:
                        payload = {
                            "status": "success",
                            "data": {"result": [{"metric": {"dst_host": "cloudflare"}, "value": [1700000000, "8000"]}]},
                        }
                    elif "sum by (dst_port)" in q:
                        payload = {
                            "status": "success",
                            "data": {"result": [{"metric": {"dst_port": "443"}, "value": [1700000000, "8000"]}]},
                        }
                    else:
                        payload = {"status": "success", "data": {"result": [{"metric": {}, "value": [1700000000, "1024"]}]}}
                elif parsed.path == "/loki/api/v1/query_range":
                    q = qs.get("query", [""])[0]
                    if "rate(" in q:
                        payload = {
                            "status": "success",
                            "data": {"result": [{"metric": {}, "values": [[1700000000, "1000"], [1700000015, "2000"]]}]},
                        }
                    else:
                        flow = json.dumps(
                            {
                                "bytes": 1024,
                                "packets": 4,
                                "src_addr": "192.168.1.10",
                                "dst_addr": "1.1.1.1",
                                "src_host": "web-1",
                                "dst_host": "cloudflare-dns",
                                "proto": "UDP",
                                "src_port": 51000,
                                "dst_port": 53,
                                "dir": "up",
                                "site": "edge-a",
                            }
                        )
                        payload = {
                            "status": "success",
                            "data": {
                                "result": [
                                    {"stream": {"site": "edge-a", "dir": "up"}, "values": [["1700000000000000000", flow]]}
                                ]
                            },
                        }
                else:
                    self.send_response(404)
                    self.end_headers()
                    return

                body = json.dumps(payload).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self._srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._srv.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._srv.server_address[1]}"

    def __enter__(self) -> Self:
        self._thread.start()
        return self

    def __exit__(self, *args: object) -> None:
        self._srv.shutdown()
        self._srv.server_close()


def test_cli_all_commands_aliases_and_logql_safeguard(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with _MockLokiServer() as srv:
        monkeypatch.setenv("NXTFLOW_LOKI_URL", srv.url)
        monkeypatch.setenv("NXTFLOW_JOB", "customflow")

        assert main(["status", "--json"]) == 0
        st = json.loads(capsys.readouterr().out)
        assert st["sites_registered"] == ["edge-a", "edge-b"]
        assert st["expected_streams"] == 6
        assert "/ready" not in srv.paths
        assert "/loki/api/v1/label/site/values" in srv.paths

        assert main(["health"]) == 0
        assert "Active streams: 2/6" in capsys.readouterr().out
        assert main(["summary"]) == 0
        assert "Download" in capsys.readouterr().out
        assert main(["top-sources", "5"]) == 0
        assert "web-1" in capsys.readouterr().out
        assert main(["top-connections", "5"]) == 0
        assert "cloudflare" in capsys.readouterr().out
        assert main(["top-ports", "5"]) == 0
        assert "443" in capsys.readouterr().out
        assert main(["host", "web-1"]) == 0
        assert "Top Peers:" in capsys.readouterr().out
        assert main(["sessions", "web-1"]) == 0
        assert "cloudflare-dns" in capsys.readouterr().out
        assert main(["search", "cloudflare"]) == 0
        assert "Matches" in capsys.readouterr().out.title()
        assert main(["directory"]) == 0
        assert "Network Directory" in capsys.readouterr().out
        assert main(["config"]) == 0
        assert "nxtflow Active Configuration" in capsys.readouterr().out

        assert main(["traffic", "--range", "15m", "--json"]) == 0
        summary = json.loads(capsys.readouterr().out)
        assert "download" in summary and "by_site" in summary

        assert main(["top-talkers", "5", "--json"]) == 0
        top_src = json.loads(capsys.readouterr().out)
        assert top_src[0]["name"] == "web-1"
        assert "bytes" in top_src[0]

        assert main(["top-dst", "--limit", "5", "--json"]) == 0
        assert json.loads(capsys.readouterr().out)[0]["name"] == "cloudflare"

        assert main(["flows", "--json"]) == 0
        assert json.loads(capsys.readouterr().out)[0]["src"] == "web-1"

        assert main(["top-ports", "--json"]) == 0
        assert json.loads(capsys.readouterr().out)[0]["port"] == "443"
        assert any("dst_port =~ `.{1,4}`" in q for q in srv.queries)
        assert all('job="customflow"' in q for q in srv.queries)
        assert any("src_host != `multicast`" in q and "src_host != `link-local`" in q for q in srv.queries)

        assert main(["host", "web-1", "--json"]) == 0
        assert json.loads(capsys.readouterr().out)["flows"] == 1

        assert main(["sessions", "web-1", "--json"]) == 0
        assert json.loads(capsys.readouterr().out)[0]["dst"] == "cloudflare-dns"

        assert main(["search", "cloudflare", "5", "--json"]) == 0
        assert len(json.loads(capsys.readouterr().out)) == 1

        assert main(["directory", "--json"]) == 0
        directory = json.loads(capsys.readouterr().out)
        assert directory["192.168.1.10"] == "web-1"
        assert directory["1.1.1.1"] == "cloudflare-dns"

        assert main(["config", "--json"]) == 0
        assert json.loads(capsys.readouterr().out)["job"] == "customflow"

        # Invalid range returns code 2
        assert main(["summary", "--range", "invalid"]) == 2
        capsys.readouterr()

        # Loki HTTP 500 returns code 1 cleanly
        srv.error_mode = True
        assert main(["status", "--json"]) == 1
        err_out = capsys.readouterr().err
        assert "HTTP 500" in err_out
        with pytest.raises(LokiError):
            LokiClient(load_config()).get_status_data()


def test_rate_window_and_step_multiday_scaling() -> None:
    assert _rate_window_and_step("5m") == ("1m", "15s")
    assert _rate_window_and_step("1h") == ("2m", "30s")
    assert _rate_window_and_step("6h") == ("2m", "60s")
    assert _rate_window_and_step("24h") == ("5m", "5m")
    assert _rate_window_and_step("7d") == ("15m", "15m")
    assert _rate_window_and_step("30d") == ("1h", "1h")


def test_cli_edge_cases_null_fields_non_dict_json_clamp_and_missing_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # 1) Missing explicit --config raises FileNotFoundError in load_config & returns exit 2 in CLI
    missing_cfg = tmp_path / "nonexistent.yaml"
    with pytest.raises(FileNotFoundError):
        load_config(config_file=missing_cfg)
    assert main(["status", "--config", str(missing_cfg), "--json"]) == 2
    assert "not found" in capsys.readouterr().err.lower()

    monkeypatch.setenv("NXTFLOW_CONFIG_FILE", str(missing_cfg))
    with pytest.raises(FileNotFoundError):
        load_config()
    monkeypatch.delenv("NXTFLOW_CONFIG_FILE")

    # 2) Mock Loki returning null flow fields, non-dict JSON, and capturing query_range params
    captured_steps: list[str] = []
    captured_limits: list[str] = []
    mode = ["null_fields"]

    class EdgeLokiHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            return

        def do_GET(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(parsed.query)
            if "step" in qs:
                captured_steps.append(qs["step"][0])
            if "limit" in qs:
                captured_limits.append(qs["limit"][0])

            if mode[0] == "non_dict":
                body = json.dumps(["unexpected"]).encode("utf-8")
            elif parsed.path == "/loki/api/v1/query":
                body = json.dumps({"status": "success", "data": {"result": [{"metric": {}, "value": [1700000000, "100"]}]}}).encode("utf-8")
            elif parsed.path == "/loki/api/v1/query_range" and "rate(" in qs.get("query", [""])[0]:
                body = json.dumps({"status": "success", "data": {"result": []}}).encode("utf-8")
            else:
                flow = json.dumps(
                    {
                        "bytes": None,
                        "src_addr": "192.168.1.10",
                        "dst_addr": "1.1.1.1",
                        "src_host": "web-1",
                        "dst_host": None,
                        "proto": None,
                        "dst_port": None,
                        "dir": None,
                        "site": None,
                    }
                )
                body = json.dumps(
                    {
                        "status": "success",
                        "data": {
                            "result": [{"stream": {}, "values": [["1700000000000000000", flow]]}]
                        },
                    }
                ).encode("utf-8")

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), EdgeLokiHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        monkeypatch.setenv("NXTFLOW_LOKI_URL", f"http://127.0.0.1:{srv.server_address[1]}")

        # summary --range 30d uses step=1h
        assert main(["summary", "--range", "30d", "--json"]) == 0
        capsys.readouterr()
        assert captured_steps and all(s == "1h" for s in captured_steps)

        # null JSON fields survive host, sessions, search without TypeError
        assert main(["host", "web-1"]) == 0
        assert "Flows: 1" in capsys.readouterr().out
        assert main(["sessions", "web-1"]) == 0
        assert "web-1" in capsys.readouterr().out
        assert main(["search", "web-1"]) == 0
        assert "web-1" in capsys.readouterr().out

        # directory -n 0 clamps limit to 1
        assert main(["directory", "-n", "0", "--json"]) == 0
        capsys.readouterr()
        assert captured_limits[-1] == "1"

        # non-dict JSON raises LokiError (exit 1 cleanly, no AttributeError)
        mode[0] = "non_dict"
        assert main(["status", "--json"]) == 1
        assert "non-object JSON" in capsys.readouterr().err
    finally:
        srv.shutdown()
        srv.server_close()


def test_kubectl_fallback_passes_headers_via_stdin_json(monkeypatch: pytest.MonkeyPatch) -> None:
    recorded: dict[str, object] = {}

    class FakeProc:
        returncode = 0
        stdout = json.dumps({"status": "success", "data": ["site-a"]})
        stderr = ""

    def fake_run(cmd: list[str], **kwargs: object) -> FakeProc:
        recorded["cmd"] = cmd
        recorded["kwargs"] = kwargs
        return FakeProc()

    monkeypatch.setattr("nxtflow.loki.subprocess.run", fake_run)
    cfg = load_config(
        use_kubectl=True,
        kube_context="ctx-1",
        loki_token="super-secret-token",
    )
    sites = LokiClient(cfg).check_readiness()
    assert sites == ["site-a"]
    cmd = recorded["cmd"]
    assert isinstance(cmd, list)
    assert "-i" in cmd
    assert "super-secret-token" not in " ".join(cmd)
    stdin_payload = json.loads(str(recorded["kwargs"]["input"]))
    assert stdin_payload["headers"]["Authorization"] == "Bearer super-secret-token"


def test_cli_invalid_yaml_config_returns_exit_2(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    bad_cfg = tmp_path / "invalid.yaml"
    bad_cfg.write_text("loki_url: [unterminated\n  bad: : :\n", encoding="utf-8")

    assert main(["status", "--config", str(bad_cfg), "--json"]) == 2
    err_json = json.loads(capsys.readouterr().err)
    assert "error" in err_json

    assert main(["status", "--config", str(bad_cfg)]) == 2
    assert "Error:" in capsys.readouterr().err


def test_loki_client_handles_null_data_result_stream_and_values(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert _extract_metric_results({"status": "success", "data": None}) == []
    assert _extract_metric_results({"status": "success", "data": {"result": None}}) == []
    assert _extract_metric_results({"status": "success", "data": {"result": [{"metric": None, "value": None}]}}) == [
        {"labels": {}, "value": 0.0}
    ]

    response_mode = ["null_data"]

    class NullLokiHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            return

        def do_GET(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == "/loki/api/v1/label/site/values" or response_mode[0] == "null_data":
                payload = {"status": "success", "data": None}
            elif response_mode[0] == "null_result":
                payload = {"status": "success", "data": {"result": None}}
            else:
                payload = {
                    "status": "success",
                    "data": {
                        "result": [
                            {"stream": None, "values": None, "metric": None, "value": None},
                            {"stream": {"site": "edge-a"}, "values": [["1700000000000000000", "not-json"]]},
                        ]
                    },
                }
            body = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), NullLokiHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        monkeypatch.setenv("NXTFLOW_LOKI_URL", f"http://127.0.0.1:{srv.server_address[1]}")
        client = LokiClient(load_config())
        for mode in ("null_data", "null_result", "null_nested"):
            response_mode[0] = mode
            assert main(["status", "--json"]) == 0
            assert main(["summary", "--json"]) == 0
            assert main(["search", "web-1", "--json"]) == 0
            capsys.readouterr()
            top_rows = client.get_top_data("src_host")
            if mode in ("null_data", "null_result"):
                assert top_rows == []
            else:
                assert len(top_rows) == 2 and all(r["bytes"] == 0.0 for r in top_rows)
            assert client.get_host_data("web-1") is None
            assert client.log_query('{job="nxtflow"}', range_str="5m") == []
    finally:
        srv.shutdown()
        srv.server_close()


def test_tier5_cli_tls_nan_kubectl_guard_null_yaml_and_limits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from nxtflow.config import NxtflowConfig, clamp_limit, parse_excluded_hosts, parse_tls_verify

    # Gap 4: invalid CA path -> LokiError (not raw FileNotFoundError) & CLI exit 1
    with pytest.raises(LokiError, match="Invalid TLS configuration"):
        LokiClient(NxtflowConfig(tls_verify=str(tmp_path / "missing-ca.pem")))
    monkeypatch.setenv("NXTFLOW_TLS_VERIFY", str(tmp_path / "missing-ca.pem"))
    assert main(["status", "--json"]) == 1
    assert "Invalid TLS configuration" in capsys.readouterr().err
    monkeypatch.delenv("NXTFLOW_TLS_VERIFY")

    # Gap 5: YAML null values do not turn into "None"
    null_yaml = tmp_path / "null_cli.yaml"
    null_yaml.write_text(
        """
loki_url: null
job: null
tls_verify: null
loki_token: null
loki_user: null
loki_password: null
loki_tenant_id: null
excluded_hosts: [null, "multicast"]
kube_context: null
kube_namespace: null
kube_target: null
cluster_loki_url: null
timeout_seconds: null
""",
        encoding="utf-8",
    )
    cfg_null = load_config(config_file=null_yaml)
    assert cfg_null.loki_url == "http://localhost:3100"
    assert cfg_null.job == "nxtflow"
    assert cfg_null.excluded_hosts == ["multicast"]
    assert cfg_null.kube_namespace == "nxtflow"
    assert parse_excluded_hosts(None) == ["multicast", "link-local"]
    assert parse_excluded_hosts([None, "keep"]) == ["keep"]
    assert parse_excluded_hosts("a, , b") == ["a", "b"]
    assert parse_tls_verify("true") is True
    assert parse_tls_verify("false") is False
    assert parse_tls_verify(None) is True

    # Gap 11: use_kubectl=True without kube_context immediately raises LokiError
    with pytest.raises(LokiError, match="kube_context is not configured"):
        LokiClient(NxtflowConfig(use_kubectl=True, kube_context="")).request("/loki/api/v1/label/site/values")

    # Gap 15: overflow & Unicode digits & negative limit clamping
    with pytest.raises(ValueError, match="integer"):
        clamp_limit(float("inf"))
    with pytest.raises(ValueError, match="Invalid range"):
        validate_range("٥m")
    assert main([]) == 0
    capsys.readouterr()

    # Gap 6: non-finite NaN/Inf in Loki responses + non-UTF-8 + unhashable dst_port
    mode = ["nan_metrics"]

    class WeirdLokiHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            return

        def do_GET(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            if mode[0] == "bad_utf8":
                body = b"\xff\xfe\xfd"
            elif parsed.path == "/loki/api/v1/query":
                body = json.dumps(
                    {
                        "status": "success",
                        "data": {
                            "result": [
                                {"metric": {"src_host": "a"}, "value": [1, "NaN"]},
                                {"metric": {"src_host": "b"}, "value": [1, "Infinity"]},
                                {"metric": {"src_host": "c"}, "value": [1, "500"]},
                            ]
                        },
                    }
                ).encode("utf-8")
            elif "rate(" in self.path:
                body = json.dumps(
                    {
                        "status": "success",
                        "data": {
                            "result": [{"values": [[100, "NaN"], [101, "Infinity"], [102, "bad"], [103, "64.0"]]}]
                        },
                    }
                ).encode("utf-8")
            else:
                flow = json.dumps(
                    {
                        "site": None,
                        "dir": None,
                        "src_host": "web-1",
                        "dst_host": "dns",
                        "src_addr": "10.0.0.1",
                        "dst_addr": "1.1.1.1",
                        "dst_port": {"nested": 53},
                        "proto": "UDP",
                        "bytes": "NaN",
                    }
                )
                body = json.dumps(
                    {"status": "success", "data": {"result": [{"stream": {}, "values": [["1", flow]]}]}}
                ).encode("utf-8")

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), WeirdLokiHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        monkeypatch.setenv("NXTFLOW_LOKI_URL", f"http://127.0.0.1:{srv.server_address[1]}")
        assert main(["summary", "--json"]) == 0
        summary_out = capsys.readouterr().out
        json.loads(summary_out, parse_constant=lambda c: (_ for _ in ()).throw(ValueError(c)))

        assert main(["top-src", "--limit", "-5"]) == 0
        top_out = capsys.readouterr().out
        assert "1 max)" in top_out
        assert "Top -5" not in top_out

        assert main(["host", "web-1", "--json"]) == 0
        host_json = json.loads(capsys.readouterr().out)
        assert host_json["bytes"] == 0
        assert host_json["top_ports"][0]["port"] == "{'nested': 53}"

        assert main(["sessions", "web-1", "--json"]) == 0
        assert json.loads(capsys.readouterr().out)[0]["bytes"] == 0
        assert main(["search", "web-1"]) == 0
        capsys.readouterr()

        mode[0] = "bad_utf8"
        assert main(["status", "--json"]) == 1
        assert "Loki request failed" in capsys.readouterr().err
    finally:
        srv.shutdown()
        srv.server_close()


def test_tier5_config_env_overrides_and_kubectl_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess
    from unittest.mock import MagicMock, patch

    from nxtflow.config import NxtflowConfig

    monkeypatch.setenv("NXTFLOW_LOKI_URL", "https://loki.example.com/")
    monkeypatch.setenv("NXTFLOW_JOB", "envjob")
    monkeypatch.setenv("NXTFLOW_LOKI_TOKEN", "tok")
    monkeypatch.setenv("NXTFLOW_LOKI_USER", "usr")
    monkeypatch.setenv("NXTFLOW_LOKI_PASSWORD", "pwd")
    monkeypatch.setenv("NXTFLOW_LOKI_TENANT_ID", "tid")
    monkeypatch.setenv("NXTFLOW_TLS_VERIFY", "false")
    monkeypatch.setenv("NXTFLOW_USE_KUBECTL", "1")
    monkeypatch.setenv("NXTFLOW_KUBE_CONTEXT", "cluster-a")
    monkeypatch.setenv("NXTFLOW_KUBE_NAMESPACE", "netflow")
    monkeypatch.setenv("NXTFLOW_KUBE_TARGET", "deploy/goflow2")
    monkeypatch.setenv("NXTFLOW_CLUSTER_LOKI_URL", "http://loki.ns:3100/")
    monkeypatch.setenv("NXTFLOW_EXCLUDED_HOSTS", "h1,h2")
    cfg = load_config(timeout_seconds=9.5)
    assert cfg.loki_url == "https://loki.example.com"
    assert cfg.job == "envjob"
    assert cfg.loki_token == "tok"
    assert cfg.loki_user == "usr"
    assert cfg.loki_password == "pwd"
    assert cfg.loki_tenant_id == "tid"
    assert cfg.tls_verify is False
    assert cfg.use_kubectl is True
    assert cfg.kube_context == "cluster-a"
    assert cfg.kube_namespace == "netflow"
    assert cfg.kube_target == "deploy/goflow2"
    assert cfg.cluster_loki_url == "http://loki.ns:3100"
    assert cfg.excluded_hosts == ["h1", "h2"]
    assert cfg.timeout_seconds == 9.5
    assert cfg.redacted_dict()["loki_token"] == "***"

    client = LokiClient(NxtflowConfig(use_kubectl=True, kube_context="cluster-a"))
    with (
        patch("nxtflow.loki.subprocess.run", side_effect=subprocess.TimeoutExpired("kubectl", 1)),
        pytest.raises(LokiError, match="timed out"),
    ):
        client.request("/loki/api/v1/label/site/values")
    with (
        patch("nxtflow.loki.subprocess.run", return_value=MagicMock(returncode=1, stderr="boom", stdout="")),
        pytest.raises(LokiError, match="boom"),
    ):
        client.request("/loki/api/v1/label/site/values")
    with (
        patch("nxtflow.loki.subprocess.run", return_value=MagicMock(returncode=0, stderr="", stdout="not-json")),
        pytest.raises(LokiError, match="Invalid JSON"),
    ):
        client.request("/loki/api/v1/label/site/values")
    with (
        patch("nxtflow.loki.subprocess.run", return_value=MagicMock(returncode=0, stderr="", stdout='{"status":"error","error":"bad query"}')),
        pytest.raises(LokiError, match="bad query"),
    ):
        client.request("/loki/api/v1/label/site/values")


def test_tier5_config_nested_yaml_and_validation_edges(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from nxtflow.config import (
        load_config,
        parse_excluded_hosts,
        sanitize_logql_regex,
        validate_dir,
        validate_range,
    )

    nested = tmp_path / "nested.yaml"
    nested.write_text(
        """
loki:
  url: https://nested-loki.example.com/
  tlsVerify: false
  bearerToken: nest-tok
  username: nest-usr
  password: nest-pwd
  tenantId: nest-tid
kube:
  context: cluster-b
  namespace: netflow-ns
  target: deploy/custom
excludedHosts:
  - multicast
timeout_seconds: 0.01
""",
        encoding="utf-8",
    )
    monkeypatch.delenv("NXTFLOW_CONFIG_FILE", raising=False)
    cfg = load_config(config_file=nested)
    assert cfg.loki_url == "https://nested-loki.example.com"
    assert cfg.tls_verify is False
    assert cfg.loki_token == "nest-tok"
    assert cfg.loki_user == "nest-usr"
    assert cfg.loki_password == "nest-pwd"
    assert cfg.loki_tenant_id == "nest-tid"
    assert cfg.kube_context == "cluster-b"
    assert cfg.kube_namespace == "netflow-ns"
    assert cfg.kube_target == "deploy/custom"
    assert cfg.excluded_hosts == ["multicast"]
    assert cfg.timeout_seconds == 0.1

    monkeypatch.setenv("NXTFLOW_LOKI_USERNAME", "alias-usr")
    assert load_config(config_file=nested).loki_user == "alias-usr"

    bad_type = tmp_path / "list.yaml"
    bad_type.write_text("- item1\n", encoding="utf-8")
    with pytest.raises(TypeError, match="YAML mapping"):
        load_config(config_file=bad_type)

    empty_yaml = tmp_path / "empty.yaml"
    empty_yaml.write_text("", encoding="utf-8")
    assert load_config(config_file=empty_yaml).loki_url == "http://localhost:3100"

    assert parse_excluded_hosts("") == []
    assert parse_excluded_hosts(123) == ["multicast", "link-local"]
    assert validate_dir("   ") is None
    with pytest.raises(TypeError, match="expected string"):
        validate_range(123)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="cannot be empty"):
        sanitize_logql_regex("   ` ")
