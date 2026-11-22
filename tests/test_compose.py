"""Tests for standalone Docker Compose stack, provisioning configs, and synthetic demo flow generator."""

from __future__ import annotations

import importlib.util
import json
import shutil
import struct
import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_demo_flows_module():
    spec = importlib.util.spec_from_file_location("demo_flows", REPO_ROOT / "scripts" / "demo-flows.py")
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_compose_files_and_env_example_valid() -> None:
    compose_path = REPO_ROOT / "docker-compose.yml"
    env_example_path = REPO_ROOT / ".env.example"
    assert compose_path.is_file()
    assert env_example_path.is_file()

    compose_data = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    services = compose_data["services"]
    expected_services = {
        "init-volumes",
        "loki",
        "prometheus",
        "goflow2",
        "enricher",
        "grafana",
        "nxtflow-mcp",
        "demo-generator",
    }
    assert expected_services <= set(services)
    assert services["demo-generator"]["profiles"] == ["demo"]

    env_text = env_example_path.read_text(encoding="utf-8")
    for var in (
        "NXTFLOW_GRAFANA_PORT",
        "NXTFLOW_LOKI_PORT",
        "NXTFLOW_NETFLOW_PORT",
        "NXTFLOW_SFLOW_PORT",
        "NXTFLOW_GOFLOW2_METRICS_PORT",
        "NXTFLOW_ENRICHER_HTTP_PORT",
        "NXTFLOW_ENRICHER_METRICS_PORT",
        "NXTFLOW_PROMETHEUS_PORT",
        "NXTFLOW_MCP_PORT",
        "NXTFLOW_SITE",
        "NXTFLOW_JOB",
        "NXTFLOW_GRAFANA_ADMIN_USER",
        "NXTFLOW_GRAFANA_ADMIN_PASSWORD",
        "NXTFLOW_LOKI_RETENTION",
    ):
        assert f"{var}=" in env_text, f"Missing {var} in .env.example"


def test_docker_compose_config_renders_cleanly() -> None:
    docker_bin = shutil.which("docker")
    if docker_bin is None:
        pytest.skip("docker binary not installed")
    res = subprocess.run(
        [docker_bin, "compose", "--env-file", str(REPO_ROOT / ".env.example"), "config", "-q"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if res.returncode != 0 and "is not a docker command" in res.stderr:
        pytest.skip("docker compose plugin not installed")
    assert res.returncode == 0, f"docker compose config failed: {res.stderr}"
    res_custom = subprocess.run(
        [docker_bin, "compose", "--env-file", str(REPO_ROOT / ".env.example"), "config"],
        cwd=REPO_ROOT,
        env={**dict(__import__("os").environ), "NXTFLOW_GRAFANA_PORT": "3030", "NXTFLOW_MCP_PORT": "18000"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert res_custom.returncode == 0, res_custom.stderr
    rendered = yaml.safe_load(res_custom.stdout)
    assert str(rendered["services"]["grafana"]["environment"]["GF_SERVER_HTTP_PORT"]) == "3030"
    assert rendered["services"]["grafana"]["ports"][0]["target"] == 3030
    assert rendered["services"]["nxtflow-mcp"]["ports"][0]["target"] == 18000
    assert "18000" in rendered["services"]["nxtflow-mcp"]["command"]


def test_compose_supporting_configs_schema() -> None:
    loki_cfg = yaml.safe_load((REPO_ROOT / "docker" / "loki" / "loki-config.yaml").read_text(encoding="utf-8"))
    assert loki_cfg["auth_enabled"] is False
    assert loki_cfg["schema_config"]["configs"][0]["schema"] == "v13"
    assert loki_cfg["limits_config"]["max_query_series"] == 5000

    enricher_cfg = yaml.safe_load((REPO_ROOT / "docker" / "enricher" / "enricher.yaml").read_text(encoding="utf-8"))
    assert enricher_cfg["ingest"]["file"]["enabled"] is True
    assert enricher_cfg["ingest"]["file"]["path"] == "/var/log/goflow2/raw.jsonl"
    assert enricher_cfg["shipper"]["mode"] == "direct"
    assert enricher_cfg["shipper"]["loki"]["url"] == "http://loki:3100"

    prom_cfg = yaml.safe_load((REPO_ROOT / "docker" / "prometheus" / "prometheus.yml").read_text(encoding="utf-8"))
    jobs = {sc["job_name"]: sc for sc in prom_cfg["scrape_configs"]}
    assert jobs["nxtflow-enricher"]["static_configs"][0]["labels"]["service"] == "nxtflow-metrics"

    ds_cfg = yaml.safe_load(
        (REPO_ROOT / "docker" / "grafana" / "provisioning" / "datasources" / "datasources.yaml").read_text(
            encoding="utf-8"
        )
    )
    by_uid = {ds["uid"]: ds for ds in ds_cfg["datasources"]}
    assert by_uid["loki"]["type"] == "loki"
    assert by_uid["loki"]["url"] == "http://loki:3100"
    assert by_uid["prometheus"]["type"] == "prometheus"
    assert by_uid["prometheus"]["url"] == "http://prometheus:9090"

    dash_prov = yaml.safe_load(
        (REPO_ROOT / "docker" / "grafana" / "provisioning" / "dashboards" / "dashboards.yaml").read_text(
            encoding="utf-8"
        )
    )
    assert dash_prov["providers"][0]["options"]["path"] == "/var/lib/grafana/dashboards"


def test_grafana_entrypoint_substitutes_datasources_and_job(tmp_path: Path) -> None:
    src = REPO_ROOT / "charts" / "nxtflow" / "files" / "dashboards" / "nxtflow-overview.json"
    dst_dir = tmp_path / "dashboards"
    dst = dst_dir / "nxtflow-overview.json"
    entrypoint = (REPO_ROOT / "docker" / "grafana" / "entrypoint.sh").read_text(encoding="utf-8")
    patched = (
        entrypoint.replace("/etc/grafana/dashboards-src/nxtflow-overview.json", str(src))
        .replace("/var/lib/grafana/dashboards", str(dst_dir))
        .replace('exec /run.sh "$@"', "")
    )
    res = subprocess.run(
        ["sh", "-c", patched],
        env={"PATH": "/usr/bin:/bin", "NXTFLOW_JOB": "edgejob"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0, res.stderr
    raw = dst.read_text(encoding="utf-8")
    assert "${DS_LOKI}" not in raw
    assert "${DS_PROMETHEUS}" not in raw
    assert 'job=\\"edgejob\\"' in raw
    parsed = json.loads(raw)
    assert parsed["uid"] == "nxtflow-overview"


def test_demo_flows_packet_encoding() -> None:
    mod = _load_demo_flows_module()
    samples = mod.generate_flow_samples(10)
    assert len(samples) == 10

    v5 = mod.build_netflow_v5_packet(samples, sequence=7, uptime_ms=5000, unix_secs=1700000000)
    ver5, cnt5 = struct.unpack("!HH", v5[:4])
    assert ver5 == 5
    assert cnt5 == 10
    assert len(v5) == 24 + 10 * 48

    v9 = mod.build_netflow_v9_packet(samples, sequence=7, uptime_ms=5000, unix_secs=1700000000)
    ver9, cnt9 = struct.unpack("!HH", v9[:4])
    assert ver9 == 9
    assert cnt9 == 11
    assert len(v9) % 4 == 0
    tpl_id, tpl_len = struct.unpack("!HH", v9[20:24])
    assert tpl_id == 0
    assert tpl_len % 4 == 0
    data_id, data_len = struct.unpack("!HH", v9[20 + tpl_len : 24 + tpl_len])
    assert data_id == 256
    assert data_len % 4 == 0


def test_docs_and_pages_build_includes_docker_compose_and_screenshots(tmp_path: Path) -> None:
    pytest.importorskip("markdown")
    assert (REPO_ROOT / "docs" / "docker-compose.md").is_file()
    for name in ("grafana-overview.png", "grafana-flow-analytics.png", "grafana-overview-full.png"):
        assert (REPO_ROOT / "assets" / "screenshots" / name).is_file()
        assert (REPO_ROOT / "docs" / "assets" / "screenshots" / name).is_file()

    site_dir = tmp_path / "_site"
    res = subprocess.run(
        [__import__("sys").executable, str(REPO_ROOT / ".github" / "scripts" / "sync_gh_pages.py"), str(site_dir)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0, res.stderr
    assert (site_dir / "index.html").is_file()
    assert (site_dir / "docker-compose.html").is_file()
    assert (site_dir / "assets" / "screenshots" / "grafana-overview.png").is_file()
    assert (site_dir / "assets" / "screenshots" / "grafana-flow-analytics.png").is_file()
    assert (site_dir / "assets" / "screenshots" / "grafana-overview-full.png").is_file()
