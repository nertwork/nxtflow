"""Comprehensive tests for nxtflow Helm chart, branding assets, dashboard, CI workflows, and security audit."""

from __future__ import annotations

import importlib.util
import json
import shutil
import struct
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import jsonschema
import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
CHART_DIR = REPO_ROOT / "charts" / "nxtflow"
EXAMPLES_DIR = REPO_ROOT / "examples"


def _load_security_audit_module():
    spec = importlib.util.spec_from_file_location("security_audit", REPO_ROOT / "scripts" / "security_audit.py")
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _require_helm() -> str:
    helm_bin = shutil.which("helm")
    assert helm_bin is not None, "helm binary is required in PATH for Helm chart tests"
    return helm_bin


def _render_chart(release: str, *extra_args: str) -> list[dict[str, Any]]:
    helm_bin = _require_helm()
    subcharts = list((CHART_DIR / "charts").glob("*.tgz"))
    assert len(subcharts) >= 3, "Missing vendored subcharts in charts/nxtflow/charts/. Run 'helm dependency build charts/nxtflow'."
    cmd = [helm_bin, "template", release, str(CHART_DIR), *extra_args]
    res = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert res.returncode == 0, f"helm template failed: {res.stderr}"
    docs = [doc for doc in yaml.safe_load_all(res.stdout) if isinstance(doc, dict)]
    assert docs, "helm template produced zero YAML documents"
    return docs


def test_security_audit_clean_and_catches_violations(tmp_path: Path) -> None:
    mod = _load_security_audit_module()
    assert mod.scan_directory(REPO_ROOT) == []

    dirty_dir = tmp_path / "dirty"
    dirty_dir.mkdir()
    (dirty_dir / "leak1.yaml").write_text("password: " + "Super" + "Secret\n", encoding="utf-8")
    (dirty_dir / "leak2.pem").write_text("-----BEGIN RSA " + "PRIVATE" + " KEY-----\n", encoding="utf-8")
    (dirty_dir / "leak3.txt").write_text("token: " + "ghp" + "_" + "A" * 24 + "\n", encoding="utf-8")
    hits = mod.scan_directory(dirty_dir)
    assert len(hits) >= 3
    joined = "\n".join(hits)
    for fname in ("leak1.yaml", "leak2.pem", "leak3.txt"):
        assert fname in joined

    safe_dir = tmp_path / "safe"
    safe_dir.mkdir()
    (safe_dir / "rfc.md").write_text(
        "192.0.2.10\n198.51.100.5\n203.0.113.42\n10.0.0.1\n"
        "192.168.1.1\n172.16.0.1\n2001:db8::1\nhttps://loki.example.com\n",
        encoding="utf-8",
    )
    assert mod.scan_directory(safe_dir) == []


def test_branding_assets_and_chart_icon() -> None:
    expected_pngs = {
        "nxtflow-icon.png": (512, 512),
        "nxtflow-icon-256.png": (256, 256),
        "nxtflow-logo.png": (960, 256),
    }
    expected_svgs = ["nxtflow-icon.svg", "nxtflow-logo.svg"]

    for base in (REPO_ROOT / "assets", REPO_ROOT / "docs" / "assets"):
        for svg_name in expected_svgs:
            svg_path = base / svg_name
            assert svg_path.is_file(), f"Missing {svg_path}"
            assert not svg_path.is_symlink(), f"{svg_path} must be a real file, not a symlink"
            root = ET.fromstring(svg_path.read_text(encoding="utf-8"))
            assert root.tag.endswith("svg")

        for png_name, (exp_w, exp_h) in expected_pngs.items():
            png_path = base / png_name
            assert png_path.is_file(), f"Missing {png_path}"
            assert not png_path.is_symlink(), f"{png_path} must be a real file, not a symlink"
            raw = png_path.read_bytes()
            assert raw[:8] == b"\x89PNG\r\n\x1a\n"
            w, h = struct.unpack(">II", raw[16:24])
            assert (w, h) == (exp_w, exp_h), f"{png_path} dimensions {(w, h)} != {(exp_w, exp_h)}"

    chart = yaml.safe_load((CHART_DIR / "Chart.yaml").read_text(encoding="utf-8"))
    assert chart["apiVersion"] == "v2"
    assert chart["icon"].startswith("https://")
    assert chart["icon"].endswith("nxtflow-icon.png")
    deps = {d["name"]: d for d in chart["dependencies"]}
    assert set(deps) == {"loki", "prometheus", "grafana"}
    for dep in deps.values():
        assert "standalone" in dep["tags"]


def test_values_schema_valid_and_rejects_invalid() -> None:
    schema = json.loads((CHART_DIR / "values.schema.json").read_text(encoding="utf-8"))
    default_values = yaml.safe_load((CHART_DIR / "values.yaml").read_text(encoding="utf-8"))
    jsonschema.validate(instance=default_values, schema=schema)

    for fname in ("values-standalone.yaml", "values-integrated.yaml", "values-collector-only.yaml"):
        overlay = yaml.safe_load((EXAMPLES_DIR / fname).read_text(encoding="utf-8"))
        jsonschema.validate(instance=overlay, schema=schema)

    invalid_cases = [
        {"enricher": {"shipper": {"mode": "kafka"}}},
        {"mcp": {"port": -5}},
        {"grafana": {"sankey": {"engine": "unknown"}}},
        {"collector": {"goflow2": {"transport": "kafka"}}},
    ]
    for bad in invalid_cases:
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=bad, schema=schema)


def test_grafana_dashboard_json() -> None:
    dash_path = CHART_DIR / "files" / "dashboards" / "nxtflow-overview.json"
    raw = dash_path.read_text(encoding="utf-8")
    dash = json.loads(raw)

    input_names = {item["name"] for item in dash["__inputs"]}
    assert {"DS_LOKI", "DS_PROMETHEUS"} <= input_names

    vars_by_name = {v["name"]: v for v in dash["templating"]["list"]}
    assert vars_by_name["DS_LOKI"]["type"] == "datasource"
    assert vars_by_name["DS_PROMETHEUS"]["type"] == "datasource"
    assert vars_by_name["site"]["type"] == "query"
    assert vars_by_name["site"]["query"]["label"] == "site"
    assert vars_by_name["dir"]["type"] == "custom"
    assert vars_by_name["search"]["type"] == "textbox"

    collector_panel = next(p for p in dash["panels"] if p["id"] == 3)
    assert collector_panel["targets"][0]["expr"] == 'max(up{service=~".*nxtflow.*"})'
    ports_panel = next(p for p in dash["panels"] if p["id"] == 15)
    assert "dst_port =~ `.{1,4}` | __error__=``" in ports_panel["targets"][0]["expr"]

    sankey_panel = next(p for p in dash["panels"] if p["id"] == 14)
    assert sankey_panel["type"] == "volkovlabs-echarts-panel"
    assert '"s:"' in sankey_panel["options"]["getOption"]
    assert '"d:"' in sankey_panel["options"]["getOption"]


def test_helm_dependencies_present() -> None:
    assert (CHART_DIR / "Chart.lock").is_file(), "Missing charts/nxtflow/Chart.lock; run 'helm dependency build charts/nxtflow'"
    tgzs = {p.name for p in (CHART_DIR / "charts").glob("*.tgz")}
    assert any(n.startswith("loki-") for n in tgzs), "Missing loki tgz; run 'helm dependency build charts/nxtflow'"
    assert any(n.startswith("prometheus-") for n in tgzs), "Missing prometheus tgz; run 'helm dependency build charts/nxtflow'"
    assert any(n.startswith("grafana-") for n in tgzs), "Missing grafana tgz; run 'helm dependency build charts/nxtflow'"


def test_helm_lint_all_modes() -> None:
    helm_bin = _require_helm()
    commands = [
        [helm_bin, "lint", str(CHART_DIR)],
        [helm_bin, "lint", str(CHART_DIR), "-f", str(EXAMPLES_DIR / "values-standalone.yaml")],
        [helm_bin, "lint", str(CHART_DIR), "-f", str(EXAMPLES_DIR / "values-integrated.yaml")],
        [helm_bin, "lint", str(CHART_DIR), "-f", str(EXAMPLES_DIR / "values-collector-only.yaml")],
    ]
    for cmd in commands:
        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        assert res.returncode == 0, f"{' '.join(cmd)} failed:\n{res.stdout}\n{res.stderr}"


def test_helm_template_standalone_integrated_collector_and_variants() -> None:
    # 1. Standalone mode
    sa_docs = _render_chart("nxt", "-f", str(EXAMPLES_DIR / "values-standalone.yaml"))
    sa_names = {(d.get("kind"), d.get("metadata", {}).get("name")) for d in sa_docs}
    assert ("StatefulSet", "nxt-loki") in sa_names
    assert ("Deployment", "nxt-grafana") in sa_names
    assert ("Deployment", "nxt-prometheus-server") in sa_names
    assert ("Deployment", "nxt-nxtflow-collector") in sa_names
    assert ("Deployment", "nxt-nxtflow-mcp") in sa_names
    assert ("ConfigMap", "nxt-nxtflow-grafana-datasources") in sa_names
    assert ("ConfigMap", "nxt-nxtflow-dashboard") in sa_names

    collector_dep = next(d for d in sa_docs if d.get("kind") == "Deployment" and d["metadata"]["name"] == "nxt-nxtflow-collector")
    assert collector_dep["spec"]["template"]["spec"]["securityContext"]["fsGroup"] == 65533
    containers = {c["name"]: c for c in collector_dep["spec"]["template"]["spec"]["containers"]}
    assert containers["goflow2"]["image"] == "netsampler/goflow2:v2.2.7"
    assert "-transport=file" in containers["goflow2"]["args"]
    assert "-transport.file=/var/log/goflow2/raw.jsonl" in containers["goflow2"]["args"]
    assert containers["goflow2"]["securityContext"]["runAsUser"] == 100
    assert containers["goflow2"]["securityContext"]["runAsGroup"] == 65533

    enricher_cm = next(d for d in sa_docs if d.get("kind") == "ConfigMap" and d["metadata"]["name"] == "nxt-nxtflow-enricher")
    enricher_cfg = yaml.safe_load(enricher_cm["data"]["enricher.yaml"])
    assert enricher_cfg["ingest"]["file"]["enabled"] is True
    assert enricher_cfg["ingest"]["http"]["enabled"] is True
    assert enricher_cfg["shipper"]["loki"]["url"] == "http://nxt-loki:3100"

    sa_dash_cm = next(d for d in sa_docs if d.get("kind") == "ConfigMap" and d["metadata"]["name"] == "nxt-nxtflow-dashboard")
    sa_dash = json.loads(sa_dash_cm["data"]["nxtflow-overview.json"])
    assert sa_dash["panels"][0]["datasource"]["uid"] == "loki"

    # 2. Integrated mode
    int_docs = _render_chart("rel", "-f", str(EXAMPLES_DIR / "values-integrated.yaml"))
    int_names = {(d.get("kind"), d.get("metadata", {}).get("name")) for d in int_docs}
    assert not any("loki" in (n or "") and k == "StatefulSet" for k, n in int_names)
    assert not any("grafana" in (n or "") and k == "Deployment" for k, n in int_names)
    assert not any("prometheus-server" in (n or "") for _, n in int_names)
    assert ("ServiceMonitor", "rel-nxtflow") in int_names
    assert ("PrometheusRule", "rel-nxtflow") in int_names
    assert ("ConfigMap", "rel-nxtflow-dashboard") in int_names
    assert ("Deployment", "rel-nxtflow-mcp") in int_names

    netflow_svc = next(d for d in int_docs if d.get("kind") == "Service" and d["metadata"]["name"] == "rel-nxtflow-netflow")
    assert netflow_svc["spec"]["externalTrafficPolicy"] == "Local"

    # 3. Collector-only mode
    col_docs = _render_chart("edge", "-f", str(EXAMPLES_DIR / "values-collector-only.yaml"))
    col_names = {(d.get("kind"), d.get("metadata", {}).get("name")) for d in col_docs}
    assert ("Deployment", "edge-nxtflow-collector") in col_names
    assert ("Deployment", "edge-nxtflow-mcp") not in col_names
    assert ("ServiceMonitor", "edge-nxtflow") not in col_names
    assert ("PrometheusRule", "edge-nxtflow") not in col_names
    assert ("ConfigMap", "edge-nxtflow-dashboard") not in col_names

    # 4. Alloy sidecar + NetSage Sankey + custom job/excludedHosts
    alt_docs = _render_chart(
        "alt",
        "-f",
        str(EXAMPLES_DIR / "values-integrated.yaml"),
        "--set",
        "enricher.shipper.mode=alloy",
        "--set",
        "grafana.sankey.engine=netsage",
        "--set",
        "collector.job=customflow",
    )
    alt_names = {(d.get("kind"), d.get("metadata", {}).get("name")) for d in alt_docs}
    assert ("ConfigMap", "alt-nxtflow-alloy") in alt_names
    alt_dep = next(d for d in alt_docs if d.get("kind") == "Deployment" and d["metadata"]["name"] == "alt-nxtflow-collector")
    assert any(c["name"] == "alloy" for c in alt_dep["spec"]["template"]["spec"]["containers"])
    alt_dash_cm = next(d for d in alt_docs if d.get("kind") == "ConfigMap" and d["metadata"]["name"] == "alt-nxtflow-dashboard")
    alt_dash_text = alt_dash_cm["data"]["nxtflow-overview.json"]
    alt_dash = json.loads(alt_dash_text)
    sankey = next(p for p in alt_dash["panels"] if p["id"] == 14)
    assert sankey["type"] == "netsage-sankey-panel"
    assert alt_dash["panels"][0]["targets"][0]["expr"].startswith('sum(sum_over_time({job="customflow"')


def test_helm_negative_fail_guards() -> None:
    helm_bin = _require_helm()
    bad_cases = [
        ["--set", "tags.standalone=false"],
        ["--set", "tags.standalone=true", "--set", "externalLoki.url=https://loki.example.com"],
        ["--set", "tags.standalone=false", "--set", "enricher.shipper.mode=file", "--set", "mcp.enabled=true"],
    ]
    for args in bad_cases:
        res = subprocess.run([helm_bin, "template", "bad", str(CHART_DIR), *args], capture_output=True, text=True, check=False)
        assert res.returncode != 0, f"Expected failure for {args}, but succeeded"


def test_ci_workflow_yaml_and_required_check_names() -> None:
    yaml_files = sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml")) + [
        REPO_ROOT / ".github" / "dependabot.yml",
        REPO_ROOT / "ct.yaml",
        REPO_ROOT / ".coderabbit.yaml",
    ]
    for path in yaml_files:
        assert path.is_file(), f"Missing {path}"
        parsed = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert isinstance(parsed, dict)

    ci = yaml.safe_load((REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    job_names = {job["name"] for job in ci["jobs"].values()}
    assert {
        "Lint, Syntax & Security Audit",
        "Python Lint & Unit Tests",
        "Helm Lint, Schema & Template",
    } <= job_names
def test_helm_partial_standalone_datasources() -> None:
    docs = _render_chart(
        "rel",
        "--set",
        "tags.standalone=true",
        "--set",
        "bundled.loki.enabled=false",
        "--set",
        "bundled.prometheus.enabled=false",
        "--set",
        "externalLoki.url=https://loki.example.com",
        "--set",
        "externalLoki.tenantId=tenant-a",
        "--set",
        "externalLoki.tls.insecureSkipVerify=true",
        "--set",
        "externalLoki.auth.bearerToken=tok-123",
    )
    ds_cm = next(d for d in docs if d.get("kind") == "ConfigMap" and d["metadata"]["name"] == "rel-nxtflow-grafana-datasources")
    ds_cfg = yaml.safe_load(ds_cm["data"]["nxtflow-datasources.yaml"])
    datasources = {d["name"]: d for d in ds_cfg["datasources"]}
    assert "Prometheus" not in datasources
    loki_ds = datasources["Loki"]
    assert loki_ds["url"] == "https://loki.example.com"
    assert "rel-loki:3100" not in loki_ds["url"]
    assert loki_ds["jsonData"]["tlsSkipVerify"] is True
    assert loki_ds["jsonData"]["httpHeaderName1"] == "X-Scope-OrgID"
    assert loki_ds["jsonData"]["httpHeaderName2"] == "Authorization"
    assert loki_ds["secureJsonData"]["httpHeaderValue1"] == "tenant-a"
    assert loki_ds["secureJsonData"]["httpHeaderValue2"] == "Bearer tok-123"

    # External Prometheus URL option + basic auth
    docs_prom = _render_chart(
        "rel",
        "--set",
        "tags.standalone=true",
        "--set",
        "bundled.loki.enabled=false",
        "--set",
        "bundled.prometheus.enabled=false",
        "--set",
        "externalLoki.url=https://loki.example.com",
        "--set",
        "externalLoki.auth.username=alice",
        "--set",
        "externalLoki.auth.password=s3cr3t",
        "--set",
        "grafana.externalPrometheusUrl=https://prom.example.com/",
    )
    ds_cm2 = next(d for d in docs_prom if d.get("kind") == "ConfigMap" and d["metadata"]["name"] == "rel-nxtflow-grafana-datasources")
    ds_cfg2 = yaml.safe_load(ds_cm2["data"]["nxtflow-datasources.yaml"])
    datasources2 = {d["name"]: d for d in ds_cfg2["datasources"]}
    assert datasources2["Prometheus"]["url"] == "https://prom.example.com"
    assert datasources2["Loki"]["basicAuth"] is True
    assert datasources2["Loki"]["basicAuthUser"] == "alice"
    assert datasources2["Loki"]["secureJsonData"]["basicAuthPassword"] == "s3cr3t"


def test_helm_enricher_http_ingest_disabled_moves_probes_to_metrics() -> None:
    docs = _render_chart("rel", "--set", "enricher.ingest.http.enabled=false")
    dep = next(d for d in docs if d.get("kind") == "Deployment" and d["metadata"]["name"] == "rel-nxtflow-collector")
    enricher = next(c for c in dep["spec"]["template"]["spec"]["containers"] if c["name"] == "enricher")
    port_names = [p["name"] for p in enricher["ports"]]
    assert "http-ingest" not in port_names
    assert "metrics" in port_names
    assert enricher["livenessProbe"]["httpGet"] == {"path": "/healthz", "port": "metrics"}
    assert enricher["readinessProbe"]["httpGet"] == {"path": "/healthz", "port": "metrics"}


def test_helm_alloy_auth_ca_and_mcp_tls_forwarding() -> None:
    docs = _render_chart(
        "rel",
        "--set",
        "tags.standalone=false",
        "--set",
        "externalLoki.url=https://loki.example.com",
        "--set",
        "externalLoki.tenantId=org1",
        "--set",
        "externalLoki.auth.username=u1",
        "--set",
        "externalLoki.auth.password=p1",
        "--set",
        "externalLoki.tls.caFile=/etc/nxtflow/ca/ca.crt",
        "--set",
        "externalLoki.tls.existingCaConfigMap=custom-loki-ca",
        "--set",
        "enricher.shipper.mode=alloy",
    )
    alloy_cm = next(d for d in docs if d.get("kind") == "ConfigMap" and d["metadata"]["name"] == "rel-nxtflow-alloy")
    alloy_cfg = alloy_cm["data"]["config.alloy"]
    assert "basic_auth {" in alloy_cfg
    assert 'sys.env("NXTFLOW_LOKI_USERNAME")' in alloy_cfg
    assert 'sys.env("NXTFLOW_LOKI_PASSWORD")' in alloy_cfg
    assert 'ca_file = "/etc/nxtflow/ca/ca.crt"' in alloy_cfg
    assert 'tenant_id = "org1"' in alloy_cfg

    col_dep = next(d for d in docs if d.get("kind") == "Deployment" and d["metadata"]["name"] == "rel-nxtflow-collector")
    col_containers = {c["name"]: c for c in col_dep["spec"]["template"]["spec"]["containers"]}
    alloy_env = {e["name"]: e for e in col_containers["alloy"]["env"]}
    assert alloy_env["NXTFLOW_LOKI_USERNAME"]["valueFrom"]["secretKeyRef"]["name"] == "rel-nxtflow-loki-auth"
    assert alloy_env["NXTFLOW_LOKI_PASSWORD"]["valueFrom"]["secretKeyRef"]["name"] == "rel-nxtflow-loki-auth"
    assert any(v["name"] == "external-loki-ca" for v in col_dep["spec"]["template"]["spec"]["volumes"])

    mcp_dep = next(d for d in docs if d.get("kind") == "Deployment" and d["metadata"]["name"] == "rel-nxtflow-mcp")
    mcp_c = mcp_dep["spec"]["template"]["spec"]["containers"][0]
    mcp_env = {e["name"]: e["value"] for e in mcp_c["env"] if "value" in e}
    assert mcp_env["NXTFLOW_TLS_VERIFY"] == "/etc/nxtflow/ca/ca.crt"
    assert any(v["name"] == "external-loki-ca" for v in mcp_dep["spec"]["template"]["spec"]["volumes"])

    # Bearer token mode in Alloy
    docs_bearer = _render_chart(
        "rel",
        "--set",
        "tags.standalone=false",
        "--set",
        "externalLoki.url=https://loki.example.com",
        "--set",
        "externalLoki.auth.bearerToken=tok-xyz",
        "--set",
        "enricher.shipper.mode=alloy",
    )
    alloy_cm_b = next(d for d in docs_bearer if d.get("kind") == "ConfigMap" and d["metadata"]["name"] == "rel-nxtflow-alloy")
    assert 'bearer_token = sys.env("NXTFLOW_LOKI_TOKEN")' in alloy_cm_b["data"]["config.alloy"]


def test_helm_transport_ingest_mismatch_fails() -> None:
    helm_bin = _require_helm()
    for args in (
        ["--set", "collector.goflow2.transport=http", "--set", "enricher.ingest.http.enabled=false"],
        ["--set", "collector.goflow2.transport=file", "--set", "enricher.ingest.file.enabled=false"],
    ):
        res = subprocess.run([helm_bin, "template", "bad", str(CHART_DIR), *args], capture_output=True, text=True, check=False)
        assert res.returncode != 0, f"Expected failure for {args}, but succeeded"


def test_sync_gh_pages_rewrites_relative_examples_links(tmp_path: Path) -> None:
    spec = importlib.util.spec_from_file_location("sync_gh_pages", REPO_ROOT / ".github" / "scripts" / "sync_gh_pages.py")
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    exporters_md = (REPO_ROOT / "docs" / "exporters.md").read_text(encoding="utf-8")
    rewritten = mod.rewrite_links(exporters_md)
    assert "../" not in rewritten
    assert "https://github.com/nertwork/nxtflow/blob/main/examples/exporters/mikrotik-routeros.rsc" in rewritten


def test_tier5_helm_subchart_names_ingress_ca_dashboard_ports_and_tags() -> None:
    helm_bin = _require_helm()

    # H1: Release names containing loki, prometheus, grafana match subchart service naming
    for rel, expected_loki, expected_prom, expected_graf in (
        ("loki", "http://loki:3100", "http://loki-prometheus-server:80", "svc/loki-grafana"),
        ("prometheus", "http://prometheus-loki:3100", "http://prometheus-server:80", "svc/prometheus-grafana"),
        ("grafana", "http://grafana-loki:3100", "http://grafana-prometheus-server:80", "svc/grafana"),
    ):
        docs = _render_chart(rel, "--set", "tags.standalone=true")
        ds_cm = next(d for d in docs if d.get("kind") == "ConfigMap" and d["metadata"]["name"].endswith("-grafana-datasources"))
        ds_cfg = yaml.safe_load(ds_cm["data"]["nxtflow-datasources.yaml"])
        by_name = {d["name"]: d for d in ds_cfg["datasources"]}
        assert by_name["Loki"]["url"] == expected_loki
        assert by_name["Prometheus"]["url"] == expected_prom
        enr_cm = next(d for d in docs if d.get("kind") == "ConfigMap" and d["metadata"]["name"].endswith("-enricher"))
        assert yaml.safe_load(enr_cm["data"]["enricher.yaml"])["shipper"]["loki"]["url"] == expected_loki
        svc_names = {d["metadata"]["name"] for d in docs if d.get("kind") == "Service"}
        assert expected_loki.removeprefix("http://").split(":", 1)[0] in svc_names
        assert expected_prom.removeprefix("http://").split(":", 1)[0] in svc_names
        assert expected_graf.removeprefix("svc/") in svc_names
        notes_tpl = (CHART_DIR / "templates" / "NOTES.txt").read_text(encoding="utf-8")
        assert 'include "nxtflow.bundledGrafanaService"' in notes_tpl
        assert 'include "nxtflow.bundledLokiService"' in notes_tpl

    # H3: mcp.ingress.enabled=true requires non-empty hosts and paths
    for bad_args in (
        ["--set", "mcp.enabled=true", "--set", "mcp.ingress.enabled=true"],
        ["--set", "mcp.enabled=true", "--set", "mcp.ingress.enabled=true", "--set", "mcp.ingress.hosts[0].host=mcp.example.com"],
    ):
        res = subprocess.run([helm_bin, "template", "bad", str(CHART_DIR), *bad_args], capture_output=True, text=True, check=False)
        assert res.returncode != 0
    ok_ing = _render_chart(
        "ok",
        "--set", "mcp.enabled=true",
        "--set", "mcp.ingress.enabled=true",
        "--set", "mcp.ingress.hosts[0].host=mcp.example.com",
        "--set", "mcp.ingress.hosts[0].paths[0].path=/",
        "--set", "mcp.ingress.hosts[0].paths[0].pathType=Prefix",
    )
    assert any(d.get("kind") == "Ingress" for d in ok_ing)

    # H4: existingCaConfigMap without explicit caFile defaults to /etc/nxtflow/ca/ca.crt across all templates
    ca_docs = _render_chart(
        "rel",
        "--set", "tags.standalone=false",
        "--set", "externalLoki.url=https://loki.example.com",
        "--set", "externalLoki.tls.existingCaConfigMap=corp-ca",
        "--set", "enricher.shipper.mode=alloy",
    )
    enr_yaml = yaml.safe_load(
        next(d for d in ca_docs if d.get("kind") == "ConfigMap" and d["metadata"]["name"] == "rel-nxtflow-enricher")["data"]["enricher.yaml"]
    )
    assert enr_yaml["shipper"]["loki"]["caFile"] == "/etc/nxtflow/ca/ca.crt"
    alloy_txt = next(d for d in ca_docs if d.get("kind") == "ConfigMap" and d["metadata"]["name"] == "rel-nxtflow-alloy")["data"]["config.alloy"]
    assert 'ca_file = "/etc/nxtflow/ca/ca.crt"' in alloy_txt
    mcp_dep = next(d for d in ca_docs if d.get("kind") == "Deployment" and d["metadata"]["name"] == "rel-nxtflow-mcp")
    mcp_env = {e["name"]: e.get("value") for e in mcp_dep["spec"]["template"]["spec"]["containers"][0]["env"]}
    assert mcp_env["NXTFLOW_TLS_VERIFY"] == "/etc/nxtflow/ca/ca.crt"

    # M1: Dashboard JSON escaping with quotes/backslashes, <fullname>-metrics selector, Prometheus UID guard
    for engine in ("echarts", "netsage"):
        m1_docs = _render_chart(
            "rel",
            "--set", "tags.standalone=true",
            "--set", "bundled.prometheus.enabled=false",
            "--set", f"grafana.sankey.engine={engine}",
            "--set", r'collector.job=bad"job	est',
            "--set", r'enricher.classification.excludedHosts={a"b,c\d}',
        )
        dash_cm = next(d for d in m1_docs if d.get("kind") == "ConfigMap" and d["metadata"]["name"] == "rel-nxtflow-dashboard")
        parsed_dash = json.loads(dash_cm["data"]["nxtflow-overview.json"])
        col_panel = next(p for p in parsed_dash["panels"] if p.get("title") == "Collector")
        assert col_panel["targets"][0]["expr"] == 'max(up{service=~"rel-nxtflow-metrics"})'
        # Prometheus disabled + no externalPrometheusUrl -> ${DS_PROMETHEUS} preserved
        assert col_panel["datasource"]["uid"] == "${DS_PROMETHEUS}"

    # M2: Custom NetFlow/sFlow/Enricher ports propagate across Service, Deployment, ConfigMap
    m2_docs = _render_chart(
        "rel",
        "--set", "collector.goflow2.transport=http",
        "--set", "collector.service.netflowPort=9995",
        "--set", "collector.service.sflowPort=6344",
        "--set", "collector.metricsService.enricherPort=9191",
        "--set", "enricher.ingest.http.listenAddr=0.0.0.0:8091",
    )
    col_dep = next(d for d in m2_docs if d.get("kind") == "Deployment" and d["metadata"]["name"] == "rel-nxtflow-collector")
    containers = {c["name"]: c for c in col_dep["spec"]["template"]["spec"]["containers"]}
    assert "-listen=sflow://:6344,netflow://:9995" in containers["goflow2"]["args"]
    assert "-transport.http.destination=http://127.0.0.1:8091/ingest" in containers["goflow2"]["args"]
    enr_ports = {p["name"]: p["containerPort"] for p in containers["enricher"]["ports"]}
    assert enr_ports == {"http-ingest": 8091, "metrics": 9191}
    m2_enr = yaml.safe_load(
        next(d for d in m2_docs if d.get("kind") == "ConfigMap" and d["metadata"]["name"] == "rel-nxtflow-enricher")["data"]["enricher.yaml"]
    )
    assert m2_enr["metrics"]["listenAddr"] == "0.0.0.0:9191"

    # M4: Image tags default to v<Chart.AppVersion> when empty in values.yaml
    chart_meta = yaml.safe_load((CHART_DIR / "Chart.yaml").read_text(encoding="utf-8"))
    expected_tag = f"v{chart_meta['appVersion']}"
    default_docs = _render_chart("rel")
    d_col = next(d for d in default_docs if d.get("kind") == "Deployment" and d["metadata"]["name"] == "rel-nxtflow-collector")
    d_mcp = next(d for d in default_docs if d.get("kind") == "Deployment" and d["metadata"]["name"] == "rel-nxtflow-mcp")
    d_enr_img = next(c["image"] for c in d_col["spec"]["template"]["spec"]["containers"] if c["name"] == "enricher")
    assert d_enr_img.endswith(f":{expected_tag}")
    assert d_mcp["spec"]["template"]["spec"]["containers"][0]["image"].endswith(f":{expected_tag}")


def test_tier5_security_audit_patterns_and_sync_gh_pages_anchors(tmp_path: Path) -> None:
    mod_sec = _load_security_audit_module()

    dirty_dir = tmp_path / "dirty"
    dirty_dir.mkdir()
    sample = "\n".join(
        [
            "github_" + "pat_" + "A" * 24,
            "xox" + "b-" + "1234567890-abcdef",
            "hv" + "s." + "A1B2C3D4E5F6G7H8I9J0K1",
        ]
    )
    (dirty_dir / "leak.txt").write_text(sample, encoding="utf-8")
    hits = mod_sec.scan_directory(dirty_dir)
    assert len(hits) == 3

    spec_gh = importlib.util.spec_from_file_location("sync_gh_pages", REPO_ROOT / ".github" / "scripts" / "sync_gh_pages.py")
    assert spec_gh is not None and spec_gh.loader is not None
    mod_gh = importlib.util.module_from_spec(spec_gh)
    spec_gh.loader.exec_module(mod_gh)

    md = (
        "[Arch](architecture.md#loki) "
        "[DocsArch](docs/architecture.md#sankey) "
        "[Values](../charts/nxtflow/values.yaml) "
        "[Logo](../assets/logo.svg)"
    )
    out = mod_gh.rewrite_links(md)
    assert "(architecture.html#loki)" in out
    assert "(architecture.html#sankey)" in out
    assert "(https://github.com/nertwork/nxtflow/blob/main/charts/nxtflow/values.yaml)" in out
    assert "(../assets/logo.svg)" in out


def test_helm_grafana_datasource_sidecar_label_parameterized() -> None:
    default_docs = _render_chart("rel", "-f", str(EXAMPLES_DIR / "values-standalone.yaml"))
    default_ds = next(d for d in default_docs if d.get("kind") == "ConfigMap" and d["metadata"]["name"] == "rel-nxtflow-grafana-datasources")
    assert default_ds["metadata"]["labels"]["grafana_datasource"] == "1"

    custom_docs = _render_chart(
        "rel",
        "-f", str(EXAMPLES_DIR / "values-standalone.yaml"),
        "--set", "grafana.sidecar.datasources.label=custom_ds_label",
        "--set", "grafana.sidecar.datasources.labelValue=custom_val",
    )
    custom_ds = next(d for d in custom_docs if d.get("kind") == "ConfigMap" and d["metadata"]["name"] == "rel-nxtflow-grafana-datasources")
    assert "grafana_datasource" not in custom_ds["metadata"]["labels"]
    assert custom_ds["metadata"]["labels"]["custom_ds_label"] == "custom_val"
