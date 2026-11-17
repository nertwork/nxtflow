"""Unit and integration tests for nxtflow-enricher and default_cidrs."""

from __future__ import annotations

import gzip
import http.client
import io
import ipaddress
import json
import socket
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from nxtflow.enricher.app import (
    EnricherConfig,
    EnricherMetrics,
    EnricherPipeline,
    LokiShipper,
    RDNSCache,
    load_enricher_config,
    normalize_proto,
    parse_goflow2_batch,
)
from nxtflow.enricher.default_cidrs import (
    PUBLIC_CIDRS,
    PUBLIC_DOMAIN_SERVICES,
    PUBLIC_WELL_KNOWN_IPS,
    lookup_public_cidr,
    simplify_rdns,
)


def test_default_cidrs_strictly_public() -> None:
    cgnat = ipaddress.ip_network("100.64.0.0/10")
    rfc1918_a = ipaddress.ip_network("10.0.0.0/8")
    rfc1918_b = ipaddress.ip_network("172.16.0.0/12")
    rfc1918_c = ipaddress.ip_network("192.168.0.0/16")
    link_local_v4 = ipaddress.ip_network("169.254.0.0/16")

    for net, label in PUBLIC_CIDRS:
        assert not net.is_loopback, f"loopback in PUBLIC_CIDRS: {net}"
        assert not net.is_link_local, f"link-local in PUBLIC_CIDRS: {net}"
        assert not net.is_multicast, f"multicast in PUBLIC_CIDRS: {net}"
        if net.version == 4:
            assert not net.overlaps(cgnat), f"CGNAT overlap in PUBLIC_CIDRS: {net} ({label})"
            assert not net.overlaps(rfc1918_a), f"RFC1918 overlap in PUBLIC_CIDRS: {net}"
            assert not net.overlaps(rfc1918_b), f"RFC1918 overlap in PUBLIC_CIDRS: {net}"
            assert not net.overlaps(rfc1918_c), f"RFC1918 overlap in PUBLIC_CIDRS: {net}"
            assert not net.overlaps(link_local_v4), f"link-local overlap in PUBLIC_CIDRS: {net}"
        else:
            assert not net.is_private, f"private IPv6 in PUBLIC_CIDRS: {net}"

    for ip_str in PUBLIC_WELL_KNOWN_IPS:
        addr = ipaddress.ip_address(ip_str)
        assert addr.is_global, f"non-global well-known IP: {ip_str}"

    assert "apple.com" in PUBLIC_DOMAIN_SERVICES


def test_simplify_rdns_longest_suffix_and_fallback() -> None:
    assert simplify_rdns("courier.push.apple.com.") == "apple-push"
    assert simplify_rdns("p12-content.icloud-content.com") == "apple-icloud"
    assert simplify_rdns("www.apple.com") == "apple"
    assert simplify_rdns("host.internal.example.com", {"internal.example.com": "corp-internal"}) == "corp-internal"
    assert simplify_rdns("edge-01.cdn.example.net") == "example.net"
    assert simplify_rdns("192.0.2.10") == "192.0.2.10"


def test_lookup_public_cidr_longest_prefix_v4_and_v6() -> None:
    assert lookup_public_cidr("13.32.0.1") == "aws-cloudfront"
    assert lookup_public_cidr("3.10.20.30") == "aws"
    assert lookup_public_cidr("52.96.1.1") == "microsoft-365"
    assert lookup_public_cidr("52.112.1.1") == "ms-teams"
    assert lookup_public_cidr("2606:4700:4700::1111") == "cloudflare"
    assert lookup_public_cidr("2607:f8b0:4005:800::200e") == "google"
    assert lookup_public_cidr("192.168.1.10") is None
    assert lookup_public_cidr("not-an-ip") is None


def test_normalize_proto_and_sampling_scaling() -> None:
    assert normalize_proto(6) == "TCP"
    assert normalize_proto("17") == "UDP"
    assert normalize_proto(58) == "ICMPv6"
    assert normalize_proto("tcp") == "TCP"

    cfg = EnricherConfig(
        site="site-a",
        http_enabled=False,
        rdns_enabled=False,
        respect_sampling_rate=True,
        static_hosts={"192.168.1.10": "web-1"},
    )
    pipeline = EnricherPipeline(cfg)
    try:
        out = pipeline.enrich_flow(
            {
                "type": "SFLOW_5",
                "src_addr": "192.168.1.10",
                "dst_addr": "8.8.8.8",
                "bytes": 1500,
                "packets": 2,
                "proto": 17,
                "src_port": 51000,
                "dst_port": 53,
                "sampling_rate": 100,
            }
        )
        assert out == {
            "bytes": 150000,
            "packets": 200,
            "src_addr": "192.168.1.10",
            "dst_addr": "8.8.8.8",
            "src_host": "web-1",
            "dst_host": "google-dns",
            "proto": "UDP",
            "src_port": 51000,
            "dst_port": 53,
            "dir": "up",
            "site": "site-a",
        }

        cfg_no_scale = EnricherConfig(site="site-a", http_enabled=False, rdns_enabled=False, respect_sampling_rate=False)
        p2 = EnricherPipeline(cfg_no_scale)
        try:
            out2 = p2.enrich_flow(
                {
                    "src_addr": "8.8.8.8",
                    "dst_addr": "192.168.1.10",
                    "bytes": 500,
                    "packets": 1,
                    "proto": "TCP",
                    "src_port": 443,
                    "dst_port": 55555,
                    "sampling_rate": 100,
                }
            )
            assert out2 is not None
            assert out2["bytes"] == 500
            assert out2["packets"] == 1
            assert out2["dir"] == "down"
        finally:
            p2.rdns_cache.close()
    finally:
        pipeline.rdns_cache.close()


def test_direction_classification_v4_v6_and_wan_ips() -> None:
    cfg = EnricherConfig(
        http_enabled=False,
        rdns_enabled=False,
        wan_ips=["203.0.113.1"],
    )
    p = EnricherPipeline(cfg)
    try:
        assert p.classify_direction("192.168.1.5", "198.51.100.10") == "up"
        assert p.classify_direction("198.51.100.10", "192.168.1.5") == "down"
        assert p.classify_direction("192.168.1.5", "10.0.0.2") == "lan"
        assert p.classify_direction("fd00::1", "2001:4860:4860::8888") == "up"
        assert p.classify_direction("2001:4860:4860::8888", "fd00::1") == "down"
        assert p.classify_direction("198.51.100.10", "203.0.113.1") == "down"
        assert p.classify_direction("203.0.113.1", "198.51.100.10") == "up"
    finally:
        p.rdns_cache.close()


def test_resolution_precedence_and_rdns_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    now = [100.0]
    monkeypatch.setattr(time, "monotonic", lambda: now[0])

    calls: list[str] = []

    def fake_gethostbyaddr(ip: str) -> tuple[str, list[str], list[str]]:
        calls.append(ip)
        if ip == "198.51.100.5":
            return ("edge.example.com", [], [ip])
        if ip == "192.168.1.77":
            return ("priv.example.com", [], [ip])
        raise socket.herror("not found")

    monkeypatch.setattr(socket, "gethostbyaddr", fake_gethostbyaddr)

    metrics = EnricherMetrics()
    cache = RDNSCache(max_entries=2, ttl_seconds=60.0, negative_ttl_seconds=10.0, metrics=metrics)
    try:
        assert cache.resolve("198.51.100.5") == "example.com"
        assert cache.resolve("198.51.100.5") == "example.com"
        assert cache.resolve("198.51.100.99") is None
        assert cache.resolve("198.51.100.99") is None  # negative cache hit
        assert len(calls) == 2

        # Evict LRU (198.51.100.5) when inserting 3rd entry
        assert cache.resolve("198.51.100.6") is None
        assert cache.resolve("198.51.100.5") == "example.com"
        assert calls.count("198.51.100.5") == 2

        # Expire positive TTL
        now[0] += 61.0
        assert cache.resolve("198.51.100.5") == "example.com"
        assert calls.count("198.51.100.5") == 3
    finally:
        cache.close()

    # Pipeline precedence check
    cfg = EnricherConfig(
        http_enabled=False,
        static_hosts={"192.168.1.10": "static-web"},
        internal_cidrs=[{"cidr": "10.244.0.0/16", "name": "k8s-pods"}],
        extra_cidrs=[{"cidr": "203.0.113.0/24", "name": "partner-dmz"}],
        rdns_private=False,
    )
    p = EnricherPipeline(cfg)
    p.netbox._hosts = {"192.168.1.10": "nb-web", "192.168.1.20": "nb-db"}
    try:
        assert p.resolve_host("192.168.1.10") == "static-web"
        assert p.resolve_host("192.168.1.20") == "nb-db"
        assert p.resolve_host("224.0.0.251") == "multicast"
        assert p.resolve_host("169.254.1.1") == "link-local"
        assert p.resolve_host("192.168.1.255") == "broadcast"
        assert p.resolve_host("10.244.1.9") == "k8s-pods"
        assert p.resolve_host("192.168.1.77") == "192.168.1.77"
        assert p.resolve_host("203.0.113.42") == "partner-dmz"
        assert p.resolve_host("198.51.100.5") == "example.com"
    finally:
        p.rdns_cache.close()


def test_netbox_paginated_sync_and_failure_retention() -> None:
    fail_mode = [False]
    seen_auth: list[str] = []

    class NetBoxHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            return

        def do_GET(self) -> None:
            seen_auth.append(self.headers.get("Authorization", ""))
            if fail_mode[0]:
                self.send_response(500)
                self.end_headers()
                return
            port = self.server.server_address[1]
            if "page=2" in self.path:
                payload = {
                    "next": None,
                    "results": [
                        {
                            "address": "192.168.1.30/24",
                            "dns_name": "",
                            "assigned_object": {"device": {"name": "switch-1.example.com"}},
                        }
                    ],
                }
            else:
                payload = {
                    "next": f"http://127.0.0.1:{port}/api/ipam/ip-addresses/?limit=1000&page=2",
                    "results": [
                        {"address": "192.168.1.10/24", "dns_name": "app-1.example.com", "assigned_object": None},
                        {
                            "address": "192.168.1.20/24",
                            "dns_name": "",
                            "assigned_object": {"virtual_machine": {"name": "vm-2.example.com"}},
                        },
                    ],
                }
            body = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), NetBoxHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        port = srv.server_address[1]
        cfg = EnricherConfig(
            http_enabled=False,
            netbox_enabled=True,
            netbox_url=f"http://127.0.0.1:{port}",
            netbox_token="test-nb-token",
            netbox_strip_domain=True,
        )
        p = EnricherPipeline(cfg)
        try:
            assert p.netbox.sync_once() is True
            assert seen_auth[0] == "Token test-nb-token"
            assert p.netbox.lookup("192.168.1.10") == "app-1"
            assert p.netbox.lookup("192.168.1.20") == "vm-2"
            assert p.netbox.lookup("192.168.1.30") == "switch-1"

            fail_mode[0] = True
            assert p.netbox.sync_once() is False
            assert p.netbox.lookup("192.168.1.10") == "app-1"
            metrics_text = p.metrics.render().decode("utf-8")
            assert "nxtflow_netbox_sync_errors_total 1.0" in metrics_text
            assert "nxtflow_netbox_hosts_cached 3.0" in metrics_text
        finally:
            p.rdns_cache.close()
    finally:
        srv.shutdown()
        srv.server_close()


def test_http_ingest_loki_push_retry_and_metrics() -> None:
    pushed_batches: list[dict] = []
    loki_mode = ["503_once"]  # 503 once -> 204, then 400 test
    attempt_count = [0]

    class LokiMockHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            return

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            attempt_count[0] += 1
            if loki_mode[0] == "503_once" and attempt_count[0] == 1:
                self.send_response(503)
                self.end_headers()
                return
            if loki_mode[0] == "400":
                self.send_response(400)
                self.end_headers()
                return
            assert self.headers.get("Content-Encoding") == "gzip"
            assert self.headers.get("X-Scope-OrgID") == "tenant-1"
            decoded = json.loads(gzip.decompress(raw).decode("utf-8"))
            pushed_batches.append(decoded)
            self.send_response(204)
            self.end_headers()

    loki_srv = ThreadingHTTPServer(("127.0.0.1", 0), LokiMockHandler)
    t = threading.Thread(target=loki_srv.serve_forever, daemon=True)
    t.start()
    try:
        loki_port = loki_srv.server_address[1]
        cfg = EnricherConfig(
            site="edge-1",
            job="nxtflow",
            http_enabled=True,
            http_listen_addr="127.0.0.1:0",
            metrics_listen_addr="127.0.0.1:0",
            rdns_enabled=False,
            loki_url=f"http://127.0.0.1:{loki_port}",
            loki_tenant_id="tenant-1",
            batch_max_entries=10,
            batch_max_wait_seconds=0.1,
            max_retries=2,
            initial_backoff_seconds=0.01,
            max_backoff_seconds=0.05,
        )
        pipeline = EnricherPipeline(cfg)
        pipeline.start()
        try:
            base = f"http://127.0.0.1:{pipeline.http_port}"
            mbase = f"http://127.0.0.1:{pipeline.metrics_port}"

            with urllib.request.urlopen(f"{base}/healthz", timeout=5) as r:
                assert r.status == 200
            with urllib.request.urlopen(f"{base}/readyz", timeout=5) as r:
                assert r.status == 200

            # 1) Single JSON object
            req1 = urllib.request.Request(
                f"{base}/ingest",
                data=json.dumps(
                    {
                        "src_addr": "192.168.1.10",
                        "dst_addr": "1.1.1.1",
                        "bytes": 1000,
                        "packets": 5,
                        "proto": "UDP",
                        "src_port": 50000,
                        "dst_port": 53,
                    }
                ).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req1, timeout=5) as r:
                assert r.status == 202
                assert json.loads(r.read().decode()) == {"accepted": 1, "errors": 0}

            # 2) Gzipped JSON array
            arr_gz = gzip.compress(
                json.dumps(
                    [
                        {
                            "src_addr": "1.1.1.1",
                            "dst_addr": "192.168.1.10",
                            "bytes": 2000,
                            "packets": 4,
                            "proto": "UDP",
                            "src_port": 53,
                            "dst_port": 50000,
                            "time_received_ns": 2000000000,
                        },
                        {
                            "src_addr": "192.168.1.10",
                            "dst_addr": "192.168.1.20",
                            "bytes": 500,
                            "packets": 2,
                            "proto": "TCP",
                            "src_port": 443,
                            "dst_port": 51000,
                            "time_received_ns": 1000000000,
                        },
                    ]
                ).encode("utf-8")
            )
            req2 = urllib.request.Request(
                f"{base}/ingest/goflow2",
                data=arr_gz,
                headers={"Content-Type": "application/json", "Content-Encoding": "gzip"},
                method="POST",
            )
            with urllib.request.urlopen(req2, timeout=5) as r:
                assert r.status == 202
                assert json.loads(r.read().decode())["accepted"] == 2

            # 3) NDJSON with 1 invalid line
            ndjson = (
                b'{"src_addr":"192.168.1.10","dst_addr":"8.8.8.8","bytes":300,"packets":1,"proto":"TCP","src_port":1,"dst_port":443}\n'
                b"{not-json}\n"
            )
            req3 = urllib.request.Request(
                f"{base}/ingest",
                data=ndjson,
                headers={"Content-Type": "application/x-ndjson"},
                method="POST",
            )
            with urllib.request.urlopen(req3, timeout=5) as r:
                assert r.status == 202
                assert json.loads(r.read().decode()) == {"accepted": 1, "errors": 1}

            # 4) Completely unparseable JSON returns 400
            req_bad = urllib.request.Request(f"{base}/ingest", data=b"{bad", method="POST")
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(req_bad, timeout=5)
            assert exc_info.value.code == 400

            pipeline.flush()
            assert len(pushed_batches) >= 1
            all_streams = [s for b in pushed_batches for s in b["streams"]]
            assert any(s["stream"] == {"job": "nxtflow", "site": "edge-1", "dir": "up"} for s in all_streams)
            for s in all_streams:
                ts_vals = [int(v[0]) for v in s["values"]]
                assert ts_vals == sorted(ts_vals)
                for _ts, line in s["values"]:
                    rec = json.loads(line)
                    assert set(rec.keys()) == {
                        "bytes",
                        "packets",
                        "src_addr",
                        "dst_addr",
                        "src_host",
                        "dst_host",
                        "proto",
                        "src_port",
                        "dst_port",
                        "dir",
                        "site",
                    }

            # 5) Test 400 non-retryable drop
            loki_mode[0] = "400"
            pipeline.ingest_records(
                [
                    {
                        "src_addr": "192.168.1.10",
                        "dst_addr": "8.8.8.8",
                        "bytes": 100,
                        "packets": 1,
                        "proto": "TCP",
                        "src_port": 1000,
                        "dst_port": 443,
                    }
                ]
            )
            pipeline.flush()

            # 6) Verify exact Prometheus metrics and NO _total_total bug
            with urllib.request.urlopen(f"{mbase}/metrics", timeout=5) as r:
                metrics_body = r.read().decode("utf-8")
            assert "_total_total" not in metrics_body
            for expected in (
                "nxtflow_flows_received_total",
                "nxtflow_bytes_total",
                "nxtflow_loki_push_requests_total",
                "nxtflow_loki_push_errors_total",
                "nxtflow_dropped_flows_total",
                "nxtflow_rdns_cache_hits_total",
                "nxtflow_rdns_cache_misses_total",
                "nxtflow_ring_buffer_size",
                "nxtflow_netbox_hosts_cached",
                "nxtflow_netbox_sync_errors_total",
            ):
                assert expected in metrics_body, f"Missing metric {expected}"
        finally:
            pipeline.stop()
    finally:
        loki_srv.shutdown()
        loki_srv.server_close()


def test_ring_buffer_overflow_and_file_shipper_truncation(tmp_path: Path) -> None:
    out_file = tmp_path / "flows.jsonl"
    cfg = EnricherConfig(
        http_enabled=False,
        rdns_enabled=False,
        metrics_listen_addr="127.0.0.1:0",
        shipper_mode="file",
        shipper_file_path=str(out_file),
        shipper_file_truncate_bytes=1024,
        ring_buffer_max_flows=2,
        batch_max_entries=10,
    )
    p = EnricherPipeline(cfg)
    try:
        for idx in range(5):
            p.ingest_records(
                [
                    {
                        "src_addr": "192.168.1.10",
                        "dst_addr": "8.8.8.8",
                        "bytes": 100 + idx,
                        "packets": 1,
                        "proto": "TCP",
                        "src_port": 1000 + idx,
                        "dst_port": 443,
                    }
                ]
            )
        metrics_text = p.metrics.render().decode("utf-8")
        assert "nxtflow_dropped_flows_total 3.0" in metrics_text
        p.flush()
        lines = out_file.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 2
    finally:
        p.rdns_cache.close()


def test_file_tailer_and_stdin_ingest(tmp_path: Path) -> None:
    raw_file = tmp_path / "raw.jsonl"
    pos_file = tmp_path / "enricher.pos"
    out_file = tmp_path / "flows.jsonl"

    raw_file.write_text('{"src_addr":"192.168.1.10","dst_addr":"1.1.1.1","bytes":100,"packets":1,"proto":"UDP","src_port":1111,"dst_port":53}\n', encoding="utf-8")

    cfg = EnricherConfig(
        http_enabled=False,
        metrics_listen_addr="127.0.0.1:0",
        file_enabled=True,
        file_path=str(raw_file),
        file_position_file=str(pos_file),
        file_poll_interval=0.05,
        file_truncate_bytes=200,
        shipper_mode="file",
        shipper_file_path=str(out_file),
        shipper_file_truncate_bytes=0,
        batch_max_wait_seconds=0.05,
        rdns_enabled=False,
    )
    p = EnricherPipeline(cfg)
    p.start()
    try:
        deadline = time.time() + 3.0
        while time.time() < deadline and not out_file.exists():
            time.sleep(0.05)
        assert out_file.exists()

        # Write partial line, then complete it, exceeding truncateAtBytes=200
        with raw_file.open("a", encoding="utf-8") as fh:
            fh.write('{"src_addr":"192.168.1.10","dst_addr":"8.8.8.8",')
        time.sleep(0.1)
        with raw_file.open("a", encoding="utf-8") as fh:
            fh.write('"bytes":250,"packets":1,"proto":"TCP","src_port":2222,"dst_port":443}\n')

        deadline = time.time() + 3.0
        while time.time() < deadline:
            if out_file.exists() and len(out_file.read_text(encoding="utf-8").splitlines()) >= 2:
                break
            time.sleep(0.05)
        lines = out_file.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 2
    finally:
        p.stop()

    # Stdin reader test
    stdin_out = tmp_path / "stdin_flows.jsonl"
    fake_stdin = io.StringIO(
        '{"src_addr":"192.168.1.10","dst_addr":"9.9.9.9","bytes":400,"packets":2,"proto":"UDP","src_port":3333,"dst_port":53}\n'
    )
    cfg_stdin = EnricherConfig(
        http_enabled=False,
        metrics_listen_addr="127.0.0.1:0",
        stdin_enabled=True,
        shipper_mode="file",
        shipper_file_path=str(stdin_out),
        shipper_file_truncate_bytes=0,
        batch_max_wait_seconds=0.05,
        rdns_enabled=False,
    )
    p2 = EnricherPipeline(cfg_stdin, stdin_stream=fake_stdin)
    p2.start()
    try:
        deadline = time.time() + 3.0
        while time.time() < deadline and not stdin_out.exists():
            time.sleep(0.05)
        p2.flush()
        assert len(stdin_out.read_text(encoding="utf-8").splitlines()) == 1
    finally:
        p2.stop()


def test_load_enricher_config_yaml_and_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg_file = tmp_path / "enricher.yaml"
    cfg_file.write_text(
        """
collector:
  site: dc-west
  job: customflow
ingest:
  file:
    enabled: true
    path: "-"
shipper:
  loki:
    url: http://loki.example.com:3100
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("NXTFLOW_CONFIG_FILE", str(cfg_file))
    monkeypatch.setenv("NXTFLOW_SITE", "dc-east")
    cfg = load_enricher_config()
    assert cfg.site == "dc-east"
    assert cfg.job == "customflow"
    assert cfg.stdin_enabled is True
    assert cfg.file_enabled is False
    assert cfg.loki_url == "http://loki.example.com:3100"


def test_parse_goflow2_batch_multiline_and_ndjson_arrays() -> None:
    pretty_obj = b"""{
  "src_addr": "192.168.1.10",
  "dst_addr": "1.1.1.1",
  "bytes": 420,
  "packets": 3,
  "proto": "UDP",
  "src_port": 50000,
  "dst_port": 53
}"""
    recs, errs = parse_goflow2_batch(pretty_obj)
    assert errs == 0
    assert len(recs) == 1
    assert recs[0]["bytes"] == 420

    ndjson_arrays = (
        b'[{"src_addr":"192.168.1.10","dst_addr":"1.1.1.1","bytes":100,"packets":1}]\n'
        b'[{"src_addr":"192.168.1.11","dst_addr":"8.8.8.8","bytes":200,"packets":2}]\n'
    )
    recs2, errs2 = parse_goflow2_batch(ndjson_arrays)
    assert errs2 == 0
    assert len(recs2) == 2
    assert recs2[1]["dst_addr"] == "8.8.8.8"


def test_resolve_host_public_dot255_not_broadcast() -> None:
    cfg = EnricherConfig(http_enabled=False, rdns_enabled=False, use_default_cidrs=True)
    p = EnricherPipeline(cfg)
    try:
        assert p.resolve_host("255.255.255.255") == "broadcast"
        assert p.resolve_host("192.168.1.255") == "broadcast"
        assert p.resolve_host("8.8.0.255") != "broadcast"
        assert p.resolve_host("198.51.100.255") == "198.51.100.255"
    finally:
        p.rdns_cache.close()


def test_http_ingest_chunked_negative_cl_and_413_keepalive() -> None:
    cfg = EnricherConfig(
        site="edge-http",
        http_enabled=True,
        http_listen_addr="127.0.0.1:0",
        metrics_listen_addr="127.0.0.1:0",
        rdns_enabled=False,
        max_body_bytes=512,
    )
    p = EnricherPipeline(cfg)
    p.start()
    try:
        port = p.http_port

        def _raw_http_exchange(raw_req: bytes) -> tuple[int, dict[str, str], bytes]:
            with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                sock.sendall(raw_req)
                r = http.client.HTTPResponse(sock)
                r.begin()
                data = r.read()
                hdrs = {k.lower(): v for k, v in r.getheaders()}
                return r.status, hdrs, data

        # 1) 413 sets Connection: close and prevents keep-alive stream desync
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("POST", "/ingest", body=b"A" * 600, headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        body = resp.read()
        assert resp.status == 413
        assert resp.getheader("Connection", "").lower() == "close"
        assert b"maxBodyBytes" in body
        # http.client closes the socket automatically on Connection: close; re-requesting opens a clean connection
        conn.request("GET", "/healthz")
        r2 = conn.getresponse()
        assert r2.status == 200
        r2.read()
        conn.close()

        # Also verify raw TCP socket actually sees EOF after 413 (no desynced 501)
        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            sock.sendall(
                b"POST /ingest HTTP/1.1\r\nHost: localhost\r\nContent-Length: 600\r\n\r\n" + (b"A" * 600)
            )
            r = http.client.HTTPResponse(sock)
            r.begin()
            assert r.status == 413
            r.read()
            assert sock.recv(1024) == b""

        # 2) Negative and invalid Content-Length rejected with 400
        st_neg, _, _ = _raw_http_exchange(
            b"POST /ingest HTTP/1.1\r\nHost: localhost\r\nContent-Length: -5\r\n\r\n"
        )
        assert st_neg == 400
        st_bad_cl, _, _ = _raw_http_exchange(
            b"POST /ingest HTTP/1.1\r\nHost: localhost\r\nContent-Length: abc\r\n\r\n"
        )
        assert st_bad_cl == 400

        # 3) Transfer-Encoding: chunked genuinely ingests flows
        flow_bytes = json.dumps(
            {
                "src_addr": "192.168.1.10",
                "dst_addr": "1.1.1.1",
                "bytes": 250,
                "packets": 2,
                "proto": "UDP",
                "src_port": 51234,
                "dst_port": 53,
            }
        ).encode("utf-8")
        part1, part2 = flow_bytes[:40], flow_bytes[40:]
        chunked_req = (
            b"POST /ingest HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Content-Type: application/json\r\n\r\n"
            + f"{len(part1):x}\r\n".encode("ascii")
            + part1
            + b"\r\n"
            + f"{len(part2):x}\r\n".encode("ascii")
            + part2
            + b"\r\n0\r\n\r\n"
        )
        st_chunk, _, body_chunk = _raw_http_exchange(chunked_req)
        assert st_chunk == 202
        assert json.loads(body_chunk.decode("utf-8")) == {"accepted": 1, "errors": 0}

        # 4) Chunked body exceeding max_body_bytes returns 413 + Connection: close
        big_chunk = b"X" * 600
        big_req = (
            b"POST /ingest HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
            + f"{len(big_chunk):x}\r\n".encode("ascii")
            + big_chunk
            + b"\r\n0\r\n\r\n"
        )
        st_big, hdr_big, _ = _raw_http_exchange(big_req)
        assert st_big == 413
        assert hdr_big.get("connection", "").lower() == "close"

        # 5) Malformed chunk framing returns 400
        bad_chunk_req = (
            b"POST /ingest HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
            b"ZZZZ\r\nhello\r\n0\r\n\r\n"
        )
        st_bad_chunk, _, _ = _raw_http_exchange(bad_chunk_req)
        assert st_bad_chunk == 400
    finally:
        p.stop()


def test_loki_shipper_retries_on_bad_status_line() -> None:
    attempts = [0]
    received_ok = [0]

    def raw_loki_server(srv_sock: socket.socket, stop_ev: threading.Event) -> None:
        srv_sock.settimeout(0.2)
        while not stop_ev.is_set():
            try:
                conn, _ = srv_sock.accept()
            except TimeoutError:
                continue
            with conn:
                conn.settimeout(2.0)
                buf = b""
                while b"\r\n\r\n" not in buf:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                header_part, _, rest = buf.partition(b"\r\n\r\n")
                cl = 0
                for line in header_part.split(b"\r\n")[1:]:
                    if line.lower().startswith(b"content-length:"):
                        cl = int(line.split(b":", 1)[1].strip())
                while len(rest) < cl:
                    more = conn.recv(4096)
                    if not more:
                        break
                    rest += more
                attempts[0] += 1
                if attempts[0] == 1:
                    conn.sendall(b"NOT_VALID_HTTP\r\n\r\n")
                else:
                    received_ok[0] += 1
                    conn.sendall(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")

    srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv_sock.bind(("127.0.0.1", 0))
    srv_sock.listen(5)
    port = srv_sock.getsockname()[1]
    stop_ev = threading.Event()
    t = threading.Thread(target=raw_loki_server, args=(srv_sock, stop_ev), daemon=True)
    t.start()
    try:
        cfg = EnricherConfig(
            http_enabled=False,
            metrics_listen_addr="127.0.0.1:0",
            rdns_enabled=False,
            loki_url=f"http://127.0.0.1:{port}",
            max_retries=2,
            initial_backoff_seconds=0.01,
            max_backoff_seconds=0.05,
        )
        p = EnricherPipeline(cfg)
        p.start()
        try:
            p.ingest_records(
                [
                    {
                        "src_addr": "192.168.1.10",
                        "dst_addr": "1.1.1.1",
                        "bytes": 500,
                        "packets": 1,
                        "proto": "UDP",
                        "src_port": 50000,
                        "dst_port": 53,
                    }
                ]
            )
            p.flush()
            assert attempts[0] == 2
            assert received_ok[0] == 1
            metrics_text = p.metrics.render().decode("utf-8")
            assert 'nxtflow_loki_push_requests_total{status="error"} 1.0' in metrics_text
            assert 'nxtflow_loki_push_requests_total{status="2xx"} 1.0' in metrics_text
            assert "nxtflow_dropped_flows_total 0.0" in metrics_text
        finally:
            p.stop()
    finally:
        stop_ev.set()
        t.join(timeout=2.0)
        srv_sock.close()


def test_file_shipper_truncates_before_write_preserving_latest_batch(tmp_path: Path) -> None:
    out_file = tmp_path / "shipped.jsonl"
    cfg = EnricherConfig(
        http_enabled=False,
        metrics_listen_addr="127.0.0.1:0",
        rdns_enabled=False,
        shipper_mode="file",
        shipper_file_path=str(out_file),
        shipper_file_truncate_bytes=120,
    )
    p = EnricherPipeline(cfg)
    try:
        p.ingest_records(
            [{"src_addr": "192.168.1.10", "dst_addr": "1.1.1.1", "bytes": 111, "packets": 1, "proto": "TCP", "src_port": 1001, "dst_port": 443}]
        )
        p.flush()
        first_lines = out_file.read_text(encoding="utf-8").splitlines()
        assert len(first_lines) == 1
        assert json.loads(first_lines[0])["bytes"] == 111
        assert out_file.stat().st_size >= 120

        # Next flush sees file >= truncate threshold and truncates BEFORE writing batch 2
        p.ingest_records(
            [{"src_addr": "192.168.1.10", "dst_addr": "8.8.8.8", "bytes": 222, "packets": 1, "proto": "TCP", "src_port": 1002, "dst_port": 443}]
        )
        p.flush()
        second_lines = out_file.read_text(encoding="utf-8").splitlines()
        assert len(second_lines) == 1
        assert json.loads(second_lines[0])["bytes"] == 222
    finally:
        p.rdns_cache.close()


def test_netbox_relative_next_and_readyz_not_wedged_on_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    class RelNetBoxHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            return

        def do_GET(self) -> None:
            if "page=2" in self.path:
                payload = {
                    "next": None,
                    "results": [{"address": "192.168.1.50/24", "dns_name": "nb-rel-2", "assigned_object": None}],
                }
            else:
                payload = {
                    "next": "/api/ipam/ip-addresses/?limit=1000&page=2",
                    "results": [{"address": "192.168.1.40/24", "dns_name": "nb-rel-1", "assigned_object": None}],
                }
            body = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), RelNetBoxHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        port = srv.server_address[1]
        cfg = EnricherConfig(
            http_enabled=False,
            netbox_enabled=True,
            netbox_url=f"http://127.0.0.1:{port}",
        )
        p = EnricherPipeline(cfg)
        try:
            assert p.netbox.sync_once() is True
            assert p.netbox.lookup("192.168.1.40") == "nb-rel-1"
            assert p.netbox.lookup("192.168.1.50") == "nb-rel-2"
        finally:
            p.rdns_cache.close()
    finally:
        srv.shutdown()
        srv.server_close()

    # Verify /readyz still becomes 200 even if initial sync_once raises an unexpected exception
    cfg_fail = EnricherConfig(
        http_enabled=True,
        http_listen_addr="127.0.0.1:0",
        metrics_listen_addr="127.0.0.1:0",
        netbox_enabled=True,
        netbox_url="http://127.0.0.1:1",
        netbox_sync_interval=60.0,
        rdns_enabled=False,
    )
    p2 = EnricherPipeline(cfg_fail)
    monkeypatch.setattr(p2.netbox, "sync_once", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    p2.start()
    try:
        deadline = time.time() + 3.0
        status_code = 503
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{p2.http_port}/readyz", timeout=2) as r:
                    status_code = r.status
                    break
            except urllib.error.HTTPError as exc:
                status_code = exc.code
                time.sleep(0.05)
        assert status_code == 200
    finally:
        p2.stop()


def test_parse_goflow2_batch_truncated_and_corrupt_gzip_raises_value_error_and_400() -> None:
    compressed = gzip.compress(b'{"src_addr":"192.168.1.10","dst_addr":"1.1.1.1","bytes":100}')
    truncated = compressed[:-6]
    with pytest.raises(ValueError, match="Invalid gzip payload"):
        parse_goflow2_batch(truncated, "gzip")

    corrupt_deflate = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff\xff\xff\xff\xff"
    with pytest.raises(ValueError, match="Invalid gzip payload"):
        parse_goflow2_batch(corrupt_deflate, "gzip")

    cfg = EnricherConfig(
        site="edge-gzip",
        http_enabled=True,
        http_listen_addr="127.0.0.1:0",
        metrics_listen_addr="127.0.0.1:0",
        rdns_enabled=False,
    )
    p = EnricherPipeline(cfg)
    p.start()
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{p.http_port}/ingest",
            data=truncated,
            headers={"Content-Type": "application/json", "Content-Encoding": "gzip"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req, timeout=5)
        assert exc_info.value.code == 400
    finally:
        p.stop()


def test_loki_shipper_retries_on_truncated_200_body() -> None:
    attempts = [0]
    received_ok = [0]

    def raw_loki_server(srv_sock: socket.socket, stop_ev: threading.Event) -> None:
        srv_sock.settimeout(0.2)
        while not stop_ev.is_set():
            try:
                conn, _ = srv_sock.accept()
            except TimeoutError:
                continue
            with conn:
                conn.settimeout(2.0)
                buf = b""
                while b"\r\n\r\n" not in buf:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                header_part, _, rest = buf.partition(b"\r\n\r\n")
                cl = 0
                for line in header_part.split(b"\r\n")[1:]:
                    if line.lower().startswith(b"content-length:"):
                        cl = int(line.split(b":", 1)[1].strip())
                while len(rest) < cl:
                    more = conn.recv(4096)
                    if not more:
                        break
                    rest += more
                attempts[0] += 1
                if attempts[0] == 1:
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\npartial")
                else:
                    received_ok[0] += 1
                    conn.sendall(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")

    srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv_sock.bind(("127.0.0.1", 0))
    srv_sock.listen(5)
    port = srv_sock.getsockname()[1]
    stop_ev = threading.Event()
    t = threading.Thread(target=raw_loki_server, args=(srv_sock, stop_ev), daemon=True)
    t.start()
    try:
        cfg = EnricherConfig(
            http_enabled=False,
            metrics_listen_addr="127.0.0.1:0",
            rdns_enabled=False,
            loki_url=f"http://127.0.0.1:{port}",
            max_retries=2,
            initial_backoff_seconds=0.01,
            max_backoff_seconds=0.05,
        )
        p = EnricherPipeline(cfg)
        p.start()
        try:
            p.ingest_records(
                [
                    {
                        "src_addr": "192.168.1.10",
                        "dst_addr": "1.1.1.1",
                        "bytes": 500,
                        "packets": 1,
                        "proto": "UDP",
                        "src_port": 50000,
                        "dst_port": 53,
                    }
                ]
            )
            p.flush()
            assert attempts[0] == 2
            assert received_ok[0] == 1
            metrics_text = p.metrics.render().decode("utf-8")
            assert 'nxtflow_loki_push_requests_total{status="error"} 1.0' in metrics_text
            assert 'nxtflow_loki_push_requests_total{status="2xx"} 1.0' in metrics_text
            assert "nxtflow_dropped_flows_total 0.0" in metrics_text
        finally:
            p.stop()
    finally:
        stop_ev.set()
        t.join(timeout=2.0)
        srv_sock.close()


def test_loki_shipper_skips_eager_ca_validation_for_file_and_alloy_modes(tmp_path: Path) -> None:
    missing_ca = str(tmp_path / "nonexistent-ca.pem")
    metrics = EnricherMetrics()

    shipper_alloy = LokiShipper(
        EnricherConfig(shipper_mode="alloy", loki_url="https://loki.example.com", loki_ca_file=missing_ca),
        metrics,
    )
    assert shipper_alloy._ssl_ctx is None

    shipper_file = LokiShipper(
        EnricherConfig(shipper_mode="file", loki_url="https://loki.example.com", loki_ca_file=missing_ca),
        metrics,
    )
    assert shipper_file._ssl_ctx is None

    shipper_dry = LokiShipper(
        EnricherConfig(shipper_mode="direct", loki_url="", loki_ca_file=missing_ca),
        metrics,
    )
    assert shipper_dry._ssl_ctx is None

    with pytest.raises(FileNotFoundError):
        LokiShipper(
            EnricherConfig(shipper_mode="direct", loki_url="https://loki.example.com", loki_ca_file=missing_ca),
            metrics,
        )
