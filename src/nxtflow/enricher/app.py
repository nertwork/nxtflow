"""nxtflow-enricher: GoFlow2 HTTP/file/stdin ingest, host/CIDR/rDNS/NetBox enrichment, and Loki shipper."""

from __future__ import annotations

import argparse
import base64
import gzip
import http.client
import ipaddress
import json
import logging
import os
import signal
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from collections import OrderedDict, deque
from collections.abc import Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, TextIO

import yaml
from prometheus_client import CollectorRegistry, Counter, Gauge, generate_latest

from nxtflow.config import parse_tls_verify
from nxtflow.enricher.default_cidrs import (
    PROTO_MAP,
    PUBLIC_WELL_KNOWN_IPS,
    lookup_public_cidr,
    simplify_rdns,
)

LOGGER = logging.getLogger("nxtflow.enricher")


def _parse_host_port(listen_addr: str, default_host: str = "0.0.0.0", default_port: int = 8081) -> tuple[str, int]:
    raw = str(listen_addr or "").strip()
    if not raw:
        return default_host, default_port
    if raw.startswith("["):
        host_part, _, port_part = raw[1:].partition("]:")
        return host_part or default_host, int(port_part or default_port)
    if ":" not in raw:
        return raw, default_port
    host_part, port_part = raw.rsplit(":", 1)
    return (host_part or default_host), int(port_part or default_port)


def _parse_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    s = str(value).strip().lower()
    if s in ("true", "1", "yes", "on"):
        return True
    if s in ("false", "0", "no", "off"):
        return False
    return default


def _build_ssl_context(tls_verify: bool | str, ca_file: str = "") -> ssl.SSLContext:
    if ca_file:
        return ssl.create_default_context(cafile=ca_file)
    if tls_verify is False:
        return ssl._create_unverified_context()
    if isinstance(tls_verify, str):
        return ssl.create_default_context(cafile=tls_verify)
    return ssl.create_default_context()


def _parse_cidr_list(items: Iterable[str]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for raw in items:
        s = str(raw).strip()
        if s:
            nets.append(ipaddress.ip_network(s, strict=False))
    return nets


def _parse_named_cidrs(items: Iterable[dict[str, Any]]) -> list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]]:
    out: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]] = []
    for entry in items:
        if not isinstance(entry, dict):
            continue
        cidr = str(entry.get("cidr", "")).strip()
        name = str(entry.get("name", "")).strip()
        if cidr and name:
            out.append((ipaddress.ip_network(cidr, strict=False), name))
    out.sort(key=lambda item: (-item[0].prefixlen, str(item[0])))
    return out


def parse_goflow2_batch(raw_bytes: bytes, content_encoding: str = "") -> tuple[list[dict[str, Any]], int]:
    """Parse GoFlow2 JSON object, JSON array, or NDJSON (optionally gzip-compressed).

    Returns (valid_records, parse_error_count). Raises ValueError when body is non-empty
    yet completely unparseable as JSON/NDJSON.
    """
    payload = raw_bytes
    if content_encoding.lower().strip() == "gzip" or payload.startswith(b"\x1f\x8b"):
        try:
            payload = gzip.decompress(payload)
        except (OSError, EOFError, zlib.error) as exc:
            raise ValueError(f"Invalid gzip payload: {exc}") from exc

    text = payload.decode("utf-8", errors="replace").strip()
    if not text:
        return [], 0

    if text.startswith(("{", "[")):
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, dict):
            return [parsed], 0
        if isinstance(parsed, list):
            records = [item for item in parsed if isinstance(item, dict)]
            return records, len(parsed) - len(records)
        if parsed is not None:
            raise ValueError("JSON payload must be an object or array")

    records: list[dict[str, Any]] = []
    errors = 0
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
        except json.JSONDecodeError:
            errors += 1
            continue
        if isinstance(obj, dict):
            records.append(obj)
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, dict):
                    records.append(item)
                else:
                    errors += 1
        else:
            errors += 1

    if not records and errors > 0:
        raise ValueError("All NDJSON lines failed JSON parsing")
    return records, errors


def parse_goflow2_payload(raw_bytes: bytes, content_encoding: str = "") -> list[dict[str, Any]]:
    """Convenience wrapper returning only parsed flow dicts."""
    records, _ = parse_goflow2_batch(raw_bytes, content_encoding=content_encoding)
    return records


def normalize_proto(raw_proto: Any) -> str:
    """Normalize GoFlow2 protocol name or IANA protocol number to uppercase string."""
    if raw_proto is None:
        return ""
    if isinstance(raw_proto, int):
        return PROTO_MAP.get(raw_proto, str(raw_proto))
    s = str(raw_proto).strip()
    if not s:
        return ""
    if s.isdigit():
        return PROTO_MAP.get(int(s), s)
    return s.upper()


@dataclass
class EnricherConfig:
    """Full configuration model for nxtflow-enricher."""

    site: str = "default"
    job: str = "nxtflow"
    include_sampler_label: bool = False

    http_enabled: bool = True
    http_listen_addr: str = "0.0.0.0:8081"
    max_body_bytes: int = 10 * 1024 * 1024

    file_enabled: bool = False
    file_path: str = "/var/log/goflow2/raw.jsonl"
    file_poll_interval: float = 0.2
    file_position_file: str = "/tmp/nxtflow-enricher.pos"
    file_truncate_bytes: int = 50 * 1024 * 1024

    stdin_enabled: bool = False
    metrics_listen_addr: str = "0.0.0.0:9090"

    respect_sampling_rate: bool = True
    default_sampling_rate: int = 1

    local_cidrs: list[str] = field(
        default_factory=lambda: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"]
    )
    wan_ips: list[str] = field(default_factory=list)
    internal_cidrs: list[dict[str, str]] = field(default_factory=list)
    excluded_hosts: list[str] = field(default_factory=list)

    static_hosts: dict[str, str] = field(default_factory=dict)
    services: dict[str, str] = field(default_factory=dict)
    extra_cidrs: list[dict[str, str]] = field(default_factory=list)
    use_default_cidrs: bool = True

    rdns_enabled: bool = True
    rdns_private: bool = False
    rdns_timeout_seconds: float = 1.5
    rdns_max_entries: int = 10000
    rdns_ttl_seconds: float = 3600.0
    rdns_negative_ttl_seconds: float = 300.0

    netbox_enabled: bool = False
    netbox_url: str = ""
    netbox_token: str = ""
    netbox_tls_verify: bool | str = True
    netbox_sync_interval: float = 300.0
    netbox_timeout_seconds: float = 10.0
    netbox_strip_domain: bool = False

    shipper_mode: str = "direct"  # "direct" | "file" | "alloy"
    loki_url: str = ""
    loki_tenant_id: str = ""
    loki_username: str = ""
    loki_password: str = ""
    loki_bearer_token: str = ""
    loki_tls_verify: bool | str = True
    loki_ca_file: str = ""
    loki_timeout_seconds: float = 10.0
    batch_max_entries: int = 500
    batch_max_wait_seconds: float = 1.0
    ring_buffer_max_flows: int = 50000
    max_retries: int = 5
    initial_backoff_seconds: float = 0.5
    max_backoff_seconds: float = 30.0
    shipper_file_path: str = "/var/log/nxtflow/flows.jsonl"
    shipper_file_truncate_bytes: int = 50 * 1024 * 1024


def load_enricher_config(
    config_file: str | Path | None = None,
    **overrides: Any,
) -> EnricherConfig:
    """Load enricher YAML configuration with environment variable overrides."""
    cfg = EnricherConfig()

    env_path = os.environ.get("NXTFLOW_CONFIG_FILE", "").strip()
    default_path = Path("/etc/nxtflow/enricher.yaml")
    chosen: Path | None = None
    if config_file:
        chosen = Path(config_file).expanduser()
    elif env_path:
        chosen = Path(env_path).expanduser()
    elif default_path.is_file():
        chosen = default_path

    if chosen is not None and chosen.is_file():
        data = yaml.safe_load(chosen.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            raise ValueError(f"Enricher config {chosen} must be a YAML mapping")

        collector = data.get("collector") or {}
        if isinstance(collector, dict):
            cfg.site = str(collector.get("site", cfg.site))
            cfg.job = str(collector.get("job", cfg.job))
            cfg.include_sampler_label = _parse_bool(collector.get("includeSamplerLabel"), cfg.include_sampler_label)

        ingest = data.get("ingest") or {}
        if isinstance(ingest, dict):
            http_sec = ingest.get("http") or {}
            if isinstance(http_sec, dict):
                cfg.http_enabled = _parse_bool(http_sec.get("enabled"), cfg.http_enabled)
                cfg.http_listen_addr = str(http_sec.get("listenAddr", cfg.http_listen_addr))
                cfg.max_body_bytes = int(http_sec.get("maxBodyBytes", cfg.max_body_bytes))
            file_sec = ingest.get("file") or {}
            if isinstance(file_sec, dict):
                cfg.file_enabled = _parse_bool(file_sec.get("enabled"), cfg.file_enabled)
                cfg.file_path = str(file_sec.get("path", cfg.file_path))
                cfg.file_poll_interval = float(file_sec.get("pollIntervalSeconds", cfg.file_poll_interval))
                cfg.file_position_file = str(file_sec.get("positionFile", cfg.file_position_file))
                cfg.file_truncate_bytes = int(file_sec.get("truncateAtBytes", cfg.file_truncate_bytes))
            stdin_sec = ingest.get("stdin") or {}
            if isinstance(stdin_sec, dict):
                cfg.stdin_enabled = _parse_bool(stdin_sec.get("enabled"), cfg.stdin_enabled)
            if cfg.file_enabled and cfg.file_path == "-":
                cfg.file_enabled = False
                cfg.stdin_enabled = True

        metrics_sec = data.get("metrics") or {}
        if isinstance(metrics_sec, dict):
            cfg.metrics_listen_addr = str(metrics_sec.get("listenAddr", cfg.metrics_listen_addr))

        sampling = data.get("sampling") or {}
        if isinstance(sampling, dict):
            cfg.respect_sampling_rate = _parse_bool(sampling.get("respectSamplingRate"), cfg.respect_sampling_rate)
            cfg.default_sampling_rate = max(1, int(sampling.get("defaultSamplingRate", cfg.default_sampling_rate)))

        classification = data.get("classification") or {}
        if isinstance(classification, dict):
            if "localCidrs" in classification and isinstance(classification["localCidrs"], list):
                cfg.local_cidrs = [str(c) for c in classification["localCidrs"]]
            if "wanIps" in classification and isinstance(classification["wanIps"], list):
                cfg.wan_ips = [str(ip).strip() for ip in classification["wanIps"] if str(ip).strip()]
            if "internalCidrs" in classification and isinstance(classification["internalCidrs"], list):
                cfg.internal_cidrs = list(classification["internalCidrs"])
            if "excludedHosts" in classification and isinstance(classification["excludedHosts"], list):
                cfg.excluded_hosts = [str(h).strip() for h in classification["excludedHosts"] if str(h).strip()]

        resolution = data.get("resolution") or {}
        if isinstance(resolution, dict):
            if isinstance(resolution.get("staticHosts"), dict):
                cfg.static_hosts = {str(k).strip(): str(v).strip() for k, v in resolution["staticHosts"].items()}
            if isinstance(resolution.get("services"), dict):
                cfg.services = {str(k).strip(): str(v).strip() for k, v in resolution["services"].items()}
            if isinstance(resolution.get("extraCidrs"), list):
                cfg.extra_cidrs = list(resolution["extraCidrs"])
            cfg.use_default_cidrs = _parse_bool(resolution.get("useDefaultCidrs"), cfg.use_default_cidrs)
            rdns = resolution.get("rdns") or {}
            if isinstance(rdns, dict):
                cfg.rdns_enabled = _parse_bool(rdns.get("enabled"), cfg.rdns_enabled)
                cfg.rdns_private = _parse_bool(rdns.get("private"), cfg.rdns_private)
                cfg.rdns_timeout_seconds = float(rdns.get("timeoutSeconds", cfg.rdns_timeout_seconds))
                cfg.rdns_max_entries = int(rdns.get("maxEntries", cfg.rdns_max_entries))
                cfg.rdns_ttl_seconds = float(rdns.get("ttlSeconds", cfg.rdns_ttl_seconds))
                cfg.rdns_negative_ttl_seconds = float(rdns.get("negativeTtlSeconds", cfg.rdns_negative_ttl_seconds))

        netbox = data.get("netbox") or {}
        if isinstance(netbox, dict):
            cfg.netbox_enabled = _parse_bool(netbox.get("enabled"), cfg.netbox_enabled)
            cfg.netbox_url = str(netbox.get("url", cfg.netbox_url) or "").rstrip("/")
            cfg.netbox_token = str(netbox.get("token", cfg.netbox_token) or "")
            if "tlsVerify" in netbox:
                cfg.netbox_tls_verify = parse_tls_verify(netbox["tlsVerify"])
            cfg.netbox_sync_interval = float(netbox.get("syncIntervalSeconds", cfg.netbox_sync_interval))
            cfg.netbox_timeout_seconds = float(netbox.get("timeoutSeconds", cfg.netbox_timeout_seconds))
            cfg.netbox_strip_domain = _parse_bool(netbox.get("stripDomain"), cfg.netbox_strip_domain)

        shipper = data.get("shipper") or {}
        if isinstance(shipper, dict):
            cfg.shipper_mode = str(shipper.get("mode", cfg.shipper_mode)).strip().lower()
            loki_sec = shipper.get("loki") or {}
            if isinstance(loki_sec, dict):
                cfg.loki_url = str(loki_sec.get("url", cfg.loki_url) or "").rstrip("/")
                cfg.loki_tenant_id = str(loki_sec.get("tenantId", cfg.loki_tenant_id) or "")
                cfg.loki_username = str(loki_sec.get("username", cfg.loki_username) or "")
                cfg.loki_password = str(loki_sec.get("password", cfg.loki_password) or "")
                cfg.loki_bearer_token = str(loki_sec.get("bearerToken", cfg.loki_bearer_token) or "")
                if "tlsVerify" in loki_sec:
                    cfg.loki_tls_verify = parse_tls_verify(loki_sec["tlsVerify"])
                cfg.loki_ca_file = str(loki_sec.get("caFile", cfg.loki_ca_file) or "")
                cfg.loki_timeout_seconds = float(loki_sec.get("timeoutSeconds", cfg.loki_timeout_seconds))
                cfg.batch_max_entries = int(loki_sec.get("batchMaxEntries", cfg.batch_max_entries))
                cfg.batch_max_wait_seconds = float(loki_sec.get("batchMaxWaitSeconds", cfg.batch_max_wait_seconds))
                cfg.ring_buffer_max_flows = int(loki_sec.get("ringBufferMaxFlows", cfg.ring_buffer_max_flows))
                cfg.max_retries = int(loki_sec.get("maxRetries", cfg.max_retries))
                cfg.initial_backoff_seconds = float(loki_sec.get("initialBackoffSeconds", cfg.initial_backoff_seconds))
                cfg.max_backoff_seconds = float(loki_sec.get("maxBackoffSeconds", cfg.max_backoff_seconds))
            sfile = shipper.get("file") or {}
            if isinstance(sfile, dict):
                cfg.shipper_file_path = str(sfile.get("path", cfg.shipper_file_path))
                cfg.shipper_file_truncate_bytes = int(sfile.get("truncateAtBytes", cfg.shipper_file_truncate_bytes))

    # Environment overrides
    if os.environ.get("NXTFLOW_SITE", "").strip():
        cfg.site = os.environ["NXTFLOW_SITE"].strip()
    if os.environ.get("NXTFLOW_JOB", "").strip():
        cfg.job = os.environ["NXTFLOW_JOB"].strip()
    if os.environ.get("NXTFLOW_HTTP_LISTEN", "").strip():
        cfg.http_listen_addr = os.environ["NXTFLOW_HTTP_LISTEN"].strip()
    if os.environ.get("NXTFLOW_METRICS_LISTEN", "").strip():
        cfg.metrics_listen_addr = os.environ["NXTFLOW_METRICS_LISTEN"].strip()
    if "NXTFLOW_INPUT_FILE" in os.environ and os.environ["NXTFLOW_INPUT_FILE"].strip():
        inp = os.environ["NXTFLOW_INPUT_FILE"].strip()
        if inp == "-":
            cfg.stdin_enabled = True
            cfg.file_enabled = False
        else:
            cfg.file_enabled = True
            cfg.file_path = inp
    if os.environ.get("NXTFLOW_LOKI_URL", "").strip():
        cfg.loki_url = os.environ["NXTFLOW_LOKI_URL"].strip().rstrip("/")
    if "NXTFLOW_LOKI_TENANT_ID" in os.environ:
        cfg.loki_tenant_id = os.environ["NXTFLOW_LOKI_TENANT_ID"].strip()
    if "NXTFLOW_LOKI_USERNAME" in os.environ:
        cfg.loki_username = os.environ["NXTFLOW_LOKI_USERNAME"].strip()
    elif "NXTFLOW_LOKI_USER" in os.environ:
        cfg.loki_username = os.environ["NXTFLOW_LOKI_USER"].strip()
    if "NXTFLOW_LOKI_PASSWORD" in os.environ:
        cfg.loki_password = os.environ["NXTFLOW_LOKI_PASSWORD"]
    if "NXTFLOW_LOKI_TOKEN" in os.environ:
        cfg.loki_bearer_token = os.environ["NXTFLOW_LOKI_TOKEN"].strip()
    if "NXTFLOW_TLS_VERIFY" in os.environ:
        cfg.loki_tls_verify = parse_tls_verify(os.environ["NXTFLOW_TLS_VERIFY"])
    if "NXTFLOW_NETBOX_ENABLED" in os.environ:
        cfg.netbox_enabled = _parse_bool(os.environ["NXTFLOW_NETBOX_ENABLED"], cfg.netbox_enabled)
    if os.environ.get("NXTFLOW_NETBOX_URL", "").strip():
        cfg.netbox_url = os.environ["NXTFLOW_NETBOX_URL"].strip().rstrip("/")
    if "NXTFLOW_NETBOX_TOKEN" in os.environ:
        cfg.netbox_token = os.environ["NXTFLOW_NETBOX_TOKEN"].strip()
    if "NXTFLOW_NETBOX_TLS_VERIFY" in os.environ:
        cfg.netbox_tls_verify = parse_tls_verify(os.environ["NXTFLOW_NETBOX_TLS_VERIFY"])

    for key, val in overrides.items():
        if val is not None and hasattr(cfg, key):
            setattr(cfg, key, val)

    return cfg


class EnricherMetrics:
    """Dedicated Prometheus CollectorRegistry exporting exact nxtflow_* metric names."""

    def __init__(self) -> None:
        self.registry = CollectorRegistry()
        self.flows_received = Counter(
            "nxtflow_flows_received",
            "Total enriched flows received",
            ["site", "dir", "proto"],
            registry=self.registry,
        )
        self.bytes_total = Counter(
            "nxtflow_bytes",
            "Total scaled bytes received",
            ["site", "dir", "proto"],
            registry=self.registry,
        )
        self.loki_push_requests = Counter(
            "nxtflow_loki_push_requests",
            "Total Loki HTTP push attempts by status category",
            ["status"],
            registry=self.registry,
        )
        self.loki_push_errors = Counter(
            "nxtflow_loki_push_errors",
            "Total failed Loki HTTP push batches",
            registry=self.registry,
        )
        self.dropped_flows = Counter(
            "nxtflow_dropped_flows",
            "Total flows dropped due to parse errors, ring buffer overflow, or push failures",
            registry=self.registry,
        )
        self.rdns_cache_hits = Counter(
            "nxtflow_rdns_cache_hits",
            "Total reverse DNS cache hits",
            registry=self.registry,
        )
        self.rdns_cache_misses = Counter(
            "nxtflow_rdns_cache_misses",
            "Total reverse DNS cache misses",
            registry=self.registry,
        )
        self.ring_buffer_size = Gauge(
            "nxtflow_ring_buffer_size",
            "Current number of flows queued in the shipper ring buffer",
            registry=self.registry,
        )
        self.netbox_hosts_cached = Gauge(
            "nxtflow_netbox_hosts_cached",
            "Current number of IP-to-host mappings cached from NetBox IPAM",
            registry=self.registry,
        )
        self.netbox_sync_errors = Counter(
            "nxtflow_netbox_sync_errors",
            "Total NetBox IPAM sync errors",
            registry=self.registry,
        )

    def render(self) -> bytes:
        return generate_latest(self.registry)


class RDNSCache:
    """Thread-safe bounded LRU+TTL reverse DNS cache with isolated executor timeouts."""

    def __init__(
        self,
        max_entries: int = 10000,
        ttl_seconds: float = 3600.0,
        negative_ttl_seconds: float = 300.0,
        timeout_seconds: float = 1.5,
        extra_services: dict[str, str] | None = None,
        metrics: EnricherMetrics | None = None,
    ) -> None:
        self.max_entries = max(1, int(max_entries))
        self.ttl_seconds = float(ttl_seconds)
        self.negative_ttl_seconds = float(negative_ttl_seconds)
        self.timeout_seconds = float(timeout_seconds)
        self.extra_services = dict(extra_services or {})
        self.metrics = metrics
        self._lock = threading.Lock()
        self._entries: OrderedDict[str, tuple[str | None, float]] = OrderedDict()
        self._executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="nxtflow-rdns")

    def get(self, ip: str) -> tuple[bool, str | None]:
        """Look up IP in cache. Returns (hit, resolved_name_or_None)."""
        now = time.monotonic()
        with self._lock:
            item = self._entries.get(ip)
            if item is None:
                return False, None
            value, expires_at = item
            if now >= expires_at:
                del self._entries[ip]
                return False, None
            self._entries.move_to_end(ip)
            if self.metrics is not None:
                self.metrics.rdns_cache_hits.inc()
            return True, value

    def put(self, ip: str, value: str | None, ttl: float) -> None:
        now = time.monotonic()
        with self._lock:
            if ip in self._entries:
                self._entries.move_to_end(ip)
            self._entries[ip] = (value, now + ttl)
            while len(self._entries) > self.max_entries:
                self._entries.popitem(last=False)

    def resolve(self, ip: str) -> str | None:
        hit, cached = self.get(ip)
        if hit:
            return cached

        if self.metrics is not None:
            self.metrics.rdns_cache_misses.inc()

        ptr_host: str | None = None
        future = self._executor.submit(socket.gethostbyaddr, ip)
        try:
            res = future.result(timeout=self.timeout_seconds)
            if res and res[0]:
                simplified = simplify_rdns(res[0], self.extra_services)
                if simplified and simplified != ip:
                    ptr_host = simplified
        except (FuturesTimeoutError, socket.herror, socket.gaierror, OSError):
            ptr_host = None

        ttl = self.ttl_seconds if ptr_host is not None else self.negative_ttl_seconds
        self.put(ip, ptr_host, ttl)
        return ptr_host

    def close(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)


class NetBoxSync:
    """Periodic NetBox IPAM synchronizer fetching /api/ipam/ip-addresses/."""

    def __init__(self, cfg: EnricherConfig, metrics: EnricherMetrics) -> None:
        self.cfg = cfg
        self.metrics = metrics
        self._lock = threading.Lock()
        self._hosts: dict[str, str] = {}
        self._ssl_ctx = _build_ssl_context(cfg.netbox_tls_verify)

    def get_hosts(self) -> dict[str, str]:
        with self._lock:
            return dict(self._hosts)

    def lookup(self, ip: str) -> str | None:
        with self._lock:
            return self._hosts.get(ip)

    def sync_once(self) -> bool:
        """Fetch paginated IP addresses from NetBox and atomically swap cache on success."""
        if not self.cfg.netbox_enabled or not self.cfg.netbox_url:
            return True
        next_url: str | None = f"{self.cfg.netbox_url.rstrip('/')}/api/ipam/ip-addresses/?limit=1000"
        headers = {"Accept": "application/json"}
        if self.cfg.netbox_token:
            headers["Authorization"] = f"Token {self.cfg.netbox_token}"

        new_map: dict[str, str] = {}
        pages = 0
        try:
            while next_url and pages < 50:
                pages += 1
                req = urllib.request.Request(next_url, headers=headers)
                with urllib.request.urlopen(
                    req,
                    timeout=self.cfg.netbox_timeout_seconds,
                    context=self._ssl_ctx,
                ) as resp:
                    payload = json.loads(resp.read().decode("utf-8"))
                if not isinstance(payload, dict):
                    raise TypeError("NetBox response must be a JSON object")
                for item in payload.get("results", []):
                    if not isinstance(item, dict):
                        continue
                    addr_raw = str(item.get("address", "")).strip()
                    if not addr_raw:
                        continue
                    ip_only = addr_raw.split("/", 1)[0].strip()
                    assigned = item.get("assigned_object") or {}
                    vm_name = ((assigned.get("virtual_machine") or {}).get("name") or "") if isinstance(assigned, dict) else ""
                    dev_name = ((assigned.get("device") or {}).get("name") or "") if isinstance(assigned, dict) else ""
                    candidate = (
                        str(item.get("dns_name") or "").strip()
                        or str(vm_name).strip()
                        or str(dev_name).strip()
                    )
                    if not candidate:
                        continue
                    if self.cfg.netbox_strip_domain:
                        try:
                            ipaddress.ip_address(candidate)
                        except ValueError:
                            candidate = candidate.split(".", 1)[0]
                    new_map[ip_only] = candidate
                raw_next = payload.get("next")
                next_url = urllib.parse.urljoin(next_url, str(raw_next).strip()) if raw_next else None
        except (
            urllib.error.URLError,
            urllib.error.HTTPError,
            http.client.HTTPException,
            TimeoutError,
            json.JSONDecodeError,
            TypeError,
            ValueError,
            OSError,
        ) as exc:
            LOGGER.warning("NetBox sync failed (keeping %d cached hosts): %s", len(self._hosts), exc)
            self.metrics.netbox_sync_errors.inc()
            return False

        with self._lock:
            self._hosts = new_map
        self.metrics.netbox_hosts_cached.set(len(new_map))
        return True


class LokiShipper:
    """Thread-safe bounded ring buffer + background shipper (Loki gzip HTTP or JSONL file)."""

    def __init__(self, cfg: EnricherConfig, metrics: EnricherMetrics) -> None:
        self.cfg = cfg
        self.metrics = metrics
        self._buffer: deque[tuple[int, dict[str, Any], str]] = deque()
        self._cond = threading.Condition()
        self._stop_event = threading.Event()
        self._ssl_ctx: ssl.SSLContext | None = (
            _build_ssl_context(cfg.loki_tls_verify, cfg.loki_ca_file)
            if cfg.shipper_mode not in ("file", "alloy") and cfg.loki_url
            else None
        )
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, name="nxtflow-shipper", daemon=True)
        self._thread.start()

    def stop(self, flush: bool = True) -> None:
        if flush:
            self.flush()
        self._stop_event.set()
        with self._cond:
            self._cond.notify_all()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None

    def enqueue(self, ts_ns: int, record: dict[str, Any]) -> None:
        line = json.dumps(record, separators=(",", ":"))
        with self._cond:
            if len(self._buffer) >= self.cfg.ring_buffer_max_flows:
                self._buffer.popleft()
                self.metrics.dropped_flows.inc()
            self._buffer.append((int(ts_ns), record, line))
            self.metrics.ring_buffer_size.set(len(self._buffer))
            if len(self._buffer) >= self.cfg.batch_max_entries:
                self._cond.notify_all()

    def flush(self) -> None:
        """Synchronously drain and ship all currently buffered flows."""
        while True:
            batch = self._drain_batch(max_items=self.cfg.batch_max_entries)
            if not batch:
                return
            self._ship_batch(batch)

    def _drain_batch(self, max_items: int) -> list[tuple[int, dict[str, Any], str]]:
        with self._cond:
            batch: list[tuple[int, dict[str, Any], str]] = []
            while self._buffer and len(batch) < max_items:
                batch.append(self._buffer.popleft())
            self.metrics.ring_buffer_size.set(len(self._buffer))
            return batch

    def _run(self) -> None:
        while not self._stop_event.is_set():
            with self._cond:
                if len(self._buffer) < self.cfg.batch_max_entries:
                    self._cond.wait(timeout=self.cfg.batch_max_wait_seconds)
            while True:
                batch = self._drain_batch(max_items=self.cfg.batch_max_entries)
                if not batch:
                    break
                self._ship_batch(batch)

    def _ship_batch(self, batch: list[tuple[int, dict[str, Any], str]]) -> None:
        if self.cfg.shipper_mode in ("file", "alloy"):
            self._write_file_batch(batch)
            return
        if not self.cfg.loki_url:
            # No Loki URL configured (e.g., dry-run or metrics-only mode)
            return
        self._push_loki_batch(batch)

    def _write_file_batch(self, batch: list[tuple[int, dict[str, Any], str]]) -> None:
        target = Path(self.cfg.shipper_file_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        mode = "a"
        if (
            self.cfg.shipper_file_truncate_bytes > 0
            and target.exists()
            and target.stat().st_size >= self.cfg.shipper_file_truncate_bytes
        ):
            mode = "w"
        with target.open(mode, encoding="utf-8") as fh:
            for _ts_ns, _rec, line in batch:
                fh.write(line + "\n")
            fh.flush()

    def _build_loki_headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Content-Encoding": "gzip",
        }
        if self.cfg.loki_bearer_token:
            headers["Authorization"] = f"Bearer {self.cfg.loki_bearer_token}"
        elif self.cfg.loki_username or self.cfg.loki_password:
            creds = f"{self.cfg.loki_username}:{self.cfg.loki_password}".encode()
            headers["Authorization"] = f"Basic {base64.b64encode(creds).decode('ascii')}"
        if self.cfg.loki_tenant_id:
            headers["X-Scope-OrgID"] = self.cfg.loki_tenant_id
        return headers

    def _push_loki_batch(self, batch: list[tuple[int, dict[str, Any], str]]) -> None:
        grouped: dict[tuple[str, str, str], list[tuple[int, str]]] = {}
        for ts_ns, rec, line in batch:
            key = (self.cfg.job, str(rec.get("site", self.cfg.site)), str(rec.get("dir", "lan")))
            grouped.setdefault(key, []).append((ts_ns, line))

        streams = []
        for (job, site, direction), entries in grouped.items():
            entries.sort(key=lambda item: item[0])
            streams.append(
                {
                    "stream": {"job": job, "site": site, "dir": direction},
                    "values": [[str(ts), ln] for ts, ln in entries],
                }
            )

        body = gzip.compress(json.dumps({"streams": streams}, separators=(",", ":")).encode("utf-8"))
        push_url = f"{self.cfg.loki_url.rstrip('/')}/loki/api/v1/push"
        headers = self._build_loki_headers()

        if self._ssl_ctx is None:
            self._ssl_ctx = _build_ssl_context(self.cfg.loki_tls_verify, self.cfg.loki_ca_file)

        attempts = max(0, int(self.cfg.max_retries)) + 1
        for attempt in range(attempts):
            try:
                req = urllib.request.Request(push_url, data=body, headers=headers, method="POST")
                with urllib.request.urlopen(
                    req,
                    timeout=self.cfg.loki_timeout_seconds,
                    context=self._ssl_ctx,
                ) as resp:
                    status = resp.status
                    resp.read()
                    if 200 <= status < 300:
                        self.metrics.loki_push_requests.labels(status="2xx").inc()
                        return
            except urllib.error.HTTPError as exc:
                code = exc.code
                if code == 429:
                    self.metrics.loki_push_requests.labels(status="429").inc()
                elif 500 <= code < 600:
                    self.metrics.loki_push_requests.labels(status="5xx").inc()
                else:
                    self.metrics.loki_push_requests.labels(status="4xx").inc()
                    self.metrics.loki_push_errors.inc()
                    self.metrics.dropped_flows.inc(len(batch))
                    LOGGER.error("Loki rejected batch with HTTP %d; dropping %d flows", code, len(batch))
                    return
            except (urllib.error.URLError, http.client.HTTPException, TimeoutError, OSError) as exc:
                LOGGER.warning("Loki push attempt %d/%d failed: %s", attempt + 1, attempts, exc)
                self.metrics.loki_push_requests.labels(status="error").inc()

            if attempt + 1 < attempts:
                backoff = min(
                    self.cfg.max_backoff_seconds,
                    self.cfg.initial_backoff_seconds * (2**attempt),
                )
                time.sleep(backoff)

        self.metrics.loki_push_errors.inc()
        self.metrics.dropped_flows.inc(len(batch))
        LOGGER.error("Exhausted %d Loki push attempts; dropped %d flows", attempts, len(batch))


class EnricherPipeline:
    """Core flow enrichment, classification, HTTP/file/stdin ingestion, and shipping coordinator."""

    def __init__(
        self,
        cfg: EnricherConfig | None = None,
        stdin_stream: TextIO | None = None,
    ) -> None:
        self.cfg = cfg or load_enricher_config()
        self.metrics = EnricherMetrics()
        self.rdns_cache = RDNSCache(
            max_entries=self.cfg.rdns_max_entries,
            ttl_seconds=self.cfg.rdns_ttl_seconds,
            negative_ttl_seconds=self.cfg.rdns_negative_ttl_seconds,
            timeout_seconds=self.cfg.rdns_timeout_seconds,
            extra_services=self.cfg.services,
            metrics=self.metrics,
        )
        self.netbox = NetBoxSync(self.cfg, self.metrics)
        self.shipper = LokiShipper(self.cfg, self.metrics)

        self._local_nets = _parse_cidr_list(self.cfg.local_cidrs)
        self._wan_ips = set(self.cfg.wan_ips)
        self._internal_cidrs = _parse_named_cidrs(self.cfg.internal_cidrs)
        self._extra_cidrs = _parse_named_cidrs(self.cfg.extra_cidrs)
        self._excluded_hosts = set(self.cfg.excluded_hosts)

        self._ready = threading.Event()
        self._stop_event = threading.Event()
        self._http_server: ThreadingHTTPServer | None = None
        self._metrics_server: ThreadingHTTPServer | None = None
        self._threads: list[threading.Thread] = []
        self._stdin_stream = stdin_stream

    @property
    def http_port(self) -> int:
        if self._http_server is None:
            return 0
        return int(self._http_server.server_address[1])

    @property
    def metrics_port(self) -> int:
        if self._metrics_server is None:
            return 0
        return int(self._metrics_server.server_address[1])

    def is_local_ip(self, ip: str) -> bool:
        if not ip:
            return False
        if ip in self._wan_ips:
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if addr.is_loopback:
            return True
        return any(addr in net for net in self._local_nets)

    def classify_direction(self, src_ip: str, dst_ip: str) -> str:
        src_local = self.is_local_ip(src_ip)
        dst_local = self.is_local_ip(dst_ip)
        if src_local and not dst_local:
            return "up"
        if not src_local and dst_local:
            return "down"
        return "lan"

    def resolve_host(self, ip: str) -> str:
        if not ip:
            return ""
        if ip in self.cfg.static_hosts:
            return self.cfg.static_hosts[ip]
        nb_hit = self.netbox.lookup(ip)
        if nb_hit:
            return nb_hit

        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return ip

        if addr.is_multicast:
            return "multicast"
        if addr.is_link_local:
            return "link-local"
        if ip == "255.255.255.255":
            return "broadcast"

        for net, name in self._internal_cidrs:
            if addr in net:
                return name

        if addr.is_loopback or any(addr in net for net in self._local_nets):
            if isinstance(addr, ipaddress.IPv4Address) and addr.is_private and ip.endswith(".255"):
                return "broadcast"
            if self.cfg.rdns_enabled and self.cfg.rdns_private:
                resolved = self.rdns_cache.resolve(ip)
                if resolved:
                    return resolved
            return ip

        for net, name in self._extra_cidrs:
            if addr in net:
                return name

        if self.cfg.use_default_cidrs and ip in PUBLIC_WELL_KNOWN_IPS:
            return PUBLIC_WELL_KNOWN_IPS[ip]

        if self.cfg.rdns_enabled:
            resolved = self.rdns_cache.resolve(ip)
            if resolved:
                return resolved

        if self.cfg.use_default_cidrs:
            cidr_label = lookup_public_cidr(ip)
            if cidr_label:
                return cidr_label

        return ip

    def enrich_flow(self, flow: dict[str, Any]) -> dict[str, Any] | None:
        """Transform a raw GoFlow2 flow dict into the 11-field nxtflow JSON schema."""
        src_addr = str(flow.get("src_addr", "") or "").strip()
        dst_addr = str(flow.get("dst_addr", "") or "").strip()
        if not src_addr or not dst_addr:
            return None

        src_host = self.resolve_host(src_addr)
        dst_host = self.resolve_host(dst_addr)
        if src_host in self._excluded_hosts or dst_host in self._excluded_hosts:
            return None

        raw_bytes = int(flow.get("bytes", 0) or 0)
        raw_packets = int(flow.get("packets", 0) or 0)
        raw_rate = int(flow.get("sampling_rate", 0) or 0)
        if self.cfg.respect_sampling_rate and raw_rate > 0:
            scale = raw_rate
        else:
            scale = max(1, int(self.cfg.default_sampling_rate))
        scaled_bytes = raw_bytes * scale
        scaled_packets = raw_packets * scale

        proto = normalize_proto(flow.get("proto", ""))
        src_port = int(flow.get("src_port", 0) or 0)
        dst_port = int(flow.get("dst_port", 0) or 0)
        direction = self.classify_direction(src_addr, dst_addr)

        enriched: dict[str, Any] = {
            "bytes": scaled_bytes,
            "packets": scaled_packets,
            "src_addr": src_addr,
            "dst_addr": dst_addr,
            "src_host": src_host,
            "dst_host": dst_host,
            "proto": proto,
            "src_port": src_port,
            "dst_port": dst_port,
            "dir": direction,
            "site": self.cfg.site,
        }
        if self.cfg.include_sampler_label and flow.get("sampler_address"):
            enriched["sampler_address"] = str(flow["sampler_address"])

        self.metrics.flows_received.labels(site=self.cfg.site, dir=direction, proto=proto).inc()
        self.metrics.bytes_total.labels(site=self.cfg.site, dir=direction, proto=proto).inc(scaled_bytes)
        return enriched

    def ingest_records(self, records: list[dict[str, Any]]) -> tuple[int, int]:
        """Enrich and enqueue a list of parsed GoFlow2 flow dicts."""
        accepted = 0
        errors = 0
        now_ns = time.time_ns()
        for raw in records:
            try:
                enriched = self.enrich_flow(raw)
            except (ValueError, TypeError):
                errors += 1
                self.metrics.dropped_flows.inc()
                continue
            if enriched is None:
                continue
            raw_ts = raw.get("time_received_ns")
            ts_ns = int(raw_ts) if isinstance(raw_ts, (int, float)) and int(raw_ts) > 0 else now_ns
            self.shipper.enqueue(ts_ns, enriched)
            accepted += 1
        return accepted, errors

    def ingest_bytes(self, raw_bytes: bytes, content_encoding: str = "") -> tuple[int, int]:
        """Parse raw payload bytes (JSON/array/NDJSON/gzip), enrich, and enqueue."""
        records, parse_errors = parse_goflow2_batch(raw_bytes, content_encoding=content_encoding)
        if parse_errors:
            self.metrics.dropped_flows.inc(parse_errors)
        accepted, enrich_errors = self.ingest_records(records)
        return accepted, parse_errors + enrich_errors

    def flush(self) -> None:
        self.shipper.flush()

    def _start_http_server(self) -> None:
        pipeline = self
        host, port = _parse_host_port(self.cfg.http_listen_addr, "0.0.0.0", 8081)

        class _PayloadTooLarge(Exception):
            pass

        class IngestHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:
                LOGGER.debug("ingest http: " + format, *args)

            def _send_json(self, code: int, payload: dict[str, Any], close_conn: bool = False) -> None:
                body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
                if close_conn:
                    self.close_connection = True
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                if close_conn:
                    self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)

            def _read_chunked_body(self, max_bytes: int) -> bytes:
                buf = bytearray()
                hex_digits = frozenset(b"0123456789abcdefABCDEF")
                while True:
                    size_line = self.rfile.readline(65536)
                    if not size_line or not size_line.endswith(b"\n"):
                        raise ValueError("malformed chunk size line")
                    size_part = size_line.rstrip(b"\r\n").split(b";", 1)[0].strip()
                    if not size_part or any(c not in hex_digits for c in size_part):
                        raise ValueError("invalid chunk size")
                    chunk_size = int(size_part, 16)
                    if chunk_size == 0:
                        while True:
                            trailer = self.rfile.readline(65536)
                            if not trailer or trailer in (b"\r\n", b"\n"):
                                break
                            if not trailer.endswith(b"\n"):
                                raise ValueError("malformed chunk trailer")
                        return bytes(buf)
                    if len(buf) + chunk_size > max_bytes:
                        raise _PayloadTooLarge("payload exceeds maxBodyBytes")
                    chunk = self.rfile.read(chunk_size)
                    if len(chunk) != chunk_size:
                        raise ValueError("truncated chunk body")
                    buf.extend(chunk)
                    crlf = self.rfile.readline(4)
                    if crlf not in (b"\r\n", b"\n"):
                        raise ValueError("missing CRLF after chunk")

            def do_GET(self) -> None:
                path = self.path.split("?", 1)[0]
                if path == "/healthz":
                    self._send_json(200, {"status": "ok"})
                elif path == "/readyz":
                    if pipeline._ready.is_set():
                        self._send_json(200, {"status": "ready"})
                    else:
                        self._send_json(503, {"status": "starting"})
                else:
                    self._send_json(404, {"error": "not found"})

            def do_POST(self) -> None:
                path = self.path.split("?", 1)[0]
                if path not in ("/ingest", "/ingest/goflow2"):
                    self._send_json(404, {"error": "not found"})
                    return
                te_tokens = [
                    tok.strip().lower()
                    for tok in (self.headers.get("Transfer-Encoding") or "").split(",")
                    if tok.strip()
                ]
                if "chunked" in te_tokens:
                    try:
                        raw = self._read_chunked_body(pipeline.cfg.max_body_bytes)
                    except _PayloadTooLarge as exc:
                        self._send_json(413, {"error": str(exc)}, close_conn=True)
                        return
                    except (ValueError, OSError) as exc:
                        self._send_json(400, {"error": f"invalid chunked body: {exc}"}, close_conn=True)
                        return
                else:
                    raw_cl = self.headers.get("Content-Length")
                    if raw_cl is not None:
                        try:
                            length = int(raw_cl.strip())
                        except ValueError:
                            self._send_json(400, {"error": "invalid Content-Length"}, close_conn=True)
                            return
                        if length < 0:
                            self._send_json(400, {"error": "negative Content-Length"}, close_conn=True)
                            return
                        if length > pipeline.cfg.max_body_bytes:
                            self._send_json(413, {"error": "payload exceeds maxBodyBytes"}, close_conn=True)
                            return
                        raw = self.rfile.read(length) if length > 0 else b""
                        if len(raw) != length:
                            self._send_json(400, {"error": "incomplete request body"}, close_conn=True)
                            return
                    else:
                        raw = b""
                encoding = self.headers.get("Content-Encoding", "")
                try:
                    accepted, errors = pipeline.ingest_bytes(raw, content_encoding=encoding)
                except ValueError as exc:
                    pipeline.metrics.dropped_flows.inc()
                    self._send_json(400, {"error": str(exc)})
                    return
                self._send_json(202, {"accepted": accepted, "errors": errors})

        self._http_server = ThreadingHTTPServer((host, port), IngestHandler)
        self._http_server.daemon_threads = True
        t = threading.Thread(target=self._http_server.serve_forever, name="nxtflow-http-ingest", daemon=True)
        t.start()
        self._threads.append(t)

    def _start_metrics_server(self) -> None:
        pipeline = self
        host, port = _parse_host_port(self.cfg.metrics_listen_addr, "0.0.0.0", 9090)

        class MetricsHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:
                LOGGER.debug("metrics http: " + format, *args)

            def do_GET(self) -> None:
                path = self.path.split("?", 1)[0]
                if path == "/metrics":
                    body = pipeline.metrics.render()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                elif path == "/healthz":
                    body = b'{"status":"ok"}'
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()

        self._metrics_server = ThreadingHTTPServer((host, port), MetricsHandler)
        self._metrics_server.daemon_threads = True
        t = threading.Thread(target=self._metrics_server.serve_forever, name="nxtflow-metrics", daemon=True)
        t.start()
        self._threads.append(t)

    def _run_netbox_loop(self) -> None:
        try:
            self.netbox.sync_once()
        except Exception as exc:  # noqa: BLE001 — keep /readyz unblocked on unexpected NetBox sync error
            LOGGER.warning("Initial NetBox sync failed: %s", exc)
        finally:
            self._ready.set()
        while not self._stop_event.wait(self.cfg.netbox_sync_interval):
            try:
                self.netbox.sync_once()
            except Exception as exc:  # noqa: BLE001 — keep NetBox background thread alive
                LOGGER.warning("Periodic NetBox sync failed: %s", exc)

    def _run_file_tailer(self) -> None:
        src_path = Path(self.cfg.file_path)
        pos_path = Path(self.cfg.file_position_file)
        offset = 0
        last_inode: int | None = None

        if pos_path.is_file():
            try:
                saved = json.loads(pos_path.read_text(encoding="utf-8"))
                offset = int(saved.get("offset", 0))
                last_inode = saved.get("inode")
            except (OSError, ValueError, json.JSONDecodeError):
                offset = 0
                last_inode = None

        while not self._stop_event.is_set():
            try:
                if src_path.is_file():
                    st = src_path.stat()
                    inode = st.st_ino
                    size = st.st_size
                    if (last_inode is not None and inode != last_inode) or size < offset:
                        offset = 0
                    last_inode = inode

                    if size > offset:
                        with src_path.open("rb") as fh:
                            fh.seek(offset)
                            chunk = fh.read()
                        last_nl = chunk.rfind(b"\n")
                        if last_nl != -1:
                            complete = chunk[: last_nl + 1]
                            offset += len(complete)
                            try:
                                self.ingest_bytes(complete)
                            except ValueError:
                                self.metrics.dropped_flows.inc()
                            try:
                                pos_path.parent.mkdir(parents=True, exist_ok=True)
                                pos_path.write_text(
                                    json.dumps({"inode": inode, "offset": offset}),
                                    encoding="utf-8",
                                )
                            except OSError:
                                pass

                    if (
                        self.cfg.file_truncate_bytes > 0
                        and size >= self.cfg.file_truncate_bytes
                        and offset >= size
                    ):
                        with src_path.open("r+b") as fh:
                            fh.truncate(0)
                        offset = 0
                        try:
                            pos_path.write_text(json.dumps({"inode": inode, "offset": 0}), encoding="utf-8")
                        except OSError:
                            pass
            except OSError as exc:
                LOGGER.debug("File tailer cycle error: %s", exc)

            self._stop_event.wait(self.cfg.file_poll_interval)

    def _run_stdin_reader(self) -> None:
        stream = self._stdin_stream if self._stdin_stream is not None else sys.stdin
        for line in stream:
            if self._stop_event.is_set():
                break
            stripped = line.strip()
            if not stripped:
                continue
            try:
                self.ingest_bytes(stripped.encode("utf-8"))
            except ValueError:
                self.metrics.dropped_flows.inc()

    def start(self) -> None:
        self._stop_event.clear()
        self.shipper.start()
        self._start_metrics_server()
        if self.cfg.http_enabled:
            self._start_http_server()

        if self.cfg.netbox_enabled and self.cfg.netbox_url:
            nb_thread = threading.Thread(target=self._run_netbox_loop, name="nxtflow-netbox", daemon=True)
            nb_thread.start()
            self._threads.append(nb_thread)
        else:
            self._ready.set()

        if self.cfg.file_enabled and self.cfg.file_path != "-":
            ft_thread = threading.Thread(target=self._run_file_tailer, name="nxtflow-file-tail", daemon=True)
            ft_thread.start()
            self._threads.append(ft_thread)

        if self.cfg.stdin_enabled or (self.cfg.file_enabled and self.cfg.file_path == "-"):
            st_thread = threading.Thread(target=self._run_stdin_reader, name="nxtflow-stdin", daemon=True)
            st_thread.start()
            self._threads.append(st_thread)

    def stop(self) -> None:
        self._stop_event.set()
        if self._http_server is not None:
            self._http_server.shutdown()
            self._http_server.server_close()
            self._http_server = None
        if self._metrics_server is not None:
            self._metrics_server.shutdown()
            self._metrics_server.server_close()
            self._metrics_server = None
        self.shipper.stop(flush=True)
        self.rdns_cache.close()


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="nxtflow-enricher", description="nxtflow GoFlow2 enricher & Loki shipper")
    parser.add_argument("--config", default=None, help="Path to enricher YAML config (NXTFLOW_CONFIG_FILE)")
    parser.add_argument("--stdin", action="store_true", help="Read newline-delimited GoFlow2 JSON from stdin")
    parser.add_argument("--input-file", default=None, help="Tail GoFlow2 JSONL file (use '-' for stdin)")
    parser.add_argument("--log-level", default=os.environ.get("NXTFLOW_LOG_LEVEL", "INFO"), help="Logging level")
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, str(args.log_level).upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    overrides: dict[str, Any] = {}
    if args.stdin:
        overrides["stdin_enabled"] = True
    if args.input_file:
        if args.input_file == "-":
            overrides["stdin_enabled"] = True
            overrides["file_enabled"] = False
        else:
            overrides["file_enabled"] = True
            overrides["file_path"] = args.input_file

    cfg = load_enricher_config(config_file=args.config, **overrides)
    pipeline = EnricherPipeline(cfg)
    stop_flag = threading.Event()

    def _handle_sig(_signum: int, _frame: Any) -> None:
        stop_flag.set()

    signal.signal(signal.SIGTERM, _handle_sig)
    signal.signal(signal.SIGINT, _handle_sig)

    pipeline.start()
    LOGGER.info(
        "nxtflow-enricher started (site=%s, job=%s, http=%s, metrics=%s, mode=%s)",
        cfg.site,
        cfg.job,
        cfg.http_listen_addr,
        cfg.metrics_listen_addr,
        cfg.shipper_mode,
    )
    try:
        while not stop_flag.is_set():
            stop_flag.wait(1.0)
    finally:
        pipeline.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
