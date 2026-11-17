"""Loki HTTP client and LogQL telemetry query engine for nxtflow."""

from __future__ import annotations

import base64
import http.client
import json
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from typing import Any

from nxtflow.config import (
    NxtflowConfig,
    escape_logql_backtick,
    escape_logql_label,
    load_config,
    parse_range_seconds,
    sanitize_logql_regex,
    validate_dir,
    validate_range,
)


class LokiError(RuntimeError):
    """Raised when Loki returns an error or cannot be reached."""


def _build_ssl_context(tls_verify: bool | str) -> ssl.SSLContext:
    if tls_verify is False:
        return ssl._create_unverified_context()
    if isinstance(tls_verify, str):
        return ssl.create_default_context(cafile=tls_verify)
    return ssl.create_default_context()


def _percentile_95(values: list[float]) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    idx = min(len(s) - 1, int(0.95 * (len(s) - 1) + 0.5))
    return s[idx]


def _rate_window_and_step(range_str: str) -> tuple[str, str]:
    secs = parse_range_seconds(range_str)
    if secs <= 900:
        return "1m", "15s"
    if secs <= 3600:
        return "2m", "30s"
    if secs <= 21600:
        return "2m", "60s"
    if secs <= 86400:
        return "5m", "5m"
    if secs <= 604800:
        return "15m", "15m"
    return "1h", "1h"


def _extract_metric_results(data: dict[str, Any]) -> list[dict[str, Any]]:
    data_block = data.get("data") if isinstance(data, dict) else None
    results = data_block.get("result") if isinstance(data_block, dict) else None
    if not isinstance(results, list):
        return []
    out = []
    for item in results:
        if not isinstance(item, dict):
            continue
        raw_labels = item.get("metric")
        labels = raw_labels if isinstance(raw_labels, dict) else {}
        raw_val = item.get("value")
        if isinstance(raw_val, (list, tuple)) and len(raw_val) > 1:
            try:
                value = float(raw_val[1])
            except (TypeError, ValueError):
                value = 0.0
        else:
            value = 0.0
        out.append({"labels": labels, "value": value})
    out.sort(key=lambda x: x["value"], reverse=True)
    return out


class LokiClient:
    """Thread-safe Loki HTTP API client and LogQL query builder."""

    def __init__(self, config: NxtflowConfig | None = None) -> None:
        self.config = config or load_config()
        self._ssl_ctx = _build_ssl_context(self.config.tls_verify)

    def _build_headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.config.loki_token:
            headers["Authorization"] = f"Bearer {self.config.loki_token}"
        elif self.config.loki_user or self.config.loki_password:
            creds = f"{self.config.loki_user}:{self.config.loki_password}".encode()
            headers["Authorization"] = f"Basic {base64.b64encode(creds).decode('ascii')}"
        if self.config.loki_tenant_id:
            headers["X-Scope-OrgID"] = self.config.loki_tenant_id
        return headers

    def request(self, endpoint: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Execute GET request against Loki API, with optional explicit kubectl fallback."""
        qs = urllib.parse.urlencode(params or {})
        suffix = f"{endpoint}?{qs}" if qs else endpoint
        headers = self._build_headers()

        if not (self.config.use_kubectl and self.config.kube_context):
            try:
                req = urllib.request.Request(f"{self.config.loki_url}{suffix}", headers=headers)
                with urllib.request.urlopen(
                    req,
                    timeout=self.config.timeout_seconds,
                    context=self._ssl_ctx,
                ) as resp:
                    payload = json.loads(resp.read().decode("utf-8"))
                if not isinstance(payload, dict):
                    raise LokiError(f"Unexpected non-object JSON from Loki: {type(payload).__name__}")
                if payload.get("status") == "error":
                    raise LokiError(payload.get("error", "Unknown Loki error"))
                return payload
            except urllib.error.HTTPError as exc:
                body = exc.read().decode("utf-8", errors="replace").strip()
                raise LokiError(f"HTTP {exc.code}: {body[:200]}") from exc
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, http.client.HTTPException, OSError) as exc:
                if not self.config.kube_context:
                    raise LokiError(f"Loki request failed ({self.config.loki_url}): {exc}") from exc

        if not self.config.kube_context:
            raise LokiError("kubectl fallback requested but kube_context is not configured")

        cluster_url = f"{self.config.cluster_loki_url}{suffix}"
        req_payload = json.dumps({"url": cluster_url, "headers": headers})
        cmd = [
            "kubectl",
            "--context",
            self.config.kube_context,
            "-n",
            self.config.kube_namespace,
            "exec",
            "-i",
            self.config.kube_target,
            "--",
            "python3",
            "-c",
            (
                "import json, sys, urllib.request; "
                "cfg = json.load(sys.stdin); "
                "req = urllib.request.Request(cfg['url'], headers=cfg['headers']); "
                "print(urllib.request.urlopen(req, timeout=30).read().decode())"
            ),
        ]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=45,
                input=req_payload,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise LokiError(f"kubectl fallback failed: {exc}") from exc

        if proc.returncode != 0:
            raise LokiError(proc.stderr.strip() or f"kubectl exited with {proc.returncode}")
        try:
            payload = json.loads(proc.stdout.strip())
        except json.JSONDecodeError as exc:
            raise LokiError(f"Invalid JSON from kubectl fallback: {proc.stdout.strip()[:200]}") from exc
        if not isinstance(payload, dict):
            raise LokiError(f"Unexpected non-object JSON from kubectl fallback: {type(payload).__name__}")
        if payload.get("status") == "error":
            raise LokiError(payload.get("error", "Unknown Loki error"))
        return payload

    def check_readiness(self) -> list[str]:
        """Verify Loki API reachability using /loki/api/v1/label/site/values (never /ready)."""
        resp = self.request("/loki/api/v1/label/site/values")
        data = resp.get("data", [])
        return [str(s) for s in data] if isinstance(data, list) else []

    def query(self, expr: str, time_ts: int | None = None, limit: int | None = None) -> dict[str, Any]:
        params: dict[str, Any] = {"query": expr}
        if time_ts is not None:
            params["time"] = str(int(time_ts))
        if limit is not None:
            params["limit"] = str(int(limit))
        return self.request("/loki/api/v1/query", params)

    def range_query(
        self,
        expr: str,
        range_str: str = "5m",
        step: str = "15s",
        end_ts: int | None = None,
    ) -> dict[str, Any]:
        range_seconds = parse_range_seconds(range_str)
        now = int(end_ts if end_ts is not None else time.time())
        params = {
            "query": expr,
            "start": str(now - range_seconds),
            "end": str(now),
            "step": step,
        }
        return self.request("/loki/api/v1/query_range", params)

    def log_query(self, expr: str, range_str: str = "5m", limit: int = 200) -> list[dict[str, Any]]:
        range_seconds = parse_range_seconds(range_str)
        now = int(time.time())
        params = {
            "query": expr,
            "limit": str(int(limit)),
            "start": str(now - range_seconds),
            "end": str(now),
        }
        data = self.request("/loki/api/v1/query_range", params)
        data_block = data.get("data") if isinstance(data, dict) else None
        results = data_block.get("result") if isinstance(data_block, dict) else None
        if not isinstance(results, list):
            return []
        lines: list[dict[str, Any]] = []
        for stream in results:
            if not isinstance(stream, dict):
                continue
            stream_meta = stream.get("stream")
            stream_site = stream_meta.get("site", "") if isinstance(stream_meta, dict) else ""
            values = stream.get("values")
            if not isinstance(values, list):
                continue
            for entry in values:
                if not isinstance(entry, (list, tuple)) or len(entry) < 2:
                    continue
                _ts, line = entry[0], entry[1]
                if not isinstance(line, str):
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        if stream_site and not obj.get("site"):
                            obj["site"] = stream_site
                        lines.append(obj)
                except json.JSONDecodeError:
                    continue
        return lines

    def _job_matcher(self) -> str:
        return f'job="{escape_logql_label(self.config.job)}"'

    def _stream_selector(self, dir_val: str | None = None, site_val: str | None = None) -> str:
        d = validate_dir(dir_val)
        parts = [f'dir="{d}"' if d else 'dir=~"up|down|lan"']
        if site_val:
            parts.append(f'site="{escape_logql_label(site_val)}"')
        else:
            parts.append('site=~".*"')
        return ", ".join(parts)

    def _excluded_host_filters(self, field: str) -> str:
        clauses = [f'| {field} != ``']
        for host in self.config.excluded_hosts:
            safe = escape_logql_backtick(host)
            if safe:
                clauses.append(f'| {field} != `{safe}`')
        return " ".join(clauses)

    def _total_bits(self, sel: str, range_str: str = "5m", time_ts: int | None = None) -> float:
        expr = (
            f'sum(sum_over_time({{{self._job_matcher()}, {sel}}} '
            f'| json flow_bytes="bytes" | unwrap flow_bytes [{range_str}])) * 8'
        )
        res = _extract_metric_results(self.query(expr, time_ts=time_ts))
        return res[0]["value"] if res else 0.0

    def get_status_data(self, range_str: str = "5m") -> dict[str, Any]:
        """Return Loki site labels and per-site byte counts for collector health verification."""
        range_str = validate_range(range_str)
        sites = self.check_readiness()
        end_ts = int(time.time())
        stream_expr = (
            f'sum by (site, dir) (sum_over_time({{{self._job_matcher()}, site=~".+", dir=~"up|down|lan"}} '
            f'| json flow_bytes="bytes" | unwrap flow_bytes [{range_str}]))'
        )
        raw = _extract_metric_results(self.query(stream_expr, time_ts=end_ts))
        site_totals: dict[str, float] = {}
        streams: dict[str, float] = {}
        for item in raw:
            s = item["labels"].get("site", "unknown")
            d = item["labels"].get("dir", "?")
            val = item["value"]
            site_totals[s] = site_totals.get(s, 0.0) + val
            streams[f"{s}/{d}"] = val
        return {
            "loki_url": self.config.loki_url,
            "job": self.config.job,
            "sites_registered": sites,
            "active_streams": len(streams),
            "expected_streams": len(sites) * 3,
            "site_bytes": site_totals,
            "streams": streams,
            "range": range_str,
        }

    def get_summary_data(
        self,
        range_str: str = "5m",
        dir_val: str | None = None,
        site_val: str | None = None,
    ) -> dict[str, Any]:
        """Collect bandwidth summary across direction and site."""
        range_str = validate_range(range_str)
        dir_val = validate_dir(dir_val)
        end_ts = int(time.time())
        win, step = _rate_window_and_step(range_str)
        range_s = parse_range_seconds(range_str)
        site_clause = f'site="{escape_logql_label(site_val)}"' if site_val else 'site=~".*"'
        dir_filter = [dir_val] if dir_val else ["down", "up", "lan"]
        dir_map = {"down": "download", "up": "upload", "lan": "lan"}

        results: dict[str, Any] = {}
        total_series: dict[Any, float] = {}

        for d in ("down", "up", "lan"):
            label = dir_map[d]
            if d not in dir_filter:
                results[label] = {"bytes": 0.0, "bps": 0.0, "p95_bps": 0.0, "max_bps": 0.0}
                continue
            expr = (
                f'sum(sum_over_time({{{self._job_matcher()}, {site_clause}, dir="{d}"}} '
                f'| json flow_bytes="bytes" | unwrap flow_bytes [{range_str}]))'
            )
            r = _extract_metric_results(self.query(expr, time_ts=end_ts))
            total_bytes = r[0]["value"] if r else 0.0
            rate_expr = (
                f'sum(rate({{{self._job_matcher()}, {site_clause}, dir="{d}"}} '
                f'| json flow_bytes="bytes" | unwrap flow_bytes [{win}])) * 8'
            )
            rate_data = self.range_query(rate_expr, range_str, step, end_ts=end_ts)
            rate_vals: list[float] = []
            rate_block = rate_data.get("data") if isinstance(rate_data, dict) else None
            rate_results = rate_block.get("result") if isinstance(rate_block, dict) else None
            if isinstance(rate_results, list):
                for series in rate_results:
                    if not isinstance(series, dict):
                        continue
                    series_values = series.get("values")
                    if not isinstance(series_values, list):
                        continue
                    for entry in series_values:
                        if not isinstance(entry, (list, tuple)) or len(entry) < 2:
                            continue
                        ts, val = entry[0], entry[1]
                        try:
                            v = float(val)
                        except (TypeError, ValueError):
                            continue
                        rate_vals.append(v)
                        total_series[ts] = total_series.get(ts, 0.0) + v
            results[label] = {
                "bytes": total_bytes,
                "bps": total_bytes / range_s * 8,
                "p95_bps": _percentile_95(rate_vals),
                "max_bps": max(rate_vals) if rate_vals else 0.0,
            }

        grand_bytes = sum(v["bytes"] for v in results.values())
        for label in ("download", "upload", "lan"):
            results[label]["share_pct"] = round(results[label]["bytes"] / grand_bytes * 100, 1) if grand_bytes else 0.0

        results["total"] = {
            "bytes": grand_bytes,
            "bps": sum(v["bps"] for v in results.values()),
            "p95_bps": _percentile_95(list(total_series.values())),
            "max_bps": max(total_series.values()) if total_series else 0.0,
            "share_pct": 100.0 if grand_bytes else 0.0,
        }

        dir_regex = dir_val if dir_val else "up|down|lan"
        site_expr = (
            f'sum by (site) (sum_over_time({{{self._job_matcher()}, {site_clause}, dir=~"{dir_regex}"}} '
            f'| json flow_bytes="bytes" | unwrap flow_bytes [{range_str}]))'
        )
        by_site_raw = _extract_metric_results(self.query(site_expr, time_ts=end_ts))
        site_sum = sum(r["value"] for r in by_site_raw) or grand_bytes
        by_site: dict[str, dict[str, float]] = {}
        for r in by_site_raw:
            sname = r["labels"].get("site") or "unlabeled"
            by_site[sname] = {
                "bytes": r["value"],
                "bps": r["value"] / range_s * 8,
                "share_pct": round(r["value"] / site_sum * 100, 1) if site_sum else 0.0,
            }
        results["by_site"] = by_site
        results["window"] = {
            "range": range_str,
            "rate_window": win,
            "site": site_val or "all",
            "dir": dir_val or "all",
        }
        return results

    def get_top_data(
        self,
        field: str,
        n: int = 10,
        range_str: str = "5m",
        dir_val: str | None = None,
        site_val: str | None = None,
    ) -> list[dict[str, Any]]:
        if field not in ("src_host", "dst_host"):
            raise ValueError(f"Unsupported top field {field!r}")
        range_str = validate_range(range_str)
        n = max(1, int(n))
        sel = self._stream_selector(dir_val, site_val)
        end_ts = int(time.time())
        filters = self._excluded_host_filters(field)
        expr = (
            f'sort_desc(topk({n}, sum by ({field}) (sum_over_time({{{self._job_matcher()}, {sel}}} '
            f'| json flow_bytes="bytes", {field}="{field}" {filters} '
            f'| unwrap flow_bytes [{range_str}])))) * 8'
        )
        results = _extract_metric_results(self.query(expr, time_ts=end_ts))
        total_bits = self._total_bits(sel, range_str, time_ts=end_ts) or sum(r["value"] for r in results)
        return [
            {
                "name": r["labels"].get(field, "?"),
                "bits": r["value"],
                "bytes": r["value"] / 8,
                "share_pct": round(r["value"] / total_bits * 100, 1) if total_bits else 0.0,
            }
            for r in results
        ]

    def get_top_connections_data(
        self,
        n: int = 15,
        range_str: str = "5m",
        dir_val: str | None = None,
        site_val: str | None = None,
    ) -> list[dict[str, Any]]:
        range_str = validate_range(range_str)
        n = max(1, int(n))
        sel = self._stream_selector(dir_val, site_val)
        end_ts = int(time.time())
        src_filters = self._excluded_host_filters("src_host")
        dst_filters = self._excluded_host_filters("dst_host")
        expr = (
            f'sort_desc(topk({n}, sum by (src_host, dst_host) (sum_over_time({{{self._job_matcher()}, {sel}}} '
            f'| json flow_bytes="bytes", src_host="src_host", dst_host="dst_host" '
            f'{src_filters} {dst_filters} | unwrap flow_bytes [{range_str}])))) * 8'
        )
        results = _extract_metric_results(self.query(expr, time_ts=end_ts))
        total_bits = self._total_bits(sel, range_str, time_ts=end_ts) or sum(r["value"] for r in results)
        return [
            {
                "src": r["labels"].get("src_host", "?"),
                "dst": r["labels"].get("dst_host", "?"),
                "bits": r["value"],
                "bytes": r["value"] / 8,
                "share_pct": round(r["value"] / total_bits * 100, 1) if total_bits else 0.0,
            }
            for r in results
        ]

    def get_top_ports_data(
        self,
        n: int = 10,
        range_str: str = "5m",
        dir_val: str | None = None,
        site_val: str | None = None,
    ) -> list[dict[str, Any]]:
        range_str = validate_range(range_str)
        n = max(1, int(n))
        sel = self._stream_selector(dir_val, site_val)
        end_ts = int(time.time())
        # Bound to <10000 ports (.{1,4}) so high ephemeral return ports do not trip Loki's 5000-series query limit.
        expr = (
            f'sort_desc(topk({n}, sum by (dst_port) (sum_over_time({{{self._job_matcher()}, {sel}}} '
            f'| json flow_bytes="bytes", dst_port="dst_port" '
            f'| dst_port =~ `.{{1,4}}` | __error__=`` | unwrap flow_bytes [{range_str}])))) * 8'
        )
        results = _extract_metric_results(self.query(expr, time_ts=end_ts))
        total_bits = sum(r["value"] for r in results)
        return [
            {
                "port": r["labels"].get("dst_port", "?"),
                "bits": r["value"],
                "bytes": r["value"] / 8,
                "share_pct": round(r["value"] / total_bits * 100, 1) if total_bits else 0.0,
            }
            for r in results
        ]

    def get_host_data(
        self,
        name: str,
        range_str: str = "5m",
        site_val: str | None = None,
    ) -> dict[str, Any] | None:
        range_str = validate_range(range_str)
        safe_name = sanitize_logql_regex(name)
        sel = self._stream_selector(None, site_val)
        lines = self.log_query(f'{{{self._job_matcher()}, {sel}}} |~ `{safe_name}` | json', range_str, 500)
        if not lines:
            return None
        dirs: Counter[str] = Counter()
        sites: Counter[str] = Counter()
        total_bytes = 0
        peers: Counter[str] = Counter()
        ports: Counter[Any] = Counter()
        needle = name.strip().lower()
        for line in lines:
            dirs[str(line.get("dir") or "?")] += 1
            sites[str(line.get("site") or "?")] += 1
            b = int(line.get("bytes") or 0)
            total_bytes += b
            src = str(line.get("src_host") or "")
            dst = str(line.get("dst_host") or "")
            src_addr = str(line.get("src_addr") or "")
            if needle in src.lower() or needle in src_addr.lower():
                peer = dst
            else:
                peer = src
            if peer:
                peers[peer] += b
            raw_port = line.get("dst_port")
            ports["?" if raw_port is None or raw_port == "" else raw_port] += b
        return {
            "host": name,
            "flows": len(lines),
            "bytes": total_bytes,
            "direction": dict(dirs),
            "sites": dict(sites),
            "top_peers": [{"name": k, "bytes": v} for k, v in peers.most_common(10)],
            "top_ports": [{"port": k, "bytes": v} for k, v in ports.most_common(10)],
        }

    def get_sessions_data(
        self,
        name: str,
        range_str: str = "5m",
        site_val: str | None = None,
        limit: int = 30,
    ) -> list[dict[str, Any]]:
        range_str = validate_range(range_str)
        limit = max(1, int(limit))
        safe_name = sanitize_logql_regex(name)
        sel = self._stream_selector(None, site_val)
        lines = self.log_query(f'{{{self._job_matcher()}, {sel}}} |~ `{safe_name}` | json', range_str, 1000)
        if not lines:
            return []
        sessions: Counter[tuple[str, str, str, str, str]] = Counter()
        session_bytes: Counter[tuple[str, str, str, str, str]] = Counter()
        for line in lines:
            raw_port = line.get("dst_port")
            key = (
                str(line.get("site") or "?"),
                str(line.get("src_host") or ""),
                str(line.get("dst_host") or ""),
                "" if raw_port is None else str(raw_port),
                str(line.get("proto") or ""),
            )
            sessions[key] += 1
            session_bytes[key] += int(line.get("bytes") or 0)
        sorted_sessions = sorted(session_bytes.items(), key=lambda x: x[1], reverse=True)
        return [
            {
                "site": k[0],
                "src": k[1],
                "dst": k[2],
                "port": k[3],
                "proto": k[4],
                "flows": sessions[k],
                "bytes": b,
            }
            for k, b in sorted_sessions[:limit]
        ]

    def get_search_data(
        self,
        term: str,
        range_str: str = "5m",
        n: int = 20,
        site_val: str | None = None,
    ) -> tuple[int, list[dict[str, Any]]]:
        range_str = validate_range(range_str)
        n = max(1, int(n))
        safe_term = sanitize_logql_regex(term)
        sel = self._stream_selector(None, site_val)
        lines = self.log_query(f'{{{self._job_matcher()}, {sel}}} |~ `{safe_term}` | json', range_str, 500)
        return len(lines), lines[:n]

    def get_directory_data(
        self,
        range_str: str = "5m",
        site_val: str | None = None,
        limit: int = 500,
    ) -> dict[str, str]:
        range_str = validate_range(range_str)
        limit = max(1, int(limit))
        sel = self._stream_selector(None, site_val)
        lines = self.log_query(f'{{{self._job_matcher()}, {sel}}} | json', range_str, limit)
        mapping: dict[str, str] = {}
        for line in lines:
            for addr_key, host_key in (("src_addr", "src_host"), ("dst_addr", "dst_host")):
                addr = str(line.get(addr_key) or "").strip()
                host = str(line.get(host_key) or "").strip()
                if addr and host and addr != host:
                    mapping[addr] = host
        return dict(sorted(mapping.items(), key=lambda item: (item[1], item[0])))
