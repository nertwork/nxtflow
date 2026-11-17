"""Configuration loading, validation, and LogQL escaping helpers for nxtflow."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

DEFAULT_LOKI_URL = "http://localhost:3100"
DEFAULT_JOB = "nxtflow"
DEFAULT_EXCLUDED_HOSTS = ["multicast", "link-local"]
DEFAULT_KUBE_NAMESPACE = "nxtflow"
DEFAULT_KUBE_TARGET = "deploy/nxtflow-enricher"
DEFAULT_CLUSTER_LOKI_URL = "http://localhost:3100"
MAX_RANGE_SECONDS = 30 * 86400  # 30d

_RANGE_RE = re.compile(r"^([1-9]\d*)([smhd])$")
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
_VALID_DIRS = frozenset({"up", "down", "lan"})


def parse_tls_verify(value: Any) -> bool | str:
    """Parse TLS verification setting into bool or CA bundle path."""
    if isinstance(value, bool):
        return value
    if value is None:
        return True
    s = str(value).strip()
    low = s.lower()
    if low in ("", "true", "1", "yes", "on"):
        return True
    if low in ("false", "0", "no", "off"):
        return False
    return s


def parse_excluded_hosts(value: Any) -> list[str]:
    """Parse excluded hosts from comma-separated string or list."""
    if value is None:
        return list(DEFAULT_EXCLUDED_HOSTS)
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return []
        return [item.strip() for item in stripped.split(",") if item.strip()]
    if isinstance(value, (list, tuple)):
        return [str(item).strip() for item in value if str(item).strip()]
    return list(DEFAULT_EXCLUDED_HOSTS)


def validate_range(range_str: str) -> str:
    r"""Validate Loki range duration string (^[1-9]\d*[smhd]$, max 30d)."""
    if not isinstance(range_str, str):
        raise TypeError(f"Invalid range {range_str!r}: expected string like '5m', '1h', '7d'")
    candidate = range_str.strip()
    m = _RANGE_RE.match(candidate)
    if not m:
        raise ValueError(rf"Invalid range {range_str!r}: must match ^[1-9]\d*[smhd]$ (e.g. 5m, 1h, 7d)")
    qty = int(m.group(1))
    unit = m.group(2)
    total_seconds = qty * _UNIT_SECONDS[unit]
    if total_seconds > MAX_RANGE_SECONDS:
        raise ValueError(f"Range {range_str!r} exceeds maximum allowed duration of 30d")
    return candidate


def parse_range_seconds(range_str: str) -> int:
    """Validate and convert range duration string into seconds."""
    valid = validate_range(range_str)
    qty = int(valid[:-1])
    unit = valid[-1]
    return qty * _UNIT_SECONDS[unit]


def validate_dir(dir_val: str | None) -> str | None:
    """Validate flow direction filter (up|down|lan)."""
    if dir_val is None:
        return None
    cleaned = str(dir_val).strip().lower()
    if not cleaned:
        return None
    if cleaned not in _VALID_DIRS:
        raise ValueError(f"Invalid direction {dir_val!r}: must be one of up, down, lan")
    return cleaned


def clamp_limit(limit: int, min_val: int = 1, max_val: int = 100) -> int:
    """Clamp integer limit to [min_val, max_val]."""
    try:
        val = int(limit)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid limit {limit!r}: must be an integer") from exc
    return max(min_val, min(max_val, val))


def escape_logql_label(value: str) -> str:
    """Escape a string for safe inclusion inside LogQL double-quoted label matchers."""
    cleaned = str(value).replace("\r", "").replace("\n", "").replace("\x00", "")
    return cleaned.replace("\\", "\\\\").replace('"', '\\"')


def escape_logql_backtick(value: str) -> str:
    """Sanitize a string for safe inclusion inside LogQL backtick raw literals."""
    return str(value).replace("`", "").replace("\r", "").replace("\n", "").replace("\x00", "")


def sanitize_logql_regex(value: str) -> str:
    """Sanitize and regex-escape a search/host term for safe LogQL |~ `...` matching."""
    cleaned = escape_logql_backtick(value).strip()
    if not cleaned:
        raise ValueError("Search or host filter term cannot be empty")
    return re.escape(cleaned)


@dataclass
class NxtflowConfig:
    """Resolved runtime configuration for nxtflow CLI and MCP server."""

    loki_url: str = DEFAULT_LOKI_URL
    job: str = DEFAULT_JOB
    tls_verify: bool | str = True
    loki_token: str = ""
    loki_user: str = ""
    loki_password: str = ""
    loki_tenant_id: str = ""
    excluded_hosts: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDED_HOSTS))
    kube_context: str = ""
    kube_namespace: str = DEFAULT_KUBE_NAMESPACE
    kube_target: str = DEFAULT_KUBE_TARGET
    cluster_loki_url: str = DEFAULT_CLUSTER_LOKI_URL
    use_kubectl: bool = False
    timeout_seconds: float = 15.0
    config_file: str = ""

    def redacted_dict(self) -> dict[str, Any]:
        """Return config dictionary with secrets redacted for safe display."""
        return {
            "loki_url": self.loki_url,
            "job": self.job,
            "tls_verify": self.tls_verify,
            "loki_token": "***" if self.loki_token else "",
            "loki_user": self.loki_user,
            "loki_password": "***" if self.loki_password else "",
            "loki_tenant_id": self.loki_tenant_id,
            "excluded_hosts": list(self.excluded_hosts),
            "kube_context": self.kube_context,
            "kube_namespace": self.kube_namespace,
            "kube_target": self.kube_target,
            "cluster_loki_url": self.cluster_loki_url,
            "use_kubectl": self.use_kubectl,
            "timeout_seconds": self.timeout_seconds,
            "config_file": self.config_file,
        }


def _read_yaml_config(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise TypeError(f"Config file {path} must contain a YAML mapping")
    return raw


def load_config(
    config_file: str | Path | None = None,
    **overrides: Any,
) -> NxtflowConfig:
    """Load configuration with precedence: defaults < YAML < env < explicit overrides."""
    cfg = NxtflowConfig()

    env_cfg_path = os.environ.get("NXTFLOW_CONFIG_FILE", "").strip()
    default_cfg_path = Path.home() / ".config" / "nxtflow" / "config.yaml"
    resolved_path: Path | None = None
    if config_file:
        resolved_path = Path(config_file).expanduser()
        if not resolved_path.is_file():
            raise FileNotFoundError(f"Config file not found: {resolved_path}")
    elif env_cfg_path:
        resolved_path = Path(env_cfg_path).expanduser()
        if not resolved_path.is_file():
            raise FileNotFoundError(f"Config file not found: {resolved_path}")
    elif default_cfg_path.is_file():
        resolved_path = default_cfg_path

    if resolved_path is not None and resolved_path.is_file():
        cfg.config_file = str(resolved_path)
        data = _read_yaml_config(resolved_path)
        loki_sec = data.get("loki") if isinstance(data.get("loki"), dict) else {}
        kube_sec = data.get("kube") if isinstance(data.get("kube"), dict) else {}

        if "loki_url" in data or "url" in loki_sec:
            cfg.loki_url = str(data.get("loki_url", loki_sec.get("url", cfg.loki_url))).rstrip("/")
        if "job" in data:
            cfg.job = str(data["job"])
        if "tls_verify" in data or "tlsVerify" in loki_sec:
            cfg.tls_verify = parse_tls_verify(data.get("tls_verify", loki_sec.get("tlsVerify")))
        if "loki_token" in data or "bearerToken" in loki_sec:
            cfg.loki_token = str(data.get("loki_token", loki_sec.get("bearerToken", "")) or "")
        if "loki_user" in data or "username" in loki_sec:
            cfg.loki_user = str(data.get("loki_user", loki_sec.get("username", "")) or "")
        if "loki_password" in data or "password" in loki_sec:
            cfg.loki_password = str(data.get("loki_password", loki_sec.get("password", "")) or "")
        if "loki_tenant_id" in data or "tenantId" in loki_sec:
            cfg.loki_tenant_id = str(data.get("loki_tenant_id", loki_sec.get("tenantId", "")) or "")
        if "excluded_hosts" in data or "excludedHosts" in data:
            raw_excl = data.get("excluded_hosts", data.get("excludedHosts"))
            cfg.excluded_hosts = parse_excluded_hosts(raw_excl)
        if "kube_context" in data or "context" in kube_sec:
            cfg.kube_context = str(data.get("kube_context", kube_sec.get("context", "")) or "")
        if "kube_namespace" in data or "namespace" in kube_sec:
            cfg.kube_namespace = str(data.get("kube_namespace", kube_sec.get("namespace", cfg.kube_namespace)) or cfg.kube_namespace)
        if "kube_target" in data or "target" in kube_sec:
            cfg.kube_target = str(data.get("kube_target", kube_sec.get("target", cfg.kube_target)) or cfg.kube_target)
        if "cluster_loki_url" in data:
            cfg.cluster_loki_url = str(data["cluster_loki_url"]).rstrip("/")
        if "timeout_seconds" in data:
            cfg.timeout_seconds = float(data["timeout_seconds"])

    # Environment overrides
    if "NXTFLOW_LOKI_URL" in os.environ and os.environ["NXTFLOW_LOKI_URL"].strip():
        cfg.loki_url = os.environ["NXTFLOW_LOKI_URL"].strip().rstrip("/")
    if "NXTFLOW_JOB" in os.environ and os.environ["NXTFLOW_JOB"].strip():
        cfg.job = os.environ["NXTFLOW_JOB"].strip()
    if "NXTFLOW_TLS_VERIFY" in os.environ:
        cfg.tls_verify = parse_tls_verify(os.environ["NXTFLOW_TLS_VERIFY"])
    if "NXTFLOW_LOKI_TOKEN" in os.environ:
        cfg.loki_token = os.environ["NXTFLOW_LOKI_TOKEN"].strip()
    if "NXTFLOW_LOKI_USER" in os.environ:
        cfg.loki_user = os.environ["NXTFLOW_LOKI_USER"].strip()
    elif "NXTFLOW_LOKI_USERNAME" in os.environ:
        cfg.loki_user = os.environ["NXTFLOW_LOKI_USERNAME"].strip()
    if "NXTFLOW_LOKI_PASSWORD" in os.environ:
        cfg.loki_password = os.environ["NXTFLOW_LOKI_PASSWORD"]
    if "NXTFLOW_LOKI_TENANT_ID" in os.environ:
        cfg.loki_tenant_id = os.environ["NXTFLOW_LOKI_TENANT_ID"].strip()
    if "NXTFLOW_EXCLUDED_HOSTS" in os.environ:
        cfg.excluded_hosts = parse_excluded_hosts(os.environ["NXTFLOW_EXCLUDED_HOSTS"])
    if "NXTFLOW_KUBE_CONTEXT" in os.environ:
        cfg.kube_context = os.environ["NXTFLOW_KUBE_CONTEXT"].strip()
    if "NXTFLOW_KUBE_NAMESPACE" in os.environ and os.environ["NXTFLOW_KUBE_NAMESPACE"].strip():
        cfg.kube_namespace = os.environ["NXTFLOW_KUBE_NAMESPACE"].strip()
    if "NXTFLOW_KUBE_TARGET" in os.environ and os.environ["NXTFLOW_KUBE_TARGET"].strip():
        cfg.kube_target = os.environ["NXTFLOW_KUBE_TARGET"].strip()
    if "NXTFLOW_CLUSTER_LOKI_URL" in os.environ and os.environ["NXTFLOW_CLUSTER_LOKI_URL"].strip():
        cfg.cluster_loki_url = os.environ["NXTFLOW_CLUSTER_LOKI_URL"].strip().rstrip("/")
    if os.environ.get("NXTFLOW_USE_KUBECTL", "").strip() == "1":
        cfg.use_kubectl = True

    # Explicit overrides
    for key, val in overrides.items():
        if val is not None and hasattr(cfg, key):
            if key == "loki_url":
                val = str(val).rstrip("/")
            elif key == "tls_verify":
                val = parse_tls_verify(val)
            elif key == "excluded_hosts":
                val = parse_excluded_hosts(val)
            setattr(cfg, key, val)

    return cfg
