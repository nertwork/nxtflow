"""nxtflow CLI — query multi-site NetFlow/IPFIX/sFlow telemetry from Loki."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

import yaml

from nxtflow.config import load_config, validate_dir, validate_range
from nxtflow.loki import LokiClient, LokiError, _safe_int


def fmt_bytes(b: float) -> str:
    val = float(b)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(val) < 1024:
            return f"{val:.1f} {unit}"
        val /= 1024
    return f"{val:.1f} PiB"


def fmt_bps(bps: float) -> str:
    val = float(bps)
    for unit in ("bps", "Kbps", "Mbps", "Gbps"):
        if abs(val) < 1000:
            return f"{val:.1f} {unit}"
        val /= 1000
    return f"{val:.1f} Tbps"


def _make_common_parser(with_defaults: bool = False) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(add_help=False)
    default_range = "5m" if with_defaults else argparse.SUPPRESS
    default_none = None if with_defaults else argparse.SUPPRESS
    default_false = False if with_defaults else argparse.SUPPRESS
    p.add_argument("--range", default=default_range, help="Time range (e.g. 5m, 15m, 1h, 7d; default: 5m)")
    p.add_argument("--dir", dest="dir_val", default=default_none, help="Direction filter (up|down|lan)")
    p.add_argument("--site", dest="site_val", default=default_none, help="Site label filter")
    p.add_argument("-n", "--limit", type=int, default=default_none, help="Maximum results to return")
    p.add_argument("--json", dest="as_json", action="store_true", default=default_false, help="Output JSON")
    p.add_argument("--config", dest="config_file", default=default_none, help="Path to YAML config file")
    return p


def build_parser() -> argparse.ArgumentParser:
    top_common = _make_common_parser(with_defaults=True)
    sub_common = _make_common_parser(with_defaults=False)

    parser = argparse.ArgumentParser(
        prog="nxtflow",
        description="Query multi-site NetFlow/IPFIX/sFlow telemetry from Loki.",
        parents=[top_common],
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    sub.add_parser("status", aliases=["health"], parents=[sub_common], help="Collector stream & ingestion health")
    sub.add_parser("summary", aliases=["traffic"], parents=[sub_common], help="Bandwidth summary by direction & site")

    p_top_src = sub.add_parser(
        "top-sources",
        aliases=["top-src", "top-talkers"],
        parents=[sub_common],
        help="Top source hosts by traffic",
    )
    p_top_src.add_argument("count", nargs="?", type=int, help="Number of results (default: 10)")

    p_top_dst = sub.add_parser(
        "top-destinations",
        aliases=["top-dst"],
        parents=[sub_common],
        help="Top destination hosts/services by traffic",
    )
    p_top_dst.add_argument("count", nargs="?", type=int, help="Number of results (default: 10)")

    p_top_conn = sub.add_parser(
        "top-connections",
        aliases=["top-conn", "flows"],
        parents=[sub_common],
        help="Top source->destination pairs by traffic",
    )
    p_top_conn.add_argument("count", nargs="?", type=int, help="Number of results (default: 15)")

    p_top_ports = sub.add_parser("top-ports", parents=[sub_common], help="Top destination ports (<10000)")
    p_top_ports.add_argument("count", nargs="?", type=int, help="Number of results (default: 10)")

    p_host = sub.add_parser("host", parents=[sub_common], help="Traffic breakdown for a specific host")
    p_host.add_argument("target", help="Hostname or IP address")

    p_sess = sub.add_parser("sessions", parents=[sub_common], help="Active 5-tuple sessions for a host")
    p_sess.add_argument("target", help="Hostname or IP address")
    p_sess.add_argument("count", nargs="?", type=int, help="Maximum sessions to show (default: 30)")

    p_search = sub.add_parser("search", parents=[sub_common], help="Search recent flows matching term")
    p_search.add_argument("target", help="IP, hostname, port, or protocol")
    p_search.add_argument("count", nargs="?", type=int, help="Maximum matching flows to show (default: 20)")

    sub.add_parser("directory", parents=[sub_common], help="IP->hostname directory from recent flows")
    sub.add_parser("config", parents=[sub_common], help="Show resolved nxtflow configuration")

    return parser


def _resolve_limit(args: argparse.Namespace, default: int) -> int:
    if getattr(args, "limit", None) is not None:
        return max(1, int(args.limit))
    if getattr(args, "count", None) is not None:
        return max(1, int(args.count))
    return max(1, default)


def _render_status(st: dict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(st, indent=2))
        return
    print(f"nxtflow Collector Status (last {st['range']}, Loki={st['loki_url']})")
    print(
        f"  Sites registered: {', '.join(st['sites_registered']) or 'none'} "
        f"| Active streams: {st['active_streams']}/{st['expected_streams']}"
    )
    for s in sorted(st["site_bytes"]):
        b = st["site_bytes"][s]
        dirs = ", ".join(
            f"{d}={fmt_bytes(st['streams'][f'{s}/{d}'])}"
            for d in ("down", "up", "lan")
            if f"{s}/{d}" in st["streams"]
        )
        print(f"  {s:8s} {fmt_bytes(b):>10s} ({dirs})")


def _render_summary(results: dict, site_val: str | None, as_json: bool) -> None:
    if as_json:
        print(json.dumps(results, indent=2))
        return
    win = results["window"]["rate_window"]
    range_str = results["window"]["range"]
    scope = f", site={site_val}" if site_val else ""
    print(f"nxtflow Summary (last {range_str}, {win} smoothed rate{scope})")
    for key, title in (("download", "Download"), ("upload", "Upload"), ("lan", "LAN"), ("total", "Total")):
        v = results[key]
        share = f" | Share {v['share_pct']:5.1f}%" if key != "total" else ""
        print(
            f"  {title:9s} {fmt_bytes(v['bytes']):>10s} | Avg {fmt_bps(v['bps']):>10s} "
            f"| P95 {fmt_bps(v['p95_bps']):>10s}{share}"
        )
    if results["by_site"]:
        print(
            "  Sites:    "
            + ", ".join(f"{k}={fmt_bytes(v['bytes'])} ({v['share_pct']:.1f}%)" for k, v in results["by_site"].items())
        )


def _render_top(items: list[dict], field: str, n: int, range_str: str, site_val: str | None, as_json: bool) -> None:
    if as_json:
        print(json.dumps(items, indent=2))
        return
    label = field.replace("_", " ").title()
    scope = f", site={site_val}" if site_val else ""
    print(f"Top {label}s (last {range_str}, {n} max{scope})")
    for item in items:
        print(f"  {item['name']:30s} {fmt_bytes(item['bytes']):>10s}  ({item['share_pct']:5.1f}%)")


def _render_top_connections(items: list[dict], n: int, range_str: str, site_val: str | None, as_json: bool) -> None:
    if as_json:
        print(json.dumps(items, indent=2))
        return
    scope = f", site={site_val}" if site_val else ""
    print(f"Top Connections (last {range_str}, {n} max{scope})")
    print(f"  {'Source':25s} {'Destination':25s} {'Traffic':>12s} {'Share':>8s}")
    print(f"  {'─' * 25} {'─' * 25} {'─' * 12} {'─' * 8}")
    for item in items:
        print(f"  {item['src']:25s} {item['dst']:25s} {fmt_bytes(item['bytes']):>12s} {item['share_pct']:6.1f}%")


def _render_top_ports(items: list[dict], n: int, range_str: str, site_val: str | None, as_json: bool) -> None:
    if as_json:
        print(json.dumps(items, indent=2))
        return
    scope = f", site={site_val}" if site_val else ""
    print(f"Top Destination Ports (last {range_str}, {n} max{scope})")
    for item in items:
        print(f"  {item['port']:8s} {fmt_bytes(item['bytes']):>10s}  ({item['share_pct']:5.1f}%)")


def _render_host(name: str, data: dict | None, range_str: str, as_json: bool) -> None:
    if not data:
        print(json.dumps({"host": name, "flows": 0}) if as_json else f"No traffic found for '{name}' in last {range_str}")
        return
    if as_json:
        print(json.dumps(data, indent=2))
        return
    print(f"Host: {name} (last {range_str})")
    print(f"  Flows: {data['flows']}, Total: {fmt_bytes(data['bytes'])}")
    print(f"  Sites: {', '.join(f'{k}={v}' for k, v in data['sites'].items())}")
    print(f"  Direction: {', '.join(f'{k}={v}' for k, v in data['direction'].items())}")
    print("\n  Top Peers:")
    for p in data["top_peers"]:
        print(f"    {p['name']:30s} {fmt_bytes(p['bytes'])}")
    print("\n  Top Ports:")
    for p in data["top_ports"]:
        print(f"    {p['port']!s:8s} {fmt_bytes(p['bytes'])}")


def _render_sessions(name: str, rows: list[dict], range_str: str, as_json: bool) -> None:
    if not rows:
        print(json.dumps([]) if as_json else f"No sessions found for '{name}' in last {range_str}")
        return
    if as_json:
        print(json.dumps(rows, indent=2))
        return
    print(f"Sessions for {name} (last {range_str}): {len(rows)} shown")
    print(f"  {'Site':6s} {'Source':22s} {'Destination':22s} {'Port':>6s} {'Proto':>5s} {'Flows':>6s} {'Traffic':>10s}")
    print(f"  {'─' * 6} {'─' * 22} {'─' * 22} {'─' * 6} {'─' * 5} {'─' * 6} {'─' * 10}")
    for r in rows:
        print(
            f"  {r['site']:6s} {r['src']:22s} {r['dst']:22s} {r['port']:>6s} "
            f"{r['proto']:>5s} {r['flows']:>6d} {fmt_bytes(r['bytes']):>10s}"
        )


def _render_search(term: str, total: int, rows: list[dict], range_str: str, as_json: bool) -> None:
    if as_json:
        print(json.dumps(rows, indent=2))
        return
    print(f"Search: '{term}' (last {range_str}, {total} matches)")
    for line in rows:
        site = str(line.get("site") or "?")
        src = str(line.get("src_host") or "?")
        dst = str(line.get("dst_host") or "?")
        raw_port = line.get("dst_port")
        port = "?" if raw_port is None or raw_port == "" else str(raw_port)
        proto = str(line.get("proto") or "?")
        b = fmt_bytes(_safe_int(line.get("bytes"), 0))
        print(f"  [{site:5s}] {src:22s} -> {dst:22s} :{port:<6} {proto:4s} {b}")


def _render_directory(mapping: dict[str, str], range_str: str, as_json: bool) -> None:
    if as_json:
        print(json.dumps(mapping, indent=2))
        return
    print(f"Network Directory ({len(mapping)} entries, last {range_str})")
    print(f"  {'IP Address':20s} {'Name'}")
    print(f"  {'─' * 20} {'─' * 30}")
    for ip, name in mapping.items():
        print(f"  {ip:20s} {name}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    if not args.command:
        parser.print_help()
        return 0

    as_json = bool(getattr(args, "as_json", False))
    try:
        range_str = validate_range(args.range)
        dir_val = validate_dir(args.dir_val)
        cfg = load_config(config_file=args.config_file)
    except (ValueError, TypeError, OSError, yaml.YAMLError) as exc:
        if as_json:
            print(json.dumps({"error": str(exc)}), file=sys.stderr)
        else:
            print(f"Error: {exc}", file=sys.stderr)
        return 2

    cmd = args.command
    if cmd == "config":
        data = cfg.redacted_dict()
        if as_json:
            print(json.dumps(data, indent=2))
        else:
            print("nxtflow Active Configuration")
            for k, v in data.items():
                print(f"  {k:18s}: {v}")
        return 0

    try:
        client = LokiClient(cfg)
        if cmd in ("status", "health"):
            _render_status(client.get_status_data(range_str=range_str), as_json)
        elif cmd in ("summary", "traffic"):
            _render_summary(
                client.get_summary_data(range_str=range_str, dir_val=dir_val, site_val=args.site_val),
                args.site_val,
                as_json,
            )
        elif cmd in ("top-sources", "top-src", "top-talkers"):
            n = _resolve_limit(args, 10)
            items = client.get_top_data("src_host", n=n, range_str=range_str, dir_val=dir_val, site_val=args.site_val)
            _render_top(items, "src_host", n, range_str, args.site_val, as_json)
        elif cmd in ("top-destinations", "top-dst"):
            n = _resolve_limit(args, 10)
            items = client.get_top_data("dst_host", n=n, range_str=range_str, dir_val=dir_val, site_val=args.site_val)
            _render_top(items, "dst_host", n, range_str, args.site_val, as_json)
        elif cmd in ("top-connections", "top-conn", "flows"):
            n = _resolve_limit(args, 15)
            items = client.get_top_connections_data(n=n, range_str=range_str, dir_val=dir_val, site_val=args.site_val)
            _render_top_connections(items, n, range_str, args.site_val, as_json)
        elif cmd == "top-ports":
            n = _resolve_limit(args, 10)
            items = client.get_top_ports_data(n=n, range_str=range_str, dir_val=dir_val, site_val=args.site_val)
            _render_top_ports(items, n, range_str, args.site_val, as_json)
        elif cmd == "host":
            data = client.get_host_data(args.target, range_str=range_str, site_val=args.site_val)
            _render_host(args.target, data, range_str, as_json)
        elif cmd == "sessions":
            n = _resolve_limit(args, 30)
            rows = client.get_sessions_data(args.target, range_str=range_str, site_val=args.site_val, limit=n)
            _render_sessions(args.target, rows, range_str, as_json)
        elif cmd == "search":
            n = _resolve_limit(args, 20)
            total, rows = client.get_search_data(args.target, range_str=range_str, n=n, site_val=args.site_val)
            _render_search(args.target, total, rows, range_str, as_json)
        elif cmd == "directory":
            n = _resolve_limit(args, 500)
            mapping = client.get_directory_data(range_str=range_str, site_val=args.site_val, limit=n)
            _render_directory(mapping, range_str, as_json)
    except (LokiError, ValueError, OSError) as exc:
        if as_json:
            print(json.dumps({"error": str(exc)}), file=sys.stderr)
        else:
            print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
