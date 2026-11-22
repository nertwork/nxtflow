#!/usr/bin/env python3
"""Synthetic NetFlow v9 / v5 UDP packet generator for nxtflow smoke tests & demos.

Uses only Python stdlib (zero external dependencies) and RFC 1918 + well-known public
IPs so GoFlow2 -> nxtflow-enricher -> Loki -> Grafana pipelines can be verified
end-to-end without a physical router exporter.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import random
import socket
import struct
import sys
import time
from dataclasses import dataclass

# Safe RFC 1918 + public well-known DNS/CDN IPs (Zero-PII compliant)
LOCAL_HOSTS = [
    "192.168.1.10",
    "192.168.1.20",
    "192.168.1.35",
    "10.0.0.50",
    "10.0.0.51",
    "172.16.10.12",
]

EXTERNAL_HOSTS = [
    ("1.1.1.1", 443, 6),       # cloudflare-dns / HTTPS
    ("1.1.1.1", 53, 17),       # cloudflare-dns / DNS
    ("8.8.8.8", 53, 17),       # google-dns / DNS
    ("8.8.8.8", 443, 6),       # google-dns / DoH
    ("13.32.0.10", 443, 6),    # aws-cloudfront / HTTPS
    ("52.96.1.10", 443, 6),    # microsoft-365 / HTTPS
    ("140.82.112.4", 22, 6),   # github / SSH
    ("151.101.1.69", 443, 6),  # fastly / HTTPS
]

LAN_SERVICES = [
    (443, 6),
    (22, 6),
    (80, 6),
    (8443, 6),
    (51820, 17),
    (53, 17),
]

# NetFlow v9 field definitions: (field_type, field_length)
# 8=IPV4_SRC_ADDR, 12=IPV4_DST_ADDR, 7=L4_SRC_PORT, 11=L4_DST_PORT,
# 4=PROTOCOL, 1=IN_BYTES, 2=IN_PKTS
NF9_FIELDS = (
    (8, 4),
    (12, 4),
    (7, 2),
    (11, 2),
    (4, 1),
    (1, 4),
    (2, 4),
)
NF9_TEMPLATE_ID = 256


@dataclass(frozen=True)
class FlowSample:
    """Single synthetic IPv4 flow tuple."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: int
    num_bytes: int
    packets: int


def generate_flow_samples(count: int, rng: random.Random | None = None) -> list[FlowSample]:
    """Generate a balanced mix of download, upload, and LAN flows."""
    r = rng or random.Random()
    samples: list[FlowSample] = []
    for idx in range(max(1, count)):
        mode = idx % 5
        local_src = r.choice(LOCAL_HOSTS)
        ext_ip, ext_port, ext_proto = r.choice(EXTERNAL_HOSTS)
        ephemeral = r.randint(32768, 60999)

        if mode in (0, 1):
            # Download (external -> local)
            samples.append(
                FlowSample(
                    src_ip=ext_ip,
                    dst_ip=local_src,
                    src_port=ext_port,
                    dst_port=ephemeral,
                    proto=ext_proto,
                    num_bytes=r.randint(15_000, 2_500_000),
                    packets=r.randint(12, 1800),
                )
            )
        elif mode in (2, 3):
            # Upload (local -> external)
            samples.append(
                FlowSample(
                    src_ip=local_src,
                    dst_ip=ext_ip,
                    src_port=ephemeral,
                    dst_port=ext_port,
                    proto=ext_proto,
                    num_bytes=r.randint(4_000, 450_000),
                    packets=r.randint(5, 400),
                )
            )
        else:
            # LAN (local -> local)
            local_dst = r.choice([h for h in LOCAL_HOSTS if h != local_src])
            svc_port, svc_proto = r.choice(LAN_SERVICES)
            samples.append(
                FlowSample(
                    src_ip=local_src,
                    dst_ip=local_dst,
                    src_port=ephemeral,
                    dst_port=svc_port,
                    proto=svc_proto,
                    num_bytes=r.randint(8_000, 950_000),
                    packets=r.randint(8, 700),
                )
            )
    return samples


def build_netflow_v5_packet(
    samples: list[FlowSample],
    sequence: int = 1,
    uptime_ms: int = 120_000,
    unix_secs: int | None = None,
) -> bytes:
    """Encode up to 30 FlowSamples into a NetFlow v5 UDP packet."""
    now = int(time.time()) if unix_secs is None else int(unix_secs)
    chunk = samples[:30]
    header = struct.pack(
        "!HHIIIIBBH",
        5,             # version
        len(chunk),    # count
        uptime_ms,     # sys_uptime
        now,           # unix_secs
        0,             # unix_nsecs
        sequence,      # flow_sequence
        0,             # engine_type
        0,             # engine_id
        0,             # sampling_interval
    )
    records = bytearray()
    for f in chunk:
        src_b = ipaddress.IPv4Address(f.src_ip).packed
        dst_b = ipaddress.IPv4Address(f.dst_ip).packed
        records.extend(
            struct.pack(
                "!4s4s4sHHIIIIHHxBBBHHBBxx",
                src_b,
                dst_b,
                b"\x00\x00\x00\x00",  # nexthop
                1,                       # input snmp
                2,                       # output snmp
                f.packets,
                f.num_bytes,
                max(0, uptime_ms - 1000),
                uptime_ms,
                f.src_port,
                f.dst_port,
                0x10 if f.proto == 6 else 0,  # tcp_flags
                f.proto,
                0,                       # tos
                0,                       # src_as
                0,                       # dst_as
                24,                      # src_mask
                24,                      # dst_mask
            )
        )
    return header + bytes(records)


def build_netflow_v9_packet(
    samples: list[FlowSample],
    sequence: int = 1,
    uptime_ms: int = 120_000,
    unix_secs: int | None = None,
    source_id: int = 1,
) -> bytes:
    """Encode a NetFlow v9 packet containing Template FlowSet + Data FlowSet."""
    now = int(time.time()) if unix_secs is None else int(unix_secs)

    # Template FlowSet (FlowSet ID = 0)
    tpl_body = bytearray(struct.pack("!HH", NF9_TEMPLATE_ID, len(NF9_FIELDS)))
    for ftype, flen in NF9_FIELDS:
        tpl_body.extend(struct.pack("!HH", ftype, flen))
    tpl_len = 4 + len(tpl_body)
    tpl_pad = (-tpl_len) % 4
    tpl_flowset = struct.pack("!HH", 0, tpl_len + tpl_pad) + bytes(tpl_body) + (b"\x00" * tpl_pad)

    # Data FlowSet (FlowSet ID = 256)
    data_body = bytearray()
    for f in samples:
        data_body.extend(
            struct.pack(
                "!4s4sHHBII",
                ipaddress.IPv4Address(f.src_ip).packed,
                ipaddress.IPv4Address(f.dst_ip).packed,
                f.src_port,
                f.dst_port,
                f.proto,
                f.num_bytes,
                f.packets,
            )
        )
    data_len = 4 + len(data_body)
    data_pad = (-data_len) % 4
    data_flowset = struct.pack("!HH", NF9_TEMPLATE_ID, data_len + data_pad) + bytes(data_body) + (b"\x00" * data_pad)

    # NetFlow v9 header count is total number of FlowSets + Data records (GoFlow2 reads FlowSets sequentially)
    header = struct.pack(
        "!HHIIII",
        9,
        1 + len(samples),
        uptime_ms,
        now,
        sequence,
        source_id,
    )
    return header + tpl_flowset + data_flowset


def send_batch(
    host: str,
    port: int,
    protocol: str,
    batch_size: int,
    sequence: int,
    sock: socket.socket,
) -> int:
    """Build and send one synthetic NetFlow UDP datagram."""
    samples = generate_flow_samples(batch_size)
    if protocol == "netflow5":
        packet = build_netflow_v5_packet(samples, sequence=sequence)
    else:
        packet = build_netflow_v9_packet(samples, sequence=sequence)
    sock.sendto(packet, (host, port))
    return len(samples)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Send synthetic NetFlow v9/v5 UDP packets to nxtflow/GoFlow2.")
    parser.add_argument("--host", default=os.environ.get("NXTFLOW_DEMO_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("NXTFLOW_DEMO_PORT", "2055")))
    parser.add_argument(
        "--protocol",
        choices=("netflow9", "netflow5"),
        default=os.environ.get("NXTFLOW_DEMO_PROTOCOL", "netflow9"),
    )
    parser.add_argument("--interval", type=float, default=float(os.environ.get("NXTFLOW_DEMO_INTERVAL", "2")))
    parser.add_argument("--batch-size", type=int, default=int(os.environ.get("NXTFLOW_DEMO_BATCH_SIZE", "12")))
    parser.add_argument("--once", action="store_true", help="Send a single batch and exit")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    seq = 1
    try:
        while True:
            sent = send_batch(args.host, args.port, args.protocol, args.batch_size, seq, sock)
            print(
                f"Sent {sent} {args.protocol} flows (seq={seq}) -> {args.host}:{args.port}",
                flush=True,
            )
            seq += 1
            if args.once:
                return 0
            time.sleep(max(0.2, args.interval))
    except KeyboardInterrupt:
        return 0
    finally:
        sock.close()


if __name__ == "__main__":
    sys.exit(main())
