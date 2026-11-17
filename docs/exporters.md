# Exporter Guides & Tuning

`nxtflow` accepts **NetFlow v5, NetFlow v9, IPFIX** on UDP port `2055` and **sFlow v5** on UDP port `6343`.

## Platform Guides

Ready-to-apply configurations are provided in `examples/exporters/`:

| Platform | Protocol | Guide |
|---|---|---|
| MikroTik RouterOS v7 | NetFlow v9 / IPFIX | [mikrotik-routeros.rsc](../examples/exporters/mikrotik-routeros.rsc) |
| Linux Hosts & Software Bridges (`softflowd`) | NetFlow v9 | [softflowd-linux.md](../examples/exporters/softflowd-linux.md) |
| pfSense & OPNsense (`softflowd` / `ng_netflow`) | NetFlow v9 | [pfsense-opnsense.md](../examples/exporters/pfsense-opnsense.md) |
| Cisco IOS-XE (Flexible NetFlow) | NetFlow v9 / IPFIX | [cisco-ios-xe.txt](../examples/exporters/cisco-ios-xe.txt) |
| UniFi Gateways | NetFlow v9 | [unifi-gateway.md](../examples/exporters/unifi-gateway.md) |

## Best Practices

1. **Preserve Exporter Source IPs (`externalTrafficPolicy: Local`):**
   Keep `collector.service.externalTrafficPolicy=Local` so Kubernetes LoadBalancer nodes do not SNAT exporter traffic to an internal cluster node IP.
2. **Prevent Feedback Loops (`not port 2055`):**
   When running `softflowd` on a Linux host inside the same cluster or subnet as the collector, include a capture filter such as `not port 2055` so NetFlow export packets themselves are not re-captured and re-exported.
3. **Configure `wanIps` and `localCidrs`:**
   Add your router's external IP(s) to `enricher.classification.wanIps` and internal subnets to `enricher.classification.localCidrs` so NATed ingress/egress traffic is classified cleanly into `up`, `down`, and `lan`.
4. **Packet Sampling (`sampling.respectSamplingRate`):**
   If your switch or router uses `1:N` sFlow or NetFlow sampling, keep `enricher.sampling.respectSamplingRate=true` so `nxtflow-enricher` scales `bytes` and `packets` automatically.
