# MikroTik RouterOS v7 Traffic Flow (NetFlow v9 / IPFIX) -> nxtflow collector
# Replace 192.168.1.50 with your local nxtflow collector IP (or 203.0.113.50 for remote collector).

/ip/traffic-flow/set enabled=yes interfaces=all cache-entries=64k active-flow-timeout=30m inactive-flow-timeout=15s
/ip/traffic-flow/target/add dst-address=192.168.1.50 port=2055 version=9

# Optional IPFIX instead of NetFlow v9:
# /ip/traffic-flow/target/add dst-address=192.168.1.50 port=2055 version=ipfix

# Verification commands:
# /ip/traffic-flow/print
# /ip/traffic-flow/target/print
# /ip/traffic-flow/monitor duration=3

# Pre-DNAT WAN classification note:
# RouterOS captures pre-DNAT packets where inbound flows carry your public WAN IP
# as dst_addr. Add your router WAN IP(s) to enricher classification.wanIps, e.g.:
#   classification:
#     wanIps:
#       - "203.0.113.1"
