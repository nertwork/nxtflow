# Exporting NetFlow / IPFIX from UniFi Gateways

## UniFi Network Application 8.5.6+ / 9.x (Gateway Firmware 4.1+)

1. Open **Settings > System > Traffic Logging** (or **Integrations > NetFlow** in newer Network versions).
2. Enable **NetFlow / IPFIX**.
3. Configure collector settings:
   - **IP Address**: `192.168.1.50` (your `nxtflow` collector IP)
   - **Port**: `2055`
   - **Version**: `9` (NetFlow v9) or `10` (IPFIX)
   - **Sampling Rate**: `0` (unsampled 1:1) or e.g. `512` on high-throughput gateways.
4. If using a non-zero sampling rate, ensure `sampling.respectSamplingRate: true` is enabled in `nxtflow-enricher` (enabled by default) so `bytes` and `packets` are automatically scaled.

## Legacy UniFi Security Gateway (USG) CLI

```text
configure
set system flow-accounting interface eth0
set system flow-accounting netflow server 192.168.1.50 port 2055
set system flow-accounting netflow version 9
set system flow-accounting netflow timeout expiry-interval 60
commit ; save ; exit
```
