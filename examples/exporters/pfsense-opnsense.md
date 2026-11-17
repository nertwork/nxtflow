# Exporting NetFlow from OPNsense and pfSense

## OPNsense (Native NetFlow / IPFIX)

1. Navigate to **Reporting > NetFlow** (or **Services > Netflow** depending on version).
2. Set **Listening Interfaces**: select `LAN` (and `WAN` only if you want external NAT-side flows).
3. Set **Capture local**: disable unless you need firewall-self traffic.
4. Set **Version**: `9` (NetFlow v9) or `10` (IPFIX).
5. Set **Destinations**: `192.168.1.50:2055` (replace with your `nxtflow` collector address).
6. Recommended timeouts: **Active timeout** `1800`, **Inactive timeout** `15`.
7. Click **Apply**.

> If exporting WAN flows, add your WAN IP (e.g. `203.0.113.1`) to `classification.wanIps` in `nxtflow-enricher` so inbound/outbound directions classify accurately.

---

## pfSense (`softflowd` Package)

1. Install **softflowd** via **System > Package Manager > Available Packages**.
2. Open **Services > softflowd**:
   - **Interface**: select `LAN` (avoid selecting both a parent physical NIC and its VLAN sub-interfaces, which double-counts packets).
   - **Host**: `192.168.1.50` (your `nxtflow` collector IP).
   - **Port**: `2055`
   - **NetFlow version**: `9`
   - **Flow Tracking Level**: `Full`
   - **Timeout values**: `maxlife=60`, `expint=15`
3. Save and verify under **Status > Services** that `softflowd` is running.
