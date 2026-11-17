# Exporting NetFlow from Linux Hosts with `softflowd`

`softflowd` exports NetFlow v5/v9/IPFIX directly from a Linux network interface (for example, a software load balancer, router, or bastion host).

## 1. Install `softflowd`

```bash
# Debian / Ubuntu
sudo apt update && sudo apt install -y softflowd

# Arch Linux
sudo pacman -S softflowd
```

## 2. Configure Interface Export

Create `/etc/softflowd/eth0.conf` (replace `eth0` with your LAN/internal interface and `192.168.1.50` with your `nxtflow` collector IP):

```ini
interface='eth0'
options='-n 192.168.1.50:2055 -v 9 -t maxlife=60 -t expint=15 -m 65536 not port 2055'
```

### Important Design Notes
- **`not port 2055` BPF filter**: Prevents `softflowd` from exporting NetFlow telemetry about its own NetFlow UDP packets (eliminating self-export feedback loops).
- **Pre-MASQUERADE / LAN interface**: Capture on the internal or pre-NAT interface when possible so original client IPs remain visible in `src_addr` and `dst_addr`.

## 3. Enable and Verify

```bash
sudo systemctl enable --now softflowd@eth0
sudo softflowctl -c /run/softflowd/eth0.ctl statistics
```
