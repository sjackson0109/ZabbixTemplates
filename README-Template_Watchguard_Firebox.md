# 📡 Zabbix Template: WatchGuard Firebox

### Author: Simon Jackson / sjackson0109  
### Created: 2025/04/01
### Updated: 2025/04/04


A production-grade Zabbix template designed for in-depth SNMPv3-based monitoring of **WatchGuard Firebox** appliances. The template is compatible with Zabbix 6.0+ and 7.0 YAML format, and provides extensive visibility into system health, network interfaces, VPN tunnels, clustering, and performance metrics.

---

## 📦 Features

This template provides:

### ✅ System Health
- CPU load
- Temperature sensors
- Fan status and RPM
- System uptime
- Memory and swap usage
- Disk and storage cache visibility

### ✅ Network Interfaces
- Full interface discovery
- Interface throughput (bps)
- Error and discard counters
- Interface status (up/down)

### ✅ VPN Monitoring
- **Branch Office VPN (BoVPN)** discovery via `ifType = 131`
- Per-tunnel traffic metrics
- BoVPN interface status and availability
- Packet loss and latency (when exposed)

### ✅ Cluster Awareness
- Detection of High Availability (HA) roles
- Cluster state and member serials
- Peer role status and health (if configured)

### ✅ Telemetry & Application Metrics
- Inbound/outbound firewall bytes
- Connection rate
- Active connections
- Stateful inspection counters

### 🛠 Template Architecture
- SNMPv3 compatible
- Static and discovery-based item configuration
- Modular layout using `Applications` and `Tags`
- Designed for compatibility with Docker-hosted or proxy-based Zabbix environments

---

## ⚠ Caveats & Known Limitations

### 🔒 Gateway VPN (GwVPN) Incompatibility
This template does **not** support monitoring of **Gateway VPNs (GwVPNs)**, as WatchGuard does not expose policy-based VPN tunnels through SNMP. Only **route-based tunnels** (BoVPNs) with interface bindings are exposed via `IF-MIB::ifType = 131`.

This is a platform limitation and not a template defect.

---

## 🧰 Requirements

- Zabbix Server/Proxy version: **6.0 LTS** or **7.0**
- WatchGuard Firebox:
  - SNMPv3 enabled and accessible
  - MIBs aligned with `WATCHGUARD-SYSTEM-MIB`
- SNMP interface configured on target host
- Host macros for thresholds (optional)

---

## ⚙ Macros (Optional)

You can override default thresholds via host-level macros:

| Macro                          | Purpose                        | Default |
|-------------------------------|--------------------------------|---------|
| `{$WATCHGUARD_MAX_CONNECTIONS}` | Connection count threshold     | `50000` |
| `{$TEMP_WARN}`                 | Temperature warning threshold  | `75`    |
| `{$FAN_WARN_RPM}`              | Fan speed warning threshold    | `1500`  |

---

## 🚀 Getting Started

1. Import the `watchguard_firebox.yaml` template into Zabbix via the **Templates** section.
2. Link the template to a Firebox host with a valid **SNMPv3 interface**.
3. Apply or tune macros as needed.
4. Allow discovery items (e.g. BoVPNs, storage, sensors) to populate over the next polling interval.

---

## 📁 Files

- `watchguard_firebox.yaml`: Main Zabbix template in YAML v6.0/7.0 format.
- `README.md`: This file.

---

## 📜 License

Distributed under a permissive license. Attribution appreciated.

---

