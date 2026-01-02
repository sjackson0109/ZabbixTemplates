# Zabbix Template: WatchGuard Firebox

### Author: Simon Jackson / sjackson0109  
### Created: 2025/04/01  
### Updated: 2025/05/01

A production-grade Zabbix template for in-depth SNMPv2-based monitoring of WatchGuard Firebox appliances. Built using YAML v7.0 format, this template provides comprehensive visibility across system health, VPNs, clustering, interfaces, and application-layer metrics.

## Features

This template provides:

### System Health
- CPU load (%), memory & swap usage, and cache utilisation
- Temperature sensors with thresholds
- Fan RPM and operational status
- Uptime, system description, firmware version
- Disk usage metrics (total, used %, thresholds)

### Network Interfaces
- SNMP interface discovery using `ifDescr` and `ifType`
- Per-interface throughput (bps), error/discard counters
- Interface up/down state with value mapping
- BoVPN-specific interfaces filtered by `ifType = 131`

### VPN Monitoring
- Branch Office VPN (BoVPN) discovery using `ifType = 131`
- Per-BoVPN metrics: bytes in/out, error counters, status
- Trigger prototypes for error thresholds, state changes
- Graphs for VPN tunnel traffic, errors, and state

### Partial Policy-Based VPN (GwVPN) Support
- GwVPN discovery is present but disabled by default
- Firebox v12.10+ does not expose GwVPN SNMP OIDs consistently
- Item prototypes exist but are limited due to platform limitations

### Cluster Awareness (FireCluster)
- Role identification: Master / Standby
- Synchronisation percentage
- Per-node health (hardware, system, and interface)
- Cluster operational state with alerting
- Graphs and dashboard views

### Application & Traffic Telemetry
- Connection count & rate
- Firewall bytes/packets in/out
- GAV, IPS, Application Control status and versioning (some disabled)

### Template Architecture
- Zabbix 6.0–7.0 YAML syntax
- Clean modular layout: tagged items, application grouping
- Static items + discovery-based VPN and interface metrics
- Value mapping for cluster role/state, interface state
- Dashboard included: FireCluster overview

## Discovery Rules

| Rule                              | Key                   | Description                                 |
|----------------------------------|------------------------|---------------------------------------------|
| Interfaces (Generic)             | `net.if.discovery`     | All SNMP interfaces (filtered by type/name) |
| VPN Tunnels (Route Based – BoVPN) | `bovpn.discovery`     | Discovers VTI-bound BoVPN tunnels           |
| VPN Tunnels (Policy Based – GwVPN) | `gwvpn.discovery`     | Present but disabled due to platform limits |

## Caveats & Limitations

### Policy-Based VPNs (GwVPN)
- SNMP OIDs under `.1.3.6.1.4.1.3097.6.5.1.2.1.*` are defined in MIBs but not exposed on Firebox firmware ≥ v12.10.
- Discovery rule `gwvpn.discovery` is present but disabled by default due to inconsistent SNMP availability.

### Dynamic VPNs
- Mobile VPNs (e.g. SSL, IPSec dial-in) are not discovered or monitored.
- Only BoVPNs with interface bindings (route-based) are supported.

## Requirements

- Zabbix Server/Proxy 6.0 LTS or 7.0
- WatchGuard Firebox:
  - SNMPv2 agent enabled
  - MIBs consistent with `WATCHGUARD-SYSTEM-MIB`
  - Firmware tested on M370, M470, M670 and compatible T-series models
- SNMP interface configured in Zabbix
- Host macros for tuning thresholds (see below)

## Macros (Customisable)

| Macro                              | Purpose                                      | Default |
|-----------------------------------|----------------------------------------------|---------|
| `{$WATCHGUARD_MAX_CONNECTIONS}`   | Connection count trigger threshold           | `50000` |
| `{$WATCHGUARD_TEMP_WARNING}`      | Temperature warning threshold (°C)           | `60`    |
| `{$WATCHGUARD_TEMP_CRITICAL}`     | Temperature critical threshold (°C)          | `70`    |
| `{$WATCHGUARD_CPU_LOW}`           | CPU usage warning threshold (%)              | `70`    |
| `{$WATCHGUARD_CPU_HIGH}`          | CPU usage critical threshold (%)             | `90`    |
| `{$WATCHGUARD_SWAP_THRESHOLD}`    | Swap usage critical threshold (%)            | `99`    |
| `{$WATCHGUARD_CACHED_THRESHOLD}`  | Cache usage warning threshold (%)            | `99`    |
| `{$WATCHGUARD_DISK_LOW}`          | Disk usage warning threshold (%)             | `80`    |
| `{$WATCHGUARD_DISK_HIGH}`         | Disk usage critical threshold (%)            | `90`    |
| `{$WATCHGUARD_INTERFACE_WARNING_THRESHOLD}` | Interface error warning threshold (pps) | `100`   |
| `{$WATCHGUARD_INTERFACE_ERROR_THRESHOLD}`   | Interface error critical threshold (pps)| `1000`  |
| `{$WATCHGUARD_FAN_MIN_SPEED}`     | Fan minimum RPM threshold                    | `2000`  |
| `{$WATCHGUARD_CLUSTER_HEALTH_PERCENT}` | Expected HA sync (%)                     | `90`    |
| `{$BOVPN_IGNORE_REGEX}`           | Regex to exclude BoVPN interfaces            | `(?i:BACKEND|TEST|MONITORING).*` |
| `{$BOVPN_WARNING_THRESHOLD}`      | BoVPN warning error rate                     | `1`     |
| `{$BOVPN_ERROR_THRESHOLD}`        | BoVPN critical error rate                    | `10`    |

## Dashboards

Includes a predefined "Watchguard Firebox" dashboard:
- Cluster health & sync status
- BoVPN traffic/error graphs
- Interface summaries
- Active connections & load indicators

## Getting Started

1. Import `watchguard_firebox.yaml` via Configuration → Templates.
2. Apply template to a Firebox host with SNMPv2 interface defined.
3. Tune host macros as needed.
4. Enable discovery and allow time for item population.

## Files

- `watchguard_firebox.yaml` – Zabbix Template (v7.0 YAML)
- `README.md` – Template overview and usage

## Licence

Distributed under a permissive Licence. Attribution appreciated.
