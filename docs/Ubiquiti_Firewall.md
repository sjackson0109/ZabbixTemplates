# Zabbix Template: Ubiquiti Firewall

### Author: Simon Jackson / sjackson0109  
### Created: 2025/04/29  
### Updated: 2025/05/05

Production-grade SNMPv2-based Zabbix template designed to monitor Ubiquiti EdgeRouter, UniFi Security Gateway (USG), and UniFi Dream Machine (UDM) devices. It covers system health, interface status, traffic, VPN tunnels, session counts, and more.

## Features

### System Health
- Hostname, uptime, location, and contact info
- CPU and memory usage
- Active session counts
- Process monitoring per service (e.g. `dnsmasq`, `sshd`, `strongswan`, `ubnt-util`, `unifi-core`)

### Interface Monitoring
- Ethernet interface discovery via `ifDescr` and `ifType`
- Per-interface byte counters (converted to bits/sec)
- In/out error monitoring
- Interface state (up/down) with trigger alerts

### VPN Monitoring
- Route-based VPNs (e.g. `vti0`, `vti1`)
- Policy-based VPNs (e.g. `ipsec0`, `ipsec1`)
- Teleport VPN tunnels (optional, disabled by default)
- Tunnel in/out traffic and error rates
- Tunnel state and flap detection

### Template Architecture
- Zabbix 7.0 YAML format
- SNMP OID-based discovery and polling
- Tagged items and grouped macros
- Preprocessing using `change per second` and `multiplier` (8 for bps conversion)
- Triggers and graph prototypes for key metrics

## Discovery Rules

| Rule                            | Key                              | Description                                             |
|---------------------------------|-----------------------------------|---------------------------------------------------------|
| Interfaces (Ethernet)           | `interface.discovery`             | Discovers usable Ethernet interfaces                    |
| VPN Tunnels (Route-Based)       | `ubiquiti.vpn.route.discovery`    | Detects VTI-style VPNs based on ifType = 131            |
| VPN Tunnels (Policy-Based)      | `ubiquiti.vpn.policy.discovery`   | Detects IPsec-style VPNs based on interface names       |
| VPN Tunnels (Teleport-Based)    | `ubiquiti.vpn.teleport.discovery` | Optional discovery of teleport tunnels (disabled)       |

## Macros

| Macro                                        | Description                                      | Default |
|---------------------------------------------|--------------------------------------------------|---------|
| `{$UBIQUITI_MEMORY_USED_MAX}`               | Memory usage threshold (%)                      | `95`    |
| `{$UBIQUITI_PROCESS_MAX}`                   | Default max process count for unknown services  | `10`    |
| `{$UBIQUITI_PROCESS_MAX:"dnsmasq"}`         | Max `dnsmasq` processes                         | `3`     |
| `{$UBIQUITI_PROCESS_MIN:"dnsmasq"}`         | Min `dnsmasq` processes                         | `1`     |
| `{$UBIQUITI_SESSION_COUNT_MAX}`             | Session count threshold                         | `50000` |
| `{$UBIQUITI_UPTIME_MIN}`                    | Uptime minimum before triggering reboot alert   | `600`   |
| `{$UBIQUITI_STORAGE_USED_MAX:"/run"}`       | Storage threshold for /run                      | `95`    |
| `{$UBIQUITI_STORAGE_USED_MAX:"/root.dev"}`  | Root mount usage threshold                      | `85`    |

## Graph Prototypes

- Interface traffic (bps)
- VPN tunnel traffic and errors
- Session count over time
- CPU and memory utilisation (where available)

## Requirements

- Zabbix Server or Proxy v6.0+ or 7.0
- SNMPv2 enabled on the Ubiquiti device
- Valid SNMP community and host access
- Compatible device (EdgeRouter, USG, UDM-Pro)

## Supported Devices

- Ubiquiti EdgeRouter series (ER-X, ER-4, ER-12)
- UniFi Security Gateway (USG / USG-Pro)
- UniFi Dream Machine (UDM/UDM-Pro, limited support)

## Getting Started

1. Import `ubiquiti_firewall.yaml` into Zabbix
2. Apply to a host with SNMPv2 configured
3. Set/override macros as needed
4. Wait for discovery rules to populate interfaces and tunnels

## Files

- `ubiquiti_firewall.yaml` – Zabbix Template (YAML 7.0)
- `README.md` – Template documentation

## Licence

Distributed under a permissive Licence. Attribution appreciated.
