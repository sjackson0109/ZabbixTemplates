# Zabbix Template: SonicWall Firewall

### Author: Simon Jackson / sjackson0109  
### Created: 2025/04/10  
### Updated: 2025/05/05

This Zabbix template provides deep SNMP-based monitoring support for SonicWall firewalls including NSA and E series appliances. Structured using YAML v7.0 format, it supports discovery of VPNs, interfaces, cluster roles, security services, and performance metrics. 

Tested on SonicOS Enhanced 6.5.x and 7.x platforms.

## Features

### System Health
- CPU load, memory usage
- Active sessions, connection rates
- High availability sync status
- Fan and temperature (where supported)

### Interface Monitoring
- Ethernet, Fibre, VLAN, PortShield interface discovery
- Inbound/outbound traffic metrics
- Error, discard, and CRC counters
- Admin and link state per interface

### VPN Monitoring
- Route-based VPNs (SA interfaces)
- Policy-based VPNs (IKE tunnel table)
- VTI (Virtual Tunnel Interfaces)
- VPN name, tunnel state, traffic in/out
- Graphs and triggers for tunnel errors and loss

### Cluster & High Availability
- Cluster role (Primary/Secondary)
- HA sync state
- Peer status visibility

### Security Services
- Gateway Anti-Virus (GAV)
- Intrusion Prevention System (IPS)
- Application Firewall (AppCtrl)
- Licensing and feature status (some items disabled by default)

### Template Structure
- Compatible with Zabbix 6.0–7.0
- Multiple discovery rules by interface class
- Macros used for tuning thresholds
- Value maps for states and roles
- Graph and trigger prototypes for discovered items

## Discovery Rules

| Rule                                 | Key                           | Description                                         |
|--------------------------------------|--------------------------------|-----------------------------------------------------|
| Interfaces (Ethernet/Fibre/VLAN)     | `sonicwall.interface.discovery`| Discovers all usable SNMP interfaces               |
| PortShield Assignments               | `sonicwall.portshield.discovery`| Logical port groupings from SonicOS                |
| VPN Tunnels (Route-Based)            | `sonicwall.routevpn.discovery` | Based on dynamic SA tunnel interfaces              |
| VPN Tunnels (Policy-Based)           | `sonicwall.policyvpn.discovery`| Based on static IKE tunnels                        |
| VPN Tunnels (VTI)                    | `sonicwall.vti.discovery`      | VTI interface-based VPNs (static Layer 3)          |

## Limitations

- SonicOS SNMP implementations vary by firmware
- Some interface types may not report CRC/error counters reliably
- Policy-based VPNs do not always expose all OIDs (firmware dependent)
- Dynamic dial-in VPNs are not discovered

## Requirements

- Zabbix Server/Proxy 6.0 LTS or 7.0
- SonicWall firewall with SNMPv2 enabled
- Read access to `.1.3.6.1.4.1.8741.1` subtree
- Device-specific MIBs (optional but recommended)
- Appropriate SNMP views and ACLs set on SonicWall

## Macros (Tunable)

| Macro                                     | Description                                  | Default |
|------------------------------------------|----------------------------------------------|---------|
| `{$SONICWALL_CPU_LOAD_HIGH}`             | CPU usage critical threshold (%)             | `90`    |
| `{$SONICWALL_MEM_USAGE_HIGH}`            | Memory usage critical threshold (%)          | `90`    |
| `{$SONICWALL_TEMP_WARNING}`              | Temperature warning threshold (°C)           | `60`    |
| `{$SONICWALL_TEMP_CRITICAL}`             | Temperature critical threshold (°C)          | `70`    |
| `{$SONICWALL_FAN_MIN_RPM}`               | Fan speed warning threshold (RPM)            | `2000`  |
| `{$SONICWALL_CONN_LIMIT}`                | Session count warning threshold              | `500000`|
| `{$SONICWALL_SKIP_INTERFACE_VTI_DISCOVERY}`| Skip VTI tunnel discovery                    | `0`     |
| `{$SONICWALL_SKIP_INTERFACE_POLICY_DISCOVERY}`| Skip policy VPN discovery                | `0`     |
| `{$SONICWALL_SKIP_INTERFACE_ROUTE_DISCOVERY}`| Skip SA-based VPN discovery                | `0`     |

## Getting Started

1. Import `sonicwall_firewall.yaml` via Configuration → Templates
2. Assign the template to a SonicWall host with a valid SNMP interface
3. Adjust macros as required to reflect performance expectations
4. Allow for discovery rules to populate interfaces and tunnels

## Files

- `sonicwall_firewall.yaml` – Zabbix Template (v7.0 YAML)
- `README.md` – Template usage and notes

## License

Distributed under a permissive license. Attribution appreciated.
