# Zabbix Template: SonicWall Firewall

### Author: Simon Jackson / sjackson0109  
### Created: 2025/04/10  
### Updated: 2026/01/06

This Zabbix template provides comprehensive SNMP-based monitoring for SonicWall firewalls including TZ, NSA, NSa, and SuperMassive series appliances. Built with YAML v7.0 format, it supports advanced discovery of BGP neighbors, VPN tunnels, network interfaces, cluster roles, security services, and performance metrics with extensive dashboard integration.

Tested on SonicOS Enhanced 6.5.x and 7.x platforms with full BGP4-MIB support.

## Features

### System Health
- CPU load, memory usage, swap utilisation
- Active sessions, connection rates, and table usage
- High availability sync status and cluster roles
- Fan speeds and temperature monitoring (where supported)
- Disk usage and system uptime tracking

### BGP Monitoring (NEW)
- **BGP4-MIB Integration**: Full support for BGP neighbour discovery
- **Neighbour States**: Real-time monitoring of BGP session states (Idle, Connect, Active, OpenSent, OpenConfirm, Established)
- **Route Monitoring**: Track received routes count and update messages per neighbour
- **Session Health**: Uptime tracking and total message counters
- **Flapping Detection**: Configurable threshold monitoring for session stability
- **Dashboard Integration**: Dedicated BGP monitoring page with multiple widget layouts

### Interface Monitoring
- **Discovery Types**: Ethernet, Fibre, VLAN, PortShield, and LAG interface discovery
- **Traffic Metrics**: Inbound/outbound traffic rates with preprocessing
- **Error Monitoring**: Comprehensive error, discard, and CRC counters
- **State Tracking**: Admin and operational state per interface
- **Flapping Detection**: Interface stability monitoring with configurable timeframes

### VPN Monitoring (Enhanced)
- **Route-based VPNs**: VTI (Virtual Tunnel Interface) monitoring with traffic analysis
- **Policy-based VPNs**: Phase-2 IPsec SA monitoring using tunnel tables
- **Tunnel Pair Discovery**: Redundant VPN monitoring for HA configurations
- **Enhanced Flapping Detection**: Extended 15-minute timeframe for better stability
- **Traffic Analysis**: Comprehensive bytes in/out and error counters
- **Failover Detection**: Tunnel pair status monitoring for redundancy

### Cluster & High Availability
- **Cluster Roles**: Primary/Secondary role monitoring with anomaly detection
- **HA Sync State**: Synchronisation status between cluster members
- **Peer Visibility**: Status monitoring of HA peer devices
- **Role Changes**: Trigger alerts for unexpected role transitions

### Security Services
- **Gateway Anti-Virus (GAV)**: Scan requests, detection rates, and scan times
- **Intrusion Prevention (IPS)**: Attack detection rates and response times
- **Intrusion Detection (IDS)**: Detection statistics and threat analysis
- **Anti-Spyware**: Scan statistics and threat detection counters
- **Content Filtering**: URL and content scanning metrics
- **DPI SSL**: Deep packet inspection utilisation monitoring

### Dashboard Integration
- **5 Comprehensive Pages**: 
  - **Cluster**: Overview with problems by severity and vendor filtering
  - **BGP**: BGP neighbour monitoring with multiple widget layouts
  - **Interfaces**: Interface status honeycomb and traffic graphs
  - **VPN Policies**: Policy-based VPN status, traffic, and problems
  - **VPN Routes**: Route-based VPN monitoring with error analysis
- **Widget Types**: Honeycomb status displays, traffic graphs, gauge widgets, and problem filters
- **Visual Indicators**: Colour-coded status with threshold-based alerts

### Host Inventory Integration
- **Hardware Information**: Model, serial numbers, firmware version
- **Network Configuration**: Primary/Secondary MAC addresses
- **Contact Information**: Administrator and location details
- **Automatic Mapping**: Template-driven inventory population

## Discovery Rules

| Rule                              | Key                              | Description                                         |
|-----------------------------------|-----------------------------------|-----------------------------------------------------|
| **BGP Neighbours**                | `bgp.neighbors.discovery`        | Discovers BGP neighbours using BGP4-MIB            |
| **Interfaces (Ethernet)**         | `ethernet.discovery`             | Discovers Ethernet, Fibre, VLAN interfaces         |
| **LAG Groups**                    | `lag.discovery`                  | Discovers Link Aggregation Group interfaces        |
| **CPU Cores**                     | `cpu.discovery`                  | Multi-core CPU monitoring discovery                 |
| **VPN Policies**                  | `vpn.policy.discovery`           | Policy-based VPN tunnel discovery                  |
| **VPN Routes**                    | `vpn.route.discovery`            | Route-based VPN tunnel discovery                   |
| **VPN Tunnel Pairs**              | `vpn.tunnel.pairs.discovery`     | Redundant tunnel pair discovery for HA             |
| **VTI Interfaces**                | `vti.discovery`                  | Virtual Tunnel Interface discovery                  |

## Template Structure

### Items (Key Categories)
- **System Information**: Hostname, firmware, model, uptime, administrator
- **Performance Metrics**: CPU utilisation, memory usage, cache statistics
- **Network Statistics**: Interface traffic, error counters, operational states
- **BGP Metrics**: Neighbour states, route counts, session uptime, message counters
- **VPN Statistics**: Tunnel states, traffic counters, SA creation times
- **Security Services**: Scan rates, detection counts, threat statistics
- **HA Monitoring**: Cluster roles, sync status, peer visibility

### Trigger Prototypes
- **Interface Monitoring**: Status changes, error thresholds, flapping detection
- **BGP Alerts**: Neighbour state changes, route count thresholds, session timeouts
- **VPN Monitoring**: Tunnel status changes, traffic anomalies, failover detection
- **Performance Thresholds**: CPU, memory, temperature, and connection limits
- **Security Alerts**: High detection rates, scan time thresholds, threat levels

### Graph Prototypes
- **Interface Traffic**: Individual and aggregated traffic graphs per interface
- **VPN Traffic**: Policy and route-based VPN traffic visualisation
- **BGP Metrics**: Neighbour state trends and route count analysis
- **Performance Graphs**: CPU, memory, and connection rate trends

## Macros (Configurable Thresholds)

### BGP Monitoring
| Macro                                          | Default | Description                                        |
|-----------------------------------------------|---------|----------------------------------------------------|
| `{$SONICWALL_BGP_NEIGHBOR_TIMEOUT}`           | `180`   | BGP neighbour timeout before considering down (seconds) |
| `{$SONICWALL_BGP_ROUTE_THRESHOLD_CRITICAL}`   | `10`    | Critical minimum BGP routes per neighbour         |
| `{$SONICWALL_BGP_ROUTE_THRESHOLD_WARNING}`    | `50`    | Warning threshold for low BGP route count         |

### Flapping Detection
| Macro                                          | Default | Description                                        |
|-----------------------------------------------|---------|----------------------------------------------------|
| `{$SONICWALL_FLAPPING_CHANGE_THRESHOLD}`      | `3`     | State changes before triggering flapping alert    |
| `{$SONICWALL_FLAPPING_TIMEFRAME}`             | `15m`   | Timeframe for detecting flapping behaviour         |

### Performance Thresholds
| Macro                                          | Default | Description                                        |
|-----------------------------------------------|---------|----------------------------------------------------|
| `{$SONICWALL_CPU_WARNING}`                    | `80`    | CPU usage warning threshold (%)                   |
| `{$SONICWALL_CPU_ERROR}`                      | `90`    | CPU usage critical threshold (%)                  |
| `{$SONICWALL_MEMORY_WARNING}`                 | `80`    | Memory usage warning threshold (%)                |
| `{$SONICWALL_MEMORY_ERROR}`                   | `90`    | Memory usage critical threshold (%)               |
| `{$SONICWALL_TEMP_WARNING}`                   | `60`    | Temperature warning threshold (°C)                |
| `{$SONICWALL_TEMP_ERROR}`                     | `70`    | Temperature critical threshold (°C)               |
| `{$SONICWALL_CONN_USAGE_WARN}`                | `90`    | Connection table usage warning (%)                |

### Security Service Thresholds
| Macro                                          | Default | Description                                        |
|-----------------------------------------------|---------|----------------------------------------------------|
| `{$SONICWALL_GAV_VIRUS_THRESHOLD}`            | `5`     | GAV virus detection threshold                      |
| `{$SONICWALL_IPS_ATTACK_THRESHOLD}`           | `10`    | IPS attack detection threshold per minute         |
| `{$SONICWALL_IDS_DETECTION_THRESHOLD}`        | `10`    | IDS detection threshold per minute                 |
| `{$SONICWALL_ASW_THREAT_THRESHOLD}`           | `10`    | Anti-Spyware threat detection threshold           |

### High Availability
| Macro                                          | Default | Description                                        |
|-----------------------------------------------|---------|----------------------------------------------------|
| `{$SONICWALL_HA_ANOMOLY_HIGH_THRESHOLD}`      | `375000`| Minimum value for active HA state                 |
| `{$SONICWALL_HA_ANOMOLY_LOW_THRESHOLD}`       | `500`   | Threshold for anomalous secondary HA state        |

## Supported Devices
- **SonicWall TZ Series**: TZ270, TZ370, TZ470, TZ570, TZ670
- **SonicWall NSA Series**: NSA2700, NSA3700, NSA4700, NSA5700, NSA6700
- **SonicWall NSa Series**: NSa2700, NSa3700, NSa4700, NSa5700, NSa6700
- **SonicWall SuperMassive Series**: SM9200, SM9400, SM9800
- **SonicOS Versions**: 6.5.x and 7.x firmware with BGP support

## BGP Requirements
- **BGP-Enabled Models**: Higher-end appliances (NSA/NSa 2700+, SuperMassive series)
- **BGP4-MIB Support**: Device must support standard BGP4-MIB (1.3.6.1.2.1.15.3.1.*)
- **BGP Configuration**: At least one BGP neighbour must be configured
- **SNMP Access**: Read access to BGP MIB subtree

## Limitations
- **BGP Availability**: BGP monitoring only works on models with BGP routing support
- **SonicOS Variations**: SNMP implementations vary by firmware version
- **Interface Types**: Some interface types may not report all counters reliably
- **Policy VPNs**: Some OIDs may not be available depending on firmware
- **Dynamic VPNs**: Dial-in/dynamic VPNs are not discovered automatically

## Requirements
- **Zabbix Version**: Server/Proxy 6.0 LTS or 7.0+ with dashboard support
- **SNMP Configuration**: SNMPv2c or SNMPv3 enabled on SonicWall
- **SNMP Access**: Read access to `.1.3.6.1.4.1.8741.1` and `.1.3.6.1.2.1.15` subtrees
- **MIB Files**: SonicWALL and BGP4-MIB files (optional but recommended)
- **Network Access**: Zabbix server/proxy can reach device SNMP port (161/UDP)

## Installation and Configuration

### 1. Template Import
1. Navigate to **Configuration → Templates** in Zabbix frontend
2. Click **Import** and select `sonicwall_firewall.yaml`
3. Configure import options as needed
4. Click **Import** to install the template

### 2. Host Configuration
1. Create or edit a host for your SonicWall device
2. Assign the **"Sonicwall Firewall"** template
3. Configure SNMP interface with appropriate community/credentials
4. Set host inventory mode to **Automatic** for inventory population

### 3. Macro Tuning
1. Adjust performance thresholds based on device capacity
2. Configure BGP-specific thresholds if BGP is enabled
3. Set flapping detection timeframes appropriate for your environment
4. Customise security service thresholds based on traffic patterns

### 4. Dashboard Access
1. Navigate to **Monitoring → Dashboards**
2. Select **"SonicWALL Firewalls"** dashboard
3. Use page navigation to access different monitoring views:
   - **Cluster**: Overall system health and problems
   - **BGP**: BGP neighbour and routing monitoring
   - **Interfaces**: Network interface status and traffic
   - **VPN Policies**: Policy-based VPN monitoring
   - **VPN Routes**: Route-based VPN and tunnel monitoring

## Files
- `sonicwall_firewall.yaml` – Complete Zabbix Template (v7.0 YAML)
- `Sonicwall_Firewall.md` – This documentation file

## Changelog
- **2026/01/06**: Added comprehensive BGP monitoring with BGP4-MIB support
- **2026/01/06**: Enhanced VPN flapping detection with 15-minute timeframes
- **2026/01/06**: Implemented 5-page dashboard with widget-based monitoring
- **2026/01/06**: Added host inventory integration for hardware tracking
- **2026/01/06**: Improved tunnel pair discovery for HA configurations
- **2025/05/05**: Initial template creation with basic monitoring features

## Licence

Distributed under a permissive Licence. Attribution appreciated.
