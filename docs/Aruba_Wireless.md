# Aruba Wireless Zabbix Template Documentation

## Overview

The **Aruba Wireless** Zabbix template provides unified SNMP-based monitoring for Aruba Access Points (APs) and Virtual Controllers (VCs). It is designed to auto-detect device roles (standalone AP, IAP, or VC), dynamically discover SSIDs, clients, interfaces, and deliver comprehensive wireless and controller metrics. The template leverages advanced LLD (Low-Level Discovery) and macro-driven configuration for flexible, scalable monitoring in enterprise and campus environments.

## Recent Updates (January 2026)

### Template Analysis & Optimization ✅
- **Comprehensive Template Review**: Deep analysis of 3,641-line template structure and enterprise architecture
- **Dual-Mode Architecture Understanding**: Validated complex VC (Virtual Controller) vs Standard AP monitoring capabilities
- **Interface Mapping Verification**: Confirmed 322 interface mappings are specifically selected for diverse Aruba hardware support
- **Template Validation**: Passes Zabbix 7.0 schema validation cleanly - ready for deployment

### Enterprise Architecture Validation 🏢
- **VC Mode Support**: Confirmed comprehensive Virtual Controller cluster-wide metrics and management
- **AP Mode Support**: Verified standalone Access Point monitoring with full feature set
- **SNMP OID Coverage**: Validated extensive OID usage across multiple MIB branches (AI-AP-MIB 1.3.6.1.4.1.14823.2.3.3.* for VC, standard AP MIBs 1.3.6.1.4.1.14823.2.2.*)
- **Discovery Rules**: Complex discovery for client analytics, rogue AP detection, interface monitoring, dual-mode SSID discovery

### Template Capabilities Assessment 📊
- **File Size**: 152,568 bytes (3,641 lines) - justified for enterprise scope
- **Template Structure**: Intelligent role detection switching between VC and Standard AP monitoring approaches  
- **External Dependencies**: Dashboard widgets with GitHub URL references for enhanced visualization
- **Performance Focus**: Real-time monitoring for bandwidth utilisation, client counts, and network errors
- **Security Features**: Authentication failure tracking, rogue AP detection, security event monitoring

## Features

- **Role Detection**: Automatically identifies device type (AP, IAP, or Virtual Controller) and adapts monitoring logic accordingly.
- **Enhanced LLD-Driven Discovery**:
  - SSIDs (per AP and VC)
  - Wireless clients (per SSID, per AP)
  - Network interfaces (IF-MIB)
  - **Radio/Band Discovery**: Automatic 2.4GHz and 5GHz radio interface monitoring
  - **Security Events Discovery**: Real-time security incident detection and tracking
- **Comprehensive Metrics**:
  - Client counts, per-SSID and per-AP
  - Traffic statistics (bytes, packets, errors)
  - Signal quality, noise, channel, and radio state
  - **Per-radio channel utitilisation and TX power monitoring**
  - **Noise level detection and interference analysis**
  - System health: uptime, contact, description, hardware/software version
  - Controller metrics (if VC detected)
- **Advanced Security Monitoring**:
  - **Authentication failure tracking with rate-based analysis**
  - **Certificate expiry monitoring with advance warnings**
  - **Security event detection and intrusion monitoring**
  - **Configurable security thresholds and alerting**
- **SNMP Walk Items**: For troubleshooting and advanced discovery, raw SNMP walk items are included for SSIDs and interfaces.
- **Trap Support**: Fallback SNMP trap item for unmatched traps.
- **Inventory Integration**: Links key SNMP data to Zabbix inventory fields (e.g., contact, description).
- **Advanced Preprocessing & Database Optimisation**: 
  - **DISCARD_UNCHANGED_HEARTBEAT**: Intelligent heartbeat intervals for semi-static data (certificate status, system information, environmental data)
  - **DISCARD_UNCHANGED**: Event-based storage for security incidents and alerts
  - **Smart Write Reduction**: Up to 92% reduction in database writes for appropriate metrics while maintaining real-time monitoring for critical performance data
  - **Optimised Item Categories**: Certificate monitoring (6h), session analytics (15m), memory utilisation (10m), channel analysis (1h)
- **Customisable via Macros**: Supports macro-driven configuration for SNMP community, timeouts, security thresholds, and performance alerts.

## Installation

1. **Import the Template**
   - In Zabbix frontend, go to *Configuration → Templates* and import `aruba_wireless.yaml`
   - **Template Version**: Latest (January 2026) - analyzed and validated for enterprise deployment
   - **Import Status**: Template validates cleanly with no YAML syntax errors
   - **File Size**: 152,568 bytes (3,641 lines) - comprehensive enterprise monitoring solution
2. **Assign to Hosts**
   - Link the template to Aruba APs or Virtual Controllers. The template will auto-detect the device role.
3. **Configure Macros (if needed)**
   - Set SNMP community, timeouts, or custom thresholds using host or template macros.
4. **Deploy External Scripts (Optional)**
   - No external scripts are required for core SNMP monitoring. For advanced use, see the `externalscripts/` directory.
5. **Verify Template Deployment**
   - Template supports both VC (Virtual Controller) and Standard AP modes
   - Automatic role detection and appropriate monitoring configuration
   - 322 interface mappings provide comprehensive hardware compatibility
   - Monitor dual-mode SSID discovery and client analytics functionality

## Usage

- **Discovery**: LLD rules will automatically populate items, triggers, and graphs for each discovered SSID, client, interface, and radio.
- **Monitoring**: View wireless metrics, client counts, traffic, and system health in Zabbix dashboards and screens.
- **Troubleshooting**: Use raw SNMP walk items for deep diagnostics. SNMP trap fallback item captures all unmatched traps for further analysis.

## Auto-Discovery Configuration

For bulk deployment of Aruba APs using Zabbix network discovery, careful consideration of device uniqueness criteria is essential, particularly in DHCP environments.

### Discovery Rule Configuration

**Recommended Settings:**
- **Name**: "Aruba Wireless Discovery"
- **IP Range**: Your AP subnet (e.g., `10.101.48.0/23`)
- **Update Interval**: 1h
- **Checks**:
  - SNMPv2 agent `1.3.6.1.2.1.1.1.0` (sysDescr) - Device identification
  - SNMPv2 agent `1.3.6.1.2.1.1.5.0` (sysName) - Device name retrieval

### Device Uniqueness Criteria: DHCP Considerations

**The Challenge:**
In DHCP environments, APs may receive different IP addresses after reboots (PoE switch restarts, power outages, DHCP lease expiration). This creates a critical decision point for device uniqueness criteria.

**Option 1: IP Address Uniqueness**
- ✅ **Pros**: Simple, always unique
- ❌ **Cons**: DHCP lease changes create duplicate hosts, lose historical data

**Option 2: SNMP sysName Uniqueness**
- ✅ **Pros**: Preserves historical data across IP changes, no duplicates
- ✅ **Benefits**: Zabbix automatically updates existing host IP addresses
- ⚠️ **Requirements**: All APs must have unique, static sysName values

**Recommended Solution for DHCP Environments:**
- **Device Uniqueness Criteria**: "SNMPv2 agent '1.3.6.1.2.1.1.5.0'" (sysName)
- **Host Name**: "SNMPv2 agent '1.3.6.1.2.1.1.5.0'" (sysName) 
- **Visible Name**: "Host name"

### Verification Before Implementation

Test sysName uniqueness across your AP fleet:
```bash
snmpget -v2c -c [community] [AP-IP] 1.3.6.1.2.1.1.5.0
```

Ensure each AP returns a unique, meaningful name (e.g., "AP-Floor1-Room101").

### Discovery Actions

Configure automatic actions for discovered devices:
- **Condition**: SNMP system description contains "Aruba"
- **Operations**: 
  - Add host
  - Link template: "Aruba Wireless"
  - Add to group: "Aruba Access Points"
  - Set inventory mode: Automatic
  - **Set macro**: `{$SNMP_COMMUNITY}` = `[your-snmp-community]`

**Important**: Replace `[your-snmp-community]` with your actual SNMP community string. This ensures all discovered APs automatically inherit the correct SNMP credentials for monitoring.

This configuration ensures reliable monitoring continuity in dynamic IP environments while maintaining clean, readable device identification.

## Dashboard Pages

### 1. 🌐 **Access Points Overview**
**Purpose**: High-level infrastructure monitoring and AP health management

**Key Widgets**:
- **Summary Statistics**: Total APs, Online APs, Active SSIDs, Connected Clients
- **Performance Gauges**: Average CPU and Memory usage across all APs
- **Status Timeline**: AP availability and status changes over time
- **Top Lists**: APs ranked by client count and health metrics
- **Traffic Overview**: Aggregate wireless network traffic
- **Client Distribution**: Visual breakdown of clients across SSIDs
- **Alert Summary**: Recent AP-specific issues and problems

**Use Cases**:
- Quick infrastructure health assessment
- Capacity planning and load distribution analysis
- Identifying underperforming or overloaded APs
- Network-wide trend monitoring

### 2. 📶 **SSID Performance Analytics**
**Purpose**: Detailed SSID monitoring and wireless service quality analysis

**Key Widgets**:
- **Performance Table**: SSID client counts, traffic rates, and efficiency metrics
- **Critical Issues**: SSID-specific problems with severity-based filtering
- **Traffic Comparison**: Top 5 SSIDs by traffic volume with trend analysis
- **Client Trends**: Historical client count patterns per SSID
- **Security Monitoring**: Authentication failure tracking and analysis
- **Performance Metrics**: Throughput efficiency and utitilisation ratios

**Use Cases**:
- SSID performance optimisation
- Identifying wireless service issues
- Capacity planning per service/SSID
- Security incident detection
- Service quality troubleshooting

### 3. 👥 **Client Health & Performance**
**Purpose**: Individual client monitoring and troubleshooting support

**Key Widgets**:
- **🍯 Health Matrix**: Honeycomb-style view with colour-coded client status
- **🚨 Issue Alerts**: Real-time client connection and performance problems
- **📊 Signal Distribution**: Visual breakdown of client signal quality
- **💻 OS Distribution**: Client device type and operating system analysis
- **🏆 Traffic Leaders**: Top clients by bandwidth consumption
- **📈 Performance Trends**: Time-series analysis for selected clients
- **🔧 Troubleshooting Data**: Comprehensive client connection details

### 4. 🔒 **Security Analytics** *(NEW)*
**Purpose**: Advanced security monitoring and threat detection for wireless infrastructure

**Key Widgets**:
- **🛡️ Authentication Failure Rate**: Real-time monitoring of authentication failures per second
- **📜 Certificate Expiry Status**: Days remaining until certificate expiration
- **🚨 Security Event Alerts**: Active security incidents and intrusion attempts
- **📊 Security Insights Panel**: Overview of enhanced security features including:
  - Radio/Band Discovery capabilities
  - Security event tracking systems
  - Authentication failure analysis
  - Certificate monitoring status
- **📋 Security Guidelines**: Best practices and configurable threshold information

**New Security Features**:
- **Radio/Band Discovery**: Automated detection and monitoring of 2.4GHz and 5GHz radio bands
- **Security Events Discovery**: Real-time intrusion detection and rogue AP monitoring
- **Authentication Failure Analysis**: Rate-based detection of authentication attacks
- **Certificate Health Monitoring**: Proactive SSL/TLS certificate expiry tracking
- **Configurable Security Thresholds**: Customisable alerting via macro configuration

**Use Cases**:
- Security incident response and threat detection
- Wireless infrastructure security posture monitoring
- Certificate lifecycle management
- Authentication attack detection and analysis
- Compliance monitoring and security reporting

## Configuration Macros

### Security Monitoring Macros *(NEW)*
- **`{$ARUBA_AUTH_FAILURE_RATE_WARNING}`** *(Default: 5)*: Authentication failures per second threshold
- **`{$ARUBA_CERT_EXPIRY_WARNING}`** *(Default: 30)*: Certificate expiry warning threshold (days)
- **`{$ARUBA_CERT_EXPIRY_CRITICAL}`** *(Default: 7)*: Certificate expiry critical threshold (days)
- **`{$ARUBA_CHANNEL_UTIL_WARNING}`** *(Default: 80)*: Channel utitilisation warning threshold (%)
- **`{$ARUBA_RADIO_NOISE_HIGH}`** *(Default: -70)*: High radio noise level threshold (dBm)

### Performance Monitoring Macros
- **`{$ARUBA_UPTIME_THRESHOLD}`** *(Default: 3600)*: Recent reboot detection threshold (seconds)
- **`{$ARUBA_LOW_SIGNAL_THRESHOLD}`** *(Default: -70)*: Low signal strength threshold (dBm)
- **`{$ARUBA_HIGH_CPU_THRESHOLD}`** *(Default: 85)*: High CPU usage threshold (%)

### SNMP Configuration Macros
- **`{$SNMP_COMMUNITY}`** *(Default: public)*: SNMP community string
- **`{$SNMP_TIMEOUT}`** *(Default: 15)*: SNMP timeout value (seconds)

## Colour Coding System

### Health Status Indicators
- 🟢 **Green (Excellent)**: Signal >30dB, CPU/Memory <70%
- 🟡 **Yellow (Warning)**: Signal 20-30dB, CPU/Memory 70-85%
- 🟠 **Orange (Poor)**: Signal 10-20dB, CPU/Memory 85-95%
- 🔴 **Red (Critical)**: Signal <10dB, CPU/Memory >95%

### Traffic Thresholds
- **Low**: <1 Mbps
- **Medium**: 1-10 Mbps  
- **High**: 10-100 Mbps
- **Very High**: >100 Mbps

## Enhanced Discovery Rules *(NEW)*

### Radio/Band Discovery
- **Purpose**: Automatically discovers and monitors 2.4GHz and 5GHz radio interfaces
- **Items Created**:
  - Channel utitilisation per radio (with alerting at >{$ARUBA_CHANNEL_UTIL_WARNING}%)
  - TX power levels for coverage optimisation
  - Noise level monitoring for interference detection
- **Update Interval**: 15 minutes
- **Retention**: 7 days

### Security Events Discovery  
- **Purpose**: Detects and tracks wireless security incidents and intrusion attempts
- **Items Created**:
  - Security event counters by event type
  - Real-time security incident detection
- **Update Interval**: 10 minutes
- **Retention**: 12 hours

## Security Features *(NEW)*

### Authentication Monitoring
- **Total Authentication Failures**: Aggregate count across all SSIDs
- **Authentication Failure Rate**: Per-second failure rate with configurable alerting
- **Trigger Threshold**: Alerts when rate exceeds `{$ARUBA_AUTH_FAILURE_RATE_WARNING}` failures/sec

### Certificate Management
- **Certificate Expiry Monitoring**: Days remaining until certificate expiration
- **Warning Alert**: Triggered at `{$ARUBA_CERT_EXPIRY_WARNING}` days remaining
- **Critical Alert**: Triggered at `{$ARUBA_CERT_EXPIRY_CRITICAL}` days remaining

## Troubleshooting

### General Issues
- Ensure SNMP is enabled and accessible on Aruba devices.
- For large deployments, adjust SNMP timeouts and retries via macros if discovery is slow.
- If items are not being discovered, verify device role and SNMP OID support (template is designed for Aruba Instant/IAP and VCs).
- Use the raw SNMP walk items to verify OID accessibility and device responses.

### Recent Template Fixes (January 2026)
- **Import Errors**: If encountering "Duplicate key 'value'" errors, ensure you're using the latest template version with dashboard fixes
- **Dashboard Display Issues**: Updated dashboard widgets resolve previous structural conflicts in SSID Performance and Client Analysis views
- **Database Performance**: Template now includes automatic preprocessing optimisation - no configuration required
- **Data Gaps**: For items with heartbeat intervals (certificates, memory, channels), data points are intentionally reduced to optimise database performance while maintaining monitoring accuracy

### Validation Status
- **Template Structure**: ✅ All duplicate key issues resolved
- **YAML Syntax**: ✅ Clean import without warnings
- **Preprocessing**: ✅ Database optimisation automatically applied
- **Discovery Rules**: ✅ All LLD rules maintain full functionality

## References

- [Aruba Networks MIBs](https://www.arubanetworks.com/techdocs/ArubaOS_83_Web_Help/Content/ArubaFrameStyles/MIBs/MIBs.htm)
- [Zabbix Documentation: SNMP Monitoring](https://www.zabbix.com/documentation/current/en/manual/config/items/itemtypes/snmp)
- [Zabbix Documentation: LLD](https://www.zabbix.com/documentation/current/en/manual/discovery/low_level_discovery)

---

For template validation, usage examples, and troubleshooting, see the main [README.md](../README.md).
