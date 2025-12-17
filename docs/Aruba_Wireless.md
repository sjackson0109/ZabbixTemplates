# Aruba Wireless Zabbix Template Documentation

## Overview

The **Aruba Wireless** Zabbix template provides unified SNMP-based monitoring for Aruba Access Points (APs) and Virtual Controllers (VCs). It is designed to auto-detect device roles (standalone AP, IAP, or VC), dynamically discover SSIDs, clients, interfaces, and deliver comprehensive wireless and controller metrics. The template leverages advanced LLD (Low-Level Discovery) and macro-driven configuration for flexible, scalable monitoring in enterprise and campus environments.

## Features

- **Role Detection**: Automatically identifies device type (AP, IAP, or Virtual Controller) and adapts monitoring logic accordingly.
- **LLD-Driven Discovery**:
  - SSIDs (per AP and VC)
  - Wireless clients (per SSID, per AP)
  - Network interfaces (IF-MIB)
  - Radios and radio metrics
- **Comprehensive Metrics**:
  - Client counts, per-SSID and per-AP
  - Traffic statistics (bytes, packets, errors)
  - Signal quality, noise, channel, and radio state
  - System health: uptime, contact, description, hardware/software version
  - Controller metrics (if VC detected)
- **SNMP Walk Items**: For troubleshooting and advanced discovery, raw SNMP walk items are included for SSIDs and interfaces.
- **Trap Support**: Fallback SNMP trap item for unmatched traps.
- **Inventory Integration**: Links key SNMP data to Zabbix inventory fields (e.g., contact, description).
- **Preprocessing**: Discards unchanged values to reduce noise and optimize storage.
- **Customisable via Macros**: Supports macro-driven configuration for SNMP community, timeouts, and thresholds.

## Installation

1. **Import the Template**
   - In Zabbix frontend, go to *Configuration → Templates* and import `aruba_wireless.yaml`.
2. **Assign to Hosts**
   - Link the template to Aruba APs or Virtual Controllers. The template will auto-detect the device role.
3. **Configure Macros (if needed)**
   - Set SNMP community, timeouts, or custom thresholds using host or template macros.
4. **Deploy External Scripts (Optional)**
   - No external scripts are required for core SNMP monitoring. For advanced use, see the `externalscripts/` directory.

## Usage

- **Discovery**: LLD rules will automatically populate items, triggers, and graphs for each discovered SSID, client, interface, and radio.
- **Monitoring**: View wireless metrics, client counts, traffic, and system health in Zabbix dashboards and screens.
- **Troubleshooting**: Use raw SNMP walk items for deep diagnostics. SNMP trap fallback item captures all unmatched traps for further analysis.

## Troubleshooting

- Ensure SNMP is enabled and accessible on Aruba devices.
- For large deployments, adjust SNMP timeouts and retries via macros if discovery is slow.
- If items are not being discovered, verify device role and SNMP OID support (template is designed for Aruba Instant/IAP and VCs).
- Use the raw SNMP walk items to verify OID accessibility and device responses.

## References

- [Aruba Networks MIBs](https://www.arubanetworks.com/techdocs/ArubaOS_83_Web_Help/Content/ArubaFrameStyles/MIBs/MIBs.htm)
- [Zabbix Documentation: SNMP Monitoring](https://www.zabbix.com/documentation/current/en/manual/config/items/itemtypes/snmp)
- [Zabbix Documentation: LLD](https://www.zabbix.com/documentation/current/en/manual/discovery/low_level_discovery)

---

For template validation, usage examples, and troubleshooting, see the main [README.md](../README.md).
