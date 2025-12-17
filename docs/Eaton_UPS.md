# Eaton UPS Zabbix Template Documentation

## Overview
This document provides comprehensive details for the **Eaton UPS Zabbix Template**. The template enables advanced monitoring of Eaton Uninterruptible Power Supply (UPS) systems using SNMP, leveraging the XUPS-MIB for dynamic discovery and metric collection. It is designed for Zabbix 6.0+ and 7.0+ environments and supports a wide range of Eaton UPS models, including but not limited to:

- Eaton 5PX, 9PX, 93PM, 93E, 93PR, 91PS, 93PS, 9SX, 5SC, 5P, 5E, and compatible models
- Models supporting SNMP cards (Network-M2, Network-MS, ConnectUPS, etc.)

## Features
- **Dynamic LLD (Low-Level Discovery):**
  - Auto-discovers power modules, batteries, load segments, and environment sensors
  - Supports multi-module and multi-battery configurations
- **Comprehensive Metric Coverage:**
  - Input/output voltage, current, frequency, and power
  - Battery status, charge, temperature, and runtime
  - Load percentage, apparent/active power, and segment status
  - Environmental sensors (temperature, humidity, etc.)
- **Advanced Triggers and Alerts:**
  - Battery low, replace battery, overload, bypass, on battery, communication lost
  - Configurable thresholds for all key metrics
- **Value Mapping:**
  - Human-readable status for states, alarms, and sensor values
- **Custom Graphs and Dashboards:**
  - Predefined graphs for voltage, load, battery, and temperature
  - Dashboard widgets for quick status overview
- **Macro Support:**
  - SNMP community, SNMP version, and custom thresholds via host macros
- **Documentation and Troubleshooting:**
  - Detailed item, trigger, and discovery descriptions
  - Links to Eaton MIBs and SNMP documentation

## Prerequisites
- **Zabbix Server/Proxy:** Version 6.0 or later (7.0+ recommended)
- **Eaton UPS:** SNMP card installed and configured (Network-M2, Network-MS, ConnectUPS, etc.)
- **Network Access:** Zabbix server/proxy must be able to reach the UPS SNMP interface
- **MIBs:** XUPS-MIB loaded on your Zabbix server/proxy for symbolic OID resolution (optional but recommended)

## Installation
1. **Copy the Template:**
   - Download the template YAML or XML file from the `templates/` directory of this repository (`eaton_ups.yaml` or `eaton_ups.xml`).
2. **Import into Zabbix:**
   - Go to **Zabbix Console > Data Collection > Templates > Import**
   - Select the template file and import
3. **Assign to Host:**
   - Create or select a host representing your Eaton UPS
   - Link the imported template to the host
   - Set SNMP interface IP and configure macros as needed (e.g., SNMP community, thresholds)
4. **Verify Data Collection:**
   - Check Latest Data for the host to ensure metrics are being collected
   - Review discovered items, triggers, and graphs

## Configuration
### Required Macros
- `{SNMP_COMMUNITY}`: SNMP community string (default: `public`)
- `{SNMP_VERSION}`: SNMP version (default: `2c`)
- Optional: Custom thresholds for battery, load, etc.

### Example Host Macros
| Macro                | Example Value |
|----------------------|--------------|
| {$SNMP_COMMUNITY}    | public       |
| {$SNMP_VERSION}      | 2c           |
| {$BATTERY_LOW}       | 20           |
| {$LOAD_OVER}         | 90           |

### Supported SNMP Versions
- SNMPv1, SNMPv2c, SNMPv3 (with authentication and privacy)

## Monitored Metrics (Sample)
- **Input:** Voltage, frequency, current, phase status
- **Output:** Voltage, frequency, current, load, power, phase status
- **Battery:** Charge, runtime, temperature, status, test results
- **Environment:** Temperature, humidity (if sensors present)
- **Alarms:** On battery, overload, replace battery, bypass, communication lost

## Triggers (Sample)
- Battery low
- Replace battery soon
- UPS on battery
- Output overload
- Communication lost
- High temperature

## Value Maps
- Battery status: Normal, Low, Replace, Charging, Discharging
- UPS state: Online, On battery, Bypass, Standby, Fault

## Troubleshooting
- **No Data Collected:**
  - Verify SNMP community, version, and network connectivity
  - Check UPS SNMP card status and access control
  - Use `snmpwalk` to test OID access from Zabbix server/proxy
- **Discovery Issues:**
  - Ensure the UPS supports XUPS-MIB and discovery OIDs
  - Check for SNMP timeouts or access restrictions
- **Incorrect Values:**
  - Confirm correct MIBs are loaded (optional for symbolic OIDs)
  - Review macro values and thresholds

## References
- [Eaton XUPS-MIB Documentation](https://powerquality.eaton.com/Support/Software-Drivers/MIBs.asp)
- [Eaton SNMP Card Manuals](https://www.eaton.com/us/en-us/catalog/backup-power-ups-surge-it-power-distribution/snmp-network-management-card.html)
- [Zabbix Template Import Guide](https://www.zabbix.com/documentation/current/en/manual/config/templates/template)
- [Eaton UPS Product Page](https://www.eaton.com/us/en-us/catalog/backup-power-ups-surge-it-power-distribution.html)

## License
This template and documentation are provided under the **Apache License 2.0**. See the [LICENSE.md](../LICENSE.md) file for details.
