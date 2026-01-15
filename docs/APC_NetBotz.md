# APC NetBotz Environmental Monitoring Template

## Overview
The APC NetBotz template provides comprehensive SNMP-based monitoring for APC NetBotz environmental monitoring devices. It supports multiple device families and automatically discovers sensors, alarms, and environmental metrics.

## Features
- **Comprehensive Environmental Monitoring**: Temperature, humidity, airflow, and dew point
- **Automatic Sensor Discovery**: Dynamic discovery of all available sensors
- **Alarm Monitoring**: Real-time monitoring of device alarms and status
- **Device Health**: System health, power status, and operational metrics
- **Value Mapping**: Human-readable status and alarm descriptions
- **Multi-Device Support**: Compatible with various NetBotz models

## Supported Devices
- APC NetBotz Room Monitor 355/455/465
- APC NetBotz Wireless Sensor Pods
- APC NetBotz Camera Pod 165
- APC NetBotz Sensor Pod 180/181
- Other NetBotz-compatible environmental sensors

## Monitored Metrics

### Environmental Sensors
- **Temperature**: Ambient, rack, and sensor-specific temperatures
- **Humidity**: Relative humidity measurements
- **Airflow**: Air velocity and direction monitoring
- **Dew Point**: Calculated dew point temperatures
- **Dry Contact**: Door sensors, leak detection, and custom inputs

### Device Status
- **Device Health**: Overall system status and operational state
- **Communication**: Network connectivity and SNMP responsiveness
- **Power**: Power supply status and consumption
- **Enclosure**: Physical security and door states

### Alarms & Notifications
- **Critical Alarms**: Temperature/humidity out of range
- **Warning Alarms**: Approaching threshold conditions
- **Information Alarms**: Status changes and events
- **Acknowledgment Status**: Alarm acknowledgment tracking

## Installation

### Prerequisites
- Zabbix 7.0 or later
- SNMP enabled on the NetBotz device
- Network connectivity from Zabbix server/proxy to NetBotz device

### Setup Steps
1. **Configure NetBotz Device**:
   - Enable SNMP v1/v2c or v3 on the device
   - Set appropriate SNMP community string or user credentials
   - Ensure device is accessible from Zabbix server/proxy

2. **Import Template**:
   - Import `apc_netbotz.yaml` via Zabbix web interface
   - Navigate to Configuration → Templates → Import

3. **Configure Host**:
   - Create or edit host for NetBotz device
   - Assign "APC NetBotz" template
   - Configure SNMP interface with correct community/credentials
   - Set appropriate SNMP version and port (default: 161)

4. **Configure Macros**:
   - `{$SNMP_COMMUNITY}`: SNMP community string (default: public)
   - `{$TEMP_CRIT_HIGH}`: Critical high temperature threshold (°C)
   - `{$TEMP_WARN_HIGH}`: Warning high temperature threshold (°C)
   - `{$TEMP_CRIT_LOW}`: Critical low temperature threshold (°C)
   - `{$HUMIDITY_CRIT_HIGH}`: Critical high humidity threshold (%)
   - `{$HUMIDITY_WARN_HIGH}`: Warning high humidity threshold (%)

## Template Components

### Discovery Rules
- **Sensor Discovery**: Automatically discovers all available sensors
- **Alarm Discovery**: Finds all configurable alarm points
- **Enclosure Discovery**: Detects physical enclosures and doors

### Items
- Environmental sensor readings (temperature, humidity, airflow)
- Device status and health indicators
- Alarm states and acknowledgment status
- Network and communication metrics

### Triggers
- Critical and warning thresholds for environmental conditions
- Device offline or communication failure alerts
- Alarm condition monitoring and escalation
- Sensor fault and calibration alerts

### Graphs
- Environmental trend analysis (temperature, humidity over time)
- Alarm frequency and resolution tracking
- Device health and uptime statistics

## Value Mappings

### Device Status
- 0: Unknown
- 1: Normal
- 2: Warning
- 3: Critical
- 4: Failure

### Alarm States
- 0: Normal
- 1: Warning
- 2: Critical
- 3: Acknowledged

### Sensor Status
- 0: Disabled
- 1: Normal
- 2: Not Installed
- 3: Error

## Troubleshooting

### Common Issues
1. **No Data Received**:
   - Verify SNMP configuration and connectivity
   - Check community string or SNMP credentials
   - Ensure correct SNMP version is configured

2. **Missing Sensors**:
   - Confirm sensors are properly connected to NetBotz device
   - Check sensor configuration in NetBotz web interface
   - Verify sensors are enabled and functioning

3. **Incorrect Threshold Alerts**:
   - Review macro values for temperature and humidity thresholds
   - Check sensor calibration and accuracy
   - Verify alarm configuration on the device

### Debugging Steps
1. Test SNMP connectivity using `snmpwalk` or similar tools
2. Check Zabbix server logs for SNMP errors
3. Review NetBotz device logs and status
4. Validate template import and host configuration

## Best Practices
- Regularly calibrate sensors for accuracy
- Set appropriate threshold values based on environmental requirements
- Monitor device health and communication status
- Use NetBotz grouping features for logical sensor organisation
- Implement proper environmental alerting workflows

## References
- [APC NetBotz User Guide](https://www.apc.com/shop/us/en/categories/power/uninterruptible-power-supply-ups-/network-and-server-room/environmental-monitoring/netbotz/_/N-1hqk3hc)
- [NetBotz SNMP Configuration Guide](https://www.apc.com/shop/us/en/products/NetBotz-SNMP-Management-Cards/P-NBMG0001)
- [Environmental Monitoring Best Practices](https://www.apc.com/shop/us/en/products/environmental-monitoring)