# Carel pCOWeb Zabbix Template

## Overview
This template provides SNMP-based monitoring for Carel pCOWeb environmental controllers. It is designed for use with Zabbix 7.0+ and supports a wide range of alarms, sensors, and device metrics.

## Features
- SNMP monitoring of key environmental parameters
- Alarm and sensor discovery
- Value mapping for status and alarms
- Technical documentation links for further reference
- Designed for easy integration with Zabbix

## Monitored Metrics
- Airflow, temperature, humidity, and dew point
- Device and enclosure status
- Dry contact and door switch sensors
- Alarm states and codes
- Power and system health

## Installation
1. Import the `carel_pcoweb.yaml` template into Zabbix via the web UI.
2. Assign the template to hosts with Carel pCOWeb controllers.
3. Ensure SNMP access is configured and the device is reachable from your Zabbix server or proxy.

## Requirements
- Zabbix 7.0 or later
- SNMP enabled on the Carel pCOWeb device

## References
- [Carel pCOWeb Technical Manual](https://www.rittal.com/imf/none/3_4342/3311320_Instructions_spec__EN)
- [Nagios SNMP Denco pCO Web Carel](https://netopslife.wordpress.com/2017/10/12/nagios-snmp-denco-pco-web-carel/)

## Notes
- The template uses SNMP OIDs as per Carel and Denco documentation.
- Value mapping is included for common alarm and status codes.
- For customisations or troubleshooting, refer to the technical manuals above.

## Licence
This template is released under the Apache Licence 2.0.
