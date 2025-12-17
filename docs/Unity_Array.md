# Dell EMC Unity Array Zabbix Template & Script

## Overview
This documentation covers the Zabbix template and external script for monitoring Dell EMC Unity storage arrays using the REST API. The solution provides auto-discovery and monitoring of Unity resources (LUNs, Pools, Disks, Ports, Batteries, and more) with health, status, and capacity metrics.

- **Template:** `dell_unity_array.yaml`
- **Script:** `get_unity_array.py`
- **Zabbix Version:** 6.0+
- **Author:** Simon Jackson / @sjackson0109

## Features
- Auto-discovers Unity resources (LUNs, Pools, Disks, Ports, Batteries, etc.)
- Monitors health, capacity, firmware, and status metrics
- Supports secure or insecure TLS/SSL connections (configurable)
- Sends data to Zabbix using `zabbix_sender`
- Logs actions and errors for troubleshooting

## Installation
### 1. Deploy the Script
Copy `get_unity_array.py` to your Zabbix `externalscripts` directory (on proxy or server).

### 2. Install Python Dependencies
```bash
pip install requests urllib3
```

### 3. Import the Template
- Import `dell_unity_array.yaml` into Zabbix (Configuration > Templates > Import).

### 4. Configure Host Macros
Add the following macros to your Unity host in Zabbix:
```yaml
{$UNITY_USER}      # Unity API username
{$UNITY_PASSWORD}  # Unity API password
{$UNITY_PORT}      # Unity API port (default: 443)
{$UNITY_TLS_VERIFY} # Set to 1 to enforce TLS/SSL certificate validation, 0 to ignore (default: 0)
```

### 5. Assign the Template
- Link the template to your Unity array host.
- Set the macros with correct values for your environment.

## Usage
- The template will auto-discover LUNs, pools, disks, and other resources.
- Metrics such as health, size, model, serial, and firmware will be collected and available in Zabbix.
- Triggers and graphs can be added as needed for your monitoring requirements.

## Security Note
- By default, the script ignores SSL certificate errors. To enforce certificate validation, set `{$UNITY_TLS_VERIFY}` to `1` and ensure your Unity array uses a valid certificate.

## Troubleshooting
- Check `/tmp/unity_state.log` for script logs and errors.
- Ensure all macros are set and correct on the Zabbix host.
- Verify Python dependencies are installed.
- Use Zabbix's "Latest Data" to confirm metrics are being collected.

## References
- [Dell EMC Unity REST API Documentation](https://www.dell.com/support/manuals/en-us/unity-family/unity_p-rest-api)
- [Zabbix External Scripts](https://www.zabbix.com/documentation/current/en/manual/config/items/itemtypes/external)
