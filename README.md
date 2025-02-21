# Custom Zabbix Scripts Repository

### Author: Simon Jackson (sjackson0109)
# Created     	: 2025/02/17
# Updated       : 2025/02/21

## Overview
This repository contains custom scripts designed for **Zabbix Monitoring**. Each script is documented individually, providing installation instructions, usage examples, and integration details.

## Structure
All custom monitoring scripts reside under this repository. Below are the available scripts with their respective documentation:

### Available Scripts:
- **[WatchGuard System Health Check](readme-watchguard.md)** - Logs into a WatchGuard Firewall, retrieves system health metrics, and calculates a health score for Zabbix. Returns a integer from 1 to 100 (healthy).
- **[get_sip_options.py](README-SIP-Options.md)** - A Python script designed to send SIP OPTIONS requests to a specified SIP server and verify its response. The script is fully compliant with RFC 3261 and supports a wide variety of optional arguments.
- **[Script B](readme-B.md)** - Description of Script B.
- **[Script C](readme-C.md)** - Description of Script C.

## Installation
For installation and usage details of each script, refer to the individual README files linked above.

## Notes
- Scripts are designed to integrate with **Zabbix Proxy** and **Zabbix Server**.
- Each script follows best practices for **error handling**, **logging**, and **parameterisation**.
- Contributions and improvements are welcome.

## License
MIT License

