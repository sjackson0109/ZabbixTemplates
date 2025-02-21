## Overview
This repository contains custom scripts designed for **Zabbix Monitoring**. Each script is documented individually, providing installation instructions, usage examples, and integration details.

## Structure
All custom monitoring scripts reside under this repository. Below are the available scripts with their respective documentation:

### Available Scripts:
- **[WatchGuard System Health Check](readme-watchguard.md)** - Logs into a WatchGuard Firewall, retrieves system health metrics, and calculates a health score for Zabbix. Returns a integer from 1 to 100 (healthy).
- **[get_sip_options.py](README-SIP-Options.md)** - A Python script designed to send SIP OPTIONS requests to a specified SIP server and verify its response. The script is fully compliant with RFC 3261 and supports a wide variety of optional arguments.
- **[get_firebox_health.py](README-WatchguardSystemHealth.md)** - This script logs into a **WatchGuard Firewall**, retrieves **system health metrics**, and calculates a **health score** for monitoring in **Zabbix** (still under development)

- **[Script C](readme-C.md)** - Description of Script C.

## Installation
For installation and usage details of each script, refer to the individual README files linked above.

## Notes
- Scripts are designed to integrate with **Zabbix Proxy** and **Zabbix Server**.
- Each script follows best practices for **error handling**, **logging**, and **parameterisation**.
- Contributions and improvements are welcome.

## License
This project is licensed under the **Apache License 2.0**.  
See the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) for details.