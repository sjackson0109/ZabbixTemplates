## Overview

### Template Validation

Before importing any template into Zabbix, it's highly recommended to validate it using our comprehensive validation tool. These scripts catche ~95% of common errors before import, returning more helpful error messages, and significantly saves on debugging time.

**Quick Start**:
```bash
# Validate a single template
python scripts/validate_zabbix_template.py templates/your_template.yaml

# Validate all templates
python scripts/validate_all_templates.py
```

**📖 Full Documentation**: See **[Template Validation Guide](docs/validate_template.md)** for:
- Complete feature list and usage examples
- Common errors and how to fix them
- CI/CD integration examples
- Troubleshooting guide

The validator checks:
- ✅ YAML syntax and Zabbix schema compliance
- ✅ UUID format (UUIDv4)
- ✅ Item key syntax (bracket matching)
- ✅ Time unit formats (1m, 5h, 30s)
- ✅ SNMP OID formats
- ✅ Enum values (item types, trigger priorities)
- ✅ Trigger expression parsing
- ✅ Item reference integrity
- ✅ Multi-line string validation

## Structure
All custom monitoring scripts reside under this repository. Below are the available scripts with their respective documentation:

### Available Scripts:
- **[snmp_client.py](docs/SNMP-Client.md)** - Comprehensive SNMPv1/v2c/v3 client with authentication and privacy support. RFC 3414 compliant, supports MD5/SHA authentication and DES/AES encryption. Integrates with Zabbix external scripts for discovery, check, and detailed check modes.
- **[get_stun_turn_checks.py](docs/STUN-TURN-Checks.md)** - STUN/TURN monitoring script with full RFC 5389/5766 support. Handles STUN binding requests, TURN allocation with authentication, and UDP/TCP/TLS transports. Optimized for fast monitoring.
- **[get_tcp_port_scan.py](docs/TCP-Port-Scan.md)** - Multithreaded TCP scanner for service discovery and exposure audits. Designed for Zabbix LLD and interactive CLI use.
- **[get_sip_options.py](docs/SIP-Options.md)** - Sends SIP OPTIONS requests to a SIP server and verifies responses. Fully RFC 3261 compliant with extensive argument support.
- **[get_tls_handshake.py](docs/TLS-Handshake.md)** - Tests TLS handshake capabilities of a host. Detects available SSL/TLS protocols and ciphers, and provides a compatibility report.
 - **[get_unity_array.py](docs/Unity_Array.md)** - Dell EMC Unity storage array monitoring and auto-discovery via REST API. Collects inventory, health, capacity, and status metrics for LUNs, pools, disks, ports, and more. See full usage and template details in the linked documentation.
- **[get_web_scenarios.py](docs/Agent_Checks.md)** - Web scenario monitoring for HTTP/HTTPS endpoints using Zabbix Agents for polling, offers a clear web application availabilty monitoring and alerting facility (cleaner than web-scenarios)
- **get_php_fpm.py** - PHP-FPM monitoring for process manager performance and health.
- **get_alien_vault_otx.py** - AlienVault OTX (Open Threat Exchange) integration for threat intelligence monitoring.

Each script is documented individually, providing installation instructions, usage examples, and integration details.

### Available Templates

- **[Agent Ping Check](docs/Agent_Checks.md)**  
  ICMP reachability and latency monitoring via PowerShell executed by Zabbix Agent. Uses host macros for destination and thresholds.

- **[Agent Web Check](docs/Agent_Checks.md)**  
  HTTP(S) endpoint monitoring via PowerShell executed by Zabbix Agent. Supports status, latency, and content validation. Highly configurable with macros.

- **[AlienVault OTX](docs/AlienVault_OTX.md)**  
  Monitors AlienVault OTX pulses and indicators via external script. Includes IOC discovery and severity thresholding.

- **[APC Netbotz](docs/APC_Netbotz.md)**  
  Comprehensive SNMP-based monitoring for APC NetBotz environmental devices. Supports multiple device families, sensor discovery, and value mapping.

- **[Aruba Wireless](docs/Aruba_Wireless.md)**  
  Unified SNMP template for Aruba Access Points (APs) and Virtual Controllers (VCs). Automatically detects device role (AP, IAP, or VC), dynamically discovers SSIDs, clients, interfaces, and radios. Monitors client counts, traffic, signal quality, system health, and controller metrics. Includes advanced LLD, SNMP walk items for diagnostics, trap support, and macro-driven configuration. See [Aruba_Wireless.md](docs/Aruba_Wireless.md) for full documentation.

- **[Carel pCOWeb](docs/Carel_pCOWeb.md)**  
  SNMP monitoring for Carel pCOWeb environmental controllers. Includes alarm and sensor discovery, value mapping, and technical documentation links.

- **[Dell Unity Array](docs/Dell_Unity_Array.md)**  
  Monitors EMC Unity XT series storage arrays using REST API. Includes discovery, error triggers, and macro configuration.

- **[Eaton UPS](docs/Eaton_UPS.md)**  
  Complete SNMP template for Eaton UPS systems. Dynamic discovery of power, battery, load, and environment metrics using XUPS-MIB.

- **[PHP-FPM](docs/PHP-FPM.md)**  
  Monitors PHP-FPM process manager performance and health metrics.

- **[Sonicwall Firewall](docs/Sonicwall_Firewall.md)**  
  SNMP-based monitoring for Sonicwall firewalls. Includes MIB-based discovery, custom items, triggers, and dashboards.

- **[STUN/TURN Check](docs/STUN-TURN-Checks.md)**  
  Monitors STUN/TURN servers with auto-discovery. Supports RFC 5389/5766, UDP/TCP/TLS, and authentication.

- **[TCP Port Scanner](docs/TCP-Port-Scan.md)**  
  Multithreaded TCP scanner for service discovery and exposure audits. Designed for Zabbix LLD and CLI use.

- **[TLS Compliance Checker](docs/TLS-Compliance-Checker.md)**  
  Tests TLS handshake capabilities and offers a compliance dashboard for hosts.

- **[Ubiquiti Firewall](docs/Ubiquiti_Firewall.md)**  
  SNMP monitoring for Ubiquiti UCG/USG devices. Includes MIB-based discovery, custom graphs, triggers, and dashboards.

- **[Watchguard Firebox](docs/Watchguard_Firebox.md)**  
  Expanded template for Watchguard Firebox. Provides 500+ metrics, full LLD, item triggers, graphs, and dashboards.

- **[Web Scenarios Triggers](docs/Web_Scenarios_Triggers.md)**  
  Template for advanced web scenario monitoring and trigger management.


## Prerequsites
Your zabbix-proxy docker containers will need pyhon installed, to be able to use any of these plugins.

1. Download the build `Dockerfile` in this repo [here](./dockerfile/zabbix_proxy_mysql_alpine_python3), save this adjacent to your docker-compose.yaml file.

2. Update your docker-compose.yml file.
From:
```yaml
services:

  zabbix-proxy:
    image: zabbix/zabbix-proxy-mysql:alpine-7.0-latest
    container_name: zabbix-proxy
    restart: unless-stopped
    env_file:
      .env
```

To:
```yaml
services:

  zabbix-proxy:
    #image: zabbix/zabbix-proxy-mysql:alpine-7.0-latest
    build:
      context: .
      dockerfile: zabbix_proxy_mysql_alpine_python3
    container_name: zabbix-proxy
    restart: unless-stopped
    env_file:
      .env
```
    
2. Rebuild your containers:
```bash
docker compose down && docker compose up -d --force-recreate --build
```
Output looks like this:
```bash
[+] Running 3/3
 ✔ Container zabbix-proxy       Removed                                                            2.5s 
 ✔ Container zabbix-mysql       Removed                                                            2.2s 
 ✔ Network prod_zabbix-network  Removed                                                            0.3s 
[+] Building 8.1s (10/10) FINISHED                                                       docker:default
 => [zabbix-proxy internal] load build definition from dockerfile                                  0.0s
 => => transferring dockerfile: 476B                                                               0.0s
 => [zabbix-proxy internal] load metadata for docker.io/zabbix/zabbix-proxy-mysql:alpine-7.0-late  0.0s
 => [zabbix-proxy internal] load .dockerignore                                                     0.0s
 => => transferring context: 2B                                                                    0.0s
 => CACHED [zabbix-proxy 1/5] FROM docker.io/zabbix/zabbix-proxy-mysql:alpine-7.0-latest           0.0s
 => [zabbix-proxy 2/5] RUN apk add --no-cache python3 py3-pip                                      2.5s
 => [zabbix-proxy 3/5] RUN pip3 install requests --break-system-packages                           2.8s 
 => [zabbix-proxy 4/5] RUN pip3 install py-zabbix --break-system-packages                          1.1s 
 => [zabbix-proxy 5/5] RUN python3 --version && pip3 --version && python3 -m pip show requests     1.0s 
 => [zabbix-proxy] exporting to image                                                              0.5s 
 => => exporting layers                                                                            0.5s 
 => => writing image sha256:fbdf1a3a0bb4b166e60f9d56f7f12237a677eb0ac2a0eaef72bb4c9548d772a1       0.0s 
 => => naming to docker.io/library/prod-zabbix-proxy                                               0.0s 
 => [zabbix-proxy] resolving provenance for metadata file                                          0.0s
[+] Running 4/4
 ✔ zabbix-proxy                 Built                                                              0.0s 
 ✔ Network prod_zabbix-network  Created                                                            0.1s 
 ✔ Container zabbix-mysql       Started                                                            0.4s 
 ✔ Container zabbix-proxy       Started                                                            0.6s 
```

## Installation
For usage details of each script, refer to the individual README files linked above; generic installation, means cloning the .py script into the externalscripts folder on your proxy. Then importing the template XML file into the Zabbix Condole > Data Collection > Templates > Import.

## Notes
- Scripts are designed to integrate with **Zabbix Proxy** and **Zabbix Server**.
- Each script follows best practices for **error handling**, **logging**, and **parameterisation**.
- Contributions and improvements are welcome.

## License
This project is licensed under the **Apache License 2.0**.  
See the [License.md](LICENSE.md) for details.