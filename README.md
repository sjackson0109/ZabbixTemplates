## Overview

### Template Validation

Before importing any template into Zabbix, it's highly recommended to validate it using our comprehensive validation tool. These scripts catch ~95% of common errors before import, returning more helpful error messages, and significantly saves on debugging time.

**Quick Start**:
```bash
# Install dependencies (PyYAML is required)
pip install -r requirements.txt

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

### Template Database Performance Optimisation

To ensure optimal Zabbix database performance, use our comprehensive optimisation analysis tool. This script identifies storage reduction opportunities and performance improvements across all templates.

**Quick Start**:
```bash
# Analyse all templates for optimisation opportunities
python scripts/analyse_template_optimisation.py
```

**📊 Key Benefits**:
- **65-85% database storage reduction** through optimised retention policies
- **70-90% fewer database writes** via improved collection frequencies
- **3-5x faster dashboard performance** through query optimisation
- **40-60% CPU load reduction** on Zabbix servers
- Detailed optimisation recommendations for each template
- Implementation strategy with phased approach
- Risk assessment and testing guidelines
- Expected benefits and monitoring validation

The validator checks:
- ✅ YAML syntax and Zabbix schema compliance
- ✅ UUID format and uniqueness validation (UUIDv4)
- ✅ Item key syntax and format validation
- ✅ Time unit formats (1m, 5h, 30s)
- ✅ SNMP OID formats and configuration validation
- ✅ Enum values (item types, trigger priorities)
- ✅ Trigger expression parsing and function validation
- ✅ Item reference integrity and dependency validation
- ✅ Multi-line string validation
- ✅ Required field validation (vendor info, UUIDs)
- ✅ LLD macro validation in prototypes
- ✅ String vs numeric constant validation (Zabbix 7.0)
- ✅ Discovery rule filter operator validation
- ✅ Template structural integrity checks

## Structure
All custom monitoring scripts reside under this repository. Below are the available scripts with their respective documentation:

### Available Scripts

| Script | Documentation | Description |
|--------|---------------|-------------|
| **get_alien_vault_otx.py** | [AlienVault_OTX.md](docs/AlienVault_OTX.md) | AlienVault OTX (Open Threat Exchange) integration for threat intelligence monitoring. Provides IOC discovery, severity tracking, and robust error handling. |
| **get_domain_health.py** | [Domain_Health.md](docs/Domain_Health.md) | Domain health and compliance monitoring. Performs DNS record checks, DNSSEC/DANE validation, email authentication (SPF/DKIM/DMARC), WHOIS/RDAP data retrieval, ASN lookup, and NS server monitoring. Full RFC compliance checking. |
| **get_email_health.py** | [Email_Health.md](docs/Email_Health.md) | Comprehensive email infrastructure monitoring and RFC compliance validation. Supports SPF/DKIM/DMARC authentication, MTA-STS/TLS-RPT security protocols, MX connectivity testing, SMTP protocol validation, blacklist monitoring, and deliverability assessment. Covers 14+ email RFCs with detailed health scoring. |
| **get_php_fpm.py** | [PHP_FPM.md](docs/PHP_FPM.md) | PHP-FPM monitoring for process manager performance and health. |
| **get_sip_health.py** | [SIP_Health.md](docs/SIP_Health.md) | Comprehensive SIP and VoIP infrastructure compliance monitoring and RFC validation. Integrates STUN/TURN testing, TCP port scanning, TLS compliance, RTP/RTCP validation, codec support analysis, NAT traversal testing, and quality assessment. Covers 13+ VoIP/SIP RFCs with comprehensive scoring and service discovery. |
| **get_tcp_port_scan.py** | [TCP-Port-Scan.md](docs/TCP-Port-Scan.md) | Multithreaded TCP scanner for service discovery and exposure audits. Designed for Zabbix LLD and interactive CLI use. |
| **template_optimisation_analysis.py** | [template_optimisation_analysis.md](docs/template_optimisation_analysis.md) | Database performance optimisation analyser. Identifies storage reduction opportunities, collection frequency improvements, and retention policy optimisations. Delivers 65-85% database storage reduction potential. |
| **get_tls_health.py** | [TLS_Health.md](docs/TLS_Health.md) | Tests TLS Health; as capabilities of a host and compliance towards RFC standards. Detects available SSL/TLS protocols and ciphers, and provides a compatibility report. |
| **get_unity_array.py** | [Unity_Array.md](docs/Unity_Array.md) | Dell EMC Unity storage array monitoring and auto-discovery via REST API. Collects inventory, health, capacity, and status metrics for LUNs, pools, disks, ports, and more. |
| **get_web_scenarios.py** | [Web_Scenarios.md](docs/Web_Scenarios.md) | Web scenario monitoring for HTTP/HTTPS endpoints using Zabbix Agents for polling, offers a clear web application availability monitoring and alerting facility (cleaner than web-scenarios). |
| **snmp_client.py** | [SNMP-Client.md](docs/SNMP-Client.md) | Comprehensive SNMPv1/v2c/v3 client with authentication and privacy support. RFC 3414 compliant, supports MD5/SHA authentication and DES/AES encryption. Integrates with Zabbix external scripts for discovery, check, and detailed check modes. |
| **validate_zabbix_template.py** | [Validate_Template.md](docs/Validate_Template.md) | Comprehensive Zabbix template validation tool. Validates YAML syntax, schema compliance, UUID formats, item keys, trigger expressions, and cross-references. Catches 95% of import errors before deployment. |

Each script is documented individually, providing installation instructions, usage examples, and integration details.

### Available Templates

| Template | Documentation | Description |
|----------|---------------|-------------|
| **Agent Ping Check** | [Agent_PowerShell_Scripts.md](docs/Agent_PowerShell_Scripts.md) | ICMP reachability and latency monitoring via PowerShell executed by Zabbix Agent. Uses host macros for destination and thresholds. |
| **Agent Web Check** | [Agent_PowerShell_Scripts.md](docs/Agent_PowerShell_Scripts.md) | HTTP(S) endpoint monitoring via PowerShell executed by Zabbix Agent. Supports status, latency, and content validation. Highly configurable with macros. |
| **AlienVault OTX** | [AlienVault_OTX.md](docs/AlienVault_OTX.md) | Monitors AlienVault OTX pulses and indicators via the external script. Features automated IOC discovery, severity/confidence tracking, pulse count, robust error handling, macro/env flexibility, and performance optimisation. |
| **APC NetBotz** | [APC_NetBotz.md](docs/APC_NetBotz.md) | Comprehensive SNMP-based monitoring for APC NetBotz environmental devices. Supports multiple device families, sensor discovery, and value mapping. |
| **Aruba Wireless** | [Aruba_Wireless.md](docs/Aruba_Wireless.md) | Unified SNMP template for Aruba Access Points (APs) and Virtual Controllers (VCs). Automatically detects device role (AP, IAP, or VC), dynamically discovers SSIDs, clients, interfaces, and radios. Monitors client counts, traffic, signal quality, system health, and controller metrics. Includes advanced LLD, SNMP walk items for diagnostics, trap support, and macro-driven configuration. |
| **Carel pCOWeb** | [Carel_pCOWeb.md](docs/Carel_pCOWeb.md) | SNMP monitoring for Carel pCOWeb environmental controllers. Includes alarm and sensor discovery, value mapping, and technical documentation links. |
| **Dell Unity Array** | [Dell_Unity_Array.md](docs/Dell_Unity_Array.md) | Monitors EMC Unity XT series storage arrays using REST API. Includes discovery, error triggers, and macro configuration. |
| **Domain Health** | [Domain_Health.md](docs/Domain_Health.md) | Comprehensive domain health and compliance monitoring. Checks DNS records, DNSSEC, DANE/TLSA, email authentication (SPF/DKIM/DMARC), WHOIS/RDAP, ASN, NS server availability and much more. Full RFC compliance with health score dashboard. |
| **Eaton UPS** | [Eaton_UPS.md](docs/Eaton_UPS.md) | Complete SNMP template for Eaton UPS systems. Dynamic discovery of power, battery, load, and environment metrics using XUPS-MIB. |
| **Email Health** | [Email_Health.md](docs/Email_Health.md) | Comprehensive email infrastructure monitoring and RFC compliance validation. Covers SPF/DKIM/DMARC authentication, MTA-STS/TLS-RPT security, MX record analysis, SMTP testing, blacklist monitoring, and deliverability assessment. Validates compliance with 14+ email-related RFCs including 5321, 7208, 6376, 7489, 8460, 8461. Provides detailed dashboards and scoring for email health. |
| **PHP-FPM** | [PHP_FPM.md](docs/PHP_FPM.md) | Monitors PHP-FPM process manager performance and health metrics. |
| **IBM Tape Libraries** | [IBM_Tape_Libraries.md](docs/IBM_Tape_Libraries.md) | Complete SNMP monitoring for IBM, Dell, and Tandberg tape libraries. Features auto-discovery of drives, fans, power supplies, door status monitoring, transport robotics tracking, cleaning alerts, and component fault detection. |
| **SIP Health** | [SIP_Health.md](docs/SIP_Health.md) | Comprehensive SIP and VoIP infrastructure monitoring with RFC compliance validation. Integrates SIP protocol testing, STUN/TURN NAT traversal, RTP/RTCP media validation, TLS security assessment, codec support analysis, and service discovery. Validates compliance with 13+ VoIP-related RFCs including 3261, 3550, 5389, 5766. Provides comprehensive compliance scoring, performance metrics, and multi-transport monitoring. |
| **Sonicwall Firewall** | [Sonicwall_Firewall.md](docs/Sonicwall_Firewall.md) | Comprehensive SNMP-based monitoring for Sonicwall firewalls. Features complete BGP4-MIB monitoring (neighbor discovery, session states, route counts, flap detection), VPN tunnel monitoring (policy-based and route-based), interface discovery, security service statistics, and advanced dashboards. |
| **TCP Port Scanner** | [TCP-Port-Scan.md](docs/TCP-Port-Scan.md) | Multithreaded TCP scanner for service discovery and exposure audits. Designed for Zabbix LLD and CLI use. |
| **TLS Health** | [TLS_Health.md](TLS_Health.md) | Comprehensive TLS/SSL security auditing and compliance monitoring. Auto-discovers protocol-cipher combinations, performs SEV1-5 severity scoring, validates compliance against PCI DSS v4.0, NIST SP 800-52r2, CIS Controls v8, and BSI TR-02102-2. Includes risk scoring and vulnerability detection (POODLE, FREAK, BEAST, DROWN). |
| **Ubiquiti Firewall** | [Ubiquiti_Firewall.md](docs/Ubiquiti_Firewall.md) | SNMP monitoring for Ubiquiti UCG/USG devices with comprehensive BGP4-MIB support. Features BGP neighbor discovery, session state monitoring, route tracking, flap detection, interface discovery, system health monitoring, and integrated dashboards. |
| **Watchguard Firebox** | [Watchguard_Firebox.md](docs/Watchguard_Firebox.md) | Enhanced template for Watchguard Firebox with 500+ metrics. Includes complete BGP4-MIB monitoring (neighbor states, route counts, session tracking), comprehensive LLD for all components, advanced triggers, performance graphs, and executive dashboards. |
| **Web Scenarios** | [Web_Scenarios.md](docs/Web_Scenarios.md) | Advanced web scenario monitoring with priority-based discovery (P1-P5), custom trigger management, error tracking, and comprehensive alerting for HTTP/HTTPS endpoints. |


## Prerequisites
Your zabbix-proxy docker containers will need Python installed, to be able to use any of these plugins.

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
For usage details of each script, refer to the individual README files linked above; generic installation means copying the .py script into the externalscripts folder on your proxy, then importing the template YAML file into the Zabbix Console > Data Collection > Templates > Import.

## Notes
- Scripts are designed to integrate with **Zabbix Proxy** and/or **Zabbix Server**.
- Each script follows best practices for **error handling**, **logging**, and **parameterisation**.
- Contributions and improvements are welcome.

## Licence
This project is licensed under the **Apache Licence 2.0**.  
See the [LICENSE.md](LICENSE.md) for details.

[def]: docs/TLS_Health.md