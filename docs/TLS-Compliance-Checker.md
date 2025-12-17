# TLS Compliance Checker Zabbix Template Documentation

## Overview
The **TLS Compliance Checker** Zabbix template provides automated monitoring and compliance validation for SSL/TLS endpoints. It is designed to help organizations ensure that their public and internal services adhere to security best practices, regulatory requirements, and organizational policies regarding TLS protocol and cipher usage.

This template leverages an external script (`get_tls_handshake.py`) to perform real-time handshake tests, protocol/cipher enumeration, and compliance checks. It is suitable for monitoring web servers, mail servers, APIs, and any service supporting SSL/TLS.

## Features
- **Automated TLS Handshake Testing:**
  - Periodically tests endpoints for supported SSL/TLS protocols (SSLv2, SSLv3, TLS 1.0–1.3)
  - Enumerates available ciphers and key exchange methods
- **Compliance Validation:**
  - Checks for deprecated/insecure protocols (SSLv2, SSLv3, TLS 1.0/1.1)
  - Detects weak ciphers (RC4, 3DES, export-grade, etc.)
  - Validates certificate expiration, chain, and hostname
  - Customizable compliance policy via macros
- **Dynamic Discovery:**
  - Supports LLD for multiple endpoints per host
  - Auto-discovers new endpoints based on macros or external sources
- **Detailed Metrics:**
  - Protocols/ciphers supported, handshake success/failure, certificate validity, days to expiry
  - Compliance status (pass/fail) with reason
- **Advanced Triggers and Alerts:**
  - Non-compliant endpoint, certificate expiring soon, handshake failure, protocol downgrade detected
- **Value Mapping:**
  - Human-readable compliance and status values
- **Custom Graphs and Dashboards:**
  - Visualize compliance status, protocol/cipher support, and certificate expiry trends

## Prerequisites
- **Zabbix Server/Proxy:** Version 6.0 or later (7.0+ recommended)
- **Python 3:** Required for the `get_tls_handshake.py` script
- **External Script:** Place `get_tls_handshake.py` in the `externalscripts/` directory of your Zabbix proxy/server
- **Network Access:** Zabbix server/proxy must be able to reach monitored endpoints

## Installation
1. **Copy the Template:**
   - Download the template YAML or XML file from the `templates/` directory (`tls_compliance_checker.yaml` or `.xml`)
2. **Import into Zabbix:**
   - Go to **Zabbix Console > Data Collection > Templates > Import**
   - Select the template file and import
3. **Deploy the Script:**
   - Copy `get_tls_handshake.py` to your Zabbix proxy/server's `externalscripts/` directory
   - Ensure Python 3 and required dependencies (e.g., `requests`, `pyOpenSSL`) are installed
4. **Assign to Host:**
   - Link the template to hosts representing your endpoints
   - Configure macros for endpoint addresses and compliance policy as needed
5. **Verify Data Collection:**
   - Check Latest Data for handshake, protocol, cipher, and compliance metrics
   - Review triggers and graphs

## Configuration
### Required Macros
- `{$TLS_ENDPOINTS}`: Comma-separated list of endpoints (host:port)
- `{$TLS_MIN_VERSION}`: Minimum allowed TLS version (e.g., `TLS1_2`)
- `{$TLS_MAX_DAYS}`: Maximum days before certificate expiry triggers alert (e.g., `30`)
- `{$TLS_POLICY}`: Custom compliance policy (optional, see script docs)

### Example Host Macros
| Macro                | Example Value           |
|----------------------|------------------------|
| {$TLS_ENDPOINTS}     | example.com:443        |
| {$TLS_MIN_VERSION}   | TLS1_2                 |
| {$TLS_MAX_DAYS}      | 30                     |
| {$TLS_POLICY}        | HIGH                   |

## Monitored Metrics (Sample)
- Supported protocols (SSLv2, SSLv3, TLS1.0, TLS1.1, TLS1.2, TLS1.3)
- Supported ciphers (list)
- Handshake success/failure
- Certificate expiry date, days to expiry
- Compliance status (pass/fail)
- Reason for non-compliance

## Triggers (Sample)
- Endpoint is non-compliant (protocol/cipher/cert)
- Certificate expiring within threshold
- Handshake failure
- Deprecated protocol supported

## Value Maps
- Compliance status: Pass, Fail, Warning
- Protocol/cipher status: Secure, Deprecated, Insecure

## Troubleshooting
- **No Data Collected:**
  - Verify script is executable and in the correct directory
  - Check Python 3 and dependencies are installed
  - Ensure network connectivity to endpoints
- **False Non-Compliance:**
  - Review macro values and compliance policy
  - Check for intermediate CA or certificate chain issues
- **Script Errors:**
  - Run script manually for debug output
  - Check Zabbix server/proxy logs for errors

## References
- [Zabbix External Scripts Documentation](https://www.zabbix.com/documentation/current/en/manual/config/items/itemtypes/external)
- [SSL Labs Best Practices](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices)
- [Mozilla TLS Configuration Generator](https://ssl-config.mozilla.org/)
- [Python pyOpenSSL Documentation](https://pyopenssl.org/en/stable/)

## License
This template and documentation are provided under the **Apache License 2.0**. See the [LICENSE.md](../LICENSE.md) file for details.
