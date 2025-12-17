# TLS Handshake Check Script

### Author: Simon Jackson / sjackson0109  
### Created: 2025/03/03
### Updated: 2025/03/06  

## Overview  
**get_tls_handshake.py** is a Python script designed to test TLS handshake capabilities with a specified host or IP endpoint. It dynamically detects available SSL/TLS protocols and ciphers on the client-system, tests their compatibility, and provides a detailed report of successful and failed connections.  

The script supports legacy SSL/TLS protocols (e.g., SSLv1.0, SSLv3.0, TLSv1.0, TLSv1.1) where supported by the client-system. It is ideal for verifying TLS configurations, identifying deprecated protocols, and ensuring secure communication.  

Finally the script then checks these available protocols and ciphers against the target host/port, providing a concise list of supported/unsupported configurations.

## Features  
- ✅ **Dynamic Protocol Detection**: Detects available SSL/TLS protocols (SSLv1.0 through TLSv1.3) from the system.  
- ✅ **Dynamic Cipher Detection**: Queries available ciphers from the operating system.  
- ✅ **Legacy Protocol Support**: Tests legacy SSL/TLS protocols if supported by the OS.  
- ✅ **Compatibility Filtering**: Filters out incompatible protocol-cipher pairs before testing.  
- ✅ **Endpoint Testing**: Tests each protocol-cipher pair against the specified endpoint.  
- ✅ **Optional Port Argument**: Defaults to port `443`, with optional override using `-p` or `--port`.  
- ✅ **Timeout Handling**: Configurable timeout for socket connections (default: 4 seconds).  
- ✅ **Verbose Mode**: Detailed logging with the `-v` or `--verbose` switch for troubleshooting.  
- ✅ **Clean Output**: Prints results in a table format with status indicators (✅ for success, ❌ for failure).  
- ✅ **Cross-Platform**: Works on Linux, Windows, and Docker containers.  

## Installation  
This script runs **natively in Python 3** with no additional dependencies.  

### Prerequisites  
Ensure you have Python 3 installed:  
```sh  
python3 --version  
```
Note: Tested with Python 3.12.9 but will likely work with all minor versions.

### Download the script
Ensure you download the `get_tls_handshake.py` script.
```bash
git clone https://github.com/sjackson0109/ZabbixTemplates.git  
cd ZabbixTemplates/externalscripts
```

## Usage
### 1️⃣ Supported Syntax
The command line syntax includes all these `[optional]` and `<value>` parameters
```bash
python3 get_tls_handshake.py <HOST> [-p/--port <PORT>] [-t/--timeout <TIMEOUT>] [-v/--verbose]
```

### Examples
#### 1️⃣ Test a Host with Default Port (443)
```bash
python3 get_tls_handshake.py example.com
```
#### 2️⃣ Test a Host with Custom Port
```bash
python3 get_tls_handshake.py example.com -p 8443
```
#### 3️⃣ Test a Host with Custom Timeout
```bash
python3 get_tls_handshake.py example.com -t 1
```
#### 4️⃣ Test a Host with Verbose Mode
```bash
python3 get_tls_handshake.py example.com -v
```

Note: You can combine arguments.

## Command-Line Arguments
| Argument | Default | Description |
|---|---|---|
|host | | Hostname, FQDN or IP-address (IPv4 or IPv6) to check |
|-p, --port | 443 | [Optional] TCP Port number to check against |
|-t, --timeout | 4 | [Optional] Timeout for socket connection in seconds |
|-v, --verbose | False | [Optional] Enable verbose output (includes errors). No input value necessary, just the switch. |

## Output
The script collects data in an array, sorts and prints out a user-friendly table of results. As well as a small breakdown of the testing capabilities.

Sample output :
```bash
python3 get_tls_handshake.py yahoo.co.uk -p 443 
Testing Capabilities:
 Protocols: TLSv1.0, TLSv1.1, TLSv1.2
 Ciphers: TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256
----------------------------------------

RESULTS:
STATUS   PROTOCOL   CIPHER
----------------------------------------
✅        TLSv1.2    ECDHE-ECDSA-AES128-GCM-SHA256
✅        TLSv1.2    ECDHE-ECDSA-AES128-SHA256
✅        TLSv1.2    ECDHE-ECDSA-AES256-GCM-SHA384
✅        TLSv1.2    ECDHE-ECDSA-AES256-SHA384
✅        TLSv1.2    ECDHE-ECDSA-CHACHA20-POLY1305
✅        TLSv1.2    ECDHE-RSA-AES128-GCM-SHA256
✅        TLSv1.2    ECDHE-RSA-AES128-SHA256
✅        TLSv1.2    ECDHE-RSA-AES256-GCM-SHA384
✅        TLSv1.2    ECDHE-RSA-AES256-SHA384
✅        TLSv1.2    ECDHE-RSA-CHACHA20-POLY1305
❌        TLSv1.0    DHE-RSA-AES128-GCM-SHA256
❌        TLSv1.0    DHE-RSA-AES128-SHA256
❌        TLSv1.0    DHE-RSA-AES256-GCM-SHA384
❌        TLSv1.0    DHE-RSA-AES256-SHA256
❌        TLSv1.0    ECDHE-ECDSA-AES128-GCM-SHA256
❌        TLSv1.0    ECDHE-ECDSA-AES128-SHA256
❌        TLSv1.0    ECDHE-ECDSA-AES256-GCM-SHA384
❌        TLSv1.0    ECDHE-ECDSA-AES256-SHA384
❌        TLSv1.0    ECDHE-ECDSA-CHACHA20-POLY1305
❌        TLSv1.0    ECDHE-RSA-AES128-GCM-SHA256
❌        TLSv1.0    ECDHE-RSA-AES128-SHA256
❌        TLSv1.0    ECDHE-RSA-AES256-GCM-SHA384
❌        TLSv1.0    ECDHE-RSA-AES256-SHA384
❌        TLSv1.0    ECDHE-RSA-CHACHA20-POLY1305
❌        TLSv1.1    DHE-RSA-AES128-GCM-SHA256
❌        TLSv1.1    DHE-RSA-AES128-SHA256
❌        TLSv1.1    DHE-RSA-AES256-GCM-SHA384
❌        TLSv1.1    DHE-RSA-AES256-SHA256
❌        TLSv1.1    ECDHE-ECDSA-AES128-GCM-SHA256
❌        TLSv1.1    ECDHE-ECDSA-AES128-SHA256
❌        TLSv1.1    ECDHE-ECDSA-AES256-GCM-SHA384
❌        TLSv1.1    ECDHE-ECDSA-AES256-SHA384
❌        TLSv1.1    ECDHE-ECDSA-CHACHA20-POLY1305
❌        TLSv1.1    ECDHE-RSA-AES128-GCM-SHA256
❌        TLSv1.1    ECDHE-RSA-AES128-SHA256
❌        TLSv1.1    ECDHE-RSA-AES256-GCM-SHA384
❌        TLSv1.1    ECDHE-RSA-AES256-SHA384
❌        TLSv1.1    ECDHE-RSA-CHACHA20-POLY1305
❌        TLSv1.2    DHE-RSA-AES128-GCM-SHA256
❌        TLSv1.2    DHE-RSA-AES128-SHA256
❌        TLSv1.2    DHE-RSA-AES256-GCM-SHA384
❌        TLSv1.2    DHE-RSA-AES256-SHA256
```

## Verboseging and Verbose Output
For detailed verboseging, use --verbose:
```bash
python3 get_tls_handshake.py example.com --verbose  
```

Example verbose mode output:
```bash
----------------------------------------
Protocol SSLv3.0 is available.  
Protocol TLSv1.0 is available.  
Protocol TLSv1.1 is available.  
Protocol TLSv1.2 is available.  
Created CRITERIA array with 68 protocol-cipher pairs.  
Added compatible pair: TLSv1.2 with TLS_AES_256_GCM_SHA384  
Added compatible pair: TLSv1.2 with TLS_CHACHA20_POLY1305_SHA256  
...  
Successfully connected using TLSv1.2 with TLS_AES_256_GCM_SHA384  
Connection error: TLSv1.0 with TLS_AES_256_GCM_SHA384 - [Error details]  
----------------------------------------
```

## Exit Codes  
This script uses **standardised monitoring solution exit codes**, making it ideal for **Zabbix/Nagios integrations**.  

| Exit Code | Status    | Description |  
|-----------|----------|-------------|  
| `0`       | OK       | All tests completed successfully |  
| `1`       | WARNING  | Some tests failed (e.g., deprecated protocols) |  
| `2`       | CRITICAL | No successful connections or critical errors |  
| `3`       | UNKNOWN  | Invalid hostname or other unexpected failure | 