# SIP OPTIONS Check Script

### Author: Simon Jackson / sjackson0109  
### Created: 2025/02/17
### Updated: 2025/02/21

## Overview
**get_sip_options.py** is a Python script designed to send SIP OPTIONS requests to a specified SIP server and verify its response. The script is fully compliant with RFC 3261 and supports both IPv4 and IPv6 communication.

It includes automatic SRV record discovery, enabling seamless resolution of SIP endpoints. The script also supports UDP, TCP, and TLS, with advanced features like explicit TLS version selection and custom cipher suites.

## Features
✅ Supports SIP OPTIONS requests over UDP, TCP, and TLS
✅ IPv4 & IPv6 compatibility
✅ SRV Record Discovery (`_sip._tcp`, `_sip._udp`, `_sips._tcp`, `_sipfederationtls._tcp`)
✅ Validates SIP response codes and categorises them
✅ Handles DNS SRV response, using compression for more accurate SRV name lookups
✅ Verbose mode for advanced debugging
✅ Nagios-compatible exit codes for monitoring integrations
✅ Secure TLS handshake support
✅ Explicit TLS version and custom cipher suite selection

## Installation
This script runs **natively in Python 3** with no additional dependencies.

### Prerequisites
Ensure you have Python 3 installed:
```sh
python3 --version
```
Note: Tested with `Python 3.12.9` but will likely work with all minor versions.

### Download the Script
```sh
git clone https://github.com/sjackson0109/ZabbixTemplates.git
cd ZabbixTemplates/externalscripts
```

Alternatively, download `get_sip_options.py` directly and place it in a directory of your choice.

## Usage
### Basic Usage
To check a SIP server using default parameters:
```sh
python3 get_sip_options.py <SIP_SERVER>
```
Example:
```sh
python3 get_sip_options.py sip.example.com
```

### Command-Line Arguments  
| Argument        | Default  | Description |
|----------------|---------|-------------|
| `sip_server`   |         | SIP server IP/hostname |
| `-d`, `--discover` | `False` | [Optional] Discover SIP SRV records (`_sip._udp`, `_sip._tcp`, `_sips._tcp`, `_sipfederationtls._tcp`) |
| `-k`, `--protocol` | `udp` | [Optional] Transport protocol (`udp`, `tcp`, or `tls`) |
| `-p`, `--port` | `5060`  | [Optional] SIP server port (default: 5060) |
| `-u`, `--user-agent` | `"get_sip_options.py"` | [Optional] User-Agent string |
| `-s`, `--source` | `auto-detect` | [Optional] Source IP/FQDN |
| `-t`, `--timeout` | `100` | [Optional] SIP Server Timeout (seconds) |
| `-w`, `--warn` | `5` | [Optional] Warning threshold for response time (seconds) |
| `-v`, `--verbose` | `False` | [Optional] Enable verbose debugging |
| `-m`, `--max-forwards` | `70` | [Optional] Max-Forwards header value |
| `--tls-version` | `TLSv1.2` | [Optional] Explicit TLS version selection |
| `--cipher-suite` | A pre-configured secure set of ciphers | [Optional] Custom TLS Cipher Suite |


### Example Commands
#### 1️⃣ Check a SIP Server Over UDP
```sh
python3 get_sip_options.py sip.example.com -k udp
```

#### 2️⃣ Use SRV Record Discovery
This mechanism supports `_sip._udp`, `_sip._tcp`, `_sips._tcp` and `_sipfederationtls._tcp` SRV record discovery.
```sh
python3 get_sip_options.py example.com -d -v
```
Example:
```sh
python3 get_sip_options.py pexip.com -d -v
🔎 [INFO] Found _sip._tcp.pexip.com: ygg1.vp.vc:5060 (Priority: 10, Weight: 100)
🔎 [INFO] Found _sip._tcp.pexip.com: ygg2.vp.vc:5060 (Priority: 50, Weight: 100)
🔎 [INFO] Found _sips._tcp.pexip.com: ygg1.vp.vc:5060 (Priority: 10, Weight: 100)
🔎 [INFO] Found _sips._tcp.pexip.com: ygg2.vp.vc:5060 (Priority: 50, Weight: 100)
🔎 [INFO] Found _sips._tcp.pexip.com: ygg2.vp.vc:5061 (Priority: 50, Weight: 100)
🔎 [INFO] Found _sips._tcp.pexip.com: ygg1.vp.vc:5061 (Priority: 10, Weight: 100)
🔎 [INFO] Found _sipfederationtls._tcp.pexip.com: ygg1.vp.vc:5060 (Priority: 10, Weight: 100)
🔎 [INFO] Found _sipfederationtls._tcp.pexip.com: ygg2.vp.vc:5060 (Priority: 50, Weight: 100)
🔎 [INFO] Found _sipfederationtls._tcp.pexip.com: ygg2.vp.vc:5061 (Priority: 50, Weight: 100)
🔎 [INFO] Found _sipfederationtls._tcp.pexip.com: ygg1.vp.vc:5061 (Priority: 10, Weight: 100)
🔎 [INFO] Found _sipfederationtls._tcp.pexip.com: sipfed.online.lync.com:5061 (Priority: 100, Weight: 1)
🌎 [INFO] Resolved IPv4 Address: 185.94.240.215
🔎 [INFO] Discovered SIP SRV Record (_sipfederationtls._tcp.pexip.com): 185.94.240.215:5060

📤 [INFO] Sending SIP OPTIONS Request (TCP):
------->
OPTIONS sip:185.94.240.215 SIP/2.0
Via: SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-281309
From: <sip:sjackson0109@185.94.240.215>
To: <sip:185.94.240.215>
Call-ID: d1ed4cc0-80fc-4144-95fe-6bc90a67f821
CSeq: 1 OPTIONS
Contact: <sip:sjackson0109@127.0.0.1>
Max-Forwards: 70
User-Agent: get_sip_options.py
Content-Length: 0

🚀 [INFO] Connecting to 185.94.240.215:5060 via TCP...
✅ [INFO] TCP connection established to 185.94.240.215:5060
📥 [INFO] Received SIP Response in 0.013s:
<-------
SIP/2.0 200 OK
Via: SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-281309;received=51.6.187.203;rport=54946
Call-ID: d1ed4cc0-80fc-4144-95fe-6bc90a67f821
CSeq: 1 OPTIONS
From: <sip:sjackson0109@185.94.240.215>
To: <sip:185.94.240.215>;tag=115153eccd3549bc
Content-Length: 0

SIP OK: 200 Success (response time: 0.013s)
```

#### 3️⃣ Check a SIP Server with a Custom Timeout
```sh
python3 get_sip_options.py sip.example.com -t 10
```

#### 4️⃣ Use an IPv6 SIP Server
```sh
python3 get_sip_options.py [2001:db8::1] -p 5061 -k tcp
```

#### 5️⃣ Perform a TLS Handshake & SIP Check
```sh
python3 get_sip_options.py sip.example.com -p 5061 -k tls -v
```

#### 6️⃣ Perform a TLS SIP Check with Explicit TLS Version and Cipher Suite
```sh
python3 get_sip_options.py sip.example.com -p 5061 -k tls --tls-version TLSv1.3 --cipher-suite ECDHE-RSA-AES128-GCM-SHA256 -v
```

## Exit Codes
This script uses **standardised monitoring solution exit codes**, making it ideal for **Zabbix/Nagios integrations**.

| Exit Code | Status    | Description |
|-----------|----------|-------------|
| `0`       | OK       | SIP server responded successfully (200 OK) |
| `1`       | WARNING  | Response time exceeded the threshold |
| `2`       | CRITICAL | SIP server returned an error or did not respond |
| `3`       | UNKNOWN  | Invalid hostname or other unexpected failure |

## Debugging and Verbose Output
For detailed debugging, use `-v`:
```sh
python3 get_sip_options.py sip.example.com -v
```

Example verbose output:
```
📤 [INFO] Sending SIP OPTIONS Request (TCP):
------->
OPTIONS sip:sip.example.com SIP/2.0
Via: SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-12345
From: <sip:monitor@sip.example.com>
To: <sip:sip.example.com>
Call-ID: abc123@example.com
CSeq: 1 OPTIONS
Max-Forwards: 70
User-Agent: get_sip_options.py
Content-Length: 0

📥 [INFO] Received SIP Response:
<-------
SIP/2.0 200 OK
Via: SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-12345
Call-ID: abc123@example.com
CSeq: 1 OPTIONS
User-Agent: Asterisk PBX
Content-Length: 0

SIP OK: 200 Success (response time: 0.045s)
```

## Supported SIP Response Codes
The script classifies SIP responses into categories:
- **1xx - Informational**
- **2xx - Success**
- **3xx - Redirection (Warning)**
- **4xx - Client Error (Critical)**
- **5xx - Server Error (Critical)**
- **6xx - Global Failure (Critical)**

## License
This project is licensed under the **Apache License 2.0**.  
See the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) for details.


