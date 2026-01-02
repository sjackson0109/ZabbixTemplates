
# Zabbix Agent Checks: PowerShell Ping & Web Monitoring

## Overview
This project provides advanced monitoring for Zabbix using PowerShell scripts and Zabbix Agent 2. It includes:
- **Ping Checks**: ICMP reachability and latency monitoring.
- **Web Checks**: HTTP/HTTPS endpoint monitoring with status, latency, and content validation.

## Project Evolution
- Initial scripts provided basic checks and single-value outputs.
- Refactored for robust parameter handling, error management, and JSON output.
- All Zabbix UserParameter keys and YAML template item keys now use the `custom.` prefix for consistency.
- YAML templates updated for LLD, macros, triggers, and tag inheritance.
- Now supports both Zabbix Agent 2 and legacy Zabbix Agent (with minor adjustments).

## Compatibility
- **Zabbix Agent 2**: Fully supported. Uses UserParameter for direct PowerShell execution.
- **Zabbix Agent (legacy)**: Supported for basic checks, but advanced features (JSON output, LLD) require Agent 2.

## Installation Instructions

### 1. Install Zabbix Agent 2
- Download Zabbix Agent 2 from [Zabbix Downloads](https://www.zabbix.com/download_agents).
- Run installer and follow prompts.
- Ensure service is running (`zabbix_agent2.exe`).

### 2. Deploy PowerShell Scripts
- Copy all `.ps1` scripts from this repository to:
  `C:\Program Files\Zabbix Agent 2\Scripts`
- Ensure the Zabbix service user has read/execute permissions.

### 3. Configure Zabbix Agent 2
- Edit `zabbix_agentd.conf` (or `zabbix_agent2.conf`) and add:

```bash
# Ping reachability (1 = success, 0 = fail)
UserParameter=custom.ping[*],powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\Zabbix Agent 2\Scripts\agent_ping_check_bool.ps1" -Ip "$1" -Count "$2" -Timeout "$3" -BufferSize "$4" -TimeToLive "$5" -DontFragment "$6"

# Ping latency in milliseconds
UserParameter=custom.ping.latency[*],powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\Zabbix Agent 2\Scripts\agent_ping_check.ps1" -Ip "$1" -Count "$2" -Timeout "$3" -BufferSize "$4" -TimeToLive "$5" -DontFragment "$6"

# Web availability (1/0)
UserParameter=custom.web.available[*],powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& { $r = & 'C:\Program Files\Zabbix Agent 2\Scripts\agent_web_check.ps1' -Url '$1' -Timeout '$2' -ExpectCode '$3'; ($r | ConvertFrom-Json).available }"

# Web latency in milliseconds
UserParameter=custom.web.latency[*],powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& { $r = & 'C:\Program Files\Zabbix Agent 2\Scripts\agent_web_check.ps1' -Url '$1' -Timeout '$2' -ExpectCode '$3'; ($r | ConvertFrom-Json).time_ms }"

# Web HTTP status code
UserParameter=custom.web.code[*],powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& { $r = & 'C:\Program Files\Zabbix Agent 2\Scripts\agent_web_check.ps1' -Url '$1' -Timeout '$2' -ExpectCode '$3'; ($r | ConvertFrom-Json).status }"

# Web content match (1/0)
UserParameter=custom.web.content[*],powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& { $r = & 'C:\Program Files\Zabbix Agent 2\Scripts\agent_web_check.ps1' -Url '$1' -Timeout '$2' -ExpectCode '$3' -ExpectContent '$4'; ($r | ConvertFrom-Json).content_match }"
```

- Restart Zabbix Agent 2 service after changes.

### 4. Import YAML Templates
- Import `agent_ping_check.yaml` and `agent_web_check.yaml` into Zabbix via the web UI.
- Assign the relevant template to your chosen hosts with the Zabbix Agent 2 installed on.

### 5. Testing
- Use the Zabbix Frontend (or Proxy if you are using them) and execute `zabbix_get` to verify the agent can process your commands:
  ```
  zabbix_get -s <HOST> -k "custom.ping[8.8.8.8,4,1000,32,64,0]"
  zabbix_get -s <HOST> -k "custom.ping.latency[8.8.8.8,4,1000,32,64,0]"
  zabbix_get -s <HOST> -k "custom.web.available[https://example.com,5000,200]"
  zabbix_get -s <HOST> -k "custom.web.latency[https://example.com,5000,200]"
  ```
- Validate item values, triggers, and macro control in Zabbix UI.

## Notes
- For legacy Zabbix Agent, use only the basic ping and web checks (no JSON parsing).
- Advanced features (LLD, content match, tags) require Zabbix Agent 2 and updated templates.


## Python Web Scenario Script: get_web_scenarios.py

### Overview

`get_web_scenarios.py` is a Python script designed for monitoring HTTP/HTTPS endpoints and web application functionality. It is intended for integration with Zabbix as an external script, enabling automated checks of web services, APIs, and application health.

### Features
- Supports HTTP and HTTPS endpoints
- Customisable request methods (GET, POST, etc.)
- Configurable headers, timeouts, and payloads
- Response code and content validation
- Designed for Zabbix external script integration
- Suitable for both simple uptime checks and advanced web scenario monitoring

### Usage

#### Command Line
You can run the script directly for ad-hoc checks:

```bash
python get_web_scenarios.py --url https://example.com --method GET --timeout 5
```

**Options:**
- `--url <URL>`: Target URL to check (required)
- `--method <METHOD>`: HTTP method (default: GET)
- `--timeout <SECONDS>`: Request timeout (default: 5)
- `--header <HEADER>`: Custom header(s), can be specified multiple times
- `--data <DATA>`: Payload for POST/PUT requests
- `--expect-code <CODE>`: Expected HTTP status code (default: 200)
- `--expect-content <STRING>`: String that must appear in the response body

#### Zabbix Integration
1. Copy `get_web_scenarios.py` to your Zabbix `externalscripts` directory.
2. Make it executable:
  ```bash
  chmod +x /usr/lib/zabbix/externalscripts/get_web_scenarios.py
  ```
3. Create an item in your Zabbix template or host:
  - Type: External check
  - Key: `get_web_scenarios.py[--url,<URL>,--method,<METHOD>,--timeout,<SECONDS>]`
  - Adjust parameters as needed for your scenario.

### Example
Check if a website is up and returns HTTP 200:
```bash
python get_web_scenarios.py --url https://example.com --expect-code 200
```

Check for a specific string in the response:
```bash
python get_web_scenarios.py --url https://example.com --expect-content "Welcome"
```

### Output
- Returns `1` if the check passes (expected code/content found)
- Returns `0` if the check fails (unexpected code/content, timeout, or error)
- Prints diagnostic output to stdout/stderr for troubleshooting

### Requirements
- Python 3.6+
- `requests` library (install with `pip install requests`)

### Troubleshooting
- Ensure the script is executable and accessible by the Zabbix user
- Check Zabbix server/proxy logs for script execution errors
- Use the script in CLI mode for debugging before Zabbix integration
