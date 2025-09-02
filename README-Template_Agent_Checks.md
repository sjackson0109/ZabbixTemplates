# Zabbix Agent Checks: PowerShell Ping & Web Monitoring

## Overview
This project provides advanced monitoring for Zabbix using PowerShell scripts and Zabbix Agent 2. It includes:
- **Agent Ping Checks**: ICMP reachability and latency monitoring.
- **Agent Web Checks**: HTTP/HTTPS endpoint monitoring with status, latency, and content validation.

## Project Evolution
- Initial scripts provided basic checks and single-value outputs.
- Refactored for robust parameter handling, error management, and JSON output.
- Added support for Zabbix Agent 2 UserParameter keys, removing legacy `system.run` reliance.
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

```
# Agent Ping Boolean (Availability)
UserParameter=agent.ping[*],powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\Zabbix Agent 2\Scripts\agent_ping_check_bool.ps1" -Ip "$1" -Count "$2" -Timeout "$3" -BufferSize "$4" -TimeToLive "$5" -DontFragment "$6"
# Agent Ping Latency
UserParameter=agent.ping.latency[*],powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\Zabbix Agent 2\Scripts\agent_ping_check.ps1" -Ip "$1" -Count "$2" -Timeout "$3" -BufferSize "$4" -TimeToLive "$5" -DontFragment "$6"
# Agent Web Checks
UserParameter=agent.web.available[*],powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\Zabbix Agent 2\Scripts\agent_web_check.ps1" -Url "$1" -Timeout "$2" -ExpectCode "$3" | ConvertFrom-Json | Select-Object -ExpandProperty available
UserParameter=agent.web.latency[*],powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\Zabbix Agent 2\Scripts\agent_web_check.ps1" -Url "$1" -Timeout "$2" -ExpectCode "$3" | ConvertFrom-Json | Select-Object -ExpandProperty time_ms
UserParameter=agent.web.code[*],powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\Zabbix Agent 2\Scripts\agent_web_check.ps1" -Url "$1" -Timeout "$2" -ExpectCode "$3" | ConvertFrom-Json | Select-Object -ExpandProperty status
UserParameter=agent.web.content[*],powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\Zabbix Agent 2\Scripts\agent_web_check.ps1" -Url "$1" -Timeout "$2" -ExpectCode "$3" -ExpectContent "$4" | ConvertFrom-Json | Select-Object -ExpandProperty content_match
```

- Restart Zabbix Agent 2 service after changes.

### 4. Import YAML Templates
- Import `agent_ping_check.yaml` and `agent_web_check.yaml` into Zabbix via the web UI.
- Assign templates to hosts.

### 5. Testing
- Use `zabbix_get` to verify:
  ```
  zabbix_get -s <HOST> -k "agent.ping[8.8.8.8,4,1000,32,64,0]"
  zabbix_get -s <HOST> -k "agent.ping.latency[8.8.8.8,4,1000,32,64,0]"
  zabbix_get -s <HOST> -k "agent.web.available[https://example.com,5000,200]"
  zabbix_get -s <HOST> -k "agent.web.latency[https://example.com,5000,200]"
  ```
- Validate item values, triggers, and macro control in Zabbix UI.

## Notes
- For legacy Zabbix Agent, use only the basic ping and web checks (no JSON parsing).
- Advanced features (LLD, content match, tags) require Zabbix Agent 2 and updated templates.

## Support
For issues or enhancements, open a GitHub issue or contact the author.
