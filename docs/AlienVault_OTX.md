# AlienVault OTX Zabbix Integration

## Overview
This integration provides automated monitoring of AlienVault OTX (Open Threat Exchange) threat intelligence data in Zabbix. It includes a Zabbix template and an external script for discovering, tracking, and alerting on IOCs (Indicators of Compromise) from OTX pulses.

---

## Features
- **Automated IOC Discovery:** Dynamically discovers IOCs (type, value, and metadata) from OTX pulses within a configurable time window.
- **Severity Tracking:** Monitors and triggers on IOC severity/confidence levels.
- **Pulse Count & Update Time:** Tracks the number of new pulses and the last update time.
- **IOC Metadata Exposure:** Each discovered IOC now includes first seen, last seen, pulse name, tags, references, and threat type for richer context and filtering in Zabbix.
- **Robust Error Handling:** All operations return Zabbix-friendly output, with clear error reporting and safe defaults.
- **Macro/Env Flexibility:** Supports macros/environment variables for API endpoint, timeout, thresholds, and debug logging.
- **Performance Optimized:** Uses a persistent SQLite cache to minimize redundant API calls and improve performance, even across script runs.

---

## Installation
1. **Copy the Script**
   - Place `get_alien_vault_otx.py` in your Zabbix `externalscripts` directory.
2. **Import the Template**
   - Import `alien_vault_otx.yaml` into Zabbix (Configuration → Templates).
3. **Configure Macros**
   - Set `{$OTX_API_KEY}` on the host or template.
   - Optionally set:
     - `{$OTX_SINCE_HOURS}` (default: 24)
     - `{$SEVERITY_THRESHOLD}` (default: 7)
     - `{$OTX_API_ENDPOINT}` (default: https://otx.alienvault.com/api/v1)
     - `{$OTX_TIMEOUT}` (default: 30)
     - `{$OTX_MIN_SEVERITY}` (default: 1)
     - `{$OTX_CACHE_DB}` (default: otx_indicator_cache.sqlite3)
     - `{$OTX_CACHE_MAX}` (default: 10000)
     - `{$OTX_CACHE_TTL}` (default: 2592000, 30 days)
   - For advanced use, set environment variables to override macros.
4. **Assign Template**
   - Link the template to any host (no SNMP required).

---


## Intended Use Case

This Zabbix template is designed to be applied to a single dedicated host (e.g., named `AlienVaultOTX`) in your Zabbix environment. The host acts as a logical integration point for AlienVault OTX threat intelligence, not as a physical or network device. All OTX data is retrieved via the API using your own OTX account and API key.

**Typical workflow:**
- Register for a free account at [https://otx.alienvault.com](https://otx.alienvault.com).
- After logging in, visit [https://otx.alienvault.com/api](https://otx.alienvault.com/api) to view your personal API key (it is visible at the top of the page).
- Create a new host in Zabbix (e.g., `AlienVaultOTX`) and link this template to it.
- Set the `{$OTX_API_KEY}` macro on the host to your OTX API key.
- The template will then automatically retrieve, monitor, and visualize threat intelligence from OTX, including IOCs, pulse activity, and risk trends.

**Note:**
- Your OTX API key is personal and should be kept secure. It is required for all API requests and is visible only to you on the OTX API page.
- This template is not intended for use on multiple hosts or for monitoring network devices directly. It is a logical integration for threat intelligence enrichment and situational awareness.

---
## Host Dashboards

The AlienVault OTX template includes a comprehensive Zabbix host dashboard to help IT administrators visualize and respond to real-world threat intelligence. The dashboard is automatically available on any host linked to the template and provides the following pages:

### Threat Intelligence (Overview)
- Table of top threats, risk level gauge, threats over time, threat type breakdown, and active threat triggers.

### Threat Timeline
- Visualizes when threats were first and last seen, helping track the lifecycle of IOCs.

### Threat Geo Map
- (If geolocation data is available) Maps the origin or affected region of threats for geographic risk awareness.

### IOC Type Distribution
- Pie chart showing the breakdown of IOC types (IP, domain, URL, hash, etc.).

### Pulse Activity
- Graph of new OTX pulses over time and a table of recent pulses with severity and tags.

### Response Actions
- Table of recommended or taken response actions for each threat (customize as needed for your workflow).

### API Health & Performance
- Single value and graph widgets for API health status and latency, helping monitor integration reliability.

### Tag/Category Heatmap
- Heatmap showing the frequency of different threat tags or categories for quick pattern recognition.

### Trigger History
- Graph of trigger activations over time, showing alerting trends and historical context.

### Custom Playbook Panel
- Text panel with links to incident response playbooks or documentation for rapid response guidance.

All dashboard widgets are filterable by host and leverage the template’s discovered items, triggers, and tags for maximum context and usability.

---
## Items & Triggers
- **Items:**
   - `otx.pulses` — Number of new OTX pulses in the last N hours
   - `otx.lastupdate` — Last update time of OTX data
   - `otx.ioc` — Details for each discovered IOC (type, value, and metadata)
   - `otx.severity` — Severity/confidence for each IOC
   - `otx.ioc.first_seen` — First seen timestamp for each IOC
   - `otx.ioc.last_seen` — Last seen timestamp for each IOC
   - `otx.ioc.pulse_name` — Pulse name for each IOC
   - `otx.ioc.tags` — Tags for each IOC
   - `otx.ioc.references` — References for each IOC
   - `otx.ioc.threat_type` — Threat type for each IOC
- **Triggers:**
  - No new OTX indicators in the last N hours
  - OTX data not updated for over 2 hours
  - High severity IOC detected (per IOC)

---

## Script Usage (Manual)
```bash
python get_alien_vault_otx.py discover <API_KEY> <HOURS> [--otx-endpoint URL] [--otx-timeout SECONDS][--otx-severity-threshold N] [--otx-min-severity N]
python get_alien_vault_otx.py ioc <TYPE> <VALUE> <API_KEY> <HOURS> [--otx-endpoint URL] [--otx-timeout SECONDS]
python get_alien_vault_otx.py severity <TYPE> <VALUE> <API_KEY> <HOURS> [--otx-severity-threshold N]
python get_alien_vault_otx.py pulses <API_KEY> <HOURS> [--otx-timeout SECONDS]
python get_alien_vault_otx.py lastupdate <API_KEY> <HOURS>
```

- All configuration can be set via macros, environment variables, or CLI arguments (CLI takes precedence).

---

## Troubleshooting
- **No Data:** Check API key, endpoint, and network connectivity. Enable debug logging with `OTX_DEBUG=1`.
- **Rate Limits:** Increase polling interval or check OTX API status.
- **Script Errors:** All errors are logged and returned as JSON or safe defaults for Zabbix.
- **Template Validation:** Use `validate_zabbix_template.py` to check YAML before import.
- **Cache File:** The script uses a persistent SQLite cache (`otx_indicator_cache.sqlite3` by default) to speed up indicator lookups and reduce API calls. If the cache file is deleted or missing, the script will simply re-fetch data from the OTX API—no data is lost, and the cache will rebuild automatically. The cache is automatically purged of entries older than 30 days and will not exceed the configured maximum size.

---

## References
- [AlienVault OTX API Documentation](https://otx.alienvault.com/api/)
- [Zabbix External Scripts](https://www.zabbix.com/documentation/current/en/manual/config/items/itemtypes/external)
- [Zabbix Low-Level Discovery](https://www.zabbix.com/documentation/current/en/manual/discovery/low_level_discovery)

---

For further help, see the script docstring or contact the author.
