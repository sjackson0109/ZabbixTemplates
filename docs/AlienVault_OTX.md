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
