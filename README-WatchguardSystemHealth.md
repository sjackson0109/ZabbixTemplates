## Overview
This script logs into a **WatchGuard Firewall**, retrieves **system health metrics**, and calculates a **health score** for monitoring in **Zabbix**; as well as the original work by Ticau Tudor on the Watchguard M400 template; updated by me for a more generic, and more automated discovery process.

##### NOTICE: STILL UNDER DEVELOPMENT


### Features:
- **Authenticates via WatchGuard API** (JSON-RPC).
- **Fetches system health metrics** (CPU, Memory, Active Connections).
- **Computes a health score (0-100)**.
- **Designed to be called by Zabbix Proxy** as an **external script**.
- **Returns a single numeric value** for Zabbix processing.

## Requirements
- Python 3.x
- `requests` library  
  Install via:
  ```bash
  pip install requests
  ```

## Installation
1. **Copy the script to Zabbix Proxy's external scripts directory:**
   ```bash
   sudo cp get_firebox_health.py /usr/lib/zabbix/externalscripts/
   ```
2. **Make it executable:**
   ```bash
   sudo chmod +x /usr/lib/zabbix/externalscripts/get_firebox_health.py
   ```
3. **Ensure Zabbix Proxy can execute external scripts:**
   ```bash
   sudo systemctl restart zabbix-proxy
   ```

## Usage
Run manually:
```bash
./get_firebox_health.py "https://firewall-ip/api" "admin" "password"
```
**Example Output:**
```
85  # Healthy
60  # Moderate issues
30  # Critical state
0   # API failure or authentication issue
```

## Zabbix Integration
### Step 1: Create an Item in Zabbix
- **Type:** External Check  
- **Key:**  
  ```
  get_firebox_health.py["https://firewall-ip/api", "admin", "password"]
  ```
- **Update Interval:** 60s (adjust as needed)  
- **Type of Information:** Numeric (Unsigned)  
- **Units:** `%`

### Step 2: Create a Zabbix Trigger
Example trigger:
```
{host:get_firebox_health.py.last()}<50
```
**Actions:**
- Alert if the health score **falls below 50**.
- Can be linked to email/SMS notifications.

## Health Score Calculation
| Metric             | Impact on Health Score |
|--------------------|----------------------|
| CPU Usage (%)     | -0.5 per %            |
| Memory Usage (%)  | -0.3 per %            |
| Active Connections | -0.01 per connection |

**Example Calculation:**
- **CPU Usage = 40%**
- **Memory Usage = 50%**
- **Active Connections = 5000**
- **Health Score =**  
  `100 - (40 * 0.5) - (50 * 0.3) - (5000 * 0.01) = 100 - 20 - 15 - 50 = 15`

## Troubleshooting
1. **API Not Responding**
   - Ensure the WatchGuard API is enabled.
   - Verify `https://firewall-ip/api` is reachable.

2. **Script Returns `0`**
   - Incorrect credentials.
   - API is unreachable or down.

3. **Zabbix Item Shows `Not Supported`**
   - Ensure the script is **executable** (`chmod +x`).
   - Check Zabbix Proxy logs for errors.

## Notes
- Designed for **WatchGuard Firewalls** with API support.
- Can be modified for additional metrics.

## License
This project is licensed under the **Apache License 2.0**.  
See the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) for details.