#!/usr/bin/env python3
"""
Author: Simon Jackson (sjackson0109)
Created: 2025/07/16
Updated: 2025/12/17
Version: 2.5
Description:
   This script interacts with the AlienVault OTX API to fetch threat intelligence data.
   Supports Zabbix external script format with positional parameters.

Usage (Zabbix format):
  python get_alien_vault_otx.py discover <API_KEY> <HOURS>
  python get_alien_vault_otx.py ioc <TYPE> <VALUE> <API_KEY> <HOURS>
  python get_alien_vault_otx.py severity <TYPE> <VALUE> <API_KEY> <HOURS>
  python get_alien_vault_otx.py pulses <API_KEY> <HOURS>
  python get_alien_vault_otx.py lastupdate <API_KEY> <HOURS>
"""

import sys
import requests
import json
import logging
from datetime import datetime, timedelta, timezone

# Base URL for OTX API
OTX_BASE = 'https://otx.alienvault.com/api/v1'
# HTTP request timeout (seconds)
HTTP_TIMEOUT = 30

logger = logging.getLogger(__name__)
logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=logging.WARNING)

# Perform GET with API key, timeout, and optional params
def otx_get(endpoint, api_key, params=None):
    url = f"{OTX_BASE}{endpoint}"
    resp = requests.get(url, headers={'X-OTX-API-KEY': api_key}, params=params, timeout=HTTP_TIMEOUT)
    resp.raise_for_status()
    return resp.json()

# Parse ISO8601 timestamp to aware datetime
def parse_ts(ts):
    dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

# Fetch pulses with server-side date filter; paginate as needed
def fetch_pulses(api_key, since_dt):
    pulses = []
    params = {
        'page_size': 100,
        'date_published__gt': since_dt.isoformat()
    }
    next_url = f"{OTX_BASE}/pulses/subscribed"
    while next_url:
        resp = requests.get(next_url, headers={'X-OTX-API-KEY': api_key}, params=params, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        page = data.get('results', [])
        pulses.extend(page)
        next_url = data.get('next')
        params = None
    return pulses

# Fetch indicators for a pulse, optionally filtered by server-side date
def fetch_indicators(pulse_id, api_key, since_ts):
    indicators = []
    params = {
        'limit': 100,
        'date_published__gt': since_ts
    }
    next_url = f"{OTX_BASE}/pulses/{pulse_id}/indicators"
    while next_url:
        resp = requests.get(next_url, headers={'X-OTX-API-KEY': api_key}, params=params, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        indicators.extend(data.get('results', []))
        next_url = data.get('next')
        params = None
    return indicators

# CLI entry point - Zabbix positional format
def main():
    if len(sys.argv) < 2:
        print("Error: Operation required", file=sys.stderr)
        sys.exit(1)
    
    operation = sys.argv[1].lower()
    
    try:
        if operation == 'discover':
            # discover <API_KEY> <HOURS>
            if len(sys.argv) < 4:
                print("Error: discover requires API_KEY and HOURS", file=sys.stderr)
                sys.exit(1)
            api_key = sys.argv[2]
            hours = int(sys.argv[3])
            
            since_dt = datetime.now(timezone.utc) - timedelta(hours=hours)
            since_ts = since_dt.isoformat()
            pulses = fetch_pulses(api_key, since_dt)
            seen = set()
            data = []
            for pulse in pulses:
                pid = pulse.get('id')
                indicators = fetch_indicators(pid, api_key, since_ts)
                for ind in indicators:
                    ioc_type = ind.get('indicator_type')
                    ioc_val = ind.get('indicator')
                    if ioc_type and ioc_val:
                        key = (ioc_type, ioc_val)
                        if key not in seen:
                            seen.add(key)
                            data.append({'{#TYPE}': ioc_type, '{#VALUE}': ioc_val})
            print(json.dumps({'data': data}))
            
        elif operation == 'ioc':
            # ioc <TYPE> <VALUE> <API_KEY> <HOURS>
            if len(sys.argv) < 6:
                print("Error: ioc requires TYPE, VALUE, API_KEY, and HOURS", file=sys.stderr)
                sys.exit(1)
            ioc_type = sys.argv[2]
            ioc_val = sys.argv[3]
            api_key = sys.argv[4]
            
            details = otx_get(f'/indicators/{ioc_type}/{ioc_val}/general', api_key)
            print(json.dumps(details))
            
        elif operation == 'severity':
            # severity <TYPE> <VALUE> <API_KEY> <HOURS>
            if len(sys.argv) < 6:
                print("Error: severity requires TYPE, VALUE, API_KEY, and HOURS", file=sys.stderr)
                sys.exit(1)
            ioc_type = sys.argv[2]
            ioc_val = sys.argv[3]
            api_key = sys.argv[4]
            
            details = otx_get(f'/indicators/{ioc_type}/{ioc_val}/general', api_key)
            confidence = details.get('pulse_info', {}).get('confidence')
            if confidence is None:
                confidence = details.get('confidence', 0)
            print(confidence if confidence is not None else 0)
            
        elif operation == 'pulses':
            # pulses <API_KEY> <HOURS>
            if len(sys.argv) < 4:
                print("Error: pulses requires API_KEY and HOURS", file=sys.stderr)
                sys.exit(1)
            api_key = sys.argv[2]
            hours = int(sys.argv[3])
            
            since_dt = datetime.now(timezone.utc) - timedelta(hours=hours)
            pulses = fetch_pulses(api_key, since_dt)
            print(len(pulses))
            
        elif operation == 'lastupdate':
            # lastupdate <API_KEY> <HOURS>
            if len(sys.argv) < 4:
                print("Error: lastupdate requires API_KEY and HOURS", file=sys.stderr)
                sys.exit(1)
            api_key = sys.argv[2]
            hours = int(sys.argv[3])
            
            since_dt = datetime.now(timezone.utc) - timedelta(hours=hours)
            pulses = fetch_pulses(api_key, since_dt)
            if pulses:
                latest = max(parse_ts(p.get('modified', p.get('created', ''))) for p in pulses if p.get('modified') or p.get('created'))
                print(latest.isoformat())
            else:
                print('')
        else:
            print(f"Error: Unknown operation '{operation}'", file=sys.stderr)
            sys.exit(1)
            
    except Exception as e:
        logger.error(f"Error in {operation}: {e}")
        # Return safe defaults for Zabbix
        if operation == 'severity':
            print(0)
        elif operation == 'pulses':
            print(0)
        else:
            print('')
        sys.exit(1)

if __name__ == '__main__':
    main()