#!/usr/bin/env python3
"""
Author: Simon Jackson (sjackson0109)
Created: 2025/07/16
Updated: 2025/12/19
Version: 2.7
Description:
    This script interacts with the AlienVault OTX API to fetch threat intelligence data.
    Supports Zabbix external script format with positional parameters.

Features:
    Dynamically Discovery: Discovers IOCs (type, value, and metadata) from OTX pulses within a configurable time window.
    Severity Tracking: Monitors and triggers on IOC severity/confidence levels.
    Pulse Count & Update Time: Tracks the number of new pulses and the last update time.
    IOC Metadata Exposure: Each discovered IOC now includes first seen, last seen, pulse name, tags, references, and threat type for richer context and filtering in Zabbix.
    Robust Error Handling: All operations return Zabbix-friendly output, with clear error reporting and safe defaults.
    Macro/Env Flexibility: Supports macros/environment variables for API endpoint, timeout, and debug logging.
    Performance Optimized: Caches API results within a run to minimize redundant calls.

Usage (Zabbix format):
    python get_alien_vault_otx.py discover <API_KEY> <HOURS>
    python get_alien_vault_otx.py ioc <TYPE> <VALUE> <API_KEY> <HOURS>
    python get_alien_vault_otx.py severity <TYPE> <VALUE> <API_KEY> <HOURS>
    python get_alien_vault_otx.py pulses <API_KEY> <HOURS>
    python get_alien_vault_otx.py lastupdate <API_KEY> <HOURS>

Environment variables/macros:
    OTX_BASE (default: https://otx.alienvault.com/api/v1)
    OTX_TIMEOUT (default: 30)
    OTX_DEBUG (set to 1 for debug logging)

Troubleshooting:
    - If you see 'error' in the output, check your arguments and API key.
    - For rate limit errors, increase delay or check OTX API status.
    - For network errors, check connectivity and proxy/firewall settings.
    - All errors are logged if OTX_DEBUG=1 is set.

Output:
    - All operations return valid JSON, integer, or empty string for Zabbix compatibility.
    - On error, returns a JSON object with an 'error' key or a safe default (0 or '').
"""

import sys
import requests
import json
import logging
import os
from datetime import datetime, timedelta, timezone

# Macro/env support
OTX_BASE = os.environ.get('OTX_BASE', 'https://otx.alienvault.com/api/v1')
try:
    HTTP_TIMEOUT = int(os.environ.get('OTX_TIMEOUT', '30'))
except Exception:
    HTTP_TIMEOUT = 30
DEBUG = os.environ.get('OTX_DEBUG', '0') == '1'

logger = logging.getLogger(__name__)
logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=logging.DEBUG if DEBUG else logging.WARNING)

# Perform GET with API key, timeout, and optional params, with retry logic
import time
def otx_get(endpoint, api_key, params=None, retries=3):
    url = f"{OTX_BASE}{endpoint}"
    for attempt in range(retries):
        try:
            resp = requests.get(url, headers={'X-OTX-API-KEY': api_key}, params=params, timeout=HTTP_TIMEOUT)
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.RequestException as e:
            logger.warning(f"API error (attempt {attempt+1}/{retries}): {e}")
            if attempt < retries - 1:
                time.sleep(2 ** attempt)
            else:
                raise

# Parse ISO8601 timestamp to aware datetime
def parse_ts(ts):
    dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

# Fetch pulses with server-side date filter; paginate as needed, with caching
def fetch_pulses(api_key, since_dt, cache=None):
    if cache is not None and 'pulses' in cache:
        return cache['pulses']
    pulses = []
    params = {
        'page_size': 100,
        'date_published__gt': since_dt.isoformat()
    }
    next_url = f"{OTX_BASE}/pulses/subscribed"
    page_count = 0
    while next_url:
        try:
            resp = requests.get(next_url, headers={'X-OTX-API-KEY': api_key}, params=params, timeout=HTTP_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
            page = data.get('results', [])
            pulses.extend(page)
            page_count += 1
            print(f"Fetched pulse page {page_count}, {len(page)} pulses")
            # For self-test, only fetch the first page
            if os.environ.get('OTX_SELFTEST', '0') == '1':
                break
            next_url = data.get('next')
            params = None
        except requests.exceptions.RequestException as e:
            logger.warning(f"API error in fetch_pulses: {e}")
            break
    if cache is not None:
        cache['pulses'] = pulses
    return pulses

# Fetch indicators for a pulse, optionally filtered by server-side date, with caching
def fetch_indicators(pulse_id, api_key, since_ts, cache=None):
    cache_key = f'indicators_{pulse_id}'
    if cache is not None and cache_key in cache:
        return cache[cache_key]
    indicators = []
    params = {
        'limit': 100,
        'date_published__gt': since_ts
    }
    next_url = f"{OTX_BASE}/pulses/{pulse_id}/indicators"
    while next_url:
        try:
            resp = requests.get(next_url, headers={'X-OTX-API-KEY': api_key}, params=params, timeout=HTTP_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
            indicators.extend(data.get('results', []))
            next_url = data.get('next')
            params = None
        except requests.exceptions.RequestException as e:
            logger.warning(f"API error in fetch_indicators: {e}")
            break
    if cache is not None:
        cache[cache_key] = indicators
    return indicators

# CLI entry point - Zabbix positional format
def main():
    if len(sys.argv) < 2:
        print("Error: Operation required", file=sys.stderr)
        sys.exit(1)

    operation = sys.argv[1].lower()

    try:
        if operation == 'selftest':
            # selftest <API_KEY>
            if len(sys.argv) < 3:
                print(json.dumps({'status': 'error', 'msg': 'selftest requires API_KEY'}))
                sys.exit(1)
            api_key = sys.argv[2]
            result = {'status': 'ok', 'api': None, 'pulses': 0, 'sample_ioc': None, 'error': None}
            try:
                # Use a shorter timeout for diagnostics
                test_timeout = min(HTTP_TIMEOUT, 10)
                resp = requests.get(f"{OTX_BASE}/user/me", headers={'X-OTX-API-KEY': api_key}, timeout=test_timeout)
                result['api'] = resp.status_code
                if resp.status_code != 200:
                    result['status'] = 'fail'
                    result['error'] = f'API status {resp.status_code}'
                else:
                    # Limit to pulses published today for faster diagnostics
                    today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
                    since_dt = today
                    # Set env var to limit fetch_pulses to one page for self-test
                    os.environ['OTX_SELFTEST'] = '1'
                    pulses = fetch_pulses(api_key, since_dt)
                    os.environ['OTX_SELFTEST'] = '0'
                    if len(pulses) > 10:
                        pulses = pulses[:10]
                    result['pulses'] = len(pulses)
                    if pulses:
                        pid = pulses[0].get('id')
                        try:
                            indicators = fetch_indicators(pid, api_key, since_dt.isoformat())
                            if indicators:
                                ioc = indicators[0]
                                result['sample_ioc'] = {
                                    'type': ioc.get('indicator_type'),
                                    'value': ioc.get('indicator')
                                }
                        except requests.exceptions.Timeout:
                            result['status'] = 'fail'
                            result['error'] = 'Indicator fetch timeout'
            except requests.exceptions.Timeout:
                result['status'] = 'fail'
                result['error'] = 'API request timeout'
            except KeyboardInterrupt:
                result['status'] = 'fail'
                result['error'] = 'Interrupted by user'
            except Exception as e:
                result['status'] = 'fail'
                result['error'] = str(e)
            print(json.dumps(result))
            return
        if operation == 'discover':
            # discover <API_KEY> <HOURS>
            if len(sys.argv) < 4:
                print(json.dumps({'error': 'discover requires API_KEY and HOURS'}))
                sys.exit(1)
            api_key = sys.argv[2]
            hours = int(sys.argv[3])

            since_dt = datetime.now(timezone.utc) - timedelta(hours=hours)
            since_ts = since_dt.isoformat()
            try:
                # Load ignore list from macro or file
                ignore_path = os.environ.get('OTX_IGNORE_FILE', 'otx_ignore.txt')
                ignore_set = set()
                if os.path.exists(ignore_path):
                    with open(ignore_path, 'r', encoding='utf-8') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                ignore_set.add(line)
                ignore_macro = os.environ.get('OTX_IGNORE_LIST', '')
                if ignore_macro:
                    for entry in ignore_macro.split(','):
                        entry = entry.strip()
                        if entry:
                            ignore_set.add(entry)
                cache = {}
                pulses = fetch_pulses(api_key, since_dt, cache)
                seen = set()
                data = []
                for pulse in pulses:
                    pid = pulse.get('id')
                    pulse_name = pulse.get('name', '')
                    pulse_tags = pulse.get('tags', [])
                    pulse_references = pulse.get('references', [])
                    indicators = fetch_indicators(pid, api_key, since_ts, cache)
                    for ind in indicators:
                        ioc_type = ind.get('indicator_type')
                        ioc_val = ind.get('indicator')
                        first_seen = ind.get('created', '')
                        last_seen = ind.get('modified', '')
                        threat_type = ind.get('type', '')
                        # Compose a unique key for deduplication
                        key = (ioc_type, ioc_val)
                        if ioc_type and ioc_val and key not in seen:
                            # Suppression: skip if in ignore list (type:value or just value)
                            if ioc_val in ignore_set or f"{ioc_type}:{ioc_val}" in ignore_set:
                                continue
                            seen.add(key)
                            data.append({
                                '{#TYPE}': ioc_type,
                                '{#VALUE}': ioc_val,
                                '{#FIRST_SEEN}': first_seen,
                                '{#LAST_SEEN}': last_seen,
                                '{#PULSE_NAME}': pulse_name,
                                '{#TAGS}': ','.join(pulse_tags) if pulse_tags else '',
                                '{#REFERENCES}': ','.join(pulse_references) if pulse_references else '',
                                '{#THREAT_TYPE}': threat_type
                            })
                print(json.dumps({'data': data}))
            except Exception as e:
                logger.error(f"Error in discover: {e}")
                print(json.dumps({'error': str(e)}))
            
        elif operation == 'ioc':
            # ioc <TYPE> <VALUE> <API_KEY> <HOURS>
            if len(sys.argv) < 6:
                print(json.dumps({'error': 'ioc requires TYPE, VALUE, API_KEY, and HOURS'}))
                sys.exit(1)
            ioc_type = sys.argv[2]
            ioc_val = sys.argv[3]
            api_key = sys.argv[4]

            try:
                details = otx_get(f'/indicators/{ioc_type}/{ioc_val}/general', api_key)
                print(json.dumps(details))
            except Exception as e:
                logger.error(f"Error in ioc: {e}")
                print(json.dumps({'error': str(e)}))
            
        elif operation == 'severity':
            # severity <TYPE> <VALUE> <API_KEY> <HOURS>
            if len(sys.argv) < 6:
                print(0)
                sys.exit(1)
            ioc_type = sys.argv[2]
            ioc_val = sys.argv[3]
            api_key = sys.argv[4]

            try:
                details = otx_get(f'/indicators/{ioc_type}/{ioc_val}/general', api_key)
                confidence = details.get('pulse_info', {}).get('confidence')
                if confidence is None:
                    confidence = details.get('confidence', 0)
                print(confidence if confidence is not None else 0)
            except Exception as e:
                logger.error(f"Error in severity: {e}")
                print(0)
            
        elif operation == 'pulses':
            # pulses <API_KEY> <HOURS>
            if len(sys.argv) < 4:
                print(0)
                sys.exit(1)
            api_key = sys.argv[2]
            hours = int(sys.argv[3])

            try:
                since_dt = datetime.now(timezone.utc) - timedelta(hours=hours)
                pulses = fetch_pulses(api_key, since_dt)
                print(len(pulses))
            except Exception as e:
                logger.error(f"Error in pulses: {e}")
                print(0)
            
        elif operation == 'lastupdate':
            # lastupdate <API_KEY> <HOURS>
            if len(sys.argv) < 4:
                print('')
                sys.exit(1)
            api_key = sys.argv[2]
            hours = int(sys.argv[3])

            try:
                since_dt = datetime.now(timezone.utc) - timedelta(hours=hours)
                pulses = fetch_pulses(api_key, since_dt)
                if pulses:
                    latest = max(parse_ts(p.get('modified', p.get('created', ''))) for p in pulses if p.get('modified') or p.get('created'))
                    print(latest.isoformat())
                else:
                    print('')
            except Exception as e:
                logger.error(f"Error in lastupdate: {e}")
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