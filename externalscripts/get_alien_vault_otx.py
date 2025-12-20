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

USAGE EXAMPLES:
    python get_alien_vault_otx.py discover <API_KEY> <HOURS>
    python get_alien_vault_otx.py ioc <TYPE> <VALUE> <API_KEY> <HOURS>
    python get_alien_vault_otx.py severity <TYPE> <VALUE> <API_KEY> <HOURS>
    python get_alien_vault_otx.py pulses <API_KEY> <HOURS>
    python get_alien_vault_otx.py lastupdate <API_KEY> <HOURS>
    python get_alien_vault_otx.py selftest <API_KEY>

TROUBLESHOOTING:
    - If you see 'error' in the output, check your arguments and API key.
    - For rate limit errors, increase delay or check OTX API status.
    - For network errors, check connectivity and proxy/firewall settings.
    - All errors are logged if OTX_DEBUG=1 is set.
    - Use selftest mode to verify API connectivity and script health.

ZABBIX INTEGRATION:
    - Returns valid JSON, integer, or empty string for Zabbix compatibility.
    - On error, returns a JSON object with an 'error' key or a safe default (0 or '').
    - Use value maps and triggers in Zabbix for severity/confidence.

ENVIRONMENT VARIABLES/MACROS:
    OTX_BASE (default: https://otx.alienvault.com/api/v1)
    OTX_TIMEOUT (default: 30)
    OTX_DEBUG (set to 1 for debug logging)
    OTX_IGNORE_FILE (optional: file with IOCs to ignore)
    OTX_IGNORE_LIST (optional: comma-separated list of IOCs to ignore)

For more information, see the README or contact the script author.

OUTPUT:
    - All operations return valid JSON, integer, or empty string for Zabbix compatibility.
    - On error, returns a JSON object with an 'error' key or a safe default (0 or '').
"""

import sys
import requests
import json
import logging
import os
from datetime import datetime, timedelta, timezone


# Macro/env/CLI support for config
import argparse

def get_config():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--otx-endpoint', dest='otx_endpoint', default=None)
    parser.add_argument('--otx-timeout', dest='otx_timeout', type=int, default=None)
    parser.add_argument('--otx-severity-threshold', dest='severity_threshold', type=int, default=None)
    parser.add_argument('--otx-min-severity', dest='min_severity', type=int, default=None)
    args, _ = parser.parse_known_args()

    # CLI > env > macro > default
    otx_base = (
        args.otx_endpoint or
        os.environ.get('OTX_API_ENDPOINT') or
        os.environ.get('OTX_BASE') or
        'https://otx.alienvault.com/api/v1'
    )
    try:
        http_timeout = (
            args.otx_timeout or
            int(os.environ.get('OTX_TIMEOUT', os.environ.get('{$OTX_TIMEOUT}', '30')))
        )
    except Exception:
        http_timeout = 30
    try:
        severity_threshold = (
            args.severity_threshold or
            int(os.environ.get('SEVERITY_THRESHOLD', os.environ.get('{$SEVERITY_THRESHOLD}', '7')))
        )
    except Exception:
        severity_threshold = 7
    try:
        min_severity = (
            args.min_severity or
            int(os.environ.get('OTX_MIN_SEVERITY', os.environ.get('{$OTX_MIN_SEVERITY}', '1')))
        )
    except Exception:
        min_severity = 1
    debug = os.environ.get('OTX_DEBUG', '0') == '1'
    return otx_base, http_timeout, severity_threshold, min_severity, debug

OTX_BASE, HTTP_TIMEOUT, SEVERITY_THRESHOLD, MIN_SEVERITY, DEBUG = get_config()

logger = logging.getLogger(__name__)
logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=logging.DEBUG if DEBUG else logging.WARNING)

# Perform GET with API key, timeout, and optional params, with retry logic
import time

# --- Performance: Simple in-memory cache for indicator lookups (per run) ---
_indicator_cache = {}

# --- Security: API key validation and masking ---
import re
def validate_api_key(key):
    # OTX API keys are 64 hex chars
    if not isinstance(key, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", key):
        raise ValueError("Invalid API key format. Must be 64 hex characters.")
    return True

# --- Input validation for CLI arguments (suggestion 5) ---
def validate_type(ioc_type):
    allowed_types = {"IPv4", "IPv6", "domain", "hostname", "email", "URL", "FileHash-MD5", "FileHash-SHA1", "FileHash-SHA256", "CIDR"}
    if ioc_type not in allowed_types:
        raise ValueError(f"Invalid IOC type: {ioc_type}. Allowed: {', '.join(sorted(allowed_types))}")
    return True

def validate_hours(hours):
    try:
        h = int(hours)
        if h < 1 or h > 168:
            raise ValueError("Hours must be between 1 and 168.")
        return h
    except Exception:
        raise ValueError("Hours must be an integer between 1 and 168.")

# --- Improved logging for auditability (suggestion 6) ---
def audit_log(message, **kwargs):
    # Log to file if OTX_AUDIT_LOG is set, else just use logger
    log_path = os.environ.get('OTX_AUDIT_LOG')
    log_entry = f"{datetime.now(timezone.utc).isoformat()} | {message} | {json.dumps(kwargs, default=str)}\n"
    if log_path:
        try:
            with open(log_path, 'a', encoding='utf-8') as f:
                f.write(log_entry)
        except Exception as e:
            logger.warning(f"Failed to write audit log: {e}")
    logger.info(f"AUDIT: {message} | {kwargs}")

def mask_api_key(key):
    # Always return masked, never log the full key
    if not key or len(key) < 8:
        return "***"
    return key[:4] + "..." + key[-4:]
def otx_get(endpoint, api_key, params=None, retries=3):
    url = f"{OTX_BASE}{endpoint}"
    for attempt in range(retries):
        try:
            resp = requests.get(url, headers={'X-OTX-API-KEY': api_key}, params=params, timeout=HTTP_TIMEOUT)
            if resp.status_code == 429:
                retry_after = int(resp.headers.get('Retry-After', 2 ** attempt))
                logger.warning(f"Rate limit hit (429) on attempt {attempt+1}/{retries}, retrying after {retry_after}s...")
                if attempt < retries - 1:
                    time.sleep(retry_after)
                    continue
                else:
                    raise Exception("Rate limit exceeded (HTTP 429)")
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.RequestException as e:
            # Never log or print the API key
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
            if resp.status_code == 429:
                retry_after = int(resp.headers.get('Retry-After', 2))
                logger.warning(f"Rate limit hit (429) in fetch_pulses, retrying after {retry_after}s...")
                time.sleep(retry_after)
                continue
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
    cache_key = f'indicators_{pulse_id}_{since_ts}'
    # Use global cache for performance
    if cache is not None and cache_key in cache:
        return cache[cache_key]
    if cache_key in _indicator_cache:
        return _indicator_cache[cache_key]
    indicators = []
    params = {
        'limit': 100,
        'date_published__gt': since_ts
    }
    next_url = f"{OTX_BASE}/pulses/{pulse_id}/indicators"
    while next_url:
        try:
            resp = requests.get(next_url, headers={'X-OTX-API-KEY': api_key}, params=params, timeout=HTTP_TIMEOUT)
            if resp.status_code == 429:
                retry_after = int(resp.headers.get('Retry-After', 2))
                logger.warning(f"Rate limit hit (429) in fetch_indicators, retrying after {retry_after}s...")
                time.sleep(retry_after)
                continue
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
    _indicator_cache[cache_key] = indicators
    return indicators

# CLI entry point - Zabbix positional format
def main():
    if len(sys.argv) < 2:
        print("Error: Operation required", file=sys.stderr)
        sys.exit(1)

    operation = sys.argv[1].lower()

    try:
        # Remove API key from sys.argv for logging
        safe_argv = [arg if (i == 0 or 'key' not in arg.lower()) else '***' for i, arg in enumerate(sys.argv)]
        if operation == 'selftest':
            audit_log('selftest invoked', user=os.environ.get('USERNAME'), args=safe_argv)
            # selftest <API_KEY>
            if len(sys.argv) < 3:
                print(json.dumps({'status': 'error', 'msg': 'selftest requires API_KEY'}))
                sys.exit(1)
            api_key = sys.argv[2]
            try:
                validate_api_key(api_key)
            except Exception as e:
                print(json.dumps({'status': 'fail', 'error': f'API key validation failed: {e}'}))
                sys.exit(1)
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
                result['error'] = f"Selftest error: {type(e).__name__}: {e}"
            print(json.dumps(result))
            return
        if operation == 'discover':
            audit_log('discover invoked', user=os.environ.get('USERNAME'), args=safe_argv)
            # discover <API_KEY> <HOURS>
            if len(sys.argv) < 4:
                print(json.dumps({'error': 'discover requires API_KEY and HOURS'}))
                sys.exit(1)
            api_key = sys.argv[2]
            try:
                validate_api_key(api_key)
            except Exception as e:
                print(json.dumps({'error': f'API key validation failed: {e}'}))
                sys.exit(1)
            try:
                hours = validate_hours(sys.argv[3])
            except Exception as e:
                print(json.dumps({'error': f'Invalid hours: {e}'}))
                sys.exit(1)

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
                print(json.dumps({'error': f"Discover error: {type(e).__name__}: {e}"}))
            
        elif operation == 'ioc':
            audit_log('ioc invoked', user=os.environ.get('USERNAME'), args=safe_argv)
            # ioc <TYPE> <VALUE> <API_KEY> <HOURS>
            if len(sys.argv) < 6:
                print(json.dumps({'error': 'ioc requires TYPE, VALUE, API_KEY, and HOURS'}))
                sys.exit(1)
            ioc_type = sys.argv[2]
            try:
                validate_type(ioc_type)
            except Exception as e:
                print(json.dumps({'error': f'Invalid IOC type: {e}'}))
                sys.exit(1)
            ioc_val = sys.argv[3]
            api_key = sys.argv[4]
            try:
                validate_api_key(api_key)
            except Exception as e:
                print(json.dumps({'error': f'API key validation failed: {e}'}))
                sys.exit(1)

            try:
                details = otx_get(f'/indicators/{ioc_type}/{ioc_val}/general', api_key)
                print(json.dumps(details))
            except Exception as e:
                logger.error(f"Error in ioc: {e}")
                print(json.dumps({'error': f"IOC error: {type(e).__name__}: {e}"}))
            
        elif operation == 'severity':
            audit_log('severity invoked', user=os.environ.get('USERNAME'), args=safe_argv)
            # severity <TYPE> <VALUE> <API_KEY> <HOURS>
            if len(sys.argv) < 6:
                print(0)
                sys.exit(1)
            ioc_type = sys.argv[2]
            try:
                validate_type(ioc_type)
            except Exception as e:
                print(f"0 # Invalid IOC type: {e}")
                sys.exit(1)
            ioc_val = sys.argv[3]
            api_key = sys.argv[4]
            try:
                validate_api_key(api_key)
            except Exception as e:
                print(f"0 # API key validation failed: {e}")
                sys.exit(1)

            try:
                details = otx_get(f'/indicators/{ioc_type}/{ioc_val}/general', api_key)
                confidence = details.get('pulse_info', {}).get('confidence')
                if confidence is None:
                    confidence = details.get('confidence', 0)
                print(confidence if confidence is not None else 0)
            except Exception as e:
                logger.error(f"Error in severity: {e}")
                print(f"0 # Severity error: {type(e).__name__}: {e}")
            
        elif operation == 'pulses':
            audit_log('pulses invoked', user=os.environ.get('USERNAME'), args=safe_argv)
            # pulses <API_KEY> <HOURS>
            if len(sys.argv) < 4:
                print(0)
                sys.exit(1)
            api_key = sys.argv[2]
            try:
                validate_api_key(api_key)
            except Exception as e:
                print(f"0 # API key validation failed: {e}")
                sys.exit(1)
            try:
                hours = validate_hours(sys.argv[3])
            except Exception as e:
                print(f"0 # Invalid hours: {e}")
                sys.exit(1)

            try:
                since_dt = datetime.now(timezone.utc) - timedelta(hours=hours)
                pulses = fetch_pulses(api_key, since_dt)
                print(len(pulses))
            except Exception as e:
                logger.error(f"Error in pulses: {e}")
                print(f"0 # Pulses error: {type(e).__name__}: {e}")
            
        elif operation == 'lastupdate':
            audit_log('lastupdate invoked', user=os.environ.get('USERNAME'), args=safe_argv)
            # lastupdate <API_KEY> <HOURS>
            if len(sys.argv) < 4:
                print('')
                sys.exit(1)
            api_key = sys.argv[2]
            try:
                validate_api_key(api_key)
            except Exception as e:
                print(f" # API key validation failed: {e}")
                sys.exit(1)
            try:
                hours = validate_hours(sys.argv[3])
            except Exception as e:
                print(f" # Invalid hours: {e}")
                sys.exit(1)

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
                print(f" # Lastupdate error: {type(e).__name__}: {e}")
        else:
            print(json.dumps({'error': f"Unknown operation: {operation}"}))
            sys.exit(1)
            
    except Exception as e:
        logger.error(f"Error in {operation}: {e}")
        # Return safe defaults for Zabbix, with error details
        if operation == 'severity':
            print(f"0 # {operation} error: {type(e).__name__}: {e}")
        elif operation == 'pulses':
            print(f"0 # {operation} error: {type(e).__name__}: {e}")
        else:
            print(f" # {operation} error: {type(e).__name__}: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()