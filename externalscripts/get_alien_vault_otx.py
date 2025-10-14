#!/usr/bin/env python3
"""
Author: Simon Jackson (sjackson0109)
Created: 2025/07/16
Updated: 2025/07/16
Version: 2.3

Description:
   This script interacts with the AlienVault OTX API to fetch threat intelligence data.
   It supports discovering IOCs, fetching IOC details, and retrieving severity levels.
   Returns structured JSON suitable for Zabbix LLD.

Usage:
  python get_alien_vault_otx.py -k <API_KEY> -d -h <HOURS>
  python get_alien_vault_otx.py -k <API_KEY> -i <TYPE> <VALUE>
  python get_alien_vault_otx.py -k <API_KEY> -s <TYPE> <VALUE>
  python get_alien_vault_otx.py -?
"""

import argparse
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

# Perform GET with API key, timeout, and optional params
def otx_get(endpoint, api_key, params=None):
    url = f"{OTX_BASE}{endpoint}"
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(f"GET {url} params={params}")
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
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Fetching pulses page: {next_url}")
        resp = requests.get(next_url, headers={'X-OTX-API-KEY': api_key}, params=params, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        page = data.get('results', [])
        pulses.extend(page)
        next_url = data.get('next')
        # After first page, clear params to continue pagination
        params = None
    logger.info(f"Total pulses fetched: {len(pulses)}")
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
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Fetching indicators page: {next_url}")
        resp = requests.get(next_url, headers={'X-OTX-API-KEY': api_key}, params=params, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        indicators.extend(data.get('results', []))
        next_url = data.get('next')
        params = None
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(f"Total indicators for pulse {pulse_id}: {len(indicators)}")
    return indicators

# CLI entry point
def main():
    parser = argparse.ArgumentParser(description='AlienVault OTX Zabbix helper', add_help=False)
    parser.add_argument('-k', '--api-key', required=True, help='OTX API key')
    parser.add_argument('-d', '--discover', action='store_true', help='Discover IOCs')
    parser.add_argument('-i', '--ioc', nargs=2, metavar=('TYPE','VALUE'), help='Fetch IOC details')
    parser.add_argument('-s', '--severity', nargs=2, metavar=('TYPE','VALUE'), help='Fetch IOC severity')
    parser.add_argument('-h', '--hours', type=int, help='Hours lookback for discovery')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('-?', '--help', action='help', help='Show help and exit')
    args = parser.parse_args()

    logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=logging.DEBUG if args.verbose else logging.WARNING)
    api_key = args.api_key

    if args.discover:
        if args.hours is None:
            print('Error: -h <HOURS> required with -d')
            sys.exit(1)
        since_dt = datetime.now(timezone.utc) - timedelta(hours=args.hours)
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
                        if logger.isEnabledFor(logging.DEBUG):
                            logger.debug(f"Appending IOC {ioc_type}:{ioc_val}")
                        data.append({'{#TYPE}': ioc_type, '{#VALUE}': ioc_val})
        print(json.dumps({'data': data}))
    elif args.ioc:
        ioc_type, ioc_val = args.ioc
        if args.verbose: logger.debug(f"Fetching details for IOC {ioc_type}:{ioc_val}")
        try:
            details = otx_get(f'/indicators/{ioc_type}/{ioc_val}/general', api_key)
            print(json.dumps(details))
        except Exception:
            print('')
    elif args.severity:
        ioc_type, ioc_val = args.severity
        if args.verbose: logger.debug(f"Fetching severity for IOC {ioc_type}:{ioc_val}")
        try:
            details = otx_get(f'/indicators/{ioc_type}/{ioc_val}/general', api_key)
            confidence = details.get('pulse_info', {}).get('confidence')
            if confidence is None:
                confidence = details.get('confidence', 0)
            print(confidence if confidence is not None else 0)
        except Exception:
            print(0)

if __name__ == '__main__':
    main()
