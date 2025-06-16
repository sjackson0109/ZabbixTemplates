#!/usr/bin/env python3

import requests
import json
import argparse
import sys

ZABBIX_API_URL = "http://localhost/zabbix/api_jsonrpc.php"
ZABBIX_USER = "api.web.discovery"
ZABBIX_PASS = "changeme"

def api_request(method, params, auth=None):
    payload = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1,
        "auth": auth
    }
    response = requests.post(ZABBIX_API_URL, headers={"Content-Type": "application/json"}, data=json.dumps(payload))
    response.raise_for_status()
    return response.json()["result"]

def get_auth_token():
    return api_request("user.login", {
        "user": ZABBIX_USER,
        "password": ZABBIX_PASS
    })

def discover_web_scenarios(auth_token, hostname):
    host_info = api_request("host.get", {"filter": {"host": [hostname]}, "output": ["hostid"]}, auth_token)
    if not host_info:
        print(f"ERROR: Host '{hostname}' not found", file=sys.stderr)
        return []

    hostid = host_info[0]["hostid"]

    scenarios = api_request("httptest.get", {
        "output": ["name"],
        "hostid": hostid,
        "selectTags": "extend",
        "selectSteps": ["name"]
    }, auth_token)

    discovery = []
    for scenario in scenarios:
        customer = ""
        priority = ""
        for tag in scenario.get("tags", []):
            if tag["tag"] == "Customer":
                customer = tag["value"]
            elif tag["tag"] == "Priority":
                priority = tag["value"]

        for step in scenario.get("steps", []):
            discovery.append({
                "{#SCENARIO}": scenario["name"],
                "{#STEP}": step["name"],
                "{#CUSTOMER}": customer,
                "{#PRIORITY}": priority
            })

    return discovery

def main():
    parser = argparse.ArgumentParser(description="Discover Zabbix web scenarios for a given host")
    parser.add_argument("host", help="Zabbix host name (case-sensitive)")

    args = parser.parse_args()
    auth_token = get_auth_token()
    data = discover_web_scenarios(auth_token, args.host)
    print(json.dumps({"data": data}, indent=4))

if __name__ == "__main__":
    main()
