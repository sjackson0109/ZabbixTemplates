#!/usr/bin/env python3
"""
Author: Simon Jackson (sjackson0109)
Created: 2024/11/18
Updated: 2025/02/21
Version: 1.1
Description: 
    - Logs into a WatchGuard Firebox (Firewall) via API.
    - Fetches system health metrics (CPU, Memory, Active Connections).
    - Computes a simple health score for Zabbix monitoring.
    - Returns a numeric metric (0-100) for use with Zabbix external checks.
"""

import requests
import sys

# Suppress SSL warnings for self-signed certificates
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

class WatchGuardMonitor:
    """Handles WatchGuard Firewall API interactions and health metric calculations."""

    def __init__(self, api_url, username, password):
        self.api_url = api_url.rstrip("/")  # Ensure no trailing slash
        self.username = username
        self.password = password
        self.auth_token = None

    def login(self):
        """Authenticate with WatchGuard API and retrieve an auth token."""
        payload = {"user": self.username, "password": self.password}
        try:
            response = requests.post(f"{self.api_url}/login", json=payload, verify=False, timeout=5)
            response.raise_for_status()
            self.auth_token = response.json().get("auth_token")
            if not self.auth_token:
                self.exit_with_failure()
        except requests.RequestException:
            self.exit_with_failure()

    def get_health_metric(self):
        """Retrieve system health metrics and compute a score."""
        if not self.auth_token:
            self.exit_with_failure()

        headers = {"Authorization": f"Bearer {self.auth_token}"}
        try:
            response = requests.get(f"{self.api_url}/status/system", headers=headers, verify=False, timeout=5)
            response.raise_for_status()
            data = response.json()

            # Extract key metrics (modify based on API responses)
            cpu_usage = data.get("cpu_usage", 0)
            memory_usage = data.get("memory_usage", 0)
            active_connections = data.get("active_connections", 0)

            # Compute a basic health score (adjust weightings as needed)
            health_score = max(100 - (cpu_usage * 0.5) - (memory_usage * 0.3) - (active_connections * 0.01), 0)
            
            print(int(health_score))  # Print metric for Zabbix ingestion
        except requests.RequestException:
            self.exit_with_failure()

    @staticmethod
    def exit_with_failure():
        """Prints failure metric (0) and exits."""
        print("0")
        sys.exit(1)

def main():
    """Main execution function to handle command-line input."""
    if len(sys.argv) != 4:
        WatchGuardMonitor.exit_with_failure()

    api_url, username, password = sys.argv[1:4]
    
    monitor = WatchGuardMonitor(api_url, username, password)
    monitor.login()
    monitor.get_health_metric()

if __name__ == "__main__":
    main()