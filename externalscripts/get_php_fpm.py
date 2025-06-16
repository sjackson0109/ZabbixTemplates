#!/usr/bin/env python3
"""
Contributor: Simon Jackson (@sjackson0109)
Author: Ramil Valitov (ramilvalitov@gmail.com) https://github.com/rvalitov/zabbix-php-fpm 
Updated: 2025/06/09
Version: 1.6
Description:
    - Discover PHP-FPM pools and their status
    - Get status of PHP-FPM pools for specific socket-paths
"""
import os
import re
import sys
import json
import socket
import shutil
import psutil
import argparse
import subprocess
import stat
from datetime import datetime
from time import time, sleep

# --- Constants ---
CACHE_DIR = "/var/cache/zabbix-php-fpm"
PENDING_FILE = os.path.join(CACHE_DIR, "php_fpm_pending.cache")
RESULTS_CACHE_FILE = os.path.join(CACHE_DIR, "php_fpm_results.cache")
DEFAULT_STATUS_PATH = "/php-fpm-status"
MAX_EXECUTION_TIME_MS = 1500
SLEEP_TIMEOUT = 0.5

# --- Globals ---
start_time_ns = time() * 1e9
debug = False
sleep_mode = False
disable_timeout = False
status_path = DEFAULT_STATUS_PATH
result_data = []

# --- Helper Functions ---
def log(msg):
    if debug:
        print(f"[DEBUG] {msg}", file=sys.stderr)

def elapsed_time_ms():
    return (time() * 1e9 - start_time_ns) / 1e6

def check_timeout():
    if disable_timeout:
        return
    if elapsed_time_ms() > MAX_EXECUTION_TIME_MS:
        log(f"Timeout exceeded: {elapsed_time_ms():.0f}ms")
        save_results()
        sys.exit(0)

def ensure_cache_dir():
    if not os.path.isdir(CACHE_DIR):
        os.makedirs(CACHE_DIR, mode=0o700, exist_ok=True)

def read_file_lines(path):
    if os.path.isfile(path):
        with open(path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    return []

def write_file_lines(path, lines):
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")

def run_fcgi(pool_url, pool_path):
    cgi_fcgi = shutil.which("cgi-fcgi")
    if not cgi_fcgi:
        return None
    env = {
        "SCRIPT_NAME": pool_path,
        "SCRIPT_FILENAME": pool_path,
        "QUERY_STRING": "json",
        "REQUEST_METHOD": "GET"
    }
    try:
        result = subprocess.run(
            [cgi_fcgi, "-bind", "-connect", pool_url],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=True
        )
        return result.stdout.decode(errors="ignore")
    except Exception as e:
        log(f"cgi-fcgi error: {e}")
        return None

def parse_fcgi_status(raw_output):
    json_start = raw_output.find("{")
    if json_start == -1:
        return None
    try:
        return json.loads(raw_output[json_start:])
    except json.JSONDecodeError:
        return None

def discover_php_fpm_pools():
    ps_list = [p.info for p in psutil.process_iter(attrs=['pid', 'name', 'cmdline'])]
    pool_names = set()
    for proc in ps_list:
        cmdline = " ".join(proc.get("cmdline", []))
        match = re.search(r"php-fpm: pool (\S+)", cmdline)
        if match:
            pool_names.add(match.group(1))

    discovered = []

    for pool_name in sorted(pool_names):
        sockets = find_sockets_for_pool(pool_name)
        for sock in sockets:
            raw = run_fcgi(sock, status_path)
            if not raw:
                continue
            parsed = parse_fcgi_status(raw)
            if parsed and "pool" in parsed:
                discovered.append({"{#POOLNAME}": pool_name, "{#POOLSOCKET}": sock})
                log(f"Discovered pool {pool_name} on {sock}")
            check_timeout()
            if sleep_mode:
                sleep(SLEEP_TIMEOUT)

    return discovered

def find_sockets_for_pool(pool_name):
    found = set()
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == psutil.CONN_LISTEN and conn.laddr:
            host, port = conn.laddr
            found.add(f"{host}:{port}")
    for proc in psutil.process_iter(['connections']):
        for con in proc.info.get('connections', []):
            if con.status == psutil.CONN_LISTEN and con.laddr:
                found.add(f"{con.laddr.ip}:{con.laddr.port}")
    common_unix_paths = ["/run/php/", "/var/run/php/"]
    for path in common_unix_paths:
        if os.path.isdir(path):
            for entry in os.listdir(path):
                full = os.path.join(path, entry)
                if os.path.isfile(full) and stat_is_socket(full):
                    found.add(full)
    return list(found)

def stat_is_socket(path):
    try:
        return stat.S_ISSOCK(os.stat(path).st_mode)
    except Exception:
        return False

def save_results():
    ensure_cache_dir()
    write_file_lines(PENDING_FILE, [f"{d['{#POOLNAME}']} {d['{#POOLSOCKET}']}" for d in result_data])
    write_file_lines(RESULTS_CACHE_FILE, [f"{d['{#POOLNAME}']} {d['{#POOLSOCKET}']} dynamic" for d in result_data])
    print(json.dumps({"data": result_data}, indent=None))

# --- Entry Point ---
def main():
    global debug, sleep_mode, disable_timeout, status_path, result_data

    parser = argparse.ArgumentParser(description="Zabbix PHP-FPM discovery and status")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--sleep", action="store_true", help="Enable sleep delay after each check")
    parser.add_argument("--nosleep", action="store_true", help="Disable execution timeout")
    parser.add_argument("--status-path", type=str, default=DEFAULT_STATUS_PATH, help="Override status path")
    args = parser.parse_args()

    debug = args.debug
    sleep_mode = args.sleep
    disable_timeout = args.nosleep
    status_path = args.status_path

    log(f"Using status path: {status_path}")
    result_data = discover_php_fpm_pools()
    save_results()

if __name__ == "__main__":
    main()
