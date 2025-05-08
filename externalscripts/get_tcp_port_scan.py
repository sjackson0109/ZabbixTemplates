#!/usr/bin/env python3
"""
Author: Simon Jackson / @sjackson0109
Created: 2025-05-08
Version: 1.3

A multithreaded TCP scanner for discovering and checking open ports on networked hosts.
Supports Zabbix low-level discovery (LLD) via JSON and per-port status checks.

Features:
- Zabbix-compatible JSON output for open ports (--discover)
- Single-port availability checks (--check)
- Full port range (--all), custom ranges (--range), or common defaults
- Multithreaded scanning with optional port limits and verbose output
- Suitable for perimeter monitoring and service exposure audits
"""
import socket
import json
import argparse
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

DEFAULT_PORTS = [22, 23, 53, 80, 161, 443, 445, 8080, 8443, 10050, 10051, 3306, 3389, 5000]

def scan_port(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False

def parse_port_range(range_str):
    try:
        start, end = map(int, range_str.split("-"))
        if start < 1 or end > 65535 or start > end:
            raise ValueError("Invalid port range")
        return list(range(start, end + 1))
    except Exception as e:
        raise argparse.ArgumentTypeError("Port range must be in format 'start-end' within 1-65535")

def discover_ports(host, ports, timeout, verbose=False, max_threads=20):
    data = []
    total = len(ports)
    completed = 0

    def worker(port):
        nonlocal completed
        is_open = scan_port(host, port, timeout)
        completed += 1
        if verbose and completed % 100 == 0:
            print(f"Scanned {completed}/{total} ports...")
        if verbose and completed % 10 == 0:
            print(f"{'✅' if is_open else '❌'} Port {port} is {'open' if is_open else 'closed'}.")
        return port if is_open else None

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_port = {executor.submit(worker, port): port for port in ports}
        for future in as_completed(future_to_port):
            port_result = future.result()
            if port_result is not None:
                data.append({"{#TCPPORT}": port_result})

    return json.dumps({"data": data}, indent=4)

def check_port(host, port, timeout):
    return 1 if scan_port(host, port, timeout) else 0

def main():
    parser = argparse.ArgumentParser(description="TCP Port Scanner for Zabbix JSON Discovery or Checks")
    parser.add_argument("host", help="Target host to scan (IP or hostname)")
    parser.add_argument("-p", "--ports", help="Comma-separated list of ports", default=None)
    parser.add_argument("-r", "--range", type=parse_port_range, help="Port range in format 'start-end'")
    parser.add_argument("-a", "--all", action="store_true", help="Scan all 65535 ports")
    parser.add_argument("--max-ports", type=int, help="Maximum number of ports to scan (applies to --all or --range)")
    parser.add_argument("-t", "--timeout", type=float, default=2, help="Timeout per port in seconds (default: 2)")
    parser.add_argument("--threads", type=int, default=20, help="Maximum number of parallel threads (default: 20)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-d", "--discover", action="store_true", help="Enable discovery mode for Zabbix")
    parser.add_argument("-c", "--check", type=int, help="Check a single port (returns 1=open, 0=closed)")

    args = parser.parse_args()

    if args.all:
        ports = list(range(1, 65536))
    elif args.range:
        ports = args.range
    elif args.ports:
        ports = sorted(set(int(p.strip()) for p in args.ports.split(",") if p.strip().isdigit()))
    else:
        ports = DEFAULT_PORTS

    if args.max_ports:
        ports = ports[:args.max_ports]

    start_time = time.time()

    if args.discover:
        print(discover_ports(args.host, ports, args.timeout, args.verbose, args.threads))
    elif args.check is not None:
        print(check_port(args.host, args.check, args.timeout))
    else:
        print("[ERROR] Please specify either --discover or --check")
        exit(2)

    if args.verbose:
        elapsed = time.time() - start_time
        print(f"Scan completed in {elapsed:.2f} seconds.")

if __name__ == "__main__":
    main()