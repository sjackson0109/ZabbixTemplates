# TCP Port Scanner Script

### Author: Simon Jackson / @sjackson0109  
### Created: 2025/05/08  
### Updated: 2025/05/08  

## Overview  
**get_tcp_port_scan_flex.py** is a multithreaded TCP scanner written in Python 3, built to assist with service discovery and exposure audits. It’s designed for use with Zabbix low-level discovery (LLD), but can also be used interactively from the command line.

The script checks if specified TCP ports are open on a host and supports flexible scan modes including full-range scans, port ranges, and targeted checks.

## Features  
- ✅ **Zabbix LLD-compatible JSON output**  
- ✅ **Single-port check mode** for Zabbix external items  
- ✅ **Multithreaded scanning** for fast performance  
- ✅ **Supports port ranges, limits, and full 1–65535 scans**  
- ✅ **Verbose mode for progress tracking and per-port output**  
- ✅ **Cross-platform**: Runs anywhere Python 3 is available  

## Installation  
No dependencies needed. This script is pure Python 3.

```bash
chmod +x get_tcp_port_scan_flex.py
```

## Usage

### Basic Syntax:
```bash
python3 get_tcp_port_scan_flex.py <HOST> [--discover | --check <PORT>] [options]
```

### Examples

#### 🔍 Discover open ports using default set:
```bash
python3 get_tcp_port_scan_flex.py 192.168.1.1 --discover
```

#### 🔍 Scan all 65535 ports:
```bash
python3 get_tcp_port_scan_flex.py 192.168.1.1 --discover --all
```

#### 🔍 Use a custom port range:
```bash
python3 get_tcp_port_scan_flex.py 192.168.1.1 --discover --range 1000-2000
```

#### 🔍 Limit scan to 1000 ports:
```bash
python3 get_tcp_port_scan_flex.py 192.168.1.1 --discover --all --max-ports 1000
```

#### ✅ Check if a single port is open:
```bash
python3 get_tcp_port_scan_flex.py 192.168.1.1 --check 443
```

## Arguments

| Argument | Default | Description |
|---------|---------|-------------|
| `<host>` | — | Target host (IP or FQDN) |
| `-d`, `--discover` | — | Output Zabbix LLD-style JSON |
| `-c`, `--check <port>` | — | Return `1` if port is open, else `0` |
| `-a`, `--all` | False | Scan all 65535 ports |
| `-r`, `--range 1000-2000` | — | Port range to scan |
| `--max-ports N` | — | Limit number of ports scanned |
| `-p`, `--ports` | common set | Comma-separated list |
| `-t`, `--timeout` | 2 | Timeout per port in seconds |
| `--threads` | 20 | Number of parallel workers |
| `-v`, `--verbose` | False | Print progress and results |

## Output

When run in `--discover` mode, the script outputs:

```json
{
    "data": [
        { "{#TCPPORT}": 80 },
        { "{#TCPPORT}": 443 }
    ]
}
```

When run in `--check` mode:

```
0  # port is closed
1  # port is open
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0    | Script executed successfully |
| 1    | Internal error |
| 2    | No action specified or bad input |
