#!/usr/bin/env python3
# Description   : Script checks SIP_SERVER for SIP OPTIONS, compliant with RFC 3261.
# File Name     : get_sip_options.py
# Author        : Simon Jackson (@sjackson0109)
# Inspiration   : Wim Devos (@WimObiwan)
# Created     	: 2025/02/17
# Updated       : 2025/01/03
# Version       : 1.5

import socket
import sys
import re
import argparse
import random
import uuid
import ipaddress
import struct
import ssl
from time import time

# Constants
DEFAULT_PORT = 5060
DEFAULT_PROTOCOL = "tcp"
DEFAULT_TIMEOUT = 3
DEFAULT_WARN_THRESHOLD = 5  # Warning threshold in seconds
DEFAULT_TLS_VERSION = "TLSv1.2"
DEFAULT_CIPHER_SUITE = "CDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305"
USER_PREFIX = "sjackson0109"
USER_AGENT = "get_sip_options.py"

# Nagios-compatible exit codes
EXIT_CODES = {
    'OK': 0,
    'WARNING': 1,
    'CRITICAL': 2,
    'UNKNOWN': 3
}

# SIP Response Code Categories
SIP_RESPONSE_CATEGORIES = {
    1: "Informational",
    2: "Success",
    3: "Redirection",
    4: "Client Error",
    5: "Server Error",
    6: "Global Failure"
}

def discover_srv_record(host, protocol, verbose=False):
    """
    Discover SIP SRV records, supporting both IPv4 and IPv6 targets.
    """
    srv_types = {
        "udp": ["_sip._udp."],  # Standard SIP over UDP
        "tcp": ["_sip._tcp.", "_sips._tcp.", "_sipfederationtls._tcp."],  # SIP over TCP, TLS, and Federation
    }

    srv_queries = srv_types.get(protocol, [])
    discovered_records = []

    # DNS server to use (default is Cloudflare's public DNS)
    dns_server = "1.1.1.1"
    dns_port = 53

    for srv_prefix in srv_queries:
        srv_query = f"{srv_prefix}{host}"

        try:
            # Create a UDP socket for DNS resolution
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(DEFAULT_TIMEOUT)

            # Generate a DNS query for the SRV record
            query_id = random.randint(0, 65535)  # Unique ID for the query
            query = build_dns_query(srv_query, query_id)

            # Send the query to the DNS server
            sock.sendto(query, (dns_server, dns_port))

            # Receive the response
            response, _ = sock.recvfrom(4096)
            sock.close()

            # Parse the DNS response
            records = parse_dns_response(response, query_id, verbose)
            for priority, weight, port, target in records:
                discovered_records.append((priority, weight, port, target))

            if verbose:
                for priority, weight, port, target in discovered_records:
                    print(f"[INFO] Found {srv_query}: {target}:{port} (Priority: {priority}, Weight: {weight})")

        except socket.timeout:
            if verbose:
                print(f"[WARNING] DNS query timed out for {srv_query}.")
            continue
        except Exception as e:
            if verbose:
                print(f"[WARNING] Error querying SRV records for {srv_query}: {e}")
            continue

    # Sort by priority (lowest first), then by weight (highest first)
    discovered_records.sort(key=lambda x: (x[0], -x[1]))

    if discovered_records:
        best_target, best_port = discovered_records[0][3], discovered_records[0][2]

        # NEW: Resolve IPv4 and IPv6 addresses
        try:
            addr_info = socket.getaddrinfo(best_target, best_port, socket.AF_UNSPEC, socket.SOCK_STREAM)
            for res in addr_info:
                family, _, _, _, sockaddr = res
                ip_address = sockaddr[0]
                
                if family == socket.AF_INET6:
                    print(f"🌍[INFO] Resolved IPv6 Address: {ip_address}")
                else:
                    print(f"🌎[INFO] Resolved IPv4 Address: {ip_address}")
                
                return ip_address, best_port, srv_query  # Return resolved address

        except socket.gaierror:
            print(f"[WARNING] SRV target {best_target} does not resolve. Skipping.")

    return None, None, None

def build_dns_query(domain, query_id):
    """
    Build a DNS query packet for the given domain.
    """
    # DNS header
    header = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)

    # DNS question
    question = b""
    for part in domain.split("."):
        question += struct.pack("B", len(part)) + part.encode()
    question += b"\x00"  # End of domain name
    question += struct.pack(">HH", 33, 1)  # SRV record type (33) and class (IN)

    return header + question

def parse_dns_response(response, query_id, verbose=False):
    """
    Parse a DNS response packet and extract SRV records.
    Correctly handles DNS compression and variable-length records.
    """
    records = []
    
    # Validate Query ID
    if response[:2] != struct.pack(">H", query_id):
        return records

    # Parse DNS Header
    header = response[:12]
    answer_count = struct.unpack(">H", header[6:8])[0]

    # Start parsing after the header
    offset = 12

    # Skip the question section
    while response[offset] != 0:
        offset += 1
    offset += 5  # Skip the NULL byte and QTYPE/QCLASS (2 bytes each)

    # Parse each answer
    for _ in range(answer_count):
        # Check if the answer is compressed (pointer)
        while response[offset] != 0:
            if response[offset] >= 192:  # Compression pointer (0xC0xx)
                offset += 2
                break
            offset += 1
        else:
            offset += 1  # Move past end-of-name marker

        # Read Type, Class, TTL, and Data Length
        type_, class_, ttl, data_len = struct.unpack(">HHIH", response[offset:offset + 10])
        offset += 10

        # Check if this is an SRV record (Type 33)
        if type_ == 33:
            priority, weight, port = struct.unpack(">HHH", response[offset:offset + 6])
            offset += 6  # Move past priority, weight, and port

            # Parse the target domain name
            target = parse_dns_name(response, offset)
            offset += data_len - 6  # Move to the next record

            records.append((priority, weight, port, target))

    return records

def parse_dns_name(response, offset):
    """
    Parse a DNS name from the response, handling name compression correctly.
    """
    name = []
    while True:
        length = response[offset]

        # End of name
        if length == 0:
            offset += 1
            break

        # Compression pointer (0xC0xx format)
        if length >= 192:
            pointer_offset = ((length & 0x3F) << 8) | response[offset + 1]
            name.append(parse_dns_name(response, pointer_offset))  # Recursive call
            offset += 2
            break

        # Read label and advance
        name.append(response[offset + 1:offset + 1 + length].decode())
        offset += 1 + length

    return ".".join(name)

def is_hostname(host):
    """Validate if the input is a valid hostname or IP address."""
    if not host:
        return False

    # Check if it's a valid IP address (IPv4 or IPv6)
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass  # Not an IP, try resolving hostname

    # Check if it's a valid hostname
    if re.match(r'^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*$', host):
        # Try resolving the A/AAAA record
        try:
            socket.gethostbyname(host)
            return True
        except socket.gaierror:
            pass  # Fall back to SRV record check

    return False

# TLS Version Mapping
TLS_VERSIONS = {
    "TLSv1.2": ssl.PROTOCOL_TLSv1_2,
    "TLSv1.3": getattr(ssl, "PROTOCOL_TLSv1_3", ssl.PROTOCOL_TLSv1_2)  # Fallback to TLSv1.2 if TLSv1.3 is unavailable
}

def create_ssl_context(tls_version, cipher_suite, verbose=False):
    """
    Create an SSL context with an explicit TLS version and cipher suite.
    """
    if tls_version not in TLS_VERSIONS and tls_version != "auto":
        print(f"[ERROR] Invalid TLS version specified: {tls_version}")
        sys.exit(EXIT_CODES['UNKNOWN'])

    context = ssl.create_default_context()

    if tls_version != "auto":
        context = ssl.SSLContext(TLS_VERSIONS[tls_version])

    if cipher_suite:
        try:
            context.set_ciphers(cipher_suite)
            if verbose:
                print(f"🔒 [INFO] Using custom cipher suite: {cipher_suite}")
        except ssl.SSLError as e:
            print(f"[ERROR] Invalid cipher suite: {cipher_suite} ({e})")
            sys.exit(EXIT_CODES['UNKNOWN'])

    return context

def check_tls(sock, hostname, tls_version="TLSv1_2", tls_ciphers=None, verbose=False):
    """
    Wrap the socket in an SSL context for TLS encryption.
    Supports user-defined TLS versions and cipher suites.
    """
    context = ssl.create_default_context()
    
    # Set TLS version explicitly if provided
    if tls_version == "TLSv1_3":
        context.minimum_version = ssl.TLSVersion.TLSv1_3
    elif tls_version == "TLSv1_2":
        context.minimum_version = ssl.TLSVersion.TLSv1_2

    # Set custom ciphers if provided
    if tls_ciphers:
        context.set_ciphers(tls_ciphers)

    try:
        if verbose:
            print(f"🔒[INFO] Wrapping socket with {tls_version} for {hostname}")
        return context.wrap_socket(sock, server_hostname=hostname)
    except ssl.SSLError as e:
        if verbose:
            print(f"[WARNING] TLS handshake failed: {e}")
        return None

def send_sip_options(sip_server, sip_port, timeout, protocol="tcp", local_ip="::1", 
                     max_forwards=70, verbose=False, srv_type=None, tls_version=None, cipher_suite=None):
    """Send a SIP OPTIONS request and return the response code and response time, supporting IPv6 and TLS."""

    branch_id = f"z9hG4bK-{random.randint(100000, 999999)}"
    call_id = str(uuid.uuid4())

    sip_message = (
        f"OPTIONS sip:{sip_server} SIP/2.0\r\n"
        f"Via: SIP/2.0/{protocol.upper()} {local_ip}:{sip_port};branch={branch_id}\r\n"
        f"From: <sip:{USER_PREFIX}@{sip_server}>\r\n"
        f"To: <sip:{sip_server}>\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: 1 OPTIONS\r\n"
        f"Contact: <sip:{USER_PREFIX}@{local_ip}>\r\n"
        f"Max-Forwards: {max_forwards}\r\n"
        f"User-Agent: {USER_AGENT}\r\n"
        f"Content-Length: 0\r\n\r\n"
    )

    try:
        # Determine the socket type based on protocol
        sock_type = socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM

        # Detect IPv6 vs IPv4
        family = socket.AF_INET6 if ":" in sip_server else socket.AF_INET
        sock = socket.socket(family, sock_type)
        sock.settimeout(timeout)

        if protocol == "tls":
            print(f"🚀 [INFO] Establishing TLS connection to {sip_server}:{sip_port}...")

            # Use SSLContext instead of hardcoded TLS versions
            context = ssl.create_default_context()

            # Set TLS version if explicitly specified
            if tls_version:
                tls_version_map = {
                    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
                    "TLSv1.3": getattr(ssl.TLSVersion, "TLSv1_3", ssl.TLSVersion.TLSv1_2)  # Fallback to TLS 1.2 if 1.3 is unavailable
                }
                context.minimum_version = tls_version_map.get(tls_version, ssl.TLSVersion.TLSv1_2)

            # Set cipher suite if provided
            if cipher_suite:
                context.set_ciphers(cipher_suite)

            sock = context.wrap_socket(sock, server_hostname=sip_server)

        # Print SIP OPTIONS request BEFORE attempting a connection
        if verbose:
            print(f"\n📤 [INFO] Sending SIP OPTIONS Request ({protocol.upper()}):\n------->\n{sip_message}")

        if protocol in ["tcp", "tls"]:
            try:
                sock.connect((sip_server, sip_port))
                print(f"✅ [INFO] {protocol.upper()} connection established to {sip_server}:{sip_port}")
            except (socket.error, ssl.SSLError) as e:
                print(f"❌ [ERROR] {protocol.upper()} Connection Failed: {e}")
                return f"Socket error: {e}", None, None

        # Send SIP OPTIONS request
        start_time = time()
        if protocol == "udp":
            sock.sendto(sip_message.encode(), (sip_server, sip_port))
        else:
            sock.send(sip_message.encode())

        # Receive response
        data = sock.recv(1024)
        response = data.decode()
        end_time = time()
        rtime = end_time - start_time

        if verbose:
            print(f"\n📥 [INFO] Received SIP Response in {rtime:.3f}s:\n<-------\n{response}")

        # Extract SIP response code
        match = re.search(r"SIP/2\.0 (\d{3})", response.strip())
        if match:
            return int(match.group(1)), rtime, response.strip()
        else:
            return "Invalid response received", rtime, response.strip()

    except socket.timeout:
        return "Timeout: No response", None, None
    except socket.error as e:
        return f"Socket error: {e}", None, None
    finally:
        sock.close()

def main():
    parser = argparse.ArgumentParser(description="SIP OPTIONS Check (RFC 3261 Compliant)")
    parser.add_argument("sip_server", help="SIP Server IP or hostname")
    parser.add_argument("-p", "--port", type=int, default=DEFAULT_PORT, help=f"SIP Port (default: {DEFAULT_PORT})")
    parser.add_argument("-k", "--protocol", choices=["tcp", "udp", "tls"], default=DEFAULT_PROTOCOL, help=f"Transport protocol (default: {DEFAULT_PROTOCOL})")
    parser.add_argument("-t", "--timeout", type=int, default=DEFAULT_TIMEOUT, help=f"Timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("-w", "--warn", type=float, default=DEFAULT_WARN_THRESHOLD, help=f"Warning threshold in seconds (default: {DEFAULT_WARN_THRESHOLD})")
    parser.add_argument("--max-forwards", type=int, default=70, help="Max-Forwards header value (default: 70)")
    parser.add_argument("--local-ip", default="127.0.0.1", help="Local IP address for the Via header (default: 127.0.0.1)")
    parser.add_argument("-d", "--discover-srv", action="store_true", help="Discover SIP SRV record and query the resolved endpoint")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode for debugging")
    parser.add_argument("--tls-version", default=DEFAULT_TLS_VERSION, help="Explicit TLS version (TLSv1.2, TLSv1.3, etc.)")
    parser.add_argument("--cipher-suite", default=DEFAULT_CIPHER_SUITE, help="Define a specific cipher suite")


    args = parser.parse_args()

    # Initialize srv_type to None
    srv_type = None

    # Discover SRV record if requested
    if args.discover_srv:
        resolved_host, resolved_port, srv_type = discover_srv_record(args.sip_server, args.protocol, args.verbose)
        if resolved_host:
            print(f"[INFO] Discovered SIP SRV Record ({srv_type}): {resolved_host}:{resolved_port}")
            args.sip_server = resolved_host
            args.port = resolved_port
        else:
            print(f"[WARNING] No SRV record found for {args.sip_server}.")
            print("[ERROR] No valid SIP target found. Exiting.")
            sys.exit(EXIT_CODES['UNKNOWN'])

    # **Validate the SIP Server Hostname or IP**
    if not is_hostname(args.sip_server):
        print(f"[ERROR] Invalid hostname or IP: {args.sip_server}")
        sys.exit(EXIT_CODES['UNKNOWN'])

    # **Send SIP OPTIONS Request**
    sip_response, rtime, full_response = send_sip_options(
        args.sip_server, args.port, args.timeout, args.protocol, args.local_ip, 
        args.max_forwards, args.verbose, srv_type, args.tls_version, args.cipher_suite
    )

    # Evaluate response
    if isinstance(sip_response, int):
        category = SIP_RESPONSE_CATEGORIES.get(sip_response // 100, "Unknown")

        if sip_response == 200:
            if rtime > args.warn:
                print(f"SIP WARNING: {sip_response} {category} (response time: {rtime:.3f}s)")
                sys.exit(EXIT_CODES['WARNING'])
            else:
                print(f"SIP OK: {sip_response} {category} (response time: {rtime:.3f}s)")
                sys.exit(EXIT_CODES['OK'])
        elif 100 <= sip_response < 200:
            print(f"SIP WARNING: {sip_response} {category} - Provisional response, awaiting final reply.")
            sys.exit(EXIT_CODES['WARNING'])
        elif 200 <= sip_response < 300:
            print(f"SIP OK: {sip_response} {category} - Server responded successfully.")
            sys.exit(EXIT_CODES['OK'])
        elif 300 <= sip_response < 400:
            print(f"SIP WARNING: {sip_response} {category} - Redirection response received.")
            sys.exit(EXIT_CODES['WARNING'])
        elif 400 <= sip_response < 500:
            print(f"SIP CRITICAL: {sip_response} {category} - Client-side error detected.")
            sys.exit(EXIT_CODES['CRITICAL'])
        elif 500 <= sip_response < 600:
            print(f"SIP CRITICAL: {sip_response} {category} - Server-side failure.")
            sys.exit(EXIT_CODES['CRITICAL'])
        else:
            print(f"SIP CRITICAL: {sip_response} {category} - Global failure.")
            sys.exit(EXIT_CODES['CRITICAL'])
    else:
        print(f"SIP CRITICAL: {sip_response}")
        sys.exit(EXIT_CODES['CRITICAL'])

if __name__ == "__main__":
    main()