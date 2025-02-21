#!/usr/bin/env python3
# Description   : Script checks SIP_SERVER for SIP OPTIONS, compliant with RFC 3261.
# File Name     : get_sip_options.py
# Author        : Simon Jackson (@sjackson0109)
# Inspiration   : Wim Devos (@WimObiwan) early pearl work on the same topic
# Created     	: 2025/02/17
# Updated       : 2025/02/21
# Version       : 1.6

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
DEFAULT_TLS_VERSION = "TLSv1.2"
DEFAULT_CIPHER_SUITE = "CDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305"
USER_PREFIX = "sjackson0109"
USER_DOMAIN = "example.com"
USER_AGENT = "get_sip_options.py"
DNS_TIMEOUT = 3
DNS_PORT = 53
DNS_SERVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]  # Cloudflare, Google, Quad9

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

def get_source(target_host, target_port):
    """
    Determine the local IP address that would be used to connect to the target host.
    
    Args:
    target_host (str): The hostname or IP address of the target SIP server.
    target_port (int): The port number of the target SIP server.
    
    Returns:
    str: The local IP address as a string.
    """
    try:
        # Create a temporary socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Connect to the target host (note: this doesn't send any packets)
        s.connect((target_host, target_port))
        
        # Get the local IP address used for this connection
        source = s.getsockname()[0]
        
        # Close the temporary socket
        s.close()
        
        return source
    except Exception as e:
        print(f"[WARNING] Unable to determine local IP: {e}")
        # Fall back to loopback address if we can't determine the IP
        return "127.0.0.1"

def discover_srv_record(host, protocol, verbose=False, custom_dns=None):
    """
    Discover SIP SRV records, supporting both IPv4 and IPv6 targets.
    Now includes fallback DNS servers for reliability.
    
    Args:
        host (str): The SIP server hostname.
        protocol (str): Protocol ("udp", "tcp", or "tls").
        verbose (bool): Enable detailed logging.
        custom_dns (str): User-defined DNS server (optional).
    
    Returns:
        tuple: (IP address, Port, SRV query) if found, else (None, None, None).
    """

    srv_types = {
        "udp": ["_sip._udp."],  # Standard SIP over UDP
        "tcp": ["_sip._tcp.", "_sips._tcp.", "_sipfederationtls._tcp."],  # SIP over TCP, TLS, and Federation
    }

    srv_queries = srv_types.get(protocol, [])
    resolved_addresses = []  # List to store resolved IP addresses and ports
    discovered_records = []

    dns_servers = [custom_dns] if custom_dns else DNS_SERVERS

    for dns_server in dns_servers:
        for srv_prefix in srv_queries:
            srv_query = f"{srv_prefix}{host}"

        try:
            # Create a UDP socket for DNS resolution
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(DNS_TIMEOUT)

            # Generate a DNS query for the SRV record
            query_id = random.randint(0, 65535)  # Unique ID for the query
            query = build_dns_query(srv_query, query_id)

            # Send the query to the DNS server
            sock.sendto(query, (dns_server, DNS_PORT))
            response, _ = sock.recvfrom(4096)
            sock.close()

            # Parse the DNS response
            records = parse_dns_response(response, query_id, verbose)
            if verbose and records:
                print(f"[INFO] Discovered SRV records for {srv_query}: {records}")
            break #If there is at least one record, then move on.

        except socket.timeout:
            print(f"[WARNING] DNS query timed out for {srv_query}.")
            continue
        except socket.gaierror as e:
                print(f"[WARNING] Error resolving DNS server {dns_server}: {e}")
                continue
        except Exception as e:
            print(f"[ERROR] An unexpected error occurred during DNS resolution: {e}")
            continue #Try the next DNS Server if possible

    # Sort by priority (lowest first), then by weight (highest first)
    discovered_records.sort(key=lambda x: (x[0], -x[1]))

    # Resolve IP addresses for all discovered targets
    for priority, weight, port, target in discovered_records:
        try:
            addr_info = socket.getaddrinfo(target, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
            for res in addr_info:
                family, _, _, _, sockaddr = res
                ip_address = sockaddr[0]
                resolved_addresses.append((ip_address, port))  # Append to the list
                if verbose:
                    if family == socket.AF_INET6:
                        print(f"🌍[INFO] Resolved IPv6 Address: {ip_address}:{port} for {target}")
                    else:
                        print(f"🌎[INFO] Resolved IPv4 Address: {ip_address}:{port} for {target}")
        except socket.gaierror:
            print(f"[WARNING] SRV target {target} does not resolve.")
        except Exception as e:
            print(f"[ERROR] An unexpected error occurred during address resolution: {e}")

    if not resolved_addresses:
        print("[WARNING] No resolvable SRV records found.")
        return [], None

    return resolved_addresses, srv_query

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
            # Validate that data_len is greater or equal to 6
            if data_len >= 6:
                offset += data_len - 6  # Move to the next record
            else:
                print(f"[WARNING] data_len is less than 6. Skipping record")

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
    try:
        socket.getaddrinfo(host, None)
        return True
    except socket.gaierror:
        return False


# TLS Version Mapping
TLS_VERSIONS = {
    "TLSv1.2": ssl.PROTOCOL_TLSv1_2,
    "TLSv1.3": getattr(ssl, "PROTOCOL_TLSv1_3", ssl.PROTOCOL_TLSv1_2)  # Fallback to TLSv1.2 if TLSv1.3 is unavailable
}

def create_ssl_context(tls_version="TLSv1.2", cipher_suite=None, verbose=False):
    """
    Create an SSL context with an explicit TLS version and optional cipher suite.
    If no cipher suite is specified, the system defaults will be used.
    
    Args:
        tls_version (str): The TLS version to use (e.g., "TLSv1.2", "TLSv1.3").
        cipher_suite (str, optional): The cipher suite to enforce. If None, system defaults are used.
        verbose (bool): Enable verbose output.

    Returns:
        ssl.SSLContext: Configured SSL context.
    """
    if tls_version not in TLS_VERSIONS and tls_version != "auto":
        print(f"[ERROR] Invalid TLS version specified: {tls_version}")
        sys.exit(EXIT_CODES['UNKNOWN'])

    # Create a secure default context
    context = ssl.create_default_context()

    # Override TLS version if specified
    if tls_version != "auto":
        context = ssl.SSLContext(TLS_VERSIONS[tls_version])

    # Apply cipher suite only if explicitly provided
    if cipher_suite:
        try:
            context.set_ciphers(cipher_suite)
            if verbose:
                print(f"🔒 [INFO] Using custom cipher suite: {cipher_suite}")
        except ssl.SSLError as e:
            print(f"[ERROR] Invalid cipher suite: {cipher_suite}. {e}")
            sys.exit(EXIT_CODES['UNKNOWN'])

    return context


def send_sip_options(sip_server, sip_port, timeout, protocol="udp", 
                     max_forwards=70, verbose=False, srv_type=None, 
                     tls_version=None, cipher_suite=None, user_agent=USER_AGENT, 
                     source="auto-detect",from_header="auto-detect"):

    """Send a SIP OPTIONS request and return the response code and response time, supporting IPv6 and TLS."""

    # Determine the appropriate source IP/fqdn
    if source == "auto-detect":
        try:
            source = get_source(sip_server, sip_port)
        except Exception as e:
            source = "::1" if socket.has_ipv6 else "127.0.0.1"
            print(f"[WARNING] Unable to determine Source IP dynamically (using NIC attributes), falling back to {source}: {e}")

    if from_header == "auto-detect":
        try:
            from_header=f"{USER_PREFIX}@{USER_DOMAIN}"
        except Exception as e:
            print(f"[WARNING] Unable to determine from field {from_header}: {e}")

    # Use an ephemeral port assigned by the OS
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM) as temp_sock:
            temp_sock.bind(('', 0))  # Bind to an available ephemeral port
            local_port = temp_sock.getsockname()[1]  # Retrieve the assigned port
    except Exception as e:
        print(f"[WARNING] Unable to determine local ephemeral port, using default 5060: {e}")
        local_port = 5060  # Fallback

    branch_id = f"z9hG4bK-{random.randint(100000, 999999)}"
    call_id = str(uuid.uuid4())
    user_agent = user_agent if user_agent and isinstance(user_agent, str) else USER_AGENT

    sip_message = (
        f"OPTIONS sip:{sip_server} SIP/2.0\r\n"
        f"Via: SIP/2.0/{protocol.upper()} {source}:{sip_port};branch={branch_id}\r\n"
        f"From: <sip:{from_header}>\r\n"
        f"To: <sip:{sip_server}>\r\n"
        f"Call-Id: {call_id}\r\n"
        f"CSeq: 1 OPTIONS\r\n"
        f"Contact: <sip:{USER_PREFIX}@{source}>\r\n"
        f"Max-Forwards: {max_forwards}\r\n"
        f"User-Agent: {user_agent}\r\n"
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
                try:
                    context.set_ciphers(cipher_suite)
                except ssl.SSLError as e:
                    error_message = f"❌ [ERROR] Invalid cipher suite: {cipher_suite}. {e}"
                    return error_message, None, None

            sock = context.wrap_socket(sock, server_hostname=sip_server)

        # Print SIP OPTIONS request BEFORE attempting a connection
        if verbose:
            print(f"\n📤 [INFO] Sending SIP OPTIONS Request ({protocol.upper()}):\n------->\n{sip_message}")

        if protocol in ["tcp", "tls"]:
            try:
                sock.connect((sip_server, sip_port))
                print(f"✅ [INFO] {protocol.upper()} connection established to {sip_server}:{sip_port}")
            except socket.gaierror as e:
                error_message = f"❌ [ERROR] DNS resolution error: {e}"
                return error_message, None, None
            except ConnectionRefusedError as e:
                error_message = f"❌ [ERROR] Connection refused: {e}"
                return error_message, None, None
            except socket.timeout:
                 error_message = "❌ [ERROR] Connection timed out"
                 return error_message, None, None
            except OSError as e:
                error_message = f"❌ [ERROR] OS error: {e}"
                return error_message, None, None
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
            return f"Invalid response: {response.strip()}", rtime, response.strip()

    except socket.timeout:
        return "Timeout: No response", None, None
    except socket.error as e:
        return f"Socket error: {e}", None, None
    finally:
        if 'sock' in locals() and sock:
            sock.close()


def main():
    parser = argparse.ArgumentParser(description="SIP OPTIONS Check (RFC 3261 Compliant)")
    parser.add_argument("sip_server", help="SIP Server IP or hostname")
    parser.add_argument("-d", "--discover", action="store_true", help="[Optional] Discover a SIP SRV record and query the resolved endpoint")
    parser.add_argument("-k", "--protocol", choices=["udp", "tcp", "tls"], default="udp", help=f"[Optional] Transport protocol (default: udp)")
    parser.add_argument("-p", "--port", type=int, default=5060, help=f"[Optional] SIP Port (default: 5060)")
    parser.add_argument("-f", "--from_header", type=str, default="auto-detect", help=f"[Optional] FROM field (default: auto-detect)")
    parser.add_argument("-u", "--user-agent", type=str, default=USER_AGENT, help=f"[Optional] Custom User-Agent string (default: {USER_AGENT})")
    parser.add_argument("-s", "--source", default="auto-detect", help="[Optional] Source IP-Address/FQDN used in the SIP Via header (default: auto-detect)")
    parser.add_argument("-t", "--timeout", type=int, default=100, help=f"[Optional] Timeout in seconds (default: 100)")
    parser.add_argument("-w", "--warn", type=float, default=5, help=f"[Optional] Warning threshold in seconds (default: 5)")
    parser.add_argument("-v", "--verbose", action="store_true", help=f"[Optional] Enable verbose mode for debugging")
    parser.add_argument("-m", "--max-forwards", type=int, default=70, help=f"[Optional] Max-Forwards header value (default: 70)")
    parser.add_argument("--tls-version", default=DEFAULT_TLS_VERSION, help=f"[Optional] specific TLS version [TLSv1.1, TLSv1.2, TLSv1.3, etc.] (default: negotiate tls)")
    parser.add_argument("--cipher-suite", default=DEFAULT_CIPHER_SUITE, help=f"[Optional] specific cipher suite (default: negotiate cipher suite)")

    args = parser.parse_args()

    # Initialize srv_type to None
    srv_type = None

    # Discover SRV record if requested
    if args.discover:
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
        sip_server=args.sip_server,
        sip_port=args.port,
        timeout=args.timeout,
        protocol=args.protocol,
        max_forwards=args.max_forwards,
        verbose=args.verbose,
        srv_type=srv_type,
        tls_version=args.tls_version,
        cipher_suite=args.cipher_suite,
        user_agent=args.user_agent,
        source=args.source,
        from_header=args.from_header
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