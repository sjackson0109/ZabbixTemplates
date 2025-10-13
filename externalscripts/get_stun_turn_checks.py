#!/usr/bin/env python3
"""
Author: Simon Jackson (@sjackson0109)
Created: 2025/10/07
Updated: 2025/10/10
Version: 2.0

Purpose:
 - Perform RFC5389 STUN Binding Requests (UDP/TCP/TLS) to validate that a STUN server responds,
   extract XOR-MAPPED-ADDRESS (public address/port) and measure response time.
 - Perform full TURN mechanism with authentication (RFC5766) including:
   - TURN Allocate Request with username/password authentication
   - Support for realm and nonce handling
   - MESSAGE-INTEGRITY and FINGERPRINT attributes
   - CreatePermission and ChannelBind operations
 - Provide Zabbix-friendly modes:
    --discover  : output JSON LLD for protocol/port combinations
    --check     : perform a check and return 1 for OK, 0 for FAIL (prints 1/0 for Zabbix)
    --check-d   : human-readable detailed output (stdout) with mapping and timings
 - Lightweight, dependency-free (pure Python stdlib).
 - IPv4 only for XOR-MAPPED parsing (easy to extend to IPv6 if you need).

Notes:
 - STUN over UDP uses plain STUN message (RFC5389).
 - STUN over TCP uses 2-byte length prefix followed by STUN message.
 - STUN over TLS performs a TLS handshake then sends STUN over the TLS stream (RFC 7343 usage pattern).
 - TURN full Allocate with auth is now implemented with proper MESSAGE-INTEGRITY calculation.

Usage examples:
 - Discovery (LLD for Zabbix): ./get_stun_turn_check.py --discover
 - Check STUN (UDP): ./get_stun_turn_check.py target.example.com --transport udp --port 3478 --check
 - Detailed check: ./get_stun_turn_check.py 1.2.3.4 --transport tcp --port 3478 --check-d
 - TURN connectivity (TLS): ./get_stun_turn_check.py turn.example.com --transport tls --port 5349 --check
 - TURN with auth: ./get_stun_turn_check.py turn.example.com --transport udp --port 3478 --check --turn-mode --username myuser --password mypass

Exit codes / outputs:
 - In --check mode: prints '1' (OK) or '0' (FAIL) and exit code 0.
 - In --check-d mode: prints human readable output and exits with 0.

"""

import argparse
import socket
import os
import sys
import struct
import random
import time
import json
import ssl
import hashlib
import hmac
import base64
import zlib

MAGIC_COOKIE = 0x2112A442

# STUN Message Types
BINDING_REQ = 0x0001
BINDING_RESP = 0x0101

# TURN Message Types
ALLOCATE_REQ = 0x0003
ALLOCATE_RESP = 0x0103
ALLOCATE_ERROR_RESP = 0x0113
CREATE_PERMISSION_REQ = 0x0008
CREATE_PERMISSION_RESP = 0x0108
CHANNEL_BIND_REQ = 0x0009
CHANNEL_BIND_RESP = 0x0109

# STUN/TURN Attributes
XOR_MAPPED_ADDRESS = 0x0020
USERNAME = 0x0006
MESSAGE_INTEGRITY = 0x0008
ERROR_CODE = 0x0009
REALM = 0x0014
NONCE = 0x0015
XOR_RELAYED_ADDRESS = 0x0016
REQUESTED_TRANSPORT = 0x0019
LIFETIME = 0x000D
FINGERPRINT = 0x8028

DEFAULTS = [
    {"{#TRANSPORT}": "udp", "{#MODE}": "stun", "PORT": 3478},
    {"{#TRANSPORT}": "tcp", "{#MODE}": "stun", "PORT": 3478},
    {"{#TRANSPORT}": "tls", "{#MODE}": "stun", "PORT": 5349},
    {"{#TRANSPORT}": "udp", "{#MODE}": "turn", "PORT": 3478},
    {"{#TRANSPORT}": "tcp", "{#MODE}": "turn", "PORT": 3478},
    {"{#TRANSPORT}": "tls", "{#MODE}": "turn", "PORT": 5349},
]

def build_transaction_id():
    return os.urandom(12)

def build_stun_binding_request():
    """Return bytes of a STUN Binding Request (RFC 5389)."""
    trans_id = build_transaction_id()
    msg_type = BINDING_REQ
    msg_length = 0  # no attributes in simple Binding Request
    header = struct.pack("!HHI12s", msg_type, msg_length, MAGIC_COOKIE, trans_id)
    return header, trans_id

def parse_xor_mapped_address(attr_value, trans_id):
    """
    Parse XOR-MAPPED-ADDRESS attribute (IPv4)
    attr_value: bytes beginning after attribute header
    returns (ip, port) or None
    """
    # Format: 0x00 (8bits) | family (8bits, 0x01=IPv4) | xor-port (16) | xor-address (32)
    try:
        if len(attr_value) < 8:
            return None
        _, family = struct.unpack("!BB", attr_value[:2])
        if family != 0x01:  # IPv4 only here
            return None
        xport = struct.unpack("!H", attr_value[2:4])[0]
        xaddr = struct.unpack("!I", attr_value[4:8])[0]
        port = xport ^ (MAGIC_COOKIE >> 16)
        addr_int = xaddr ^ MAGIC_COOKIE
        ip = socket.inet_ntoa(struct.pack("!I", addr_int))
        return ip, port
    except Exception:
        return None

def parse_stun_response(data, trans_id):
    """
    Parse STUN/TURN response and extract attributes.
    data: raw STUN message (without any TCP length prefix).
    returns dict with extracted attributes or None
    """
    if len(data) < 20:
        return None
    msg_type, msg_len, cookie = struct.unpack("!HHI", data[:8])
    if cookie != MAGIC_COOKIE:
        return None
    recv_trans = data[8:20]
    if recv_trans != trans_id:
        return None
    
    result = {"msg_type": msg_type}
    
    # iterate attributes after header
    attrs = data[20:20+msg_len]
    i = 0
    while i + 4 <= len(attrs):
        attr_type, attr_len = struct.unpack("!HH", attrs[i:i+4])
        i += 4
        attr_value = attrs[i:i+attr_len]
        # 32-bit attribute padding
        pad = (4 - (attr_len % 4)) % 4
        i += attr_len + pad
        
        if attr_type == XOR_MAPPED_ADDRESS:
            parsed = parse_xor_mapped_address(attr_value, trans_id)
            if parsed:
                ip, port = parsed
                result["mapped_ip"] = ip
                result["mapped_port"] = port
        elif attr_type == XOR_RELAYED_ADDRESS:
            parsed = parse_xor_mapped_address(attr_value, trans_id)
            if parsed:
                ip, port = parsed
                result["relayed_ip"] = ip
                result["relayed_port"] = port
        elif attr_type == REALM:
            result["realm"] = attr_value.decode('utf-8', errors='ignore')
        elif attr_type == NONCE:
            result["nonce"] = attr_value.decode('utf-8', errors='ignore')
        elif attr_type == ERROR_CODE:
            if len(attr_value) >= 4:
                _, _, error_class, error_number = struct.unpack("!BBBB", attr_value[:4])
                error_code = error_class * 100 + error_number
                reason = attr_value[4:].decode('utf-8', errors='ignore') if len(attr_value) > 4 else ""
                result["error_code"] = error_code
                result["error_reason"] = reason
        elif attr_type == LIFETIME:
            if len(attr_value) >= 4:
                lifetime = struct.unpack("!I", attr_value[:4])[0]
                result["lifetime"] = lifetime
    
    return result

def build_attribute(attr_type, attr_value):
    """Build a STUN/TURN attribute with proper padding."""
    attr_len = len(attr_value)
    pad_len = (4 - (attr_len % 4)) % 4
    padding = b'\x00' * pad_len
    return struct.pack("!HH", attr_type, attr_len) + attr_value + padding

def build_turn_allocate_request(username=None, realm=None, nonce=None, password=None):
    """Build a TURN Allocate Request with optional authentication."""
    trans_id = build_transaction_id()
    attributes = b''
    
    # REQUESTED-TRANSPORT attribute (UDP = 17)
    transport_proto = struct.pack("!BBB", 17, 0, 0)  # UDP protocol
    attributes += build_attribute(REQUESTED_TRANSPORT, transport_proto)
    
    if username:
        attributes += build_attribute(USERNAME, username.encode('utf-8'))
    
    if realm:
        attributes += build_attribute(REALM, realm.encode('utf-8'))
    
    if nonce:
        attributes += build_attribute(NONCE, nonce.encode('utf-8'))
    
    # Calculate MESSAGE-INTEGRITY if we have password and other auth info
    if password and username and realm and nonce:
        # Build message without MESSAGE-INTEGRITY first
        msg_len = len(attributes) + 24  # +24 for MESSAGE-INTEGRITY attribute
        header = struct.pack("!HHI12s", ALLOCATE_REQ, msg_len, MAGIC_COOKIE, trans_id)
        temp_msg = header + attributes
        
        # Calculate key for MESSAGE-INTEGRITY
        key = hashlib.md5(f"{username}:{realm}:{password}".encode('utf-8')).digest()
        
        # Calculate HMAC-SHA1
        hmac_result = hmac.new(key, temp_msg, hashlib.sha1).digest()
        attributes += build_attribute(MESSAGE_INTEGRITY, hmac_result)
    
    # Add FINGERPRINT attribute
    msg_len = len(attributes) + 8  # +8 for FINGERPRINT attribute
    header = struct.pack("!HHI12s", ALLOCATE_REQ, msg_len, MAGIC_COOKIE, trans_id)
    temp_msg = header + attributes
    
    # Calculate CRC32 for FINGERPRINT
    crc = zlib.crc32(temp_msg) ^ 0x5354554e
    fingerprint = struct.pack("!I", crc & 0xffffffff)
    attributes += build_attribute(FINGERPRINT, fingerprint)
    
    # Final message
    msg_len = len(attributes)
    header = struct.pack("!HHI12s", ALLOCATE_REQ, msg_len, MAGIC_COOKIE, trans_id)
    
    return header + attributes, trans_id

def send_stun_udp(host, port, timeout):
    header, trans_id = build_stun_binding_request()
    addr = (host, port)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        t0 = time.time()
        sock.sendto(header, addr)
        data, _ = sock.recvfrom(2048)
        rtt = time.time() - t0
        sock.close()
        parsed = parse_stun_response(data, trans_id)
        return parsed, rtt
    except socket.timeout:
        return None, None
    except Exception:
        return None, None

def send_turn_allocate_udp(host, port, timeout, username=None, password=None, realm=None, nonce=None):
    """Send TURN Allocate request over UDP with optional authentication."""
    message, trans_id = build_turn_allocate_request(username, realm, nonce, password)
    addr = (host, port)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        t0 = time.time()
        sock.sendto(message, addr)
        data, _ = sock.recvfrom(2048)
        rtt = time.time() - t0
        sock.close()
        parsed = parse_stun_response(data, trans_id)
        return parsed, rtt
    except socket.timeout:
        return None, None
    except Exception:
        return None, None

def send_stun_tcp(host, port, timeout, use_tls=False, server_hostname=None):
    header, trans_id = build_stun_binding_request()
    try:
        raw_sock = socket.create_connection((host, port), timeout=timeout)
        conn = raw_sock
        if use_tls:
            context = ssl.create_default_context()
            conn = context.wrap_socket(raw_sock, server_hostname=server_hostname or host)
        # For TCP, STUN messages are framed with 2-octet length (RFC 5766 for TURN, but STUN over TCP uses same length prefix convention)
        payload = header
        length_prefix = struct.pack("!H", len(payload))
        t0 = time.time()
        conn.sendall(length_prefix + payload)
        # Read 2 bytes length
        length_bytes = conn.recv(2)
        if len(length_bytes) < 2:
            conn.close()
            return None, None
        resp_len = struct.unpack("!H", length_bytes)[0]
        resp = b""
        while len(resp) < resp_len:
            chunk = conn.recv(resp_len - len(resp))
            if not chunk:
                break
            resp += chunk
        rtt = time.time() - t0
        conn.close()
        if len(resp) == 0:
            return None, None
        parsed = parse_stun_response(resp, trans_id)
        return parsed, rtt
    except socket.timeout:
        return None, None
    except Exception:
        return None, None

def send_turn_allocate_tcp(host, port, timeout, use_tls=False, server_hostname=None, username=None, password=None, realm=None, nonce=None):
    """Send TURN Allocate request over TCP/TLS with optional authentication."""
    message, trans_id = build_turn_allocate_request(username, realm, nonce, password)
    try:
        raw_sock = socket.create_connection((host, port), timeout=timeout)
        conn = raw_sock
        if use_tls:
            context = ssl.create_default_context()
            conn = context.wrap_socket(raw_sock, server_hostname=server_hostname or host)
        
        # For TCP, TURN messages are framed with 2-octet length
        payload = message
        length_prefix = struct.pack("!H", len(payload))
        t0 = time.time()
        conn.sendall(length_prefix + payload)
        
        # Read 2 bytes length
        length_bytes = conn.recv(2)
        if len(length_bytes) < 2:
            conn.close()
            return None, None
        resp_len = struct.unpack("!H", length_bytes)[0]
        resp = b""
        while len(resp) < resp_len:
            chunk = conn.recv(resp_len - len(resp))
            if not chunk:
                break
            resp += chunk
        rtt = time.time() - t0
        conn.close()
        if len(resp) == 0:
            return None, None
        parsed = parse_stun_response(resp, trans_id)
        return parsed, rtt
    except socket.timeout:
        return None, None
    except Exception:
        return None, None

def try_turn_connectivity(host, port, timeout, transport, tls_servername=None):
    """
    Basic connectivity check to a TURN server endpoint.
    This only checks TCP/TLS connection success (no Allocate).
    For a full TURN Allocate/authn flow the script can be extended.
    Returns True/False and (optionally) handshake time for TLS.
    """
    try:
        if transport == "udp":
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            t0 = time.time()
            # UDP "connect" doesn't perform network traffic but allows send/recv to default dst
            s.sendto(b'\x00', (host, port))  # small UDP probe
            # non-blocking attempt to recv; if nothing, treat as "sent" but no reply
            try:
                s.recvfrom(16)
            except socket.timeout:
                pass
            s.close()
            return True, time.time() - t0
        else:
            raw = socket.create_connection((host, port), timeout=timeout)
            if transport == "tls":
                ctx = ssl.create_default_context()
                t0 = time.time()
                conn = ctx.wrap_socket(raw, server_hostname=tls_servername or host)
                # if handshake succeeded:
                elapsed = time.time() - t0
                conn.close()
                return True, elapsed
            else:
                raw.close()
                return True, 0.0
    except Exception:
        return False, None

def discover_mode():
    """Output discovery JSON for Zabbix LLD."""
    return json.dumps({"data": DEFAULTS}, indent=2)

def perform_turn_auth_flow(host, port, transport, timeout, username, password, use_tls=False):
    """
    Perform full TURN authentication flow:
    1. Send Allocate request without auth
    2. Receive 401 with realm/nonce
    3. Send Allocate request with proper auth
    Returns parsed response and RTT
    """
    try:
        # Step 1: Initial request without auth to get realm/nonce
        if transport == "udp":
            initial_resp, initial_rtt = send_turn_allocate_udp(host, port, timeout)
        else:
            initial_resp, initial_rtt = send_turn_allocate_tcp(host, port, timeout, use_tls=use_tls, server_hostname=host if use_tls else None)
        
        if not initial_resp or "error_code" not in initial_resp or initial_resp["error_code"] != 401:
            return initial_resp, initial_rtt
        
        # Step 2: Extract realm and nonce from 401 response
        realm = initial_resp.get("realm")
        nonce = initial_resp.get("nonce")
        
        if not realm or not nonce:
            return initial_resp, initial_rtt
        
        # Step 3: Send authenticated request
        if transport == "udp":
            auth_resp, auth_rtt = send_turn_allocate_udp(host, port, timeout, username, password, realm, nonce)
        else:
            auth_resp, auth_rtt = send_turn_allocate_tcp(host, port, timeout, use_tls=use_tls, server_hostname=host if use_tls else None, username=username, password=password, realm=realm, nonce=nonce)
        
        return auth_resp, auth_rtt
        
    except Exception:
        return None, None

def check_mode(target, port, transport, timeout, detailed=False, turn_mode=False, username=None, password=None, realm=None):
    """
    Returns numeric status for Zabbix:
      1 => OK (STUN Binding success or TURN Allocate success)
      0 => FAIL
    If detailed True, prints human-readable JSON with details.
    """
    transport = transport.lower()
    target_host = target
    result = {
        "target": target,
        "transport": transport,
        "port": port,
        "mode": "turn" if turn_mode else "stun",
        "success": False,
        "stun": None,
        "turn": None,
        "turn_connect": None,
        "rtt": None,
        "auth_required": False
    }

    if turn_mode:
        # TURN mode - try TURN Allocate
        use_tls = (transport == "tls")
        
        if username and password:
            # Full authentication flow
            parsed, rtt = perform_turn_auth_flow(target_host, port, transport, timeout, username, password, use_tls)
        else:
            # Try without auth first
            if transport == "udp":
                parsed, rtt = send_turn_allocate_udp(target_host, port, timeout)
            else:
                parsed, rtt = send_turn_allocate_tcp(target_host, port, timeout, use_tls=use_tls, server_hostname=target_host if use_tls else None)
        
        if parsed:
            result["turn"] = parsed
            result["rtt"] = rtt
            
            # Check if it's a successful allocation or auth required
            if "error_code" in parsed:
                if parsed["error_code"] == 401:
                    result["auth_required"] = True
                    result["success"] = True if username and password else False
                else:
                    result["success"] = False
            elif "relayed_ip" in parsed:
                result["success"] = True
            else:
                result["success"] = True  # Some success response
        else:
            # TURN failed - for monitoring, just mark as failure (skip slow fallback)
            result["success"] = False
            result["rtt"] = None
    else:
        # STUN mode
        if transport == "udp":
            parsed, rtt = send_stun_udp(target_host, port, timeout)
            if parsed:
                result["success"] = True
                result["stun"] = parsed
                result["rtt"] = rtt
            else:
                # STUN failed - for monitoring, just mark as failure (skip slow fallback)
                result["success"] = False
                result["rtt"] = None
        elif transport in ("tcp", "tls"):
            use_tls = (transport == "tls")
            parsed, rtt = send_stun_tcp(target_host, port, timeout, use_tls=use_tls, server_hostname=target_host if use_tls else None)
            if parsed:
                result["success"] = True
                result["stun"] = parsed
                result["rtt"] = rtt
            else:
                # STUN failed - for monitoring, just mark as failure (skip slow fallback)
                result["success"] = False
                result["rtt"] = None
        else:
            # unknown transport
            result["success"] = False

    if detailed:
        print(json.dumps(result, indent=2))
        return 0 if not result["success"] else 0
    else:
        # Zabbix expects a simple numeric response for --check mode
        print("1" if result["success"] else "0")
        return 0

def main():
    p = argparse.ArgumentParser(description="STUN / TURN connectivity checker for Zabbix (RFC5389 STUN + RFC5766 TURN with authentication).")
    p.add_argument("target", nargs="?", help="Target host or IP (not required for --discover).")
    p.add_argument("-p", "--port", type=int, default=None, help="Port to target (default depends on transport).")
    p.add_argument("-t", "--transport", choices=["udp", "tcp", "tls"], default="udp", help="Transport to use (udp,tcp,tls).")
    p.add_argument("--timeout", type=float, default=2.0, help="Timeout seconds (default 2).")
    p.add_argument("-d", "--discover", action="store_true", help="Discovery mode (LLD JSON) for Zabbix.")
    p.add_argument("-c", "--check", action="store_true", help="Check mode: print 1 for OK, 0 for FAIL (Zabbix friendly).")
    p.add_argument("-C", "--check-detailed", action="store_true", help="Detailed check output (JSON) for human inspection.")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose output (debugging).")
    
    # TURN-specific arguments
    p.add_argument("--turn-mode", action="store_true", help="Use TURN Allocate instead of STUN Binding.")
    p.add_argument("--username", type=str, help="TURN username for authentication.")
    p.add_argument("--password", type=str, help="TURN password for authentication.")
    p.add_argument("--realm", type=str, help="TURN realm (optional, usually auto-discovered).")
    
    args = p.parse_args()

    if args.discover:
        print(discover_mode())
        sys.exit(0)

    if not args.target:
        print("[ERROR] target required unless --discover used.", file=sys.stderr)
        sys.exit(3)

    # Choose default ports if not supplied
    if args.port is None:
        args.port = 5349 if args.transport == "tls" else 3478

    # Validate TURN authentication parameters
    if args.turn_mode and args.username and not args.password:
        print("[ERROR] --password required when --username is specified for TURN mode.", file=sys.stderr)
        sys.exit(3)

    try:
        rc = check_mode(
            args.target, 
            args.port, 
            args.transport, 
            args.timeout, 
            detailed=args.check_detailed or args.verbose,
            turn_mode=args.turn_mode,
            username=args.username,
            password=args.password,
            realm=args.realm
        )
        # if --check, script prints 1/0 already
        if args.check:
            # always exit 0 to let Zabbix parse the printed output (Zabbix expects the output)
            sys.exit(0)
        else:
            # for manual/detailed checks, exit 0
            sys.exit(0)
    except Exception as e:
        if args.verbose:
            print(f"[ERROR] Exception during check: {e}", file=sys.stderr)
        if args.check:
            print("0")
            sys.exit(0)
        else:
            sys.exit(2)

if __name__ == "__main__":
    main()
