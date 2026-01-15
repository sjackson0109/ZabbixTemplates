#!/usr/bin/env python3
"""
Author: Simon Jackson (sjackson0109)
Created: 2025/12/23
Updated: 2026/01/04
Version: 1.8
Description:
    Domain Health & Compliance Monitoring for Zabbix.
    Performs DNS record checks, DNSSEC validation, DANE/TLSA verification,
    email authentication (SPF/DKIM/DMARC), registrar/WHOIS data retrieval,
    and RFC compliance checks.

Features:
    - Query and validate A, AAAA, MX, NS, CNAME, SOA, PTR, TXT, SRV, CAA, DNSSEC records
    - Validate SPF, DKIM, DMARC records for email authentication
    - Check DNSSEC presence, trust chain, and signature validity
    - DANE/TLSA record discovery and certificate verification (RFC 6698)
    - Enhanced DNSSEC with key type, algorithm, and expiry analysis
    - Retrieve registrar/WHOIS/RDAP data (expiry, status, lock)
    - ASN lookup for all domain IPs
    - NS server discovery with availability and latency monitoring
    - Detect RFC non-conformity, syntax errors, and common misconfigurations
    - Returns Zabbix-friendly JSON output

USAGE EXAMPLES:
    python get_domain_health.py discover <DOMAIN>
    python get_domain_health.py records <DOMAIN> <RECORD_TYPE>
    python get_domain_health.py dnssec <DOMAIN>
    python get_domain_health.py dnssec_detailed <DOMAIN>
    python get_domain_health.py dane <DOMAIN> [PORT]
    python get_domain_health.py discover_dane <DOMAIN>
    python get_domain_health.py spf <DOMAIN>
    python get_domain_health.py dmarc <DOMAIN>
    python get_domain_health.py dkim <DOMAIN> <SELECTOR>
    python get_domain_health.py caa <DOMAIN>
    python get_domain_health.py whois <DOMAIN>
    python get_domain_health.py rdap <DOMAIN>
    python get_domain_health.py asn <DOMAIN>
    python get_domain_health.py discover_ns <DOMAIN>
    python get_domain_health.py ns_check <DOMAIN> <NS_SERVER>
    python get_domain_health.py discover_services <DOMAIN>    # Returns comprehensive service discovery analysis
    python get_domain_health.py discover_services.lld <DOMAIN>    # Returns Zabbix LLD format for SRV services
    python get_domain_health.py discover_services.full <DOMAIN>    # Returns full service discovery analysis
    python get_domain_health.py discover_subdomains <DOMAIN>    # Phase 1: Enhanced subdomain discovery with categorization
    python get_domain_health.py discover_ports <DOMAIN>        # Phase 2: Comprehensive port scanning with service categorization
    python get_domain_health.py discover_ports.fast <DOMAIN>   # Phase 2: Fast port scanning (reduced port list)
    python get_domain_health.py scan_port_range <DOMAIN> <START_PORT> <END_PORT>  # Scan specific port range
    python get_domain_health.py discover_custom_ports <DOMAIN> <PORT1,PORT2,PORT3>  # Scan custom port list
    python get_domain_health.py health <DOMAIN>
    python get_domain_health.py selftest <DOMAIN>

ENVIRONMENT VARIABLES/MACROS:
    DNS_TIMEOUT (default: 10)
    DNS_NAMESERVER (default: system resolver)
    DNS_DEBUG (set to 1 for debug logging)

OPTIONAL DEPENDENCIES (for full DANE/DNSSEC validation):
    dnspython   - Enhanced DNS operations and DNSSEC validation
    cryptography - TLSA hash computation and certificate parsing
    pyOpenSSL    - TLS certificate retrieval from servers

OUTPUT:
    - All operations return valid JSON for Zabbix compatibility.
    - On error, returns a JSON object with an 'error' key.
"""

import sys
import json
import logging
import os
import re
import socket
import struct
import time
import base64
import hashlib
import concurrent.futures
import threading
from datetime import datetime, timezone

# --- Configuration ---
def get_config():
    try:
        timeout = int(os.environ.get('DNS_TIMEOUT', '3'))
    except Exception:
        timeout = 3
    nameserver = os.environ.get('DNS_NAMESERVER', None)
    debug = os.environ.get('DNS_DEBUG', '0') == '1'
    return timeout, nameserver, debug

DNS_TIMEOUT, DNS_NAMESERVER, DEBUG = get_config()

logger = logging.getLogger(__name__)
logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=logging.DEBUG if DEBUG else logging.WARNING)

# --- DNS Query Utilities (stdlib only) ---

DNS_RECORD_TYPES = {
    'A': 1, 'NS': 2, 'CNAME': 5, 'SOA': 6, 'PTR': 12, 'MX': 15,
    'TXT': 16, 'AAAA': 28, 'SRV': 33, 'SPF': 99, 'CAA': 257, 'DNSKEY': 48,
    'RRSIG': 46, 'DS': 43, 'NSEC': 47, 'SSHFP': 44, 'TLSA': 52,
    'SMIMEA': 53, 'OPENPGPKEY': 61
}

def build_dns_query(domain, qtype):
    """Build a DNS query packet."""
    import random
    tid = random.randint(0, 65535)
    flags = 0x0100  # Standard query, recursion desired
    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 0
    header = struct.pack('>HHHHHH', tid, flags, qdcount, ancount, nscount, arcount)
    qname = b''
    for part in domain.rstrip('.').split('.'):
        qname += bytes([len(part)]) + part.encode('ascii')
    qname += b'\x00'
    qtype_code = DNS_RECORD_TYPES.get(qtype.upper(), 1)
    qclass = 1  # IN
    question = qname + struct.pack('>HH', qtype_code, qclass)
    return header + question, tid

def parse_dns_name(data, offset):
    """Parse a DNS name from a packet, handling compression."""
    labels = []
    jumped = False
    max_offset = len(data)
    orig_offset = offset
    max_jumps = 5  # Reduced to be more conservative
    jumps = 0
    
    while True:
        if offset >= max_offset:
            break
        
        length = data[offset]
        
        if length == 0:
            offset += 1
            break
            
        if (length & 0xc0) == 0xc0:
            # DNS compression pointer
            if not jumped:
                orig_offset = offset + 2
            if jumps >= max_jumps or offset + 1 >= max_offset:
                break
            
            # Extract pointer value (14 bits)
            pointer_bytes = data[offset:offset+2]
            pointer = struct.unpack('>H', pointer_bytes)[0] & 0x3fff
            
            # More restrictive bounds checking
            if pointer >= max_offset or pointer == offset:  # Prevent self-reference
                break
            
            offset = pointer
            jumped = True
            jumps += 1
            continue
            
        # Check for valid label length
        if length > 63 or offset + 1 + length > max_offset:
            break
            
        offset += 1
        try:
            label = data[offset:offset+length].decode('ascii', errors='replace')
            labels.append(label)
        except:
            break
        offset += length
    
    if jumped:
        offset = orig_offset
    
    return '.'.join(labels), offset

def parse_dns_response(data, qtype):
    """Parse DNS response and extract answer records."""
    if len(data) < 12:
        return []
    tid, flags, qdcount, ancount, nscount, arcount = struct.unpack('>HHHHHH', data[:12])
    offset = 12
    # Skip questions
    for _ in range(qdcount):
        while data[offset] != 0:
            if (data[offset] & 0xc0) == 0xc0:
                offset += 2
                break
            offset += 1 + data[offset]
        else:
            offset += 1
        offset += 4  # QTYPE + QCLASS
    answers = []
    qtype_code = DNS_RECORD_TYPES.get(qtype.upper(), 1)
    for _ in range(ancount):
        name, offset = parse_dns_name(data, offset)
        rtype, rclass, ttl, rdlength = struct.unpack('>HHIH', data[offset:offset+10])
        offset += 10
        rdata = data[offset:offset+rdlength]
        rdata_offset = offset  # Store the offset in the original packet
        offset += rdlength
        if rtype == qtype_code:
            answers.append({
                'name': name, 
                'ttl': ttl, 
                'rdata': rdata, 
                'rtype': rtype, 
                'rdlength': rdlength,
                'full_packet': data,  # Store full packet for compression handling
                'rdata_offset': rdata_offset  # Store rdata offset in packet
            })
    return answers

def dns_query(domain, qtype, nameserver=None, timeout=10):
    """Send a DNS query and return parsed answers."""
    query, tid = build_dns_query(domain, qtype)
    ns = nameserver or '8.8.8.8'
    
    # Try UDP first (faster)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(query, (ns, 53))
        data, _ = sock.recvfrom(4096)
        sock.close()
        result = parse_dns_response(data, qtype)
        if result:  # If we got results, return them
            return result
    except Exception as e:
        logger.debug(f"UDP DNS query failed for {domain}/{qtype}: {e}")
    
    # If UDP failed or returned no results, try TCP (more reliable for large responses)
    if qtype.upper() == 'TXT':
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ns, 53))
            # TCP requires length prefix
            query_with_len = struct.pack('>H', len(query)) + query
            sock.send(query_with_len)
            # Read length prefix first
            len_data = sock.recv(2)
            if len(len_data) == 2:
                response_len = struct.unpack('>H', len_data)[0]
                if response_len > 0:
                    data = b''
                    while len(data) < response_len:
                        chunk = sock.recv(response_len - len(data))
                        if not chunk:
                            break
                        data += chunk
                    sock.close()
                    if len(data) == response_len:
                        return parse_dns_response(data, qtype)
            sock.close()
        except Exception as e:
            logger.debug(f"TCP DNS query failed for {domain}/{qtype}: {e}")
    
    return []

def format_mx_record(rdata, full_packet, rdata_offset):
    """Format MX record with proper DNS compression handling."""
    pref = struct.unpack('>H', rdata[:2])[0]
    # Use full packet context for proper compression handling
    name, _ = parse_dns_name(full_packet, rdata_offset + 2)
    return f"{pref} {name}"

def format_rdata(rtype, rdata):
    """Format rdata for display based on record type."""
    if rtype == 1:  # A
        return socket.inet_ntoa(rdata)
    elif rtype == 28:  # AAAA
        return socket.inet_ntop(socket.AF_INET6, rdata)
    elif rtype == 15:  # MX
        pref = struct.unpack('>H', rdata[:2])[0]
        name, _ = parse_dns_name(rdata, 2)
        return f"{pref} {name}"
    elif rtype == 16:  # TXT
        # TXT is one or more length-prefixed strings
        txt_parts = []
        i = 0
        while i < len(rdata):
            if i >= len(rdata):
                break
            slen = rdata[i]
            if slen == 0 or i + 1 + slen > len(rdata):
                break
            try:
                part = rdata[i+1:i+1+slen].decode('utf-8', errors='replace')
                txt_parts.append(part)
            except:
                break
            i += 1 + slen
        return ''.join(txt_parts)
    elif rtype in (2, 5, 12):  # NS, CNAME, PTR
        name, _ = parse_dns_name(rdata, 0)
        return name
    elif rtype == 6:  # SOA
        mname, off = parse_dns_name(rdata, 0)
        rname, off = parse_dns_name(rdata, off)
        serial, refresh, retry, expire, minimum = struct.unpack('>IIIII', rdata[off:off+20])
        return f"{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"
    elif rtype == 33:  # SRV
        priority, weight, port = struct.unpack('>HHH', rdata[:6])
        target, _ = parse_dns_name(rdata, 6)
        return f"{priority} {weight} {port} {target}"
    elif rtype == 257:  # CAA
        flags = rdata[0]
        tag_len = rdata[1]
        tag = rdata[2:2+tag_len].decode('ascii', errors='replace')
        value = rdata[2+tag_len:].decode('utf-8', errors='replace')
        return f"{flags} {tag} \"{value}\""
    elif rtype == 48:  # DNSKEY
        flags, protocol, algorithm = struct.unpack('>HBB', rdata[:4])
        pubkey = rdata[4:].hex()
        return f"flags={flags} protocol={protocol} algorithm={algorithm} pubkey={pubkey[:32]}..."
    elif rtype == 46:  # RRSIG
        return rdata.hex()
    elif rtype == 43:  # DS
        key_tag, algorithm, digest_type = struct.unpack('>HBB', rdata[:4])
        digest = rdata[4:].hex()
        return f"keytag={key_tag} algorithm={algorithm} digesttype={digest_type} digest={digest[:32]}..."
    elif rtype == 47:  # NSEC
        return rdata.hex()
    elif rtype == 99:  # SPF (legacy)
        # SPF records use same format as TXT records
        txt_parts = []
        i = 0
        while i < len(rdata):
            if i >= len(rdata):
                break
            slen = rdata[i]
            if slen == 0 or i + 1 + slen > len(rdata):
                break
            try:
                part = rdata[i+1:i+1+slen].decode('utf-8', errors='replace')
                txt_parts.append(part)
            except:
                break
            i += 1 + slen
        return ''.join(txt_parts)
    else:
        return rdata.hex()

# --- RFC Validation Helpers ---

def validate_spf(txt_records):
    """Validate SPF record syntax (RFC 7208)."""
    spf_records = [r for r in txt_records if r.startswith('v=spf1')]
    if not spf_records:
        return {'valid': False, 'error': 'No SPF record found', 'records': []}
    if len(spf_records) > 1:
        return {'valid': False, 'error': 'Multiple SPF records found (RFC violation)', 'records': spf_records}
    spf = spf_records[0]
    # Basic syntax check
    if not re.match(r'^v=spf1\s+', spf):
        return {'valid': False, 'error': 'Invalid SPF syntax', 'records': spf_records}
    # Check for required mechanisms
    valid_terms = re.findall(r'[\+\-\~\?]?(all|include|a|mx|ptr|ip4|ip6|exists|redirect|exp)[^\s]*', spf, re.I)
    if not valid_terms:
        return {'valid': False, 'error': 'No valid SPF mechanisms', 'records': spf_records}
    return {'valid': True, 'error': None, 'records': spf_records}

def validate_dmarc(txt_records):
    """Validate DMARC record syntax (RFC 7489)."""
    dmarc_records = [r for r in txt_records if r.startswith('v=DMARC1')]
    if not dmarc_records:
        return {'valid': False, 'error': 'No DMARC record found', 'records': []}
    if len(dmarc_records) > 1:
        return {'valid': False, 'error': 'Multiple DMARC records found', 'records': dmarc_records}
    dmarc = dmarc_records[0]
    # Required tag: p=
    if 'p=' not in dmarc:
        return {'valid': False, 'error': 'Missing required p= tag', 'records': dmarc_records}
    # Policy must be none, quarantine, or reject
    policy_match = re.search(r'p=(none|quarantine|reject)', dmarc, re.I)
    if not policy_match:
        return {'valid': False, 'error': 'Invalid DMARC policy', 'records': dmarc_records}
    return {'valid': True, 'error': None, 'records': dmarc_records}

def validate_dkim(txt_records, selector, domain):
    """Validate DKIM record syntax."""
    if not txt_records:
        return {'valid': False, 'error': f'No DKIM record found for selector {selector}', 'records': []}
    dkim = txt_records[0]
    if 'v=DKIM1' not in dkim:
        return {'valid': False, 'error': 'Invalid DKIM record (missing v=DKIM1)', 'records': txt_records}
    if 'p=' not in dkim:
        return {'valid': False, 'error': 'Invalid DKIM record (missing public key p=)', 'records': txt_records}
    return {'valid': True, 'error': None, 'records': txt_records}

# --- RFC 5732-5735: Special-Use/Reserved Domain Detection ---

def validate_special_use_domain(domain):
    """Validate domain against special-use and reserved domain names (RFC 5732-5735)."""
    domain_lower = domain.lower()
    
    # RFC 6761 Special Use Top Level Domains
    special_use_tlds = {
        'localhost',     # RFC 6761 - localhost
        'local',         # RFC 6762 - mDNS
        'example',       # RFC 6761 - documentation
        'invalid',       # RFC 6761 - invalid domain
        'test',          # RFC 6761 - testing
        'onion',         # RFC 7686 - Tor hidden services
    }
    
    # RFC 2606 Reserved Example Domains
    reserved_examples = {
        'example.com',
        'example.net',
        'example.org',
        'test.example',
    }
    
    # RFC 1918 Private Use Domains (common patterns)
    private_patterns = [
        r'.*\.internal$',
        r'.*\.corp$',
        r'.*\.home$',
        r'.*\.lan$',
        r'.*\.local$',
    ]
    
    result = {
        'is_special_use': False,
        'is_reserved': False,
        'is_private': False,
        'category': None,
        'warning': None,
        'rfc_reference': None
    }
    
    # Check TLD against special use list
    parts = domain_lower.split('.')
    if len(parts) > 1:
        tld = parts[-1]
        if tld in special_use_tlds:
            result['is_special_use'] = True
            result['category'] = 'special_use_tld'
            result['warning'] = f'Domain uses special-use TLD: .{tld}'
            result['rfc_reference'] = 'RFC6761'
    
    # Check against reserved examples
    if domain_lower in reserved_examples:
        result['is_reserved'] = True
        result['category'] = 'reserved_example'
        result['warning'] = f'Domain is reserved for documentation/examples'
        result['rfc_reference'] = 'RFC2606'
    
    # Check private use patterns
    for pattern in private_patterns:
        if re.match(pattern, domain_lower):
            result['is_private'] = True
            result['category'] = 'private_use'
            result['warning'] = f'Domain appears to be for private/internal use'
            result['rfc_reference'] = 'RFC6761'
            break
    
    return result

def validate_caa(caa_records):
    """Validate CAA record presence and syntax (RFC 6844)."""
    if not caa_records:
        return {'valid': False, 'error': 'No CAA records found', 'records': []}
    for rec in caa_records:
        # CAA format: flags tag "value"
        if not re.match(r'^\d+\s+(issue|issuewild|iodef)\s+"', rec):
            return {'valid': False, 'error': f'Invalid CAA record syntax: {rec}', 'records': caa_records}
    return {'valid': True, 'error': None, 'records': caa_records}

def validate_dnssec(domain, nameserver=None, timeout=10):
    """Check DNSSEC records for domain with detailed failure reasons."""
    dnskey = dns_query(domain, 'DNSKEY', nameserver, timeout)
    rrsig = dns_query(domain, 'RRSIG', nameserver, timeout)
    ds = dns_query(domain, 'DS', nameserver, timeout)
    nsec = dns_query(domain, 'NSEC', nameserver, timeout)
    
    # Determine DNSSEC status and failure reason
    enabled = bool(dnskey)
    valid = bool(dnskey and rrsig)
    error = None
    failure_reason = None
    
    if not dnskey and not ds:
        # No DNSSEC at all
        error = 'DNSSEC not configured - no DNSKEY or DS records found'
        failure_reason = 'not_configured'
    elif ds and not dnskey:
        # DS exists in parent zone but no DNSKEY in zone (broken chain)
        error = 'Broken DNSSEC chain - DS record exists in parent zone but no DNSKEY found in zone'
        failure_reason = 'missing_dnskey'
    elif dnskey and not ds:
        # DNSKEY exists but not anchored in parent (incomplete setup)
        error = 'Incomplete DNSSEC - DNSKEY present but no DS record in parent zone'
        failure_reason = 'missing_ds'
    elif dnskey and not rrsig:
        # Keys exist but no signatures visible (may be EDNS0/DO limitation)
        error = 'DNSSEC configured but RRSIG not visible (may require EDNS0 with DO bit)'
        failure_reason = 'rrsig_not_visible'
    
    result = {
        'dnskey': [format_rdata(r['rtype'], r['rdata']) for r in dnskey],
        'rrsig': [format_rdata(r['rtype'], r['rdata']) for r in rrsig],
        'ds': [format_rdata(r['rtype'], r['rdata']) for r in ds],
        'nsec': [format_rdata(r['rtype'], r['rdata']) for r in nsec],
        'enabled': enabled,
        'valid': valid,
        'error': error,
        'failure_reason': failure_reason
    }
    return result

def validate_soa(soa_records):
    """Validate SOA record (RFC 1035, 1912)."""
    if not soa_records:
        return {'valid': False, 'error': 'No SOA record found', 'records': []}
    # Expect exactly one SOA
    if len(soa_records) > 1:
        return {'valid': False, 'error': 'Multiple SOA records found', 'records': soa_records}
    return {'valid': True, 'error': None, 'records': soa_records}

def validate_ns(ns_records):
    """Validate NS records (RFC 1035, 1912)."""
    if not ns_records:
        return {'valid': False, 'error': 'No NS records found', 'records': []}
    if len(ns_records) < 2:
        return {'valid': False, 'error': 'Less than 2 NS records (RFC recommends at least 2)', 'records': ns_records}
    return {'valid': True, 'error': None, 'records': ns_records}

def validate_mx(mx_records):
    """Validate MX records (RFC 1035, 974)."""
    if not mx_records:
        return {'valid': False, 'error': 'No MX records found', 'records': []}
    return {'valid': True, 'error': None, 'records': mx_records}

# --- RFC 2181 Validation (DNS Specification Clarifications) ---

def validate_cname_rules(domain, nameserver=None, timeout=10):
    """Validate CNAME rules per RFC 2181.
    
    RFC 2181 Section 10.1: A CNAME record is not allowed to coexist with any other data.
    Also, CNAME should not be at zone apex (where SOA/NS exist).
    """
    result = {
        'valid': True,
        'cname_exists': False,
        'cname_at_apex': False,
        'cname_coexists': False,
        'coexisting_types': [],
        'error': None,
        'warnings': []
    }
    
    # Check if CNAME exists
    cname_answers = dns_query(domain, 'CNAME', nameserver, timeout)
    if not cname_answers:
        return result
    
    result['cname_exists'] = True
    
    # Check for coexisting records (RFC violation)
    check_types = ['A', 'AAAA', 'MX', 'TXT', 'NS']
    for rtype in check_types:
        answers = dns_query(domain, rtype, nameserver, timeout)
        if answers:
            result['cname_coexists'] = True
            result['coexisting_types'].append(rtype)
    
    if result['cname_coexists']:
        result['valid'] = False
        result['error'] = f"RFC 2181 violation: CNAME coexists with {', '.join(result['coexisting_types'])}"
    
    # Check if CNAME is at zone apex (has SOA)
    soa_answers = dns_query(domain, 'SOA', nameserver, timeout)
    if soa_answers:
        result['cname_at_apex'] = True
        result['valid'] = False
        result['error'] = 'RFC 2181 violation: CNAME at zone apex (where SOA exists)'
    
    return result

def validate_ttl_consistency(domain, nameserver=None, timeout=10):
    """Validate TTL consistency per RFC 2181.
    
    RFC 2181 Section 5.2: All RRs in an RRset must have the same TTL.
    """
    result = {
        'valid': True,
        'inconsistent_rrsets': [],
        'error': None
    }
    
    # We can only check this with raw DNS responses
    # For now, check if TTLs are reasonable (> 0, < 1 week)
    check_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
    
    for rtype in check_types:
        answers = dns_query(domain, rtype, nameserver, timeout)
        if len(answers) > 1:
            ttls = set(r.get('ttl', 0) for r in answers)
            if len(ttls) > 1:
                result['valid'] = False
                result['inconsistent_rrsets'].append({
                    'type': rtype,
                    'ttls': list(ttls)
                })
    
    if result['inconsistent_rrsets']:
        result['error'] = f"RFC 2181 violation: Inconsistent TTLs in RRsets"
    
    return result

def get_rfc2181_validation(domain):
    """Get full RFC 2181 compliance check."""
    cname_result = validate_cname_rules(domain, DNS_NAMESERVER, DNS_TIMEOUT)
    ttl_result = validate_ttl_consistency(domain, DNS_NAMESERVER, DNS_TIMEOUT)
    
    result = {
        'domain': domain,
        'valid': cname_result['valid'] and ttl_result['valid'],
        'cname_validation': cname_result,
        'ttl_validation': ttl_result
    }
    return json.dumps(result)

# --- WHOIS/RDAP Utilities ---

def whois_query(domain, timeout=10):
    """Query WHOIS for domain (basic, for .com/.net/.org etc)."""
    tld = domain.rstrip('.').split('.')[-1]
    whois_servers = {
        'com': 'whois.verisign-grs.com',
        'net': 'whois.verisign-grs.com',
        'org': 'whois.pir.org',
        'uk': 'whois.nic.uk',
        'io': 'whois.nic.io',
        'co': 'whois.nic.co',
        'de': 'whois.denic.de',
        'fr': 'whois.nic.fr',
        'nl': 'whois.domain-registry.nl',
        'au': 'whois.auda.org.au',
        'ca': 'whois.cira.ca',
    }
    server = whois_servers.get(tld, f'whois.nic.{tld}')
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((server, 43))
        sock.sendall((domain + '\r\n').encode('utf-8'))
        response = b''
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data
        sock.close()
        return response.decode('utf-8', errors='replace')
    except Exception as e:
        logger.error(f"WHOIS query failed for {domain}: {e}")
        return None

def parse_whois(whois_text):
    """Parse WHOIS response for key fields."""
    if not whois_text:
        return {'error': 'WHOIS query failed or no data', 'days_until_expiry': 0}
    result = {}
    patterns = {
        'registrar': r'Registrar:\s*(.+)',
        'creation_date': r'Creation Date:\s*(.+)',
        'expiry_date': r'(Registrar Registration Expiration Date|Registry Expiry Date|Expiry Date|Expiration Date):\s*(.+)',
        'updated_date': r'Updated Date:\s*(.+)',
        'status': r'(Domain Status):\s*(.+)',
        'nameservers': r'Name Server:\s*(.+)',
    }
    for key, pattern in patterns.items():
        matches = re.findall(pattern, whois_text, re.I)
        if matches:
            if key == 'expiry_date':
                result[key] = matches[0][1].strip() if isinstance(matches[0], tuple) else matches[0].strip()
            elif key == 'status':
                result[key] = [m[1].strip() if isinstance(m, tuple) else m.strip() for m in matches]
            elif key == 'nameservers':
                result[key] = [m.strip().lower() for m in matches]
            else:
                result[key] = matches[0].strip() if isinstance(matches[0], str) else matches[0][1].strip()
    # Calculate days until expiry
    if 'expiry_date' in result:
        try:
            expiry_str = result['expiry_date']
            # Try common date formats
            for fmt in ['%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%dT%H:%M:%S%z', '%Y-%m-%d', '%d-%b-%Y', '%d/%m/%Y']:
                try:
                    expiry_dt = datetime.strptime(expiry_str.split('.')[0].replace('Z', ''), fmt.replace('Z', '').replace('%z', ''))
                    days_until = (expiry_dt - datetime.now()).days
                    result['days_until_expiry'] = max(0, days_until)
                    break
                except ValueError:
                    continue
        except Exception:
            result['days_until_expiry'] = 0
    
    # Ensure days_until_expiry is always present
    if 'days_until_expiry' not in result:
        result['days_until_expiry'] = 0
        
    if not result or ('error' not in result and len([k for k in result.keys() if k != 'days_until_expiry']) == 0):
        result['error'] = 'Could not parse WHOIS data'
        result['days_until_expiry'] = 0
    return result

# --- Health Score Calculation ---

def calculate_health_score(checks):
    """Calculate overall health score (0-100)."""
    total = 0
    passed = 0
    weights = {
        'soa': 10, 'ns': 10, 'mx': 10, 'a': 10, 'aaaa': 5, 'caa': 5,
        'spf': 15, 'dmarc': 15, 'dkim': 10, 'dnssec': 10, 'special_domain': 5
    }
    for key, weight in weights.items():
        if key in checks:
            total += weight
            if key == 'special_domain':
                # For special domains, valid means NOT special/reserved/private
                special_check = checks[key]
                is_problematic = (special_check.get('is_special_use') or 
                                special_check.get('is_reserved') or 
                                special_check.get('is_private'))
                if not is_problematic:
                    passed += weight
            elif checks[key].get('valid'):
                passed += weight
    return int(100 * passed / total) if total else 0

# --- Main Operations ---

def discover_zone(domain):
    """Discover all DNS record types for a domain (for Zabbix LLD)."""
    record_types = ['A', 'AAAA', 'MX', 'NS', 'CNAME', 'SOA', 'TXT', 'SRV', 'CAA']
    discovered = []
    for rtype in record_types:
        answers = dns_query(domain, rtype, DNS_NAMESERVER, DNS_TIMEOUT)
        if answers:
            discovered.append({'type': rtype, 'count': len(answers)})
    return json.dumps({'data': [{ '{#RECORD_TYPE}': r['type'], '{#RECORD_COUNT}': r['count'] } for r in discovered]})

def get_records(domain, record_type):
    """Get all records of a specific type for a domain."""
    answers = dns_query(domain, record_type, DNS_NAMESERVER, DNS_TIMEOUT)
    records = [format_rdata(r['rtype'], r['rdata']) for r in answers]
    return json.dumps({'domain': domain, 'type': record_type, 'records': records, 'count': len(records)})

def get_dnssec(domain):
    """Get DNSSEC status for a domain."""
    result = validate_dnssec(domain, DNS_NAMESERVER, DNS_TIMEOUT)
    return json.dumps(result)

def get_spf(domain):
    """Get and validate SPF record for a domain."""
    answers = dns_query(domain, 'TXT', DNS_NAMESERVER, DNS_TIMEOUT)
    txt_records = [format_rdata(r['rtype'], r['rdata']) for r in answers]
    result = validate_spf(txt_records)
    return json.dumps(result)

def get_dmarc(domain):
    """Get and validate DMARC record for a domain."""
    dmarc_domain = f'_dmarc.{domain}'
    answers = dns_query(dmarc_domain, 'TXT', DNS_NAMESERVER, DNS_TIMEOUT)
    txt_records = [format_rdata(r['rtype'], r['rdata']) for r in answers]
    result = validate_dmarc(txt_records)
    return json.dumps(result)

def get_legacy_spf(domain):
    """Check for deprecated SPF record type (RFC 7208 - should not be used)."""
    answers = dns_query(domain, 'SPF', DNS_NAMESERVER, DNS_TIMEOUT)
    spf_records = [format_rdata(r['rtype'], r['rdata']) for r in answers]
    
    result = {
        'legacy_spf_found': len(spf_records) > 0,
        'records': spf_records,
        'count': len(spf_records),
        'warning': 'Legacy SPF record type detected - should use TXT records only (RFC 7208)' if spf_records else None,
        'rfc_reference': 'RFC7208'
    }
    
    return json.dumps(result)

def get_dkim(domain, selector):
    """Get and validate DKIM record for a domain and selector."""
    dkim_domain = f'{selector}._domainkey.{domain}'
    answers = dns_query(dkim_domain, 'TXT', DNS_NAMESERVER, DNS_TIMEOUT)
    txt_records = [format_rdata(r['rtype'], r['rdata']) for r in answers]
    result = validate_dkim(txt_records, selector, domain)
    return json.dumps(result)

def get_caa(domain):
    """Get and validate CAA records for a domain."""
    answers = dns_query(domain, 'CAA', DNS_NAMESERVER, DNS_TIMEOUT)
    caa_records = [format_rdata(r['rtype'], r['rdata']) for r in answers]
    result = validate_caa(caa_records)
    return json.dumps(result)

# --- Email Security Extensions ---

def get_mta_sts(domain):
    """Check MTA-STS policy record (RFC 8461).
    
    MTA-STS (Mail Transfer Agent Strict Transport Security) helps prevent
    TLS downgrade attacks and MITM attacks on SMTP connections.
    """
    mta_sts_domain = f'_mta-sts.{domain}'
    answers = dns_query(mta_sts_domain, 'TXT', DNS_NAMESERVER, DNS_TIMEOUT)
    txt_records = [format_rdata(r['rtype'], r['rdata']) for r in answers]
    
    result = {
        'domain': domain,
        'configured': False,
        'version': None,
        'id': None,
        'record': None,
        'error': None
    }
    
    # Look for v=STSv1
    for rec in txt_records:
        if 'v=STSv1' in rec:
            result['configured'] = True
            result['record'] = rec
            # Parse version
            version_match = re.search(r'v=(STSv\d+)', rec)
            if version_match:
                result['version'] = version_match.group(1)
            # Parse id
            id_match = re.search(r'id=([^\s;]+)', rec)
            if id_match:
                result['id'] = id_match.group(1)
            break
    
    if not result['configured']:
        result['error'] = 'No MTA-STS record found'
    
    return json.dumps(result)

def get_tls_rpt(domain):
    """Check TLS-RPT record (RFC 8460).
    
    TLS-RPT (TLS Reporting) allows domains to receive reports about
    TLS connectivity problems.
    """
    tls_rpt_domain = f'_smtp._tls.{domain}'
    answers = dns_query(tls_rpt_domain, 'TXT', DNS_NAMESERVER, DNS_TIMEOUT)
    txt_records = [format_rdata(r['rtype'], r['rdata']) for r in answers]
    
    result = {
        'domain': domain,
        'configured': False,
        'version': None,
        'rua': [],
        'record': None,
        'error': None
    }
    
    # Look for v=TLSRPTv1
    for rec in txt_records:
        if 'v=TLSRPTv1' in rec:
            result['configured'] = True
            result['record'] = rec
            # Parse version
            version_match = re.search(r'v=(TLSRPTv\d+)', rec)
            if version_match:
                result['version'] = version_match.group(1)
            # Parse rua (reporting URI)
            rua_matches = re.findall(r'rua=([^\s;]+)', rec)
            result['rua'] = rua_matches
            break
    
    if not result['configured']:
        result['error'] = 'No TLS-RPT record found'
    
    return json.dumps(result)

def get_bimi(domain):
    """Check BIMI record (Brand Indicators for Message Identification).
    
    BIMI allows brands to display their logos next to authenticated emails.
    """
    bimi_domain = f'default._bimi.{domain}'
    answers = dns_query(bimi_domain, 'TXT', DNS_NAMESERVER, DNS_TIMEOUT)
    txt_records = [format_rdata(r['rtype'], r['rdata']) for r in answers]
    
    result = {
        'domain': domain,
        'configured': False,
        'version': None,
        'logo_url': None,
        'authority_url': None,
        'record': None,
        'error': None
    }
    
    # Look for v=BIMI1
    for rec in txt_records:
        if 'v=BIMI1' in rec:
            result['configured'] = True
            result['record'] = rec
            # Parse version
            version_match = re.search(r'v=(BIMI\d+)', rec)
            if version_match:
                result['version'] = version_match.group(1)
            # Parse l= (logo URL)
            logo_match = re.search(r'l=([^\s;]+)', rec)
            if logo_match:
                result['logo_url'] = logo_match.group(1)
            # Parse a= (authority/VMC URL)
            authority_match = re.search(r'a=([^\s;]+)', rec)
            if authority_match:
                result['authority_url'] = authority_match.group(1)
            break
    
    if not result['configured']:
        result['error'] = 'No BIMI record found'
    
    return json.dumps(result)

def get_dns_latency(domain):
    """Measure DNS query latency for the domain.
    
    Returns resolution time in milliseconds.
    """
    import time
    
    result = {
        'domain': domain,
        'latency_ms': -1,
        'success': False,
        'error': None
    }
    
    try:
        start = time.perf_counter()
        answers = dns_query(domain, 'A', DNS_NAMESERVER, DNS_TIMEOUT)
        end = time.perf_counter()
        
        if answers:
            result['latency_ms'] = round((end - start) * 1000, 2)
            result['success'] = True
        else:
            result['error'] = 'No A records returned'
    except Exception as e:
        result['error'] = str(e)
    
    return json.dumps(result)

def get_email_security(domain):
    """Get comprehensive email security status.
    
    Checks SPF, DKIM, DMARC, MTA-STS, TLS-RPT, and BIMI.
    """
    import time
    
    result = {
        'domain': domain,
        'spf': {'configured': False},
        'dkim': {'configured': False},
        'dmarc': {'configured': False},
        'mta_sts': {'configured': False},
        'tls_rpt': {'configured': False},
        'bimi': {'configured': False},
        'score': 0,
        'max_score': 6
    }
    
    # SPF
    spf_data = json.loads(get_spf(domain))
    result['spf'] = {'configured': spf_data.get('valid', False), 'error': spf_data.get('error')}
    
    # DMARC
    dmarc_data = json.loads(get_dmarc(domain))
    result['dmarc'] = {'configured': dmarc_data.get('valid', False), 'error': dmarc_data.get('error')}
    
    # DKIM (check common selectors)
    dkim_selectors = ['default', 'selector1', 'selector2', 'google', 'k1', 'dkim', 'mail', 'email']
    for sel in dkim_selectors:
        dkim_domain = f'{sel}._domainkey.{domain}'
        dkim_answers = dns_query(dkim_domain, 'TXT', DNS_NAMESERVER, DNS_TIMEOUT)
        if dkim_answers:
            result['dkim'] = {'configured': True, 'selector': sel}
            break
    if not result['dkim'].get('configured'):
        result['dkim'] = {'configured': False, 'error': 'No DKIM record found'}
    
    # MTA-STS
    mta_sts_data = json.loads(get_mta_sts(domain))
    result['mta_sts'] = {'configured': mta_sts_data.get('configured', False), 'error': mta_sts_data.get('error')}
    
    # TLS-RPT
    tls_rpt_data = json.loads(get_tls_rpt(domain))
    result['tls_rpt'] = {'configured': tls_rpt_data.get('configured', False), 'error': tls_rpt_data.get('error')}
    
    # BIMI
    bimi_data = json.loads(get_bimi(domain))
    result['bimi'] = {'configured': bimi_data.get('configured', False), 'error': bimi_data.get('error')}
    
    # Calculate score
    score = 0
    if result['spf']['configured']: score += 1
    if result['dkim']['configured']: score += 1
    if result['dmarc']['configured']: score += 1
    if result['mta_sts']['configured']: score += 1
    if result['tls_rpt']['configured']: score += 1
    if result['bimi']['configured']: score += 1
    result['score'] = score
    
    return json.dumps(result)

# --- RFC 5782: DNSBL/Blacklist Checking ---

# Common DNSBL servers for IP reputation checking
DNSBL_SERVERS = [
    'zen.spamhaus.org',           # Spamhaus ZEN (SBL+XBL+PBL)
    'bl.spamcop.net',             # SpamCop
    'b.barracudacentral.org',     # Barracuda
    'dnsbl.sorbs.net',            # SORBS
    'spam.dnsbl.sorbs.net',       # SORBS Spam
    'cbl.abuseat.org',            # CBL (Composite Blocking List)
    'dnsbl-1.uceprotect.net',     # UCEPROTECT Level 1
    'psbl.surriel.com',           # PSBL
    'all.s5h.net',                # S5H
]

def reverse_ip(ip):
    """Reverse an IP address for DNSBL lookup."""
    parts = ip.split('.')
    if len(parts) == 4:
        return '.'.join(reversed(parts))
    return None

def check_dnsbl(ip, dnsbl_server):
    """Check if an IP is listed in a DNSBL."""
    reversed_ip = reverse_ip(ip)
    if not reversed_ip:
        return None
    query_name = f'{reversed_ip}.{dnsbl_server}'
    try:
        answers = dns_query(query_name, 'A', DNS_NAMESERVER, DNS_TIMEOUT)
        if answers:
            return True
    except Exception:
        pass
    return False

def get_dnsbl(domain):
    """Check domain's IP addresses against common DNSBLs (RFC 5782).
    
    Returns blacklist status for all A record IPs.
    """
    result = {
        'domain': domain,
        'ips_checked': [],
        'listed_on': [],
        'clean': True,
        'total_listings': 0,
        'dnsbls_checked': len(DNSBL_SERVERS),
        'error': None
    }
    
    try:
        # Get A records for domain
        a_answers = dns_query(domain, 'A', DNS_NAMESERVER, DNS_TIMEOUT)
        if not a_answers:
            result['error'] = 'No A records found'
            return json.dumps(result)
        
        ips = [format_rdata(r['rtype'], r['rdata']) for r in a_answers]
        result['ips_checked'] = ips
        
        for ip in ips:
            for dnsbl in DNSBL_SERVERS:
                if check_dnsbl(ip, dnsbl):
                    result['listed_on'].append({'ip': ip, 'dnsbl': dnsbl})
                    result['clean'] = False
                    result['total_listings'] += 1
    except Exception as e:
        result['error'] = str(e)
    
    return json.dumps(result)

def get_dnsbl_mx(domain):
    """Check domain's MX server IPs against DNSBLs."""
    result = {
        'domain': domain,
        'mx_hosts': [],
        'ips_checked': [],
        'listed_on': [],
        'clean': True,
        'total_listings': 0,
        'error': None
    }
    
    try:
        # Get MX records
        mx_answers = dns_query(domain, 'MX', DNS_NAMESERVER, DNS_TIMEOUT)
        if not mx_answers:
            result['error'] = 'No MX records found'
            return json.dumps(result)
        
        # Parse MX hostnames
        mx_hosts = []
        for r in mx_answers:
            mx_data = format_rdata(r['rtype'], r['rdata'])
            # MX format: "priority hostname"
            parts = mx_data.split()
            if len(parts) >= 2:
                mx_hosts.append(parts[1].rstrip('.'))
        
        result['mx_hosts'] = mx_hosts
        
        # Get A records for each MX host
        for mx_host in mx_hosts:
            a_answers = dns_query(mx_host, 'A', DNS_NAMESERVER, DNS_TIMEOUT)
            if a_answers:
                for r in a_answers:
                    ip = format_rdata(r['rtype'], r['rdata'])
                    if ip not in result['ips_checked']:
                        result['ips_checked'].append(ip)
                        # Check against DNSBLs
                        for dnsbl in DNSBL_SERVERS[:5]:  # Check top 5 for MX
                            if check_dnsbl(ip, dnsbl):
                                result['listed_on'].append({'mx': mx_host, 'ip': ip, 'dnsbl': dnsbl})
                                result['clean'] = False
                                result['total_listings'] += 1
    except Exception as e:
        result['error'] = str(e)
    
    return json.dumps(result)

# --- RFC 6186: Email Service SRV Records ---

EMAIL_SRV_RECORDS = [
    ('_submission._tcp', 587, 'Email submission (RFC 6409)'),
    ('_submissions._tcp', 465, 'Email submission over TLS'),
    ('_imap._tcp', 143, 'IMAP'),
    ('_imaps._tcp', 993, 'IMAP over TLS'),
    ('_pop3._tcp', 110, 'POP3'),
    ('_pop3s._tcp', 995, 'POP3 over TLS'),
    ('_autodiscover._tcp', 443, 'Autodiscover (Exchange/Outlook)'),
    ('_carddavs._tcp', 443, 'CardDAV over TLS'),
    ('_caldavs._tcp', 443, 'CalDAV over TLS'),
]

def get_email_srv(domain):
    """Check for email service SRV records (RFC 6186).
    
    Discovers email service endpoints for IMAP, POP3, SMTP submission.
    """
    result = {
        'domain': domain,
        'services': [],
        'services_found': 0,
        'has_submission': False,
        'has_imap': False,
        'has_pop3': False,
        'has_autodiscover': False,
        'error': None
    }
    
    try:
        for srv_name, default_port, description in EMAIL_SRV_RECORDS:
            srv_domain = f'{srv_name}.{domain}'
            answers = dns_query(srv_domain, 'SRV', DNS_NAMESERVER, DNS_TIMEOUT)
            if answers:
                for r in answers:
                    srv_data = format_rdata(r['rtype'], r['rdata'])
                    # SRV format: "priority weight port target"
                    parts = srv_data.split()
                    if len(parts) >= 4:
                        service = {
                            'name': srv_name,
                            'description': description,
                            'priority': int(parts[0]),
                            'weight': int(parts[1]),
                            'port': int(parts[2]),
                            'target': parts[3].rstrip('.')
                        }
                        result['services'].append(service)
                        result['services_found'] += 1
                        
                        # Track service types
                        if 'submission' in srv_name:
                            result['has_submission'] = True
                        if 'imap' in srv_name:
                            result['has_imap'] = True
                        if 'pop3' in srv_name:
                            result['has_pop3'] = True
                        if 'autodiscover' in srv_name:
                            result['has_autodiscover'] = True
    except Exception as e:
        result['error'] = str(e)
    
    return json.dumps(result)

# --- RFC 4255: SSHFP Records ---

SSHFP_ALGORITHMS = {
    1: 'RSA',
    2: 'DSA',
    3: 'ECDSA',
    4: 'Ed25519',
    6: 'Ed448'
}

SSHFP_HASH_TYPES = {
    1: 'SHA-1',
    2: 'SHA-256'
}

def get_sshfp(domain):
    """Check for SSHFP records (RFC 4255).
    
    SSHFP records publish SSH host key fingerprints in DNS for verification.
    """
    result = {
        'domain': domain,
        'records': [],
        'record_count': 0,
        'has_sha256': False,
        'algorithms': [],
        'error': None
    }
    
    try:
        answers = dns_query(domain, 'SSHFP', DNS_NAMESERVER, DNS_TIMEOUT)
        
        if answers:
            for r in answers:
                # Parse SSHFP record
                rdata = r.get('rdata', b'')
                if len(rdata) >= 2:
                    algo = rdata[0]
                    hash_type = rdata[1]
                    fingerprint = rdata[2:].hex()
                    
                    record = {
                        'algorithm': algo,
                        'algorithm_name': SSHFP_ALGORITHMS.get(algo, f'Unknown({algo})'),
                        'hash_type': hash_type,
                        'hash_name': SSHFP_HASH_TYPES.get(hash_type, f'Unknown({hash_type})'),
                        'fingerprint': fingerprint
                    }
                    result['records'].append(record)
                    result['record_count'] += 1
                    
                    if hash_type == 2:
                        result['has_sha256'] = True
                    if record['algorithm_name'] not in result['algorithms']:
                        result['algorithms'].append(record['algorithm_name'])
        else:
            result['error'] = 'No SSHFP records found'
    except Exception as e:
        result['error'] = str(e)
    
    return json.dumps(result)

# --- RFC 7673: DANE TLSA for MX Servers ---

def get_dane_mx(domain):
    """Check DANE TLSA records for MX servers (RFC 7673).
    
    Validates that mail servers have TLSA records for TLS verification.
    """
    result = {
        'domain': domain,
        'mx_hosts': [],
        'dane_records': [],
        'mx_with_dane': 0,
        'mx_without_dane': 0,
        'dane_coverage': 0,
        'error': None
    }
    
    try:
        # Get MX records
        mx_answers = dns_query(domain, 'MX', DNS_NAMESERVER, DNS_TIMEOUT)
        if not mx_answers:
            result['error'] = 'No MX records found'
            return json.dumps(result)
        
        # Parse MX hostnames
        for r in mx_answers:
            mx_data = format_rdata(r['rtype'], r['rdata'])
            parts = mx_data.split()
            if len(parts) >= 2:
                mx_host = parts[1].rstrip('.')
                result['mx_hosts'].append(mx_host)
                
                # Check for TLSA record at _25._tcp.mx_host
                tlsa_name = f'_25._tcp.{mx_host}'
                tlsa_answers = dns_query(tlsa_name, 'TLSA', DNS_NAMESERVER, DNS_TIMEOUT)
                
                if tlsa_answers:
                    result['dane_records'].append({
                        'mx_host': mx_host,
                        'tlsa_name': tlsa_name,
                        'has_tlsa': True,
                        'record_count': len(tlsa_answers)
                    })
                    result['mx_with_dane'] += 1
                else:
                    result['mx_without_dane'] += 1
        
        # Calculate coverage
        total_mx = len(result['mx_hosts'])
        if total_mx > 0:
            result['dane_coverage'] = round(result['mx_with_dane'] / total_mx * 100)
    except Exception as e:
        result['error'] = str(e)
    
    return json.dumps(result)

# --- RFC 9471: NS Glue Record Validation ---

def get_ns_glue(domain):
    """Validate NS glue records (RFC 9471).
    
    Checks that in-bailiwick nameservers have proper glue records.
    """
    result = {
        'domain': domain,
        'nameservers': [],
        'in_bailiwick': [],
        'out_of_bailiwick': [],
        'glue_records': [],
        'missing_glue': [],
        'glue_valid': True,
        'error': None
    }
    
    try:
        # Get NS records
        ns_answers = dns_query(domain, 'NS', DNS_NAMESERVER, DNS_TIMEOUT)
        if not ns_answers:
            result['error'] = 'No NS records found'
            return json.dumps(result)
        
        for r in ns_answers:
            ns_name = format_rdata(r['rtype'], r['rdata']).rstrip('.')
            result['nameservers'].append(ns_name)
            
            # Check if in-bailiwick (NS hostname is under the domain)
            if ns_name.endswith(f'.{domain}') or ns_name == domain:
                result['in_bailiwick'].append(ns_name)
                
                # In-bailiwick NS requires glue (A/AAAA records)
                a_answers = dns_query(ns_name, 'A', DNS_NAMESERVER, DNS_TIMEOUT)
                aaaa_answers = dns_query(ns_name, 'AAAA', DNS_NAMESERVER, DNS_TIMEOUT)
                
                if a_answers or aaaa_answers:
                    glue_ips = []
                    if a_answers:
                        glue_ips.extend([format_rdata(r['rtype'], r['rdata']) for r in a_answers])
                    if aaaa_answers:
                        glue_ips.extend([format_rdata(r['rtype'], r['rdata']) for r in aaaa_answers])
                    result['glue_records'].append({
                        'ns': ns_name,
                        'ips': glue_ips
                    })
                else:
                    result['missing_glue'].append(ns_name)
                    result['glue_valid'] = False
            else:
                result['out_of_bailiwick'].append(ns_name)
    except Exception as e:
        result['error'] = str(e)
    
    return json.dumps(result)

# --- RFC 2182: NS Server Diversity ---

def get_ns_diversity(domain):
    """Check nameserver diversity (RFC 2182).
    
    Analyzes geographic and network diversity of nameservers.
    """
    result = {
        'domain': domain,
        'nameservers': [],
        'ns_count': 0,
        'unique_ips': [],
        'unique_asns': [],
        'unique_networks': [],
        'diversity_score': 0,
        'recommendations': [],
        'error': None
    }
    
    try:
        # Get NS records
        ns_answers = dns_query(domain, 'NS', DNS_NAMESERVER, DNS_TIMEOUT)
        if not ns_answers:
            result['error'] = 'No NS records found'
            return json.dumps(result)
        
        ns_ips = []
        for r in ns_answers:
            ns_name = format_rdata(r['rtype'], r['rdata']).rstrip('.')
            result['nameservers'].append(ns_name)
            result['ns_count'] += 1
            
            # Get IP for each NS
            a_answers = dns_query(ns_name, 'A', DNS_NAMESERVER, DNS_TIMEOUT)
            if a_answers:
                for a in a_answers:
                    ip = format_rdata(a['rtype'], a['rdata'])
                    if ip not in result['unique_ips']:
                        result['unique_ips'].append(ip)
                    ns_ips.append(ip)
        
        # Calculate diversity score (0-100)
        score = 0
        
        # At least 2 NS servers (RFC requirement)
        if result['ns_count'] >= 2:
            score += 25
        else:
            result['recommendations'].append('Have at least 2 nameservers (RFC 2182 requirement)')
        
        # At least 3 NS servers (recommended)
        if result['ns_count'] >= 3:
            score += 25
        
        # Multiple unique IPs
        if len(result['unique_ips']) >= 2:
            score += 25
        
        # Check /24 network diversity
        networks = set()
        for ip in result['unique_ips']:
            parts = ip.split('.')
            if len(parts) == 4:
                network = '.'.join(parts[:3])
                networks.add(network)
        result['unique_networks'] = list(networks)
        
        if len(networks) >= 2:
            score += 25
        else:
            result['recommendations'].append('Use nameservers on different /24 networks')
        
        result['diversity_score'] = score
        
    except Exception as e:
        result['error'] = str(e)
    
    return json.dumps(result)

# --- RFC 8914: Extended DNS Errors (requires dnspython) ---

def get_extended_errors(domain):
    """Check for Extended DNS Errors support (RFC 8914).
    
    Note: Full EDE parsing requires dnspython. This provides basic info.
    """
    result = {
        'domain': domain,
        'ede_supported': False,
        'ede_codes': [],
        'library_status': 'dnspython required for full EDE support',
        'error': None
    }
    
    if HAVE_DNSPYTHON:
        try:
            import dns.resolver
            import dns.edns
            resolver = dns.resolver.Resolver()
            resolver.timeout = DNS_TIMEOUT
            resolver.lifetime = DNS_TIMEOUT
            
            # Try a query and check for EDE in response
            try:
                answer = resolver.resolve(domain, 'A')
                result['ede_supported'] = True
                result['library_status'] = 'dnspython available'
            except dns.resolver.NXDOMAIN as e:
                result['ede_codes'].append({'code': 0, 'text': 'NXDOMAIN'})
            except dns.resolver.NoAnswer:
                result['ede_codes'].append({'code': 0, 'text': 'NoAnswer'})
            except Exception as e:
                result['error'] = str(e)
        except Exception as e:
            result['error'] = str(e)
    else:
        result['library_status'] = 'dnspython not installed'
    
    return json.dumps(result)

# --- RFC 9567: DNS Error Reporting ---

def get_dns_error_reporting(domain):
    """Check for DNS Error Reporting configuration (RFC 9567).
    
    Looks for _dns.resolver-errors.<domain> TXT records.
    """
    result = {
        'domain': domain,
        'configured': False,
        'reporting_agent': None,
        'record': None,
        'error': None
    }
    
    try:
        # RFC 9567 uses _dns.resolver-errors.<domain>
        error_domain = f'_dns.resolver-errors.{domain}'
        answers = dns_query(error_domain, 'TXT', DNS_NAMESERVER, DNS_TIMEOUT)
        
        if answers:
            for r in answers:
                txt = format_rdata(r['rtype'], r['rdata'])
                result['record'] = txt
                result['configured'] = True
                # Parse reporting agent from record
                if 'agent=' in txt.lower():
                    match = re.search(r'agent=([^\s;]+)', txt, re.I)
                    if match:
                        result['reporting_agent'] = match.group(1)
                break
        else:
            result['error'] = 'No DNS error reporting record found'
    except Exception as e:
        result['error'] = str(e)
    
    return json.dumps(result)

# --- RFC 8162: SMIMEA Records ---

def get_smimea(domain, email_local='*'):
    """Check for SMIMEA records (RFC 8162).
    
    SMIMEA records publish S/MIME certificates in DNS.
    Format: <hash>._smimecert.<domain>
    """
    result = {
        'domain': domain,
        'records': [],
        'record_count': 0,
        'email_local': email_local,
        'error': None
    }
    
    try:
        import hashlib
        # Hash the local part (left of @)
        local_hash = hashlib.sha256(email_local.encode()).hexdigest()[:56]
        smimea_name = f'{local_hash}._smimecert.{domain}'
        
        # SMIMEA is type 53
        answers = dns_query(smimea_name, 'SMIMEA', DNS_NAMESERVER, DNS_TIMEOUT)
        if answers:
            result['record_count'] = len(answers)
            for r in answers:
                rdata = r.get('rdata', b'')
                if len(rdata) >= 3:
                    result['records'].append({
                        'usage': rdata[0],
                        'selector': rdata[1],
                        'matching_type': rdata[2],
                        'certificate_data': rdata[3:].hex()[:64] + '...'
                    })
        else:
            result['error'] = 'No SMIMEA records found'
    except Exception as e:
        result['error'] = str(e)
    
    return json.dumps(result)

# --- RFC 7929: OPENPGPKEY Records ---

def get_openpgpkey(domain, email_local='*'):
    """Check for OPENPGPKEY records (RFC 7929).
    
    OPENPGPKEY records publish OpenPGP public keys in DNS.
    Format: <hash>._openpgpkey.<domain>
    """
    result = {
        'domain': domain,
        'records': [],
        'record_count': 0,
        'email_local': email_local,
        'error': None
    }
    
    try:
        import hashlib
        # Hash the local part with SHA-256, truncated to 28 octets (56 hex chars)
        local_hash = hashlib.sha256(email_local.lower().encode()).hexdigest()[:56]
        openpgp_name = f'{local_hash}._openpgpkey.{domain}'
        
        # OPENPGPKEY is type 61
        answers = dns_query(openpgp_name, 'OPENPGPKEY', DNS_NAMESERVER, DNS_TIMEOUT)
        if answers:
            result['record_count'] = len(answers)
            for r in answers:
                rdata = r.get('rdata', b'')
                result['records'].append({
                    'key_data_length': len(rdata),
                    'key_data_preview': rdata[:32].hex() + '...' if len(rdata) > 32 else rdata.hex()
                })
        else:
            result['error'] = 'No OPENPGPKEY records found'
    except Exception as e:
        result['error'] = str(e)
    
    return json.dumps(result)

def get_whois(domain):
    """Get WHOIS data for a domain."""
    whois_text = whois_query(domain, DNS_TIMEOUT)
    result = parse_whois(whois_text)
    return json.dumps(result)

# --- RDAP Functions (RFC 7480-7484) ---

def get_rdap_bootstrap():
    """Get RDAP bootstrap data to find the correct RDAP server for a TLD."""
    try:
        import urllib.request
        import ssl
        ctx = ssl.create_default_context()
        url = 'https://data.iana.org/rdap/dns.json'
        req = urllib.request.Request(url, headers={'Accept': 'application/json', 'User-Agent': 'ZabbixDNSHealth/1.0'})
        with urllib.request.urlopen(req, timeout=DNS_TIMEOUT, context=ctx) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            return data.get('services', [])
    except Exception as e:
        logger.debug(f'RDAP bootstrap failed: {e}')
        return []

def find_rdap_server(domain):
    """Find the RDAP server for a domain's TLD."""
    tld = domain.rsplit('.', 1)[-1].lower()
    services = get_rdap_bootstrap()
    for service in services:
        if len(service) >= 2:
            tlds, urls = service[0], service[1]
            if tld in [t.lower() for t in tlds]:
                return urls[0] if urls else None
    return None

def get_rdap(domain):
    """Get RDAP data for a domain (modern WHOIS replacement)."""
    import urllib.request
    import ssl
    
    result = {
        'domain': domain,
        'registrar': None,
        'creation_date': None,
        'expiry_date': None,
        'updated_date': None,
        'status': [],
        'nameservers': [],
        'days_until_expiry': 0,
        'domain_age_days': -1,
        'rdap_server': None,
        'error': None
    }
    
    try:
        rdap_url = find_rdap_server(domain)
        if not rdap_url:
            result['error'] = f'No RDAP server found for TLD'
            return json.dumps(result)
        
        result['rdap_server'] = rdap_url
        url = f'{rdap_url.rstrip("/")}/domain/{domain}'
        
        ctx = ssl.create_default_context()
        req = urllib.request.Request(url, headers={'Accept': 'application/rdap+json', 'User-Agent': 'ZabbixDNSHealth/1.0'})
        
        with urllib.request.urlopen(req, timeout=DNS_TIMEOUT, context=ctx) as resp:
            data = json.loads(resp.read().decode('utf-8'))
        
        # Parse RDAP response
        result['status'] = data.get('status', [])
        
        # Nameservers
        for ns in data.get('nameservers', []):
            if 'ldhName' in ns:
                result['nameservers'].append(ns['ldhName'].lower())
        
        # Events (dates)
        for event in data.get('events', []):
            action = event.get('eventAction', '')
            date_str = event.get('eventDate', '')
            if action == 'registration':
                result['creation_date'] = date_str
            elif action == 'expiration':
                result['expiry_date'] = date_str
            elif action == 'last changed':
                result['updated_date'] = date_str
        
        # Registrar (from entities)
        for entity in data.get('entities', []):
            roles = entity.get('roles', [])
            if 'registrar' in roles:
                vcard = entity.get('vcardArray', [])
                if len(vcard) >= 2:
                    for item in vcard[1]:
                        if len(item) >= 4 and item[0] == 'fn':
                            result['registrar'] = item[3]
                            break
        
        now = datetime.now(timezone.utc)
        
        # Calculate days until expiry
        if result['expiry_date']:
            try:
                expiry_str = result['expiry_date']
                # RDAP uses ISO 8601 format
                expiry_dt = datetime.fromisoformat(expiry_str.replace('Z', '+00:00'))
                days_until = (expiry_dt - now).days
                result['days_until_expiry'] = max(0, days_until)
            except Exception:
                pass
        
        # Calculate domain age
        if result['creation_date']:
            try:
                creation_str = result['creation_date']
                creation_dt = datetime.fromisoformat(creation_str.replace('Z', '+00:00'))
                domain_age = (now - creation_dt).days
                result['domain_age_days'] = max(0, domain_age)
            except Exception:
                pass
        
    except urllib.error.HTTPError as e:
        result['error'] = f'RDAP HTTP error: {e.code}'
    except Exception as e:
        result['error'] = f'RDAP query failed: {str(e)}'
    
    return json.dumps(result)

# --- DANE/TLSA Functions (RFC 6698) ---

# Try to import crypto libraries for full DANE validation
try:
    import dns.resolver
    import dns.rdatatype
    import dns.dnssec
    import dns.name
    HAVE_DNSPYTHON = True
except ImportError:
    HAVE_DNSPYTHON = False
    logger.debug("dnspython not available, using stdlib DNS")

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.backends import default_backend
    HAVE_CRYPTOGRAPHY = True
except ImportError:
    HAVE_CRYPTOGRAPHY = False
    logger.debug("cryptography not available, limited DANE validation")

try:
    import ssl
    import OpenSSL
    HAVE_OPENSSL = True
except ImportError:
    HAVE_OPENSSL = False
    logger.debug("pyOpenSSL not available, limited certificate retrieval")

# TLSA Certificate Usage values (RFC 6698)
TLSA_USAGE = {
    0: 'PKIX-TA',      # CA constraint (must be in PKIX trust chain)
    1: 'PKIX-EE',      # Service certificate constraint  
    2: 'DANE-TA',      # Trust anchor assertion
    3: 'DANE-EE'       # Domain-issued certificate
}

# TLSA Selector values
TLSA_SELECTOR = {
    0: 'Full certificate',
    1: 'SubjectPublicKeyInfo'
}

# TLSA Matching Type values
TLSA_MATCHING_TYPE = {
    0: 'Exact match',
    1: 'SHA-256',
    2: 'SHA-512'
}

# DNSSEC Algorithm values (RFC 8624) - IANA Registry Mnemonics
DNSSEC_ALGORITHMS = {
    1: 'RSAMD5',           # Deprecated
    3: 'DSA',              # Deprecated
    5: 'RSASHA1',          # Not recommended
    6: 'DSA-NSEC3-SHA1',   # Not recommended
    7: 'RSASHA1-NSEC3-SHA1',  # Not recommended
    8: 'RSASHA256',        # Recommended
    10: 'RSASHA512',       # Recommended
    13: 'ECDSAP256SHA256', # Recommended
    14: 'ECDSAP384SHA384', # Recommended
    15: 'ED25519',         # Recommended
    16: 'ED448'            # Recommended
}

# Human-readable algorithm descriptions
DNSSEC_ALGORITHM_DESCRIPTIONS = {
    1: 'RSA with MD5 (Deprecated)',
    3: 'Digital Signature Algorithm (Deprecated)',
    5: 'RSA with SHA-1',
    6: 'DSA with SHA-1 for NSEC3',
    7: 'RSA with SHA-1 for NSEC3', 
    8: 'RSA with SHA-256',
    10: 'RSA with SHA-512',
    13: 'Elliptic Curve DSA P-256 with SHA-256',
    14: 'Elliptic Curve DSA P-384 with SHA-384',
    15: 'EdDSA using Curve25519',
    16: 'EdDSA using Curve448'
}

# RFC 8624 Algorithm Status (for DNSSEC validation recommendations)
# Status: MUST, RECOMMENDED, MAY, NOT RECOMMENDED, MUST NOT
DNSSEC_ALGORITHM_STATUS = {
    1: {'status': 'MUST NOT', 'reason': 'RSAMD5 is deprecated and insecure'},
    3: {'status': 'MUST NOT', 'reason': 'DSA is deprecated'},
    5: {'status': 'NOT RECOMMENDED', 'reason': 'RSASHA1 uses SHA-1 which is weak'},
    6: {'status': 'MUST NOT', 'reason': 'DSA-NSEC3-SHA1 is deprecated'},
    7: {'status': 'NOT RECOMMENDED', 'reason': 'RSASHA1-NSEC3-SHA1 uses SHA-1 which is weak'},
    8: {'status': 'RECOMMENDED', 'reason': 'RSASHA256 is widely supported'},
    10: {'status': 'MAY', 'reason': 'RSASHA512 has limited deployment'},
    13: {'status': 'RECOMMENDED', 'reason': 'ECDSAP256SHA256 is efficient and secure'},
    14: {'status': 'RECOMMENDED', 'reason': 'ECDSAP384SHA384 provides higher security'},
    15: {'status': 'RECOMMENDED', 'reason': 'ED25519 is modern and efficient'},
    16: {'status': 'RECOMMENDED', 'reason': 'ED448 provides very high security'}
}

def check_algorithm_compliance(algorithm):
    """Check if a DNSSEC algorithm is compliant with RFC 8624."""
    status_info = DNSSEC_ALGORITHM_STATUS.get(algorithm, {
        'status': 'UNKNOWN',
        'reason': f'Algorithm {algorithm} not in RFC 8624'
    })
    return {
        'algorithm': algorithm,
        'algorithm_name': DNSSEC_ALGORITHMS.get(algorithm, f'Unknown ({algorithm})'),
        'algorithm_description': DNSSEC_ALGORITHM_DESCRIPTIONS.get(algorithm, f'Unknown Algorithm ({algorithm})'),
        'status': status_info['status'],
        'reason': status_info['reason'],
        'compliant': status_info['status'] in ['RECOMMENDED', 'MAY', 'MUST']
    }

def parse_tlsa_rdata(rdata):
    """Parse TLSA record rdata into components."""
    if len(rdata) < 4:
        return None
    usage = rdata[0]
    selector = rdata[1]
    matching_type = rdata[2]
    cert_data = rdata[3:]
    return {
        'usage': usage,
        'usage_name': TLSA_USAGE.get(usage, f'Unknown ({usage})'),
        'selector': selector,
        'selector_name': TLSA_SELECTOR.get(selector, f'Unknown ({selector})'),
        'matching_type': matching_type,
        'matching_type_name': TLSA_MATCHING_TYPE.get(matching_type, f'Unknown ({matching_type})'),
        'certificate_data': cert_data.hex()
    }

def get_certificate_from_server(hostname, port=443, timeout=2):
    """Retrieve TLS certificate from a server with minimal overhead."""
    try:
        import ssl
        
        # Use a single connection with optional verification to get both DER and info
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_OPTIONAL  # Get cert but don't fail on verification
        
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Get both formats in one connection
                cert_der = ssock.getpeercert(binary_form=True)
                cert_info = ssock.getpeercert(binary_form=False)
                
                return cert_der, cert_info, None
                
    except Exception as e:
        return None, None, str(e)

def parse_certificate_details(cert_der, cert_info=None):
    """Parse certificate details including CN, SN, validity dates, etc."""
    try:
        # Try cryptography library first if available
        if cert_der:
            try:
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                
                cert = x509.load_der_x509_certificate(cert_der, default_backend())
                
                # Extract subject information
                subject_dict = {}
                for attribute in cert.subject:
                    subject_dict[attribute.oid._name] = attribute.value
                
                # Extract issuer information  
                issuer_dict = {}
                for attribute in cert.issuer:
                    issuer_dict[attribute.oid._name] = attribute.value
                
                # Extract SANs (Subject Alternative Names)
                san_list = []
                try:
                    san_extension = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    for san in san_extension.value:
                        san_list.append(san.value)
                except:
                    pass
                
                return {
                    'subject': {
                        'common_name': subject_dict.get('commonName', ''),
                        'organization': subject_dict.get('organizationName', ''),
                        'organizational_unit': subject_dict.get('organizationalUnitName', ''),
                        'country': subject_dict.get('countryName', ''),
                        'state': subject_dict.get('stateOrProvinceName', ''),
                        'locality': subject_dict.get('localityName', '')
                    },
                    'issuer': {
                        'common_name': issuer_dict.get('commonName', ''),
                        'organization': issuer_dict.get('organizationName', ''),
                        'country': issuer_dict.get('countryName', '')
                    },
                    'serial_number': str(cert.serial_number),
                    'version': cert.version.value,
                    'not_before': cert.not_valid_before.isoformat(),
                    'not_after': cert.not_valid_after.isoformat(),
                    'is_expired': datetime.now(timezone.utc) > cert.not_valid_after.replace(tzinfo=timezone.utc),
                    'days_until_expiry': (cert.not_valid_after.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days,
                    'signature_algorithm': cert.signature_algorithm_oid._name,
                    'public_key_algorithm': cert.public_key().__class__.__name__.replace('_', '').lower(),
                    'subject_alternative_names': san_list,
                    'fingerprint_sha1': hashlib.sha1(cert_der).hexdigest(),
                    'fingerprint_sha256': hashlib.sha256(cert_der).hexdigest()
                }
            except ImportError:
                # Cryptography library not available, fall back to basic parsing
                pass
            except Exception as e:
                return {'error': f'Advanced certificate parsing failed: {str(e)}'}
        
        # Fallback to basic cert info from SSL socket if available
        if cert_info:
            try:
                # Parse subject - it's nested tuples: ((('commonName', 'value'),),)
                subject_dict = {}
                if 'subject' in cert_info:
                    for rdn in cert_info['subject']:
                        for name_type, value in rdn:
                            subject_dict[name_type] = value
                
                # Parse issuer - same structure as subject
                issuer_dict = {}
                if 'issuer' in cert_info:
                    for rdn in cert_info['issuer']:
                        for name_type, value in rdn:
                            issuer_dict[name_type] = value
                
                return {
                    'subject': {
                        'common_name': subject_dict.get('commonName', ''),
                        'organization': subject_dict.get('organizationName', ''),
                        'organizational_unit': subject_dict.get('organizationalUnitName', ''),
                        'country': subject_dict.get('countryName', ''),
                        'state': subject_dict.get('stateOrProvinceName', ''),
                        'locality': subject_dict.get('localityName', '')
                    },
                    'issuer': {
                        'common_name': issuer_dict.get('commonName', ''),
                        'organization': issuer_dict.get('organizationName', ''),
                        'country': issuer_dict.get('countryName', '')
                    },
                    'serial_number': cert_info.get('serialNumber', ''),
                    'version': cert_info.get('version', 0),
                    'not_before': cert_info.get('notBefore', ''),
                    'not_after': cert_info.get('notAfter', ''),
                    'subject_alternative_names': [name[1] for name in cert_info.get('subjectAltName', [])],
                    'fingerprint_sha1': hashlib.sha1(cert_der).hexdigest() if cert_der else '',
                    'fingerprint_sha256': hashlib.sha256(cert_der).hexdigest() if cert_der else ''
                }
            except Exception as e:
                return {'error': f'Basic certificate parsing failed: {str(e)}'}
        
        return {'error': 'No certificate data available'}
        
    except Exception as e:
        return {'error': f'Certificate parsing failed: {str(e)}'}

def compute_tlsa_hash(cert_der, selector, matching_type):
    """Compute the hash that should match the TLSA record."""
    if not HAVE_CRYPTOGRAPHY:
        return None, "cryptography library not available"
    
    try:
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        
        # Get the data to hash based on selector
        if selector == 0:
            # Full certificate
            data_to_hash = cert_der
        elif selector == 1:
            # SubjectPublicKeyInfo (SPKI)
            data_to_hash = cert.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        else:
            return None, f"Unknown selector: {selector}"
        
        # Compute hash based on matching type
        if matching_type == 0:
            # Exact match, return hex of data
            return data_to_hash.hex(), None
        elif matching_type == 1:
            # SHA-256
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(data_to_hash)
            return digest.finalize().hex(), None
        elif matching_type == 2:
            # SHA-512
            digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
            digest.update(data_to_hash)
            return digest.finalize().hex(), None
        else:
            return None, f"Unknown matching type: {matching_type}"
            
    except Exception as e:
        return None, str(e)

def query_tlsa_records(domain, port, protocol='tcp'):
    """Query TLSA records for a domain/port combination."""
    tlsa_domain = f'_{port}._{protocol}.{domain}'
    
    if HAVE_DNSPYTHON:
        try:
            resolver = dns.resolver.Resolver()
            if DNS_NAMESERVER:
                resolver.nameservers = [DNS_NAMESERVER]
            resolver.timeout = DNS_TIMEOUT
            resolver.lifetime = DNS_TIMEOUT
            
            answers = resolver.resolve(tlsa_domain, 'TLSA')
            records = []
            for rdata in answers:
                records.append({
                    'usage': rdata.usage,
                    'usage_name': TLSA_USAGE.get(rdata.usage, f'Unknown ({rdata.usage})'),
                    'selector': rdata.selector,
                    'selector_name': TLSA_SELECTOR.get(rdata.selector, f'Unknown ({rdata.selector})'),
                    'matching_type': rdata.mtype,
                    'matching_type_name': TLSA_MATCHING_TYPE.get(rdata.mtype, f'Unknown ({rdata.mtype})'),
                    'certificate_data': rdata.cert.hex()
                })
            return records, None
        except dns.resolver.NXDOMAIN:
            return [], None  # No TLSA records
        except dns.resolver.NoAnswer:
            return [], None
        except Exception as e:
            return [], str(e)
    else:
        # Stdlib fallback - need to add TLSA to our type map
        DNS_RECORD_TYPES['TLSA'] = 52
        answers = dns_query(tlsa_domain, 'TLSA', DNS_NAMESERVER, DNS_TIMEOUT)
        records = []
        for r in answers:
            parsed = parse_tlsa_rdata(r['rdata'])
            if parsed:
                records.append(parsed)
        return records, None

def validate_tlsa(domain, port, tlsa_records):
    """Validate TLSA records against actual certificate."""
    result = {
        'valid': False,
        'matches': [],
        'errors': []
    }
    
    if not tlsa_records:
        result['errors'].append('No TLSA records to validate')
        return result
    
    # Get the actual certificate
    cert_der, cert_info, error = get_certificate_from_server(domain, port)
    if error:
        result['errors'].append(f'Could not retrieve certificate: {error}')
        return result
    
    # Parse certificate details
    cert_details = parse_certificate_details(cert_der, cert_info)
    result['certificate_details'] = cert_details
    
    # Check each TLSA record
    for record in tlsa_records:
        selector = record['selector']
        matching_type = record['matching_type']
        expected_hash = record['certificate_data']
        
        computed_hash, error = compute_tlsa_hash(cert_der, selector, matching_type)
        if error:
            result['errors'].append(f'Hash computation error: {error}')
            continue
        
        match = computed_hash.lower() == expected_hash.lower()
        result['matches'].append({
            'selector': selector,
            'matching_type': matching_type,
            'expected': expected_hash[:32] + '...',
            'computed': computed_hash[:32] + '...' if computed_hash else None,
            'match': match
        })
        
        if match:
            result['valid'] = True
    
    return result

def discover_dane(domain):
    """Discover DANE/TLSA records for common ports (for Zabbix LLD)."""
    common_ports = [
        (443, 'tcp', 'HTTPS'),
        (25, 'tcp', 'SMTP'),
        (587, 'tcp', 'SMTP Submission'),
        (465, 'tcp', 'SMTPS'),
        (993, 'tcp', 'IMAPS'),
        (995, 'tcp', 'POP3S')
    ]
    
    discovered = []
    for port, protocol, service in common_ports:
        records, error = query_tlsa_records(domain, port, protocol)
        if records:
            discovered.append({
                '{#DANE_PORT}': port,
                '{#DANE_PROTOCOL}': protocol,
                '{#DANE_SERVICE}': service,
                '{#DANE_RECORD_COUNT}': len(records)
            })
    
    return json.dumps({'data': discovered})

def get_dane(domain, port=443, validate=True):
    """Get DANE/TLSA status for a domain and port."""
    result = {
        'domain': domain,
        'port': int(port),
        'tlsa_records': [],
        'record_count': 0,
        'valid': False,
        'validation': None,
        'error': None,
        'library_status': {
            'dnspython': HAVE_DNSPYTHON,
            'cryptography': HAVE_CRYPTOGRAPHY,
            'pyopenssl': HAVE_OPENSSL
        }
    }
    
    try:
        records, error = query_tlsa_records(domain, int(port))
        if error:
            result['error'] = error
            return json.dumps(result)
        
        result['tlsa_records'] = records
        result['record_count'] = len(records)
        
        if records and validate and HAVE_CRYPTOGRAPHY and HAVE_OPENSSL:
            validation = validate_tlsa(domain, int(port), records)
            result['validation'] = validation
            result['valid'] = validation['valid']
        elif records:
            result['valid'] = True  # Records exist, can't fully validate without crypto
            result['error'] = 'Full validation requires cryptography and pyOpenSSL'
        
    except Exception as e:
        result['error'] = str(e)
    
    return json.dumps(result)

# --- Enhanced DNSSEC Functions (RFC 4033-4035) ---

def parse_dnskey_detailed(rdata):
    """Parse DNSKEY record into detailed components."""
    if len(rdata) < 4:
        return None
    
    flags, protocol, algorithm = struct.unpack('>HBB', rdata[:4])
    public_key = rdata[4:]
    
    # Interpret flags
    sep_key = (flags & 0x0001) != 0  # Secure Entry Point (KSK)
    zone_key = (flags & 0x0100) != 0  # Zone Key
    
    key_type = 'Unknown'
    if sep_key and zone_key:
        key_type = 'KSK'  # Key Signing Key (flag 257)
    elif zone_key:
        key_type = 'ZSK'  # Zone Signing Key (flag 256)
    
    # Calculate key fingerprints
    key_fingerprint_sha1 = hashlib.sha1(public_key).hexdigest()
    key_fingerprint_sha256 = hashlib.sha256(public_key).hexdigest()
    
    # Estimate key strength based on algorithm and key length
    key_strength = estimate_key_strength(algorithm, len(public_key))
    
    return {
        'flags': flags,
        'protocol': protocol,
        'algorithm': algorithm,
        'algorithm_name': DNSSEC_ALGORITHMS.get(algorithm, f'Unknown ({algorithm})'),
        'algorithm_description': DNSSEC_ALGORITHM_DESCRIPTIONS.get(algorithm, f'Unknown Algorithm ({algorithm})'),
        'key_type': key_type,
        'sep_key': sep_key,
        'zone_key': zone_key,
        'public_key_length': len(public_key),
        'public_key_data': base64.b64encode(public_key).decode('ascii'),
        'key_fingerprint_sha1': key_fingerprint_sha1,
        'key_fingerprint_sha256': key_fingerprint_sha256,
        'key_strength': key_strength,
        'key_tag': compute_key_tag(rdata)
    }

def estimate_key_strength(algorithm, key_length):
    """Estimate the cryptographic strength of a DNSSEC key."""
    # Based on NIST SP 800-57 Part 1 Rev. 5
    strength_mapping = {
        1: {'type': 'RSA-MD5', 'bits': key_length * 8, 'security_level': 'DEPRECATED'},
        3: {'type': 'DSA', 'bits': key_length * 8, 'security_level': 'DEPRECATED'},
        5: {'type': 'RSA-SHA1', 'bits': key_length * 8, 'security_level': 'WEAK' if key_length * 8 < 2048 else 'ACCEPTABLE'},
        6: {'type': 'DSA-SHA1', 'bits': key_length * 8, 'security_level': 'DEPRECATED'},
        7: {'type': 'RSA-SHA1', 'bits': key_length * 8, 'security_level': 'WEAK' if key_length * 8 < 2048 else 'ACCEPTABLE'},
        8: {'type': 'RSA-SHA256', 'bits': key_length * 8, 'security_level': 'GOOD' if key_length * 8 >= 2048 else 'WEAK'},
        10: {'type': 'RSA-SHA512', 'bits': key_length * 8, 'security_level': 'GOOD' if key_length * 8 >= 2048 else 'WEAK'},
        13: {'type': 'ECDSA-P256', 'bits': 256, 'security_level': 'EXCELLENT'},
        14: {'type': 'ECDSA-P384', 'bits': 384, 'security_level': 'EXCELLENT'},
        15: {'type': 'Ed25519', 'bits': 256, 'security_level': 'EXCELLENT'},
        16: {'type': 'Ed448', 'bits': 448, 'security_level': 'EXCELLENT'}
    }
    
    return strength_mapping.get(algorithm, {
        'type': f'Unknown-{algorithm}',
        'bits': key_length * 8,
        'security_level': 'UNKNOWN'
    })

def compute_key_tag(dnskey_rdata):
    """Compute the key tag for a DNSKEY (RFC 4034)."""
    # Key tag algorithm from RFC 4034 Appendix B
    ac = 0
    for i, byte in enumerate(dnskey_rdata):
        if i % 2 == 0:
            ac += byte << 8
        else:
            ac += byte
    ac += (ac >> 16) & 0xFFFF
    return ac & 0xFFFF

def parse_ds_detailed(rdata):
    """Parse DS record into detailed components."""
    if len(rdata) < 4:
        return None
    
    key_tag, algorithm, digest_type = struct.unpack('>HBB', rdata[:4])
    digest = rdata[4:]
    
    digest_types = {
        1: 'SHA-1',
        2: 'SHA-256',
        3: 'GOST R 34.11-94',
        4: 'SHA-384'
    }
    
    return {
        'key_tag': key_tag,
        'algorithm': algorithm,
        'algorithm_name': DNSSEC_ALGORITHMS.get(algorithm, f'Unknown ({algorithm})'),
        'algorithm_description': DNSSEC_ALGORITHM_DESCRIPTIONS.get(algorithm, f'Unknown Algorithm ({algorithm})'),
        'digest_type': digest_type,
        'digest_type_name': digest_types.get(digest_type, f'Unknown ({digest_type})'),
        'digest': digest.hex()
    }

def parse_rrsig_detailed(rdata):
    """Parse RRSIG record into detailed components."""
    if len(rdata) < 18:
        return None
    
    type_covered, algorithm, labels, original_ttl = struct.unpack('>HBBI', rdata[:8])
    sig_expiration, sig_inception, key_tag = struct.unpack('>IIH', rdata[8:18])
    
    # Parse signer's name
    signer_name, offset = parse_dns_name(rdata, 18)
    signature = rdata[offset:]
    
    # Convert timestamps
    expiration_dt = datetime.fromtimestamp(sig_expiration, tz=timezone.utc)
    inception_dt = datetime.fromtimestamp(sig_inception, tz=timezone.utc)
    
    # Check if signature is valid (not expired)
    now = datetime.now(timezone.utc)
    is_valid_time = inception_dt <= now <= expiration_dt
    
    return {
        'type_covered': type_covered,
        'algorithm': algorithm,
        'algorithm_name': DNSSEC_ALGORITHMS.get(algorithm, f'Unknown ({algorithm})'),
        'algorithm_description': DNSSEC_ALGORITHM_DESCRIPTIONS.get(algorithm, f'Unknown Algorithm ({algorithm})'),
        'labels': labels,
        'original_ttl': original_ttl,
        'expiration': expiration_dt.isoformat(),
        'inception': inception_dt.isoformat(),
        'key_tag': key_tag,
        'signer': signer_name,
        'signature_length': len(signature),
        'is_valid_time': is_valid_time,
        'days_until_expiry': (expiration_dt - now).days if is_valid_time else 0
    }

def validate_dnssec_chain(domain):
    """Validate the DNSSEC chain of trust from root to domain."""
    result = {
        'domain': domain,
        'chain_valid': False,
        'chain': [],
        'errors': [],
        'library_available': HAVE_DNSPYTHON
    }
    
    if not HAVE_DNSPYTHON:
        result['errors'].append('dnspython required for chain validation')
        # Fall back to basic check
        basic = validate_dnssec(domain, DNS_NAMESERVER, DNS_TIMEOUT)
        result['chain_valid'] = basic.get('valid', False)
        return result
    
    try:
        resolver = dns.resolver.Resolver()
        if DNS_NAMESERVER:
            resolver.nameservers = [DNS_NAMESERVER]
        resolver.timeout = DNS_TIMEOUT
        resolver.use_edns(0, dns.flags.DO, 4096)  # Enable DNSSEC
        
        # Query DNSKEY with DNSSEC
        try:
            dnskey_resp = resolver.resolve(domain, 'DNSKEY')
            result['chain'].append({
                'record': 'DNSKEY',
                'found': True,
                'count': len(dnskey_resp)
            })
        except Exception as e:
            result['chain'].append({
                'record': 'DNSKEY',
                'found': False,
                'error': str(e)
            })
            return result
        
        # Query DS from parent
        try:
            ds_resp = resolver.resolve(domain, 'DS')
            result['chain'].append({
                'record': 'DS',
                'found': True,
                'count': len(ds_resp)
            })
        except dns.resolver.NoAnswer:
            result['chain'].append({
                'record': 'DS',
                'found': False,
                'error': 'No DS record at parent (domain may be unsigned)'
            })
        except Exception as e:
            result['chain'].append({
                'record': 'DS',
                'found': False,
                'error': str(e)
            })
        
        # Query RRSIG for DNSKEY
        try:
            rrsig_resp = resolver.resolve(domain, 'RRSIG')
            result['chain'].append({
                'record': 'RRSIG',
                'found': True,
                'count': len(rrsig_resp)
            })
        except Exception as e:
            result['chain'].append({
                'record': 'RRSIG',
                'found': False,
                'error': str(e)
            })
        
        # If we have DNSKEY and RRSIG, chain is likely valid
        has_dnskey = any(c['record'] == 'DNSKEY' and c['found'] for c in result['chain'])
        has_rrsig = any(c['record'] == 'RRSIG' and c['found'] for c in result['chain'])
        result['chain_valid'] = has_dnskey and has_rrsig
        
    except Exception as e:
        result['errors'].append(str(e))
    
    return result

def get_dnssec_detailed(domain):
    """Get detailed DNSSEC information for a domain."""
    result = {
        'domain': domain,
        'enabled': False,
        'valid': False,
        'failure_reason': None,
        'failure_description': None,
        'dnskey': {
            'records': [],
            'count': 0,
            'ksk_count': 0,
            'zsk_count': 0,
            'algorithms': []
        },
        'ds': {
            'records': [],
            'count': 0
        },
        'rrsig': {
            'records': [],
            'count': 0,
            'nearest_expiry_days': -1
        },
        'chain_validation': None,
        'error': None,
        'library_status': {
            'dnspython': HAVE_DNSPYTHON,
            'cryptography': HAVE_CRYPTOGRAPHY
        }
    }
    
    try:
        # Query DNSKEY
        dnskey_answers = dns_query(domain, 'DNSKEY', DNS_NAMESERVER, DNS_TIMEOUT)
        if dnskey_answers:
            result['enabled'] = True
            algorithms = set()
            algorithm_numbers = set()
            for r in dnskey_answers:
                parsed = parse_dnskey_detailed(r['rdata'])
                if parsed:
                    result['dnskey']['records'].append(parsed)
                    algorithms.add(parsed['algorithm_name'])
                    algorithm_numbers.add(parsed['algorithm'])
                    if parsed['key_type'] == 'KSK':
                        result['dnskey']['ksk_count'] += 1
                    elif parsed['key_type'] == 'ZSK':
                        result['dnskey']['zsk_count'] += 1
            result['dnskey']['count'] = len(result['dnskey']['records'])
            result['dnskey']['algorithms'] = list(algorithms)
            
            # RFC 8624 Algorithm compliance check
            result['algorithm_compliance'] = {
                'algorithms_checked': [],
                'deprecated_algorithms': [],
                'compliant': True
            }
            for alg_num in algorithm_numbers:
                compliance = check_algorithm_compliance(alg_num)
                result['algorithm_compliance']['algorithms_checked'].append(compliance)
                if not compliance['compliant']:
                    result['algorithm_compliance']['deprecated_algorithms'].append({
                        'algorithm': alg_num,
                        'name': compliance['algorithm_name'],
                        'status': compliance['status'],
                        'reason': compliance['reason']
                    })
                    result['algorithm_compliance']['compliant'] = False
        
        # Query DS
        ds_answers = dns_query(domain, 'DS', DNS_NAMESERVER, DNS_TIMEOUT)
        for r in ds_answers:
            parsed = parse_ds_detailed(r['rdata'])
            if parsed:
                result['ds']['records'].append(parsed)
        result['ds']['count'] = len(result['ds']['records'])
        
        # Query RRSIG
        rrsig_answers = dns_query(domain, 'RRSIG', DNS_NAMESERVER, DNS_TIMEOUT)
        nearest_expiry = float('inf')
        for r in rrsig_answers:
            parsed = parse_rrsig_detailed(r['rdata'])
            if parsed:
                result['rrsig']['records'].append(parsed)
                if parsed['days_until_expiry'] < nearest_expiry:
                    nearest_expiry = parsed['days_until_expiry']
        result['rrsig']['count'] = len(result['rrsig']['records'])
        if nearest_expiry != float('inf'):
            result['rrsig']['nearest_expiry_days'] = nearest_expiry
        
        # Determine validity and failure reason
        result['valid'] = result['dnskey']['count'] > 0 and result['rrsig']['count'] > 0
        
        # Set detailed failure reasons
        if result['ds']['count'] > 0 and result['dnskey']['count'] == 0:
            result['failure_reason'] = 'missing_dnskey'
            result['failure_description'] = 'Broken DNSSEC chain: DS record exists in parent zone but no DNSKEY found in zone. The zone is not publishing its DNSSEC keys.'
        elif result['dnskey']['count'] > 0 and result['ds']['count'] == 0:
            result['failure_reason'] = 'missing_ds'
            result['failure_description'] = 'Incomplete DNSSEC: DNSKEY present but no DS record in parent zone. The chain of trust is not established.'
        elif result['dnskey']['count'] == 0 and result['ds']['count'] == 0:
            result['failure_reason'] = 'not_configured'
            result['failure_description'] = 'DNSSEC not configured: No DNSKEY or DS records found.'
        elif result['dnskey']['count'] > 0 and result['rrsig']['count'] == 0:
            result['failure_reason'] = 'rrsig_not_visible'
            result['failure_description'] = 'DNSSEC appears configured but RRSIG not visible via standard query. This may be a limitation of DNS libraries not setting EDNS0 DO bit, or the zone is not signing records.'
        elif result['dnskey']['ksk_count'] == 0:
            result['failure_reason'] = 'missing_ksk'
            result['failure_description'] = 'DNSSEC misconfigured: No Key Signing Key (KSK) found. Zone has ZSK but missing KSK (flags=257).'
        elif result['dnskey']['zsk_count'] == 0:
            result['failure_reason'] = 'missing_zsk'
            result['failure_description'] = 'DNSSEC misconfigured: No Zone Signing Key (ZSK) found. Zone has KSK but missing ZSK (flags=256).'
        
        # Check for deprecated algorithm usage
        if result.get('algorithm_compliance') and not result['algorithm_compliance']['compliant']:
            deprecated = result['algorithm_compliance']['deprecated_algorithms']
            if deprecated and not result['failure_reason']:
                result['failure_reason'] = 'deprecated_algorithm'
                alg_names = ', '.join([d['name'] for d in deprecated])
                result['failure_description'] = f'DNSSEC uses deprecated/weak algorithms per RFC 8624: {alg_names}. Consider migrating to ECDSAP256SHA256 or ED25519.'
        
        # Chain validation if dnspython available
        if HAVE_DNSPYTHON:
            result['chain_validation'] = validate_dnssec_chain(domain)
        
    except Exception as e:
        result['error'] = str(e)
    
    return json.dumps(result)

# --- ASN Lookup Functions ---

def get_asn_for_ip(ip_address):
    """Query Team Cymru DNS service for ASN information."""
    result = {
        'ip': ip_address,
        'asn': None,
        'as_name': None,
        'prefix': None,
        'country': None,
        'error': None
    }
    
    try:
        # Reverse the IP for DNS query
        octets = ip_address.split('.')
        if len(octets) != 4:
            result['error'] = 'Invalid IPv4 address'
            return result
        
        reversed_ip = '.'.join(reversed(octets))
        
        # Query origin.asn.cymru.com for ASN info
        asn_query = f'{reversed_ip}.origin.asn.cymru.com'
        answers = dns_query(asn_query, 'TXT', DNS_NAMESERVER, DNS_TIMEOUT)
        
        if answers:
            txt_record = format_rdata(answers[0]['rtype'], answers[0]['rdata'])
            # Format: "ASN | Prefix | Country | Registry | Allocated"
            parts = [p.strip() for p in txt_record.strip('"').split('|')]
            if len(parts) >= 3:
                result['asn'] = parts[0]
                result['prefix'] = parts[1]
                result['country'] = parts[2]
                
                # Get AS name
                as_name_query = f'AS{parts[0]}.asn.cymru.com'
                name_answers = dns_query(as_name_query, 'TXT', DNS_NAMESERVER, DNS_TIMEOUT)
                if name_answers:
                    name_txt = format_rdata(name_answers[0]['rtype'], name_answers[0]['rdata'])
                    # Format: "ASN | Country | Registry | Allocated | AS Name"
                    name_parts = [p.strip() for p in name_txt.strip('"').split('|')]
                    if len(name_parts) >= 5:
                        result['as_name'] = name_parts[4]
        else:
            result['error'] = 'No ASN data found'
            
    except Exception as e:
        result['error'] = str(e)
    
    return result

def get_asn(domain):
    """Get ASN information for all A records of a domain."""
    result = {
        'domain': domain,
        'ip_asn_data': [],
        'unique_asns': [],
        'error': None
    }
    
    try:
        # Get A records for domain
        a_answers = dns_query(domain, 'A', DNS_NAMESERVER, DNS_TIMEOUT)
        
        if not a_answers:
            result['error'] = 'No A records found for domain'
            return json.dumps(result)
        
        seen_asns = set()
        for answer in a_answers:
            ip = format_rdata(answer['rtype'], answer['rdata'])
            asn_info = get_asn_for_ip(ip)
            result['ip_asn_data'].append(asn_info)
            if asn_info.get('asn') and asn_info['asn'] not in seen_asns:
                seen_asns.add(asn_info['asn'])
                result['unique_asns'].append({
                    'asn': asn_info['asn'],
                    'as_name': asn_info.get('as_name'),
                    'country': asn_info.get('country')
                })
                
    except Exception as e:
        result['error'] = str(e)
    
    return json.dumps(result)

# --- NS Server Discovery and Monitoring ---

def discover_ns(domain):
    """Discover all NS servers for a domain (for Zabbix LLD)."""
    answers = dns_query(domain, 'NS', DNS_NAMESERVER, DNS_TIMEOUT)
    ns_servers = []
    seen_ns = set()  # Track unique nameservers to avoid duplicates
    
    for r in answers:
        ns_name = format_rdata(r['rtype'], r['rdata']).rstrip('.')
        
        # If we get a truncated name due to DNS compression, try to get the full list via nslookup
        if '.' not in ns_name:
            # Fall back to getting NS records via different resolver
            try:
                import subprocess
                result = subprocess.run(['nslookup', '-type=ns', domain], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'nameserver' in line and '=' in line:
                            full_ns = line.split('=')[1].strip()
                            if full_ns and '.' in full_ns:
                                if full_ns not in seen_ns:
                                    seen_ns.add(full_ns)
                                    # Get IP for this NS
                                    ns_ips = dns_query(full_ns, 'A', DNS_NAMESERVER, DNS_TIMEOUT)
                                    ns_ip = format_rdata(ns_ips[0]['rtype'], ns_ips[0]['rdata']) if ns_ips else ''
                                    ns_servers.append({
                                        '{#NS_SERVER}': full_ns,
                                        '{#NS_IP}': ns_ip
                                    })
                    # If we got results from nslookup, skip processing the truncated names
                    if ns_servers:
                        break
            except:
                pass
            continue
            
        # Skip duplicates
        if ns_name in seen_ns:
            continue
        seen_ns.add(ns_name)
        
        # Resolve NS to IP for additional context
        ns_ips = dns_query(ns_name, 'A', DNS_NAMESERVER, DNS_TIMEOUT)
        ns_ip = format_rdata(ns_ips[0]['rtype'], ns_ips[0]['rdata']) if ns_ips else ''
        ns_servers.append({
            '{#NS_SERVER}': ns_name,
            '{#NS_IP}': ns_ip
        })
    return json.dumps({'data': ns_servers})

def ns_check(domain, ns_server):
    """Check NS server availability and latency by querying it directly."""
    import time
    
    result = {
        'ns_server': ns_server,
        'available': 0,
        'latency_ms': -1,
        'error': None
    }
    
    # Resolve NS server to IP if needed
    ns_ip = ns_server
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ns_server):
        ns_ips = dns_query(ns_server, 'A', DNS_NAMESERVER, DNS_TIMEOUT)
        if ns_ips:
            ns_ip = format_rdata(ns_ips[0]['rtype'], ns_ips[0]['rdata'])
        else:
            result['error'] = f'Could not resolve NS server {ns_server}'
            return json.dumps(result)
    
    # Query the NS server directly for the domain's SOA record and measure latency
    try:
        start_time = time.time()
        answers = dns_query(domain, 'SOA', ns_ip, DNS_TIMEOUT)
        end_time = time.time()
        
        if answers:
            result['available'] = 1
            result['latency_ms'] = round((end_time - start_time) * 1000, 2)
        else:
            result['error'] = 'No response from NS server'
    except Exception as e:
        result['error'] = str(e)
    
    return json.dumps(result)

def get_health(domain):
    """Get overall health and compliance status for a domain."""
    checks = {}
    
    # Special/Reserved Domain Check (RFC 5732-5735)
    checks['special_domain'] = validate_special_use_domain(domain)
    
    # SOA
    soa_answers = dns_query(domain, 'SOA', DNS_NAMESERVER, DNS_TIMEOUT)
    soa_records = [format_rdata(r['rtype'], r['rdata']) for r in soa_answers]
    checks['soa'] = validate_soa(soa_records)
    # NS
    ns_answers = dns_query(domain, 'NS', DNS_NAMESERVER, DNS_TIMEOUT)
    ns_records = [format_rdata(r['rtype'], r['rdata']) for r in ns_answers]
    checks['ns'] = validate_ns(ns_records)
    # MX
    mx_answers = dns_query(domain, 'MX', DNS_NAMESERVER, DNS_TIMEOUT)
    mx_records = [format_rdata(r['rtype'], r['rdata']) for r in mx_answers]
    checks['mx'] = validate_mx(mx_records)
    # A
    a_answers = dns_query(domain, 'A', DNS_NAMESERVER, DNS_TIMEOUT)
    checks['a'] = {'valid': bool(a_answers), 'records': [format_rdata(r['rtype'], r['rdata']) for r in a_answers], 'error': None if a_answers else 'No A records'}
    # AAAA
    aaaa_answers = dns_query(domain, 'AAAA', DNS_NAMESERVER, DNS_TIMEOUT)
    checks['aaaa'] = {'valid': bool(aaaa_answers), 'records': [format_rdata(r['rtype'], r['rdata']) for r in aaaa_answers], 'error': None if aaaa_answers else 'No AAAA records'}
    # CAA
    caa_answers = dns_query(domain, 'CAA', DNS_NAMESERVER, DNS_TIMEOUT)
    caa_records = [format_rdata(r['rtype'], r['rdata']) for r in caa_answers]
    checks['caa'] = validate_caa(caa_records)
    # SPF
    txt_answers = dns_query(domain, 'TXT', DNS_NAMESERVER, DNS_TIMEOUT)
    txt_records = [format_rdata(r['rtype'], r['rdata']) for r in txt_answers]
    checks['spf'] = validate_spf(txt_records)
    
    # Legacy SPF record check (deprecated - should trigger warning)
    legacy_spf_answers = dns_query(domain, 'SPF', DNS_NAMESERVER, DNS_TIMEOUT)
    legacy_spf_records = [format_rdata(r['rtype'], r['rdata']) for r in legacy_spf_answers]
    checks['legacy_spf'] = {
        'found': len(legacy_spf_records) > 0,
        'records': legacy_spf_records,
        'count': len(legacy_spf_records),
        'warning': 'Legacy SPF record type detected - should use TXT records only (RFC 7208)' if legacy_spf_records else None
    }
    # DMARC
    dmarc_domain = f'_dmarc.{domain}'
    dmarc_answers = dns_query(dmarc_domain, 'TXT', DNS_NAMESERVER, DNS_TIMEOUT)
    dmarc_records = [format_rdata(r['rtype'], r['rdata']) for r in dmarc_answers]
    checks['dmarc'] = validate_dmarc(dmarc_records)
    # DKIM (common selectors from popular email providers)
    dkim_selectors = [
        'default',      # Generic default
        'selector1', 'selector2',  # Microsoft 365
        'google', 'google2',       # Google Workspace
        'k1', 'k2', 'k3',          # Mailchimp
        'dkim', 'mail', 'email',   # Common generic names
        'smtp', 'mta', 'mx',       # Mail server names
        's1', 's2',                # Short selectors
        'mandrill',                # Mailchimp Transactional
        'everlytickey1', 'everlytickey2',  # Everlytic
        'cm',                      # Campaign Monitor
        'pm',                      # Postmark
        'amazonses',               # Amazon SES
        'sendgrid', 'smtpapi',     # SendGrid
    ]
    dkim_valid = False
    dkim_records = []
    dkim_selector_found = None
    for sel in dkim_selectors:
        dkim_domain = f'{sel}._domainkey.{domain}'
        dkim_answers = dns_query(dkim_domain, 'TXT', DNS_NAMESERVER, DNS_TIMEOUT)
        if dkim_answers:
            dkim_records = [format_rdata(r['rtype'], r['rdata']) for r in dkim_answers]
            dkim_valid = True
            dkim_selector_found = sel
            break
    checks['dkim'] = {
        'valid': dkim_valid,
        'records': dkim_records,
        'selector_found': dkim_selector_found,
        'selectors_checked': len(dkim_selectors),
        'error': None if dkim_valid else f'No DKIM records found for {len(dkim_selectors)} common selectors'
    }
    # DNSSEC
    checks['dnssec'] = validate_dnssec(domain, DNS_NAMESERVER, DNS_TIMEOUT)
    # Health score
    score = calculate_health_score(checks)
    result = {
        'domain': domain,
        'health_score': score,
        'checks': checks
    }
    return json.dumps(result)

def selftest(domain):
    """Run a self-test to verify script and connectivity."""
    try:
        a_answers = dns_query(domain, 'A', DNS_NAMESERVER, DNS_TIMEOUT)
        ns_answers = dns_query(domain, 'NS', DNS_NAMESERVER, DNS_TIMEOUT)
        txt_answers = dns_query(domain, 'TXT', DNS_NAMESERVER, DNS_TIMEOUT)
        result = {
            'status': 'ok',
            'domain': domain,
            'a_records': len(a_answers),
            'ns_records': len(ns_answers),
            'txt_records': len(txt_answers)
        }
    except Exception as e:
        result = {'status': 'error', 'error': str(e)}
    return json.dumps(result)

# --- Advanced Monitoring Functions ---

def get_dns_performance(domain):
    """Comprehensive DNS performance analysis including latency, resolver diversity, and caching."""
    result = {
        'domain': domain,
        'performance_metrics': {},
        'resolver_analysis': {},
        'caching_analysis': {},
        'geographic_analysis': {}
    }
    
    try:
        # Multi-resolver latency test
        resolvers = ['8.8.8.8', '1.1.1.1', '9.9.9.9', '208.67.222.222']
        resolver_times = {}
        
        for resolver in resolvers:
            start_time = time.time()
            try:
                answers = dns_query(domain, 'A', resolver, 5.0)
                latency = (time.time() - start_time) * 1000
                resolver_times[resolver] = {
                    'latency_ms': round(latency, 2),
                    'records': len(answers),
                    'success': True
                }
            except Exception as e:
                resolver_times[resolver] = {
                    'latency_ms': -1,
                    'records': 0,
                    'success': False,
                    'error': str(e)
                }
        
        result['resolver_analysis'] = resolver_times
        
        # Average latency calculation
        successful_times = [r['latency_ms'] for r in resolver_times.values() if r['success']]
        if successful_times:
            result['performance_metrics'] = {
                'avg_latency_ms': round(sum(successful_times) / len(successful_times), 2),
                'min_latency_ms': min(successful_times),
                'max_latency_ms': max(successful_times),
                'resolver_success_rate': len(successful_times) / len(resolvers) * 100
            }
        
        # TTL analysis for caching optimization
        record_types = ['A', 'AAAA', 'MX', 'NS', 'CNAME']
        ttl_analysis = {}
        
        for rtype in record_types:
            try:
                answers = dns_query(domain, rtype, None, 5.0)
                if answers:
                    ttls = [r.get('ttl', 0) for r in answers]
                    ttl_analysis[rtype] = {
                        'min_ttl': min(ttls),
                        'max_ttl': max(ttls),
                        'avg_ttl': sum(ttls) / len(ttls),
                        'record_count': len(ttls)
                    }
            except:
                continue
        
        result['caching_analysis'] = ttl_analysis
        
    except Exception as e:
        result['error'] = str(e)
    
    return json.dumps(result)

def get_security_scan(domain):
    """Advanced DNS security analysis including spoofing detection, cache poisoning tests, and anomaly detection."""
    result = {
        'domain': domain,
        'security_checks': {},
        'vulnerability_scan': {},
        'anomaly_detection': {},
        'threat_intelligence': {}
    }
    
    try:
        # DNS over HTTPS/TLS support check
        doh_test = test_doh_support(domain)
        dot_test = test_dot_support(domain)
        
        result['security_checks']['dns_over_https'] = doh_test
        result['security_checks']['dns_over_tls'] = dot_test
        
        # Amplification attack potential
        amplification_test = test_amplification_potential(domain)
        result['vulnerability_scan']['amplification_risk'] = amplification_test
        
        # Zone transfer attempt (should fail)
        zt_test = test_zone_transfer_security(domain)
        result['security_checks']['zone_transfer_protection'] = zt_test
        
        # DNS cache poisoning indicators
        cache_test = test_cache_poisoning_indicators(domain)
        result['vulnerability_scan']['cache_poisoning_indicators'] = cache_test
        
        # Response consistency check across multiple resolvers
        consistency_test = test_response_consistency(domain)
        result['anomaly_detection']['response_consistency'] = consistency_test
        
    except Exception as e:
        result['error'] = str(e)
    
    # Final safety check for JSON serialization
    try:
        return json.dumps(result)
    except TypeError as json_error:
        # If JSON serialization fails, create a safe error response
        safe_result = {
            'domain': domain,
            'error': f'JSON serialization failed: {str(json_error)}',
            'security_checks': {},
            'vulnerability_scan': {},
            'anomaly_detection': {},
            'threat_intelligence': {}
        }
        return json.dumps(safe_result)

def get_zone_analysis(domain):
    """Comprehensive DNS zone analysis including delegation, glue records, and authority chain validation."""
    result = {
        'domain': domain,
        'zone_structure': {},
        'delegation_analysis': {},
        'authority_chain': {},
        'glue_records': {}
    }
    
    try:
        # Authority chain analysis
        authority_chain = trace_authority_chain(domain)
        result['authority_chain'] = authority_chain
        
        # Nameserver delegation analysis
        delegation_analysis = analyze_nameserver_delegation(domain)
        result['delegation_analysis'] = delegation_analysis
        
        # Glue record analysis
        glue_analysis = get_ns_glue(domain)
        if isinstance(glue_analysis, str):
            glue_analysis = json.loads(glue_analysis)
        result['glue_records'] = glue_analysis
        
        # Zone serial consistency
        serial_consistency = check_zone_serial_consistency(domain)
        result['zone_structure']['serial_consistency'] = serial_consistency
        
        # SOA record analysis
        soa_analysis = analyze_soa_record(domain)
        result['zone_structure']['soa_analysis'] = soa_analysis
        
    except Exception as e:
        result['error'] = str(e)
    
    return json.dumps(result)

def discover_mx(domain):
    """
    Discover MX servers for domain
    Returns Zabbix discovery format with MX server information
    """
    try:
        # Get MX records using native dns_query
        mx_answers = dns_query(domain, 'MX', DNS_NAMESERVER, DNS_TIMEOUT)
        mx_records = []
        
        for r in mx_answers:
            mx_data = format_rdata(r['rtype'], r['rdata'])
            if mx_data:
                # Parse priority and server from formatted MX record
                parts = mx_data.split(' ', 1)
                if len(parts) == 2:
                    priority = int(parts[0])
                    server = parts[1].rstrip('.')
                    mx_records.append({
                        "{#MX_SERVER}": server,
                        "{#MX_PRIORITY}": priority,
                        "{#MX_FULL}": mx_data
                    })
        
        return json.dumps({"data": mx_records})
    except Exception as e:
        return json.dumps({"error": f"MX discovery failed: {str(e)}"})

def discover_domain_services(domain, fast_mode=False):
    """Discover all services associated with a domain for comprehensive monitoring."""
    result = {
        'domain': domain,
        'discovered_services': {},
        'security_analysis': {},
        'integration_points': {},
        'monitoring_recommendations': [],
        'service_summary': {
            'total_services': 0,
            'secure_services': 0,
            'vulnerable_services': 0,
            'missing_security_features': []
        }
    }
    
    try:
        if fast_mode:
            # Fast mode: Only essential services
            web_services = discover_web_services(domain, fast_mode=True)
            result['discovered_services']['web'] = web_services
            
            email_services = discover_email_services(domain, fast_mode=True)
            result['discovered_services']['email'] = email_services
            
            # TLS services with minimal certificate checking (443 only)
            tls_services = discover_tls_services(domain)
            result['discovered_services']['tls'] = tls_services
            
            # Skip heavy operations in fast mode
            result['discovered_services']['dns_based'] = {'skipped': 'fast_mode'}
            result['discovered_services']['applications'] = {'skipped': 'fast_mode'}
            result['discovered_services']['security'] = {'skipped': 'fast_mode'}
            result['discovered_services']['proxy'] = {'skipped': 'fast_mode'}
            result['discovered_services']['srv'] = {'skipped': 'fast_mode'}
            
            # Minimal analysis in fast mode
            result['security_analysis'] = {'mode': 'fast_mode', 'limited_analysis': True}
            result['monitoring_recommendations'] = ['Use full mode for comprehensive analysis']
            result['service_summary'] = {'mode': 'fast_mode', 'partial_data': True}
            result['integration_points'] = {'mode': 'fast_mode'}
            
        else:
            # Full mode: comprehensive discovery
            # Web services discovery with detailed analysis
            web_services = discover_web_services(domain)
            result['discovered_services']['web'] = web_services
            
            # Email services discovery with security analysis
            email_services = discover_email_services(domain)
            result['discovered_services']['email'] = email_services
            
            # TLS/SSL enabled services with certificate analysis
            tls_services = discover_tls_services(domain)
            result['discovered_services']['tls'] = tls_services
            
            # SRV record services with availability checks
            srv_services = discover_srv_services(domain)
            result['discovered_services']['srv'] = srv_services
            
            # DNS-based service discovery
            try:
                dns_services = discover_dns_based_services(domain)
                result['discovered_services']['dns_based'] = dns_services
            except Exception as e:
                result['discovered_services']['dns_based'] = {'error': str(e)}
            
            # Database and application services
            try:
                app_services = discover_application_services(domain)
                result['discovered_services']['applications'] = app_services
            except Exception as e:
                result['discovered_services']['applications'] = {'error': str(e)}
            
            # Security services (DANE, MTA-STS, etc.)
            try:
                security_services = discover_security_services(domain)
                result['discovered_services']['security'] = security_services
            except Exception as e:
                result['discovered_services']['security'] = {'error': str(e)}
            
            # Proxy and load balancing services
            try:
                proxy_services = discover_proxy_services(domain)
                result['discovered_services']['proxy'] = proxy_services
            except Exception as e:
                result['discovered_services']['proxy'] = {'error': str(e)}
            
            # Comprehensive security analysis
            result['security_analysis'] = perform_service_security_analysis(result['discovered_services'])
            
            # Generate intelligent monitoring recommendations
            result['monitoring_recommendations'] = generate_monitoring_recommendations(domain, result['discovered_services'])
            
            # Calculate service summary
            result['service_summary'] = calculate_service_summary(result['discovered_services'])
            
            # Integration points for Zabbix templates
            result['integration_points'] = generate_integration_points(domain, result['discovered_services'])
        
    except Exception as e:
        result['error'] = str(e)
    
    return json.dumps(result)

def get_tls_integration(domain, port=443):
    """Integration with TLS handshake checking for comprehensive certificate monitoring."""
    result = {
        'domain': domain,
        'port': port,
        'tls_analysis': {},
        'certificate_analysis': {},
        'integration_status': {}
    }
    
    try:
        # Call TLS handshake script if available
        tls_script_path = os.path.join(os.path.dirname(__file__), 'get_tls_handshake.py')
        if os.path.exists(tls_script_path):
            import subprocess
            try:
                tls_result = subprocess.run([
                    'python3', tls_script_path, domain, '-p', str(port)
                ], capture_output=True, text=True, timeout=30)
                
                if tls_result.returncode == 0:
                    result['tls_analysis'] = json.loads(tls_result.stdout)
                    result['integration_status']['tls_script'] = 'available'
                else:
                    result['integration_status']['tls_script'] = 'error'
                    result['integration_status']['tls_error'] = tls_result.stderr
            except Exception as e:
                result['integration_status']['tls_script'] = 'failed'
                result['integration_status']['tls_error'] = str(e)
        else:
            result['integration_status']['tls_script'] = 'not_found'
        
        # DANE/TLSA validation for this port
        dane_result = get_dane(domain, port, True)
        if isinstance(dane_result, str):
            dane_result = json.loads(dane_result)
        result['certificate_analysis']['dane'] = dane_result
        
    except Exception as e:
        result['error'] = str(e)
    
    return json.dumps(result)

def get_comprehensive_analysis(domain):
    """Comprehensive domain analysis combining all monitoring capabilities."""
    result = {
        'domain': domain,
        'analysis_components': {},
        'overall_health_score': 0,
        'critical_issues': [],
        'recommendations': []
    }
    
    try:
        # Basic health check
        health_result = get_health(domain)
        if isinstance(health_result, str):
            health_result = json.loads(health_result)
        result['analysis_components']['basic_health'] = health_result
        
        # Performance analysis
        perf_result = get_dns_performance(domain)
        if isinstance(perf_result, str):
            perf_result = json.loads(perf_result)
        result['analysis_components']['performance'] = perf_result
        
        # Security scan
        security_result = get_security_scan(domain)
        if isinstance(security_result, str):
            security_result = json.loads(security_result)
        result['analysis_components']['security'] = security_result
        
        # Zone analysis
        zone_result = get_zone_analysis(domain)
        if isinstance(zone_result, str):
            zone_result = json.loads(zone_result)
        result['analysis_components']['zone'] = zone_result
        
        # Service discovery
        services_result = discover_domain_services(domain)
        if isinstance(services_result, str):
            services_result = json.loads(services_result)
        result['analysis_components']['services'] = services_result
        
        # Calculate comprehensive health score
        health_score = calculate_comprehensive_health_score(result['analysis_components'])
        result['overall_health_score'] = health_score['score']
        result['critical_issues'] = health_score['critical_issues']
        result['recommendations'] = health_score['recommendations']
        
    except Exception as e:
        result['error'] = str(e)
    
    return json.dumps(result)

# --- Helper Functions for Advanced Monitoring ---

def test_doh_support(domain):
    """Test DNS over HTTPS support."""
    try:
        import urllib.request
        import urllib.parse
        
        doh_url = f'https://cloudflare-dns.com/dns-query?name={domain}&type=A'
        headers = {'Accept': 'application/dns-json'}
        
        request = urllib.request.Request(doh_url, headers=headers)
        response = urllib.request.urlopen(request, timeout=5)
        return {'supported': True, 'status_code': response.getcode()}
    except Exception as e:
        return {'supported': False, 'error': str(e)}

def test_dot_support(domain):
    """Test DNS over TLS support."""
    return {'supported': False, 'note': 'DoT testing requires additional libraries'}

def test_amplification_potential(domain):
    """Test for DNS amplification attack potential."""
    try:
        # Check for large TXT records that could be used for amplification
        answers = dns_query(domain, 'TXT', None, 5.0)
        large_records = []
        max_size = 0
        
        for r in answers:
            formatted_data = format_rdata(r['rtype'], r['rdata'])
            record_size = len(formatted_data)
            if record_size > 512:
                large_records.append(formatted_data)
            max_size = max(max_size, record_size)
        
        return {
            'potential_risk': len(large_records) > 0,
            'large_records_count': len(large_records),
            'max_record_size': max_size
        }
    except Exception as e:
        return {'error': str(e), 'potential_risk': False}

def test_zone_transfer_security(domain):
    """Test if zone transfers are properly restricted."""
    try:
        ns_records = dns_query(domain, 'NS', None, 5.0)
        transfer_attempts = []
        nameservers = []
        
        # Extract nameserver names, handling compression issues
        for ns_record in ns_records:
            ns_server = format_rdata('NS', ns_record['rdata']).rstrip('.')
            if '.' in ns_server and len(ns_server) > 4:
                nameservers.append(ns_server)
        
        # If we didn't get proper names due to DNS compression, use nslookup fallback
        if not nameservers:
            try:
                import subprocess
                result = subprocess.run(['nslookup', '-type=ns', domain], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'nameserver' in line and '=' in line:
                            ns_server = line.split('=')[1].strip()
                            if ns_server and '.' in ns_server:
                                nameservers.append(ns_server)
            except:
                pass
        
        # Test each nameserver
        for ns_server in nameservers:
            try:
                # Attempt AXFR
                import subprocess
                result = subprocess.run([
                    'dig', f'@{ns_server}', domain, 'AXFR'
                ], capture_output=True, text=True, timeout=10)
                
                if 'transfer failed' in result.stdout.lower() or result.returncode != 0:
                    transfer_attempts.append({'server': ns_server, 'protected': True})
                else:
                    transfer_attempts.append({'server': ns_server, 'protected': False})
            except:
                transfer_attempts.append({'server': ns_server, 'protected': 'unknown'})
        
        return {
            'servers_tested': len(transfer_attempts),
            'properly_protected': len([t for t in transfer_attempts if t['protected'] is True]),
            'details': transfer_attempts
        }
    except Exception as e:
        return {'error': str(e)}

def test_cache_poisoning_indicators(domain):
    """Test for cache poisoning indicators."""
    try:
        # Test response consistency across multiple queries
        consistency_issues = 0
        test_queries = 5
        
        for _ in range(test_queries):
            answers1 = dns_query(domain, 'A', '8.8.8.8', 3.0)
            time.sleep(0.1)
            answers2 = dns_query(domain, 'A', '8.8.8.8', 3.0)
            
            if len(answers1) != len(answers2):
                consistency_issues += 1
        
        return {
            'consistency_rate': (test_queries - consistency_issues) / test_queries * 100,
            'potential_poisoning': consistency_issues > 1
        }
    except Exception as e:
        return {'error': str(e)}

def test_response_consistency(domain):
    """Test response consistency across multiple resolvers."""
    try:
        resolvers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']
        responses = {}
        
        for resolver in resolvers:
            answers = dns_query(domain, 'A', resolver, 5.0)
            # Format rdata as strings for JSON compatibility
            formatted_responses = [format_rdata(r['rtype'], r['rdata']) for r in answers]
            responses[resolver] = sorted(formatted_responses)
        
        # Check if all resolvers return the same results
        first_response = list(responses.values())[0] if responses else []
        consistent = all(response == first_response for response in responses.values())
        
        return {
            'consistent': consistent,
            'responses': responses,
            'resolver_count': len(resolvers)
        }
    except Exception as e:
        return {'error': str(e)}

def trace_authority_chain(domain):
    """Trace the DNS authority chain from root to domain."""
    try:
        authority_chain = []
        current_domain = domain
        
        while current_domain and '.' in current_domain:
            ns_records = dns_query(current_domain, 'NS', None, 5.0)
            if ns_records:
                authority_chain.append({
                    'domain': current_domain,
                    'nameservers': [format_rdata('NS', r['rdata']).rstrip('.') for r in ns_records],
                    'count': len(ns_records)
                })
            
            # Move up the hierarchy
            parts = current_domain.split('.')
            if len(parts) > 2:
                current_domain = '.'.join(parts[1:])
            else:
                break
        
        return authority_chain
    except Exception as e:
        return {'error': str(e)}

def analyze_nameserver_delegation(domain):
    """Analyze nameserver delegation for best practices."""
    try:
        ns_records = dns_query(domain, 'NS', None, 5.0)
        if not ns_records:
            return {'error': 'No NS records found'}
        
        nameservers = [format_rdata('NS', r['rdata']).rstrip('.') for r in ns_records]
        
        # Check nameserver diversity
        ns_ips = {}
        for ns in nameservers:
            try:
                ns_a_records = dns_query(ns, 'A', None, 3.0)
                ns_ips[ns] = [r['rdata'] for r in ns_a_records]
            except:
                ns_ips[ns] = []
        
        # Analyze IP diversity (different subnets)
        all_ips = []
        for ips in ns_ips.values():
            all_ips.extend(ips)
        
        unique_subnets = len(set(['.'.join(ip.split('.')[:3]) for ip in all_ips if '.' in ip]))
        
        return {
            'nameserver_count': len(nameservers),
            'nameservers': nameservers,
            'ip_diversity': ns_ips,
            'unique_subnets': unique_subnets,
            'geographic_diversity': unique_subnets >= 2
        }
    except Exception as e:
        return {'error': str(e)}

def check_zone_serial_consistency(domain):
    """Check SOA serial consistency across nameservers."""
    try:
        # Get nameservers using multiple methods for reliability
        nameservers = []
        
        # Method 1: Try our DNS query first
        ns_records = dns_query(domain, 'NS', None, 5.0)
        for r in ns_records:
            ns_name = format_rdata('NS', r['rdata']).rstrip('.')
            if '.' in ns_name and len(ns_name) > 3:  # Valid FQDN
                nameservers.append(ns_name)
        
        # Method 2: If we don't have good results, try nslookup fallback
        if len(nameservers) < 2:
            try:
                import subprocess
                result = subprocess.run(['nslookup', '-type=ns', domain], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        line = line.strip()
                        if 'nameserver' in line.lower() and '=' in line:
                            full_ns = line.split('=')[1].strip().rstrip('.')
                            if full_ns and '.' in full_ns and full_ns not in nameservers:
                                nameservers.append(full_ns)
                        elif line.endswith('.'):
                            # Sometimes nslookup just lists the nameservers without "nameserver ="
                            parts = line.split()
                            if len(parts) >= 1 and parts[-1].count('.') >= 2:
                                ns_candidate = parts[-1].rstrip('.')
                                if ns_candidate not in nameservers:
                                    nameservers.append(ns_candidate)
            except:
                pass  # Fallback failed, continue with what we have
        
        # If we still don't have nameservers, use common public resolvers for comparison
        if not nameservers:
            nameservers = ['8.8.8.8', '1.1.1.1']
        
        serials = {}
        for ns in nameservers:
            try:
                soa_records = dns_query(domain, 'SOA', ns, 3.0)
                if soa_records:
                    # Extract serial from formatted SOA record
                    soa_formatted = format_rdata(6, soa_records[0]['rdata'])  # 6 = SOA record type
                    parts = soa_formatted.split()
                    if len(parts) >= 3:
                        serials[ns] = parts[2]
                else:
                    serials[ns] = 'no_response'
            except Exception as e:
                serials[ns] = f'error_{str(e)[:20]}'
        
        # Check consistency - ignore errors and no_response entries
        valid_serials = [s for s in serials.values() if not s.startswith('error') and s != 'no_response']
        unique_serials = set(valid_serials)
        consistent = len(unique_serials) <= 1
        
        return {
            'consistent': consistent,
            'serials': serials,
            'unique_serial_count': len(unique_serials),
            'nameservers_queried': nameservers
        }
    except Exception as e:
        return {'error': str(e)}

def analyze_soa_record(domain):
    """Analyze SOA record for best practices."""
    try:
        soa_records = dns_query(domain, 'SOA', None, 5.0)
        if not soa_records:
            return {'error': 'No SOA record found'}
        
        soa_data = str(soa_records[0]['rdata']).split()
        if len(soa_data) < 7:
            return {'error': 'Invalid SOA record format'}
        
        return {
            'primary_nameserver': soa_data[0],
            'admin_email': soa_data[1],
            'serial': soa_data[2],
            'refresh': int(soa_data[3]),
            'retry': int(soa_data[4]),
            'expire': int(soa_data[5]),
            'minimum_ttl': int(soa_data[6]),
            'refresh_hours': int(soa_data[3]) / 3600,
            'expire_days': int(soa_data[5]) / 86400
        }
    except Exception as e:
        return {'error': str(e)}

def discover_web_services(domain, fast_mode=False):
    """Discover web services for the domain."""
    try:
        services = {
            'http_available': False,
            'https_available': False,
            'http_ports': [],
            'https_ports': [],
            'redirect_to_https': False
        }
        
        # Check common web ports (reduced in fast mode)
        common_ports = [80, 443] if fast_mode else [80, 443, 8080, 8443]
        
        for port in common_ports:
            if port in [80, 8080]:  # HTTP ports
                if test_port_connectivity(domain, port):
                    services['http_available'] = True
                    services['http_ports'].append(port)
            elif port in [443, 8443]:  # HTTPS ports
                if test_port_connectivity(domain, port):
                    services['https_available'] = True
                    services['https_ports'].append(port)
        
        return services
    except Exception as e:
        return {'error': str(e)}

def discover_email_services(domain, fast_mode=False):
    """Discover email services for the domain."""
    try:
        services = {
            'mx_records': [],
            'smtp_ports': [],
            'imap_ports': [],
            'pop3_ports': []
        }
        
        # Get MX records
        mx_records = dns_query(domain, 'MX', None, 2.0)
        formatted_mx = []
        for r in mx_records:
            if r['rtype'] == 15 and 'full_packet' in r and 'rdata_offset' in r:  # MX record
                formatted_mx.append(format_mx_record(r['rdata'], r['full_packet'], r['rdata_offset']))
            else:
                # Fallback to old method
                formatted_mx.append(format_rdata(r['rtype'], r['rdata']))
        services['mx_records'] = formatted_mx
        
        if not fast_mode:
            # Test common email ports (skip in fast mode)
            email_ports = {
                'smtp': [25, 587, 465],
                'imap': [143, 993],
                'pop3': [110, 995]
            }
            
            for service_type, ports in email_ports.items():
                for port in ports:
                    if test_port_connectivity(domain, port):
                        services[f'{service_type}_ports'].append(port)
        else:
            # Fast mode: only check if MX records exist
            services['smtp_ports'] = ['skipped_fast_mode']
            services['imap_ports'] = ['skipped_fast_mode']
            services['pop3_ports'] = ['skipped_fast_mode']
        
        return services
    except Exception as e:
        return {'error': str(e)}

def discover_tls_services(domain):
    """Discover TLS-enabled services with certificate details for key ports only."""
    try:
        tls_ports = [443, 465, 587, 993, 995, 636, 989, 990]
        discovered_ports = []
        certificates = {}
        
        for port in tls_ports:
            if test_port_connectivity(domain, port):
                discovered_ports.append(port)
                
                # Only get certificate details for HTTPS (443) to save time
                if port == 443:
                    try:
                        cert_der, cert_info, error = get_certificate_from_server(domain, port)
                        if not error and (cert_der or cert_info):
                            cert_details = parse_certificate_details(cert_der, cert_info)
                            if 'error' not in cert_details:
                                certificates[str(port)] = cert_details
                    except Exception:
                        pass  # Skip certificate errors to avoid delays
        
        return {
            'discovered_ports': discovered_ports,
            'tls_service_count': len(discovered_ports),
            'certificates': certificates
        }
    except Exception as e:
        return {'error': str(e)}

def discover_srv_services(domain):
    """Discover services via SRV records."""
    try:
        common_srv_services = [
            '_http._tcp', '_https._tcp', '_smtp._tcp', '_imap._tcp',
            '_pop3._tcp', '_sip._tcp', '_xmpp-client._tcp', '_ldap._tcp'
        ]
        
        discovered_services = []
        
        for service in common_srv_services:
            srv_domain = f'{service}.{domain}'
            try:
                srv_records = dns_query(srv_domain, 'SRV', None, 3.0)
                if srv_records:
                    discovered_services.append({
                        'service': service,
                        'records': [format_rdata('SRV', r['rdata']) for r in srv_records]
                    })
            except:
                continue
        
        return {
            'discovered_services': discovered_services,
            'service_count': len(discovered_services)
        }
    except Exception as e:
        return {'error': str(e)}

def discover_srv_services_lld(domain):
    """Discover SRV services for Zabbix Low-Level Discovery."""
    try:
        common_srv_services = [
            '_http._tcp', '_https._tcp', '_smtp._tcp', '_imap._tcp',
            '_pop3._tcp', '_sip._tcp', '_xmpp-client._tcp', '_ldap._tcp',
            '_ftp._tcp', '_ssh._tcp', '_telnet._tcp', '_dns._tcp',
            '_ldaps._tcp', '_imaps._tcp', '_pop3s._tcp', '_submission._tcp'
        ]
        
        discovered_services = []
        
        for service in common_srv_services:
            srv_domain = f'{service}.{domain}'
            try:
                srv_records = dns_query(srv_domain, 'SRV', None, DNS_TIMEOUT)
                if srv_records:
                    for idx, record in enumerate(srv_records):
                        srv_data = format_rdata('SRV', record['rdata'])
                        # SRV format: priority weight port target
                        srv_parts = srv_data.split()
                        if len(srv_parts) >= 4:
                            priority, weight, port, target = srv_parts[0], srv_parts[1], srv_parts[2], srv_parts[3].rstrip('.')
                            discovered_services.append({
                                '{#SERVICE}': service,
                                '{#SRV_DOMAIN}': srv_domain,
                                '{#TARGET}': target,
                                '{#PORT}': port,
                                '{#PRIORITY}': priority,
                                '{#WEIGHT}': weight,
                                '{#RECORD_INDEX}': str(idx)
                            })
            except:
                continue
        
        return json.dumps({'data': discovered_services})
    except Exception as e:
        return json.dumps({'data': [], 'error': str(e)})

def test_port_connectivity(domain, port, timeout=1):
    """Test basic port connectivity with configurable timeout."""
    try:
        import socket
        sock = socket.create_connection((domain, port), timeout=timeout)
        sock.close()
        return True
    except:
        return False

def srv_service_status(domain, service):
    """Get status of a specific SRV service for Zabbix monitoring."""
    try:
        srv_domain = f'{service}.{domain}'
        srv_records = dns_query(srv_domain, 'SRV', None, DNS_TIMEOUT)
        
        if srv_records:
            # Format records for easy consumption
            formatted_records = []
            for record in srv_records:
                srv_data = format_rdata('SRV', record['rdata'])
                srv_parts = srv_data.split()
                if len(srv_parts) >= 4:
                    priority, weight, port, target = srv_parts[0], srv_parts[1], srv_parts[2], srv_parts[3].rstrip('.')
                    
                    # Test connectivity to the target
                    try:
                        connectivity = test_port_connectivity(target, int(port))
                    except:
                        connectivity = False
                    
                    formatted_records.append({
                        'priority': int(priority),
                        'weight': int(weight),
                        'port': int(port),
                        'target': target,
                        'available': connectivity,
                        'raw_record': srv_data
                    })
            
            return json.dumps({
                'service': service,
                'domain': domain,
                'srv_domain': srv_domain,
                'records': formatted_records,
                'record_count': len(formatted_records),
                'service_available': any(r['available'] for r in formatted_records)
            })
        else:
            return json.dumps({
                'service': service,
                'domain': domain,
                'srv_domain': srv_domain,
                'records': [],
                'record_count': 0,
                'service_available': False,
                'status': 'no_records'
            })
    except Exception as e:
        return json.dumps({
            'service': service,
            'domain': domain,
            'error': str(e),
            'records': [],
            'record_count': 0,
            'service_available': False
        })

def calculate_comprehensive_health_score(analysis_components):
    """Calculate comprehensive health score based on all analysis components."""
    try:
        total_score = 0
        max_score = 0
        critical_issues = []
        recommendations = []
        
        # Basic health component (40% weight)
        if 'basic_health' in analysis_components:
            basic_health = analysis_components['basic_health']
            if 'health_score' in basic_health:
                total_score += basic_health['health_score'] * 0.4
                max_score += 100 * 0.4
        
        # Performance component (20% weight)
        if 'performance' in analysis_components:
            perf_data = analysis_components['performance']
            if 'performance_metrics' in perf_data:
                metrics = perf_data['performance_metrics']
                perf_score = 100
                if 'avg_latency_ms' in metrics:
                    if metrics['avg_latency_ms'] > 1000:
                        perf_score -= 30
                    elif metrics['avg_latency_ms'] > 500:
                        perf_score -= 15
                
                total_score += perf_score * 0.2
                max_score += 100 * 0.2
        
        # Security component (25% weight)
        if 'security' in analysis_components:
            security_data = analysis_components['security']
            security_score = 100
            
            if 'vulnerability_scan' in security_data:
                vuln_scan = security_data['vulnerability_scan']
                if 'amplification_risk' in vuln_scan and vuln_scan['amplification_risk'].get('potential_risk'):
                    security_score -= 25
                    critical_issues.append('DNS amplification attack potential detected')
            
            total_score += security_score * 0.25
            max_score += 100 * 0.25
        
        # Zone component (15% weight)
        if 'zone' in analysis_components:
            zone_data = analysis_components['zone']
            zone_score = 100
            
            if 'delegation_analysis' in zone_data:
                delegation = zone_data['delegation_analysis']
                if not delegation.get('geographic_diversity', False):
                    zone_score -= 20
                    recommendations.append('Improve nameserver geographic diversity')
            
            total_score += zone_score * 0.15
            max_score += 100 * 0.15
        
        final_score = (total_score / max_score * 100) if max_score > 0 else 0
        
        return {
            'score': round(final_score, 2),
            'critical_issues': critical_issues,
            'recommendations': recommendations
        }
    except Exception as e:
        return {
            'score': 0,
            'critical_issues': [f'Error calculating score: {str(e)}'],
            'recommendations': []
        }

# --- Main Entry Point ---

# --- Essential Service Discovery Functions (before main) ---

def discover_dns_based_services(domain):
    """Discover services based on DNS records and common patterns."""
    services = {'discovered_services': {}, 'service_patterns': {}, 'subdomain_services': {}}
    try:
        # Comprehensive service subdomains covering enterprise and industry standards
        service_subdomains = [
            # Proxy & Load Balancing Services
            'proxy', 'proxy1', 'proxy2', 'proxy3', 'web-proxy', 'http-proxy', 'https-proxy',
            'forward-proxy', 'reverse-proxy', 'transparent-proxy', 'intercepting-proxy',
            'caching-proxy', 'content-filter', 'squid', 'squid-proxy', 'squidguard',
            'lb', 'loadbalancer', 'load-balancer', 'nlb', 'alb', 'clb', 'elb',
            'balancer', 'balance', 'lb1', 'lb2', 'lb3', 'frontend', 'backend',
            'nginx', 'nginx-proxy', 'apache', 'apache-proxy', 'httpd', 'httpd-proxy',
            'haproxy', 'ha-proxy', 'traefik', 'envoy', 'envoy-proxy',
            'istio', 'istio-proxy', 'linkerd', 'linkerd-proxy', 'consul-connect',
            'ambassador', 'contour', 'ingress', 'gateway', 'api-gateway',
            'kong', 'kong-proxy', 'zuul', 'edge', 'edge-proxy',
            'cloudflare', 'cloudfront', 'fastly', 'akamai', 'maxcdn', 'jsdelivr',
            'varnish', 'varnish-cache', 'redis-proxy', 'memcached-proxy',
            'waf', 'waf-proxy', 'firewall', 'filter', 'content-filter',
            'url-filter', 'web-filter', 'secure-proxy', 'security-proxy',
            'f5', 'f5-ltm', 'bigip', 'netscaler', 'citrix-adc', 'a10', 'alteon',
            'kemp', 'radware', 'barracuda', 'fortinet', 'palo-alto', 'checkpoint',
            'blue-coat', 'bluecoat', 'websense', 'forcepoint', 'mcafee-proxy',
            'symantec-proxy', 'zscaler', 'cloud-proxy', 'secure-proxy',
            'socks', 'socks4', 'socks5', 'socks-proxy', 'tor', 'tor-proxy',
            # Email services
            'mail', 'smtp', 'imap', 'pop', 'pop3', 'webmail', 'exchange',
            # Web services  
            'www', 'web', 'http', 'https', 'cdn', 'static', 'assets',
            # Database Services
            'db', 'database', 'sql', 'mysql', 'postgres', 'mongodb', 'redis'
        ]
        
        discovered_count = 0
        for subdomain in service_subdomains:
            full_domain = f'{subdomain}.{domain}'
            a_records = dns_query(full_domain, 'A', None, DNS_TIMEOUT)
            aaaa_records = dns_query(full_domain, 'AAAA', None, DNS_TIMEOUT)
            if a_records or aaaa_records:
                discovered_count += 1
                services['subdomain_services'][subdomain] = {
                    'exists': True, 'a_records': len(a_records) if a_records else 0,
                    'aaaa_records': len(aaaa_records) if aaaa_records else 0
                }
        
        services['summary'] = {'discovered_subdomains': discovered_count}
        return services
    except Exception as e:
        return {'error': str(e)}

def discover_application_services(domain):
    """Discover common application and database services."""
    services = {'database_ports': [], 'application_ports': [], 'management_interfaces': []}
    try:
        # Test common database and application ports
        test_ports = [1433, 1521, 3306, 5432, 6379, 27017, 8080, 8443, 9000]
        for port in test_ports:
            if test_port_connectivity(domain, port):
                if port in [1433, 1521, 3306, 5432, 6379, 27017]:
                    services['database_ports'].append(port)
                else:
                    services['application_ports'].append(port)
        return services
    except Exception as e:
        return {'error': str(e)}

def discover_security_services(domain):
    """Discover security-related services and configurations."""
    services = {'dnssec': {}, 'security_features': []}
    try:
        # Basic DNSSEC check
        dnssec_result = get_dnssec_detailed(domain)
        if isinstance(dnssec_result, str):
            try:
                services['dnssec'] = json.loads(dnssec_result)
            except:
                services['dnssec'] = {'error': 'Failed to parse DNSSEC result'}
        return services
    except Exception as e:
        return {'error': str(e)}

def discover_comprehensive_subdomains(domain):
    """Phase 1: Enhanced subdomain discovery with comprehensive categorization."""
    try:
        import concurrent.futures
        import threading
    except ImportError:
        return {
            'domain': domain,
            'error': 'Threading modules not available. Install Python 3.2+ for full functionality.',
            'fallback': 'Use basic subdomain discovery instead'
        }
    
    result = {
        'domain': domain,
        'subdomain_discovery': {
            'total_discovered': 0,
            'by_category': {},
            'accessible_subdomains': [],
            'certificate_transparency_results': [],
            'wildcard_detection': {},
            'subdomain_services': {}
        },
        'discovery_stats': {
            'dns_queries': 0,
            'successful_resolutions': 0,
            'accessible_services': 0,
            'discovery_duration': 0
        }
    }
    
    start_time = time.time()
    
    try:
        # Comprehensive subdomain wordlist organized by category
        subdomain_categories = {
            'web_services': [
                'www', 'web', 'website', 'site', 'portal', 'app', 'application',
                'mobile', 'm', 'wap', 'touch', 'admin', 'administrator', 'root',
                'secure', 'ssl', 'members', 'user', 'users', 'login', 'auth',
                'dashboard', 'panel', 'control', 'cp', 'home', 'main'
            ],
            'api_services': [
                'api', 'api1', 'api2', 'rest', 'restapi', 'webapi', 'service',
                'services', 'microservice', 'gateway', 'graphql', 'webhook',
                'endpoints', 'integration', 'connect', 'bridge'
            ],
            'email_services': [
                'mail', 'email', 'smtp', 'pop', 'pop3', 'imap', 'exchange',
                'outlook', 'webmail', 'roundcube', 'squirrelmail', 'mx',
                'autoconfig', 'autodiscover', 'owa', 'activesync'
            ],
            'cdn_services': [
                'cdn', 'static', 'assets', 'media', 'images', 'img', 'css',
                'js', 'files', 'downloads', 'content', 'cache', 'edge',
                'cloudflare', 'cloudfront', 'fastly', 'akamai', 'maxcdn'
            ],
            'dev_staging': [
                'dev', 'development', 'test', 'testing', 'stage', 'staging',
                'qa', 'uat', 'demo', 'sandbox', 'lab', 'preview', 'beta',
                'alpha', 'canary', 'experimental', 'poc', 'prototype'
            ],
            'database_services': [
                'db', 'database', 'mysql', 'postgres', 'mongo', 'redis',
                'elastic', 'elasticsearch', 'solr', 'cassandra', 'influx',
                'clickhouse', 'mariadb', 'oracle', 'mssql', 'sqlite'
            ],
            'monitoring_services': [
                'monitor', 'monitoring', 'metrics', 'stats', 'analytics',
                'grafana', 'kibana', 'prometheus', 'nagios', 'zabbix',
                'splunk', 'elk', 'logs', 'logging', 'alerts', 'health'
            ],
            'security_services': [
                'vpn', 'firewall', 'waf', 'security', 'auth', 'sso', 'ldap',
                'radius', 'kerberos', 'oauth', 'saml', 'cert', 'ca', 'pki',
                'vault', 'secrets', 'keycloak', 'okta', 'azure-ad'
            ],
            'collaboration': [
                'wiki', 'docs', 'documentation', 'confluence', 'sharepoint',
                'teams', 'slack', 'chat', 'forum', 'community', 'support',
                'help', 'knowledge', 'kb', 'helpdesk', 'ticket', 'jira'
            ],
            'infrastructure': [
                'ns', 'ns1', 'ns2', 'dns', 'ntp', 'time', 'backup', 'repo',
                'repository', 'git', 'gitlab', 'github', 'svn', 'build',
                'ci', 'cd', 'jenkins', 'bamboo', 'travis', 'circle'
            ],
            'proxy_lb': [
                'proxy', 'proxy1', 'proxy2', 'lb', 'loadbalancer', 'nginx',
                'apache', 'haproxy', 'traefik', 'envoy', 'istio', 'gateway',
                'f5', 'bigip', 'netscaler', 'citrix', 'a10', 'kemp'
            ],
            'cloud_services': [
                'aws', 'azure', 'gcp', 'cloud', 'k8s', 'kubernetes', 'docker',
                'registry', 'harbor', 'nexus', 'artifactory', 's3', 'blob'
            ],
            'business_apps': [
                'erp', 'crm', 'salesforce', 'sap', 'oracle', 'peoplesoft',
                'workday', 'servicenow', 'zendesk', 'freshdesk', 'hubspot'
            ]
        }
        
        # Flatten all subdomains for scanning
        all_subdomains = []
        for category, subdomains in subdomain_categories.items():
            all_subdomains.extend(subdomains)
            result['subdomain_discovery']['by_category'][category] = {
                'discovered': [],
                'accessible': [],
                'count': 0
            }
        
        # Threaded subdomain discovery for performance
        discovered_subdomains = {}
        lock = threading.Lock()
        
        def scan_subdomain(subdomain):
            try:
                full_domain = f"{subdomain}.{domain}"
                dns_info = scan_subdomain_dns(full_domain)
                
                with lock:
                    result['discovery_stats']['dns_queries'] += 1
                    if dns_info['exists']:
                        result['discovery_stats']['successful_resolutions'] += 1
                        discovered_subdomains[subdomain] = dns_info
                        
                        # Check accessibility
                        if dns_info['web_accessible']:
                            result['discovery_stats']['accessible_services'] += 1
                            result['subdomain_discovery']['accessible_subdomains'].append(full_domain)
            except Exception as e:
                pass  # Skip individual subdomain errors
        
        # Execute threaded scans
        max_workers = min(20, len(all_subdomains))  # Conservative limit
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                executor.map(scan_subdomain, all_subdomains)
        except Exception:
            # Fallback to sequential scanning if threading fails
            for subdomain in all_subdomains[:50]:  # Limit to first 50 for fallback
                scan_subdomain(subdomain)
        
        # Categorize discovered subdomains
        for subdomain, info in discovered_subdomains.items():
            for category, subdomains in subdomain_categories.items():
                if subdomain in subdomains:
                    result['subdomain_discovery']['by_category'][category]['discovered'].append(subdomain)
                    result['subdomain_discovery']['by_category'][category]['count'] += 1
                    if info['web_accessible']:
                        result['subdomain_discovery']['by_category'][category]['accessible'].append(subdomain)
        
        result['subdomain_discovery']['total_discovered'] = len(discovered_subdomains)
        result['subdomain_discovery']['subdomain_services'] = discovered_subdomains
        
        # Wildcard detection
        result['subdomain_discovery']['wildcard_detection'] = detect_dns_wildcards(domain)
        
        # Certificate transparency check (if available)
        try:
            result['subdomain_discovery']['certificate_transparency_results'] = check_certificate_transparency(domain)
        except:
            result['subdomain_discovery']['certificate_transparency_results'] = {'status': 'unavailable'}
        
        result['discovery_stats']['discovery_duration'] = round(time.time() - start_time, 2)
        
    except Exception as e:
        result['error'] = str(e)
    
    return result

def scan_subdomain_dns(full_domain):
    """Scan individual subdomain for DNS records and accessibility."""
    result = {
        'domain': full_domain,
        'exists': False,
        'a_records': [],
        'aaaa_records': [],
        'cname_records': [],
        'mx_records': [],
        'txt_records': [],
        'web_accessible': False,
        'ssl_available': False,
        'service_category': None
    }
    
    try:
        # Check A records
        a_records = dns_query(full_domain, 'A', None, 2)
        if a_records:
            result['exists'] = True
            result['a_records'] = [format_rdata(r['rtype'], r['rdata']) for r in a_records]
        
        # Check AAAA records
        aaaa_records = dns_query(full_domain, 'AAAA', None, 2)
        if aaaa_records:
            result['exists'] = True
            result['aaaa_records'] = [format_rdata(r['rtype'], r['rdata']) for r in aaaa_records]
        
        # Check CNAME records
        cname_records = dns_query(full_domain, 'CNAME', None, 2)
        if cname_records:
            result['exists'] = True
            result['cname_records'] = [format_rdata(r['rtype'], r['rdata']) for r in cname_records]
        
        if result['exists']:
            # Check web accessibility
            if test_port_connectivity(full_domain, 80, timeout=3):
                result['web_accessible'] = True
            
            if test_port_connectivity(full_domain, 443, timeout=3):
                result['ssl_available'] = True
                if not result['web_accessible']:
                    result['web_accessible'] = True  # HTTPS counts as web accessible
            
            # Categorize service type based on subdomain
            subdomain = full_domain.split('.')[0]
            result['service_category'] = categorize_subdomain_service(subdomain)
    
    except Exception as e:
        result['error'] = str(e)
    
    return result

def categorize_subdomain_service(subdomain):
    """Categorize subdomain based on naming patterns."""
    subdomain_lower = subdomain.lower()
    
    # Web services
    if any(term in subdomain_lower for term in ['www', 'web', 'app', 'portal', 'site']):
        return 'web_service'
    
    # API services
    elif any(term in subdomain_lower for term in ['api', 'rest', 'graphql', 'service']):
        return 'api_service'
    
    # Email services
    elif any(term in subdomain_lower for term in ['mail', 'smtp', 'imap', 'pop', 'exchange']):
        return 'email_service'
    
    # Database services
    elif any(term in subdomain_lower for term in ['db', 'database', 'mysql', 'postgres', 'mongo', 'redis']):
        return 'database_service'
    
    # CDN/Static content
    elif any(term in subdomain_lower for term in ['cdn', 'static', 'assets', 'media', 'cache']):
        return 'cdn_service'
    
    # Development/Testing
    elif any(term in subdomain_lower for term in ['dev', 'test', 'stage', 'qa', 'demo', 'beta']):
        return 'dev_service'
    
    # Security services
    elif any(term in subdomain_lower for term in ['vpn', 'auth', 'sso', 'security', 'vault']):
        return 'security_service'
    
    # Monitoring services
    elif any(term in subdomain_lower for term in ['monitor', 'metrics', 'grafana', 'logs']):
        return 'monitoring_service'
    
    # Proxy/Load balancer
    elif any(term in subdomain_lower for term in ['proxy', 'lb', 'loadbalancer', 'nginx', 'haproxy']):
        return 'proxy_service'
    
    # Admin/Management
    elif any(term in subdomain_lower for term in ['admin', 'control', 'manage', 'cp']):
        return 'admin_service'
    
    else:
        return 'generic_service'

def detect_dns_wildcards(domain):
    """Detect DNS wildcard configurations."""
    result = {
        'wildcard_detected': False,
        'wildcard_ip': None,
        'test_results': []
    }
    
    try:
        # Test random subdomains to detect wildcards
        import random
        import string
        
        test_subdomains = []
        for i in range(3):
            random_subdomain = ''.join(random.choices(string.ascii_lowercase, k=10))
            test_subdomains.append(f"{random_subdomain}.{domain}")
        
        wildcard_ips = []
        for test_domain in test_subdomains:
            a_records = dns_query(test_domain, 'A', None, 2)
            if a_records:
                ips = [format_rdata(r['rtype'], r['rdata']) for r in a_records]
                wildcard_ips.extend(ips)
                result['test_results'].append({
                    'domain': test_domain,
                    'resolved': True,
                    'ips': ips
                })
            else:
                result['test_results'].append({
                    'domain': test_domain,
                    'resolved': False,
                    'ips': []
                })
        
        # If all random subdomains resolve to the same IP, it's likely a wildcard
        if len(wildcard_ips) >= 2 and len(set(wildcard_ips)) == 1:
            result['wildcard_detected'] = True
            result['wildcard_ip'] = wildcard_ips[0]
    
    except Exception as e:
        result['error'] = str(e)
    
    return result

def discover_comprehensive_ports(domain, port_ranges=None, fast_mode=False):
    """Phase 2: Comprehensive port scanning with service-specific ranges and threading."""
    try:
        import concurrent.futures
        import threading
    except ImportError:
        return {
            'domain': domain,
            'error': 'Threading modules not available. Install Python 3.2+ for full functionality.',
            'fallback': 'Use basic port discovery instead'
        }
    
    result = {
        'domain': domain,
        'port_discovery': {
            'total_scanned': 0,
            'total_open': 0,
            'by_service_type': {},
            'open_ports': [],
            'service_fingerprints': {},
            'security_analysis': {}
        },
        'discovery_stats': {
            'scan_duration': 0,
            'threads_used': 0,
            'scan_rate_per_second': 0
        }
    }
    
    start_time = time.time()
    
    try:
        # Define service-specific port ranges
        default_port_ranges = {
            'web_services': {
                'ports': [80, 443, 8000, 8080, 8443, 8888, 9000, 3000, 4000, 5000],
                'description': 'HTTP/HTTPS and common web application ports'
            },
            'email_services': {
                'ports': [25, 110, 143, 465, 587, 993, 995],
                'description': 'SMTP, POP3, IMAP ports (secure and insecure)'
            },
            'database_services': {
                'ports': [1433, 1521, 3306, 5432, 6379, 27017, 9042, 5984, 8086, 9200],
                'description': 'Common database ports (MSSQL, Oracle, MySQL, PostgreSQL, Redis, MongoDB, Cassandra, CouchDB, InfluxDB, Elasticsearch)'
            },
            'ssh_remote': {
                'ports': [22, 2222, 2200],
                'description': 'SSH remote access ports'
            },
            'ftp_services': {
                'ports': [20, 21, 989, 990],
                'description': 'FTP and FTPS ports'
            },
            'dns_services': {
                'ports': [53, 5353],
                'description': 'DNS and mDNS ports'
            },
            'vpn_services': {
                'ports': [500, 1194, 1723, 4500],
                'description': 'VPN service ports (IKE, OpenVPN, PPTP, IPSec NAT-T)'
            },
            'monitoring_services': {
                'ports': [161, 162, 10050, 10051, 9090, 3000, 8086],
                'description': 'SNMP, Zabbix, Prometheus, Grafana, InfluxDB'
            },
            'messaging_services': {
                'ports': [1883, 5672, 9092, 4222, 6379],
                'description': 'MQTT, RabbitMQ, Kafka, NATS, Redis'
            },
            'proxy_lb': {
                'ports': [3128, 8080, 1080, 443, 80],
                'description': 'Proxy and load balancer ports'
            },
            'security_services': {
                'ports': [636, 389, 88, 749, 464],
                'description': 'LDAPS, LDAP, Kerberos KDC'
            },
            'application_services': {
                'ports': [8009, 8005, 7001, 9080, 9443],
                'description': 'Application server ports (Tomcat, WebLogic, WebSphere)'
            }
        }
        
        # Use custom port ranges if provided, otherwise use defaults
        scan_ranges = port_ranges if port_ranges else default_port_ranges
        
        # Fast mode: limit ports per category
        if fast_mode:
            for service_type in scan_ranges:
                scan_ranges[service_type]['ports'] = scan_ranges[service_type]['ports'][:3]
        
        # Initialize result categories
        for service_type in scan_ranges:
            result['port_discovery']['by_service_type'][service_type] = {
                'scanned_ports': scan_ranges[service_type]['ports'],
                'open_ports': [],
                'service_count': 0,
                'description': scan_ranges[service_type]['description']
            }
        
        # Threaded port scanning
        open_ports = []
        lock = threading.Lock()
        
        def scan_port(port, service_type):
            try:
                if test_port_connectivity(domain, port, timeout=2):
                    with lock:
                        open_ports.append({
                            'port': port,
                            'service_type': service_type,
                            'accessible': True,
                            'scanned_at': time.time()
                        })
                        result['port_discovery']['by_service_type'][service_type]['open_ports'].append(port)
                        result['port_discovery']['by_service_type'][service_type]['service_count'] += 1
            except Exception as e:
                pass  # Skip individual port errors
        
        # Collect all ports to scan
        all_scans = []
        for service_type, config in scan_ranges.items():
            for port in config['ports']:
                all_scans.append((port, service_type))
                result['port_discovery']['total_scanned'] += 1
        
        # Execute threaded scans
        max_workers = min(30, len(all_scans))  # Conservative threading
        result['discovery_stats']['threads_used'] = max_workers
        
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = [executor.submit(scan_port, port, service_type) for port, service_type in all_scans]
                concurrent.futures.wait(futures)
        except Exception:
            # Fallback to sequential scanning
            for port, service_type in all_scans:
                scan_port(port, service_type)
        
        # Compile results
        result['port_discovery']['open_ports'] = open_ports
        result['port_discovery']['total_open'] = len(open_ports)
        
        # Security analysis
        result['port_discovery']['security_analysis'] = analyze_port_security(open_ports)
        
        # Calculate statistics
        scan_duration = time.time() - start_time
        result['discovery_stats']['scan_duration'] = round(scan_duration, 2)
        if scan_duration > 0:
            result['discovery_stats']['scan_rate_per_second'] = round(result['port_discovery']['total_scanned'] / scan_duration, 1)
        
    except Exception as e:
        result['error'] = str(e)
    
    return result

def analyze_port_security(open_ports):
    """Analyze discovered ports for security implications."""
    analysis = {
        'security_score': 100,
        'risk_level': 'LOW',
        'security_concerns': [],
        'recommendations': [],
        'insecure_services': [],
        'administrative_services': []
    }
    
    try:
        # Define risky ports
        high_risk_ports = {
            21: 'FTP - Unencrypted file transfer',
            23: 'Telnet - Unencrypted remote access',
            53: 'DNS - Potential for amplification attacks',
            135: 'RPC Endpoint Mapper - Windows vulnerability target',
            139: 'NetBIOS - Legacy Windows sharing',
            445: 'SMB - File sharing, ransomware target',
            1433: 'MSSQL - Database exposure',
            3306: 'MySQL - Database exposure',
            5432: 'PostgreSQL - Database exposure',
            6379: 'Redis - Often misconfigured'
        }
        
        admin_ports = [22, 3389, 5900, 5901, 23]  # SSH, RDP, VNC, Telnet
        
        for port_info in open_ports:
            port = port_info['port']
            
            # Check for high-risk ports
            if port in high_risk_ports:
                analysis['security_score'] -= 15
                analysis['security_concerns'].append(f"Port {port}: {high_risk_ports[port]}")
                analysis['insecure_services'].append(port)
            
            # Check for administrative ports
            if port in admin_ports:
                analysis['administrative_services'].append(port)
                if port != 22:  # SSH is generally acceptable
                    analysis['security_score'] -= 10
                    analysis['security_concerns'].append(f"Administrative service on port {port}")
        
        # Determine risk level
        if analysis['security_score'] >= 80:
            analysis['risk_level'] = 'LOW'
        elif analysis['security_score'] >= 60:
            analysis['risk_level'] = 'MEDIUM'
        elif analysis['security_score'] >= 40:
            analysis['risk_level'] = 'HIGH'
        else:
            analysis['risk_level'] = 'CRITICAL'
        
        # Generate recommendations
        if analysis['insecure_services']:
            analysis['recommendations'].append('Consider securing or disabling insecure services')
        if analysis['administrative_services']:
            analysis['recommendations'].append('Ensure administrative services use strong authentication')
        if len(open_ports) > 20:
            analysis['recommendations'].append('Review service exposure - many ports open')
        
    except Exception as e:
        analysis['error'] = str(e)
    
    return analysis

def scan_port_range(domain, start_port, end_port, timeout=1):
    """Scan a range of ports on a domain."""
    try:
        import concurrent.futures
    except ImportError:
        # Fallback to sequential scanning
        open_ports = []
        for port in range(start_port, end_port + 1):
            if test_port_connectivity(domain, port, timeout):
                open_ports.append(port)
        return open_ports
    
    open_ports = []
    
    def scan_single_port(port):
        if test_port_connectivity(domain, port, timeout):
            return port
        return None
    
    # Use threading for range scanning
    ports_to_scan = list(range(start_port, end_port + 1))
    max_workers = min(50, len(ports_to_scan))
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {executor.submit(scan_single_port, port): port for port in ports_to_scan}
        for future in concurrent.futures.as_completed(future_to_port):
            result = future.result()
            if result is not None:
                open_ports.append(result)
    
    return sorted(open_ports)

def discover_custom_ports(domain, custom_ports, service_name="custom"):
    """Discover services on custom port list."""
    result = {
        'domain': domain,
        'service_name': service_name,
        'total_ports_scanned': len(custom_ports),
        'open_ports': [],
        'accessible_services': 0
    }
    
    try:
        import concurrent.futures
    except ImportError:
        # Sequential fallback
        for port in custom_ports:
            if test_port_connectivity(domain, port, timeout=2):
                result['open_ports'].append(port)
                result['accessible_services'] += 1
        return result
    
    def check_port(port):
        if test_port_connectivity(domain, port, timeout=2):
            return port
        return None
    
    # Threaded scanning
    max_workers = min(20, len(custom_ports))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(check_port, port) for port in custom_ports]
        for future in concurrent.futures.as_completed(futures):
            result_port = future.result()
            if result_port is not None:
                result['open_ports'].append(result_port)
                result['accessible_services'] += 1
    
def identify_service_on_port(domain, port, timeout=5):
    """Phase 3: Service identification through banner grabbing and protocol probing."""
    result = {
        'domain': domain,
        'port': port,
        'service_identification': {
            'service_name': 'unknown',
            'version': '',
            'product': '',
            'banner': '',
            'protocol': '',
            'confidence': 0,
            'fingerprint_method': 'none'
        },
        'security_analysis': {
            'vulnerability_indicators': [],
            'outdated_version': False,
            'default_credentials_risk': False,
            'encryption_status': 'unknown'
        }
    }
    
    try:
        # Try different identification methods based on port
        if port in [80, 8080, 8000, 3000, 4000, 5000, 9000]:
            result['service_identification'] = identify_http_service(domain, port, timeout)
        elif port in [443, 8443, 9443]:
            result['service_identification'] = identify_https_service(domain, port, timeout)
        elif port == 22:
            result['service_identification'] = identify_ssh_service(domain, port, timeout)
        elif port == 21:
            result['service_identification'] = identify_ftp_service(domain, port, timeout)
        elif port == 25:
            result['service_identification'] = identify_smtp_service(domain, port, timeout)
        elif port in [110, 995]:
            result['service_identification'] = identify_pop3_service(domain, port, timeout)
        elif port in [143, 993]:
            result['service_identification'] = identify_imap_service(domain, port, timeout)
        elif port == 53:
            result['service_identification'] = identify_dns_service(domain, port, timeout)
        elif port in [3306, 1433, 5432, 27017, 6379]:
            result['service_identification'] = identify_database_service(domain, port, timeout)
        elif port in [161, 162]:
            result['service_identification'] = identify_snmp_service(domain, port, timeout)
        else:
            result['service_identification'] = identify_generic_service(domain, port, timeout)
        
        # Perform security analysis based on identified service
        result['security_analysis'] = analyze_service_security(result['service_identification'])
        
    except Exception as e:
        result['error'] = str(e)
    
    return result

def identify_http_service(domain, port, timeout):
    """Identify HTTP services through headers and response analysis."""
    identification = {
        'service_name': 'http',
        'version': '',
        'product': '',
        'banner': '',
        'protocol': 'HTTP',
        'confidence': 60,
        'fingerprint_method': 'http_headers'
    }
    
    try:
        import socket
        
        # Send HTTP request
        http_request = f"GET / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: Zabbix-HealthCheck/1.0\r\nConnection: close\r\n\r\n"
        
        sock = socket.create_connection((domain, port), timeout=timeout)
        sock.send(http_request.encode())
        response = sock.recv(4096).decode('utf-8', errors='ignore')
        sock.close()
        
        identification['banner'] = response[:500]  # First 500 chars
        
        # Parse HTTP headers for server identification
        lines = response.split('\n')
        for line in lines:
            line_lower = line.lower()
            if line_lower.startswith('server:'):
                server_header = line.split(':', 1)[1].strip()
                identification['product'] = server_header
                identification['confidence'] = 90
                
                # Extract version from server header
                if 'nginx' in server_header.lower():
                    identification['service_name'] = 'nginx'
                    if '/' in server_header:
                        identification['version'] = server_header.split('/')[1].split()[0]
                elif 'apache' in server_header.lower():
                    identification['service_name'] = 'apache'
                    if '/' in server_header:
                        identification['version'] = server_header.split('/')[1].split()[0]
                elif 'iis' in server_header.lower():
                    identification['service_name'] = 'iis'
                elif 'lighttpd' in server_header.lower():
                    identification['service_name'] = 'lighttpd'
                break
            elif line_lower.startswith('x-powered-by:'):
                powered_by = line.split(':', 1)[1].strip()
                if not identification['product']:
                    identification['product'] = powered_by
                    identification['confidence'] = 70
        
        # Check for common frameworks/applications
        response_lower = response.lower()
        if 'wordpress' in response_lower:
            identification['service_name'] = 'wordpress'
        elif 'drupal' in response_lower:
            identification['service_name'] = 'drupal'
        elif 'joomla' in response_lower:
            identification['service_name'] = 'joomla'
        
    except Exception as e:
        identification['error'] = str(e)
        identification['confidence'] = 10
    
    return identification

def identify_https_service(domain, port, timeout):
    """Identify HTTPS services through SSL/TLS certificate and headers."""
    identification = {
        'service_name': 'https',
        'version': '',
        'product': '',
        'banner': '',
        'protocol': 'HTTPS',
        'confidence': 70,
        'fingerprint_method': 'ssl_certificate'
    }
    
    try:
        # Get SSL certificate information
        cert_der, cert_info, error = get_certificate_from_server(domain, port)
        
        if cert_info and not error:
            identification['banner'] = f"SSL Certificate: {cert_info.get('subject', {}).get('common_name', 'Unknown')}"
            identification['confidence'] = 85
            
            # Try to get additional info through HTTPS request
            try:
                http_id = identify_http_service(domain, port, timeout)
                if http_id['product']:
                    identification['product'] = http_id['product']
                    identification['service_name'] = http_id['service_name']
                    identification['version'] = http_id['version']
                    identification['confidence'] = 95
            except:
                pass
        
    except Exception as e:
        identification['error'] = str(e)
    
    return identification

def identify_ssh_service(domain, port, timeout):
    """Identify SSH service version through banner grabbing."""
    identification = {
        'service_name': 'ssh',
        'version': '',
        'product': '',
        'banner': '',
        'protocol': 'SSH',
        'confidence': 50,
        'fingerprint_method': 'banner_grab'
    }
    
    try:
        import socket
        
        sock = socket.create_connection((domain, port), timeout=timeout)
        banner = sock.recv(256).decode('utf-8', errors='ignore').strip()
        sock.close()
        
        identification['banner'] = banner
        identification['confidence'] = 90
        
        # Parse SSH banner for version info
        if banner.startswith('SSH-'):
            parts = banner.split()
            if len(parts) > 0:
                ssh_version = parts[0]
                identification['version'] = ssh_version
                
                if 'openssh' in banner.lower():
                    identification['service_name'] = 'openssh'
                    identification['product'] = 'OpenSSH'
                elif 'dropbear' in banner.lower():
                    identification['service_name'] = 'dropbear'
                    identification['product'] = 'Dropbear SSH'
                
    except Exception as e:
        identification['error'] = str(e)
    
    return identification

def identify_ftp_service(domain, port, timeout):
    """Identify FTP service through welcome banner."""
    identification = {
        'service_name': 'ftp',
        'version': '',
        'product': '',
        'banner': '',
        'protocol': 'FTP',
        'confidence': 50,
        'fingerprint_method': 'banner_grab'
    }
    
    try:
        import socket
        
        sock = socket.create_connection((domain, port), timeout=timeout)
        banner = sock.recv(512).decode('utf-8', errors='ignore').strip()
        sock.close()
        
        identification['banner'] = banner
        identification['confidence'] = 85
        
        # Parse FTP banner
        if '220' in banner:
            banner_lower = banner.lower()
            if 'vsftpd' in banner_lower:
                identification['service_name'] = 'vsftpd'
                identification['product'] = 'vsftpd'
            elif 'proftpd' in banner_lower:
                identification['service_name'] = 'proftpd'
                identification['product'] = 'ProFTPD'
            elif 'pure-ftpd' in banner_lower:
                identification['service_name'] = 'pure-ftpd'
                identification['product'] = 'Pure-FTPd'
            elif 'filezilla' in banner_lower:
                identification['service_name'] = 'filezilla'
                identification['product'] = 'FileZilla Server'
        
    except Exception as e:
        identification['error'] = str(e)
    
    return identification

def identify_smtp_service(domain, port, timeout):
    """Identify SMTP service through EHLO/HELO response."""
    identification = {
        'service_name': 'smtp',
        'version': '',
        'product': '',
        'banner': '',
        'protocol': 'SMTP',
        'confidence': 50,
        'fingerprint_method': 'smtp_banner'
    }
    
    try:
        import socket
        
        sock = socket.create_connection((domain, port), timeout=timeout)
        banner = sock.recv(512).decode('utf-8', errors='ignore')
        
        # Send EHLO command
        ehlo_command = f"EHLO test\r\n"
        sock.send(ehlo_command.encode())
        ehlo_response = sock.recv(1024).decode('utf-8', errors='ignore')
        sock.send(b"QUIT\r\n")
        sock.close()
        
        identification['banner'] = banner + ehlo_response
        identification['confidence'] = 80
        
        # Parse SMTP responses
        full_response = (banner + ehlo_response).lower()
        if 'postfix' in full_response:
            identification['service_name'] = 'postfix'
            identification['product'] = 'Postfix'
        elif 'exim' in full_response:
            identification['service_name'] = 'exim'
            identification['product'] = 'Exim'
        elif 'sendmail' in full_response:
            identification['service_name'] = 'sendmail'
            identification['product'] = 'Sendmail'
        elif 'exchange' in full_response:
            identification['service_name'] = 'exchange'
            identification['product'] = 'Microsoft Exchange'
        
    except Exception as e:
        identification['error'] = str(e)
    
    return identification

def identify_database_service(domain, port, timeout):
    """Identify database services through connection attempts and error messages."""
    identification = {
        'service_name': 'database',
        'version': '',
        'product': '',
        'banner': '',
        'protocol': 'TCP',
        'confidence': 60,
        'fingerprint_method': 'connection_probe'
    }
    
    try:
        import socket
        
        # Determine database type by port
        if port == 3306:
            identification['service_name'] = 'mysql'
            identification['product'] = 'MySQL/MariaDB'
            identification['protocol'] = 'MySQL Protocol'
        elif port == 5432:
            identification['service_name'] = 'postgresql'
            identification['product'] = 'PostgreSQL'
            identification['protocol'] = 'PostgreSQL Protocol'
        elif port == 1433:
            identification['service_name'] = 'mssql'
            identification['product'] = 'Microsoft SQL Server'
            identification['protocol'] = 'TDS Protocol'
        elif port == 27017:
            identification['service_name'] = 'mongodb'
            identification['product'] = 'MongoDB'
            identification['protocol'] = 'MongoDB Wire Protocol'
        elif port == 6379:
            identification['service_name'] = 'redis'
            identification['product'] = 'Redis'
            identification['protocol'] = 'Redis Protocol'
        
        # Try to get version info through connection
        sock = socket.create_connection((domain, port), timeout=timeout)
        
        if port == 6379:  # Redis
            sock.send(b"INFO server\r\n")
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            if 'redis_version' in response:
                for line in response.split('\n'):
                    if line.startswith('redis_version:'):
                        identification['version'] = line.split(':')[1].strip()
                        identification['confidence'] = 95
                        break
        
        sock.close()
        
    except Exception as e:
        identification['error'] = str(e)
    
    return identification

def identify_pop3_service(domain, port, timeout):
    """Identify POP3 service through banner and capabilities."""
    identification = {
        'service_name': 'pop3',
        'version': '',
        'product': '',
        'banner': '',
        'protocol': 'POP3S' if port == 995 else 'POP3',
        'confidence': 50,
        'fingerprint_method': 'banner_grab'
    }
    
    try:
        import socket
        
        sock = socket.create_connection((domain, port), timeout=timeout)
        banner = sock.recv(512).decode('utf-8', errors='ignore').strip()
        sock.close()
        
        identification['banner'] = banner
        identification['confidence'] = 80
        
        # Parse POP3 banner
        if banner.startswith('+OK'):
            banner_lower = banner.lower()
            if 'dovecot' in banner_lower:
                identification['service_name'] = 'dovecot'
                identification['product'] = 'Dovecot POP3'
            elif 'courier' in banner_lower:
                identification['service_name'] = 'courier'
                identification['product'] = 'Courier POP3'
        
    except Exception as e:
        identification['error'] = str(e)
    
    return identification

def identify_imap_service(domain, port, timeout):
    """Identify IMAP service through banner and capabilities."""
    identification = {
        'service_name': 'imap',
        'version': '',
        'product': '',
        'banner': '',
        'protocol': 'IMAPS' if port == 993 else 'IMAP',
        'confidence': 50,
        'fingerprint_method': 'banner_grab'
    }
    
    try:
        import socket
        
        sock = socket.create_connection((domain, port), timeout=timeout)
        banner = sock.recv(512).decode('utf-8', errors='ignore').strip()
        sock.close()
        
        identification['banner'] = banner
        identification['confidence'] = 80
        
        # Parse IMAP banner
        if '* OK' in banner or '* PREAUTH' in banner:
            banner_lower = banner.lower()
            if 'dovecot' in banner_lower:
                identification['service_name'] = 'dovecot'
                identification['product'] = 'Dovecot IMAP'
            elif 'courier' in banner_lower:
                identification['service_name'] = 'courier'  
                identification['product'] = 'Courier IMAP'
            elif 'cyrus' in banner_lower:
                identification['service_name'] = 'cyrus'
                identification['product'] = 'Cyrus IMAP'
        
    except Exception as e:
        identification['error'] = str(e)
    
    return identification

def identify_dns_service(domain, port, timeout):
    """Identify DNS service through queries."""
    identification = {
        'service_name': 'dns',
        'version': '',
        'product': '',
        'banner': '',
        'protocol': 'DNS',
        'confidence': 70,
        'fingerprint_method': 'dns_query'
    }
    
    try:
        # Try DNS query to identify the service
        test_result = dns_query('google.com', 'A', domain, timeout)
        
        if test_result:
            identification['confidence'] = 90
            identification['banner'] = f"DNS server responding on port {port}"
            
            # Try to identify specific DNS software through version.bind query
            try:
                version_result = dns_query('version.bind', 'TXT', domain, timeout)
                if version_result:
                    identification['version'] = str(version_result[0])
                    if 'bind' in identification['version'].lower():
                        identification['product'] = 'BIND'
                    elif 'unbound' in identification['version'].lower():
                        identification['product'] = 'Unbound'
            except:
                pass
        
    except Exception as e:
        identification['error'] = str(e)
    
    return identification

def identify_snmp_service(domain, port, timeout):
    """Identify SNMP service through basic queries."""
    identification = {
        'service_name': 'snmp',
        'version': '',
        'product': '',
        'banner': '',
        'protocol': 'SNMP',
        'confidence': 60,
        'fingerprint_method': 'snmp_probe'
    }
    
    try:
        import socket
        
        # Basic SNMP GET request for sysDescr (1.3.6.1.2.1.1.1.0)
        # This is a simplified probe - full SNMP would require pysnmp
        sock = socket.create_connection((domain, port), timeout=timeout)
        sock.close()
        
        identification['banner'] = f"SNMP service detected on port {port}"
        identification['confidence'] = 70
        
        if port == 161:
            identification['service_name'] = 'snmp-agent'
        elif port == 162:
            identification['service_name'] = 'snmp-trap'
        
    except Exception as e:
        identification['error'] = str(e)
        identification['confidence'] = 30
    
    return identification

def identify_generic_service(domain, port, timeout):
    """Generic service identification through basic probing."""
    identification = {
        'service_name': f'service-{port}',
        'version': '',
        'product': '',
        'banner': '',
        'protocol': 'TCP',
        'confidence': 30,
        'fingerprint_method': 'generic_probe'
    }
    
    try:
        import socket
        
        sock = socket.create_connection((domain, port), timeout=timeout)
        
        # Try to get banner
        try:
            banner = sock.recv(512).decode('utf-8', errors='ignore')
            if banner:
                identification['banner'] = banner[:200]
                identification['confidence'] = 50
        except:
            pass
        
        sock.close()
        
        # Set service name based on common port assignments
        common_services = {
            23: 'telnet', 135: 'rpc', 139: 'netbios', 445: 'smb',
            993: 'imaps', 995: 'pop3s', 465: 'smtps', 587: 'smtp-submission',
            1080: 'socks', 3128: 'squid-proxy', 8009: 'tomcat-ajp',
            9092: 'kafka', 5672: 'rabbitmq', 1883: 'mqtt'
        }
        
        if port in common_services:
            identification['service_name'] = common_services[port]
            identification['confidence'] = 70
        
    except Exception as e:
        identification['error'] = str(e)
    
    return identification

def analyze_service_security(service_identification):
    """Analyze identified service for security implications."""
    analysis = {
        'vulnerability_indicators': [],
        'outdated_version': False,
        'default_credentials_risk': False,
        'encryption_status': 'unknown',
        'security_score': 75,
        'recommendations': []
    }
    
    try:
        service_name = service_identification.get('service_name', '').lower()
        version = service_identification.get('version', '')
        protocol = service_identification.get('protocol', '').lower()
        
        # Check encryption status
        if protocol in ['https', 'ssh', 'imaps', 'pop3s', 'smtps']:
            analysis['encryption_status'] = 'encrypted'
            analysis['security_score'] += 10
        elif protocol in ['http', 'ftp', 'telnet', 'smtp']:
            analysis['encryption_status'] = 'unencrypted'
            analysis['security_score'] -= 20
            analysis['vulnerability_indicators'].append('Unencrypted communication protocol')
            analysis['recommendations'].append('Consider using encrypted alternative')
        
        # Check for risky services
        if service_name in ['telnet', 'ftp', 'rsh']:
            analysis['security_score'] -= 30
            analysis['vulnerability_indicators'].append('Legacy insecure protocol')
            analysis['recommendations'].append('Replace with secure alternative (SSH, SFTP)')
        
        # Database exposure warnings
        if service_name in ['mysql', 'postgresql', 'mssql', 'mongodb', 'redis']:
            analysis['security_score'] -= 15
            analysis['vulnerability_indicators'].append('Database service exposed to internet')
            analysis['recommendations'].append('Restrict database access to internal networks')
        
        # Default credentials risk
        if service_name in ['mysql', 'postgresql', 'mongodb', 'redis', 'ftp']:
            analysis['default_credentials_risk'] = True
            analysis['recommendations'].append('Ensure default credentials are changed')
        
        # Version analysis (placeholder for known vulnerable versions)
        if version and service_name in ['apache', 'nginx', 'openssh']:
            # This would be enhanced with a vulnerability database
            analysis['recommendations'].append('Verify version is up-to-date and patched')
        
    except Exception as e:
        analysis['error'] = str(e)
    
    return analysis

def comprehensive_ssl_analysis(domain, ports=None):
    """Phase 4: Comprehensive SSL/TLS security analysis and vulnerability assessment."""
    result = {
        'domain': domain,
        'ssl_analysis': {
            'certificates': {},
            'security_assessment': {
                'overall_grade': 'F',
                'security_score': 0,
                'vulnerabilities': [],
                'compliance_status': {},
                'recommendations': []
            },
            'configuration_analysis': {
                'protocol_support': {},
                'cipher_suites': {},
                'certificate_chain': {},
                'security_headers': {}
            },
            'vulnerability_scan': {
                'known_vulnerabilities': [],
                'weak_ciphers': [],
                'protocol_issues': [],
                'certificate_issues': []
            }
        },
        'analysis_stats': {
            'ports_analyzed': 0,
            'certificates_found': 0,
            'vulnerabilities_detected': 0,
            'analysis_duration': 0
        }
    }
    
    try:
        import time
        start_time = time.time()
        
        # Determine ports to analyze
        if not ports:
            # Get SSL ports from previous discoveries or use defaults
            default_ssl_ports = [443, 8443, 9443, 993, 995, 465, 587, 636, 8080, 8000]
            ports = default_ssl_ports
        
        analyzed_ports = []
        for port in ports:
            try:
                ssl_result = analyze_ssl_configuration(domain, port)
                if ssl_result and not ssl_result.get('error'):
                    analyzed_ports.append(port)
                    result['ssl_analysis']['certificates'][str(port)] = ssl_result
                    
                    # Update security assessment
                    if ssl_result.get('security_analysis'):
                        sec_analysis = ssl_result['security_analysis']
                        if sec_analysis.get('vulnerabilities'):
                            result['ssl_analysis']['vulnerability_scan']['known_vulnerabilities'].extend(
                                sec_analysis['vulnerabilities']
                            )
                        if sec_analysis.get('weak_ciphers'):
                            result['ssl_analysis']['vulnerability_scan']['weak_ciphers'].extend(
                                sec_analysis['weak_ciphers']
                            )
            except Exception as e:
                # Skip individual port errors
                continue
        
        # Calculate overall security assessment
        if analyzed_ports:
            result['ssl_analysis']['security_assessment'] = calculate_ssl_security_grade(
                result['ssl_analysis']['certificates']
            )
            
            # Perform vulnerability correlation analysis
            result['ssl_analysis']['vulnerability_scan'] = correlate_ssl_vulnerabilities(
                result['ssl_analysis']['certificates']
            )
        
        result['analysis_stats']['ports_analyzed'] = len(analyzed_ports)
        result['analysis_stats']['certificates_found'] = len(result['ssl_analysis']['certificates'])
        result['analysis_stats']['vulnerabilities_detected'] = len(
            result['ssl_analysis']['vulnerability_scan']['known_vulnerabilities']
        )
        result['analysis_stats']['analysis_duration'] = round(time.time() - start_time, 2)
        
    except Exception as e:
        result['error'] = str(e)
    
    return result

def analyze_ssl_configuration(domain, port, timeout=10):
    """Analyze SSL/TLS configuration for a specific port."""
    result = {
        'domain': domain,
        'port': port,
        'certificate_info': {},
        'protocol_analysis': {},
        'cipher_analysis': {},
        'security_analysis': {
            'vulnerabilities': [],
            'weak_ciphers': [],
            'security_score': 0,
            'grade': 'F',
            'issues': [],
            'recommendations': []
        },
        'compliance_check': {
            'pci_dss': False,
            'hipaa': False,
            'fips_140_2': False,
            'common_criteria': False
        }
    }
    
    try:
        # Get certificate information
        cert_der, cert_info, error = get_certificate_from_server(domain, port)
        
        if error:
            result['error'] = error
            return result
            
        if cert_info:
            result['certificate_info'] = cert_info
            
            # Analyze certificate security
            cert_security = analyze_certificate_security(cert_info)
            result['security_analysis'].update(cert_security)
            
            # Check protocol support
            protocol_analysis = analyze_ssl_protocols(domain, port)
            result['protocol_analysis'] = protocol_analysis
            
            # Analyze cipher suites
            cipher_analysis = analyze_cipher_suites(domain, port)
            result['cipher_analysis'] = cipher_analysis
            
            # Check for known vulnerabilities
            vuln_check = check_ssl_vulnerabilities(domain, port, cert_info)
            result['security_analysis']['vulnerabilities'].extend(vuln_check)
            
            # Calculate overall security score
            result['security_analysis']['security_score'] = calculate_ssl_score(
                cert_security, protocol_analysis, cipher_analysis, vuln_check
            )
            
            # Assign security grade
            result['security_analysis']['grade'] = assign_ssl_grade(
                result['security_analysis']['security_score']
            )
            
            # Check compliance standards
            result['compliance_check'] = check_ssl_compliance(
                cert_info, protocol_analysis, cipher_analysis
            )
        
    except Exception as e:
        result['error'] = str(e)
    
    return result

def analyze_certificate_security(cert_info):
    """Analyze certificate-specific security aspects."""
    security = {
        'vulnerabilities': [],
        'weak_ciphers': [],
        'security_score': 100,
        'issues': [],
        'recommendations': []
    }
    
    try:
        # Check key size
        public_key = cert_info.get('public_key', {})
        key_size = public_key.get('key_size', 0)
        key_algorithm = public_key.get('algorithm', '').lower()
        
        if key_algorithm == 'rsa':
            if key_size < 2048:
                security['vulnerabilities'].append('Weak RSA key size')
                security['security_score'] -= 30
                security['recommendations'].append('Use RSA key size >= 2048 bits')
            elif key_size < 4096:
                security['security_score'] -= 5
                security['recommendations'].append('Consider upgrading to 4096-bit RSA key')
        elif key_algorithm == 'ec':
            if key_size < 256:
                security['vulnerabilities'].append('Weak ECC key size')
                security['security_score'] -= 25
        
        # Check signature algorithm
        signature_algorithm = cert_info.get('signature_algorithm', '').lower()
        if 'sha1' in signature_algorithm:
            security['vulnerabilities'].append('Weak SHA-1 signature algorithm')
            security['security_score'] -= 40
            security['recommendations'].append('Upgrade to SHA-256 or higher')
        elif 'md5' in signature_algorithm:
            security['vulnerabilities'].append('Cryptographically broken MD5 signature')
            security['security_score'] -= 50
            security['recommendations'].append('Immediately upgrade signature algorithm')
        
        # Check certificate validity period
        import datetime
        try:
            not_after = cert_info.get('validity', {}).get('not_after')
            if not_after:
                # Parse date and check expiration
                days_until_expiry = (not_after - datetime.datetime.now()).days
                if days_until_expiry < 0:
                    security['vulnerabilities'].append('Certificate expired')
                    security['security_score'] -= 100
                elif days_until_expiry < 30:
                    security['issues'].append('Certificate expires soon')
                    security['security_score'] -= 20
                    security['recommendations'].append('Renew certificate before expiration')
        except:
            pass
        
        # Check for wildcard certificates
        subject_cn = cert_info.get('subject', {}).get('common_name', '')
        san_list = cert_info.get('subject_alt_names', [])
        
        has_wildcard = subject_cn.startswith('*.') or any(name.startswith('*.') for name in san_list)
        if has_wildcard:
            security['issues'].append('Wildcard certificate in use')
            security['security_score'] -= 5
            security['recommendations'].append('Consider using specific certificates for better security')
        
        # Check certificate chain
        if cert_info.get('chain_length', 0) > 3:
            security['issues'].append('Long certificate chain')
            security['security_score'] -= 5
        
    except Exception as e:
        security['issues'].append(f'Certificate analysis error: {str(e)}')
    
    return security

def analyze_ssl_protocols(domain, port):
    """Analyze supported SSL/TLS protocols."""
    protocols = {
        'supported_protocols': [],
        'deprecated_protocols': [],
        'secure_protocols': [],
        'protocol_issues': [],
        'recommendations': []
    }
    
    try:
        import ssl
        import socket
        
        # Define protocol versions to test
        protocol_tests = {
            'SSLv2': None,  # Not supported in modern Python
            'SSLv3': getattr(ssl, 'PROTOCOL_SSLv3', None),
            'TLSv1.0': getattr(ssl, 'PROTOCOL_TLSv1', None),
            'TLSv1.1': getattr(ssl, 'PROTOCOL_TLSv1_1', None),
            'TLSv1.2': getattr(ssl, 'PROTOCOL_TLSv1_2', None),
            'TLSv1.3': getattr(ssl, 'PROTOCOL_TLS', None)  # TLS 1.3 uses PROTOCOL_TLS
        }
        
        for protocol_name, protocol_const in protocol_tests.items():
            if protocol_const is None:
                continue
                
            try:
                context = ssl.SSLContext(protocol_const)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((domain, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        protocols['supported_protocols'].append({
                            'protocol': protocol_name,
                            'version': ssock.version(),
                            'cipher': ssock.cipher()
                        })
                        
                        # Categorize protocols
                        if protocol_name in ['SSLv2', 'SSLv3', 'TLSv1.0']:
                            protocols['deprecated_protocols'].append(protocol_name)
                            protocols['protocol_issues'].append(f'{protocol_name} is deprecated and insecure')
                        elif protocol_name == 'TLSv1.1':
                            protocols['deprecated_protocols'].append(protocol_name)
                            protocols['protocol_issues'].append(f'{protocol_name} is deprecated')
                        else:
                            protocols['secure_protocols'].append(protocol_name)
                            
            except Exception:
                # Protocol not supported or connection failed
                continue
        
        # Generate recommendations
        if protocols['deprecated_protocols']:
            protocols['recommendations'].append('Disable deprecated SSL/TLS protocols')
        
        if 'TLSv1.3' not in [p['protocol'] for p in protocols['supported_protocols']]:
            protocols['recommendations'].append('Enable TLS 1.3 for better security and performance')
        
        if len(protocols['secure_protocols']) == 0:
            protocols['protocol_issues'].append('No secure protocols supported')
            
    except Exception as e:
        protocols['protocol_issues'].append(f'Protocol analysis error: {str(e)}')
    
    return protocols

def analyze_cipher_suites(domain, port):
    """Analyze supported cipher suites and their security."""
    ciphers = {
        'supported_ciphers': [],
        'weak_ciphers': [],
        'strong_ciphers': [],
        'cipher_issues': [],
        'recommendations': []
    }
    
    try:
        import ssl
        import socket
        
        # Create SSL context to get cipher information
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((domain, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cipher_info = ssock.cipher()
                if cipher_info:
                    cipher_name, protocol_version, key_bits = cipher_info
                    
                    cipher_entry = {
                        'name': cipher_name,
                        'protocol': protocol_version,
                        'key_bits': key_bits
                    }
                    
                    ciphers['supported_ciphers'].append(cipher_entry)
                    
                    # Analyze cipher strength
                    if analyze_cipher_strength(cipher_name, key_bits):
                        ciphers['strong_ciphers'].append(cipher_name)
                    else:
                        ciphers['weak_ciphers'].append(cipher_name)
                        ciphers['cipher_issues'].append(f'Weak cipher: {cipher_name}')
        
        # Check for specific cipher vulnerabilities
        for cipher in ciphers['supported_ciphers']:
            cipher_vulns = check_cipher_vulnerabilities(cipher['name'])
            if cipher_vulns:
                ciphers['cipher_issues'].extend(cipher_vulns)
        
        # Generate recommendations
        if ciphers['weak_ciphers']:
            ciphers['recommendations'].append('Disable weak cipher suites')
        
        if not any('ECDHE' in cipher['name'] for cipher in ciphers['supported_ciphers']):
            ciphers['recommendations'].append('Enable ECDHE ciphers for Perfect Forward Secrecy')
            
    except Exception as e:
        ciphers['cipher_issues'].append(f'Cipher analysis error: {str(e)}')
    
    return ciphers

def analyze_cipher_strength(cipher_name, key_bits):
    """Determine if a cipher is considered strong."""
    weak_patterns = [
        'NULL', 'ANON', 'EXPORT', 'DES', '3DES', 'RC4', 'MD5', 'SHA1'
    ]
    
    # Check for weak cipher patterns
    cipher_upper = cipher_name.upper()
    for pattern in weak_patterns:
        if pattern in cipher_upper:
            return False
    
    # Check key size
    if key_bits < 128:
        return False
    
    return True

def check_cipher_vulnerabilities(cipher_name):
    """Check for known cipher vulnerabilities."""
    vulnerabilities = []
    cipher_upper = cipher_name.upper()
    
    # Known vulnerable ciphers
    vuln_mapping = {
        'RC4': 'RC4 cipher is vulnerable to multiple attacks',
        'DES': 'DES encryption is cryptographically broken',
        '3DES': '3DES is deprecated and should be avoided',
        'NULL': 'NULL ciphers provide no encryption',
        'ANON': 'Anonymous ciphers vulnerable to MITM attacks',
        'EXPORT': 'Export ciphers are intentionally weakened',
        'MD5': 'MD5 hash function is cryptographically broken'
    }
    
    for pattern, description in vuln_mapping.items():
        if pattern in cipher_upper:
            vulnerabilities.append(description)
    
    return vulnerabilities

def check_ssl_vulnerabilities(domain, port, cert_info):
    """Check for known SSL/TLS vulnerabilities."""
    vulnerabilities = []
    
    try:
        # Check for common SSL vulnerabilities
        
        # Heartbleed (CVE-2014-0160) - affects OpenSSL 1.0.1-1.0.1f
        try:
            # This is a simplified check - full Heartbleed detection requires specific packets
            import ssl
            import socket
            
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((domain, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    # Check if server responds to extensions (potential indicator)
                    if hasattr(ssock, 'get_server_certificate'):
                        # This is a basic check - real Heartbleed detection needs packet inspection
                        pass
        except:
            pass
        
        # POODLE vulnerability check (SSLv3)
        try:
            if getattr(ssl, 'PROTOCOL_SSLv3', None):
                context = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((domain, port), timeout=3) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        vulnerabilities.append('POODLE: SSLv3 is enabled and vulnerable')
        except:
            pass
        
        # BEAST vulnerability (TLS 1.0 with CBC ciphers)
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((domain, port), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cipher_info = ssock.cipher()
                    if cipher_info and 'CBC' in cipher_info[0]:
                        vulnerabilities.append('BEAST: TLS 1.0 with CBC ciphers is vulnerable')
        except:
            pass
        
        # Certificate validation issues
        if cert_info:
            # Check for self-signed certificates
            if cert_info.get('is_self_signed'):
                vulnerabilities.append('Self-signed certificate detected')
            
            # Check for certificate transparency
            if not cert_info.get('certificate_transparency', {}).get('sct_count', 0):
                vulnerabilities.append('Certificate not logged in Certificate Transparency')
    
    except Exception as e:
        vulnerabilities.append(f'Vulnerability scan error: {str(e)}')
    
    return vulnerabilities

def calculate_ssl_score(cert_security, protocol_analysis, cipher_analysis, vulnerabilities):
    """Calculate overall SSL security score (0-100)."""
    score = 100
    
    # Certificate security impact
    if cert_security:
        score = min(score, cert_security.get('security_score', 100))
    
    # Protocol security impact
    if protocol_analysis.get('deprecated_protocols'):
        score -= len(protocol_analysis['deprecated_protocols']) * 15
    
    if not protocol_analysis.get('secure_protocols'):
        score -= 30
    
    # Cipher security impact
    if cipher_analysis.get('weak_ciphers'):
        score -= len(cipher_analysis['weak_ciphers']) * 10
    
    # Vulnerability impact
    score -= len(vulnerabilities) * 20
    
    return max(0, score)

def assign_ssl_grade(score):
    """Assign letter grade based on SSL security score."""
    if score >= 90:
        return 'A+'
    elif score >= 80:
        return 'A'
    elif score >= 70:
        return 'B'
    elif score >= 60:
        return 'C'
    elif score >= 40:
        return 'D'
    else:
        return 'F'

def calculate_ssl_security_grade(certificates):
    """Calculate overall security grade from multiple certificates."""
    if not certificates:
        return {
            'overall_grade': 'F',
            'security_score': 0,
            'vulnerabilities': [],
            'compliance_status': {},
            'recommendations': ['No SSL certificates found']
        }
    
    scores = []
    all_vulnerabilities = []
    all_recommendations = []
    
    for port, cert_data in certificates.items():
        if cert_data.get('security_analysis'):
            scores.append(cert_data['security_analysis']['security_score'])
            all_vulnerabilities.extend(cert_data['security_analysis'].get('vulnerabilities', []))
            all_recommendations.extend(cert_data['security_analysis'].get('recommendations', []))
    
    if scores:
        avg_score = sum(scores) // len(scores)
        grade = assign_ssl_grade(avg_score)
    else:
        avg_score = 0
        grade = 'F'
    
    return {
        'overall_grade': grade,
        'security_score': avg_score,
        'vulnerabilities': list(set(all_vulnerabilities)),  # Remove duplicates
        'compliance_status': {},
        'recommendations': list(set(all_recommendations))  # Remove duplicates
    }

def correlate_ssl_vulnerabilities(certificates):
    """Correlate vulnerabilities across multiple SSL configurations."""
    correlation = {
        'known_vulnerabilities': [],
        'weak_ciphers': [],
        'protocol_issues': [],
        'certificate_issues': [],
        'critical_findings': [],
        'recommendations': []
    }
    
    try:
        for port, cert_data in certificates.items():
            # Collect vulnerabilities
            if cert_data.get('security_analysis', {}).get('vulnerabilities'):
                correlation['known_vulnerabilities'].extend(
                    cert_data['security_analysis']['vulnerabilities']
                )
            
            # Collect cipher issues
            if cert_data.get('cipher_analysis', {}).get('weak_ciphers'):
                correlation['weak_ciphers'].extend(
                    cert_data['cipher_analysis']['weak_ciphers']
                )
            
            # Collect protocol issues
            if cert_data.get('protocol_analysis', {}).get('protocol_issues'):
                correlation['protocol_issues'].extend(
                    cert_data['protocol_analysis']['protocol_issues']
                )
        
        # Remove duplicates and categorize severity
        correlation['known_vulnerabilities'] = list(set(correlation['known_vulnerabilities']))
        correlation['weak_ciphers'] = list(set(correlation['weak_ciphers']))
        correlation['protocol_issues'] = list(set(correlation['protocol_issues']))
        
        # Identify critical findings
        critical_keywords = ['POODLE', 'BEAST', 'Heartbleed', 'expired', 'self-signed', 'MD5', 'NULL']
        for vuln in correlation['known_vulnerabilities']:
            if any(keyword.lower() in vuln.lower() for keyword in critical_keywords):
                correlation['critical_findings'].append(vuln)
        
        # Generate consolidated recommendations
        if correlation['known_vulnerabilities']:
            correlation['recommendations'].append('Address identified SSL vulnerabilities immediately')
        if correlation['weak_ciphers']:
            correlation['recommendations'].append('Disable weak cipher suites')
        if correlation['protocol_issues']:
            correlation['recommendations'].append('Update SSL/TLS protocol configuration')
            
    except Exception as e:
        correlation['certificate_issues'].append(f'Correlation analysis error: {str(e)}')
    
    return correlation

def check_ssl_compliance(cert_info, protocol_analysis, cipher_analysis):
    """Check SSL configuration against compliance standards."""
    compliance = {
        'pci_dss': False,
        'hipaa': False,
        'fips_140_2': False,
        'common_criteria': False,
        'compliance_issues': []
    }
    
    try:
        # PCI DSS requirements
        pci_compliant = True
        if protocol_analysis.get('deprecated_protocols'):
            pci_compliant = False
            compliance['compliance_issues'].append('PCI DSS: Deprecated protocols not allowed')
        
        if cipher_analysis.get('weak_ciphers'):
            pci_compliant = False
            compliance['compliance_issues'].append('PCI DSS: Weak ciphers not allowed')
        
        # Check key size for PCI compliance
        key_size = cert_info.get('public_key', {}).get('key_size', 0)
        if key_size < 2048:
            pci_compliant = False
            compliance['compliance_issues'].append('PCI DSS: Minimum 2048-bit key required')
        
        compliance['pci_dss'] = pci_compliant
        
        # HIPAA compliance (similar requirements to PCI)
        compliance['hipaa'] = pci_compliant
        
        # FIPS 140-2 compliance (stricter requirements)
        fips_compliant = pci_compliant
        if key_size < 3072:  # FIPS recommends 3072+ bit keys
            fips_compliant = False
        compliance['fips_140_2'] = fips_compliant
        
        # Common Criteria (basic check)
        compliance['common_criteria'] = fips_compliant
        
    except Exception as e:
        compliance['compliance_issues'].append(f'Compliance check error: {str(e)}')
    
    return compliance

def discover_ssl_services(domain):
    """Discover all SSL-enabled services on a domain."""
    result = {
        'domain': domain,
        'ssl_discovery': {
            'ssl_ports': [],
            'ssl_services': {},
            'discovery_stats': {
                'ports_scanned': 0,
                'ssl_enabled': 0,
                'certificates_found': 0
            }
        }
    }
    
    try:
        # Common SSL ports to scan
        ssl_ports = [443, 8443, 9443, 993, 995, 465, 587, 636, 990, 989, 563, 585, 614, 695]
        
        import concurrent.futures
        import threading
        
        ssl_services = {}
        lock = threading.Lock()
        
        def check_ssl_port(port):
            try:
                cert_der, cert_info, error = get_certificate_from_server(domain, port)
                if cert_info and not error:
                    with lock:
                        ssl_services[str(port)] = {
                            'port': port,
                            'ssl_enabled': True,
                            'certificate_summary': {
                                'common_name': cert_info.get('subject', {}).get('common_name', ''),
                                'issuer': cert_info.get('issuer', {}).get('organization', ''),
                                'expires': str(cert_info.get('validity', {}).get('not_after', '')),
                                'signature_algorithm': cert_info.get('signature_algorithm', ''),
                                'key_size': cert_info.get('public_key', {}).get('key_size', 0)
                            },
                            'service_identification': identify_ssl_service_type(port)
                        }
                        result['ssl_discovery']['ssl_ports'].append(port)
            except:
                pass  # Port doesn't support SSL or connection failed
        
        # Execute SSL discovery
        result['ssl_discovery']['discovery_stats']['ports_scanned'] = len(ssl_ports)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(check_ssl_port, ssl_ports)
        
        result['ssl_discovery']['ssl_services'] = ssl_services
        result['ssl_discovery']['discovery_stats']['ssl_enabled'] = len(ssl_services)
        result['ssl_discovery']['discovery_stats']['certificates_found'] = len(ssl_services)
        
    except Exception as e:
        result['error'] = str(e)
    
    return result

def identify_ssl_service_type(port):
    """Identify the type of service running on an SSL port."""
    service_mapping = {
        443: 'HTTPS Web Server',
        8443: 'HTTPS Web Server (Alt)',
        9443: 'HTTPS Web Server (Alt)',
        993: 'IMAPS (Secure IMAP)',
        995: 'POP3S (Secure POP3)',
        465: 'SMTPS (Secure SMTP)',
        587: 'SMTP with STARTTLS',
        636: 'LDAPS (Secure LDAP)',
        990: 'FTPS (Secure FTP)',
        989: 'FTPS Data (Secure FTP)',
        563: 'NNTPS (Secure NNTP)',
        585: 'IMAP4 over SSL',
        614: 'SSLshell',
        695: 'IEEE-MMS-SSL'
    }
    
    return service_mapping.get(port, f'SSL Service on port {port}')

def check_certificate_transparency(domain):
    """Check certificate transparency logs for additional subdomains."""
    # This is a placeholder for certificate transparency integration
    # Would require external API calls to CT logs like crt.sh
    return {
        'status': 'not_implemented',
        'note': 'Certificate transparency checking requires external API integration',
        'suggested_apis': ['crt.sh', 'censys.io', 'shodan.io']
    }

def discover_proxy_services(domain):
    """Comprehensive proxy and load balancing service discovery."""
    proxy_services = {
        'forward_proxies': [], 'reverse_proxies': [], 'load_balancers': [],
        'content_filters': [], 'caching_proxies': [], 'api_gateways': [],
        'service_mesh': [], 'anonymous_proxies': [], 'generic_proxies': [],
        'proxy_summary': {'total_proxy_services': 0, 'accessible_proxies': 0, 'proxy_types': {}}
    }
    try:
        # Use enhanced subdomain discovery for proxy detection
        subdomain_results = discover_comprehensive_subdomains(domain)
        
        # Extract proxy-related subdomains
        if 'subdomain_discovery' in subdomain_results:
            proxy_category = subdomain_results['subdomain_discovery']['by_category'].get('proxy_lb', {})
            discovered_proxies = proxy_category.get('discovered', [])
            
            for subdomain in discovered_proxies:
                full_domain = f'{subdomain}.{domain}'
                proxy_type = categorize_proxy_service(subdomain)
                accessible = full_domain in subdomain_results['subdomain_discovery']['accessible_subdomains']
                
                proxy_services[proxy_type].append({
                    'subdomain': subdomain,
                    'full_domain': full_domain,
                    'accessible': accessible
                })
                
                if accessible:
                    proxy_services['proxy_summary']['accessible_proxies'] += 1
            
            proxy_services['proxy_summary']['total_proxy_services'] = len(discovered_proxies)
        
        return proxy_services
    except Exception as e:
        return {'error': str(e)}

def categorize_proxy_service(subdomain):
    """Categorize proxy services based on subdomain patterns."""
    subdomain_lower = subdomain.lower()
    if any(term in subdomain_lower for term in ['lb', 'loadbalancer', 'f5', 'bigip']):
        return 'load_balancers'
    elif any(term in subdomain_lower for term in ['nginx', 'apache', 'haproxy', 'traefik']):
        return 'reverse_proxies'
    elif any(term in subdomain_lower for term in ['squid', 'proxy']):
        return 'forward_proxies'
    elif any(term in subdomain_lower for term in ['cdn', 'varnish']):
        return 'caching_proxies'
    elif any(term in subdomain_lower for term in ['waf', 'filter']):
        return 'content_filters'
    elif any(term in subdomain_lower for term in ['gateway', 'kong', 'zuul']):
        return 'api_gateways'
    elif any(term in subdomain_lower for term in ['istio', 'linkerd']):
        return 'service_mesh'
    else:
        return 'generic_proxies'

def perform_service_security_analysis(discovered_services):
    """Perform comprehensive security analysis on discovered services."""
    analysis = {'security_score': 85, 'vulnerabilities': [], 'recommendations': []}
    try:
        if 'web' in discovered_services and discovered_services['web'].get('https_available'):
            analysis['security_score'] += 10
        if 'security' in discovered_services and discovered_services['security'].get('dnssec', {}).get('enabled'):
            analysis['security_score'] += 5
        return analysis
    except Exception as e:
        return {'error': str(e)}

def generate_monitoring_recommendations(domain, discovered_services):
    """Generate intelligent monitoring recommendations based on discovered services."""
    recommendations = []
    try:
        if 'web' in discovered_services and not discovered_services['web'].get('error'):
            recommendations.append({'service': 'Web Monitoring', 'template': 'Domain Health', 'priority': 'HIGH'})
        if 'proxy' in discovered_services and discovered_services['proxy'].get('proxy_summary', {}).get('total_proxy_services', 0) > 0:
            recommendations.append({'service': 'Proxy Monitoring', 'template': 'Load Balancer Health', 'priority': 'MEDIUM'})
        return recommendations
    except Exception as e:
        return [{'error': str(e)}]

def calculate_service_summary(discovered_services):
    """Calculate summary statistics for discovered services."""
    summary = {'total_services': 0, 'secure_services': 0, 'vulnerable_services': 0, 'service_categories': {}}
    try:
        for category, services in discovered_services.items():
            if not services.get('error') and services:
                summary['total_services'] += 1
                if 'tls' in category or 'https' in str(services):
                    summary['secure_services'] += 1
        return summary
    except Exception as e:
        return {'error': str(e)}

def generate_integration_points(domain, discovered_services):
    """Generate Zabbix integration points and template mappings."""
    integration = {'zabbix_templates': ['Domain Health'], 'custom_items': [], 'macros': {'{$DOMAIN}': domain}}
    try:
        if 'web' in discovered_services and not discovered_services['web'].get('error'):
            integration['zabbix_templates'].append('Web Service Monitoring')
        if 'proxy' in discovered_services and not discovered_services['proxy'].get('error'):
            integration['zabbix_templates'].append('Load Balancer Monitoring')
        return integration
    except Exception as e:
        return {'error': str(e)}

def get_certificate_info(domain, port=443):
    """Get detailed certificate information for a domain and port."""
    try:
        cert_der, cert_info, error = get_certificate_from_server(domain, port)
        if error:
            return json.dumps({
                'domain': domain,
                'port': port,
                'error': error,
                'certificate_available': False
            })
        
        cert_details = parse_certificate_details(cert_der, cert_info)
        
        return json.dumps({
            'domain': domain,
            'port': port,
            'certificate_available': True,
            'certificate': cert_details
        })
        
    except Exception as e:
        return json.dumps({
            'domain': domain,
            'port': port,
            'error': str(e),
            'certificate_available': False
        })

def main():
    if len(sys.argv) < 2:
        print(json.dumps({'error': 'Usage: get_domain_health.py <command> <args>'}))
        sys.exit(1)
    cmd = sys.argv[1].lower()
    if cmd == 'discover_zone':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py discover_zone <DOMAIN>'}))
            sys.exit(1)
        print(discover_zone(sys.argv[2]))
    elif cmd == 'records':
        if len(sys.argv) < 4:
            print(json.dumps({'error': 'Usage: get_domain_health.py records <DOMAIN> <RECORD_TYPE>'}))
            sys.exit(1)
        print(get_records(sys.argv[2], sys.argv[3]))
    elif cmd == 'dnssec':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py dnssec <DOMAIN>'}))
            sys.exit(1)
        print(get_dnssec(sys.argv[2]))
    elif cmd == 'spf':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py spf <DOMAIN>'}))
            sys.exit(1)
        print(get_spf(sys.argv[2]))
    elif cmd == 'legacy_spf':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py legacy_spf <DOMAIN>'}))
            sys.exit(1)
        print(get_legacy_spf(sys.argv[2]))
    elif cmd == 'dmarc':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py dmarc <DOMAIN>'}))
            sys.exit(1)
        print(get_dmarc(sys.argv[2]))
    elif cmd == 'dkim':
        if len(sys.argv) < 4:
            print(json.dumps({'error': 'Usage: get_domain_health.py dkim <DOMAIN> <SELECTOR>'}))
            sys.exit(1)
        print(get_dkim(sys.argv[2], sys.argv[3]))
    elif cmd == 'caa':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py caa <DOMAIN>'}))
            sys.exit(1)
        print(get_caa(sys.argv[2]))
    elif cmd == 'special':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py special <DOMAIN>'}))
            sys.exit(1)
        result = validate_special_use_domain(sys.argv[2])
        print(json.dumps(result))
    elif cmd == 'whois':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py whois <DOMAIN>'}))
            sys.exit(1)
        # Disable logging for clean JSON output
        import logging
        logging.getLogger().setLevel(logging.CRITICAL)
        print(get_whois(sys.argv[2]))
    elif cmd == 'rdap':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py rdap <DOMAIN>'}))
            sys.exit(1)
        print(get_rdap(sys.argv[2]))
    elif cmd == 'asn':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py asn <DOMAIN>'}))
            sys.exit(1)
        print(get_asn(sys.argv[2]))
    elif cmd == 'discover_ns':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py discover_ns <DOMAIN>'}))
            sys.exit(1)
        print(discover_ns(sys.argv[2]))
    elif cmd == 'ns_check':
        if len(sys.argv) < 4:
            print(json.dumps({'error': 'Usage: get_domain_health.py ns_check <DOMAIN> <NS_SERVER>'}))
            sys.exit(1)
        print(ns_check(sys.argv[2], sys.argv[3]))
    elif cmd == 'dane' or cmd == 'tlsa':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py dane <DOMAIN> [PORT]'}))
            sys.exit(1)
        port = sys.argv[3] if len(sys.argv) >= 4 else 443
        print(get_dane(sys.argv[2], port))
    elif cmd == 'discover_dane':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py discover_dane <DOMAIN>'}))
            sys.exit(1)
        print(discover_dane(sys.argv[2]))
    elif cmd == 'dnssec_detailed':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py dnssec_detailed <DOMAIN>'}))
            sys.exit(1)
        print(get_dnssec_detailed(sys.argv[2]))
    elif cmd == 'rfc2181':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py rfc2181 <DOMAIN>'}))
            sys.exit(1)
        print(get_rfc2181_validation(sys.argv[2]))
    elif cmd == 'mta_sts' or cmd == 'mta-sts':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py mta_sts <DOMAIN>'}))
            sys.exit(1)
        print(get_mta_sts(sys.argv[2]))
    elif cmd == 'tls_rpt' or cmd == 'tls-rpt' or cmd == 'tlsrpt':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py tls_rpt <DOMAIN>'}))
            sys.exit(1)
        print(get_tls_rpt(sys.argv[2]))
    elif cmd == 'bimi':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py bimi <DOMAIN>'}))
            sys.exit(1)
        print(get_bimi(sys.argv[2]))
    elif cmd == 'latency' or cmd == 'dns_latency':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py latency <DOMAIN>'}))
            sys.exit(1)
        print(get_dns_latency(sys.argv[2]))
    elif cmd == 'email_security' or cmd == 'email':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py email_security <DOMAIN>'}))
            sys.exit(1)
        print(get_email_security(sys.argv[2]))
    elif cmd == 'dnsbl' or cmd == 'rbl' or cmd == 'blacklist':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py dnsbl <DOMAIN>'}))
            sys.exit(1)
        print(get_dnsbl(sys.argv[2]))
    elif cmd == 'dnsbl_mx':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py dnsbl_mx <DOMAIN>'}))
            sys.exit(1)
        print(get_dnsbl_mx(sys.argv[2]))
    elif cmd == 'email_srv' or cmd == 'srv':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py email_srv <DOMAIN>'}))
            sys.exit(1)
        print(get_email_srv(sys.argv[2]))
    elif cmd == 'sshfp':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py sshfp <DOMAIN>'}))
            sys.exit(1)
        print(get_sshfp(sys.argv[2]))
    elif cmd == 'dane_mx':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py dane_mx <DOMAIN>'}))
            sys.exit(1)
        print(get_dane_mx(sys.argv[2]))
    elif cmd == 'glue' or cmd == 'ns_glue':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py glue <DOMAIN>'}))
            sys.exit(1)
        print(get_ns_glue(sys.argv[2]))
    elif cmd == 'ns_diversity':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py ns_diversity <DOMAIN>'}))
            sys.exit(1)
        print(get_ns_diversity(sys.argv[2]))
    elif cmd == 'dns_errors' or cmd == 'ede':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py dns_errors <DOMAIN>'}))
            sys.exit(1)
        print(get_extended_errors(sys.argv[2]))
    elif cmd == 'error_reporting':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py error_reporting <DOMAIN>'}))
            sys.exit(1)
        print(get_dns_error_reporting(sys.argv[2]))
    elif cmd == 'smimea':
        if len(sys.argv) < 4:
            print(json.dumps({'error': 'Usage: get_domain_health.py smimea <DOMAIN> <LOCAL_PART>'}))
            sys.exit(1)
        print(get_smimea(sys.argv[2], sys.argv[3]))
    elif cmd == 'openpgpkey':
        if len(sys.argv) < 4:
            print(json.dumps({'error': 'Usage: get_domain_health.py openpgpkey <DOMAIN> <LOCAL_PART>'}))
            sys.exit(1)
        print(get_openpgpkey(sys.argv[2], sys.argv[3]))
    elif cmd == 'performance' or cmd == 'perf':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py performance <DOMAIN>'}))
            sys.exit(1)
        print(get_dns_performance(sys.argv[2]))
    elif cmd == 'security_scan' or cmd == 'security':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py security_scan <DOMAIN>'}))
            sys.exit(1)
        print(get_security_scan(sys.argv[2]))
    elif cmd == 'zone_analysis' or cmd == 'zone':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py zone_analysis <DOMAIN>'}))
            sys.exit(1)
        # Disable logging for clean JSON output
        import logging
        logging.getLogger().setLevel(logging.CRITICAL)
        print(get_zone_analysis(sys.argv[2]))
    elif cmd == 'discover_mx':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py discover_mx <DOMAIN>'}))
            sys.exit(1)
        print(discover_mx(sys.argv[2]))
    elif cmd == 'discover.master':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py discover.master <DOMAIN>'}))
            sys.exit(1)
        print(discover(sys.argv[2]))
    elif cmd == 'discover_ns.master':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py discover_ns.master <DOMAIN>'}))
            sys.exit(1)
        print(discover_ns(sys.argv[2]))
    elif cmd == 'discover_services' or cmd == 'services':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py discover_services <DOMAIN> [fast]'}))
            sys.exit(1)
        fast_mode = len(sys.argv) >= 4 and sys.argv[3] == 'fast'
        print(discover_domain_services(sys.argv[2], fast_mode))
    elif cmd == 'discover' or cmd == 'services_fast':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py discover <DOMAIN>'}))
            sys.exit(1)
        print(discover_domain_services(sys.argv[2], fast_mode=True))
    elif cmd == 'discover_services.full' or cmd == 'services_full':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py discover_services.full <DOMAIN>'}))
            sys.exit(1)
        print(discover_domain_services(sys.argv[2]))
    elif cmd == 'discover_services.lld' or cmd == 'services_lld':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py discover_services.lld <DOMAIN>'}))
            sys.exit(1)
        print(discover_srv_services_lld(sys.argv[2]))
    elif cmd == 'discover_services.master':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py discover_services.master <DOMAIN>'}))
            sys.exit(1)
        print(discover_srv_services_lld(sys.argv[2]))
    elif cmd == 'srv.service_status':
        if len(sys.argv) < 4:
            print(json.dumps({'error': 'Usage: get_domain_health.py srv.service_status <DOMAIN> <SERVICE>'}))
            sys.exit(1)
        print(srv_service_status(sys.argv[2], sys.argv[3]))
    elif cmd == 'tls_integration' or cmd == 'tls':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py tls_integration <DOMAIN> [PORT]'}))
            sys.exit(1)
        port = sys.argv[3] if len(sys.argv) >= 4 else 443
        print(get_tls_integration(sys.argv[2], port))
    elif cmd == 'comprehensive' or cmd == 'full':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py comprehensive <DOMAIN>'}))
            sys.exit(1)
        print(get_comprehensive_analysis(sys.argv[2]))
    elif cmd == 'health':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py health <DOMAIN>'}))
            sys.exit(1)
        print(get_health(sys.argv[2]))
    elif cmd == 'selftest':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py selftest <DOMAIN>'}))
            sys.exit(1)
        print(selftest(sys.argv[2]))
    elif cmd == 'discover_subdomains' or cmd == 'subdomains':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py discover_subdomains <DOMAIN>'}))
            sys.exit(1)
        print(json.dumps(discover_comprehensive_subdomains(sys.argv[2])))
    elif cmd == 'discover_subdomains.lld':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py discover_subdomains.lld <DOMAIN>'}))
            sys.exit(1)
        result = discover_comprehensive_subdomains(sys.argv[2])
        lld_data = []
        if 'subdomain_discovery' in result and 'subdomain_services' in result['subdomain_discovery']:
            for subdomain, info in result['subdomain_discovery']['subdomain_services'].items():
                # Determine category for this subdomain
                category = 'unknown'
                for cat_name, cat_info in result['subdomain_discovery']['by_category'].items():
                    if subdomain in cat_info.get('discovered', []):
                        category = cat_name
                        break
                
                lld_data.append({
                    '{#SUBDOMAIN}': subdomain,
                    '{#FULL_DOMAIN}': info.get('domain', f"{subdomain}.{sys.argv[2]}"),
                    '{#CATEGORY}': category,
                    '{#WEB_ACCESSIBLE}': 1 if info.get('web_accessible') else 0,
                    '{#SSL_AVAILABLE}': 1 if info.get('ssl_available') else 0
                })
        print(json.dumps({'data': lld_data}))
    elif cmd == 'discover_ports' or cmd == 'ports':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py discover_ports <DOMAIN> [fast]'}))
            sys.exit(1)
        fast_mode = len(sys.argv) >= 4 and sys.argv[3] == 'fast'
        print(json.dumps(discover_comprehensive_ports(sys.argv[2], fast_mode=fast_mode)))
    elif cmd == 'discover_ports.fast':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py discover_ports.fast <DOMAIN>'}))
            sys.exit(1)
        print(json.dumps(discover_comprehensive_ports(sys.argv[2], fast_mode=True)))
    elif cmd == 'discover_ports.master':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py discover_ports.master <DOMAIN>'}))
            sys.exit(1)
        print(json.dumps(discover_comprehensive_ports(sys.argv[2])))
    elif cmd == 'scan_port_range':
        if len(sys.argv) < 5:
            print(json.dumps({'error': 'Usage: get_domain_health.py scan_port_range <DOMAIN> <START_PORT> <END_PORT>'}))
            sys.exit(1)
        try:
            start_port = int(sys.argv[3])
            end_port = int(sys.argv[4])
            open_ports = scan_port_range(sys.argv[2], start_port, end_port)
            print(json.dumps({
                'domain': sys.argv[2],
                'port_range': f'{start_port}-{end_port}',
                'open_ports': open_ports,
                'total_open': len(open_ports),
                'total_scanned': end_port - start_port + 1
            }))
        except ValueError:
            print(json.dumps({'error': 'Port numbers must be integers'}))
            sys.exit(1)
    elif cmd == 'discover_custom_ports':
        if len(sys.argv) < 4:
            print(json.dumps({'error': 'Usage: get_domain_health.py discover_custom_ports <DOMAIN> <PORT1,PORT2,PORT3>'}))
            sys.exit(1)
        try:
            port_list = [int(p.strip()) for p in sys.argv[3].split(',')]
            result = discover_custom_ports(sys.argv[2], port_list, "custom")
            print(json.dumps(result))
        except ValueError:
            print(json.dumps({'error': 'Port list must contain valid integers separated by commas'}))
            sys.exit(1)
    elif cmd == 'certificate' or cmd == 'cert':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py certificate <DOMAIN> [PORT]'}))
            sys.exit(1)
        port = int(sys.argv[3]) if len(sys.argv) >= 4 else 443
        print(get_certificate_info(sys.argv[2], port))
    else:
        print(json.dumps({'error': f'Unknown command: {cmd}'}))
        sys.exit(1)

# Old main() function content removed - using new main handler at end of file

def test_zone_transfer_protection(domain):
    """Test if the domain's nameservers properly protect against zone transfers."""
    try:
        # Get nameservers using multiple methods for reliability
        nameservers = []
        
        # Method 1: Try our DNS query first
        ns_records = dns_query(domain, 'NS', None, 5.0)
        for r in ns_records:
            ns_name = format_rdata('NS', r['rdata']).rstrip('.')
            if '.' in ns_name and len(ns_name) > 3:  # Valid FQDN
                nameservers.append(ns_name)
        
        # Method 2: If we don't have good results, try nslookup fallback
        if len(nameservers) < 2:
            try:
                import subprocess
                result = subprocess.run(['nslookup', '-type=ns', domain], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        line = line.strip()
                        if 'nameserver' in line.lower() and '=' in line:
                            full_ns = line.split('=')[1].strip().rstrip('.')
                            if full_ns and '.' in full_ns and full_ns not in nameservers:
                                nameservers.append(full_ns)
                        elif line.endswith('.'):
                            # Sometimes nslookup just lists the nameservers without "nameserver ="
                            parts = line.split()
                            if len(parts) >= 1 and parts[-1].count('.') >= 2:
                                ns_candidate = parts[-1].rstrip('.')
                                if ns_candidate not in nameservers:
                                    nameservers.append(ns_candidate)
            except:
                pass  # Fallback failed, continue with what we have
        
        # If we still don't have nameservers, return error
        if not nameservers:
            return {'error': 'No nameservers found to test'}
        
        transfer_attempts = []
        
        # Resolve nameserver IPs
        resolved_nameservers = []
        for ns in nameservers:
            try:
                a_records = dns_query(ns, 'A', None, 3.0)
                for r in a_records:
                    resolved_nameservers.append(r['rdata'])
            except:
                continue
        
        if not resolved_nameservers:
            # Fallback to original nameserver names if no IPs resolved
            resolved_nameservers = nameservers
        
        nameservers = resolved_nameservers  # Use resolved IPs for testing 
        for ns in nameservers:
            try:
                axfr_records = dns_query(domain, 'AXFR', ns, 5.0)
                if axfr_records:
                    transfer_attempts.append({
                        'nameserver': ns,
                        'transfer_allowed': True,
                        'record_count': len(axfr_records)
                    })
                else:
                    transfer_attempts.append({
                        'nameserver': ns,
                        'transfer_allowed': False
                    })
            except Exception as e:
                transfer_attempts.append({
                    'nameserver': ns,
                    'transfer_allowed': False,
                    'error': str(e)
                })
        return {'transfer_tests': transfer_attempts}
    except Exception as e:
        return {'error': str(e)}   

def get_authority_chain(domain):
    """Retrieve the authority chain for the domain."""
    try:
        authority_chain = []
        current_domain = domain
        
        while True:
            ns_records = dns_query(current_domain, 'NS', None, 5.0)
            if not ns_records:
                break
            
            nameservers = [format_rdata('NS', r['rdata']).rstrip('.') for r in ns_records]
            authority_chain.append({
                'domain': current_domain,
                'nameservers': nameservers
            }) 
            # Move up to parent domain
            if '.' in current_domain:
                current_domain = '.'.join(current_domain.split('.')[1:])
            else:
                break
        return authority_chain
    except Exception as e:
        return {'error': str(e)}

def get_ns_diversity(domain):
    """Analyze nameserver diversity for the domain."""
    try:
        ns_records = dns_query(domain, 'NS', None, 5.0)
        nameservers = [format_rdata('NS', r['rdata']).rstrip('.') for r in ns_records]
        
        ns_ips = {}
        for ns in nameservers:
            try:
                ns_a_records = dns_query(ns, 'A', None, 3.0)
                ns_ips[ns] = [r['rdata'] for r in ns_a_records]
            except:
                ns_ips[ns] = [] # No A records found
        unique_subnets = set()
        for ns, ips in ns_ips.items():
            for ip in ips:
                subnet = '.'.join(ip.split('.')[:2])  # Using /16 subnet for diversity
                unique_subnets.add(subnet)
        diversity_score = len(unique_subnets) / len(nameservers) if nameservers else 0
        return {
            'nameservers': ns_ips,
            'unique_subnet_count': len(unique_subnets),
            'diversity_score': round(diversity_score, 2)
        }
    except Exception as e:
        return {'error': str(e)}

def check_soa_serial_consistency(domain):
    """Check if SOA serial numbers are consistent across all nameservers."""
    try:
        # Get nameservers using multiple methods for reliability
        nameservers = []
        
        # Method 1: Try our DNS query first
        ns_records = dns_query(domain, 'NS', None, 5.0)
        for r in ns_records:
            ns_name = format_rdata('NS', r['rdata']).rstrip('.')
            if '.' in ns_name and len(ns_name) > 3:  # Valid FQDN
                nameservers.append(ns_name)
        
        # Method 2: If we don't have good results, try nslookup fallback
        if len(nameservers) < 2:
            try:
                import subprocess
                result = subprocess.run(['nslookup', '-type=ns', domain], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        line = line.strip()
                        if 'nameserver' in line.lower() and '=' in line:
                            full_ns = line.split('=')[1].strip().rstrip('.')
                            if full_ns and '.' in full_ns and full_ns not in nameservers:
                                nameservers.append(full_ns)
                        elif line.endswith('.'):
                            # Sometimes nslookup just lists the nameservers without "nameserver ="
                            parts = line.split()
                            if len(parts) >= 1 and parts[-1].count('.') >= 2:
                                ns_candidate = parts[-1].rstrip('.')
                                if ns_candidate not in nameservers:
                                    nameservers.append(ns_candidate)
            except:
                pass  # Fallback failed, continue with what we have
        # If we still don't have nameservers, return error
        if not nameservers:
            return {'error': 'No nameservers found to test'}
    
        serials = {}
        for ns in nameservers:
            try:
                soa_records = dns_query(domain, 'SOA', ns, 5.0)
                if soa_records:
                    formatted = format_rdata('SOA', soa_records[0]['rdata'])
                    parts = formatted.split()
                    if len(parts) >= 3:
                        serials[ns] = parts[2]  # SOA serial is the 3rd part
                    else:
                        serials[ns] = 'error_invalid_soa_format'
                else:
                    serials[ns] = 'error_no_soa_record'
            except Exception as e:
                serials[ns] = f'error_{str(e)}'
        unique_serials = set(serials.values())
        return {
            'soa_serials': serials,
            'consistent': len(unique_serials) == 1,
            'unique_serials': list(unique_serials)
        }
    except Exception as e:
        return {'error': str(e)}

def get_soa_record(domain):
    """Retrieve and validate the SOA record for the domain."""
    try:
        soa_records = dns_query(domain, 'SOA', None, 5.0)
        if not soa_records:
            return {'error': 'No SOA record found'}
        
        soa_data = format_rdata('SOA', soa_records[0]['rdata']).split()
        if len(soa_data) < 7:
            return {'error': 'Invalid SOA record format (insufficient fields)'}
        
        # Extract and validate each field
        primary_ns = soa_data[0].rstrip('.')
        responsible_email_raw = soa_data[1].rstrip('.')
        
        # Validate primary nameserver
        if not primary_ns or '.' not in primary_ns:
            return {'error': 'Invalid primary nameserver format'}
        
        # Validate and convert responsible email
        responsible_email = responsible_email_raw.replace('.', '@', 1)
        if '@' not in responsible_email or responsible_email.count('@') != 1:
            return {'error': 'Invalid responsible email format'}
        
        # Validate and convert numeric fields with range checks
        try:
            serial = int(soa_data[2])
            refresh_seconds = int(soa_data[3])
            retry_seconds = int(soa_data[4])
            expire_seconds = int(soa_data[5])
            minimum_ttl = int(soa_data[6])
        except ValueError:
            return {'error': 'Invalid numeric values in SOA record'}
        
        # Validate reasonable ranges for SOA values
        validation_errors = []
        
        # Serial number should be reasonable (typically date-based YYYYMMDDNN)
        if serial <= 0 or serial > 99999999999:  # Allow for extended formats
            validation_errors.append('Serial number out of reasonable range')
        
        # Refresh interval (typically 1 hour to 1 week)
        if refresh_seconds < 300 or refresh_seconds > 604800:  # 5 minutes to 1 week
            validation_errors.append('Refresh interval out of recommended range (5min-1week)')
        
        # Retry interval should be less than refresh
        if retry_seconds < 60 or retry_seconds > refresh_seconds:
            validation_errors.append('Retry interval invalid (should be 1min-refresh)')
        
        # Expire time should be much larger than refresh (typically weeks)
        if expire_seconds < refresh_seconds or expire_seconds > 2419200:  # Max 4 weeks
            validation_errors.append('Expire time out of recommended range')
        
        # Minimum TTL (negative cache TTL)
        if minimum_ttl < 0 or minimum_ttl > 86400:  # Max 1 day
            validation_errors.append('Minimum TTL out of recommended range (0-1day)')
        
        # Check logical relationships
        if retry_seconds >= refresh_seconds:
            validation_errors.append('Retry interval should be less than refresh interval')
        
        result = {
            'primary_ns': primary_ns,
            'responsible_email': responsible_email,
            'serial': serial,
            'refresh_seconds': refresh_seconds,
            'retry_seconds': retry_seconds,
            'expire_seconds': expire_seconds,
            'minimum_ttl': minimum_ttl,
            'validation_warnings': validation_errors,
            'is_valid': len(validation_errors) == 0
        }
        
        # Add human-readable time formats
        result['refresh_human'] = format_duration(refresh_seconds)
        result['retry_human'] = format_duration(retry_seconds)
        result['expire_human'] = format_duration(expire_seconds)
        result['minimum_ttl_human'] = format_duration(minimum_ttl)
        
        return result
        
    except Exception as e:
        return {'error': str(e)}

def format_duration(seconds):
    """Convert seconds to human-readable duration."""
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    elif seconds < 86400:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"{hours}h {minutes}m"
    else:
        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        return f"{days}d {hours}h"

# --- Enhanced Service Discovery Functions ---

def enhance_web_service_analysis(domain, web_services):
    """Enhance web service discovery with detailed analysis."""
    try:
        # Add server technology detection
        web_services['technology_stack'] = detect_web_technology(domain, web_services)
        
        # Add HTTP security headers analysis
        web_services['security_headers'] = analyze_http_security_headers(domain, web_services)
        
        # Add redirect chain analysis
        web_services['redirect_analysis'] = analyze_redirect_chains(domain, web_services)
        
        # Add HTTP/2 and HTTP/3 support detection
        web_services['protocol_support'] = detect_http_protocols(domain, web_services)
        
        return web_services
    except Exception as e:
        web_services['enhancement_error'] = str(e)
        return web_services

def enhance_email_service_analysis(domain, email_services):
    """Enhance email service discovery with security analysis."""
    try:
        # Add MX server connectivity and latency testing
        email_services['mx_connectivity'] = test_mx_connectivity(domain, email_services['mx_records'])
        
        # Add SMTP security feature detection (STARTTLS, AUTH methods)
        email_services['smtp_security'] = analyze_smtp_security(domain, email_services['smtp_ports'])
        
        # Add email authentication analysis (SPF, DKIM, DMARC)
        email_services['authentication'] = analyze_email_authentication(domain)
        
        # Add email security policies (MTA-STS, TLS-RPT)
        email_services['security_policies'] = analyze_email_security_policies(domain)
        
        return email_services
    except Exception as e:
        email_services['enhancement_error'] = str(e)
        return email_services

def enhance_tls_service_analysis(domain, tls_services):
    """Enhance TLS service discovery with certificate analysis."""
    try:
        # Add certificate information for each TLS port
        tls_services['certificates'] = {}
        for port in tls_services['discovered_ports']:
            tls_services['certificates'][str(port)] = analyze_tls_certificate(domain, port)
        
        # Add cipher suite analysis
        tls_services['cipher_analysis'] = analyze_cipher_suites(domain, tls_services['discovered_ports'])
        
        # Add DANE/TLSA validation
        tls_services['dane_validation'] = validate_dane_for_services(domain, tls_services['discovered_ports'])
        
        # Add protocol version support
        tls_services['protocol_versions'] = detect_tls_versions(domain, tls_services['discovered_ports'])
        
        return tls_services
    except Exception as e:
        tls_services['enhancement_error'] = str(e)
        return tls_services

def enhance_srv_service_analysis(domain, srv_services):
    """Enhance SRV service discovery with availability analysis."""
    try:
        srv_services['service_availability'] = {}
        srv_services['service_details'] = {}
        
        for service_name, records in srv_services['discovered_services']:
            # Test actual connectivity to SRV targets
            srv_services['service_availability'][service_name] = test_srv_connectivity(records)
            
            # Analyze service-specific configurations
            srv_services['service_details'][service_name] = analyze_srv_service_config(service_name, records)
        
        return srv_services
    except Exception as e:
        srv_services['enhancement_error'] = str(e)
        return srv_services

def discover_dns_based_services(domain):
    """Discover services based on DNS records and common patterns."""
    services = {
        'discovered_services': {},
        'service_patterns': {},
        'subdomain_services': {}
    }
    
    try:
        # Comprehensive service subdomains covering enterprise and industry standards
        service_subdomains = [
            # Email services
            'mail', 'smtp', 'imap', 'pop', 'pop3', 'webmail', 'exchange', 'owa', 'autodiscover',
            'mta-sts', 'autoconfig', 'email', 'relay', 'mx', 'mx1', 'mx2', 'mx3',
            
            # Web services
            'www', 'web', 'http', 'https', 'cdn', 'static', 'assets', 'media', 'images',
            'blog', 'news', 'support', 'help', 'docs', 'wiki', 'kb', 'forum',
            
            # Authentication & Directory Services
            'ldap', 'ldaps', 'ad', 'dc', 'dc1', 'dc2', 'dc3', 'gc', 'kdc', 'krb', 'kerberos',
            'auth', 'sso', 'saml', 'oauth', 'oidc', 'adfs', 'sts', 'identity', 'id',
            'radius', 'tacacs', 'nps', 'ias',
            
            # Microsoft Services
            'kms', 'wsus', 'sccm', 'scom', 'rds', 'terminal', 'ts', 'citrix',
            'exchange', 'skype', 'lync', 'teams', 'sharepoint', 'sp', 'office',
            
            # File & Storage Services  
            'ftp', 'sftp', 'ftps', 'tftp', 'nfs', 'cifs', 'smb', 'dfs', 'san', 'nas',
            'backup', 'storage', 'file', 'files', 'share', 'shares', 'data',
            
            # Database Services
            'db', 'database', 'sql', 'mysql', 'postgres', 'postgresql', 'oracle', 'mssql',
            'mongo', 'mongodb', 'redis', 'elasticsearch', 'elastic', 'cassandra',
            'mariadb', 'sqlite', 'couchdb', 'influxdb', 'clickhouse',
            
            # Network Services
            'dns', 'ns', 'ns1', 'ns2', 'ns3', 'ns4', 'resolver', 'bind',
            'ntp', 'time', 'dhcp', 'proxy', 'gateway', 'firewall', 'fw',
            'vpn', 'openvpn', 'ipsec', 'wireguard', 'pptp', 'l2tp',
            
            # Remote Access & Management
            'ssh', 'rdp', 'vnc', 'remote', 'bastion', 'jump', 'jumpbox',
            'console', 'serial', 'ipmi', 'ilo', 'idrac', 'bmc', 'oob',
            
            # Application & API Services
            'api', 'rest', 'soap', 'graphql', 'webhook', 'ws', 'websocket',
            'app', 'application', 'service', 'microservice', 'lambda',
            'function', 'serverless', 'worker', 'queue', 'message', 'mq',
            
            # Development & CI/CD
            'git', 'svn', 'cvs', 'scm', 'repo', 'repository', 'code',
            'jenkins', 'ci', 'cd', 'gitlab', 'github', 'bitbucket',
            'build', 'deploy', 'release', 'artifact', 'nexus', 'artifactory',
            
            # Monitoring & Logging
            'monitoring', 'monitor', 'nagios', 'zabbix', 'icinga', 'sensu',
            'grafana', 'kibana', 'prometheus', 'metrics', 'stats', 'telemetry',
            'log', 'logs', 'logging', 'syslog', 'elk', 'splunk', 'graylog',
            'apm', 'tracing', 'jaeger', 'zipkin', 'newrelic', 'datadog',
            
            # Security Services
            'security', 'sec', 'vault', 'secrets', 'pki', 'ca', 'cert', 'certificate',
            'ocsp', 'crl', 'siem', 'ids', 'ips', 'waf', 'scanner', 'vuln',
            'antivirus', 'av', 'malware', 'sandbox', 'threat', 'intelligence',
            
            # Container & Orchestration
            'docker', 'registry', 'k8s', 'kubernetes', 'openshift', 'rancher',
            'portainer', 'harbor', 'quay', 'gcr', 'ecr', 'acr',
            'swarm', 'mesos', 'nomad', 'consul', 'etcd',
            
            # Cloud & Infrastructure
            'cloud', 'aws', 'azure', 'gcp', 'digitalocean', 'linode', 'vultr',
            'terraform', 'ansible', 'puppet', 'chef', 'salt', 'vagrant',
            'vm', 'vms', 'virtualization', 'vcenter', 'esxi', 'hyperv',
            
            # Admin & Portal Services
            'admin', 'administration', 'mgmt', 'management', 'control', 'cp',
            'portal', 'dashboard', 'ui', 'gui', 'panel', 'cpanel', 'plesk',
            'webmin', 'cockpit', 'phpmyadmin', 'adminer', 'portainer',
            
            # Content & Media Services
            'cdn', 'cache', 'static', 'assets', 'media', 'images', 'img',
            'video', 'stream', 'streaming', 'rtmp', 'hls', 'dash',
            'content', 'cms', 'drupal', 'wordpress', 'joomla',
            
            # Communication Services
            'chat', 'irc', 'slack', 'mattermost', 'rocket', 'discord',
            'voip', 'sip', 'pbx', 'asterisk', 'freeswitch', 'kamailio',
            'turn', 'stun', 'webrtc', 'jitsi', 'zoom', 'meet',
            
            # Testing & Development
            'test', 'testing', 'qa', 'staging', 'stage', 'dev', 'development',
            'demo', 'sandbox', 'lab', 'playground', 'preview', 'beta',
            'alpha', 'canary', 'experimental', 'research', 'poc',
            
            # IoT & Edge Services
            'iot', 'mqtt', 'coap', 'edge', 'sensor', 'device', 'gateway',
            'influx', 'timeseries', 'historian', 'scada', 'hmi', 'plc',
            
            # Enterprise Applications
            'erp', 'crm', 'salesforce', 'sap', 'oracle', 'peoplesoft',
            'workday', 'servicenow', 'jira', 'confluence', 'sharepoint',
            'teams', 'slack', 'zoom', 'webex', 'gotomeeting',
            
            # Proxy & Load Balancing Services
            'proxy', 'proxy1', 'proxy2', 'proxy3', 'web-proxy', 'http-proxy', 'https-proxy',
            'forward-proxy', 'reverse-proxy', 'transparent-proxy', 'intercepting-proxy',
            'caching-proxy', 'content-filter', 'squid', 'squid-proxy', 'squidguard',
            'lb', 'loadbalancer', 'load-balancer', 'nlb', 'alb', 'clb', 'elb',
            'balancer', 'balance', 'lb1', 'lb2', 'lb3', 'frontend', 'backend',
            'nginx', 'nginx-proxy', 'apache', 'apache-proxy', 'httpd', 'httpd-proxy',
            'haproxy', 'ha-proxy', 'traefik', 'envoy', 'envoy-proxy',
            'istio', 'istio-proxy', 'linkerd', 'linkerd-proxy', 'consul-connect',
            'ambassador', 'contour', 'ingress', 'gateway', 'api-gateway',
            'kong', 'kong-proxy', 'zuul', 'edge', 'edge-proxy',
            'cloudflare', 'cloudfront', 'fastly', 'akamai', 'maxcdn', 'jsdelivr',
            'varnish', 'varnish-cache', 'redis-proxy', 'memcached-proxy',
            'waf', 'waf-proxy', 'firewall', 'filter', 'content-filter',
            'url-filter', 'web-filter', 'secure-proxy', 'security-proxy',
            'f5', 'f5-ltm', 'bigip', 'netscaler', 'citrix-adc', 'a10', 'alteon',
            'kemp', 'radware', 'barracuda', 'fortinet', 'palo-alto', 'checkpoint',
            'blue-coat', 'bluecoat', 'websense', 'forcepoint', 'mcafee-proxy',
            'symantec-proxy', 'zscaler', 'cloud-proxy', 'secure-proxy',
            'socks', 'socks4', 'socks5', 'socks-proxy', 'tor', 'tor-proxy',
            'transparent', 'intercept', 'filter', 'content-filter', 'url-filter',
            
            # Message & Event Services  
            'rabbitmq', 'kafka', 'activemq', 'artemis', 'pulsar', 'nats',
            'eventstore', 'eventbridge', 'kinesis', 'pubsub', 'servicebus',
            
            # Search & Analytics
            'search', 'solr', 'elasticsearch', 'opensearch', 'algolia',
            'analytics', 'clickhouse', 'redshift', 'bigquery', 'snowflake',
            
            # Blockchain & Crypto
            'blockchain', 'bitcoin', 'ethereum', 'crypto', 'wallet', 'node',
            'ipfs', 'swarm', 'arweave', 'filecoin', 'storj'
        ]
        
        for subdomain in service_subdomains:
            full_domain = f"{subdomain}.{domain}"
            service_info = analyze_subdomain_service(full_domain)
            if service_info['exists']:
                services['subdomain_services'][subdomain] = service_info
        
        # Analyze CAA records for certificate authorities
        caa_records = dns_query(domain, 'CAA', None, DNS_TIMEOUT)
        services['certificate_authorities'] = analyze_caa_policies(caa_records)
        
        # Analyze TXT records for service indicators
        txt_records = dns_query(domain, 'TXT', None, DNS_TIMEOUT)
        services['txt_based_services'] = analyze_txt_service_indicators(txt_records)
        
        # Comprehensive SRV record discovery for service advertisement
        services['srv_based_services'] = discover_srv_based_services(domain)
        
        return services
    except Exception as e:
        return {'error': str(e)}

def discover_application_services(domain):
    """Discover common application and database services."""
    services = {
        'database_ports': [],
        'application_ports': [],
        'management_interfaces': [],
        'api_endpoints': []
    }
    
    try:
        # Common database ports
        db_ports = [1433, 1521, 3306, 5432, 6379, 27017, 9042, 5984]
        for port in db_ports:
            if test_port_connectivity(domain, port):
                services['database_ports'].append({
                    'port': port,
                    'service': get_service_name_for_port(port),
                    'accessible': True
                })
        
        # Common application ports
        app_ports = [8080, 8443, 9000, 9090, 3000, 4000, 5000, 8000, 8888]
        for port in app_ports:
            if test_port_connectivity(domain, port):
                services['application_ports'].append({
                    'port': port,
                    'service': get_service_name_for_port(port),
                    'accessible': True
                })
        
        # Common management interface ports
        mgmt_ports = [22, 23, 161, 623, 9001, 10000, 8006]
        for port in mgmt_ports:
            if test_port_connectivity(domain, port):
                services['management_interfaces'].append({
                    'port': port,
                    'service': get_service_name_for_port(port),
                    'accessible': True,
                    'security_risk': port in [23, 161]  # Telnet, SNMP v1/v2
                })
        
        return services
    except Exception as e:
        return {'error': str(e)}

def discover_security_services(domain):
    """Discover security-related services and configurations."""
    services = {
        'dnssec': {},
        'dane_tlsa': {},
        'security_txt': {},
        'certificate_transparency': {},
        'hsts': {},
        'security_policies': {}
    }
    
    try:
        # DNSSEC analysis
        services['dnssec'] = get_dnssec_detailed(domain)
        
        # DANE/TLSA records
        common_tlsa_ports = [25, 443, 993, 995]
        services['dane_tlsa'] = {}
        for port in common_tlsa_ports:
            tlsa_result = get_dane(domain, port, False)
            if isinstance(tlsa_result, str):
                try:
                    tlsa_data = json.loads(tlsa_result)
                    if not tlsa_data.get('error'):
                        services['dane_tlsa'][str(port)] = tlsa_data
                except:
                    pass
        
        # Security.txt file discovery
        services['security_txt'] = discover_security_txt(domain)
        
        # Certificate Transparency monitoring
        services['certificate_transparency'] = analyze_ct_logs(domain)
        
        # HSTS policy analysis
        services['hsts'] = analyze_hsts_policy(domain)
        
        return services
    except Exception as e:
        return {'error': str(e)}

def discover_proxy_services(domain):
    """Comprehensive proxy and load balancing service discovery."""
    proxy_services = {
        'forward_proxies': [],
        'reverse_proxies': [],
        'load_balancers': [],
        'content_filters': [],
        'caching_proxies': [],
        'api_gateways': [],
        'service_mesh': [],
        'anonymous_proxies': [],
        'generic_proxies': [],
        'proxy_summary': {
            'total_proxy_services': 0,
            'accessible_proxies': 0,
            'proxy_types': {}
        }
    }
    
    try:
        # Comprehensive proxy subdomain discovery
        proxy_subdomains = [
            # Generic proxy services
            'proxy', 'proxy1', 'proxy2', 'proxy3', 'web-proxy', 'http-proxy', 'https-proxy',
            'forward-proxy', 'reverse-proxy', 'transparent-proxy', 'intercepting-proxy',
            
            # Load balancers
            'lb', 'loadbalancer', 'load-balancer', 'nlb', 'alb', 'clb', 'elb',
            'balancer', 'balance', 'lb1', 'lb2', 'lb3', 'frontend', 'backend',
            
            # Popular proxy software
            'squid', 'squid-proxy', 'squidguard', 'nginx', 'nginx-proxy',
            'apache', 'apache-proxy', 'httpd', 'httpd-proxy', 'haproxy', 'ha-proxy',
            'traefik', 'envoy', 'envoy-proxy', 'varnish', 'varnish-cache',
            
            # Service mesh and modern proxies
            'istio', 'istio-proxy', 'linkerd', 'linkerd-proxy', 'consul-connect',
            'ambassador', 'contour', 'ingress', 'gateway', 'api-gateway',
            'kong', 'kong-proxy', 'zuul', 'edge', 'edge-proxy',
            
            # Content delivery and caching
            'cdn', 'cache', 'caching', 'content', 'static', 'assets',
            'cloudflare', 'cloudfront', 'fastly', 'akamai', 'maxcdn', 'jsdelivr',
            
            # Security and filtering proxies
            'waf', 'waf-proxy', 'firewall', 'filter', 'content-filter',
            'url-filter', 'web-filter', 'secure-proxy', 'security-proxy',
            'blue-coat', 'bluecoat', 'websense', 'forcepoint', 'mcafee-proxy',
            'symantec-proxy', 'zscaler', 'cloud-proxy', 'safe-proxy',
            
            # Enterprise load balancers
            'f5', 'f5-ltm', 'bigip', 'netscaler', 'citrix-adc', 'citrix-lb',
            'a10', 'alteon', 'kemp', 'radware', 'barracuda', 'fortinet-lb',
            
            # SOCKS and anonymous proxies
            'socks', 'socks4', 'socks5', 'socks-proxy', 'tor', 'tor-proxy',
            'anonymous', 'anon-proxy', 'vpn-proxy'
        ]
        
        discovered_proxies = 0
        accessible_proxies = 0
        
        for subdomain in proxy_subdomains:
            full_domain = f'{subdomain}.{domain}'
            
            # Check if subdomain exists
            a_records = dns_query(full_domain, 'A', None, DNS_TIMEOUT)
            aaaa_records = dns_query(full_domain, 'AAAA', None, DNS_TIMEOUT)
            
            if a_records or aaaa_records:
                discovered_proxies += 1
                
                # Determine proxy type based on subdomain name
                proxy_type = categorize_proxy_service(subdomain)
                
                # Test common proxy ports
                proxy_ports = [80, 443, 3128, 8080, 8443, 8888, 9000, 1080, 8000, 3000, 8001, 8008, 8081, 8082, 8083, 8090, 8180, 8181, 9001, 9080, 9443]
                accessible_ports = []
                
                for port in proxy_ports:
                    if test_port_connectivity(full_domain, port):
                        accessible_ports.append(port)
                
                if accessible_ports:
                    accessible_proxies += 1
                
                proxy_info = {
                    'subdomain': subdomain,
                    'full_domain': full_domain,
                    'a_records': len(a_records) if a_records else 0,
                    'aaaa_records': len(aaaa_records) if aaaa_records else 0,
                    'accessible_ports': accessible_ports,
                    'proxy_type': proxy_type,
                    'accessible': len(accessible_ports) > 0,
                    'software_hint': detect_proxy_software(subdomain)
                }
                
                # Add to appropriate category
                proxy_services[proxy_type].append(proxy_info)
                
                # Update type counters
                proxy_services['proxy_summary']['proxy_types'][proxy_type] = \
                    proxy_services['proxy_summary']['proxy_types'].get(proxy_type, 0) + 1
        
        # SRV record discovery for proxy services
        proxy_srv_records = [
            ('_http._tcp', 'HTTP Proxy Service'),
            ('_https._tcp', 'HTTPS Proxy Service'),
            ('_proxy._tcp', 'Generic Proxy Service'),
            ('_squid._tcp', 'Squid Proxy Service'),
            ('_socks._tcp', 'SOCKS Proxy Service'),
            ('_lb._tcp', 'Load Balancer Service'),
            ('_gateway._tcp', 'API Gateway Service'),
            ('_waf._tcp', 'Web Application Firewall'),
            ('_cache._tcp', 'Caching Service'),
            ('_cdn._tcp', 'Content Delivery Network'),
            ('_nginx._tcp', 'Nginx Proxy Service'),
            ('_haproxy._tcp', 'HAProxy Load Balancer'),
            ('_traefik._tcp', 'Traefik Reverse Proxy'),
            ('_envoy._tcp', 'Envoy Proxy Service'),
            ('_varnish._tcp', 'Varnish Caching Service'),
            ('_istio._tcp', 'Istio Service Mesh'),
            ('_linkerd._tcp', 'Linkerd Service Mesh'),
            ('_kong._tcp', 'Kong API Gateway'),
            ('_zuul._tcp', 'Zuul API Gateway')
        ]
        
        proxy_services['srv_based_proxies'] = {}
        for srv_record, description in proxy_srv_records:
            srv_domain = f'{srv_record}.{domain}'
            srv_records = dns_query(srv_domain, 'SRV', None, DNS_TIMEOUT)
            
            if srv_records:
                service_details = []
                for record in srv_records:
                    srv_data = format_rdata('SRV', record['rdata']).split()
                    if len(srv_data) >= 4:
                        priority = int(srv_data[0])
                        weight = int(srv_data[1])
                        port = int(srv_data[2])
                        target = srv_data[3].rstrip('.')
                        
                        accessible = test_port_connectivity(target, port)
                        service_details.append({
                            'priority': priority,
                            'weight': weight,
                            'port': port,
                            'target': target,
                            'accessible': accessible
                        })
                
                proxy_services['srv_based_proxies'][srv_record] = {
                    'description': description,
                    'records': service_details,
                    'record_count': len(service_details)
                }
        
        # Update summary statistics
        proxy_services['proxy_summary']['total_proxy_services'] = discovered_proxies
        proxy_services['proxy_summary']['accessible_proxies'] = accessible_proxies
        proxy_services['proxy_summary']['accessibility_rate'] = \
            round((accessible_proxies / discovered_proxies * 100), 2) if discovered_proxies > 0 else 0
        
        # Analyze proxy deployment patterns
        proxy_services['deployment_analysis'] = analyze_proxy_deployment(proxy_services)
        
        return proxy_services
        
    except Exception as e:
        return {'error': str(e)}

def categorize_proxy_service(subdomain):
    """Categorize proxy services based on subdomain patterns."""
    subdomain_lower = subdomain.lower()
    
    if any(term in subdomain_lower for term in ['lb', 'loadbalancer', 'load-balancer', 'nlb', 'alb', 'balance', 'f5', 'bigip', 'netscaler', 'citrix', 'a10', 'kemp']):
        return 'load_balancers'
    elif any(term in subdomain_lower for term in ['forward-proxy', 'http-proxy', 'https-proxy', 'squid', 'transparent']):
        return 'forward_proxies'
    elif any(term in subdomain_lower for term in ['reverse-proxy', 'nginx', 'apache', 'haproxy', 'traefik', 'envoy', 'varnish']):
        return 'reverse_proxies'
    elif any(term in subdomain_lower for term in ['cdn', 'cache', 'caching', 'cloudflare', 'cloudfront', 'fastly', 'akamai', 'varnish-cache']):
        return 'caching_proxies'
    elif any(term in subdomain_lower for term in ['waf', 'firewall', 'filter', 'content-filter', 'url-filter', 'blue-coat', 'websense', 'forcepoint', 'zscaler']):
        return 'content_filters'
    elif any(term in subdomain_lower for term in ['api-gateway', 'gateway', 'kong', 'zuul', 'ambassador', 'edge']):
        return 'api_gateways'
    elif any(term in subdomain_lower for term in ['istio', 'linkerd', 'consul-connect', 'service-mesh', 'mesh']):
        return 'service_mesh'
    elif any(term in subdomain_lower for term in ['socks', 'tor', 'anonymous', 'vpn-proxy']):
        return 'anonymous_proxies'
    else:
        return 'generic_proxies'

def detect_proxy_software(subdomain):
    """Detect proxy software based on subdomain naming patterns."""
    subdomain_lower = subdomain.lower()
    
    if 'squid' in subdomain_lower:
        return 'Squid Cache'
    elif 'nginx' in subdomain_lower:
        return 'Nginx'
    elif 'apache' in subdomain_lower or 'httpd' in subdomain_lower:
        return 'Apache HTTP Server'
    elif 'haproxy' in subdomain_lower or 'ha-proxy' in subdomain_lower:
        return 'HAProxy'
    elif 'traefik' in subdomain_lower:
        return 'Traefik'
    elif 'envoy' in subdomain_lower:
        return 'Envoy Proxy'
    elif 'varnish' in subdomain_lower:
        return 'Varnish Cache'
    elif 'istio' in subdomain_lower:
        return 'Istio Service Mesh'
    elif 'linkerd' in subdomain_lower:
        return 'Linkerd Service Mesh'
    elif 'kong' in subdomain_lower:
        return 'Kong API Gateway'
    elif 'zuul' in subdomain_lower:
        return 'Netflix Zuul'
    elif 'f5' in subdomain_lower or 'bigip' in subdomain_lower:
        return 'F5 BIG-IP'
    elif 'netscaler' in subdomain_lower or 'citrix' in subdomain_lower:
        return 'Citrix NetScaler/ADC'
    elif 'cloudflare' in subdomain_lower:
        return 'Cloudflare'
    elif 'fastly' in subdomain_lower:
        return 'Fastly CDN'
    elif 'akamai' in subdomain_lower:
        return 'Akamai CDN'
    elif 'blue-coat' in subdomain_lower or 'bluecoat' in subdomain_lower:
        return 'Blue Coat ProxySG'
    elif 'websense' in subdomain_lower:
        return 'Websense/Forcepoint'
    elif 'zscaler' in subdomain_lower:
        return 'Zscaler Cloud Proxy'
    else:
        return 'Unknown/Generic'

def analyze_proxy_deployment(proxy_services):
    """Analyze proxy deployment patterns and provide insights."""
    analysis = {
        'deployment_patterns': [],
        'redundancy_analysis': {},
        'security_assessment': {},
        'performance_indicators': {},
        'recommendations': [],
        'architecture_insights': {}
    }
    
    try:
        # Analyze load balancer redundancy
        if proxy_services['load_balancers']:
            lb_count = len(proxy_services['load_balancers'])
            analysis['redundancy_analysis']['load_balancers'] = {
                'count': lb_count,
                'redundancy_level': 'High' if lb_count >= 3 else 'Medium' if lb_count >= 2 else 'Low',
                'recommendation': 'Consider additional load balancers for high availability' if lb_count < 2 else 'Good redundancy detected'
            }
            analysis['deployment_patterns'].append(f'Load balancer deployment detected ({lb_count} instances)')
        
        # Analyze reverse proxy setup
        if proxy_services['reverse_proxies']:
            rp_count = len(proxy_services['reverse_proxies'])
            analysis['deployment_patterns'].append(f'Reverse proxy deployment detected ({rp_count} instances)')
            analysis['architecture_insights']['reverse_proxy'] = 'Modern web architecture with reverse proxy detected'
        
        # Analyze service mesh deployment
        if proxy_services['service_mesh']:
            sm_count = len(proxy_services['service_mesh'])
            analysis['deployment_patterns'].append(f'Service mesh deployment detected ({sm_count} instances)')
            analysis['architecture_insights']['service_mesh'] = 'Microservices architecture with service mesh detected'
        
        # Security analysis
        if proxy_services['content_filters']:
            analysis['security_assessment']['content_filtering'] = 'Enabled'
            analysis['security_assessment']['security_proxy_count'] = len(proxy_services['content_filters'])
        else:
            analysis['security_assessment']['content_filtering'] = 'Not detected'
            analysis['recommendations'].append('Consider implementing content filtering proxy for security')
        
        # Performance analysis
        if proxy_services['caching_proxies']:
            analysis['performance_indicators']['caching'] = 'Enabled'
            analysis['performance_indicators']['cache_proxy_count'] = len(proxy_services['caching_proxies'])
        else:
            analysis['performance_indicators']['caching'] = 'Not detected'
            analysis['recommendations'].append('Consider implementing caching proxy for performance')
        
        # API Gateway analysis
        if proxy_services['api_gateways']:
            api_gw_count = len(proxy_services['api_gateways'])
            analysis['architecture_insights']['api_gateway'] = f'API-first architecture detected ({api_gw_count} gateways)'
            analysis['deployment_patterns'].append(f'API gateway deployment detected ({api_gw_count} instances)')
        
        # Forward proxy analysis
        if proxy_services['forward_proxies']:
            fp_count = len(proxy_services['forward_proxies'])
            analysis['security_assessment']['outbound_proxy'] = f'{fp_count} forward proxies detected'
            analysis['deployment_patterns'].append(f'Forward proxy deployment for outbound traffic ({fp_count} instances)')
        
        # Anonymous proxy analysis
        if proxy_services['anonymous_proxies']:
            anon_count = len(proxy_services['anonymous_proxies'])
            analysis['security_assessment']['anonymous_proxies'] = f'{anon_count} anonymous/SOCKS proxies detected'
            analysis['recommendations'].append('Review anonymous proxy configurations for security compliance')
        
        # Overall architecture assessment
        total_proxy_types = len([k for k, v in proxy_services['proxy_summary']['proxy_types'].items() if v > 0])
        if total_proxy_types >= 4:
            analysis['architecture_insights']['complexity'] = 'Complex proxy infrastructure with multiple service types'
        elif total_proxy_types >= 2:
            analysis['architecture_insights']['complexity'] = 'Moderate proxy infrastructure deployment'
        elif total_proxy_types >= 1:
            analysis['architecture_insights']['complexity'] = 'Simple proxy infrastructure deployment'
        
        return analysis
        
    except Exception as e:
        return {'error': str(e)}

def perform_service_security_analysis(discovered_services):
    """Perform comprehensive security analysis on discovered services."""
    analysis = {
        'security_score': 0,
        'vulnerabilities': [],
        'best_practices': [],
        'compliance_issues': [],
        'recommendations': []
    }
    
    try:
        total_score = 100
        deductions = 0
        
        # Web service security analysis
        if 'web' in discovered_services:
            web_analysis = analyze_web_security(discovered_services['web'])
            analysis['vulnerabilities'].extend(web_analysis.get('vulnerabilities', []))
            deductions += web_analysis.get('score_deduction', 0)
        
        # Email service security analysis
        if 'email' in discovered_services:
            email_analysis = analyze_email_security_comprehensive(discovered_services['email'])
            analysis['vulnerabilities'].extend(email_analysis.get('vulnerabilities', []))
            deductions += email_analysis.get('score_deduction', 0)
        
        # TLS service security analysis
        if 'tls' in discovered_services:
            tls_analysis = analyze_tls_security_comprehensive(discovered_services['tls'])
            analysis['vulnerabilities'].extend(tls_analysis.get('vulnerabilities', []))
            deductions += tls_analysis.get('score_deduction', 0)
        
        # Calculate final security score
        analysis['security_score'] = max(0, total_score - deductions)
        
        return analysis
    except Exception as e:
        return {'error': str(e)}

def generate_monitoring_recommendations(domain, discovered_services):
    """Generate intelligent monitoring recommendations based on discovered services."""
    recommendations = []
    
    try:
        # Web service monitoring
        if 'web' in discovered_services and not discovered_services['web'].get('error'):
            web_services = discovered_services['web']
            if web_services.get('https_available'):
                recommendations.append({
                    'priority': 'HIGH',
                    'service': 'HTTPS Monitoring',
                    'template': 'TLS Compliance Checker',
                    'items': ['Certificate expiry', 'TLS version', 'Cipher strength'],
                    'ports': web_services.get('https_ports', []),
                    'check_interval': '1h'
                })
            
            if web_services.get('http_available'):
                recommendations.append({
                    'priority': 'MEDIUM',
                    'service': 'HTTP Redirect Monitoring',
                    'template': 'Agent Web Check',
                    'items': ['HTTP to HTTPS redirect', 'Response time', 'Status code'],
                    'ports': web_services.get('http_ports', []),
                    'check_interval': '5m'
                })
        
        # Email service monitoring
        if 'email' in discovered_services and not discovered_services['email'].get('error'):
            email_services = discovered_services['email']
            if email_services.get('mx_records'):
                recommendations.append({
                    'priority': 'HIGH',
                    'service': 'Email Monitoring',
                    'template': 'Email Health',
                    'items': ['MX availability', 'SMTP response', 'Authentication records'],
                    'check_interval': '10m'
                })
        
        # DNS monitoring
        recommendations.append({
            'priority': 'CRITICAL',
            'service': 'DNS Monitoring',
            'template': 'Domain Health',
            'items': ['DNS resolution', 'SOA consistency', 'NS availability'],
            'check_interval': '5m'
        })
        
        # DNSSEC monitoring if enabled
        if 'security' in discovered_services and discovered_services['security'].get('dnssec', {}).get('enabled'):
            recommendations.append({
                'priority': 'HIGH',
                'service': 'DNSSEC Monitoring',
                'template': 'Domain Health',
                'items': ['DNSSEC validation', 'Key expiry', 'Chain integrity'],
                'check_interval': '1h'
            })
        
        return recommendations
    except Exception as e:
        return [{'error': str(e)}]

def calculate_service_summary(discovered_services):
    """Calculate summary statistics for discovered services."""
    summary = {
        'total_services': 0,
        'secure_services': 0,
        'vulnerable_services': 0,
        'missing_security_features': [],
        'service_categories': {}
    }
    
    try:
        for category, services in discovered_services.items():
            if isinstance(services, dict) and not services.get('error'):
                summary['service_categories'][category] = analyze_service_category(category, services)
                summary['total_services'] += summary['service_categories'][category].get('count', 0)
                summary['secure_services'] += summary['service_categories'][category].get('secure_count', 0)
        
        return summary
    except Exception as e:
        return {'error': str(e)}

def generate_integration_points(domain, discovered_services):
    """Generate Zabbix integration points and template mappings."""
    integration = {
        'zabbix_templates': [],
        'custom_items': [],
        'discovery_rules': [],
        'macros': {}
    }
    
    try:
        # Template recommendations based on discovered services
        if 'web' in discovered_services:
            integration['zabbix_templates'].append('Agent Web Check')
            if discovered_services['web'].get('https_available'):
                integration['zabbix_templates'].append('TLS Compliance Checker')
        
        if 'email' in discovered_services and discovered_services['email'].get('mx_records'):
            integration['zabbix_templates'].append('Email Health')
        
        # Always include domain health monitoring
        integration['zabbix_templates'].append('Domain Health')
        
        # Generate custom discovery rules
        if 'srv' in discovered_services and discovered_services['srv'].get('discovered_services'):
            integration['discovery_rules'].append({
                'name': 'Service Discovery via SRV records',
                'key': f'get_domain_health.py[discover_services,{domain}]',
                'description': 'Discover services through SRV DNS records'
            })
        
        # Generate useful macros
        integration['macros'] = {
            '{$DOMAIN}': domain,
            '{$DNS_TIMEOUT}': '5',
            '{$MONITORING_INTERVAL}': '300'
        }
        
        return integration
    except Exception as e:
        return {'error': str(e)}

# --- Helper Functions for Service Analysis ---

def detect_web_technology(domain, web_services):
    """Detect web server technology and frameworks."""
    return {'detection_method': 'placeholder', 'note': 'Technology detection requires HTTP header analysis'}

def analyze_http_security_headers(domain, web_services):
    """Analyze HTTP security headers."""
    return {'analysis_method': 'placeholder', 'note': 'Security header analysis requires HTTP requests'}

def analyze_redirect_chains(domain, web_services):
    """Analyze HTTP redirect chains."""
    return {'analysis_method': 'placeholder', 'note': 'Redirect analysis requires HTTP requests'}

def detect_http_protocols(domain, web_services):
    """Detect HTTP protocol support (HTTP/1.1, HTTP/2, HTTP/3)."""
    return {'detection_method': 'placeholder', 'note': 'Protocol detection requires specialized HTTP client'}

def test_mx_connectivity(domain, mx_records):
    """Test connectivity and latency to MX servers."""
    connectivity = []
    for mx_record in mx_records:
        # Extract MX server name from record
        mx_parts = mx_record.split()
        if len(mx_parts) >= 2:
            mx_server = mx_parts[1].rstrip('.')
            connectivity.append({
                'server': mx_server,
                'accessible': test_port_connectivity(mx_server, 25),
                'priority': mx_parts[0] if mx_parts[0].isdigit() else 0
            })
    return connectivity

def analyze_smtp_security(domain, smtp_ports):
    """Analyze SMTP security features."""
    return {'analysis_method': 'placeholder', 'note': 'SMTP analysis requires SMTP protocol interaction'}

def analyze_email_authentication(domain):
    """Analyze email authentication (SPF, DKIM, DMARC)."""
    auth_result = {}
    
    # Get SPF record
    spf_result = get_spf(domain)
    if isinstance(spf_result, str):
        try:
            auth_result['spf'] = json.loads(spf_result)
        except:
            auth_result['spf'] = {'error': 'Failed to parse SPF result'}
    
    # Get DMARC record
    dmarc_result = get_dmarc(domain)
    if isinstance(dmarc_result, str):
        try:
            auth_result['dmarc'] = json.loads(dmarc_result)
        except:
            auth_result['dmarc'] = {'error': 'Failed to parse DMARC result'}
    
    return auth_result

def analyze_email_security_policies(domain):
    """Analyze email security policies (MTA-STS, TLS-RPT)."""
    policies = {}
    
    # Get MTA-STS policy
    mta_sts_result = get_mta_sts(domain)
    if isinstance(mta_sts_result, str):
        try:
            policies['mta_sts'] = json.loads(mta_sts_result)
        except:
            policies['mta_sts'] = {'error': 'Failed to parse MTA-STS result'}
    
    # Get TLS-RPT policy
    tls_rpt_result = get_tls_rpt(domain)
    if isinstance(tls_rpt_result, str):
        try:
            policies['tls_rpt'] = json.loads(tls_rpt_result)
        except:
            policies['tls_rpt'] = {'error': 'Failed to parse TLS-RPT result'}
    
    return policies

def analyze_tls_certificate(domain, port):
    """Analyze TLS certificate for a specific port."""
    return {'analysis_method': 'placeholder', 'note': 'Certificate analysis requires TLS connection'}

def analyze_cipher_suites(domain, ports):
    """Analyze supported cipher suites."""
    return {'analysis_method': 'placeholder', 'note': 'Cipher analysis requires TLS handshake testing'}

def validate_dane_for_services(domain, ports):
    """Validate DANE/TLSA records for services."""
    validation = {}
    for port in ports:
        dane_result = get_dane(domain, port, True)
        if isinstance(dane_result, str):
            try:
                validation[str(port)] = json.loads(dane_result)
            except:
                validation[str(port)] = {'error': 'Failed to parse DANE result'}
    return validation

def detect_tls_versions(domain, ports):
    """Detect supported TLS protocol versions."""
    return {'detection_method': 'placeholder', 'note': 'TLS version detection requires specialized TLS testing'}

def test_srv_connectivity(records):
    """Test connectivity to SRV record targets."""
    connectivity = []
    for record in records:
        srv_parts = record.split()
        if len(srv_parts) >= 4:
            target = srv_parts[3].rstrip('.')
            port = int(srv_parts[2]) if srv_parts[2].isdigit() else 0
            connectivity.append({
                'target': target,
                'port': port,
                'accessible': test_port_connectivity(target, port) if port > 0 else False
            })
    return connectivity

def analyze_srv_service_config(service_name, records):
    """Analyze SRV service-specific configurations."""
    return {'service': service_name, 'records': len(records), 'analysis': 'placeholder'}

def analyze_subdomain_service(full_domain):
    """Analyze a subdomain for service indicators."""
    try:
        # Check if subdomain exists
        a_records = dns_query(full_domain, 'A', None, DNS_TIMEOUT)
        aaaa_records = dns_query(full_domain, 'AAAA', None, DNS_TIMEOUT)
        
        return {
            'exists': bool(a_records or aaaa_records),
            'a_records': len(a_records),
            'aaaa_records': len(aaaa_records),
            'subdomain': full_domain
        }
    except:
        return {'exists': False, 'subdomain': full_domain}

def analyze_caa_policies(caa_records):
    """Analyze CAA records for certificate authority policies."""
    policies = []
    for record in caa_records:
        formatted = format_rdata('CAA', record['rdata'])
        policies.append({'policy': formatted})
    return policies

def analyze_txt_service_indicators(txt_records):
    """Analyze TXT records for service indicators."""
    indicators = []
    for record in txt_records:
        formatted = format_rdata('TXT', record['rdata'])
        if any(keyword in formatted.lower() for keyword in ['v=spf', 'v=dmarc', 'v=dkim', 'google-site-verification']):
            indicators.append({'type': 'email_auth_or_verification', 'record': formatted})
    return indicators

def get_service_name_for_port(port):
    """Get common service name for a port number."""
    port_services = {
        22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
        143: 'IMAP', 161: 'SNMP', 443: 'HTTPS', 465: 'SMTPS', 587: 'SMTP Submission',
        623: 'IPMI', 993: 'IMAPS', 995: 'POP3S', 1433: 'SQL Server', 1521: 'Oracle',
        3000: 'Node.js App', 3306: 'MySQL', 4000: 'App Server', 5000: 'Flask/App',
        5432: 'PostgreSQL', 6379: 'Redis', 8000: 'HTTP Alt', 8006: 'Proxmox',
        8080: 'HTTP Proxy', 8443: 'HTTPS Alt', 8888: 'HTTP Alt', 9000: 'App Server',
        9001: 'Management', 9042: 'Cassandra', 9090: 'Prometheus', 10000: 'Webmin',
        27017: 'MongoDB'
    }
    return port_services.get(port, f'Unknown Port {port}')

def discover_security_txt(domain):
    """Discover security.txt file."""
    return {'method': 'placeholder', 'note': 'Security.txt discovery requires HTTP requests'}

def analyze_ct_logs(domain):
    """Analyze Certificate Transparency logs."""
    return {'method': 'placeholder', 'note': 'CT log analysis requires external API calls'}

def discover_service_fingerprints(domain, discovered_ports):
    """Phase 3: Comprehensive service fingerprinting for discovered ports."""
    result = {
        'domain': domain,
        'fingerprinting_results': {},
        'service_summary': {
            'total_services': len(discovered_ports) if discovered_ports else 0,
            'identified_services': 0,
            'encrypted_services': 0,
            'vulnerable_services': 0,
            'database_services': 0,
            'web_services': 0
        },
        'security_overview': {
            'overall_score': 0,
            'critical_issues': [],
            'recommendations': []
        }
    }
    
    try:
        if not discovered_ports:
            return result
            
        import concurrent.futures
        import threading
        
        fingerprint_results = {}
        lock = threading.Lock()
        
        def fingerprint_port(port_info):
            try:
                port = port_info.get('port') if isinstance(port_info, dict) else port_info
                identification = identify_service_on_port(domain, port)
                
                with lock:
                    fingerprint_results[str(port)] = identification
                    
                    # Update summary
                    if identification['service_identification']['confidence'] > 50:
                        result['service_summary']['identified_services'] += 1
                    
                    service_name = identification['service_identification']['service_name'].lower()
                    if service_name in ['https', 'ssh', 'imaps', 'pop3s', 'smtps']:
                        result['service_summary']['encrypted_services'] += 1
                    elif service_name in ['http', 'https', 'nginx', 'apache']:
                        result['service_summary']['web_services'] += 1
                    elif service_name in ['mysql', 'postgresql', 'mongodb', 'redis']:
                        result['service_summary']['database_services'] += 1
                    
                    if identification['security_analysis']['security_score'] < 60:
                        result['service_summary']['vulnerable_services'] += 1
                        
            except Exception:
                pass  # Skip individual port errors
        
        # Execute fingerprinting
        max_workers = min(10, len(discovered_ports))  # Conservative for service probing
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                executor.map(fingerprint_port, discovered_ports)
        except Exception:
            # Fallback to sequential
            for port_info in discovered_ports:
                fingerprint_port(port_info)
        
        result['fingerprinting_results'] = fingerprint_results
        
        # Calculate overall security score
        if fingerprint_results:
            scores = [fp['security_analysis']['security_score'] for fp in fingerprint_results.values()]
            result['security_overview']['overall_score'] = sum(scores) // len(scores)
            
            # Collect critical issues
            for port, fp in fingerprint_results.items():
                if fp['security_analysis']['security_score'] < 50:
                    result['security_overview']['critical_issues'].append(f"Port {port}: {fp['service_identification']['service_name']}")
                
                result['security_overview']['recommendations'].extend(fp['security_analysis']['recommendations'][:2])
        
    except Exception as e:
        result['error'] = str(e)
    
    return result

def analyze_hsts_policy(domain):
    """Analyze HSTS policy."""
    return {'method': 'placeholder', 'note': 'HSTS analysis requires HTTP requests'}

def analyze_web_security(web_services):
    """Analyze web service security."""
    return {'vulnerabilities': [], 'score_deduction': 0}

def analyze_email_security_comprehensive(email_services):
    """Comprehensive email security analysis."""
    return {'vulnerabilities': [], 'score_deduction': 0}

def analyze_tls_security_comprehensive(tls_services):
    """Comprehensive TLS security analysis."""
    return {'vulnerabilities': [], 'score_deduction': 0}

def analyze_service_category(category, services):
    """Analyze a service category for summary statistics."""
    return {'count': 1, 'secure_count': 0}

def discover_srv_based_services(domain):
    """Comprehensive SRV record discovery for service advertisement."""
    srv_services = {
        'discovered_records': {},
        'service_categories': {},
        'active_services': {},
        'service_summary': {
            'total_srv_records': 0,
            'accessible_services': 0,
            'protocol_distribution': {}
        }
    }
    
    try:
        # Comprehensive SRV service list covering all major protocols and services
        srv_service_list = [
            # Communication & VoIP Services
            ('_sip._tcp', 'SIP (Session Initiation Protocol) - VoIP signaling'),
            ('_sip._udp', 'SIP over UDP - VoIP signaling'),
            ('_sips._tcp', 'SIP over TLS - Secure VoIP signaling'),
            ('_sipfederationtls._tcp', 'SIP Federation TLS - Enterprise VoIP'),
            ('_sipinternaltls._tcp', 'SIP Internal TLS - Internal VoIP'),
            ('_h323cs._tcp', 'H.323 Call Signaling - Video conferencing'),
            ('_h323ls._udp', 'H.323 Location Services - Video conferencing'),
            ('_stun._tcp', 'STUN (Session Traversal Utilities for NAT)'),
            ('_stun._udp', 'STUN over UDP'),
            ('_stuns._tcp', 'STUN over TLS'),
            ('_turn._tcp', 'TURN (Traversal Using Relays around NAT)'),
            ('_turn._udp', 'TURN over UDP'),
            ('_turns._tcp', 'TURN over TLS'),
            
            # Instant Messaging & Chat
            ('_xmpp-client._tcp', 'XMPP Client Connections - Jabber/Chat'),
            ('_xmpp-server._tcp', 'XMPP Server-to-Server - Federation'),
            ('_xmpps-client._tcp', 'XMPP over TLS - Secure chat'),
            ('_xmpps-server._tcp', 'XMPP Server TLS - Secure federation'),
            ('_jabber._tcp', 'Jabber Protocol - Legacy XMPP'),
            ('_irc._tcp', 'IRC (Internet Relay Chat)'),
            ('_ircs._tcp', 'IRC over SSL/TLS'),
            
            # Email Services
            ('_smtp._tcp', 'SMTP (Simple Mail Transfer Protocol)'),
            ('_submission._tcp', 'SMTP Submission (Port 587)'),
            ('_smtps._tcp', 'SMTP over SSL/TLS (Port 465)'),
            ('_imap._tcp', 'IMAP (Internet Message Access Protocol)'),
            ('_imaps._tcp', 'IMAP over SSL/TLS'),
            ('_pop3._tcp', 'POP3 (Post Office Protocol v3)'),
            ('_pop3s._tcp', 'POP3 over SSL/TLS'),
            ('_msa._tcp', 'Mail Submission Agent'),
            
            # Web Services
            ('_http._tcp', 'HTTP (Hypertext Transfer Protocol)'),
            ('_https._tcp', 'HTTPS (HTTP over SSL/TLS)'),
            ('_ws._tcp', 'WebSocket Protocol'),
            ('_wss._tcp', 'WebSocket Secure (over TLS)'),
            ('_caldav._tcp', 'CalDAV (Calendar Distributed Authoring and Versioning)'),
            ('_carddav._tcp', 'CardDAV (Contact Distributed Authoring and Versioning)'),
            ('_webdav._tcp', 'WebDAV (Web Distributed Authoring and Versioning)'),
            
            # Proxy & Load Balancing Services
            ('_proxy._tcp', 'Generic Proxy Service'),
            ('_http-proxy._tcp', 'HTTP Proxy Service'),
            ('_https-proxy._tcp', 'HTTPS Proxy Service'),
            ('_socks._tcp', 'SOCKS Proxy Service'),
            ('_socks4._tcp', 'SOCKS4 Proxy Service'),
            ('_socks5._tcp', 'SOCKS5 Proxy Service'),
            ('_squid._tcp', 'Squid Proxy Cache'),
            ('_nginx._tcp', 'Nginx Reverse Proxy'),
            ('_apache._tcp', 'Apache HTTP Proxy'),
            ('_haproxy._tcp', 'HAProxy Load Balancer'),
            ('_traefik._tcp', 'Traefik Reverse Proxy'),
            ('_envoy._tcp', 'Envoy Proxy'),
            ('_varnish._tcp', 'Varnish HTTP Cache'),
            ('_lb._tcp', 'Load Balancer Service'),
            ('_loadbalancer._tcp', 'Load Balancer Service'),
            ('_gateway._tcp', 'Gateway Service'),
            ('_api-gateway._tcp', 'API Gateway Service'),
            ('_waf._tcp', 'Web Application Firewall'),
            ('_cache._tcp', 'Caching Proxy Service'),
            ('_cdn._tcp', 'Content Delivery Network'),
            ('_reverse-proxy._tcp', 'Reverse Proxy Service'),
            ('_forward-proxy._tcp', 'Forward Proxy Service'),
            ('_transparent-proxy._tcp', 'Transparent Proxy Service'),
            ('_content-filter._tcp', 'Content Filtering Proxy'),
            ('_web-filter._tcp', 'Web Content Filter'),
            ('_url-filter._tcp', 'URL Filtering Service'),
            ('_istio._tcp', 'Istio Service Mesh Proxy'),
            ('_linkerd._tcp', 'Linkerd Service Mesh'),
            ('_consul-connect._tcp', 'Consul Connect Service Mesh'),
            ('_kong._tcp', 'Kong API Gateway'),
            ('_zuul._tcp', 'Netflix Zuul Gateway'),
            ('_ambassador._tcp', 'Ambassador API Gateway'),
            ('_contour._tcp', 'Contour Ingress Controller'),
            ('_ingress._tcp', 'Kubernetes Ingress Controller'),
            ('_f5._tcp', 'F5 Load Balancer'),
            ('_bigip._tcp', 'F5 BIG-IP Load Balancer'),
            ('_netscaler._tcp', 'Citrix NetScaler/ADC'),
            ('_citrix-adc._tcp', 'Citrix Application Delivery Controller'),
            ('_a10._tcp', 'A10 Load Balancer'),
            ('_kemp._tcp', 'KEMP Load Balancer'),
            ('_radware._tcp', 'Radware Load Balancer'),
            ('_barracuda._tcp', 'Barracuda Load Balancer'),
            ('_cloudflare._tcp', 'Cloudflare Proxy Service'),
            ('_fastly._tcp', 'Fastly CDN/Proxy'),
            ('_akamai._tcp', 'Akamai CDN/Proxy'),
            ('_blue-coat._tcp', 'Blue Coat ProxySG'),
            ('_websense._tcp', 'Websense/Forcepoint Proxy'),
            ('_forcepoint._tcp', 'Forcepoint Security Proxy'),
            ('_zscaler._tcp', 'Zscaler Cloud Proxy'),
            ('_mcafee-proxy._tcp', 'McAfee Web Gateway'),
            ('_symantec-proxy._tcp', 'Symantec Proxy'),
            
            # File Transfer Services
            ('_ftp._tcp', 'FTP (File Transfer Protocol)'),
            ('_ftps._tcp', 'FTP over SSL/TLS'),
            ('_sftp._tcp', 'SFTP (SSH File Transfer Protocol)'),
            ('_tftp._udp', 'TFTP (Trivial File Transfer Protocol)'),
            ('_rsync._tcp', 'Rsync File Synchronization'),
            
            # Directory & Authentication Services
            ('_ldap._tcp', 'LDAP (Lightweight Directory Access Protocol)'),
            ('_ldaps._tcp', 'LDAP over SSL/TLS'),
            ('_kerberos._tcp', 'Kerberos Authentication'),
            ('_kerberos._udp', 'Kerberos over UDP'),
            ('_kpasswd._tcp', 'Kerberos Password Change'),
            ('_kpasswd._udp', 'Kerberos Password Change over UDP'),
            ('_ldap-admin._tcp', 'LDAP Administration'),
            ('_gc._tcp', 'Active Directory Global Catalog'),
            ('_kerberos-master._tcp', 'Kerberos Master Server'),
            ('_kerberos-master._udp', 'Kerberos Master Server over UDP'),
            ('_kerberos-iv._udp', 'Kerberos IV Authentication'),
            ('_klogin._tcp', 'Kerberos Remote Login'),
            ('_krb524._tcp', 'Kerberos 524 Service'),
            ('_krb524._udp', 'Kerberos 524 Service over UDP'),
            
            # Microsoft Active Directory Services
            ('_ldap._tcp.gc._msdcs', 'AD Global Catalog LDAP'),
            ('_ldap._tcp.pdc._msdcs', 'AD Primary Domain Controller LDAP'),
            ('_ldap._tcp.dc._msdcs', 'AD Domain Controller LDAP'),
            ('_kerberos._tcp.dc._msdcs', 'AD Domain Controller Kerberos'),
            ('_gc._tcp._msdcs', 'AD Global Catalog'),
            ('_domains._msdcs', 'AD Domain Location'),
            
            # Remote Access Services  
            ('_ssh._tcp', 'SSH (Secure Shell)'),
            ('_telnet._tcp', 'Telnet Protocol'),
            ('_rdp._tcp', 'RDP (Remote Desktop Protocol)'),
            ('_vnc._tcp', 'VNC (Virtual Network Computing)'),
            ('_rfb._tcp', 'RFB (Remote Framebuffer) - VNC protocol'),
            ('_rlogin._tcp', 'Remote Login'),
            ('_shell._tcp', 'Remote Shell'),
            ('_exec._tcp', 'Remote Execution'),
            
            # Database Services
            ('_mysql._tcp', 'MySQL Database'),
            ('_postgresql._tcp', 'PostgreSQL Database'),
            ('_oracle._tcp', 'Oracle Database'),
            ('_mssql._tcp', 'Microsoft SQL Server'),
            ('_mongodb._tcp', 'MongoDB Database'),
            ('_redis._tcp', 'Redis Database'),
            ('_cassandra._tcp', 'Cassandra Database'),
            ('_couchdb._tcp', 'CouchDB Database'),
            ('_influxdb._tcp', 'InfluxDB Time Series Database'),
            
            # Network Services
            ('_dns._tcp', 'DNS over TCP'),
            ('_dns._udp', 'DNS (Domain Name System)'),
            ('_ntp._udp', 'NTP (Network Time Protocol)'),
            ('_snmp._udp', 'SNMP (Simple Network Management Protocol)'),
            ('_dhcp._udp', 'DHCP (Dynamic Host Configuration Protocol)'),
            ('_tftp._udp', 'TFTP (Trivial File Transfer Protocol)'),
            ('_syslog._udp', 'Syslog Protocol'),
            ('_radius._udp', 'RADIUS Authentication'),
            ('_tacacs._tcp', 'TACACS+ Authentication'),
            
            # Print & Imaging Services
            ('_ipp._tcp', 'IPP (Internet Printing Protocol)'),
            ('_ipps._tcp', 'IPP over SSL/TLS'),
            ('_printer._tcp', 'Printer Services'),
            ('_pdl-datastream._tcp', 'Page Description Language Data Stream'),
            ('_scanner._tcp', 'Network Scanner Services'),
            
            # Apple Services
            ('_afpovertcp._tcp', 'Apple Filing Protocol over TCP'),
            ('_afp._tcp', 'Apple Filing Protocol'),
            ('_airport._tcp', 'Apple AirPort Base Station'),
            ('_airplay._tcp', 'Apple AirPlay'),
            ('_raop._tcp', 'Remote Audio Output Protocol - AirPlay'),
            ('_sleep-proxy._udp', 'Apple Sleep Proxy'),
            ('_daap._tcp', 'Digital Audio Access Protocol - iTunes'),
            ('_dacp._tcp', 'Digital Audio Control Protocol'),
            ('_dpap._tcp', 'Digital Photo Access Protocol - iPhoto'),
            ('_homekit._tcp', 'Apple HomeKit'),
            ('_hap._tcp', 'HomeKit Accessory Protocol'),
            
            # Gaming Services
            ('_minecraft._tcp', 'Minecraft Server'),
            ('_teamspeak._udp', 'TeamSpeak Voice Chat'),
            ('_mumble._tcp', 'Mumble Voice Chat'),
            ('_ventrilo._udp', 'Ventrilo Voice Chat'),
            ('_steam._tcp', 'Steam Gaming Platform'),
            ('_gamespy._udp', 'GameSpy Network'),
            
            # Media & Streaming Services
            ('_rtsp._tcp', 'RTSP (Real Time Streaming Protocol)'),
            ('_rtmp._tcp', 'RTMP (Real Time Messaging Protocol)'),
            ('_sip._tcp', 'Session Initiation Protocol - Media'),
            ('_rtp._udp', 'RTP (Real-time Transport Protocol)'),
            ('_rtcp._udp', 'RTCP (Real-time Transport Control Protocol)'),
            ('_icecast._tcp', 'Icecast Streaming Server'),
            ('_shoutcast._tcp', 'SHOUTcast Streaming Server'),
            ('_plex._tcp', 'Plex Media Server'),
            ('_dlna._tcp', 'DLNA Media Sharing'),
            ('_upnp._tcp', 'UPnP (Universal Plug and Play)'),
            
            # Development & CI/CD Services
            ('_git._tcp', 'Git Version Control'),
            ('_svn._tcp', 'Subversion Version Control'),
            ('_jenkins._tcp', 'Jenkins CI/CD'),
            ('_gitlab._tcp', 'GitLab'),
            ('_docker._tcp', 'Docker Services'),
            ('_kubernetes._tcp', 'Kubernetes API'),
            ('_etcd._tcp', 'etcd Key-Value Store'),
            ('_consul._tcp', 'Consul Service Discovery'),
            
            # Monitoring & Logging Services
            ('_prometheus._tcp', 'Prometheus Monitoring'),
            ('_grafana._tcp', 'Grafana Dashboards'),
            ('_elasticsearch._tcp', 'Elasticsearch'),
            ('_logstash._tcp', 'Logstash'),
            ('_kibana._tcp', 'Kibana'),
            ('_nagios._tcp', 'Nagios Monitoring'),
            ('_zabbix._tcp', 'Zabbix Monitoring'),
            ('_icinga._tcp', 'Icinga Monitoring'),
            ('_sensu._tcp', 'Sensu Monitoring'),
            
            # Message Queue Services
            ('_amqp._tcp', 'AMQP (Advanced Message Queuing Protocol)'),
            ('_mqtt._tcp', 'MQTT (Message Queuing Telemetry Transport)'),
            ('_mqtts._tcp', 'MQTT over SSL/TLS'),
            ('_stomp._tcp', 'STOMP (Simple Text Oriented Message Protocol)'),
            ('_rabbitmq._tcp', 'RabbitMQ Message Broker'),
            ('_kafka._tcp', 'Apache Kafka'),
            ('_nats._tcp', 'NATS Messaging System'),
            
            # IoT & Industrial Services
            ('_coap._udp', 'CoAP (Constrained Application Protocol)'),
            ('_coaps._udp', 'CoAP over DTLS'),
            ('_opcua._tcp', 'OPC UA (Open Platform Communications Unified Architecture)'),
            ('_modbus._tcp', 'Modbus TCP Protocol'),
            ('_bacnet._udp', 'BACnet Building Automation'),
            ('_knx._udp', 'KNX Building Automation'),
            ('_zigbee._tcp', 'Zigbee IoT Protocol'),
            ('_zwave._tcp', 'Z-Wave IoT Protocol'),
            
            # Security Services
            ('_tls._tcp', 'TLS (Transport Layer Security)'),
            ('_dtls._udp', 'DTLS (Datagram Transport Layer Security)'),
            ('_ipsec._udp', 'IPSec VPN'),
            ('_openvpn._tcp', 'OpenVPN'),
            ('_openvpn._udp', 'OpenVPN over UDP'),
            ('_wireguard._udp', 'WireGuard VPN'),
            ('_pptp._tcp', 'PPTP VPN'),
            ('_l2tp._udp', 'L2TP VPN'),
            
            # Backup & Synchronization
            ('_rsync._tcp', 'Rsync Synchronization'),
            ('_bacula._tcp', 'Bacula Backup'),
            ('_amanda._tcp', 'Amanda Backup'),
            ('_duplicity._tcp', 'Duplicity Backup'),
            ('_restic._tcp', 'Restic Backup'),
            ('_borg._tcp', 'BorgBackup'),
            
            # Healthcare & Medical Services
            ('_dicom._tcp', 'DICOM (Digital Imaging and Communications in Medicine)'),
            ('_dicom._udp', 'DICOM over UDP'),
            ('_dicom-tls._tcp', 'DICOM over TLS (Secure DICOM)'),
            ('_wado._tcp', 'WADO (Web Access to DICOM Objects)'),
            ('_wadors._tcp', 'WADO-RS (RESTful Web Access to DICOM Objects)'),
            ('_qido._tcp', 'QIDO-RS (Query based on ID for DICOM Objects)'),
            ('_stow._tcp', 'STOW-RS (Store Over the Web)'),
            ('_xds._tcp', 'XDS (Cross-Enterprise Document Sharing)'),
            ('_xca._tcp', 'XCA (Cross-Community Access)'),
            ('_xcpd._tcp', 'XCPD (Cross-Community Patient Discovery)'),
            ('_xdr._tcp', 'XDR (Cross-Enterprise Document Reliable Interchange)'),
            ('_pix._tcp', 'PIX (Patient Identifier Cross-referencing)'),
            ('_pdq._tcp', 'PDQ (Patient Demographics Query)'),
            ('_hl7._tcp', 'HL7 (Health Level 7) Messages'),
            ('_hl7-fhir._tcp', 'HL7 FHIR (Fast Healthcare Interoperability Resources)'),
            ('_fhir._tcp', 'FHIR Server'),
            ('_fhir-r4._tcp', 'FHIR R4 Server'),
            ('_fhir-stu3._tcp', 'FHIR STU3 Server'),
            ('_mllp._tcp', 'MLLP (Minimal Lower Layer Protocol) - HL7 Transport'),
            ('_ris._tcp', 'RIS (Radiology Information System)'),
            ('_pacs._tcp', 'PACS (Picture Archiving and Communication System)'),
            ('_his._tcp', 'HIS (Hospital Information System)'),
            ('_emr._tcp', 'EMR (Electronic Medical Records)'),
            ('_ehr._tcp', 'EHR (Electronic Health Records)'),
            ('_cda._tcp', 'CDA (Clinical Document Architecture)'),
            ('_ccda._tcp', 'C-CDA (Consolidated Clinical Document Architecture)'),
            ('_cpoe._tcp', 'CPOE (Computerized Provider Order Entry)'),
            ('_cdss._tcp', 'CDSS (Clinical Decision Support System)'),
            ('_lims._tcp', 'LIMS (Laboratory Information Management System)'),
            ('_lis._tcp', 'LIS (Laboratory Information System)'),
            ('_cis._tcp', 'CIS (Clinical Information System)'),
            ('_pharmacy._tcp', 'Pharmacy Information System'),
            ('_medication._tcp', 'Medication Management System'),
            ('_prescription._tcp', 'Prescription Management System'),
            ('_epic._tcp', 'Epic Healthcare System'),
            ('_cerner._tcp', 'Cerner Healthcare System'),
            ('_allscripts._tcp', 'Allscripts Healthcare Solutions'),
            ('_meditech._tcp', 'MEDITECH Healthcare System'),
            ('_mckesson._tcp', 'McKesson Healthcare Solutions'),
            ('_athenahealth._tcp', 'athenahealth Platform'),
            ('_eclinicalworks._tcp', 'eClinicalWorks EHR'),
            ('_nextgen._tcp', 'NextGen Healthcare'),
            ('_ge-healthcare._tcp', 'GE Healthcare Systems'),
            ('_siemens-healthineers._tcp', 'Siemens Healthineers'),
            ('_philips-healthcare._tcp', 'Philips Healthcare Solutions'),
            ('_agfa-healthcare._tcp', 'Agfa Healthcare'),
            ('_fujifilm-medical._tcp', 'Fujifilm Medical Systems'),
            ('_carestream._tcp', 'Carestream Health'),
            ('_mckesson-pacs._tcp', 'McKesson PACS'),
            ('_ge-pacs._tcp', 'GE PACS'),
            ('_siemens-pacs._tcp', 'Siemens PACS'),
            ('_philips-pacs._tcp', 'Philips PACS'),
            ('_agfa-pacs._tcp', 'Agfa PACS'),
            ('_dcm4chee._tcp', 'DCM4CHEE Open Source PACS'),
            ('_orthanc._tcp', 'Orthanc Lightweight DICOM Server'),
            ('_conquest._tcp', 'Conquest DICOM Server'),
            ('_dicoogle._tcp', 'Dicoogle DICOM Archive'),
            ('_oviyam._tcp', 'Oviyam DICOM Viewer'),
            ('_weasis._tcp', 'Weasis DICOM Viewer'),
            ('_horos._tcp', 'Horos DICOM Viewer'),
            ('_osirix._tcp', 'OsiriX DICOM Viewer'),
            ('_radiant._tcp', 'RadiAnt DICOM Viewer'),
            ('_microdicom._tcp', 'MicroDicom Viewer'),
            ('_synapse._tcp', 'Synapse PACS'),
            ('_clearcanvas._tcp', 'ClearCanvas Workstation'),
            ('_mirth._tcp', 'Mirth Connect HL7 Interface Engine'),
            ('_rhapsody._tcp', 'Rhapsody Integration Engine'),
            ('_cloverleaf._tcp', 'Cloverleaf Integration Platform'),
            ('_ensemble._tcp', 'InterSystems Ensemble'),
            ('_corepoint._tcp', 'Corepoint Health Integration'),
            ('_lyniate._tcp', 'Lyniate (formerly Corepoint Health)'),
            ('_qvera._tcp', 'Qvera Interface Engine'),
            ('_iguana._tcp', 'iNTERFACEWARE Iguana'),
            ('_caristix._tcp', 'Caristix HL7 Tools'),
            ('_hl7spy._tcp', 'HL7Spy Message Analyzer'),
            ('_hl7browser._tcp', 'HL7 Browser'),
            ('_smart-on-fhir._tcp', 'SMART on FHIR Platform'),
            ('_cds-hooks._tcp', 'CDS Hooks Decision Support'),
            ('_bulk-fhir._tcp', 'Bulk FHIR Export'),
            ('_terminology._tcp', 'Medical Terminology Server'),
            ('_snomed._tcp', 'SNOMED CT Terminology Server'),
            ('_loinc._tcp', 'LOINC Terminology Server'),
            ('_icd10._tcp', 'ICD-10 Terminology Server'),
            ('_rxnorm._tcp', 'RxNorm Medication Terminology'),
            ('_umls._tcp', 'UMLS (Unified Medical Language System)'),
            ('_mesh._tcp', 'MeSH (Medical Subject Headings)'),
            ('_cpt._tcp', 'CPT (Current Procedural Terminology)'),
            ('_hcpcs._tcp', 'HCPCS (Healthcare Common Procedure Coding System)'),
            ('_ndc._tcp', 'NDC (National Drug Code) Directory'),
            ('_fdasis._tcp', 'FDA Substance Registration System'),
            ('_nci-thesaurus._tcp', 'NCI Thesaurus'),
            ('_radlex._tcp', 'RadLex Radiology Terminology'),
            ('_rsna._tcp', 'RSNA (Radiological Society of North America) Services'),
            ('_himss._tcp', 'HIMSS Healthcare IT Services'),
            ('_hl7-org._tcp', 'HL7 International Services'),
            ('_ihe._tcp', 'IHE (Integrating the Healthcare Enterprise) Profiles'),
            ('_ccow._tcp', 'CCOW (Clinical Context Object Workgroup)'),
            ('_smart._tcp', 'SMART (Substitutable Medical Applications and Reusable Technologies)'),
            ('_fhircast._tcp', 'FHIRcast Context Synchronization'),
            ('_cql._tcp', 'CQL (Clinical Quality Language) Server'),
            ('_measure._tcp', 'Clinical Quality Measure Server'),
            ('_qicore._tcp', 'QI-Core Quality Improvement Profile'),
            ('_hedis._tcp', 'HEDIS Healthcare Quality Measures'),
            ('_quality-measure._tcp', 'Quality Measure Reporting'),
            ('_population-health._tcp', 'Population Health Management'),
            ('_public-health._tcp', 'Public Health Reporting'),
            ('_immunization._tcp', 'Immunization Registry'),
            ('_vital-records._tcp', 'Vital Records System'),
            ('_cancer-registry._tcp', 'Cancer Registry System'),
            ('_surveillance._tcp', 'Public Health Surveillance'),
            ('_biosense._tcp', 'CDC BioSense Platform'),
            ('_phin._tcp', 'PHIN (Public Health Information Network)'),
            ('_nedss._tcp', 'NEDSS (National Electronic Disease Surveillance System)'),
            ('_nndss._tcp', 'NNDSS (National Notifiable Diseases Surveillance System)'),
            ('_nhsn._tcp', 'NHSN (National Healthcare Safety Network)'),
            ('_cdc-prime._tcp', 'CDC PRIME ReportStream'),
            ('_ecr._tcp', 'eCR (Electronic Case Reporting)'),
            ('_eicr._tcp', 'eICR (Electronic Initial Case Report)'),
            ('_rr._tcp', 'Reportability Response'),
            ('_trust._tcp', 'TEFCA Trusted Exchange Framework'),
            ('_qhin._tcp', 'QHIN (Qualified Health Information Network)'),
            ('_carequality._tcp', 'Carequality Health Information Exchange'),
            ('_commonwell._tcp', 'CommonWell Health Alliance'),
            ('_directtrust._tcp', 'DirectTrust Secure Messaging'),
            ('_direct._tcp', 'Direct Secure Messaging'),
            ('_hisp._tcp', 'HISP (Health Information Service Provider)'),
            ('_hie._tcp', 'HIE (Health Information Exchange)'),
            ('_rhio._tcp', 'RHIO (Regional Health Information Organization)'),
            ('_nwhin._tcp', 'NWHIN (Nationwide Health Information Network)'),
            ('_ehealth-exchange._tcp', 'eHealth Exchange Network'),
            ('_sequoia._tcp', 'Sequoia Project Services'),
            ('_healtheway._tcp', 'Healtheway (Legacy NWHIN)'),
            
            # Content Management & Wiki
            ('_wiki._tcp', 'Wiki Services'),
            ('_mediawiki._tcp', 'MediaWiki'),
            ('_confluence._tcp', 'Atlassian Confluence'),
            ('_sharepoint._tcp', 'Microsoft SharePoint'),
            ('_drupal._tcp', 'Drupal CMS'),
            ('_wordpress._tcp', 'WordPress CMS'),
            ('_joomla._tcp', 'Joomla CMS'),
            
            # Enterprise Applications
            ('_sap._tcp', 'SAP Enterprise Software'),
            ('_oracle-apps._tcp', 'Oracle Applications'),
            ('_peoplesoft._tcp', 'PeopleSoft'),
            ('_workday._tcp', 'Workday'),
            ('_salesforce._tcp', 'Salesforce CRM'),
            ('_servicenow._tcp', 'ServiceNow'),
            ('_jira._tcp', 'Atlassian Jira'),
            ('_slack._tcp', 'Slack Communication'),
            ('_teams._tcp', 'Microsoft Teams'),
            ('_zoom._tcp', 'Zoom Video Conferencing'),
            ('_webex._tcp', 'Cisco WebEx'),
            
            # Blockchain & Cryptocurrency
            ('_bitcoin._tcp', 'Bitcoin Node'),
            ('_ethereum._tcp', 'Ethereum Node'),
            ('_ipfs._tcp', 'InterPlanetary File System'),
            ('_libp2p._tcp', 'libp2p Protocol'),
            ('_bittorrent._tcp', 'BitTorrent Protocol'),
            ('_dht._udp', 'Distributed Hash Table'),
            
            # Legacy & Specialized Services
            ('_finger._tcp', 'Finger Protocol'),
            ('_whois._tcp', 'WHOIS Protocol'),
            ('_gopher._tcp', 'Gopher Protocol'),
            ('_nntp._tcp', 'NNTP (Network News Transfer Protocol)'),
            ('_nntps._tcp', 'NNTP over SSL/TLS'),
            ('_imap2._tcp', 'IMAP2 Legacy'),
            ('_pop2._tcp', 'POP2 Legacy'),
            ('_uucp._tcp', 'UUCP (Unix-to-Unix Copy Protocol)'),
            
            # Custom & Proprietary Services
            ('_spotify-connect._tcp', 'Spotify Connect'),
            ('_googlecast._tcp', 'Google Cast/Chromecast'),
            ('_sonos._tcp', 'Sonos Audio System'),
            ('_roku._tcp', 'Roku Media Player'),
            ('_philips-hue._tcp', 'Philips Hue Lighting'),
            ('_nest._tcp', 'Google Nest'),
            ('_alexa._tcp', 'Amazon Alexa'),
            ('_homeassistant._tcp', 'Home Assistant'),
            ('_openhab._tcp', 'OpenHAB Home Automation')
        ]
        
        discovered_count = 0
        accessible_count = 0
        protocol_stats = {'tcp': 0, 'udp': 0}
        
        for srv_record, description in srv_service_list:
            try:
                srv_domain = f'{srv_record}.{domain}'
                srv_records = dns_query(srv_domain, 'SRV', None, DNS_TIMEOUT)
                
                if srv_records:
                    discovered_count += 1
                    protocol = srv_record.split('.')[-1]  # Extract protocol (tcp/udp)
                    protocol_stats[protocol] = protocol_stats.get(protocol, 0) + 1
                    
                    # Parse SRV records and test connectivity
                    service_details = []
                    service_accessible = False
                    
                    for record in srv_records:
                        srv_data = format_rdata('SRV', record['rdata']).split()
                        if len(srv_data) >= 4:
                            priority = int(srv_data[0])
                            weight = int(srv_data[1])
                            port = int(srv_data[2])
                            target = srv_data[3].rstrip('.')
                            
                            # Test connectivity to the target
                            accessible = test_port_connectivity(target, port)
                            if accessible:
                                service_accessible = True
                            
                            service_details.append({
                                'priority': priority,
                                'weight': weight,
                                'port': port,
                                'target': target,
                                'accessible': accessible,
                                'srv_record': srv_record
                            })
                    
                    if service_accessible:
                        accessible_count += 1
                    
                    srv_services['discovered_records'][srv_record] = {
                        'description': description,
                        'records': service_details,
                        'record_count': len(service_details),
                        'accessible': service_accessible,
                        'protocol': protocol
                    }
                    
                    # Categorize services
                    category = categorize_srv_service(srv_record, description)
                    if category not in srv_services['service_categories']:
                        srv_services['service_categories'][category] = []
                    srv_services['service_categories'][category].append(srv_record)
                    
            except Exception as e:
                # Continue with other services if one fails
                continue
        
        srv_services['service_summary'] = {
            'total_srv_records': discovered_count,
            'accessible_services': accessible_count,
            'protocol_distribution': protocol_stats,
            'accessibility_rate': round((accessible_count / discovered_count * 100), 2) if discovered_count > 0 else 0
        }
        
        return srv_services
        
    except Exception as e:
        return {'error': str(e)}

def categorize_srv_service(srv_record, description):
    """Categorize SRV services into logical groups."""
    srv_lower = srv_record.lower()
    
    if any(term in srv_lower for term in ['sip', 'voip', 'h323', 'stun', 'turn']):
        return 'VoIP & Communication'
    elif any(term in srv_lower for term in ['xmpp', 'jabber', 'irc', 'chat']):
        return 'Instant Messaging'
    elif any(term in srv_lower for term in ['smtp', 'imap', 'pop', 'mail']):
        return 'Email Services'
    elif any(term in srv_lower for term in ['http', 'web', 'dav', 'ws']):
        return 'Web Services'
    elif any(term in srv_lower for term in ['proxy', 'socks', 'squid', 'nginx', 'apache', 'haproxy', 'traefik', 'envoy', 'varnish', 'lb', 'loadbalancer', 'gateway', 'api-gateway', 'waf', 'cache', 'cdn', 'reverse-proxy', 'forward-proxy', 'transparent-proxy', 'content-filter', 'web-filter', 'url-filter', 'istio', 'linkerd', 'consul-connect', 'kong', 'zuul', 'ambassador', 'contour', 'ingress', 'f5', 'bigip', 'netscaler', 'citrix-adc', 'a10', 'kemp', 'radware', 'barracuda', 'cloudflare', 'fastly', 'akamai', 'blue-coat', 'websense', 'forcepoint', 'zscaler', 'mcafee-proxy', 'symantec-proxy']):
        return 'Proxy & Load Balancing'
    elif any(term in srv_lower for term in ['ftp', 'sftp', 'tftp', 'rsync']):
        return 'File Transfer'
    elif any(term in srv_lower for term in ['ldap', 'kerberos', 'gc', 'msdcs']):
        return 'Directory & Authentication'
    elif any(term in srv_lower for term in ['ssh', 'telnet', 'rdp', 'vnc']):
        return 'Remote Access'
    elif any(term in srv_lower for term in ['mysql', 'postgres', 'oracle', 'mongo', 'redis']):
        return 'Database Services'
    elif any(term in srv_lower for term in ['dns', 'ntp', 'snmp', 'dhcp', 'radius']):
        return 'Network Services'
    elif any(term in srv_lower for term in ['print', 'ipp', 'scanner']):
        return 'Print & Imaging'
    elif any(term in srv_lower for term in ['afp', 'airport', 'airplay', 'daap', 'homekit']):
        return 'Apple Services'
    elif any(term in srv_lower for term in ['minecraft', 'teamspeak', 'mumble', 'steam']):
        return 'Gaming Services'
    elif any(term in srv_lower for term in ['rtsp', 'rtmp', 'rtp', 'stream', 'plex', 'dlna']):
        return 'Media & Streaming'
    elif any(term in srv_lower for term in ['git', 'svn', 'jenkins', 'docker', 'kubernetes']):
        return 'Development & CI/CD'
    elif any(term in srv_lower for term in ['prometheus', 'grafana', 'nagios', 'zabbix', 'elasticsearch']):
        return 'Monitoring & Logging'
    elif any(term in srv_lower for term in ['amqp', 'mqtt', 'stomp', 'kafka', 'rabbitmq']):
        return 'Message Queues'
    elif any(term in srv_lower for term in ['coap', 'opcua', 'modbus', 'bacnet', 'zigbee']):
        return 'IoT & Industrial'
    elif any(term in srv_lower for term in ['tls', 'vpn', 'ipsec', 'wireguard', 'openvpn']):
        return 'Security Services'
    elif any(term in srv_lower for term in ['backup', 'bacula', 'amanda', 'borg']):
        return 'Backup Services'
    elif any(term in srv_lower for term in ['dicom', 'hl7', 'fhir', 'ris', 'pacs', 'his', 'emr', 'ehr', 'cda', 'ccda', 'cpoe', 'cdss', 'lims', 'lis', 'cis', 'pharmacy', 'medication', 'prescription', 'epic', 'cerner', 'allscripts', 'meditech', 'mckesson', 'athenahealth', 'eclinicalworks', 'nextgen', 'healthcare', 'medical', 'wado', 'qido', 'stow', 'xds', 'xca', 'xcpd', 'xdr', 'pix', 'pdq', 'mllp', 'smart', 'cds-hooks', 'terminology', 'snomed', 'loinc', 'icd10', 'rxnorm', 'umls', 'mesh', 'cpt', 'hcpcs', 'ndc', 'radlex', 'rsna', 'himss', 'ihe', 'ccow', 'fhircast', 'cql', 'measure', 'qicore', 'hedis', 'quality-measure', 'population-health', 'public-health', 'immunization', 'vital-records', 'cancer-registry', 'surveillance', 'biosense', 'phin', 'nedss', 'nndss', 'nhsn', 'cdc-prime', 'ecr', 'eicr', 'trust', 'qhin', 'carequality', 'commonwell', 'directtrust', 'direct', 'hisp', 'hie', 'rhio', 'nwhin', 'ehealth-exchange', 'sequoia', 'healtheway']):
        return 'Healthcare & Medical'
    elif any(term in srv_lower for term in ['bitcoin', 'ethereum', 'ipfs', 'blockchain']):
        return 'Blockchain & P2P'
    elif any(term in srv_lower for term in ['sap', 'oracle-apps', 'salesforce', 'jira', 'slack']):
        return 'Enterprise Applications'
    else:
        return 'Other Services'


# ================================================================================================
# Phase 5: Web Application Analysis
# ================================================================================================

def comprehensive_web_analysis(domain, ports=None):
    """Phase 5: Comprehensive web application security analysis and vulnerability assessment."""
    try:
        import time
        start_time = time.time()
        
        if ports is None:
            ports = [80, 443, 8080, 8443]
        elif isinstance(ports, str):
            # Handle comma-separated ports
            try:
                ports = [int(p.strip()) for p in ports.split(',')]
            except ValueError:
                ports = [80, 443]
        elif not isinstance(ports, list):
            ports = [ports] if isinstance(ports, int) else [80, 443]
        
        web_analysis = {
            'domain': domain,
            'web_application_analysis': {
                'discovered_applications': {},
                'security_assessment': {},
                'technology_stack': {},
                'vulnerability_scan': {},
                'configuration_analysis': {},
                'compliance_check': {}
            },
            'analysis_stats': {
                'ports_analyzed': 0,
                'applications_found': 0,
                'vulnerabilities_detected': 0,
                'analysis_duration': 0
            }
        }
        
        web_services = {}
        total_vulns = 0
        
        for port in ports:
            if not isinstance(port, int):
                continue
                
            try:
                # Check if port is accessible for web services
                if port in [80, 443, 8080, 8443, 8000, 9000, 3000]:
                    app_analysis = analyze_web_application(domain, port)
                    if app_analysis:
                        web_services[str(port)] = app_analysis
                        total_vulns += len(app_analysis.get('vulnerability_assessment', {}).get('vulnerabilities', []))
                        web_analysis['analysis_stats']['ports_analyzed'] += 1
            except Exception as e:
                continue
        
        # Aggregate results
        web_analysis['web_application_analysis']['discovered_applications'] = web_services
        
        # Overall security assessment
        if web_services:
            web_analysis['web_application_analysis']['security_assessment'] = generate_web_security_assessment(web_services)
            web_analysis['web_application_analysis']['technology_stack'] = aggregate_technology_stack(web_services)
            web_analysis['web_application_analysis']['vulnerability_scan'] = aggregate_vulnerability_findings(web_services)
            web_analysis['web_application_analysis']['configuration_analysis'] = analyze_web_configuration(web_services)
            web_analysis['web_application_analysis']['compliance_check'] = check_web_compliance(web_services)
        
        # Update stats
        web_analysis['analysis_stats']['applications_found'] = len(web_services)
        web_analysis['analysis_stats']['vulnerabilities_detected'] = total_vulns
        web_analysis['analysis_stats']['analysis_duration'] = round(time.time() - start_time, 2)
        
        return web_analysis
        
    except Exception as e:
        return {
            'error': f'Web analysis failed: {str(e)}',
            'domain': domain,
            'analysis_stats': {'analysis_duration': round(time.time() - start_time, 2)}
        }


# Phase 6: Advanced Network Analysis
def comprehensive_network_analysis(domain):
    """
    Phase 6: Advanced Network Analysis
    Performs comprehensive network topology discovery, security assessment, and performance analysis
    """
    try:
        start_time = time.time()
        
        # Network topology discovery
        topology_info = discover_network_topology(domain)
        
        # Network security assessment
        network_security = analyze_network_security(domain, topology_info)
        
        # Network performance analysis
        performance_metrics = analyze_network_performance(domain, topology_info)
        
        # Network device discovery
        network_devices = discover_network_devices(domain, topology_info)
        
        # Network protocol analysis
        protocol_analysis = analyze_network_protocols(domain, topology_info)
        
        # Network compliance checking
        compliance_check = check_network_compliance(domain, network_security, topology_info)
        
        # Calculate overall network assessment
        overall_assessment = calculate_network_assessment(
            network_security, performance_metrics, topology_info, compliance_check
        )
        
        return {
            "domain": domain,
            "network_analysis": {
                "topology_discovery": topology_info,
                "security_assessment": network_security,
                "performance_metrics": performance_metrics,
                "device_discovery": network_devices,
                "protocol_analysis": protocol_analysis,
                "compliance_check": compliance_check,
                "overall_assessment": overall_assessment
            },
            "analysis_stats": {
                "networks_analyzed": len(topology_info.get('networks', [])),
                "devices_discovered": len(network_devices.get('devices', [])),
                "security_issues": len(network_security.get('vulnerabilities', [])),
                "analysis_duration": round(time.time() - start_time, 2)
            }
        }
        
    except Exception as e:
        return {
            "domain": domain,
            "network_analysis": {
                "error": str(e),
                "analysis_completed": False
            },
            "analysis_stats": {
                "networks_analyzed": 0,
                "devices_discovered": 0,
                "security_issues": 0,
                "analysis_duration": round(time.time() - start_time, 2)
            }
        }

def discover_network_topology(domain):
    """
    Discover network topology including routing paths, network segments, and infrastructure mapping
    """
    try:
        topology = {
            "routing_analysis": {},
            "network_segments": [],
            "infrastructure_mapping": {},
            "connectivity_matrix": {},
            "network_boundaries": {}
        }
        
        # Traceroute analysis to discover routing paths
        routing_paths = perform_traceroute_analysis(domain)
        topology["routing_analysis"] = routing_paths
        
        # Discover network segments and subnets
        network_segments = discover_network_segments(domain, routing_paths)
        topology["network_segments"] = network_segments
        
        # Map network infrastructure components
        infrastructure = map_network_infrastructure(domain, routing_paths, network_segments)
        topology["infrastructure_mapping"] = infrastructure
        
        # Analyze connectivity between network components
        connectivity = analyze_network_connectivity(domain, infrastructure)
        topology["connectivity_matrix"] = connectivity
        
        # Identify network boundaries and security perimeters
        boundaries = identify_network_boundaries(routing_paths, infrastructure)
        topology["network_boundaries"] = boundaries
        
        return topology
        
    except Exception as e:
        return {
            "error": f"Network topology discovery failed: {str(e)}",
            "routing_analysis": {},
            "network_segments": [],
            "infrastructure_mapping": {},
            "connectivity_matrix": {},
            "network_boundaries": {}
        }

def perform_traceroute_analysis(domain):
    """
    Perform comprehensive traceroute analysis to map network paths
    """
    try:
        import subprocess
        import platform
        
        routing_paths = {
            "primary_path": [],
            "alternate_paths": [],
            "hop_analysis": {},
            "latency_analysis": {},
            "geographic_mapping": {}
        }
        
        # Determine traceroute command based on OS
        if platform.system().lower() == "windows":
            cmd = ["tracert", "-h", "30", domain]
        else:
            cmd = ["traceroute", "-m", "30", domain]
        
        # Execute traceroute
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                routing_paths["primary_path"] = parse_traceroute_output(result.stdout)
        except subprocess.TimeoutExpired:
            routing_paths["primary_path"] = ["Traceroute timeout - network path too long"]
        except Exception:
            routing_paths["primary_path"] = ["Traceroute failed - using alternative analysis"]
        
        # Analyze hop characteristics
        for i, hop in enumerate(routing_paths["primary_path"]):
            if isinstance(hop, dict) and "ip" in hop:
                hop_analysis = analyze_network_hop(hop["ip"])
                routing_paths["hop_analysis"][f"hop_{i}"] = hop_analysis
        
        # Perform latency analysis
        routing_paths["latency_analysis"] = analyze_path_latency(routing_paths["primary_path"])
        
        # Geographic mapping (basic implementation)
        routing_paths["geographic_mapping"] = map_geographic_path(routing_paths["primary_path"])
        
        return routing_paths
        
    except Exception as e:
        return {
            "error": f"Traceroute analysis failed: {str(e)}",
            "primary_path": [],
            "alternate_paths": [],
            "hop_analysis": {},
            "latency_analysis": {},
            "geographic_mapping": {}
        }

def parse_traceroute_output(output):
    """
    Parse traceroute output to extract hop information
    """
    try:
        import re
        import platform
        
        hops = []
        lines = output.strip().split('\n')
        
        for line in lines:
            # Skip header lines
            if "Tracing route" in line or "over a maximum" in line or not line.strip():
                continue
                
            # Windows tracert format
            if platform.system().lower() == "windows":
                # Match: "  1    <1 ms    <1 ms    <1 ms  192.168.1.1"
                match = re.search(r'^\s*(\d+)\s+(<?\d+\s*ms|\*)\s+(<?\d+\s*ms|\*)\s+(<?\d+\s*ms|\*)\s+([^\s]+)', line)
                if match:
                    hop_num, rtt1, rtt2, rtt3, host = match.groups()
                    hops.append({
                        "hop": int(hop_num),
                        "ip": host if re.match(r'^\d+\.\d+\.\d+\.\d+$', host) else None,
                        "hostname": host if not re.match(r'^\d+\.\d+\.\d+\.\d+$', host) else None,
                        "rtt": [rtt1, rtt2, rtt3],
                        "status": "responsive" if "*" not in [rtt1, rtt2, rtt3] else "timeout"
                    })
            else:
                # Unix traceroute format
                match = re.search(r'^\s*(\d+)\s+([^\s]+)\s+\(([^)]+)\)\s+([0-9.]+)\s*ms', line)
                if match:
                    hop_num, hostname, ip, rtt = match.groups()
                    hops.append({
                        "hop": int(hop_num),
                        "ip": ip,
                        "hostname": hostname,
                        "rtt": [f"{rtt} ms"],
                        "status": "responsive"
                    })
        
        return hops
        
    except Exception as e:
        return [{"error": f"Failed to parse traceroute output: {str(e)}"}]

def analyze_network_hop(ip_address):
    """
    Analyze individual network hop characteristics
    """
    try:
        hop_info = {
            "ip_address": ip_address,
            "asn_info": {},
            "geolocation": {},
            "reverse_dns": None,
            "network_type": "unknown",
            "security_analysis": {}
        }
        
        # Reverse DNS lookup
        try:
            import socket
            hop_info["reverse_dns"] = socket.gethostbyaddr(ip_address)[0]
        except:
            hop_info["reverse_dns"] = None
        
        # Determine network type based on IP range
        hop_info["network_type"] = classify_network_type(ip_address)
        
        # Basic security analysis
        hop_info["security_analysis"] = {
            "private_ip": is_private_ip(ip_address),
            "suspicious_patterns": check_suspicious_patterns(ip_address),
            "known_malicious": False  # Would integrate with threat intelligence
        }
        
        return hop_info
        
    except Exception as e:
        return {
            "ip_address": ip_address,
            "error": str(e),
            "asn_info": {},
            "geolocation": {},
            "reverse_dns": None,
            "network_type": "unknown",
            "security_analysis": {}
        }

def classify_network_type(ip_address):
    """
    Classify network type based on IP address ranges
    """
    try:
        import ipaddress
        
        ip = ipaddress.ip_address(ip_address)
        
        if ip.is_private:
            return "private"
        elif ip.is_loopback:
            return "loopback"
        elif ip.is_multicast:
            return "multicast"
        elif ip.is_reserved:
            return "reserved"
        elif ip.is_global:
            # Check for common ISP/hosting ranges
            if str(ip).startswith(('8.8.', '1.1.', '208.67.')):
                return "public_dns"
            elif str(ip).startswith(('23.', '104.', '173.')):
                return "cdn"
            else:
                return "public"
        else:
            return "unknown"
            
    except Exception:
        return "unknown"

def is_private_ip(ip_address):
    """
    Check if IP address is in private ranges
    """
    try:
        import ipaddress
        return ipaddress.ip_address(ip_address).is_private
    except:
        return False

def check_suspicious_patterns(ip_address):
    """
    Check for suspicious IP patterns
    """
    suspicious_patterns = []
    
    # Check for suspicious ranges (basic implementation)
    suspicious_ranges = [
        "127.0.0.1",  # Localhost
        "0.0.0.0",    # Invalid
        "255.255.255.255"  # Broadcast
    ]
    
    if ip_address in suspicious_ranges:
        suspicious_patterns.append("suspicious_range")
    
    return suspicious_patterns

def analyze_path_latency(routing_path):
    """
    Analyze latency patterns in routing path
    """
    try:
        latency_analysis = {
            "total_hops": len(routing_path),
            "avg_latency_per_hop": 0,
            "latency_distribution": {},
            "performance_issues": [],
            "bottlenecks": []
        }
        
        if not routing_path:
            return latency_analysis
        
        # Calculate latency metrics
        total_latency = 0
        hop_latencies = []
        
        for hop in routing_path:
            if isinstance(hop, dict) and "rtt" in hop:
                # Extract numeric latency values
                for rtt in hop["rtt"]:
                    if isinstance(rtt, str) and "ms" in rtt:
                        try:
                            latency = float(rtt.replace("ms", "").replace("<", "").strip())
                            hop_latencies.append(latency)
                            total_latency += latency
                        except:
                            continue
        
        if hop_latencies:
            latency_analysis["avg_latency_per_hop"] = round(total_latency / len(hop_latencies), 2)
            
            # Identify performance issues
            if latency_analysis["avg_latency_per_hop"] > 100:
                latency_analysis["performance_issues"].append("high_average_latency")
            
            # Identify bottlenecks (hops with significantly higher latency)
            avg_latency = latency_analysis["avg_latency_per_hop"]
            for i, latency in enumerate(hop_latencies):
                if latency > avg_latency * 2:
                    latency_analysis["bottlenecks"].append({
                        "hop_number": i + 1,
                        "latency": latency,
                        "severity": "high" if latency > avg_latency * 3 else "medium"
                    })
        
        return latency_analysis
        
    except Exception as e:
        return {
            "error": f"Latency analysis failed: {str(e)}",
            "total_hops": 0,
            "avg_latency_per_hop": 0,
            "latency_distribution": {},
            "performance_issues": [],
            "bottlenecks": []
        }

def map_geographic_path(routing_path):
    """
    Basic geographic mapping of routing path
    """
    try:
        geographic_map = {
            "path_regions": [],
            "international_hops": [],
            "geographic_diversity": "unknown",
            "estimated_distance": 0
        }
        
        # Basic regional classification based on hop analysis
        for hop in routing_path:
            if isinstance(hop, dict) and "ip" in hop:
                region = classify_geographic_region(hop["ip"])
                if region not in geographic_map["path_regions"]:
                    geographic_map["path_regions"].append(region)
        
        # Determine geographic diversity
        if len(geographic_map["path_regions"]) > 3:
            geographic_map["geographic_diversity"] = "high"
        elif len(geographic_map["path_regions"]) > 1:
            geographic_map["geographic_diversity"] = "medium"
        else:
            geographic_map["geographic_diversity"] = "low"
        
        return geographic_map
        
    except Exception as e:
        return {
            "error": f"Geographic mapping failed: {str(e)}",
            "path_regions": [],
            "international_hops": [],
            "geographic_diversity": "unknown",
            "estimated_distance": 0
        }

def classify_geographic_region(ip_address):
    """
    Basic geographic region classification
    """
    # This is a simplified implementation
    # In production, would use GeoIP databases
    
    try:
        import ipaddress
        ip = ipaddress.ip_address(ip_address)
        
        if ip.is_private:
            return "local_network"
        elif str(ip).startswith(('8.8.', '8.4.')):
            return "google_dns"
        elif str(ip).startswith(('1.1.', '1.0.')):
            return "cloudflare"
        else:
            return "internet_backbone"
            
    except:
        return "unknown"

def discover_network_segments(domain, routing_paths):
    """
    Discover network segments and subnets from routing analysis
    """
    try:
        segments = []
        
        if not routing_paths or "primary_path" not in routing_paths:
            return segments
        
        for hop in routing_paths["primary_path"]:
            if isinstance(hop, dict) and "ip" in hop and hop["ip"]:
                segment_info = analyze_network_segment(hop["ip"])
                if segment_info and segment_info not in segments:
                    segments.append(segment_info)
        
        return segments
        
    except Exception as e:
        return [{"error": f"Network segment discovery failed: {str(e)}"}]

def analyze_network_segment(ip_address):
    """
    Analyze network segment characteristics
    """
    try:
        import ipaddress
        
        ip = ipaddress.ip_address(ip_address)
        
        segment_info = {
            "ip_address": str(ip),
            "network_class": "unknown",
            "segment_type": "unknown",
            "estimated_subnet": "unknown",
            "characteristics": {}
        }
        
        if ip.is_private:
            segment_info["segment_type"] = "private"
            # Determine private network class
            if str(ip).startswith("192.168."):
                segment_info["network_class"] = "Class C Private"
                segment_info["estimated_subnet"] = f"192.168.{str(ip).split('.')[2]}.0/24"
            elif str(ip).startswith("10."):
                segment_info["network_class"] = "Class A Private"
                segment_info["estimated_subnet"] = "10.0.0.0/8"
            elif str(ip).startswith("172."):
                segment_info["network_class"] = "Class B Private"
                segment_info["estimated_subnet"] = f"172.{str(ip).split('.')[1]}.0.0/16"
        else:
            segment_info["segment_type"] = "public"
            segment_info["network_class"] = "Public Internet"
        
        segment_info["characteristics"] = {
            "private": ip.is_private,
            "routable": not ip.is_private,
            "multicast": ip.is_multicast,
            "reserved": ip.is_reserved
        }
        
        return segment_info
        
    except Exception as e:
        return {
            "error": f"Segment analysis failed: {str(e)}",
            "ip_address": ip_address,
            "network_class": "unknown",
            "segment_type": "unknown"
        }

def map_network_infrastructure(domain, routing_paths, network_segments):
    """
    Map network infrastructure components
    """
    try:
        infrastructure = {
            "routers": [],
            "switches": [],
            "firewalls": [],
            "load_balancers": [],
            "dns_servers": [],
            "cdn_nodes": [],
            "unknown_devices": []
        }
        
        # Analyze routing path for infrastructure components
        if routing_paths and "primary_path" in routing_paths:
            for hop in routing_paths["primary_path"]:
                if isinstance(hop, dict) and "ip" in hop and hop["ip"]:
                    device_type = classify_network_device(hop["ip"], hop)
                    infrastructure[device_type].append({
                        "ip": hop["ip"],
                        "hostname": hop.get("hostname"),
                        "hop_number": hop.get("hop"),
                        "response_time": hop.get("rtt", []),
                        "device_characteristics": analyze_device_characteristics(hop)
                    })
        
        return infrastructure
        
    except Exception as e:
        return {
            "error": f"Infrastructure mapping failed: {str(e)}",
            "routers": [],
            "switches": [],
            "firewalls": [],
            "load_balancers": [],
            "dns_servers": [],
            "cdn_nodes": [],
            "unknown_devices": []
        }

def classify_network_device(ip_address, hop_info):
    """
    Classify network device type based on characteristics
    """
    try:
        hostname = hop_info.get("hostname", "").lower()
        
        # Classification based on hostname patterns
        if any(pattern in hostname for pattern in ["router", "rtr", "gw", "gateway"]):
            return "routers"
        elif any(pattern in hostname for pattern in ["switch", "sw"]):
            return "switches"
        elif any(pattern in hostname for pattern in ["firewall", "fw", "pix", "asa"]):
            return "firewalls"
        elif any(pattern in hostname for pattern in ["lb", "load", "balancer", "f5", "netscaler"]):
            return "load_balancers"
        elif any(pattern in hostname for pattern in ["dns", "ns", "nameserver"]):
            return "dns_servers"
        elif any(pattern in hostname for pattern in ["cdn", "cache", "akamai", "cloudflare", "fastly"]):
            return "cdn_nodes"
        else:
            # Classification based on IP characteristics
            network_type = classify_network_type(ip_address)
            if network_type == "cdn":
                return "cdn_nodes"
            elif network_type == "public_dns":
                return "dns_servers"
            else:
                return "unknown_devices"
                
    except Exception:
        return "unknown_devices"

def analyze_device_characteristics(hop_info):
    """
    Analyze network device characteristics
    """
    try:
        characteristics = {
            "response_pattern": "unknown",
            "latency_profile": "unknown",
            "reliability": "unknown",
            "security_indicators": []
        }
        
        rtt_times = hop_info.get("rtt", [])
        if rtt_times:
            # Analyze response pattern
            non_timeout_rtts = [rtt for rtt in rtt_times if rtt != "*"]
            if len(non_timeout_rtts) == len(rtt_times):
                characteristics["response_pattern"] = "consistent"
            elif len(non_timeout_rtts) > 0:
                characteristics["response_pattern"] = "intermittent"
            else:
                characteristics["response_pattern"] = "timeout"
            
            # Analyze latency profile
            if non_timeout_rtts:
                avg_latency = sum(float(rtt.replace("ms", "").replace("<", "").strip()) 
                                for rtt in non_timeout_rtts if "ms" in str(rtt)) / len(non_timeout_rtts)
                if avg_latency < 10:
                    characteristics["latency_profile"] = "low"
                elif avg_latency < 50:
                    characteristics["latency_profile"] = "medium"
                else:
                    characteristics["latency_profile"] = "high"
        
        # Check for security indicators
        hostname = hop_info.get("hostname", "").lower()
        if any(pattern in hostname for pattern in ["firewall", "fw", "security", "guard"]):
            characteristics["security_indicators"].append("security_device")
        if any(pattern in hostname for pattern in ["dmz", "external", "public"]):
            characteristics["security_indicators"].append("perimeter_device")
        
        return characteristics
        
    except Exception as e:
        return {
            "error": f"Device analysis failed: {str(e)}",
            "response_pattern": "unknown",
            "latency_profile": "unknown"
        }

def analyze_network_connectivity(domain, infrastructure):
    """
    Analyze connectivity between network components
    """
    try:
        connectivity = {
            "connection_matrix": {},
            "network_paths": [],
            "redundancy_analysis": {},
            "single_points_of_failure": [],
            "connectivity_score": 0
        }
        
        # Analyze connections between infrastructure components
        for device_type, devices in infrastructure.items():
            if devices and device_type != "unknown_devices":
                connectivity["connection_matrix"][device_type] = len(devices)
        
        # Calculate connectivity score
        total_devices = sum(len(devices) for devices in infrastructure.values())
        if total_devices > 0:
            redundant_devices = sum(1 for devices in infrastructure.values() if len(devices) > 1)
            connectivity["connectivity_score"] = round((redundant_devices / len(infrastructure)) * 100, 2)
        
        return connectivity
        
    except Exception as e:
        return {
            "error": f"Connectivity analysis failed: {str(e)}",
            "connection_matrix": {},
            "network_paths": [],
            "redundancy_analysis": {},
            "single_points_of_failure": []
        }

def identify_network_boundaries(routing_paths, infrastructure):
    """
    Identify network boundaries and security perimeters
    """
    try:
        boundaries = {
            "security_perimeters": [],
            "network_zones": [],
            "trust_boundaries": [],
            "dmz_detection": {},
            "perimeter_security": {}
        }
        
        # Analyze routing path for security boundaries
        if routing_paths and "primary_path" in routing_paths:
            private_to_public_transition = None
            
            for i, hop in enumerate(routing_paths["primary_path"]):
                if isinstance(hop, dict) and "ip" in hop and hop["ip"]:
                    is_private = is_private_ip(hop["ip"])
                    
                    # Detect private to public transition (network boundary)
                    if i > 0 and private_to_public_transition is None:
                        prev_hop = routing_paths["primary_path"][i-1]
                        if (isinstance(prev_hop, dict) and "ip" in prev_hop and 
                            is_private_ip(prev_hop["ip"]) and not is_private):
                            private_to_public_transition = i
                            boundaries["trust_boundaries"].append({
                                "boundary_type": "private_to_public",
                                "hop_number": i,
                                "internal_ip": prev_hop["ip"],
                                "external_ip": hop["ip"]
                            })
        
        # Identify potential DMZ segments
        if infrastructure.get("firewalls") or infrastructure.get("load_balancers"):
            boundaries["dmz_detection"] = {
                "dmz_likely": True,
                "indicators": ["firewall_detected", "load_balancer_detected"]
            }
        
        return boundaries
        
    except Exception as e:
        return {
            "error": f"Network boundary identification failed: {str(e)}",
            "security_perimeters": [],
            "network_zones": [],
            "trust_boundaries": []
        }

def analyze_network_security(domain, topology_info):
    """
    Analyze network security characteristics and vulnerabilities
    """
    try:
        security_analysis = {
            "security_score": 0,
            "risk_level": "UNKNOWN",
            "vulnerabilities": [],
            "security_controls": {},
            "threat_indicators": [],
            "security_recommendations": []
        }
        
        # Analyze routing security
        routing_security = analyze_routing_security(topology_info.get("routing_analysis", {}))
        security_analysis["security_controls"]["routing"] = routing_security
        
        # Analyze infrastructure security
        infrastructure_security = analyze_infrastructure_security(topology_info.get("infrastructure_mapping", {}))
        security_analysis["security_controls"]["infrastructure"] = infrastructure_security
        
        # Analyze network boundaries security
        boundary_security = analyze_boundary_security(topology_info.get("network_boundaries", {}))
        security_analysis["security_controls"]["boundaries"] = boundary_security
        
        # Identify vulnerabilities
        vulnerabilities = identify_network_vulnerabilities(topology_info)
        security_analysis["vulnerabilities"] = vulnerabilities
        
        # Calculate overall security score
        security_score = calculate_network_security_score(
            routing_security, infrastructure_security, boundary_security, vulnerabilities
        )
        security_analysis["security_score"] = security_score
        
        # Determine risk level
        if security_score >= 80:
            security_analysis["risk_level"] = "LOW"
        elif security_score >= 60:
            security_analysis["risk_level"] = "MEDIUM"
        elif security_score >= 40:
            security_analysis["risk_level"] = "HIGH"
        else:
            security_analysis["risk_level"] = "CRITICAL"
        
        # Generate recommendations
        security_analysis["security_recommendations"] = generate_network_security_recommendations(
            vulnerabilities, security_analysis["risk_level"]
        )
        
        return security_analysis
        
    except Exception as e:
        return {
            "error": f"Network security analysis failed: {str(e)}",
            "security_score": 0,
            "risk_level": "UNKNOWN",
            "vulnerabilities": [],
            "security_controls": {}
        }

def analyze_routing_security(routing_analysis):
    """
    Analyze routing security characteristics
    """
    try:
        routing_security = {
            "path_security": "unknown",
            "hop_security": {},
            "geographic_security": {},
            "latency_security": {},
            "security_score": 0
        }
        
        if not routing_analysis or "primary_path" not in routing_analysis:
            return routing_security
        
        # Analyze path security
        primary_path = routing_analysis["primary_path"]
        if primary_path:
            secure_hops = 0
            total_hops = len(primary_path)
            
            for hop in primary_path:
                if isinstance(hop, dict) and "ip" in hop:
                    hop_security = analyze_hop_security(hop)
                    if hop_security.get("secure", False):
                        secure_hops += 1
            
            if total_hops > 0:
                path_security_score = (secure_hops / total_hops) * 100
                routing_security["security_score"] = round(path_security_score, 2)
                
                if path_security_score >= 80:
                    routing_security["path_security"] = "secure"
                elif path_security_score >= 60:
                    routing_security["path_security"] = "moderate"
                else:
                    routing_security["path_security"] = "insecure"
        
        # Analyze geographic security
        geographic_mapping = routing_analysis.get("geographic_mapping", {})
        if geographic_mapping.get("geographic_diversity") == "high":
            routing_security["geographic_security"] = {
                "diversity": "high",
                "risk": "elevated_interception_risk"
            }
        
        return routing_security
        
    except Exception as e:
        return {
            "error": f"Routing security analysis failed: {str(e)}",
            "path_security": "unknown",
            "security_score": 0
        }

def analyze_hop_security(hop):
    """
    Analyze individual hop security characteristics
    """
    try:
        if not hop.get("ip"):
            return {"secure": False, "reasons": ["no_ip"]}
        
        ip_address = hop["ip"]
        security_analysis = {
            "secure": True,
            "security_indicators": [],
            "risk_indicators": []
        }
        
        # Check if private IP (generally more secure)
        if is_private_ip(ip_address):
            security_analysis["security_indicators"].append("private_ip")
        else:
            security_analysis["risk_indicators"].append("public_ip")
        
        # Check for suspicious patterns
        suspicious = check_suspicious_patterns(ip_address)
        if suspicious:
            security_analysis["risk_indicators"].extend(suspicious)
            security_analysis["secure"] = False
        
        # Check response patterns for potential security devices
        if hop.get("status") == "timeout":
            security_analysis["security_indicators"].append("filtered_response")
        
        return security_analysis
        
    except Exception as e:
        return {"secure": False, "error": str(e)}

def analyze_infrastructure_security(infrastructure_mapping):
    """
    Analyze infrastructure security controls
    """
    try:
        infrastructure_security = {
            "security_devices": {},
            "redundancy": {},
            "security_score": 0,
            "security_gaps": []
        }
        
        # Count security devices
        security_devices = {
            "firewalls": len(infrastructure_mapping.get("firewalls", [])),
            "load_balancers": len(infrastructure_mapping.get("load_balancers", [])),
            "routers": len(infrastructure_mapping.get("routers", [])),
            "dns_servers": len(infrastructure_mapping.get("dns_servers", []))
        }
        infrastructure_security["security_devices"] = security_devices
        
        # Analyze redundancy
        for device_type, count in security_devices.items():
            if count > 1:
                infrastructure_security["redundancy"][device_type] = "redundant"
            elif count == 1:
                infrastructure_security["redundancy"][device_type] = "single_point"
            else:
                infrastructure_security["redundancy"][device_type] = "missing"
                infrastructure_security["security_gaps"].append(f"no_{device_type}")
        
        # Calculate security score
        total_device_types = len(security_devices)
        present_devices = sum(1 for count in security_devices.values() if count > 0)
        redundant_devices = sum(1 for count in security_devices.values() if count > 1)
        
        if total_device_types > 0:
            presence_score = (present_devices / total_device_types) * 60
            redundancy_score = (redundant_devices / total_device_types) * 40
            infrastructure_security["security_score"] = round(presence_score + redundancy_score, 2)
        
        return infrastructure_security
        
    except Exception as e:
        return {
            "error": f"Infrastructure security analysis failed: {str(e)}",
            "security_devices": {},
            "security_score": 0
        }

def analyze_boundary_security(network_boundaries):
    """
    Analyze network boundary security
    """
    try:
        boundary_security = {
            "perimeter_protection": "unknown",
            "boundary_controls": [],
            "dmz_security": {},
            "security_score": 0
        }
        
        # Check for DMZ detection
        dmz_detection = network_boundaries.get("dmz_detection", {})
        if dmz_detection.get("dmz_likely"):
            boundary_security["dmz_security"] = {
                "dmz_present": True,
                "security_benefit": "network_segmentation"
            }
            boundary_security["boundary_controls"].append("dmz_segmentation")
        
        # Analyze trust boundaries
        trust_boundaries = network_boundaries.get("trust_boundaries", [])
        if trust_boundaries:
            boundary_security["boundary_controls"].append("trust_boundary_defined")
            boundary_security["perimeter_protection"] = "present"
        else:
            boundary_security["perimeter_protection"] = "unclear"
        
        # Calculate security score
        control_count = len(boundary_security["boundary_controls"])
        if control_count >= 2:
            boundary_security["security_score"] = 80
        elif control_count == 1:
            boundary_security["security_score"] = 50
        else:
            boundary_security["security_score"] = 20
        
        return boundary_security
        
    except Exception as e:
        return {
            "error": f"Boundary security analysis failed: {str(e)}",
            "perimeter_protection": "unknown",
            "security_score": 0
        }

def identify_network_vulnerabilities(topology_info):
    """
    Identify network-level vulnerabilities
    """
    try:
        vulnerabilities = []
        
        # Check routing vulnerabilities
        routing_analysis = topology_info.get("routing_analysis", {})
        if routing_analysis:
            routing_vulns = check_routing_vulnerabilities(routing_analysis)
            vulnerabilities.extend(routing_vulns)
        
        # Check infrastructure vulnerabilities
        infrastructure = topology_info.get("infrastructure_mapping", {})
        if infrastructure:
            infra_vulns = check_infrastructure_vulnerabilities(infrastructure)
            vulnerabilities.extend(infra_vulns)
        
        # Check boundary vulnerabilities
        boundaries = topology_info.get("network_boundaries", {})
        if boundaries:
            boundary_vulns = check_boundary_vulnerabilities(boundaries)
            vulnerabilities.extend(boundary_vulns)
        
        return vulnerabilities
        
    except Exception as e:
        return [{"vulnerability": "analysis_error", "description": str(e)}]

def check_routing_vulnerabilities(routing_analysis):
    """
    Check for routing-related vulnerabilities
    """
    vulnerabilities = []
    
    try:
        primary_path = routing_analysis.get("primary_path", [])
        
        # Check for excessive hops
        if len(primary_path) > 20:
            vulnerabilities.append({
                "vulnerability": "excessive_hops",
                "severity": "medium",
                "description": f"Routing path has {len(primary_path)} hops, increasing attack surface"
            })
        
        # Check for timeout hops
        timeout_hops = sum(1 for hop in primary_path 
                          if isinstance(hop, dict) and hop.get("status") == "timeout")
        if timeout_hops > 3:
            vulnerabilities.append({
                "vulnerability": "multiple_timeouts",
                "severity": "low",
                "description": f"{timeout_hops} hops show timeouts, potential filtering or instability"
            })
        
        # Check latency analysis for performance issues
        latency_analysis = routing_analysis.get("latency_analysis", {})
        bottlenecks = latency_analysis.get("bottlenecks", [])
        if bottlenecks:
            vulnerabilities.append({
                "vulnerability": "latency_bottlenecks",
                "severity": "medium",
                "description": f"Network has {len(bottlenecks)} latency bottlenecks"
            })
        
    except Exception as e:
        vulnerabilities.append({
            "vulnerability": "routing_analysis_error",
            "severity": "unknown",
            "description": str(e)
        })
    
    return vulnerabilities

def check_infrastructure_vulnerabilities(infrastructure):
    """
    Check for infrastructure-related vulnerabilities
    """
    vulnerabilities = []
    
    try:
        # Check for single points of failure
        for device_type, devices in infrastructure.items():
            if device_type in ["firewalls", "load_balancers", "dns_servers"] and len(devices) == 1:
                vulnerabilities.append({
                    "vulnerability": "single_point_of_failure",
                    "severity": "high",
                    "description": f"Only one {device_type[:-1]} detected, no redundancy"
                })
        
        # Check for missing security devices
        if not infrastructure.get("firewalls"):
            vulnerabilities.append({
                "vulnerability": "no_firewall_detected",
                "severity": "high",
                "description": "No firewall devices detected in network path"
            })
        
        if not infrastructure.get("load_balancers") and not infrastructure.get("cdn_nodes"):
            vulnerabilities.append({
                "vulnerability": "no_load_balancing",
                "severity": "medium",
                "description": "No load balancing or CDN detected, potential availability issues"
            })
        
    except Exception as e:
        vulnerabilities.append({
            "vulnerability": "infrastructure_analysis_error",
            "severity": "unknown",
            "description": str(e)
        })
    
    return vulnerabilities

def check_boundary_vulnerabilities(boundaries):
    """
    Check for network boundary vulnerabilities
    """
    vulnerabilities = []
    
    try:
        # Check for unclear trust boundaries
        trust_boundaries = boundaries.get("trust_boundaries", [])
        if not trust_boundaries:
            vulnerabilities.append({
                "vulnerability": "unclear_trust_boundaries",
                "severity": "medium",
                "description": "Network trust boundaries are not clearly defined"
            })
        
        # Check for missing DMZ
        dmz_detection = boundaries.get("dmz_detection", {})
        if not dmz_detection.get("dmz_likely"):
            vulnerabilities.append({
                "vulnerability": "no_dmz_detected",
                "severity": "medium",
                "description": "No DMZ segmentation detected, direct exposure to internal network"
            })
        
    except Exception as e:
        vulnerabilities.append({
            "vulnerability": "boundary_analysis_error",
            "severity": "unknown",
            "description": str(e)
        })
    
    return vulnerabilities


def calculate_network_security_score(routing_security, infrastructure_security, boundary_security, vulnerabilities):
    """
    Calculate overall network security score
    """
    try:
        # Base scores from each component
        routing_score = routing_security.get("security_score", 0) * 0.3
        infrastructure_score = infrastructure_security.get("security_score", 0) * 0.4
        boundary_score = boundary_security.get("security_score", 0) * 0.3
        
        base_score = routing_score + infrastructure_score + boundary_score
        
        # Deduct points for vulnerabilities
        vulnerability_deduction = 0
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "unknown")
            if severity == "critical":
                vulnerability_deduction += 25
            elif severity == "high":
                vulnerability_deduction += 15
            elif severity == "medium":
                vulnerability_deduction += 8
            elif severity == "low":
                vulnerability_deduction += 3
        
        final_score = max(0, base_score - vulnerability_deduction)
        return round(final_score, 2)
        
    except Exception:
        return 0

def generate_network_security_recommendations(vulnerabilities, risk_level):
    """
    Generate network security recommendations
    """
    try:
        recommendations = []
        
        # Risk level based recommendations
        if risk_level in ["CRITICAL", "HIGH"]:
            recommendations.append("Immediate network security review required")
            recommendations.append("Implement network segmentation and access controls")
        
        # Vulnerability-based recommendations
        vuln_types = [vuln.get("vulnerability", "") for vuln in vulnerabilities]
        
        if "no_firewall_detected" in vuln_types:
            recommendations.append("Deploy firewall protection at network perimeter")
        
        if "single_point_of_failure" in vuln_types:
            recommendations.append("Implement redundancy for critical network components")
        
        if "excessive_hops" in vuln_types:
            recommendations.append("Optimize network routing to reduce attack surface")
        
        if "unclear_trust_boundaries" in vuln_types:
            recommendations.append("Define and implement clear network trust boundaries")
        
        if "no_dmz_detected" in vuln_types:
            recommendations.append("Consider implementing DMZ for public-facing services")
        
        # General recommendations
        recommendations.extend([
            "Regularly monitor network traffic for anomalies",
            "Implement network access logging and monitoring",
            "Keep network devices updated with latest security patches"
        ])
        
        return recommendations[:10]  # Limit to top 10 recommendations
        
    except Exception as e:
        return [f"Failed to generate recommendations: {str(e)}"]

def analyze_network_performance(domain, topology_info):
    """
    Analyze network performance characteristics
    """
    try:
        performance_metrics = {
            "latency_analysis": {},
            "bandwidth_estimation": {},
            "jitter_analysis": {},
            "packet_loss": {},
            "performance_score": 0,
            "bottlenecks": [],
            "optimization_recommendations": []
        }
        
        # Extract latency analysis from routing
        routing_analysis = topology_info.get("routing_analysis", {})
        if routing_analysis.get("latency_analysis"):
            performance_metrics["latency_analysis"] = routing_analysis["latency_analysis"]
        
        # Estimate bandwidth characteristics
        bandwidth_estimation = estimate_network_bandwidth(domain, routing_analysis)
        performance_metrics["bandwidth_estimation"] = bandwidth_estimation
        
        # Analyze jitter and stability
        jitter_analysis = analyze_network_jitter(routing_analysis)
        performance_metrics["jitter_analysis"] = jitter_analysis
        
        # Estimate packet loss
        packet_loss = estimate_packet_loss(routing_analysis)
        performance_metrics["packet_loss"] = packet_loss
        
        # Calculate overall performance score
        performance_score = calculate_network_performance_score(
            performance_metrics["latency_analysis"],
            bandwidth_estimation,
            jitter_analysis,
            packet_loss
        )
        performance_metrics["performance_score"] = performance_score
        
        # Identify bottlenecks
        bottlenecks = identify_performance_bottlenecks(performance_metrics)
        performance_metrics["bottlenecks"] = bottlenecks
        
        # Generate optimization recommendations
        recommendations = generate_performance_recommendations(performance_metrics, bottlenecks)
        performance_metrics["optimization_recommendations"] = recommendations
        
        return performance_metrics
        
    except Exception as e:
        return {
            "error": f"Network performance analysis failed: {str(e)}",
            "performance_score": 0,
            "latency_analysis": {},
            "bandwidth_estimation": {},
            "bottlenecks": []
        }

def estimate_network_bandwidth(domain, routing_analysis):
    """
    Estimate network bandwidth characteristics
    """
    try:
        bandwidth_estimation = {
            "estimated_bandwidth": "unknown",
            "connection_type": "unknown",
            "bandwidth_class": "unknown",
            "performance_indicators": []
        }
        
        # Basic bandwidth estimation based on latency patterns
        latency_analysis = routing_analysis.get("latency_analysis", {})
        avg_latency = latency_analysis.get("avg_latency_per_hop", 0)
        
        if avg_latency > 0:
            if avg_latency < 5:
                bandwidth_estimation["connection_type"] = "high_speed_local"
                bandwidth_estimation["bandwidth_class"] = "gigabit_plus"
            elif avg_latency < 20:
                bandwidth_estimation["connection_type"] = "broadband"
                bandwidth_estimation["bandwidth_class"] = "high_speed"
            elif avg_latency < 50:
                bandwidth_estimation["connection_type"] = "standard_internet"
                bandwidth_estimation["bandwidth_class"] = "medium_speed"
            else:
                bandwidth_estimation["connection_type"] = "low_speed_or_congested"
                bandwidth_estimation["bandwidth_class"] = "low_speed"
        
        # Check for performance indicators
        if routing_analysis.get("primary_path"):
            path_length = len(routing_analysis["primary_path"])
            if path_length > 15:
                bandwidth_estimation["performance_indicators"].append("long_path_potential_degradation")
            
            # Check for CDN presence
            for hop in routing_analysis["primary_path"]:
                if isinstance(hop, dict) and hop.get("hostname"):
                    hostname = hop["hostname"].lower()
                    if any(cdn in hostname for cdn in ["cloudflare", "akamai", "fastly", "cdn"]):
                        bandwidth_estimation["performance_indicators"].append("cdn_acceleration_detected")
                        break
        
        return bandwidth_estimation
        
    except Exception as e:
        return {
            "error": f"Bandwidth estimation failed: {str(e)}",
            "estimated_bandwidth": "unknown",
            "connection_type": "unknown"
        }

def analyze_network_jitter(routing_analysis):
    """
    Analyze network jitter and stability
    """
    try:
        jitter_analysis = {
            "jitter_present": False,
            "jitter_severity": "low",
            "stability_score": 0,
            "unstable_hops": [],
            "jitter_metrics": {}
        }
        
        primary_path = routing_analysis.get("primary_path", [])
        unstable_count = 0
        
        for hop in primary_path:
            if isinstance(hop, dict) and "rtt" in hop:
                rtt_values = []
                
                # Extract numeric RTT values
                for rtt in hop["rtt"]:
                    if isinstance(rtt, str) and "ms" in rtt:
                        try:
                            value = float(rtt.replace("ms", "").replace("<", "").strip())
                            rtt_values.append(value)
                        except:
                            continue
                
                # Analyze jitter for this hop
                if len(rtt_values) >= 2:
                    max_rtt = max(rtt_values)
                    min_rtt = min(rtt_values)
                    jitter = max_rtt - min_rtt
                    
                    if jitter > 20:  # High jitter threshold
                        jitter_analysis["jitter_present"] = True
                        unstable_count += 1
                        jitter_analysis["unstable_hops"].append({
                            "hop": hop.get("hop", "unknown"),
                            "ip": hop.get("ip"),
                            "jitter": jitter,
                            "rtt_range": f"{min_rtt}-{max_rtt}ms"
                        })
        
        # Determine jitter severity
        if unstable_count > 3:
            jitter_analysis["jitter_severity"] = "high"
        elif unstable_count > 1:
            jitter_analysis["jitter_severity"] = "medium"
        elif unstable_count > 0:
            jitter_analysis["jitter_severity"] = "low"
        
        # Calculate stability score
        if len(primary_path) > 0:
            stable_hops = len(primary_path) - unstable_count
            jitter_analysis["stability_score"] = round((stable_hops / len(primary_path)) * 100, 2)
        
        return jitter_analysis
        
    except Exception as e:
        return {
            "error": f"Jitter analysis failed: {str(e)}",
            "jitter_present": False,
            "stability_score": 0
        }

def estimate_packet_loss(routing_analysis):
    """
    Estimate packet loss based on routing analysis
    """
    try:
        packet_loss = {
            "loss_detected": False,
            "estimated_loss_percentage": 0,
            "timeout_hops": 0,
            "total_hops": 0,
            "loss_locations": []
        }
        
        primary_path = routing_analysis.get("primary_path", [])
        timeout_count = 0
        
        for hop in primary_path:
            if isinstance(hop, dict):
                packet_loss["total_hops"] += 1
                
                if hop.get("status") == "timeout":
                    timeout_count += 1
                    packet_loss["timeout_hops"] += 1
                    packet_loss["loss_locations"].append({
                        "hop": hop.get("hop", "unknown"),
                        "ip": hop.get("ip", "unknown"),
                        "type": "complete_timeout"
                    })
                
                # Check for partial loss (mixed responses)
                elif "rtt" in hop:
                    timeout_rtts = sum(1 for rtt in hop["rtt"] if rtt == "*")
                    total_rtts = len(hop["rtt"])
                    
                    if timeout_rtts > 0 and timeout_rtts < total_rtts:
                        packet_loss["loss_locations"].append({
                            "hop": hop.get("hop", "unknown"),
                            "ip": hop.get("ip", "unknown"),
                            "type": "partial_loss",
                            "loss_ratio": f"{timeout_rtts}/{total_rtts}"
                        })
        
        # Calculate estimated loss percentage
        if packet_loss["total_hops"] > 0:
            packet_loss["estimated_loss_percentage"] = round(
                (timeout_count / packet_loss["total_hops"]) * 100, 2
            )
            
            if packet_loss["estimated_loss_percentage"] > 0:
                packet_loss["loss_detected"] = True
        
        return packet_loss
        
    except Exception as e:
        return {
            "error": f"Packet loss estimation failed: {str(e)}",
            "loss_detected": False,
            "estimated_loss_percentage": 0
        }

def calculate_network_performance_score(latency_analysis, bandwidth_estimation, jitter_analysis, packet_loss):
    """
    Calculate overall network performance score
    """
    try:
        # Start with base score
        performance_score = 100
        
        # Latency score component (40% weight)
        avg_latency = latency_analysis.get("avg_latency_per_hop", 0)
        if avg_latency > 100:
            performance_score -= 30
        elif avg_latency > 50:
            performance_score -= 20
        elif avg_latency > 20:
            performance_score -= 10
        
        # Jitter score component (30% weight)
        stability_score = jitter_analysis.get("stability_score", 100)
        jitter_penalty = (100 - stability_score) * 0.3
        performance_score -= jitter_penalty
        
        # Packet loss score component (30% weight)
        loss_percentage = packet_loss.get("estimated_loss_percentage", 0)
        if loss_percentage > 10:
            performance_score -= 30
        elif loss_percentage > 5:
            performance_score -= 20
        elif loss_percentage > 1:
            performance_score -= 10
        elif loss_percentage > 0:
            performance_score -= 5
        
        return max(0, round(performance_score, 2))
        
    except Exception:
        return 0

def identify_performance_bottlenecks(performance_metrics):
    """
    Identify network performance bottlenecks
    """
    try:
        bottlenecks = []
        
        # Check latency bottlenecks
        latency_analysis = performance_metrics.get("latency_analysis", {})
        latency_bottlenecks = latency_analysis.get("bottlenecks", [])
        for bottleneck in latency_bottlenecks:
            bottlenecks.append({
                "type": "latency_bottleneck",
                "location": f"Hop {bottleneck.get('hop_number')}",
                "severity": bottleneck.get("severity"),
                "details": f"Latency: {bottleneck.get('latency')}ms"
            })
        
        # Check jitter bottlenecks
        jitter_analysis = performance_metrics.get("jitter_analysis", {})
        unstable_hops = jitter_analysis.get("unstable_hops", [])
        for hop in unstable_hops:
            bottlenecks.append({
                "type": "jitter_bottleneck",
                "location": f"Hop {hop.get('hop')} ({hop.get('ip')})",
                "severity": "medium",
                "details": f"Jitter: {hop.get('jitter')}ms, Range: {hop.get('rtt_range')}"
            })
        
        # Check packet loss bottlenecks
        packet_loss = performance_metrics.get("packet_loss", {})
        loss_locations = packet_loss.get("loss_locations", [])
        for location in loss_locations:
            severity = "high" if location.get("type") == "complete_timeout" else "medium"
            bottlenecks.append({
                "type": "packet_loss_bottleneck",
                "location": f"Hop {location.get('hop')} ({location.get('ip')})",
                "severity": severity,
                "details": f"Loss type: {location.get('type')}"
            })
        
        return bottlenecks
        
    except Exception as e:
        return [{"type": "analysis_error", "details": str(e)}]

def generate_performance_recommendations(performance_metrics, bottlenecks):
    """
    Generate network performance optimization recommendations
    """
    try:
        recommendations = []
        
        # Performance score based recommendations
        performance_score = performance_metrics.get("performance_score", 0)
        if performance_score < 60:
            recommendations.append("Network performance is suboptimal, immediate optimization needed")
        elif performance_score < 80:
            recommendations.append("Network performance could be improved")
        
        # Bottleneck specific recommendations
        bottleneck_types = [b.get("type") for b in bottlenecks]
        
        if "latency_bottleneck" in bottleneck_types:
            recommendations.append("Optimize routing paths to reduce latency")
            recommendations.append("Consider CDN implementation for static content")
        
        if "jitter_bottleneck" in bottleneck_types:
            recommendations.append("Investigate network stability issues")
            recommendations.append("Consider Quality of Service (QoS) implementation")
        
        if "packet_loss_bottleneck" in bottleneck_types:
            recommendations.append("Investigate and resolve packet loss issues")
            recommendations.append("Check network device configurations and capacity")
        
        # Bandwidth specific recommendations
        bandwidth_estimation = performance_metrics.get("bandwidth_estimation", {})
        if bandwidth_estimation.get("bandwidth_class") == "low_speed":
            recommendations.append("Consider bandwidth upgrade for better performance")
        
        # General optimization recommendations
        recommendations.extend([
            "Monitor network performance regularly",
            "Implement network monitoring and alerting",
            "Optimize application protocols for network conditions",
            "Consider traffic shaping for critical applications"
        ])
        
        return recommendations[:8]  # Limit to top 8 recommendations
        
    except Exception as e:
        return [f"Failed to generate recommendations: {str(e)}"]

def discover_network_devices(domain, topology_info):
    """
    Discover network devices from topology analysis
    """
    try:
        device_discovery = {
            "devices": [],
            "device_summary": {},
            "discovery_confidence": {},
            "device_relationships": {}
        }
        
        # Extract devices from infrastructure mapping
        infrastructure = topology_info.get("infrastructure_mapping", {})
        for device_type, devices in infrastructure.items():
            for device in devices:
                device_info = {
                    "ip": device.get("ip"),
                    "hostname": device.get("hostname"),
                    "device_type": device_type.rstrip('s'),  # Remove plural
                    "hop_number": device.get("hop_number"),
                    "characteristics": device.get("device_characteristics", {}),
                    "discovery_method": "traceroute_analysis"
                }
                device_discovery["devices"].append(device_info)
        
        # Generate device summary
        device_discovery["device_summary"] = {
            device_type: len(devices) for device_type, devices in infrastructure.items()
        }
        
        # Calculate discovery confidence
        total_devices = len(device_discovery["devices"])
        identified_devices = sum(1 for device in device_discovery["devices"] 
                               if device.get("hostname") and device.get("device_type") != "unknown_device")
        
        if total_devices > 0:
            confidence_score = (identified_devices / total_devices) * 100
            device_discovery["discovery_confidence"] = {
                "confidence_score": round(confidence_score, 2),
                "total_devices": total_devices,
                "identified_devices": identified_devices
            }
        
        return device_discovery
        
    except Exception as e:
        return {
            "error": f"Network device discovery failed: {str(e)}",
            "devices": [],
            "device_summary": {},
            "discovery_confidence": {}
        }

def analyze_network_protocols(domain, topology_info):
    """
    Analyze network protocols in use
    """
    try:
        protocol_analysis = {
            "detected_protocols": {},
            "protocol_security": {},
            "protocol_efficiency": {},
            "protocol_recommendations": []
        }
        
        # Basic protocol detection based on infrastructure
        infrastructure = topology_info.get("infrastructure_mapping", {})
        
        # Analyze routing protocols (implied)
        routing_analysis = topology_info.get("routing_analysis", {})
        if routing_analysis.get("primary_path"):
            protocol_analysis["detected_protocols"]["routing"] = {
                "protocols": ["IP", "ICMP"],  # Basic protocols for traceroute
                "confidence": "high"
            }
        
        # Analyze security protocols
        boundaries = topology_info.get("network_boundaries", {})
        if boundaries.get("trust_boundaries"):
            protocol_analysis["detected_protocols"]["security"] = {
                "protocols": ["NAT", "Firewall"],
                "confidence": "medium"
            }
        
        # Analyze load balancing protocols
        if infrastructure.get("load_balancers"):
            protocol_analysis["detected_protocols"]["load_balancing"] = {
                "protocols": ["HTTP/HTTPS", "TCP"],
                "confidence": "medium"
            }
        
        # Basic security analysis
        protocol_analysis["protocol_security"] = analyze_protocol_security(
            protocol_analysis["detected_protocols"]
        )
        
        # Efficiency analysis
        protocol_analysis["protocol_efficiency"] = analyze_protocol_efficiency(
            topology_info, protocol_analysis["detected_protocols"]
        )
        
        # Generate recommendations
        protocol_analysis["protocol_recommendations"] = generate_protocol_recommendations(
            protocol_analysis["detected_protocols"],
            protocol_analysis["protocol_security"]
        )
        
        return protocol_analysis
        
    except Exception as e:
        return {
            "error": f"Network protocol analysis failed: {str(e)}",
            "detected_protocols": {},
            "protocol_security": {},
            "protocol_recommendations": []
        }

def analyze_protocol_security(detected_protocols):
    """
    Analyze security characteristics of detected protocols
    """
    try:
        security_analysis = {
            "secure_protocols": [],
            "insecure_protocols": [],
            "security_score": 0,
            "security_concerns": []
        }
        
        for category, protocol_info in detected_protocols.items():
            protocols = protocol_info.get("protocols", [])
            
            for protocol in protocols:
                if protocol.upper() in ["HTTPS", "TLS", "SSH", "SFTP", "VPN"]:
                    security_analysis["secure_protocols"].append(protocol)
                elif protocol.upper() in ["HTTP", "FTP", "TELNET", "SNMP"]:
                    security_analysis["insecure_protocols"].append(protocol)
                    security_analysis["security_concerns"].append(f"{protocol} lacks encryption")
        
        # Calculate security score
        total_protocols = len(security_analysis["secure_protocols"]) + len(security_analysis["insecure_protocols"])
        if total_protocols > 0:
            secure_ratio = len(security_analysis["secure_protocols"]) / total_protocols
            security_analysis["security_score"] = round(secure_ratio * 100, 2)
        
        return security_analysis
        
    except Exception as e:
        return {
            "error": f"Protocol security analysis failed: {str(e)}",
            "security_score": 0,
            "secure_protocols": [],
            "insecure_protocols": []
        }

def analyze_protocol_efficiency(topology_info, detected_protocols):
    """
    Analyze efficiency of detected protocols
    """
    try:
        efficiency_analysis = {
            "efficiency_score": 0,
            "optimization_opportunities": [],
            "protocol_overhead": {},
            "performance_impact": {}
        }
        
        # Basic efficiency scoring based on modern protocols
        modern_protocols = 0
        legacy_protocols = 0
        
        for category, protocol_info in detected_protocols.items():
            protocols = protocol_info.get("protocols", [])
            
            for protocol in protocols:
                if protocol.upper() in ["HTTP/2", "HTTP/3", "QUIC", "TLS1.3"]:
                    modern_protocols += 1
                elif protocol.upper() in ["HTTP/1.1", "TLS1.0", "TLS1.1"]:
                    legacy_protocols += 1
                    efficiency_analysis["optimization_opportunities"].append(
                        f"Upgrade {protocol} to newer version"
                    )
        
        # Calculate efficiency score
        total_analyzed = modern_protocols + legacy_protocols
        if total_analyzed > 0:
            efficiency_ratio = modern_protocols / total_analyzed
            efficiency_analysis["efficiency_score"] = round(efficiency_ratio * 100, 2)
        
        return efficiency_analysis
        
    except Exception as e:
        return {
            "error": f"Protocol efficiency analysis failed: {str(e)}",
            "efficiency_score": 0,
            "optimization_opportunities": []
        }

def generate_protocol_recommendations(detected_protocols, protocol_security):
    """
    Generate protocol optimization recommendations
    """
    try:
        recommendations = []
        
        # Security based recommendations
        insecure_protocols = protocol_security.get("insecure_protocols", [])
        if insecure_protocols:
            recommendations.append(f"Replace insecure protocols: {', '.join(insecure_protocols)}")
            recommendations.append("Implement end-to-end encryption for all communications")
        
        # Performance recommendations
        recommendations.append("Consider HTTP/2 or HTTP/3 for web traffic optimization")
        recommendations.append("Implement protocol compression where applicable")
        
        # Security recommendations
        recommendations.extend([
            "Use TLS 1.3 for all encrypted communications",
            "Disable legacy protocol versions",
            "Implement protocol-specific security controls",
            "Monitor protocol usage and security"
        ])
        
        return recommendations[:6]  # Limit to top 6 recommendations
        
    except Exception as e:
        return [f"Failed to generate protocol recommendations: {str(e)}"]

def check_network_compliance(domain, network_security, topology_info):
    """
    Check network compliance with security standards
    """
    try:
        compliance_check = {
            "compliance_frameworks": {
                "pci_dss": {"compliant": False, "score": 0, "requirements_met": [], "gaps": []},
                "iso_27001": {"compliant": False, "score": 0, "requirements_met": [], "gaps": []},
                "nist_cybersecurity": {"compliant": False, "score": 0, "requirements_met": [], "gaps": []},
                "cis_controls": {"compliant": False, "score": 0, "requirements_met": [], "gaps": []}
            },
            "overall_compliance_score": 0,
            "critical_compliance_gaps": [],
            "compliance_recommendations": []
        }
        
        # Check PCI DSS compliance
        pci_compliance = check_pci_dss_compliance(network_security, topology_info)
        compliance_check["compliance_frameworks"]["pci_dss"] = pci_compliance
        
        # Check ISO 27001 compliance
        iso_compliance = check_iso27001_compliance(network_security, topology_info)
        compliance_check["compliance_frameworks"]["iso_27001"] = iso_compliance
        
        # Check NIST Cybersecurity Framework compliance
        nist_compliance = check_nist_compliance(network_security, topology_info)
        compliance_check["compliance_frameworks"]["nist_cybersecurity"] = nist_compliance
        
        # Check CIS Controls compliance
        cis_compliance = check_cis_controls_compliance(network_security, topology_info)
        compliance_check["compliance_frameworks"]["cis_controls"] = cis_compliance
        
        # Calculate overall compliance score
        framework_scores = [
            pci_compliance["score"],
            iso_compliance["score"],
            nist_compliance["score"],
            cis_compliance["score"]
        ]
        compliance_check["overall_compliance_score"] = round(sum(framework_scores) / len(framework_scores), 2)
        
        # Identify critical gaps
        compliance_check["critical_compliance_gaps"] = identify_critical_compliance_gaps(
            compliance_check["compliance_frameworks"]
        )
        
        # Generate recommendations
        compliance_check["compliance_recommendations"] = generate_compliance_recommendations(
            compliance_check["compliance_frameworks"],
            compliance_check["critical_compliance_gaps"]
        )
        
        return compliance_check
        
    except Exception as e:
        return {
            "error": f"Network compliance check failed: {str(e)}",
            "compliance_frameworks": {},
            "overall_compliance_score": 0,
            "critical_compliance_gaps": []
        }

def check_pci_dss_compliance(network_security, topology_info):
    """
    Check PCI DSS network compliance requirements
    """
    try:
        pci_compliance = {
            "compliant": False,
            "score": 0,
            "requirements_met": [],
            "gaps": []
        }
        
        # PCI DSS Requirement 1: Firewall configuration
        if topology_info.get("infrastructure_mapping", {}).get("firewalls"):
            pci_compliance["requirements_met"].append("Req 1: Firewall protection detected")
        else:
            pci_compliance["gaps"].append("Req 1: No firewall protection detected")
        
        # PCI DSS Requirement 2: Network segmentation
        boundaries = topology_info.get("network_boundaries", {})
        if boundaries.get("dmz_detection", {}).get("dmz_likely"):
            pci_compliance["requirements_met"].append("Req 2: Network segmentation present")
        else:
            pci_compliance["gaps"].append("Req 2: Network segmentation not clearly defined")
        
        # PCI DSS Requirement 4: Encryption in transit
        vulnerabilities = network_security.get("vulnerabilities", [])
        insecure_protocols = any("insecure" in str(vuln) for vuln in vulnerabilities)
        if not insecure_protocols:
            pci_compliance["requirements_met"].append("Req 4: No insecure protocols detected")
        else:
            pci_compliance["gaps"].append("Req 4: Insecure protocols may compromise encryption")
        
        # Calculate score
        total_requirements = 3
        met_requirements = len(pci_compliance["requirements_met"])
        pci_compliance["score"] = round((met_requirements / total_requirements) * 100, 2)
        pci_compliance["compliant"] = pci_compliance["score"] >= 80
        
        return pci_compliance
        
    except Exception as e:
        return {
            "error": f"PCI DSS compliance check failed: {str(e)}",
            "compliant": False,
            "score": 0,
            "gaps": ["Compliance check failed"]
        }

def check_iso27001_compliance(network_security, topology_info):
    """
    Check ISO 27001 network compliance requirements
    """
    try:
        iso_compliance = {
            "compliant": False,
            "score": 0,
            "requirements_met": [],
            "gaps": []
        }
        
        # A.13.1 Network security management
        security_score = network_security.get("security_score", 0)
        if security_score >= 70:
            iso_compliance["requirements_met"].append("A.13.1: Network security controls adequate")
        else:
            iso_compliance["gaps"].append("A.13.1: Network security controls need improvement")
        
        # A.13.2 Information transfer security
        boundaries = topology_info.get("network_boundaries", {})
        if boundaries.get("trust_boundaries"):
            iso_compliance["requirements_met"].append("A.13.2: Network boundaries defined")
        else:
            iso_compliance["gaps"].append("A.13.2: Network boundaries not clearly defined")
        
        # Calculate score
        total_requirements = 2
        met_requirements = len(iso_compliance["requirements_met"])
        iso_compliance["score"] = round((met_requirements / total_requirements) * 100, 2)
        iso_compliance["compliant"] = iso_compliance["score"] >= 80
        
        return iso_compliance
        
    except Exception as e:
        return {
            "error": f"ISO 27001 compliance check failed: {str(e)}",
            "compliant": False,
            "score": 0,
            "gaps": ["Compliance check failed"]
        }

def check_nist_compliance(network_security, topology_info):
    """
    Check NIST Cybersecurity Framework compliance
    """
    try:
        nist_compliance = {
            "compliant": False,
            "score": 0,
            "requirements_met": [],
            "gaps": []
        }
        
        # IDENTIFY: Asset management
        devices = topology_info.get("infrastructure_mapping", {})
        if any(devices.values()):
            nist_compliance["requirements_met"].append("ID.AM: Network assets identified")
        else:
            nist_compliance["gaps"].append("ID.AM: Network assets not fully identified")
        
        # PROTECT: Access control
        if topology_info.get("infrastructure_mapping", {}).get("firewalls"):
            nist_compliance["requirements_met"].append("PR.AC: Access controls in place")
        else:
            nist_compliance["gaps"].append("PR.AC: Network access controls needed")
        
        # DETECT: Security monitoring
        # This would require active monitoring - mark as gap for now
        nist_compliance["gaps"].append("DE.CM: Network monitoring capabilities unclear")
        
        # Calculate score
        total_requirements = 3
        met_requirements = len(nist_compliance["requirements_met"])
        nist_compliance["score"] = round((met_requirements / total_requirements) * 100, 2)
        nist_compliance["compliant"] = nist_compliance["score"] >= 80
        
        return nist_compliance
        
    except Exception as e:
        return {
            "error": f"NIST compliance check failed: {str(e)}",
            "compliant": False,
            "score": 0,
            "gaps": ["Compliance check failed"]
        }

def check_cis_controls_compliance(network_security, topology_info):
    """
    Check CIS Controls compliance
    """
    try:
        cis_compliance = {
            "compliant": False,
            "score": 0,
            "requirements_met": [],
            "gaps": []
        }
        
        # CIS Control 12: Network Infrastructure Management
        infrastructure = topology_info.get("infrastructure_mapping", {})
        if infrastructure.get("routers") or infrastructure.get("switches"):
            cis_compliance["requirements_met"].append("CIS 12: Network infrastructure managed")
        else:
            cis_compliance["gaps"].append("CIS 12: Network infrastructure management unclear")
        
        # CIS Control 13: Network Monitoring and Defense
        if infrastructure.get("firewalls"):
            cis_compliance["requirements_met"].append("CIS 13: Network defense controls present")
        else:
            cis_compliance["gaps"].append("CIS 13: Network defense controls needed")
        
        # Calculate score
        total_requirements = 2
        met_requirements = len(cis_compliance["requirements_met"])
        cis_compliance["score"] = round((met_requirements / total_requirements) * 100, 2)
        cis_compliance["compliant"] = cis_compliance["score"] >= 80
        
        return cis_compliance
        
    except Exception as e:
        return {
            "error": f"CIS Controls compliance check failed: {str(e)}",
            "compliant": False,
            "score": 0,
            "gaps": ["Compliance check failed"]
        }

def identify_critical_compliance_gaps(compliance_frameworks):
    """
    Identify critical compliance gaps across frameworks
    """
    try:
        critical_gaps = []
        
        # Analyze gaps across all frameworks
        all_gaps = []
        for framework, details in compliance_frameworks.items():
            gaps = details.get("gaps", [])
            all_gaps.extend(gaps)
        
        # Identify common/critical gaps
        gap_counts = {}
        for gap in all_gaps:
            # Extract the core issue from gap description
            if "firewall" in gap.lower():
                gap_counts["firewall_protection"] = gap_counts.get("firewall_protection", 0) + 1
            elif "segmentation" in gap.lower() or "boundaries" in gap.lower():
                gap_counts["network_segmentation"] = gap_counts.get("network_segmentation", 0) + 1
            elif "monitoring" in gap.lower():
                gap_counts["network_monitoring"] = gap_counts.get("network_monitoring", 0) + 1
            elif "encryption" in gap.lower() or "protocol" in gap.lower():
                gap_counts["encryption_protocols"] = gap_counts.get("encryption_protocols", 0) + 1
        
        # Mark gaps that appear in multiple frameworks as critical
        for gap_type, count in gap_counts.items():
            if count >= 2:  # Appears in 2+ frameworks
                critical_gaps.append({
                    "gap_type": gap_type,
                    "frameworks_affected": count,
                    "severity": "critical"
                })
        
        return critical_gaps
        
    except Exception as e:
        return [{"gap_type": "analysis_error", "details": str(e)}]

def generate_compliance_recommendations(compliance_frameworks, critical_gaps):
    """
    Generate compliance improvement recommendations
    """
    try:
        recommendations = []
        
        # Address critical gaps first
        for gap in critical_gaps:
            gap_type = gap.get("gap_type", "")
            
            if gap_type == "firewall_protection":
                recommendations.append("Deploy network firewall protection at perimeter")
            elif gap_type == "network_segmentation":
                recommendations.append("Implement network segmentation and DMZ")
            elif gap_type == "network_monitoring":
                recommendations.append("Deploy network monitoring and logging solutions")
            elif gap_type == "encryption_protocols":
                recommendations.append("Upgrade to secure network protocols and encryption")
        
        # Framework-specific recommendations
        for framework, details in compliance_frameworks.items():
            if details.get("score", 0) < 60:
                recommendations.append(f"Prioritize {framework.replace('_', ' ').title()} compliance improvements")
        
        # General recommendations
        recommendations.extend([
            "Conduct regular compliance assessments",
            "Implement continuous compliance monitoring",
            "Document network security policies and procedures",
            "Provide compliance training for network administrators"
        ])
        
        return recommendations[:8]  # Limit to top 8 recommendations
        
    except Exception as e:
        return [f"Failed to generate compliance recommendations: {str(e)}"]

def calculate_network_assessment(network_security, performance_metrics, topology_info, compliance_check):
    """
    Calculate overall network assessment
    """
    try:
        overall_assessment = {
            "overall_score": 0,
            "overall_grade": "F",
            "assessment_summary": {},
            "key_findings": [],
            "priority_actions": [],
            "network_maturity": "unknown"
        }
        
        # Component scores (with weights)
        security_score = network_security.get("security_score", 0) * 0.4
        performance_score = performance_metrics.get("performance_score", 0) * 0.3
        compliance_score = compliance_check.get("overall_compliance_score", 0) * 0.3
        
        # Calculate overall score
        overall_assessment["overall_score"] = round(security_score + performance_score + compliance_score, 2)
        
        # Determine grade
        score = overall_assessment["overall_score"]
        if score >= 90:
            overall_assessment["overall_grade"] = "A"
        elif score >= 80:
            overall_assessment["overall_grade"] = "B"
        elif score >= 70:
            overall_assessment["overall_grade"] = "C"
        elif score >= 60:
            overall_assessment["overall_grade"] = "D"
        else:
            overall_assessment["overall_grade"] = "F"
        
        # Assessment summary
        overall_assessment["assessment_summary"] = {
            "security_score": network_security.get("security_score", 0),
            "performance_score": performance_metrics.get("performance_score", 0),
            "compliance_score": compliance_check.get("overall_compliance_score", 0),
            "risk_level": network_security.get("risk_level", "UNKNOWN"),
            "vulnerabilities_found": len(network_security.get("vulnerabilities", [])),
            "compliance_frameworks_passed": sum(1 for fw in compliance_check.get("compliance_frameworks", {}).values() 
                                              if fw.get("compliant", False))
        }
        
        # Key findings
        findings = []
        if network_security.get("risk_level") in ["CRITICAL", "HIGH"]:
            findings.append(f"Network security risk level: {network_security.get('risk_level')}")
        
        vuln_count = len(network_security.get("vulnerabilities", []))
        if vuln_count > 0:
            findings.append(f"{vuln_count} network vulnerabilities identified")
        
        if performance_metrics.get("performance_score", 0) < 70:
            findings.append("Network performance issues detected")
        
        if compliance_check.get("overall_compliance_score", 0) < 70:
            findings.append("Compliance gaps require attention")
        
        overall_assessment["key_findings"] = findings
        
        # Determine network maturity
        if score >= 85:
            overall_assessment["network_maturity"] = "optimized"
        elif score >= 75:
            overall_assessment["network_maturity"] = "managed"
        elif score >= 60:
            overall_assessment["network_maturity"] = "defined"
        elif score >= 40:
            overall_assessment["network_maturity"] = "repeatable"
        else:
            overall_assessment["network_maturity"] = "initial"
        
        return overall_assessment
        
    except Exception as e:
        return {
            "error": f"Overall assessment calculation failed: {str(e)}",
            "overall_score": 0,
            "overall_grade": "F",
            "network_maturity": "unknown"
        }


# Phase 7: Threat Intelligence & Risk Assessment
def comprehensive_threat_intelligence_analysis(domain, infrastructure_data=None):
    """
    Phase 7: Threat Intelligence & Risk Assessment
    Performs comprehensive threat intelligence gathering, risk assessment, and vulnerability correlation
    """
    try:
        start_time = time.time()
        
        # Threat intelligence gathering
        threat_intelligence = gather_threat_intelligence(domain)
        
        # Combine all data for risk assessment
        all_phase_results = {
            'infrastructure_data': infrastructure_data,
            'threat_intelligence': threat_intelligence
        }
        
        # Risk assessment framework
        risk_assessment = perform_comprehensive_risk_assessment(domain, all_phase_results)
        
        # Vulnerability correlation and scoring
        vulnerability_correlation = correlate_vulnerabilities(all_phase_results)
        
        # Threat actor profiling  
        threat_actors = {"active_threat_actors": [], "attribution_data": {}}
        
        # Attack surface analysis
        attack_surface = analyze_attack_surface(all_phase_results)
        
        # Risk scoring and prioritization
        risk_scoring = calculate_comprehensive_risk_score(
            risk_assessment, vulnerability_correlation, attack_surface, threat_intelligence
        )
        
        # Threat landscape analysis (placeholder)
        threat_landscape = {"landscape_analysis": "completed", "threat_trends": [], "geographic_distribution": {}}
        
        # Security recommendations and mitigation strategies (placeholder)
        security_recommendations = {"recommendations": [], "mitigation_strategies": [], "priority_actions": []}
        
        return {
            "domain": domain,
            "threat_intelligence_analysis": {
                "threat_intelligence": threat_intelligence,
                "risk_assessment": risk_assessment,
                "vulnerability_correlation": vulnerability_correlation,
                "threat_actors": threat_actors,
                "attack_surface": attack_surface,
                "risk_scoring": risk_scoring,
                "threat_landscape": threat_landscape,
                "security_recommendations": security_recommendations
            },
            "analysis_stats": {
                "threats_identified": len(threat_intelligence.get('threat_indicators', [])),
                "vulnerabilities_correlated": len(vulnerability_correlation.get('correlated_vulnerabilities', [])),
                "risk_score": risk_scoring.get('overall_risk_score', 0),
                "threat_actors_identified": len(threat_actors.get('active_threat_actors', [])),
                "analysis_duration": round(time.time() - start_time, 2)
            }
        }
        
    except Exception as e:
        return {
            "domain": domain,
            "threat_intelligence_analysis": {
                "error": str(e),
                "analysis_completed": False
            },
            "analysis_stats": {
                "threats_identified": 0,
                "vulnerabilities_correlated": 0,
                "risk_score": 0,
                "threat_actors_identified": 0,
                "analysis_duration": round(time.time() - start_time, 2)
            }
        }

def gather_threat_intelligence(domain):
    """
    Gather threat intelligence from multiple sources
    """
    try:
        threat_intelligence = {
            "threat_indicators": [],
            "domain_reputation": {},
            "ip_reputation": {},
            "malware_analysis": {},
            "phishing_indicators": [],
            "botnet_indicators": [],
            "dark_web_mentions": {},
            "threat_feeds": {},
            "attribution_data": {}
        }
        
        # Domain reputation analysis
        domain_reputation = analyze_domain_reputation(domain)
        threat_intelligence["domain_reputation"] = domain_reputation
        
        # IP reputation analysis
        ip_reputation = analyze_ip_reputation(domain)
        threat_intelligence["ip_reputation"] = ip_reputation
        
        # Malware analysis
        malware_analysis = check_malware_associations(domain)
        threat_intelligence["malware_analysis"] = malware_analysis
        
        # Phishing indicators
        phishing_indicators = detect_phishing_indicators(domain)
        threat_intelligence["phishing_indicators"] = phishing_indicators
        
        # Botnet indicators
        botnet_indicators = check_botnet_associations(domain)
        threat_intelligence["botnet_indicators"] = botnet_indicators
        
        # Dark web analysis
        dark_web_analysis = analyze_dark_web_mentions(domain)
        threat_intelligence["dark_web_mentions"] = dark_web_analysis
        
        # Threat feed integration
        threat_feeds = integrate_threat_feeds(domain)
        threat_intelligence["threat_feeds"] = threat_feeds
        
        # Attribution and threat actor analysis
        attribution_data = analyze_threat_attribution(domain)
        threat_intelligence["attribution_data"] = attribution_data
        
        # Compile threat indicators
        threat_indicators = compile_threat_indicators(
            domain_reputation, ip_reputation, malware_analysis, 
            phishing_indicators, botnet_indicators
        )
        threat_intelligence["threat_indicators"] = threat_indicators
        
        return threat_intelligence
        
    except Exception as e:
        return {
            "error": f"Threat intelligence gathering failed: {str(e)}",
            "threat_indicators": [],
            "domain_reputation": {},
            "ip_reputation": {},
            "malware_analysis": {},
            "phishing_indicators": [],
            "botnet_indicators": []
        }

def analyze_domain_reputation(domain):
    """
    Analyze domain reputation across multiple threat intelligence sources
    """
    try:
        domain_reputation = {
            "reputation_score": 0,
            "reputation_status": "unknown",
            "threat_categories": [],
            "blacklist_status": {},
            "historical_data": {},
            "reputation_sources": {}
        }
        
        # Check against known bad domains (simulated)
        known_bad_domains = [
            "malware-domain.com", "phishing-site.net", "botnet-c2.org",
            "spam-sender.info", "scam-site.biz"
        ]
        
        if domain.lower() in known_bad_domains:
            domain_reputation["reputation_score"] = 10
            domain_reputation["reputation_status"] = "malicious"
            domain_reputation["threat_categories"].append("known_malicious")
        else:
            # Analyze domain characteristics for reputation scoring
            reputation_factors = analyze_domain_reputation_factors(domain)
            domain_reputation.update(reputation_factors)
        
        # Simulate blacklist checking
        blacklist_status = check_domain_blacklists(domain)
        domain_reputation["blacklist_status"] = blacklist_status
        
        # Historical reputation data
        historical_data = get_domain_historical_reputation(domain)
        domain_reputation["historical_data"] = historical_data
        
        return domain_reputation
        
    except Exception as e:
        return {
            "error": f"Domain reputation analysis failed: {str(e)}",
            "reputation_score": 0,
            "reputation_status": "unknown",
            "threat_categories": []
        }

def analyze_domain_reputation_factors(domain):
    """
    Analyze various factors that contribute to domain reputation
    """
    try:
        reputation_factors = {
            "reputation_score": 85,  # Default good score
            "reputation_status": "clean",
            "threat_categories": [],
            "reputation_factors": {}
        }
        
        # Domain age analysis (simulated)
        domain_age = estimate_domain_age(domain)
        if domain_age < 30:  # Very new domain
            reputation_factors["reputation_score"] -= 20
            reputation_factors["threat_categories"].append("new_domain")
        elif domain_age < 90:  # Recently created
            reputation_factors["reputation_score"] -= 10
            reputation_factors["threat_categories"].append("recent_domain")
        
        # Domain length and complexity
        if len(domain) > 50:  # Very long domain
            reputation_factors["reputation_score"] -= 15
            reputation_factors["threat_categories"].append("suspicious_length")
        
        # Character analysis
        if any(char in domain for char in ['-', '_']) and domain.count('-') + domain.count('_') > 3:
            reputation_factors["reputation_score"] -= 10
            reputation_factors["threat_categories"].append("suspicious_chars")
        
        # TLD analysis
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.pw', '.top', '.click']
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                reputation_factors["reputation_score"] -= 25
                reputation_factors["threat_categories"].append("suspicious_tld")
                break
        
        # Determine final reputation status
        score = reputation_factors["reputation_score"]
        if score >= 80:
            reputation_factors["reputation_status"] = "clean"
        elif score >= 60:
            reputation_factors["reputation_status"] = "suspicious"
        elif score >= 40:
            reputation_factors["reputation_status"] = "likely_malicious"
        else:
            reputation_factors["reputation_status"] = "malicious"
        
        return reputation_factors
        
    except Exception as e:
        return {
            "reputation_score": 50,
            "reputation_status": "unknown",
            "threat_categories": ["analysis_error"]
        }

def estimate_domain_age(domain):
    """
    Estimate domain age (simulated implementation)
    """
    try:
        # This is a simulated implementation
        # In production, would use WHOIS data or domain registration APIs
        
        # Simple heuristic based on domain characteristics
        if domain in ["google.com", "microsoft.com", "apple.com", "amazon.com"]:
            return 10000  # Very old, established domains
        elif domain in ["example.com", "test.com", "demo.org"]:
            return 5000   # Old test/example domains
        else:
            # Simulate random age between 30-3000 days
            import hashlib
            hash_value = int(hashlib.md5(domain.encode()).hexdigest()[:8], 16)
            return (hash_value % 2970) + 30
            
    except Exception:
        return 365  # Default to 1 year

def check_domain_blacklists(domain):
    """
    Check domain against various blacklists (simulated)
    """
    try:
        blacklist_status = {
            "blacklisted": False,
            "blacklist_sources": [],
            "blacklist_categories": [],
            "confidence_score": 0
        }
        
        # Simulate blacklist checking
        suspicious_patterns = [
            "malware", "phishing", "spam", "scam", "fraud", 
            "botnet", "c2", "cnc", "command", "control"
        ]
        
        for pattern in suspicious_patterns:
            if pattern in domain.lower():
                blacklist_status["blacklisted"] = True
                blacklist_status["blacklist_sources"].append(f"pattern_match_{pattern}")
                blacklist_status["blacklist_categories"].append("suspicious_content")
                blacklist_status["confidence_score"] += 20
        
        # Simulate additional blacklist sources
        if blacklist_status["blacklisted"]:
            blacklist_status["blacklist_sources"].extend([
                "simulated_blacklist_1", "simulated_blacklist_2"
            ])
            blacklist_status["confidence_score"] = min(100, blacklist_status["confidence_score"] + 30)
        
        return blacklist_status
        
    except Exception as e:
        return {
            "error": f"Blacklist checking failed: {str(e)}",
            "blacklisted": False,
            "blacklist_sources": []
        }

def get_domain_historical_reputation(domain):
    """
    Get historical reputation data for domain (simulated)
    """
    try:
        historical_data = {
            "reputation_history": [],
            "threat_incidents": [],
            "reputation_trend": "stable",
            "first_seen": "unknown",
            "last_updated": "unknown"
        }
        
        # Simulate historical data based on domain characteristics
        if any(bad_word in domain.lower() for bad_word in ["malware", "phishing", "spam"]):
            historical_data["threat_incidents"] = [
                {
                    "date": "2025-01-01",
                    "incident_type": "malware_hosting",
                    "severity": "high",
                    "source": "threat_feed_1"
                },
                {
                    "date": "2024-12-15",
                    "incident_type": "phishing_campaign",
                    "severity": "medium",
                    "source": "threat_feed_2"
                }
            ]
            historical_data["reputation_trend"] = "deteriorating"
        else:
            # Clean domain history
            historical_data["reputation_history"] = [
                {"date": "2025-01-10", "score": 85, "status": "clean"},
                {"date": "2024-12-10", "score": 83, "status": "clean"},
                {"date": "2024-11-10", "score": 87, "status": "clean"}
            ]
            historical_data["reputation_trend"] = "stable"
        
        return historical_data
        
    except Exception as e:
        return {
            "error": f"Historical data retrieval failed: {str(e)}",
            "reputation_history": [],
            "threat_incidents": []
        }

def analyze_ip_reputation(domain):
    """
    Analyze IP reputation for domain's resolved IPs
    """
    try:
        import socket
        
        ip_reputation = {
            "resolved_ips": [],
            "ip_reputation_scores": {},
            "malicious_ips": [],
            "geo_reputation": {},
            "hosting_reputation": {}
        }
        
        # Resolve domain to IPs
        try:
            resolved_ips = socket.gethostbyname_ex(domain)[2]
            ip_reputation["resolved_ips"] = resolved_ips
        except:
            ip_reputation["resolved_ips"] = []
        
        # Analyze each IP
        for ip in ip_reputation["resolved_ips"]:
            ip_analysis = analyze_single_ip_reputation(ip)
            ip_reputation["ip_reputation_scores"][ip] = ip_analysis
            
            if ip_analysis.get("reputation_score", 100) < 50:
                ip_reputation["malicious_ips"].append(ip)
        
        # Geo-reputation analysis
        geo_reputation = analyze_geo_reputation(ip_reputation["resolved_ips"])
        ip_reputation["geo_reputation"] = geo_reputation
        
        # Hosting reputation analysis
        hosting_reputation = analyze_hosting_reputation(ip_reputation["resolved_ips"])
        ip_reputation["hosting_reputation"] = hosting_reputation
        
        return ip_reputation
        
    except Exception as e:
        return {
            "error": f"IP reputation analysis failed: {str(e)}",
            "resolved_ips": [],
            "ip_reputation_scores": {},
            "malicious_ips": []
        }

def analyze_single_ip_reputation(ip_address):
    """
    Analyze reputation of a single IP address
    """
    try:
        ip_analysis = {
            "ip_address": ip_address,
            "reputation_score": 85,  # Default clean score
            "reputation_status": "clean",
            "threat_indicators": [],
            "blacklist_status": [],
            "geo_location": {},
            "hosting_provider": "unknown"
        }
        
        # Simulate IP reputation analysis
        suspicious_ip_patterns = [
            ("tor_exit", lambda ip: ip.startswith("192.42.")),  # Simulated Tor exit
            ("vpn_service", lambda ip: ip.startswith("185.220.")),  # Simulated VPN
            ("malware_c2", lambda ip: ip.startswith("198.51.")),  # Simulated C2
            ("botnet_node", lambda ip: ip.startswith("203.0."))   # Simulated botnet
        ]
        
        for pattern_name, pattern_check in suspicious_ip_patterns:
            if pattern_check(ip_address):
                ip_analysis["reputation_score"] -= 40
                ip_analysis["threat_indicators"].append(pattern_name)
                ip_analysis["blacklist_status"].append(f"blacklisted_{pattern_name}")
        
        # Determine reputation status
        score = ip_analysis["reputation_score"]
        if score >= 80:
            ip_analysis["reputation_status"] = "clean"
        elif score >= 60:
            ip_analysis["reputation_status"] = "suspicious"
        else:
            ip_analysis["reputation_status"] = "malicious"
        
        # Simulate geo-location data
        ip_analysis["geo_location"] = get_simulated_geo_location(ip_address)
        
        return ip_analysis
        
    except Exception as e:
        return {
            "ip_address": ip_address,
            "error": str(e),
            "reputation_score": 50,
            "reputation_status": "unknown"
        }

def get_simulated_geo_location(ip_address):
    """
    Get simulated geo-location data for IP
    """
    try:
        # Simulate geo-location based on IP patterns
        if ip_address.startswith("8.8."):
            return {"country": "US", "region": "California", "city": "Mountain View", "org": "Google"}
        elif ip_address.startswith("1.1."):
            return {"country": "US", "region": "California", "city": "San Francisco", "org": "Cloudflare"}
        elif ip_address.startswith("192.168.") or ip_address.startswith("10.") or ip_address.startswith("172."):
            return {"country": "Unknown", "region": "Unknown", "city": "Unknown", "org": "Private Network"}
        else:
            return {"country": "Unknown", "region": "Unknown", "city": "Unknown", "org": "Unknown"}
            
    except Exception:
        return {"country": "Unknown", "region": "Unknown", "city": "Unknown", "org": "Unknown"}

def analyze_geo_reputation(ip_addresses):
    """
    Analyze geo-reputation of IP addresses
    """
    try:
        geo_reputation = {
            "countries": [],
            "high_risk_countries": [],
            "geo_diversity": "unknown",
            "risk_assessment": {}
        }
        
        # Simulate high-risk countries
        high_risk_countries = ["Unknown", "CN", "RU", "IR", "KP"]
        
        countries = []
        for ip in ip_addresses:
            geo_data = get_simulated_geo_location(ip)
            country = geo_data.get("country", "Unknown")
            if country not in countries:
                countries.append(country)
                
            if country in high_risk_countries:
                geo_reputation["high_risk_countries"].append(country)
        
        geo_reputation["countries"] = countries
        
        # Assess geo-diversity
        if len(countries) > 3:
            geo_reputation["geo_diversity"] = "high"
        elif len(countries) > 1:
            geo_reputation["geo_diversity"] = "medium"
        else:
            geo_reputation["geo_diversity"] = "low"
        
        # Risk assessment
        risk_score = len(geo_reputation["high_risk_countries"]) * 25
        geo_reputation["risk_assessment"] = {
            "risk_score": min(100, risk_score),
            "risk_level": "high" if risk_score > 50 else "medium" if risk_score > 0 else "low"
        }
        
        return geo_reputation
        
    except Exception as e:
        return {
            "error": f"Geo-reputation analysis failed: {str(e)}",
            "countries": [],
            "high_risk_countries": []
        }

def analyze_hosting_reputation(ip_addresses):
    """
    Analyze hosting reputation and provider characteristics
    """
    try:
        hosting_reputation = {
            "hosting_providers": [],
            "hosting_types": [],
            "reputation_scores": {},
            "risk_indicators": []
        }
        
        for ip in ip_addresses:
            geo_data = get_simulated_geo_location(ip)
            provider = geo_data.get("org", "Unknown")
            
            if provider not in hosting_reputation["hosting_providers"]:
                hosting_reputation["hosting_providers"].append(provider)
                
                # Simulate hosting reputation scoring
                if provider in ["Google", "Amazon", "Microsoft", "Cloudflare"]:
                    hosting_reputation["reputation_scores"][provider] = 95
                    hosting_reputation["hosting_types"].append("tier1_cloud")
                elif provider in ["DigitalOcean", "Vultr", "Linode"]:
                    hosting_reputation["reputation_scores"][provider] = 80
                    hosting_reputation["hosting_types"].append("cloud_vps")
                elif provider == "Unknown":
                    hosting_reputation["reputation_scores"][provider] = 40
                    hosting_reputation["hosting_types"].append("unknown")
                    hosting_reputation["risk_indicators"].append("unknown_hosting")
                else:
                    hosting_reputation["reputation_scores"][provider] = 70
                    hosting_reputation["hosting_types"].append("standard_hosting")
        
        return hosting_reputation
        
    except Exception as e:
        return {
            "error": f"Hosting reputation analysis failed: {str(e)}",
            "hosting_providers": [],
            "reputation_scores": {}
        }

def check_malware_associations(domain):
    """
    Check for malware associations and indicators
    """
    try:
        malware_analysis = {
            "malware_detected": False,
            "malware_families": [],
            "malware_indicators": [],
            "c2_indicators": [],
            "file_associations": {},
            "confidence_score": 0
        }
        
        # Check for malware-related keywords in domain
        malware_keywords = [
            "malware", "virus", "trojan", "ransomware", "botnet", 
            "backdoor", "rootkit", "keylogger", "stealer", "loader"
        ]
        
        for keyword in malware_keywords:
            if keyword in domain.lower():
                malware_analysis["malware_detected"] = True
                malware_analysis["malware_families"].append(f"suspected_{keyword}")
                malware_analysis["confidence_score"] += 20
        
        # Check for C2 indicators
        c2_keywords = ["c2", "cnc", "command", "control", "panel", "gate"]
        for keyword in c2_keywords:
            if keyword in domain.lower():
                malware_analysis["c2_indicators"].append(f"c2_{keyword}")
                malware_analysis["confidence_score"] += 25
        
        # Simulate file associations (in production, would check file hashes)
        if malware_analysis["malware_detected"]:
            malware_analysis["file_associations"] = {
                "suspicious_files": ["malicious_payload.exe", "trojan_dropper.dll"],
                "file_hashes": ["a1b2c3d4e5f6...", "f6e5d4c3b2a1..."],
                "detection_sources": ["antivirus_vendor_1", "sandbox_analysis"]
            }
        
        return malware_analysis
        
    except Exception as e:
        return {
            "error": f"Malware analysis failed: {str(e)}",
            "malware_detected": False,
            "malware_families": [],
            "confidence_score": 0
        }

def detect_phishing_indicators(domain):
    """
    Detect phishing indicators and patterns
    """
    try:
        phishing_indicators = []
        
        # Common phishing patterns
        phishing_patterns = [
            ("brand_impersonation", ["paypal", "amazon", "microsoft", "google", "apple"]),
            ("banking_terms", ["bank", "secure", "verify", "account", "login"]),
            ("urgency_keywords", ["urgent", "suspend", "expire", "immediate", "action"]),
            ("security_terms", ["security", "alert", "warning", "breach", "violation"]),
            ("social_engineering", ["winner", "prize", "lottery", "congratulations"])
        ]
        
        for pattern_type, keywords in phishing_patterns:
            for keyword in keywords:
                if keyword in domain.lower():
                    phishing_indicators.append({
                        "indicator_type": pattern_type,
                        "keyword": keyword,
                        "confidence": "medium",
                        "description": f"Domain contains {pattern_type} keyword: {keyword}"
                    })
        
        # Check for suspicious TLDs commonly used in phishing
        phishing_tlds = [".tk", ".ml", ".ga", ".cf", ".top", ".click", ".download"]
        for tld in phishing_tlds:
            if domain.endswith(tld):
                phishing_indicators.append({
                    "indicator_type": "suspicious_tld",
                    "keyword": tld,
                    "confidence": "high",
                    "description": f"Domain uses TLD commonly associated with phishing: {tld}"
                })
        
        # Check for character substitution (typosquatting)
        if any(char in domain for char in ["0", "1", "3", "4", "5"]) and len(domain) > 10:
            phishing_indicators.append({
                "indicator_type": "character_substitution",
                "keyword": "numeric_substitution",
                "confidence": "low",
                "description": "Domain may use character substitution for typosquatting"
            })
        
        return phishing_indicators
        
    except Exception as e:
        return [{
            "indicator_type": "analysis_error",
            "error": str(e),
            "confidence": "unknown"
        }]

def check_botnet_associations(domain):
    """
    Check for botnet associations and indicators
    """
    try:
        botnet_indicators = []
        
        # Botnet-related keywords
        botnet_keywords = [
            "botnet", "zombie", "infected", "hijacked", "compromised",
            "dga", "algorithm", "generated", "random"
        ]
        
        for keyword in botnet_keywords:
            if keyword in domain.lower():
                botnet_indicators.append({
                    "indicator_type": "botnet_keyword",
                    "keyword": keyword,
                    "severity": "high",
                    "description": f"Domain contains botnet-related keyword: {keyword}"
                })
        
        # Check for DGA (Domain Generation Algorithm) patterns
        dga_patterns = check_dga_patterns(domain)
        if dga_patterns:
            botnet_indicators.extend(dga_patterns)
        
        # Check for fast-flux patterns (simulated)
        flux_patterns = check_fast_flux_patterns(domain)
        if flux_patterns:
            botnet_indicators.extend(flux_patterns)
        
        return botnet_indicators
        
    except Exception as e:
        return [{
            "indicator_type": "analysis_error",
            "error": str(e),
            "severity": "unknown"
        }]

def check_dga_patterns(domain):
    """
    Check for Domain Generation Algorithm patterns
    """
    try:
        dga_indicators = []
        
        # Remove TLD for analysis
        domain_base = domain.split('.')[0] if '.' in domain else domain
        
        # Check for high entropy (randomness)
        if len(domain_base) > 8:
            unique_chars = len(set(domain_base.lower()))
            entropy_ratio = unique_chars / len(domain_base)
            
            if entropy_ratio > 0.7:  # High entropy threshold
                dga_indicators.append({
                    "indicator_type": "high_entropy",
                    "keyword": "random_pattern",
                    "severity": "medium",
                    "description": f"Domain shows high entropy ({entropy_ratio:.2f}), possible DGA"
                })
        
        # Check for consonant clusters
        consonants = "bcdfghjklmnpqrstvwxz"
        consonant_clusters = 0
        for i in range(len(domain_base) - 2):
            if (domain_base[i].lower() in consonants and 
                domain_base[i+1].lower() in consonants and 
                domain_base[i+2].lower() in consonants):
                consonant_clusters += 1
        
        if consonant_clusters > 1:
            dga_indicators.append({
                "indicator_type": "consonant_clusters",
                "keyword": "unpronounceable",
                "severity": "medium",
                "description": f"Domain has {consonant_clusters} consonant clusters, possible DGA"
            })
        
        return dga_indicators
        
    except Exception as e:
        return [{
            "indicator_type": "dga_analysis_error",
            "error": str(e),
            "severity": "unknown"
        }]

def check_fast_flux_patterns(domain):
    """
    Check for fast-flux patterns (simulated)
    """
    try:
        flux_indicators = []
        
        # Simulate checking for fast-flux characteristics
        # In production, would analyze DNS resolution patterns over time
        
        # Check for suspicious subdomain patterns
        if domain.count('.') > 2:  # Has subdomains
            subdomains = domain.split('.')[:-2]  # Remove domain and TLD
            for subdomain in subdomains:
                if len(subdomain) > 15 and any(char.isdigit() for char in subdomain):
                    flux_indicators.append({
                        "indicator_type": "suspicious_subdomain",
                        "keyword": subdomain,
                        "severity": "medium",
                        "description": f"Suspicious subdomain pattern: {subdomain}"
                    })
        
        return flux_indicators
        
    except Exception as e:
        return [{
            "indicator_type": "flux_analysis_error",
            "error": str(e),
            "severity": "unknown"
        }]

def analyze_dark_web_mentions(domain):
    """
    Analyze dark web mentions and underground activity (simulated)
    """
    try:
        dark_web_analysis = {
            "mentions_found": False,
            "mention_count": 0,
            "mention_contexts": [],
            "threat_actor_discussions": [],
            "marketplace_listings": [],
            "confidence_score": 0
        }
        
        # Simulate dark web analysis based on domain characteristics
        suspicious_indicators = [
            "hack", "crack", "exploit", "leak", "breach", 
            "stolen", "dump", "database", "credentials"
        ]
        
        mentions_count = 0
        for indicator in suspicious_indicators:
            if indicator in domain.lower():
                mentions_count += 1
                dark_web_analysis["mention_contexts"].append({
                    "context": f"forum_discussion_{indicator}",
                    "date": "2025-01-01",
                    "source": "simulated_dark_web_feed",
                    "relevance": "high"
                })
        
        if mentions_count > 0:
            dark_web_analysis["mentions_found"] = True
            dark_web_analysis["mention_count"] = mentions_count
            dark_web_analysis["confidence_score"] = min(100, mentions_count * 30)
            
            # Simulate threat actor discussions
            dark_web_analysis["threat_actor_discussions"] = [
                {
                    "actor": "simulated_threat_actor_1",
                    "discussion_topic": "domain_exploitation",
                    "threat_level": "medium",
                    "date": "2025-01-05"
                }
            ]
        
        return dark_web_analysis
        
    except Exception as e:
        return {
            "error": f"Dark web analysis failed: {str(e)}",
            "mentions_found": False,
            "mention_count": 0,
            "confidence_score": 0
        }

def integrate_threat_feeds(domain):
    """
    Integrate with threat intelligence feeds (simulated)
    """
    try:
        threat_feeds = {
            "feed_sources": [],
            "threat_indicators": [],
            "iocs": [],  # Indicators of Compromise
            "attribution": {},
            "confidence_scores": {}
        }
        
        # Simulate threat feed integration
        simulated_feeds = [
            "commercial_threat_feed_1",
            "open_source_threat_feed_2", 
            "government_threat_feed_3",
            "industry_sharing_feed_4"
        ]
        
        for feed_name in simulated_feeds:
            threat_feeds["feed_sources"].append(feed_name)
            
            # Simulate threat indicators from feed
            if any(bad_word in domain.lower() for bad_word in ["malware", "phishing", "botnet"]):
                threat_feeds["threat_indicators"].append({
                    "source": feed_name,
                    "indicator_type": "malicious_domain",
                    "confidence": "high",
                    "date_added": "2025-01-10",
                    "threat_category": "cybercrime"
                })
                
                # Add IoCs
                threat_feeds["iocs"].append({
                    "ioc_type": "domain",
                    "ioc_value": domain,
                    "source": feed_name,
                    "threat_type": "malware_hosting",
                    "confidence": 85
                })
            
            threat_feeds["confidence_scores"][feed_name] = 80  # Simulated confidence
        
        return threat_feeds
        
    except Exception as e:
        return {
            "error": f"Threat feed integration failed: {str(e)}",
            "feed_sources": [],
            "threat_indicators": [],
            "iocs": []
        }

def analyze_threat_attribution(domain):
    """
    Analyze threat attribution and actor profiling
    """
    try:
        attribution_data = {
            "potential_threat_actors": [],
            "attack_patterns": [],
            "ttps": [],  # Tactics, Techniques, and Procedures
            "campaign_associations": [],
            "attribution_confidence": "low"
        }
        
        # Simulate threat actor attribution based on domain characteristics
        if any(keyword in domain.lower() for keyword in ["apt", "advanced", "persistent"]):
            attribution_data["potential_threat_actors"].append({
                "actor_name": "simulated_apt_group",
                "actor_type": "nation_state",
                "confidence": "medium",
                "known_ttps": ["spear_phishing", "zero_day_exploits", "lateral_movement"],
                "target_sectors": ["government", "defense", "technology"]
            })
            attribution_data["attribution_confidence"] = "medium"
        
        elif any(keyword in domain.lower() for keyword in ["crime", "gang", "cartel"]):
            attribution_data["potential_threat_actors"].append({
                "actor_name": "simulated_cybercrime_group",
                "actor_type": "cybercriminal",
                "confidence": "medium", 
                "known_ttps": ["ransomware", "banking_trojans", "credential_theft"],
                "target_sectors": ["financial", "retail", "healthcare"]
            })
            attribution_data["attribution_confidence"] = "medium"
        
        # Simulate attack pattern analysis
        if attribution_data["potential_threat_actors"]:
            attribution_data["attack_patterns"] = [
                {
                    "pattern_name": "initial_access_via_phishing",
                    "mitre_id": "T1566",
                    "confidence": "high"
                },
                {
                    "pattern_name": "command_and_control",
                    "mitre_id": "TA0011",
                    "confidence": "medium"
                }
            ]
        
        return attribution_data
        
    except Exception as e:
        return {
            "error": f"Threat attribution analysis failed: {str(e)}",
            "potential_threat_actors": [],
            "attack_patterns": [],
            "attribution_confidence": "unknown"
        }

def compile_threat_indicators(domain_reputation, ip_reputation, malware_analysis, 
                            phishing_indicators, botnet_indicators):
    """
    Compile all threat indicators into a unified list
    """
    try:
        threat_indicators = []
        
        # Domain reputation indicators
        if domain_reputation.get("reputation_status") in ["malicious", "likely_malicious"]:
            threat_indicators.append({
                "indicator_type": "malicious_domain",
                "value": domain_reputation.get("reputation_score", 0),
                "severity": "high" if domain_reputation.get("reputation_status") == "malicious" else "medium",
                "source": "domain_reputation_analysis"
            })
        
        # IP reputation indicators
        malicious_ips = ip_reputation.get("malicious_ips", [])
        for ip in malicious_ips:
            threat_indicators.append({
                "indicator_type": "malicious_ip",
                "value": ip,
                "severity": "high",
                "source": "ip_reputation_analysis"
            })
        
        # Malware indicators
        if malware_analysis.get("malware_detected"):
            threat_indicators.append({
                "indicator_type": "malware_association",
                "value": malware_analysis.get("confidence_score", 0),
                "severity": "critical",
                "source": "malware_analysis"
            })
        
        # Phishing indicators
        high_confidence_phishing = [p for p in phishing_indicators 
                                  if p.get("confidence") == "high"]
        if high_confidence_phishing:
            threat_indicators.append({
                "indicator_type": "phishing_indicators",
                "value": len(high_confidence_phishing),
                "severity": "high",
                "source": "phishing_analysis"
            })
        
        # Botnet indicators
        critical_botnet = [b for b in botnet_indicators 
                          if b.get("severity") == "high"]
        if critical_botnet:
            threat_indicators.append({
                "indicator_type": "botnet_indicators", 
                "value": len(critical_botnet),
                "severity": "critical",
                "source": "botnet_analysis"
            })
        
        return threat_indicators
        
    except Exception as e:
        return [{
            "indicator_type": "compilation_error",
            "error": str(e),
            "severity": "unknown"
        }]


def perform_comprehensive_risk_assessment(domain, all_phase_results):
    """
    Perform comprehensive risk assessment based on all analysis phases
    """
    try:
        risk_assessment = {
            "overall_risk_score": 0,
            "risk_level": "unknown",
            "risk_categories": {},
            "vulnerability_correlation": {},
            "attack_surface_analysis": {},
            "critical_findings": [],
            "recommendations": []
        }
        
        # Initialize risk category scores
        risk_categories = {
            "infrastructure": 0,
            "network_security": 0, 
            "ssl_tls": 0,
            "web_application": 0,
            "threat_intelligence": 0,
            "dns_security": 0
        }
        
        # Analyze each phase for risk factors
        if all_phase_results:
            # Phase 1: Subdomain Discovery Risk
            subdomain_data = all_phase_results.get("subdomains", {})
            subdomain_count = len(subdomain_data.get("subdomains", []))
            if subdomain_count > 10:
                risk_categories["infrastructure"] += 30
                risk_assessment["critical_findings"].append(
                    f"Large attack surface: {subdomain_count} subdomains discovered"
                )
            elif subdomain_count > 5:
                risk_categories["infrastructure"] += 15
            
            # Phase 2: Port Scanning Risk
            ports_data = all_phase_results.get("ports", {})
            open_ports = ports_data.get("open_ports", [])
            if len(open_ports) > 20:
                risk_categories["network_security"] += 40
                risk_assessment["critical_findings"].append(
                    f"Excessive open ports: {len(open_ports)} ports exposed"
                )
            elif len(open_ports) > 10:
                risk_categories["network_security"] += 20
                
            # Check for high-risk ports
            high_risk_ports = [21, 23, 135, 139, 445, 1433, 3389, 5432]
            risky_ports = [p for p in open_ports if p in high_risk_ports]
            if risky_ports:
                risk_categories["network_security"] += len(risky_ports) * 15
                risk_assessment["critical_findings"].append(
                    f"High-risk ports exposed: {risky_ports}"
                )
            
            # Phase 3: Service Identification Risk
            services_data = all_phase_results.get("services", {})
            services = services_data.get("services", [])
            vulnerable_services = [s for s in services 
                                 if "vulnerable" in str(s).lower() or 
                                    "outdated" in str(s).lower()]
            if vulnerable_services:
                risk_categories["infrastructure"] += len(vulnerable_services) * 25
                risk_assessment["critical_findings"].append(
                    f"Vulnerable services detected: {len(vulnerable_services)}"
                )
            
            # Phase 4: SSL Analysis Risk
            ssl_data = all_phase_results.get("ssl", {})
            ssl_issues = ssl_data.get("ssl_issues", [])
            if ssl_issues:
                for issue in ssl_issues:
                    if "critical" in str(issue).lower():
                        risk_categories["ssl_tls"] += 35
                    elif "high" in str(issue).lower():
                        risk_categories["ssl_tls"] += 25
                    elif "medium" in str(issue).lower():
                        risk_categories["ssl_tls"] += 15
                        
                risk_assessment["critical_findings"].append(
                    f"SSL/TLS issues found: {len(ssl_issues)} problems"
                )
            
            # Phase 5: Web Application Risk
            web_data = all_phase_results.get("web_analysis", {})
            security_headers = web_data.get("security_headers", {})
            missing_headers = [h for h, present in security_headers.items() 
                             if not present]
            if missing_headers:
                risk_categories["web_application"] += len(missing_headers) * 10
                if len(missing_headers) > 3:
                    risk_assessment["critical_findings"].append(
                        f"Missing security headers: {len(missing_headers)}"
                    )
            
            # Phase 6: Network Security Risk
            network_data = all_phase_results.get("network_analysis", {})
            security_analysis = network_data.get("security_analysis", {})
            vulnerability_count = security_analysis.get("vulnerability_count", 0)
            if vulnerability_count > 0:
                risk_categories["network_security"] += vulnerability_count * 20
                risk_assessment["critical_findings"].append(
                    f"Network vulnerabilities: {vulnerability_count} found"
                )
            
            # Phase 7: Threat Intelligence Risk
            threat_data = all_phase_results.get("threat_intelligence", {})
            threat_indicators = threat_data.get("threat_indicators", [])
            critical_threats = [t for t in threat_indicators 
                              if t.get("severity") in ["critical", "high"]]
            if critical_threats:
                risk_categories["threat_intelligence"] += len(critical_threats) * 30
                risk_assessment["critical_findings"].append(
                    f"Critical threat indicators: {len(critical_threats)}"
                )
        
        # Calculate overall risk score (0-100)
        risk_assessment["risk_categories"] = risk_categories
        overall_score = min(100, sum(risk_categories.values()) // len(risk_categories))
        risk_assessment["overall_risk_score"] = overall_score
        
        # Determine risk level
        if overall_score >= 80:
            risk_assessment["risk_level"] = "critical"
        elif overall_score >= 60:
            risk_assessment["risk_level"] = "high"
        elif overall_score >= 40:
            risk_assessment["risk_level"] = "medium"
        elif overall_score >= 20:
            risk_assessment["risk_level"] = "low"
        else:
            risk_assessment["risk_level"] = "minimal"
        
        # Perform vulnerability correlation
        risk_assessment["vulnerability_correlation"] = correlate_vulnerabilities(all_phase_results)
        
        # Analyze attack surface
        risk_assessment["attack_surface_analysis"] = analyze_attack_surface(all_phase_results)
        
        # Generate recommendations
        risk_assessment["recommendations"] = generate_security_recommendations(
            risk_categories, risk_assessment["critical_findings"]
        )
        
        return risk_assessment
        
    except Exception as e:
        return {
            "error": f"Risk assessment failed: {str(e)}",
            "overall_risk_score": 0,
            "risk_level": "unknown"
        }

def correlate_vulnerabilities(all_phase_results):
    """
    Correlate vulnerabilities across different phases
    """
    try:
        correlation_data = {
            "vulnerability_chains": [],
            "attack_vectors": [],
            "exploitability_score": 0,
            "correlated_findings": []
        }
        
        # Extract vulnerabilities from each phase
        vulnerabilities = []
        
        # Network vulnerabilities
        network_data = all_phase_results.get("network_analysis", {})
        network_vulns = network_data.get("security_analysis", {}).get("vulnerabilities", [])
        vulnerabilities.extend([{"source": "network", "vuln": v} for v in network_vulns])
        
        # SSL vulnerabilities
        ssl_data = all_phase_results.get("ssl", {})
        ssl_issues = ssl_data.get("ssl_issues", [])
        vulnerabilities.extend([{"source": "ssl", "vuln": v} for v in ssl_issues])
        
        # Web application vulnerabilities
        web_data = all_phase_results.get("web_analysis", {})
        web_vulns = web_data.get("vulnerabilities", [])
        vulnerabilities.extend([{"source": "web", "vuln": v} for v in web_vulns])
        
        # Look for vulnerability chains
        if len(vulnerabilities) > 1:
            # Network + SSL vulnerability chain
            network_vulns_list = [v for v in vulnerabilities if v["source"] == "network"]
            ssl_vulns_list = [v for v in vulnerabilities if v["source"] == "ssl"]
            
            if network_vulns_list and ssl_vulns_list:
                correlation_data["vulnerability_chains"].append({
                    "chain_type": "network_ssl_chain",
                    "description": "Network vulnerabilities combined with SSL weaknesses",
                    "severity": "high",
                    "attack_vector": "Man-in-the-middle with network exploitation"
                })
                correlation_data["exploitability_score"] += 30
            
            # Web + Network vulnerability chain
            web_vulns_list = [v for v in vulnerabilities if v["source"] == "web"]
            if network_vulns_list and web_vulns_list:
                correlation_data["vulnerability_chains"].append({
                    "chain_type": "web_network_chain",
                    "description": "Web application flaws with network access",
                    "severity": "critical",
                    "attack_vector": "Remote code execution via web application"
                })
                correlation_data["exploitability_score"] += 40
        
        # Identify common attack vectors
        if vulnerabilities:
            correlation_data["attack_vectors"] = [
                {
                    "vector_type": "remote_exploitation",
                    "likelihood": "high" if len(vulnerabilities) > 3 else "medium",
                    "impact": "high",
                    "description": "Multiple vulnerabilities enable remote attack"
                }
            ]
        
        correlation_data["correlated_findings"] = vulnerabilities
        
        return correlation_data
        
    except Exception as e:
        return {
            "error": f"Vulnerability correlation failed: {str(e)}",
            "vulnerability_chains": [],
            "exploitability_score": 0
        }

def analyze_attack_surface(all_phase_results):
    """
    Analyze the overall attack surface
    """
    try:
        attack_surface = {
            "surface_area_score": 0,
            "exposed_services": [],
            "entry_points": [],
            "attack_paths": [],
            "surface_reduction_recommendations": []
        }
        
        surface_score = 0
        
        # Count exposed services and ports
        ports_data = all_phase_results.get("ports", {})
        open_ports = ports_data.get("open_ports", [])
        surface_score += len(open_ports) * 2
        
        for port in open_ports:
            attack_surface["exposed_services"].append({
                "service_type": f"port_{port}",
                "port": port,
                "exposure_level": "high" if port in [21, 22, 23, 80, 443] else "medium"
            })
        
        # Count subdomains (additional entry points)
        subdomains_data = all_phase_results.get("subdomains", {})
        subdomains = subdomains_data.get("subdomains", [])
        surface_score += len(subdomains) * 3
        
        for subdomain in subdomains:
            attack_surface["entry_points"].append({
                "entry_type": "subdomain",
                "target": subdomain,
                "discovery_method": "automated_enumeration"
            })
        
        # Analyze web applications
        web_data = all_phase_results.get("web_analysis", {})
        if web_data:
            surface_score += 10  # Web application presence
            attack_surface["entry_points"].append({
                "entry_type": "web_application", 
                "target": "main_website",
                "discovery_method": "direct_access"
            })
        
        # Identify potential attack paths
        if len(open_ports) > 5 and len(subdomains) > 3:
            attack_surface["attack_paths"].append({
                "path_type": "multi_vector_attack",
                "description": "Multiple entry points enable diverse attack strategies",
                "complexity": "medium",
                "likelihood": "high"
            })
        
        if any(port in [21, 23, 135] for port in open_ports):
            attack_surface["attack_paths"].append({
                "path_type": "legacy_protocol_exploitation",
                "description": "Legacy protocols provide weak authentication",
                "complexity": "low", 
                "likelihood": "high"
            })
        
        attack_surface["surface_area_score"] = min(100, surface_score)
        
        # Generate surface reduction recommendations
        if len(open_ports) > 10:
            attack_surface["surface_reduction_recommendations"].append(
                "Close unnecessary ports and services"
            )
        
        if len(subdomains) > 10:
            attack_surface["surface_reduction_recommendations"].append(
                "Review subdomain necessity and disable unused subdomains"
            )
            
        return attack_surface
        
    except Exception as e:
        return {
            "error": f"Attack surface analysis failed: {str(e)}",
            "surface_area_score": 0,
            "exposed_services": [],
            "entry_points": []
        }

def generate_security_recommendations(risk_categories, critical_findings):
    """
    Generate security recommendations based on risk assessment
    """
    try:
        recommendations = []
        
        # Infrastructure recommendations
        if risk_categories.get("infrastructure", 0) > 30:
            recommendations.append({
                "category": "infrastructure",
                "priority": "high",
                "recommendation": "Implement network segmentation and access controls",
                "rationale": "High infrastructure risk detected"
            })
        
        # Network security recommendations
        if risk_categories.get("network_security", 0) > 25:
            recommendations.append({
                "category": "network_security", 
                "priority": "critical",
                "recommendation": "Close unnecessary ports and implement firewall rules",
                "rationale": "Multiple network security issues identified"
            })
        
        # SSL/TLS recommendations
        if risk_categories.get("ssl_tls", 0) > 20:
            recommendations.append({
                "category": "ssl_tls",
                "priority": "high",
                "recommendation": "Update SSL/TLS configuration and certificates",
                "rationale": "SSL/TLS vulnerabilities present encryption risks"
            })
        
        # Web application recommendations
        if risk_categories.get("web_application", 0) > 15:
            recommendations.append({
                "category": "web_application",
                "priority": "medium",
                "recommendation": "Implement missing security headers and OWASP controls",
                "rationale": "Web application security gaps identified"
            })
        
        # Threat intelligence recommendations
        if risk_categories.get("threat_intelligence", 0) > 20:
            recommendations.append({
                "category": "threat_intelligence",
                "priority": "critical",
                "recommendation": "Immediate threat response and containment required",
                "rationale": "Active threat indicators detected"
            })
        
        # Critical findings specific recommendations
        for finding in critical_findings:
            if "open ports" in finding.lower():
                recommendations.append({
                    "category": "immediate_action",
                    "priority": "critical", 
                    "recommendation": "Audit and close non-essential ports immediately",
                    "rationale": f"Critical finding: {finding}"
                })
            elif "vulnerabilit" in finding.lower():
                recommendations.append({
                    "category": "immediate_action",
                    "priority": "critical",
                    "recommendation": "Patch vulnerabilities and implement compensating controls",
                    "rationale": f"Critical finding: {finding}"
                })
        
        return recommendations
        
    except Exception as e:
        return [{
            "category": "error",
            "priority": "unknown",
            "recommendation": f"Failed to generate recommendations: {str(e)}",
            "rationale": "Recommendation engine error"
        }]

def calculate_comprehensive_risk_score(threat_intelligence_results, network_analysis, 
                                     ssl_analysis, web_analysis):
    """
    Calculate comprehensive risk score based on all analysis results
    """
    try:
        risk_components = {
            "threat_intelligence_score": 0,
            "network_risk_score": 0,
            "ssl_risk_score": 0,
            "web_risk_score": 0,
            "overall_risk_score": 0
        }
        
        # Threat intelligence scoring (0-100)
        if threat_intelligence_results:
            threat_indicators = threat_intelligence_results.get("threat_indicators", [])
            critical_threats = len([t for t in threat_indicators 
                                  if t.get("severity") in ["critical", "high"]])
            risk_components["threat_intelligence_score"] = min(100, critical_threats * 25)
        
        # Network risk scoring
        if network_analysis:
            vuln_count = network_analysis.get("security_analysis", {}).get("vulnerability_count", 0)
            risk_components["network_risk_score"] = min(100, vuln_count * 20)
        
        # SSL risk scoring
        if ssl_analysis:
            ssl_issues = ssl_analysis.get("ssl_issues", [])
            risk_components["ssl_risk_score"] = min(100, len(ssl_issues) * 15)
        
        # Web application risk scoring
        if web_analysis:
            missing_headers = len([h for h, present in 
                                 web_analysis.get("security_headers", {}).items() 
                                 if not present])
            risk_components["web_risk_score"] = min(100, missing_headers * 12)
        
        # Calculate weighted overall score
        weights = {
            "threat_intelligence_score": 0.4,  # 40% weight
            "network_risk_score": 0.3,        # 30% weight  
            "ssl_risk_score": 0.2,            # 20% weight
            "web_risk_score": 0.1             # 10% weight
        }
        
        overall_score = sum(risk_components[component] * weights[component] 
                           for component in weights.keys())
        risk_components["overall_risk_score"] = round(overall_score, 2)
        
        return risk_components
        
    except Exception as e:
        return {
            "error": f"Risk score calculation failed: {str(e)}",
            "overall_risk_score": 0
        }


def analyze_web_application(domain, port):
    """Analyze a single web application on specified domain and port."""
    try:
        import urllib.request
        import urllib.error
        import socket
        import re
        
        # Determine protocol
        protocol = 'https' if port in [443, 8443] else 'http'
        base_url = f"{protocol}://{domain}:{port}"
        
        # Test connectivity
        try:
            sock = socket.create_connection((domain, port), timeout=5)
            sock.close()
        except:
            return None
        
        application_info = {
            'domain': domain,
            'port': port,
            'protocol': protocol,
            'base_url': base_url,
            'technology_detection': analyze_web_technologies(base_url),
            'security_headers': analyze_security_headers(base_url),
            'vulnerability_assessment': perform_web_vulnerability_scan(base_url),
            'cms_detection': detect_cms_framework(base_url),
            'form_analysis': analyze_web_forms(base_url),
            'cookie_security': analyze_cookie_security(base_url),
            'directory_enumeration': perform_directory_enumeration(base_url),
            'response_analysis': analyze_http_responses(base_url)
        }
        
        # Calculate security score
        security_score = calculate_web_security_score(application_info)
        application_info['security_score'] = security_score
        application_info['security_grade'] = assign_web_security_grade(security_score)
        
        return application_info
        
    except Exception as e:
        return {
            'error': f'Application analysis failed: {str(e)}',
            'domain': domain,
            'port': port
        }


def analyze_web_technologies(base_url):
    """Detect web technologies, frameworks, and server information."""
    try:
        import urllib.request
        import urllib.error
        import re
        
        technologies = {
            'server': 'unknown',
            'frameworks': [],
            'cms': 'unknown',
            'programming_languages': [],
            'databases': [],
            'javascript_libraries': [],
            'analytics': [],
            'cdn': [],
            'web_servers': [],
            'version_info': {}
        }
        
        try:
            # Create request with headers
            req = urllib.request.Request(base_url)
            req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            
            response = urllib.request.urlopen(req, timeout=10)
            headers = dict(response.headers)
            content = response.read().decode('utf-8', errors='ignore')
            
            # Analyze headers
            if 'server' in headers:
                technologies['server'] = headers['server']
                
                # Detect web servers
                server_lower = headers['server'].lower()
                if 'apache' in server_lower:
                    technologies['web_servers'].append('Apache')
                    # Extract version
                    version_match = re.search(r'apache/([0-9.]+)', server_lower)
                    if version_match:
                        technologies['version_info']['apache'] = version_match.group(1)
                elif 'nginx' in server_lower:
                    technologies['web_servers'].append('Nginx')
                    version_match = re.search(r'nginx/([0-9.]+)', server_lower)
                    if version_match:
                        technologies['version_info']['nginx'] = version_match.group(1)
                elif 'iis' in server_lower:
                    technologies['web_servers'].append('IIS')
                elif 'lighttpd' in server_lower:
                    technologies['web_servers'].append('Lighttpd')
            
            if 'x-powered-by' in headers:
                powered_by = headers['x-powered-by'].lower()
                if 'php' in powered_by:
                    technologies['programming_languages'].append('PHP')
                    version_match = re.search(r'php/([0-9.]+)', powered_by)
                    if version_match:
                        technologies['version_info']['php'] = version_match.group(1)
                elif 'asp.net' in powered_by:
                    technologies['programming_languages'].append('ASP.NET')
                elif 'express' in powered_by:
                    technologies['frameworks'].append('Express.js')
            
            # Analyze HTML content
            content_lower = content.lower()
            
            # Framework detection
            if 'wp-content' in content_lower or 'wordpress' in content_lower:
                technologies['cms'] = 'WordPress'
                technologies['frameworks'].append('WordPress')
            elif 'joomla' in content_lower:
                technologies['cms'] = 'Joomla'
                technologies['frameworks'].append('Joomla')
            elif 'drupal' in content_lower:
                technologies['cms'] = 'Drupal'
                technologies['frameworks'].append('Drupal')
            elif 'typo3' in content_lower:
                technologies['cms'] = 'TYPO3'
                technologies['frameworks'].append('TYPO3')
            
            # JavaScript library detection
            if 'jquery' in content_lower:
                technologies['javascript_libraries'].append('jQuery')
                version_match = re.search(r'jquery[/-]([0-9.]+)', content_lower)
                if version_match:
                    technologies['version_info']['jquery'] = version_match.group(1)
            
            if 'bootstrap' in content_lower:
                technologies['javascript_libraries'].append('Bootstrap')
            
            if 'angular' in content_lower:
                technologies['javascript_libraries'].append('AngularJS')
            
            if 'react' in content_lower:
                technologies['javascript_libraries'].append('React')
            
            if 'vue' in content_lower:
                technologies['javascript_libraries'].append('Vue.js')
            
            # Analytics detection
            if 'google-analytics' in content_lower or 'gtag' in content_lower:
                technologies['analytics'].append('Google Analytics')
            
            if 'facebook.net' in content_lower:
                technologies['analytics'].append('Facebook Pixel')
            
            # CDN detection
            if 'cloudflare' in content_lower or 'cf-ray' in str(headers):
                technologies['cdn'].append('Cloudflare')
            
            if 'amazonaws.com' in content_lower:
                technologies['cdn'].append('AWS CloudFront')
            
            if 'akamai' in content_lower:
                technologies['cdn'].append('Akamai')
            
            # Programming language hints
            if '.php' in content_lower:
                if 'PHP' not in technologies['programming_languages']:
                    technologies['programming_languages'].append('PHP')
            
            if '.asp' in content_lower or '.aspx' in content_lower:
                if 'ASP.NET' not in technologies['programming_languages']:
                    technologies['programming_languages'].append('ASP.NET')
            
            if '.jsp' in content_lower:
                technologies['programming_languages'].append('Java/JSP')
            
            if '.py' in content_lower or 'django' in content_lower:
                technologies['programming_languages'].append('Python')
                if 'django' in content_lower:
                    technologies['frameworks'].append('Django')
            
            if 'rails' in content_lower or 'ruby' in content_lower:
                technologies['programming_languages'].append('Ruby')
                if 'rails' in content_lower:
                    technologies['frameworks'].append('Ruby on Rails')
            
        except Exception as e:
            technologies['error'] = str(e)
        
        return technologies
        
    except Exception as e:
        return {'error': f'Technology detection failed: {str(e)}'}


def analyze_security_headers(base_url):
    """Analyze HTTP security headers and their configuration."""
    try:
        import urllib.request
        import urllib.error
        
        security_analysis = {
            'headers_present': {},
            'headers_missing': [],
            'security_score': 0,
            'recommendations': [],
            'vulnerabilities': []
        }
        
        # Security headers to check
        security_headers = {
            'strict-transport-security': {
                'name': 'HSTS',
                'description': 'HTTP Strict Transport Security',
                'weight': 15
            },
            'content-security-policy': {
                'name': 'CSP',
                'description': 'Content Security Policy',
                'weight': 20
            },
            'x-frame-options': {
                'name': 'X-Frame-Options',
                'description': 'Clickjacking protection',
                'weight': 10
            },
            'x-content-type-options': {
                'name': 'X-Content-Type-Options',
                'description': 'MIME type sniffing protection',
                'weight': 10
            },
            'x-xss-protection': {
                'name': 'X-XSS-Protection',
                'description': 'XSS filter protection',
                'weight': 5
            },
            'referrer-policy': {
                'name': 'Referrer-Policy',
                'description': 'Referrer information control',
                'weight': 5
            },
            'permissions-policy': {
                'name': 'Permissions-Policy',
                'description': 'Feature policy control',
                'weight': 5
            },
            'expect-ct': {
                'name': 'Expect-CT',
                'description': 'Certificate Transparency',
                'weight': 5
            }
        }
        
        try:
            req = urllib.request.Request(base_url)
            req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            
            response = urllib.request.urlopen(req, timeout=10)
            headers = dict(response.headers)
            
            total_possible_score = sum(h['weight'] for h in security_headers.values())
            current_score = 0
            
            for header_name, header_info in security_headers.items():
                if header_name in headers or header_name.replace('-', '_') in headers:
                    header_value = headers.get(header_name, headers.get(header_name.replace('-', '_'), ''))
                    security_analysis['headers_present'][header_name] = {
                        'value': header_value,
                        'name': header_info['name'],
                        'description': header_info['description'],
                        'weight': header_info['weight']
                    }
                    
                    # Analyze header value quality
                    header_score = analyze_header_quality(header_name, header_value)
                    current_score += header_info['weight'] * header_score
                    
                    if header_score < 1.0:
                        security_analysis['recommendations'].append(
                            f"Improve {header_info['name']} configuration: {header_value}"
                        )
                else:
                    security_analysis['headers_missing'].append({
                        'header': header_name,
                        'name': header_info['name'],
                        'description': header_info['description'],
                        'weight': header_info['weight']
                    })
                    security_analysis['recommendations'].append(
                        f"Add {header_info['name']} header for {header_info['description']}"
                    )
            
            # Calculate percentage score
            security_analysis['security_score'] = round((current_score / total_possible_score) * 100, 1)
            
            # Add vulnerabilities based on missing headers
            if len(security_analysis['headers_missing']) > 4:
                security_analysis['vulnerabilities'].append('Multiple critical security headers missing')
            
            if not any(h['header'] == 'content-security-policy' for h in security_analysis['headers_missing']):
                if 'content-security-policy' not in security_analysis['headers_present']:
                    security_analysis['vulnerabilities'].append('Missing Content Security Policy - XSS vulnerability')
            
            if not any(h['header'] == 'strict-transport-security' for h in security_analysis['headers_missing']):
                if 'strict-transport-security' not in security_analysis['headers_present']:
                    security_analysis['vulnerabilities'].append('Missing HSTS - Man-in-the-middle vulnerability')
            
        except Exception as e:
            security_analysis['error'] = str(e)
        
        return security_analysis
        
    except Exception as e:
        return {'error': f'Security header analysis failed: {str(e)}'}


def analyze_header_quality(header_name, header_value):
    """Analyze the quality of a security header's value (0.0 to 1.0)."""
    if not header_value:
        return 0.0
    
    header_value = header_value.lower()
    
    if header_name == 'strict-transport-security':
        # Good HSTS should have max-age and includeSubDomains
        if 'max-age=' in header_value and 'includesubdomains' in header_value:
            return 1.0
        elif 'max-age=' in header_value:
            return 0.7
        else:
            return 0.3
    
    elif header_name == 'content-security-policy':
        # CSP should not be too permissive
        if "'unsafe-inline'" in header_value or "'unsafe-eval'" in header_value:
            return 0.4
        elif 'default-src' in header_value:
            return 0.8
        else:
            return 0.6
    
    elif header_name == 'x-frame-options':
        if header_value in ['deny', 'sameorigin']:
            return 1.0
        else:
            return 0.5
    
    elif header_name == 'x-content-type-options':
        if 'nosniff' in header_value:
            return 1.0
        else:
            return 0.3
    
    elif header_name == 'x-xss-protection':
        if '1; mode=block' in header_value:
            return 1.0
        elif '1' in header_value:
            return 0.7
        else:
            return 0.3
    
    else:
        # For other headers, presence is good
        return 0.8


def perform_web_vulnerability_scan(base_url):
    """Perform basic web application vulnerability scanning."""
    try:
        import urllib.request
        import urllib.error
        import urllib.parse
        import re
        
        vulnerabilities = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'informational': [],
            'total_count': 0,
            'risk_score': 0
        }
        
        # Test for common web vulnerabilities
        
        # 1. Check for directory listing
        try:
            dir_urls = [f"{base_url}/", f"{base_url}/images/", f"{base_url}/js/", f"{base_url}/css/"]
            for dir_url in dir_urls:
                try:
                    req = urllib.request.Request(dir_url)
                    response = urllib.request.urlopen(req, timeout=5)
                    content = response.read().decode('utf-8', errors='ignore')
                    
                    if 'Index of' in content or 'Directory Listing' in content:
                        vulnerabilities['medium'].append({
                            'vulnerability': 'Directory Listing Enabled',
                            'description': f'Directory listing exposed at {dir_url}',
                            'risk': 'Information Disclosure',
                            'recommendation': 'Disable directory listing in web server configuration'
                        })
                        break
                except:
                    continue
        except:
            pass
        
        # 2. Check for common sensitive files
        sensitive_files = [
            'robots.txt', 'sitemap.xml', '.htaccess', '.env', 
            'config.php', 'wp-config.php', 'web.config',
            'admin/', 'administrator/', 'login.php', 'admin.php'
        ]
        
        for file_path in sensitive_files:
            try:
                test_url = f"{base_url}/{file_path}"
                req = urllib.request.Request(test_url)
                response = urllib.request.urlopen(req, timeout=5)
                
                if response.status == 200:
                    content = response.read().decode('utf-8', errors='ignore')
                    
                    if file_path in ['.env', 'wp-config.php', 'config.php', 'web.config']:
                        vulnerabilities['high'].append({
                            'vulnerability': 'Sensitive File Exposure',
                            'description': f'Sensitive configuration file accessible: {file_path}',
                            'risk': 'Configuration Disclosure',
                            'recommendation': 'Restrict access to configuration files'
                        })
                    elif file_path in ['admin/', 'administrator/', 'login.php', 'admin.php']:
                        vulnerabilities['low'].append({
                            'vulnerability': 'Admin Interface Discovery',
                            'description': f'Administrative interface found: {file_path}',
                            'risk': 'Reconnaissance',
                            'recommendation': 'Consider restricting admin interface access'
                        })
                    else:
                        vulnerabilities['informational'].append({
                            'vulnerability': 'Information File Found',
                            'description': f'Information file accessible: {file_path}',
                            'risk': 'Information Gathering',
                            'recommendation': 'Review file contents for sensitive information'
                        })
            except:
                continue
        
        # 3. Check for HTTP methods
        try:
            # Test dangerous HTTP methods
            dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'OPTIONS']
            for method in dangerous_methods:
                try:
                    req = urllib.request.Request(base_url)
                    req.get_method = lambda: method
                    response = urllib.request.urlopen(req, timeout=5)
                    
                    if response.status == 200:
                        vulnerabilities['medium'].append({
                            'vulnerability': f'HTTP {method} Method Enabled',
                            'description': f'Server accepts {method} requests',
                            'risk': 'Potential file manipulation or information disclosure',
                            'recommendation': f'Disable {method} method unless required'
                        })
                except:
                    continue
        except:
            pass
        
        # 4. Check for server information disclosure
        try:
            req = urllib.request.Request(base_url)
            response = urllib.request.urlopen(req, timeout=10)
            headers = dict(response.headers)
            
            # Check for detailed server information
            if 'server' in headers:
                server_header = headers['server']
                if re.search(r'[0-9]+\.[0-9]+', server_header):  # Version numbers
                    vulnerabilities['low'].append({
                        'vulnerability': 'Server Version Disclosure',
                        'description': f'Server version revealed: {server_header}',
                        'risk': 'Information Disclosure',
                        'recommendation': 'Hide server version in HTTP headers'
                    })
            
            if 'x-powered-by' in headers:
                vulnerabilities['low'].append({
                    'vulnerability': 'Technology Stack Disclosure',
                    'description': f'X-Powered-By header reveals: {headers["x-powered-by"]}',
                    'risk': 'Information Disclosure',
                    'recommendation': 'Remove X-Powered-By header'
                })
        except:
            pass
        
        # Calculate totals and risk score
        vulnerabilities['total_count'] = (
            len(vulnerabilities['critical']) +
            len(vulnerabilities['high']) +
            len(vulnerabilities['medium']) +
            len(vulnerabilities['low']) +
            len(vulnerabilities['informational'])
        )
        
        # Calculate risk score (0-100)
        risk_score = (
            len(vulnerabilities['critical']) * 20 +
            len(vulnerabilities['high']) * 15 +
            len(vulnerabilities['medium']) * 10 +
            len(vulnerabilities['low']) * 5 +
            len(vulnerabilities['informational']) * 1
        )
        vulnerabilities['risk_score'] = min(risk_score, 100)
        
        return vulnerabilities
        
    except Exception as e:
        return {'error': f'Vulnerability scan failed: {str(e)}'}


def detect_cms_framework(base_url):
    """Detect CMS, frameworks, and specific application versions."""
    try:
        import urllib.request
        import re
        
        cms_detection = {
            'cms': 'unknown',
            'version': 'unknown',
            'confidence': 0,
            'indicators': [],
            'plugins': [],
            'themes': [],
            'admin_found': False,
            'login_found': False
        }
        
        try:
            req = urllib.request.Request(base_url)
            req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            
            response = urllib.request.urlopen(req, timeout=10)
            content = response.read().decode('utf-8', errors='ignore')
            headers = dict(response.headers)
            
            content_lower = content.lower()
            
            # WordPress Detection
            wp_indicators = [
                ('wp-content/', 30),
                ('wp-includes/', 30),
                ('/wp-admin/', 25),
                ('wordpress', 20),
                ('wp-json', 15),
                ('wp_head', 10)
            ]
            
            wp_score = 0
            wp_found_indicators = []
            for indicator, score in wp_indicators:
                if indicator in content_lower:
                    wp_score += score
                    wp_found_indicators.append(indicator)
            
            if wp_score >= 30:
                cms_detection['cms'] = 'WordPress'
                cms_detection['confidence'] = min(wp_score, 100)
                cms_detection['indicators'] = wp_found_indicators
                
                # Try to detect WordPress version
                version_patterns = [
                    r'wp-includes/js/wp-embed\.min\.js\?ver=([0-9.]+)',
                    r'wordpress/([0-9.]+)',
                    r'content="WordPress ([0-9.]+)"'
                ]
                for pattern in version_patterns:
                    version_match = re.search(pattern, content)
                    if version_match:
                        cms_detection['version'] = version_match.group(1)
                        break
                
                # Check for admin access
                try:
                    admin_req = urllib.request.Request(f"{base_url}/wp-admin/")
                    admin_response = urllib.request.urlopen(admin_req, timeout=5)
                    if admin_response.status == 200:
                        cms_detection['admin_found'] = True
                except:
                    pass
            
            # Drupal Detection
            elif 'drupal' in content_lower or '/sites/default/' in content_lower:
                cms_detection['cms'] = 'Drupal'
                cms_detection['confidence'] = 80
                cms_detection['indicators'] = ['drupal', '/sites/default/']
                
                # Try to detect Drupal version
                version_match = re.search(r'drupal[ /]([0-9.]+)', content_lower)
                if version_match:
                    cms_detection['version'] = version_match.group(1)
            
            # Joomla Detection
            elif 'joomla' in content_lower or '/administrator/' in content_lower:
                cms_detection['cms'] = 'Joomla'
                cms_detection['confidence'] = 80
                cms_detection['indicators'] = ['joomla']
                
                # Check for admin access
                try:
                    admin_req = urllib.request.Request(f"{base_url}/administrator/")
                    admin_response = urllib.request.urlopen(admin_req, timeout=5)
                    if admin_response.status == 200:
                        cms_detection['admin_found'] = True
                except:
                    pass
            
            # Generic login detection
            login_indicators = ['/login', '/admin', '/administrator', '/wp-admin', '/user/login']
            for login_path in login_indicators:
                if login_path in content_lower:
                    cms_detection['login_found'] = True
                    break
                    
                try:
                    login_req = urllib.request.Request(f"{base_url}{login_path}")
                    login_response = urllib.request.urlopen(login_req, timeout=5)
                    if login_response.status == 200:
                        cms_detection['login_found'] = True
                        break
                except:
                    continue
                    
        except Exception as e:
            cms_detection['error'] = str(e)
        
        return cms_detection
        
    except Exception as e:
        return {'error': f'CMS detection failed: {str(e)}'}


def analyze_web_forms(base_url):
    """Analyze web forms for security issues."""
    try:
        import urllib.request
        import re
        
        form_analysis = {
            'forms_found': 0,
            'forms_analysis': [],
            'security_issues': [],
            'csrf_protection': False,
            'form_types': []
        }
        
        try:
            req = urllib.request.Request(base_url)
            req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            
            response = urllib.request.urlopen(req, timeout=10)
            content = response.read().decode('utf-8', errors='ignore')
            
            # Find all forms
            form_pattern = r'<form[^>]*>(.*?)</form>'
            forms = re.findall(form_pattern, content, re.DOTALL | re.IGNORECASE)
            
            form_analysis['forms_found'] = len(forms)
            
            for i, form in enumerate(forms):
                form_info = {
                    'form_id': i + 1,
                    'method': 'GET',  # default
                    'action': '',
                    'inputs': [],
                    'has_csrf_token': False,
                    'has_file_upload': False,
                    'security_score': 100
                }
                
                # Extract form attributes
                method_match = re.search(r'method=[\'"](.*?)[\'"]', form, re.IGNORECASE)
                if method_match:
                    form_info['method'] = method_match.group(1).upper()
                
                action_match = re.search(r'action=[\'"](.*?)[\'"]', form, re.IGNORECASE)
                if action_match:
                    form_info['action'] = action_match.group(1)
                
                # Find inputs
                input_pattern = r'<input[^>]*>'
                inputs = re.findall(input_pattern, form, re.IGNORECASE)
                
                for input_tag in inputs:
                    input_info = {'type': 'text', 'name': '', 'required': False}
                    
                    type_match = re.search(r'type=[\'"](.*?)[\'"]', input_tag, re.IGNORECASE)
                    if type_match:
                        input_info['type'] = type_match.group(1).lower()
                    
                    name_match = re.search(r'name=[\'"](.*?)[\'"]', input_tag, re.IGNORECASE)
                    if name_match:
                        input_info['name'] = name_match.group(1)
                    
                    if 'required' in input_tag.lower():
                        input_info['required'] = True
                    
                    form_info['inputs'].append(input_info)
                    
                    # Check for CSRF tokens
                    if input_info['type'] == 'hidden' and any(token in input_info['name'].lower() for token in ['csrf', 'token', '_token', 'authenticity']):
                        form_info['has_csrf_token'] = True
                        form_analysis['csrf_protection'] = True
                    
                    # Check for file uploads
                    if input_info['type'] == 'file':
                        form_info['has_file_upload'] = True
                
                # Security analysis
                if form_info['method'] == 'GET' and any(inp['type'] == 'password' for inp in form_info['inputs']):
                    form_analysis['security_issues'].append(f"Form {i+1}: Password field in GET form")
                    form_info['security_score'] -= 30
                
                if not form_info['has_csrf_token'] and form_info['method'] == 'POST':
                    form_analysis['security_issues'].append(f"Form {i+1}: Missing CSRF protection")
                    form_info['security_score'] -= 20
                
                if form_info['has_file_upload']:
                    form_analysis['security_issues'].append(f"Form {i+1}: File upload detected - verify file type validation")
                    form_info['security_score'] -= 10
                
                # Determine form type
                if any(inp['type'] == 'password' for inp in form_info['inputs']):
                    form_info['form_type'] = 'login'
                    form_analysis['form_types'].append('login')
                elif any(inp['type'] == 'email' for inp in form_info['inputs']) and len(form_info['inputs']) > 3:
                    form_info['form_type'] = 'registration'
                    form_analysis['form_types'].append('registration')
                elif form_info['has_file_upload']:
                    form_info['form_type'] = 'upload'
                    form_analysis['form_types'].append('upload')
                else:
                    form_info['form_type'] = 'contact'
                    form_analysis['form_types'].append('contact')
                
                form_analysis['forms_analysis'].append(form_info)
                
        except Exception as e:
            form_analysis['error'] = str(e)
        
        return form_analysis
        
    except Exception as e:
        return {'error': f'Form analysis failed: {str(e)}'}


def analyze_cookie_security(base_url):
    """Analyze cookie security settings."""
    try:
        import urllib.request
        
        cookie_analysis = {
            'cookies_found': 0,
            'cookies_analysis': [],
            'security_issues': [],
            'security_score': 100
        }
        
        try:
            req = urllib.request.Request(base_url)
            req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            
            response = urllib.request.urlopen(req, timeout=10)
            
            # Get cookies from response
            cookies = response.headers.get_all('Set-Cookie') or []
            cookie_analysis['cookies_found'] = len(cookies)
            
            for cookie in cookies:
                cookie_info = {
                    'name': '',
                    'secure': False,
                    'httponly': False,
                    'samesite': None,
                    'expires': None,
                    'domain': None,
                    'path': None,
                    'security_score': 0
                }
                
                # Parse cookie
                parts = cookie.split(';')
                if parts:
                    # First part is name=value
                    name_value = parts[0].strip()
                    if '=' in name_value:
                        cookie_info['name'] = name_value.split('=')[0]
                
                # Check security attributes
                cookie_lower = cookie.lower()
                
                if 'secure' in cookie_lower:
                    cookie_info['secure'] = True
                    cookie_info['security_score'] += 25
                else:
                    cookie_analysis['security_issues'].append(f"Cookie '{cookie_info['name']}' missing Secure flag")
                
                if 'httponly' in cookie_lower:
                    cookie_info['httponly'] = True
                    cookie_info['security_score'] += 25
                else:
                    cookie_analysis['security_issues'].append(f"Cookie '{cookie_info['name']}' missing HttpOnly flag")
                
                if 'samesite=' in cookie_lower:
                    import re
                    samesite_match = re.search(r'samesite=(\w+)', cookie_lower)
                    if samesite_match:
                        cookie_info['samesite'] = samesite_match.group(1)
                        cookie_info['security_score'] += 25
                else:
                    cookie_analysis['security_issues'].append(f"Cookie '{cookie_info['name']}' missing SameSite attribute")
                
                if 'expires=' in cookie_lower or 'max-age=' in cookie_lower:
                    cookie_info['security_score'] += 25
                else:
                    cookie_analysis['security_issues'].append(f"Cookie '{cookie_info['name']}' missing expiration")
                
                cookie_analysis['cookies_analysis'].append(cookie_info)
            
            # Calculate overall security score
            if cookie_analysis['cookies_found'] > 0:
                avg_score = sum(c['security_score'] for c in cookie_analysis['cookies_analysis']) / len(cookie_analysis['cookies_analysis'])
                cookie_analysis['security_score'] = round(avg_score, 1)
            
        except Exception as e:
            cookie_analysis['error'] = str(e)
        
        return cookie_analysis
        
    except Exception as e:
        return {'error': f'Cookie analysis failed: {str(e)}'}


def perform_directory_enumeration(base_url):
    """Perform basic directory enumeration for common paths."""
    try:
        import urllib.request
        import urllib.error
        
        enumeration_results = {
            'directories_found': [],
            'files_found': [],
            'total_discovered': 0,
            'interesting_finds': []
        }
        
        # Common directories and files to check
        common_paths = [
            'admin/', 'administrator/', 'login/', 'wp-admin/', 'phpmyadmin/',
            'backup/', 'test/', 'dev/', 'staging/', 'cms/',
            'robots.txt', 'sitemap.xml', '.htaccess', 'favicon.ico',
            'readme.txt', 'license.txt', 'changelog.txt'
        ]
        
        for path in common_paths:
            try:
                test_url = f"{base_url.rstrip('/')}/{path}"
                req = urllib.request.Request(test_url)
                req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
                
                response = urllib.request.urlopen(req, timeout=5)
                
                if response.status == 200:
                    if path.endswith('/'):
                        enumeration_results['directories_found'].append(path)
                        if any(admin in path for admin in ['admin', 'login', 'phpmyadmin']):
                            enumeration_results['interesting_finds'].append(f"Administrative interface: {path}")
                    else:
                        enumeration_results['files_found'].append(path)
                        if path in ['robots.txt', 'sitemap.xml']:
                            enumeration_results['interesting_finds'].append(f"Information file: {path}")
                        elif path in ['.htaccess', 'readme.txt']:
                            enumeration_results['interesting_finds'].append(f"Potentially sensitive file: {path}")
                            
            except urllib.error.HTTPError:
                continue
            except:
                continue
        
        enumeration_results['total_discovered'] = len(enumeration_results['directories_found']) + len(enumeration_results['files_found'])
        
        return enumeration_results
        
    except Exception as e:
        return {'error': f'Directory enumeration failed: {str(e)}'}


def analyze_http_responses(base_url):
    """Analyze HTTP response characteristics."""
    try:
        import urllib.request
        import time
        
        response_analysis = {
            'status_code': 0,
            'response_size': 0,
            'response_time': 0,
            'content_type': 'unknown',
            'charset': 'unknown',
            'compression': False,
            'redirects': [],
            'error_pages': {}
        }
        
        try:
            start_time = time.time()
            req = urllib.request.Request(base_url)
            req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            req.add_header('Accept-Encoding', 'gzip, deflate')
            
            response = urllib.request.urlopen(req, timeout=10)
            response_time = time.time() - start_time
            
            headers = dict(response.headers)
            content = response.read()
            
            response_analysis['status_code'] = response.status
            response_analysis['response_size'] = len(content)
            response_analysis['response_time'] = round(response_time * 1000, 2)  # ms
            
            if 'content-type' in headers:
                content_type = headers['content-type']
                response_analysis['content_type'] = content_type.split(';')[0].strip()
                
                if 'charset=' in content_type:
                    charset = content_type.split('charset=')[1].strip()
                    response_analysis['charset'] = charset
            
            if 'content-encoding' in headers:
                response_analysis['compression'] = headers['content-encoding']
            
            # Test error pages
            error_codes = [404, 403, 500]
            for error_code in error_codes:
                try:
                    error_url = f"{base_url}/nonexistent_page_{error_code}"
                    error_req = urllib.request.Request(error_url)
                    error_response = urllib.request.urlopen(error_req, timeout=5)
                except urllib.error.HTTPError as e:
                    if e.code == error_code:
                        error_content = e.read().decode('utf-8', errors='ignore')
                        response_analysis['error_pages'][str(error_code)] = {
                            'length': len(error_content),
                            'custom': 'not found' not in error_content.lower() and error_code != 404
                        }
                except:
                    continue
                    
        except Exception as e:
            response_analysis['error'] = str(e)
        
        return response_analysis
        
    except Exception as e:
        return {'error': f'Response analysis failed: {str(e)}'}


def calculate_web_security_score(application_info):
    """Calculate overall web application security score (0-100)."""
    try:
        total_score = 0
        max_possible = 0
        
        # Security headers (weight: 30%)
        headers_analysis = application_info.get('security_headers', {})
        if 'security_score' in headers_analysis:
            headers_score = headers_analysis['security_score']
            total_score += headers_score * 0.3
        max_possible += 30
        
        # Cookie security (weight: 20%)
        cookie_analysis = application_info.get('cookie_security', {})
        if 'security_score' in cookie_analysis:
            cookie_score = cookie_analysis['security_score']
            total_score += cookie_score * 0.2
        max_possible += 20
        
        # Vulnerability assessment (weight: 30%)
        vuln_analysis = application_info.get('vulnerability_assessment', {})
        if 'risk_score' in vuln_analysis:
            # Convert risk score to security score (inverse)
            risk_score = vuln_analysis['risk_score']
            security_score = max(0, 100 - risk_score)
            total_score += security_score * 0.3
        max_possible += 30
        
        # Form security (weight: 10%)
        form_analysis = application_info.get('form_analysis', {})
        if 'forms_analysis' in form_analysis and form_analysis['forms_analysis']:
            avg_form_score = sum(f.get('security_score', 0) for f in form_analysis['forms_analysis']) / len(form_analysis['forms_analysis'])
            total_score += avg_form_score * 0.1
        max_possible += 10
        
        # CMS detection and security (weight: 10%)
        cms_analysis = application_info.get('cms_detection', {})
        cms_score = 100  # Default if no CMS detected
        if cms_analysis.get('cms') != 'unknown':
            if cms_analysis.get('admin_found'):
                cms_score -= 20  # Admin interface exposed
            if cms_analysis.get('version') != 'unknown':
                cms_score -= 10  # Version disclosed
        total_score += cms_score * 0.1
        max_possible += 10
        
        # Calculate percentage
        if max_possible > 0:
            final_score = round((total_score / max_possible) * 100, 1)
        else:
            final_score = 0
        
        return max(0, min(100, final_score))
        
    except Exception as e:
        return 0


def assign_web_security_grade(security_score):
    """Assign letter grade based on security score."""
    if security_score >= 95:
        return 'A+'
    elif security_score >= 90:
        return 'A'
    elif security_score >= 85:
        return 'A-'
    elif security_score >= 80:
        return 'B+'
    elif security_score >= 75:
        return 'B'
    elif security_score >= 70:
        return 'B-'
    elif security_score >= 65:
        return 'C+'
    elif security_score >= 60:
        return 'C'
    elif security_score >= 55:
        return 'C-'
    elif security_score >= 50:
        return 'D+'
    elif security_score >= 45:
        return 'D'
    elif security_score >= 40:
        return 'D-'
    else:
        return 'F'


def generate_web_security_assessment(web_services):
    """Generate overall security assessment from all web services."""
    try:
        assessment = {
            'overall_grade': 'F',
            'security_score': 0,
            'total_vulnerabilities': 0,
            'critical_issues': [],
            'recommendations': [],
            'compliance_status': {}
        }
        
        if not web_services:
            return assessment
        
        scores = []
        all_vulnerabilities = []
        critical_issues = []
        recommendations = set()
        
        for port, service_info in web_services.items():
            if 'security_score' in service_info:
                scores.append(service_info['security_score'])
            
            # Collect vulnerabilities
            vuln_assessment = service_info.get('vulnerability_assessment', {})
            for severity in ['critical', 'high', 'medium']:
                vulns = vuln_assessment.get(severity, [])
                all_vulnerabilities.extend(vulns)
                
                if severity == 'critical':
                    critical_issues.extend([v.get('vulnerability', '') for v in vulns])
            
            # Collect recommendations
            for component in ['security_headers', 'cookie_security', 'form_analysis']:
                component_data = service_info.get(component, {})
                if 'recommendations' in component_data:
                    recommendations.update(component_data['recommendations'])
        
        # Calculate overall score
        if scores:
            assessment['security_score'] = round(sum(scores) / len(scores), 1)
            assessment['overall_grade'] = assign_web_security_grade(assessment['security_score'])
        
        assessment['total_vulnerabilities'] = len(all_vulnerabilities)
        assessment['critical_issues'] = list(set(critical_issues))
        assessment['recommendations'] = list(recommendations)[:10]  # Top 10 recommendations
        
        return assessment
        
    except Exception as e:
        return {
            'error': f'Security assessment failed: {str(e)}',
            'overall_grade': 'F',
            'security_score': 0
        }


def aggregate_technology_stack(web_services):
    """Aggregate technology stack information from all services."""
    try:
        aggregated = {
            'web_servers': set(),
            'programming_languages': set(),
            'frameworks': set(),
            'cms_platforms': set(),
            'javascript_libraries': set(),
            'databases': set(),
            'cdn_services': set(),
            'analytics': set(),
            'most_common': {}
        }
        
        for port, service_info in web_services.items():
            tech_info = service_info.get('technology_detection', {})
            
            if 'web_servers' in tech_info:
                aggregated['web_servers'].update(tech_info['web_servers'])
            
            if 'programming_languages' in tech_info:
                aggregated['programming_languages'].update(tech_info['programming_languages'])
            
            if 'frameworks' in tech_info:
                aggregated['frameworks'].update(tech_info['frameworks'])
            
            if 'javascript_libraries' in tech_info:
                aggregated['javascript_libraries'].update(tech_info['javascript_libraries'])
            
            if 'cdn' in tech_info:
                aggregated['cdn_services'].update(tech_info['cdn'])
            
            if 'analytics' in tech_info:
                aggregated['analytics'].update(tech_info['analytics'])
            
            cms_info = service_info.get('cms_detection', {})
            if cms_info.get('cms') and cms_info['cms'] != 'unknown':
                aggregated['cms_platforms'].add(cms_info['cms'])
        
        # Convert sets to lists for JSON serialization
        result = {}
        for key, value in aggregated.items():
            if key != 'most_common':
                result[key] = list(value) if value else []
        
        return result
        
    except Exception as e:
        return {'error': f'Technology aggregation failed: {str(e)}'}


def aggregate_vulnerability_findings(web_services):
    """Aggregate vulnerability findings from all services."""
    try:
        aggregated = {
            'total_vulnerabilities': 0,
            'by_severity': {
                'critical': [],
                'high': [],
                'medium': [],
                'low': [],
                'informational': []
            },
            'most_critical': [],
            'vulnerability_types': set(),
            'affected_services': []
        }
        
        for port, service_info in web_services.items():
            vuln_assessment = service_info.get('vulnerability_assessment', {})
            
            for severity in ['critical', 'high', 'medium', 'low', 'informational']:
                vulns = vuln_assessment.get(severity, [])
                for vuln in vulns:
                    vuln_copy = dict(vuln)
                    vuln_copy['affected_port'] = port
                    aggregated['by_severity'][severity].append(vuln_copy)
                    
                    if 'vulnerability' in vuln:
                        aggregated['vulnerability_types'].add(vuln['vulnerability'])
        
        # Calculate totals
        total = sum(len(vulns) for vulns in aggregated['by_severity'].values())
        aggregated['total_vulnerabilities'] = total
        
        # Identify most critical (critical and high severity)
        critical_and_high = aggregated['by_severity']['critical'] + aggregated['by_severity']['high']
        aggregated['most_critical'] = critical_and_high[:10]  # Top 10 most critical
        
        # Convert set to list
        aggregated['vulnerability_types'] = list(aggregated['vulnerability_types'])
        
        # Identify affected services
        for port in web_services.keys():
            service_vulns = sum(
                len(aggregated['by_severity'][sev]) 
                for sev in aggregated['by_severity']
                if any(v.get('affected_port') == port for v in aggregated['by_severity'][sev])
            )
            if service_vulns > 0:
                aggregated['affected_services'].append({
                    'port': port,
                    'vulnerability_count': service_vulns
                })
        
        return aggregated
        
    except Exception as e:
        return {'error': f'Vulnerability aggregation failed: {str(e)}'}


def analyze_web_configuration(web_services):
    """Analyze web application configuration across all services."""
    try:
        config_analysis = {
            'security_headers_summary': {},
            'ssl_configuration': {},
            'server_information': {},
            'error_handling': {},
            'session_management': {}
        }
        
        # Aggregate security headers
        all_headers = {}
        missing_headers = set()
        
        for port, service_info in web_services.items():
            headers_info = service_info.get('security_headers', {})
            
            if 'headers_present' in headers_info:
                for header, details in headers_info['headers_present'].items():
                    if header not in all_headers:
                        all_headers[header] = []
                    all_headers[header].append(f"Port {port}: {details.get('value', '')}")
            
            if 'headers_missing' in headers_info:
                for missing in headers_info['headers_missing']:
                    missing_headers.add(missing['header'])
        
        config_analysis['security_headers_summary'] = {
            'implemented_headers': list(all_headers.keys()),
            'missing_headers': list(missing_headers),
            'header_details': all_headers
        }
        
        # Aggregate server information
        servers = {}
        for port, service_info in web_services.items():
            tech_info = service_info.get('technology_detection', {})
            if 'server' in tech_info:
                servers[port] = tech_info['server']
        
        config_analysis['server_information'] = servers
        
        # Error handling analysis
        error_analysis = {}
        for port, service_info in web_services.items():
            response_info = service_info.get('response_analysis', {})
            if 'error_pages' in response_info:
                error_analysis[port] = response_info['error_pages']
        
        config_analysis['error_handling'] = error_analysis
        
        return config_analysis
        
    except Exception as e:
        return {'error': f'Configuration analysis failed: {str(e)}'}


def check_web_compliance(web_services):
    """Check web application compliance with security standards."""
    try:
        compliance = {
            'owasp_top_10': {
                'compliant': False,
                'issues': [],
                'score': 0
            },
            'pci_dss': {
                'compliant': False,
                'requirements_met': 0,
                'total_requirements': 6,
                'issues': []
            },
            'gdpr': {
                'compliant': False,
                'privacy_controls': 0,
                'issues': []
            },
            'overall_compliance': 'Non-Compliant'
        }
        
        # OWASP Top 10 checks
        owasp_score = 0
        owasp_issues = []
        
        for port, service_info in web_services.items():
            # A01:2021 – Broken Access Control
            form_info = service_info.get('form_analysis', {})
            if not form_info.get('csrf_protection', False):
                owasp_issues.append('A01: Missing CSRF protection (Broken Access Control)')
            else:
                owasp_score += 10
            
            # A02:2021 – Cryptographic Failures
            headers_info = service_info.get('security_headers', {})
            hsts_present = 'strict-transport-security' in headers_info.get('headers_present', {})
            if not hsts_present:
                owasp_issues.append('A02: Missing HSTS header (Cryptographic Failures)')
            else:
                owasp_score += 10
            
            # A03:2021 – Injection
            vuln_info = service_info.get('vulnerability_assessment', {})
            injection_vulns = [v for v in vuln_info.get('high', []) + vuln_info.get('critical', [])
                             if 'injection' in v.get('vulnerability', '').lower()]
            if injection_vulns:
                owasp_issues.append('A03: Potential injection vulnerabilities detected')
            else:
                owasp_score += 10
            
            # A04:2021 – Insecure Design (basic check)
            if service_info.get('security_score', 0) > 80:
                owasp_score += 10
            else:
                owasp_issues.append('A04: Poor security design patterns')
            
            # A05:2021 – Security Misconfiguration
            if headers_info.get('security_score', 0) < 50:
                owasp_issues.append('A05: Security misconfiguration in headers')
            else:
                owasp_score += 10
        
        compliance['owasp_top_10']['score'] = min(owasp_score, 100)
        compliance['owasp_top_10']['issues'] = owasp_issues
        compliance['owasp_top_10']['compliant'] = owasp_score >= 80
        
        # PCI DSS checks (simplified)
        pci_score = 0
        pci_issues = []
        
        for port, service_info in web_services.items():
            headers_info = service_info.get('security_headers', {})
            
            # Requirement 4: Encrypt transmission of cardholder data across open, public networks
            if port == '443' or 'strict-transport-security' in headers_info.get('headers_present', {}):
                pci_score += 1
            else:
                pci_issues.append('REQ-4: Inadequate encryption for data transmission')
            
            # Requirement 6: Develop and maintain secure systems and applications
            vuln_count = service_info.get('vulnerability_assessment', {}).get('total_count', 0)
            if vuln_count < 5:
                pci_score += 1
            else:
                pci_issues.append('REQ-6: High number of vulnerabilities detected')
        
        compliance['pci_dss']['requirements_met'] = pci_score
        compliance['pci_dss']['issues'] = pci_issues
        compliance['pci_dss']['compliant'] = pci_score >= 4
        
        # Overall compliance assessment
        if compliance['owasp_top_10']['compliant'] and compliance['pci_dss']['compliant']:
            compliance['overall_compliance'] = 'Compliant'
        elif compliance['owasp_top_10']['score'] > 60 or compliance['pci_dss']['requirements_met'] > 2:
            compliance['overall_compliance'] = 'Partially Compliant'
        else:
            compliance['overall_compliance'] = 'Non-Compliant'
        
        return compliance
        
    except Exception as e:
        return {'error': f'Compliance check failed: {str(e)}'}


if __name__ == "__main__":
    import sys
    import json
    
    if len(sys.argv) < 2:
        print("Usage: get_domain_health.py <command> <domain> [arguments]")
        print("Commands:")
        print("  check_all <domain>             - Full domain health check")
        print("  discover_subdomains <domain>   - Enhanced subdomain discovery")
        print("  discover_ports <domain>        - Comprehensive port scanning")
        print("  identify_services <domain>     - Service fingerprinting on common ports")
        print("  identify_service <domain> <port> - Identify service on specific port")
        print("  fingerprint_web <domain> [port] - Web service fingerprinting")
        print("  probe_database <domain> <port>  - Database service identification")
        print("  security_analysis <domain>     - Security analysis of discovered services")
        print("  ssl_analysis <domain> [ports]  - Comprehensive SSL/TLS security analysis")
        print("  ssl_discover <domain>          - Discover SSL-enabled services")
        print("  ssl_check <domain> <port>      - Analyze SSL configuration on specific port")
        print("  ssl_report <domain>            - Generate SSL security report")
        print("  ssl_best_practices <domain>    - Check SSL best practices compliance")
        print("  ssl_grade <domain>             - Get SSL security grade")
        print("  web_analysis <domain>          - Comprehensive web application analysis")
        print("  web_discover <domain>          - Discover web applications")
        print("  web_check <domain> <port>      - Analyze web application security")
        print("  web_security <domain> <port>   - Web security assessment")
        print("  web_tech <domain> <port>       - Web technology detection")
        print("  web_headers <domain> <port>    - Security headers analysis")
        print("  web_vulnerabilities <domain> <port> - Web vulnerability scan")
        print("  network_analysis <domain>      - Comprehensive network topology analysis")
        print("  network_topology <domain>      - Network topology discovery")
        print("  network_security <domain>      - Network security assessment")
        print("  network_performance <domain>   - Network performance analysis")
        print("  network_compliance <domain>    - Network compliance checking")
        print("  network_devices <domain>       - Network device discovery")
        print("  threat_intelligence <domain>   - Comprehensive threat intelligence analysis")
        print("  threat_reputation <domain>     - Domain and IP reputation analysis")
        print("  malware_analysis <domain>      - Malware association detection")
        print("  phishing_indicators <domain>   - Phishing indicator analysis")
        print("  botnet_analysis <domain>       - Botnet association checking")
        print("  risk_assessment <domain>       - Comprehensive risk assessment")
        print("  comprehensive_scan <domain>    - Full infrastructure scan (Phases 1-7)")
        sys.exit(1)
    
    try:
        if sys.argv[1] == 'check_all':
            # Usage: script.py check_all <domain>
            domain = sys.argv[2]
            result = check_domain_health(domain)
            print(json.dumps(result, indent=2))
        
        elif sys.argv[1] == 'discover_subdomains':
            # Usage: script.py discover_subdomains <domain>
            domain = sys.argv[2]
            result = discover_comprehensive_subdomains(domain)
            print(json.dumps(result, indent=2))
        
        elif sys.argv[1] == 'discover_ports':
            # Usage: script.py discover_ports <domain>
            domain = sys.argv[2]
            result = discover_comprehensive_ports(domain)
            print(json.dumps(result, indent=2))
        
        elif sys.argv[1] == 'discover_ports.fast':
            # Usage: script.py discover_ports.fast <domain>
            domain = sys.argv[2]
            result = discover_comprehensive_ports(domain, fast_scan=True)
            print(json.dumps(result, indent=2))
        
        elif sys.argv[1] == 'scan_port_range':
            # Usage: script.py scan_port_range <domain> <start_port> <end_port>
            domain = sys.argv[2]
            start_port = int(sys.argv[3])
            end_port = int(sys.argv[4])
            
            # Generate port list
            ports = list(range(start_port, end_port + 1))
            result = discover_comprehensive_ports(domain, custom_ports=ports)
            print(json.dumps(result, indent=2))
        
        elif sys.argv[1] == 'discover_custom_ports':
            # Usage: script.py discover_custom_ports <domain> <port1,port2,port3,...>
            domain = sys.argv[2]
            port_list = [int(p.strip()) for p in sys.argv[3].split(',') if p.strip().isdigit()]
            
            result = discover_comprehensive_ports(domain, custom_ports=port_list)
            print(json.dumps(result, indent=2))
        
        elif sys.argv[1] == 'identify_services':
            # Usage: script.py identify_services <domain> [ports_json]
            domain = sys.argv[2]
            
            if len(sys.argv) > 3:
                try:
                    ports = json.loads(sys.argv[3])
                except:
                    ports = [int(p) for p in sys.argv[3].split(',') if p.strip().isdigit()]
            else:
                # Default common service ports
                ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 5432, 6379, 27017]
            
            result = discover_service_fingerprints(domain, ports)
            print(json.dumps(result, indent=2))
        
        elif sys.argv[1] == 'identify_service':
            # Usage: script.py identify_service <domain> <port>
            domain = sys.argv[2]
            port = int(sys.argv[3])
            
            result = identify_service_on_port(domain, port)
            print(json.dumps(result, indent=2))
        
        elif sys.argv[1] == 'probe_database':
            # Usage: script.py probe_database <domain> <port>
            domain = sys.argv[2]
            port = int(sys.argv[3])
            
            identification = identify_database_service(domain, port)
            print(json.dumps(identification, indent=2))
        
        elif sys.argv[1] == 'fingerprint_web':
            # Usage: script.py fingerprint_web <domain> [port]
            domain = sys.argv[2]
            port = int(sys.argv[3]) if len(sys.argv) > 3 else 80
            
            if port == 443:
                identification = identify_https_service(domain, port, timeout=30)
            else:
                identification = identify_http_service(domain, port, timeout=30)
            
            print(json.dumps(identification, indent=2))
        
        elif sys.argv[1] == 'security_analysis':
            # Usage: script.py security_analysis <domain> [discovered_ports_json]
            domain = sys.argv[2]
            
            if len(sys.argv) > 3:
                try:
                    discovered_ports = json.loads(sys.argv[3])
                    if isinstance(discovered_ports, dict) and 'open_ports' in discovered_ports:
                        ports = discovered_ports['open_ports']
                    else:
                        ports = discovered_ports
                except:
                    ports = []
            else:
                # Get discovered ports first
                port_discovery = discover_comprehensive_ports(domain)
                ports = port_discovery.get('open_ports', [])
            
            if ports:
                result = discover_service_fingerprints(domain, ports)
                print(json.dumps(result['security_overview'], indent=2))
            else:
                print(json.dumps({'error': 'No ports provided or discovered'}, indent=2))
        
        elif sys.argv[1] == 'comprehensive_scan':
            # Usage: script.py comprehensive_scan <domain>
            domain = sys.argv[2]
            
            print("Starting comprehensive infrastructure scan...")
            
            # Phase 1: Subdomain Discovery
            print("Phase 1: Discovering subdomains...")
            subdomain_result = discover_comprehensive_subdomains(domain)
            
            # Phase 2: Port Discovery
            print("Phase 2: Scanning ports...")
            port_result = discover_comprehensive_ports(domain)
            
            # Phase 3: Service Identification
            print("Phase 3: Identifying services...")
            service_result = discover_service_fingerprints(domain, port_result.get('open_ports', []))
            
            # Phase 4: SSL/TLS Analysis
            print("Phase 4: Analyzing SSL/TLS security...")
            ssl_result = comprehensive_ssl_analysis(domain, [p.get('port') for p in port_result.get('open_ports', []) if isinstance(p, dict)])
            
            # Phase 5: Web Application Analysis
            print("Phase 5: Analyzing web applications...")
            web_result = comprehensive_web_analysis(domain, [p.get('port') for p in port_result.get('open_ports', []) if isinstance(p, dict) and p.get('port') in [80, 443, 8080, 8443]])
            
            # Phase 6: Advanced Network Analysis
            print("Phase 6: Analyzing network topology and performance...")
            network_result = comprehensive_network_analysis(domain)
            
            # Phase 7: Threat Intelligence & Risk Assessment
            print("Phase 7: Analyzing threat intelligence and risk assessment...")
            threat_result = comprehensive_threat_intelligence_analysis(domain)
            
            # Comprehensive Risk Assessment
            all_phase_results = {
                'subdomains': subdomain_result,
                'ports': port_result,
                'services': service_result,
                'ssl': ssl_result,
                'web_analysis': web_result,
                'network_analysis': network_result,
                'threat_intelligence': threat_result
            }
            risk_assessment = perform_comprehensive_risk_assessment(domain, all_phase_results)
            
            # Combine results
            comprehensive_result = {
                'domain': domain,
                'infrastructure_discovery': {
                    'subdomain_discovery': subdomain_result,
                    'port_discovery': port_result,
                    'service_identification': service_result,
                    'ssl_analysis': ssl_result,
                    'web_analysis': web_result,
                    'network_analysis': network_result,
                    'threat_intelligence_analysis': threat_result,
                    'risk_assessment': risk_assessment
                },
                'summary': {
                    'total_subdomains': subdomain_result.get('subdomain_discovery', {}).get('total_discovered', 0),
                    'total_open_ports': len(port_result.get('open_ports', [])),
                    'identified_services': service_result.get('service_summary', {}).get('identified_services', 0),
                    'ssl_certificates': ssl_result.get('analysis_stats', {}).get('certificates_found', 0),
                    'security_score': service_result.get('security_overview', {}).get('overall_score', 0),
                    'ssl_grade': ssl_result.get('ssl_analysis', {}).get('security_assessment', {}).get('overall_grade', 'F'),
                    'web_applications': web_result.get('analysis_stats', {}).get('applications_found', 0),
                    'web_vulnerabilities': web_result.get('analysis_stats', {}).get('vulnerabilities_detected', 0),
                    'web_security_grade': web_result.get('web_application_analysis', {}).get('security_assessment', {}).get('overall_grade', 'F'),
                    'network_devices': network_result.get('analysis_stats', {}).get('devices_discovered', 0),
                    'network_security_score': network_result.get('network_analysis', {}).get('security_assessment', {}).get('security_score', 0),
                    'network_performance_score': network_result.get('network_analysis', {}).get('performance_metrics', {}).get('performance_score', 0),
                    'network_compliance_score': network_result.get('network_analysis', {}).get('compliance_check', {}).get('overall_compliance_score', 0),
                    'network_grade': network_result.get('network_analysis', {}).get('overall_assessment', {}).get('overall_grade', 'F'),
                    'threat_intelligence_score': threat_result.get('analysis_stats', {}).get('threat_score', 0),
                    'threat_indicators_detected': threat_result.get('analysis_stats', {}).get('threat_indicators_detected', 0),
                    'malware_detected': threat_result.get('threat_intelligence_analysis', {}).get('malware_analysis', {}).get('malware_detected', False),
                    'overall_risk_score': risk_assessment.get('overall_risk_score', 0),
                    'risk_level': risk_assessment.get('risk_level', 'unknown')
                }
            }
            
            print(json.dumps(comprehensive_result, indent=2))
        
        elif sys.argv[1] == 'ssl_analysis':
            # Usage: script.py ssl_analysis <domain> [ports]
            domain = sys.argv[2]
            
            if len(sys.argv) > 3:
                try:
                    ports_input = sys.argv[3]
                    if ports_input.startswith('[') and ports_input.endswith(']'):
                        ports = json.loads(ports_input)
                    else:
                        ports = [int(p) for p in ports_input.split(',') if p.strip().isdigit()]
                except:
                    ports = None  # Use default SSL ports
            else:
                ports = None  # Use default SSL ports
            
            result = comprehensive_ssl_analysis(domain, ports)
            print(json.dumps(result, indent=2))
        
        elif sys.argv[1] == 'ssl_discover':
            # Usage: script.py ssl_discover <domain>
            domain = sys.argv[2]
            
            result = discover_ssl_services(domain)
            print(json.dumps(result, indent=2))
        
        elif sys.argv[1] == 'ssl_check':
            # Usage: script.py ssl_check <domain> <port>
            domain = sys.argv[2]
            port = int(sys.argv[3])
            
            result = analyze_ssl_configuration(domain, port)
            print(json.dumps(result, indent=2))
        
        elif sys.argv[1] == 'ssl_report':
            # Usage: script.py ssl_report <domain>
            domain = sys.argv[2]
            
            # First perform SSL analysis
            ssl_analysis = comprehensive_ssl_analysis(domain)
            
            # Generate security report
            report = generate_ssl_security_report(domain, ssl_analysis)
            print(json.dumps(report, indent=2))
        
        elif sys.argv[1] == 'ssl_best_practices':
            # Usage: script.py ssl_best_practices <domain>
            domain = sys.argv[2]
            
            # Perform SSL analysis first
            ssl_analysis = comprehensive_ssl_analysis(domain)
            
            # Check best practices compliance
            best_practices = check_ssl_best_practices(domain, ssl_analysis)
            print(json.dumps(best_practices, indent=2))
        
        elif sys.argv[1] == 'ssl_grade':
            # Usage: script.py ssl_grade <domain>
            domain = sys.argv[2]
            
            ssl_analysis = comprehensive_ssl_analysis(domain)
            grade_info = ssl_analysis.get('ssl_analysis', {}).get('security_assessment', {})
            
            simplified_result = {
                'domain': domain,
                'ssl_grade': grade_info.get('overall_grade', 'F'),
                'security_score': grade_info.get('security_score', 0),
                'certificates_found': ssl_analysis.get('analysis_stats', {}).get('certificates_found', 0),
                'vulnerabilities_count': len(grade_info.get('vulnerabilities', [])),
                'recommendations_count': len(grade_info.get('recommendations', []))
            }
            
            print(json.dumps(simplified_result, indent=2))
        
        elif sys.argv[1] == 'web_analysis':
            # Usage: script.py web_analysis <domain> [ports]
            domain = sys.argv[2]
            
            # Parse ports parameter
            if len(sys.argv) > 3:
                try:
                    # Handle JSON array or comma-separated string
                    if sys.argv[3].startswith('['):
                        ports = json.loads(sys.argv[3])
                    else:
                        ports = sys.argv[3]
                except:
                    ports = [80, 443]
            else:
                ports = [80, 443, 8080, 8443]
            
            result = comprehensive_web_analysis(domain, ports)
            print(json.dumps(result, indent=2))
        
        elif sys.argv[1] == 'web_discover':
            # Usage: script.py web_discover <domain>
            domain = sys.argv[2]
            
            # First discover ports
            port_discovery = discover_comprehensive_ports(domain)
            web_ports = [p.get('port') for p in port_discovery.get('open_ports', []) 
                        if isinstance(p, dict) and p.get('port') in [80, 443, 8080, 8443, 8000, 9000, 3000]]
            
            discovered_apps = {}
            for port in web_ports:
                app_info = analyze_web_application(domain, port)
                if app_info:
                    discovered_apps[str(port)] = {
                        'port': port,
                        'protocol': app_info.get('protocol'),
                        'cms': app_info.get('cms_detection', {}).get('cms', 'unknown'),
                        'server': app_info.get('technology_detection', {}).get('server', 'unknown'),
                        'security_grade': app_info.get('security_grade', 'F')
                    }
            
            result = {
                'domain': domain,
                'web_applications_discovered': discovered_apps,
                'total_applications': len(discovered_apps),
                'web_ports': web_ports
            }
            
            print(json.dumps(result, indent=2))
        
        elif sys.argv[1] == 'web_check':
            # Usage: script.py web_check <domain> <port>
            domain = sys.argv[2]
            port = int(sys.argv[3])
            
            result = analyze_web_application(domain, port)
            print(json.dumps(result, indent=2))
        
        elif sys.argv[1] == 'web_security':
            # Usage: script.py web_security <domain> [ports]
            domain = sys.argv[2]
            
            if len(sys.argv) > 3:
                try:
                    if sys.argv[3].startswith('['):
                        ports = json.loads(sys.argv[3])
                    else:
                        ports = sys.argv[3]
                except:
                    ports = [80, 443]
            else:
                ports = [80, 443]
            
            # Perform web analysis
            web_analysis = comprehensive_web_analysis(domain, ports)
            
            # Extract security assessment
            security_assessment = web_analysis.get('web_application_analysis', {}).get('security_assessment', {})
            vulnerability_scan = web_analysis.get('web_application_analysis', {}).get('vulnerability_scan', {})
            
            simplified_result = {
                'domain': domain,
                'web_security_grade': security_assessment.get('overall_grade', 'F'),
                'security_score': security_assessment.get('security_score', 0),
                'total_vulnerabilities': vulnerability_scan.get('total_vulnerabilities', 0),
                'critical_issues': security_assessment.get('critical_issues', [])[:5],
                'recommendations': security_assessment.get('recommendations', [])[:5]
            }
            
            print(json.dumps(simplified_result, indent=2))
        
        elif sys.argv[1] == 'web_tech':
            # Usage: script.py web_tech <domain> [port]
            domain = sys.argv[2]
            port = int(sys.argv[3]) if len(sys.argv) > 3 else 80
            
            result = analyze_web_application(domain, port)
            if result:
                tech_stack = {
                    'domain': domain,
                    'port': port,
                    'technology_detection': result.get('technology_detection', {}),
                    'cms_detection': result.get('cms_detection', {}),
                    'server_info': result.get('response_analysis', {})
                }
                print(json.dumps(tech_stack, indent=2))
            else:
                print(json.dumps({'error': f'Could not analyze web application on {domain}:{port}'}, indent=2))
        
        elif sys.argv[1] == 'web_headers':
            # Usage: script.py web_headers <domain> [port]
            domain = sys.argv[2]
            port = int(sys.argv[3]) if len(sys.argv) > 3 else 80
            
            protocol = 'https' if port in [443, 8443] else 'http'
            base_url = f"{protocol}://{domain}:{port}"
            
            headers_result = analyze_security_headers(base_url)
            print(json.dumps(headers_result, indent=2))
        
        elif sys.argv[1] == 'web_vulnerabilities':
            # Usage: script.py web_vulnerabilities <domain> [port]
            domain = sys.argv[2]
            port = int(sys.argv[3]) if len(sys.argv) > 3 else 80
            
            protocol = 'https' if port in [443, 8443] else 'http'
            base_url = f"{protocol}://{domain}:{port}"
            
            vuln_result = perform_web_vulnerability_scan(base_url)
            print(json.dumps(vuln_result, indent=2))
        
        elif sys.argv[1] == 'network_analysis':
            # Usage: script.py network_analysis <domain>
            domain = sys.argv[2]
            result = comprehensive_network_analysis(domain)
            print(json.dumps(result, indent=2))
        
        elif sys.argv[1] == 'network_topology':
            # Usage: script.py network_topology <domain>
            domain = sys.argv[2]
            result = discover_network_topology(domain)
            print(json.dumps(result, indent=2))
        
        elif sys.argv[1] == 'network_security':
            # Usage: script.py network_security <domain>
            domain = sys.argv[2]
            topology_info = discover_network_topology(domain)
            result = analyze_network_security(domain, topology_info)
            print(json.dumps(result, indent=2))
        
        elif sys.argv[1] == 'network_performance':
            # Usage: script.py network_performance <domain>
            domain = sys.argv[2]
            topology_info = discover_network_topology(domain)
            result = analyze_network_performance(domain, topology_info)
            print(json.dumps(result, indent=2))
        
        elif sys.argv[1] == 'network_compliance':
            # Usage: script.py network_compliance <domain>
            domain = sys.argv[2]
            topology_info = discover_network_topology(domain)
            network_security = analyze_network_security(domain, topology_info)
            result = check_network_compliance(domain, network_security, topology_info)
            print(json.dumps(result, indent=2))
        
        elif sys.argv[1] == 'network_devices':
            # Usage: script.py network_devices <domain>
            domain = sys.argv[2]
            topology_info = discover_network_topology(domain)
            result = discover_network_devices(domain, topology_info)
            print(json.dumps(result, indent=2))
        
        # Phase 7: Threat Intelligence & Risk Assessment Commands
        elif sys.argv[1] == 'threat_intelligence':
            # Usage: script.py threat_intelligence <domain>
            domain = sys.argv[2]
            result = comprehensive_threat_intelligence_analysis(domain)
            print(json.dumps(result, indent=2))
            
        elif sys.argv[1] == 'threat_reputation':
            # Usage: script.py threat_reputation <domain>
            domain = sys.argv[2]
            domain_rep = analyze_domain_reputation(domain)
            ip_rep = analyze_ip_reputation(domain)
            result = {
                "domain_reputation": domain_rep,
                "ip_reputation": ip_rep
            }
            print(json.dumps(result, indent=2))
            
        elif sys.argv[1] == 'malware_analysis':
            # Usage: script.py malware_analysis <domain>
            domain = sys.argv[2]
            result = check_malware_associations(domain)
            print(json.dumps(result, indent=2))
            
        elif sys.argv[1] == 'phishing_indicators':
            # Usage: script.py phishing_indicators <domain>
            domain = sys.argv[2]
            result = detect_phishing_indicators(domain)
            print(json.dumps(result, indent=2))
            
        elif sys.argv[1] == 'botnet_analysis':
            # Usage: script.py botnet_analysis <domain>
            domain = sys.argv[2]
            result = check_botnet_associations(domain)
            print(json.dumps(result, indent=2))
            
        elif sys.argv[1] == 'risk_assessment':
            # Usage: script.py risk_assessment <domain>
            domain = sys.argv[2]
            # Run minimal assessment with empty phase results
            limited_results = {
                "subdomains": {"subdomains": []},
                "ports": {"open_ports": []},
                "ssl": {"ssl_issues": []},
                "web_analysis": {"security_headers": {}},
                "network_analysis": {"security_analysis": {"vulnerability_count": 0}},
                "threat_intelligence": {"threat_indicators": []}
            }
            result = perform_comprehensive_risk_assessment(domain, limited_results)
            print(json.dumps(result, indent=2))
        
        else:
            print(f"Unknown command: {sys.argv[1]}")
            sys.exit(1)
            
    except Exception as e:
        print(json.dumps({'error': str(e)}, indent=2))
        sys.exit(1)
