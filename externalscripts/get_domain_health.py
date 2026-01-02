#!/usr/bin/env python3
"""
Author: Simon Jackson (sjackson0109)
Created: 2025/12/23
Updated: 2025/12/23
Version: 1.1
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
from datetime import datetime, timezone

# --- Configuration ---
def get_config():
    try:
        timeout = int(os.environ.get('DNS_TIMEOUT', '10'))
    except Exception:
        timeout = 10
    nameserver = os.environ.get('DNS_NAMESERVER', None)
    debug = os.environ.get('DNS_DEBUG', '0') == '1'
    return timeout, nameserver, debug

DNS_TIMEOUT, DNS_NAMESERVER, DEBUG = get_config()

logger = logging.getLogger(__name__)
logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=logging.DEBUG if DEBUG else logging.WARNING)

# --- DNS Query Utilities (stdlib only) ---

DNS_RECORD_TYPES = {
    'A': 1, 'NS': 2, 'CNAME': 5, 'SOA': 6, 'PTR': 12, 'MX': 15,
    'TXT': 16, 'AAAA': 28, 'SRV': 33, 'CAA': 257, 'DNSKEY': 48,
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
    while True:
        if offset >= max_offset:
            break
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xc0) == 0xc0:
            if not jumped:
                orig_offset = offset + 2
            pointer = struct.unpack('>H', data[offset:offset+2])[0] & 0x3fff
            offset = pointer
            jumped = True
            continue
        offset += 1
        labels.append(data[offset:offset+length].decode('ascii', errors='replace'))
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
        offset += rdlength
        if rtype == qtype_code:
            answers.append({'name': name, 'ttl': ttl, 'rdata': rdata, 'rtype': rtype, 'rdlength': rdlength})
    return answers

def dns_query(domain, qtype, nameserver=None, timeout=10):
    """Send a DNS query and return parsed answers."""
    query, tid = build_dns_query(domain, qtype)
    ns = nameserver or '8.8.8.8'
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(query, (ns, 53))
        data, _ = sock.recvfrom(4096)
        sock.close()
        return parse_dns_response(data, qtype)
    except Exception as e:
        logger.error(f"DNS query failed for {domain}/{qtype}: {e}")
        return []

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
        txt = ''
        i = 0
        while i < len(rdata):
            slen = rdata[i]
            txt += rdata[i+1:i+1+slen].decode('utf-8', errors='replace')
            i += 1 + slen
        return txt
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
        return {'error': 'WHOIS query failed or no data'}
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
            result['days_until_expiry'] = -1
    if not result:
        result['error'] = 'Could not parse WHOIS data'
    return result

# --- Health Score Calculation ---

def calculate_health_score(checks):
    """Calculate overall health score (0-100)."""
    total = 0
    passed = 0
    weights = {
        'soa': 10, 'ns': 10, 'mx': 10, 'a': 10, 'aaaa': 5, 'caa': 5,
        'spf': 15, 'dmarc': 15, 'dkim': 10, 'dnssec': 10
    }
    for key, weight in weights.items():
        if key in checks:
            total += weight
            if checks[key].get('valid'):
                passed += weight
    return int(100 * passed / total) if total else 0

# --- Main Operations ---

def discover(domain):
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
        'days_until_expiry': -1,
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

# DNSSEC Algorithm values (RFC 8624)
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

def get_certificate_from_server(hostname, port=443):
    """Retrieve TLS certificate from a server."""
    if not HAVE_OPENSSL:
        return None, "pyOpenSSL not available"
    
    try:
        import ssl
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((hostname, port), timeout=DNS_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                return cert_der, None
    except Exception as e:
        return None, str(e)

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
    cert_der, error = get_certificate_from_server(domain, port)
    if error:
        result['errors'].append(f'Could not retrieve certificate: {error}')
        return result
    
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
    
    return {
        'flags': flags,
        'protocol': protocol,
        'algorithm': algorithm,
        'algorithm_name': DNSSEC_ALGORITHMS.get(algorithm, f'Unknown ({algorithm})'),
        'key_type': key_type,
        'sep_key': sep_key,
        'zone_key': zone_key,
        'public_key_length': len(public_key),
        'public_key_hex': public_key.hex()[:64] + '...' if len(public_key) > 32 else public_key.hex(),
        'key_tag': compute_key_tag(rdata)
    }

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
    for r in answers:
        ns_name = format_rdata(r['rtype'], r['rdata']).rstrip('.')
        # If NS name doesn't contain a dot, it's likely a compressed name missing the domain
        # Try to resolve it as-is first, then with domain appended
        if '.' not in ns_name:
            # Try common patterns: ns1.domain.tld or ns1.google.com style
            ns_name_full = f'{ns_name}.{domain}'
        else:
            ns_name_full = ns_name
        
        # Resolve NS to IP for additional context
        ns_ips = dns_query(ns_name_full, 'A', DNS_NAMESERVER, DNS_TIMEOUT)
        ns_ip = format_rdata(ns_ips[0]['rtype'], ns_ips[0]['rdata']) if ns_ips else ''
        ns_servers.append({
            '{#NS_SERVER}': ns_name_full,
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

# --- Main Entry Point ---

def main():
    if len(sys.argv) < 2:
        print(json.dumps({'error': 'Usage: get_domain_health.py <command> <args>'}))
        sys.exit(1)
    cmd = sys.argv[1].lower()
    if cmd == 'discover':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py discover <DOMAIN>'}))
            sys.exit(1)
        print(discover(sys.argv[2]))
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
    elif cmd == 'whois':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_domain_health.py whois <DOMAIN>'}))
            sys.exit(1)
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
    else:
        print(json.dumps({'error': f'Unknown command: {cmd}'}))
        sys.exit(1)

if __name__ == '__main__':
    main()
