#!/usr/bin/env python3
"""
Author: Simon Jackson (sjackson0109)
Created: 2025/03/03
Updated: 2026/01/12
Version: 3.3

Description:
    TLS Handshake Testing & Protocol Analysis for Zabbix.
    Tests TLS handshake capabilities with specified endpoints, dynamically detects 
    available SSL/TLS protocols and ciphers, and provides comprehensive support status.

Features:
    - Dynamic protocol and cipher detection from client system
    - Comprehensive cipher_suites structure with 1/0 support status
    - All protocol-cipher combinations tested and reported
    - Timestamp-free output for efficient Zabbix discard_unchanged processing
    - Individual protocol-cipher testing against endpoints
    - Zabbix-friendly JSON output for monitoring integration
    - Function-driven CLI architecture for modular operations
    - Cross-platform support (Linux, Windows, Docker containers)
    - Configurable timeouts and error handling
    - Discovery and validation modes for monitoring workflows

USAGE EXAMPLES:
    python get_tls_health.py discover <HOST> [PORT]
    python get_tls_health.py check <HOST> <PROTOCOL> <CIPHER> [PORT]
    python get_tls_health.py protocols
    python get_tls_health.py ciphers
    python get_tls_health.py test <HOST> <PROTOCOL> <CIPHER> [PORT]
    python get_tls_health.py compatibility <HOST> [PORT]
    python get_tls_health.py health <HOST> [PORT]

ENVIRONMENT VARIABLES:
    TLS_TIMEOUT (default: 4)
    TLS_DEBUG (set to 1 for debug logging)

OUTPUT:
    - All operations return valid JSON for Zabbix compatibility
    - Discovery command provides comprehensive cipher_suites with support status (1/0)
    - Timestamp-free for efficient database storage and change detection
    - On error, returns a JSON object with an 'error' key
"""

import json
import sys
import ssl
import socket
import warnings
import os
import logging
from datetime import datetime

# --- Configuration ---
def get_config():
    """Get configuration from environment variables."""
    try:
        timeout = int(os.environ.get('TLS_TIMEOUT', '4'))
    except Exception:
        timeout = 4
    debug = os.environ.get('TLS_DEBUG', '0') == '1'
    return timeout, debug

TLS_TIMEOUT, DEBUG = get_config()

logger = logging.getLogger(__name__)
logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', 
                   level=logging.DEBUG if DEBUG else logging.WARNING)

# --- Protocol and Cipher Management ---

PROTOCOL_MAP = {
    "PROTOCOL_SSLv1": "SSLv1.0",
    "PROTOCOL_SSLv2": "SSLv2.0", 
    "PROTOCOL_SSLv3": "SSLv3.0",
    "PROTOCOL_TLSv1": "TLSv1.0",
    "PROTOCOL_TLSv1_1": "TLSv1.1",
    "PROTOCOL_TLSv1_2": "TLSv1.2",
    "PROTOCOL_TLSv1_3": "TLSv1.3",
}

# IANA cipher suite mapping (based on https://testssl.sh/openssl-iana.mapping.html)
# Updated 2026/01/12
IANA_CIPHER_MAP = {
    # TLS 1.2 ECDHE ciphers
    'ECDHE-ECDSA-AES256-GCM-SHA384': 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
    'ECDHE-RSA-AES256-GCM-SHA384': 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
    'ECDHE-ECDSA-AES128-GCM-SHA256': 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
    'ECDHE-RSA-AES128-GCM-SHA256': 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
    'ECDHE-ECDSA-CHACHA20-POLY1305': 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
    'ECDHE-RSA-CHACHA20-POLY1305': 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
    'ECDHE-ECDSA-AES256-SHA384': 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
    'ECDHE-RSA-AES256-SHA384': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
    'ECDHE-ECDSA-AES128-SHA256': 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
    'ECDHE-RSA-AES128-SHA256': 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
    'ECDHE-ECDSA-AES256-SHA': 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
    'ECDHE-RSA-AES256-SHA': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
    'ECDHE-ECDSA-AES128-SHA': 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
    'ECDHE-RSA-AES128-SHA': 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
    
    # DHE ciphers
    'DHE-RSA-AES256-GCM-SHA384': 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
    'DHE-RSA-AES128-GCM-SHA256': 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256',
    'DHE-RSA-AES256-SHA256': 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256',
    'DHE-RSA-AES128-SHA256': 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256',
    'DHE-RSA-AES256-SHA': 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA',
    'DHE-RSA-AES128-SHA': 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA',
    
    # RSA ciphers
    'AES256-GCM-SHA384': 'TLS_RSA_WITH_AES_256_GCM_SHA384',
    'AES128-GCM-SHA256': 'TLS_RSA_WITH_AES_128_GCM_SHA256',
    'AES256-SHA256': 'TLS_RSA_WITH_AES_256_CBC_SHA256',
    'AES128-SHA256': 'TLS_RSA_WITH_AES_128_CBC_SHA256',
    'AES256-SHA': 'TLS_RSA_WITH_AES_256_CBC_SHA',
    'AES128-SHA': 'TLS_RSA_WITH_AES_128_CBC_SHA',
    
    # Legacy/weak ciphers
    'DES-CBC3-SHA': 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
    'RC4-SHA': 'TLS_RSA_WITH_RC4_128_SHA',
    'RC4-MD5': 'TLS_RSA_WITH_RC4_128_MD5',
    'NULL-SHA': 'TLS_RSA_WITH_NULL_SHA',
    'NULL-MD5': 'TLS_RSA_WITH_NULL_MD5',
    'EXP-DES-CBC-SHA': 'TLS_RSA_EXPORT_WITH_DES40_CBC_SHA',
    'EXP-RC4-MD5': 'TLS_RSA_EXPORT_WITH_RC4_40_MD5',
    'ADH-AES128-SHA': 'TLS_DH_anon_WITH_AES_128_CBC_SHA',
    'ADH-AES256-SHA': 'TLS_DH_anon_WITH_AES_256_CBC_SHA',
    
    # TLS 1.3 cipher suites (IANA names - these are used directly)
    'TLS_AES_256_GCM_SHA384': 'TLS_AES_256_GCM_SHA384',
    'TLS_CHACHA20_POLY1305_SHA256': 'TLS_CHACHA20_POLY1305_SHA256',
    'TLS_AES_128_GCM_SHA256': 'TLS_AES_128_GCM_SHA256',
    'TLS_AES_128_CCM_SHA256': 'TLS_AES_128_CCM_SHA256',
    'TLS_AES_128_CCM_8_SHA256': 'TLS_AES_128_CCM_8_SHA256',
}

# TLS protocol version mapping to IANA names
IANA_PROTOCOL_MAP = {
    'SSLv2.0': 'SSL_2.0',
    'SSLv3.0': 'SSL_3.0', 
    'TLSv1.0': 'TLS_1.0',
    'TLSv1.1': 'TLS_1.1',
    'TLSv1.2': 'TLS_1.2',
    'TLSv1.3': 'TLS_1.3'
}

# Risk tier patterns based on template macros
RISK_TIER_PATTERNS = {
    'sev5_protocols': r'^SSL_2\.0$|^SSL_3\.0$|^TLS_1\.0$',
    'sev5_ciphers': r'RC4|NULL|EXP|ANON|CBC|MD5',
    'sev4_protocols': r'^TLS_1\.1$', 
    'sev4_ciphers': r'3DES|DES|SEED|IDEA|PSK|CAMELLIA',
    'sev3_protocols': r'^TLS_1\.2$',
    'sev3_ciphers': r'SHA$|RSA$|ECDSA$',
    'sev2_protocols': r'^$',  # Disabled by default
    'sev2_ciphers': r'^$',   # Disabled by default  
    'sev1_protocols': r'^$', # Disabled by default
    'sev1_ciphers': r'^$'    # Disabled by default
}

def openssl_to_iana_cipher(openssl_name):
    """Convert OpenSSL cipher name to IANA cipher name."""
    return IANA_CIPHER_MAP.get(openssl_name, openssl_name)

def openssl_to_iana_protocol(openssl_name):
    """Convert OpenSSL protocol name to IANA protocol name.""" 
    return IANA_PROTOCOL_MAP.get(openssl_name, openssl_name)

def extract_iana_key_exchange(iana_cipher_name):
    """Extract key exchange method from IANA cipher name."""
    if 'ECDHE_ECDSA' in iana_cipher_name:
        return 'TLS_ECDHE_ECDSA'
    elif 'ECDHE_RSA' in iana_cipher_name:
        return 'TLS_ECDHE_RSA'
    elif 'ECDH_ECDSA' in iana_cipher_name:
        return 'TLS_ECDH_ECDSA'
    elif 'ECDH_RSA' in iana_cipher_name:
        return 'TLS_ECDH_RSA'
    elif 'DHE_RSA' in iana_cipher_name:
        return 'TLS_DHE_RSA'
    elif 'DHE_DSS' in iana_cipher_name:
        return 'TLS_DHE_DSS'
    elif 'DH_anon' in iana_cipher_name:
        return 'TLS_DH_anon'
    elif 'RSA_WITH' in iana_cipher_name:
        return 'TLS_RSA'
    elif 'PSK' in iana_cipher_name:
        return 'TLS_PSK'
    else:
        return 'TLS_OTHER'

def extract_iana_cipher_algorithm(iana_cipher_name):
    """Extract cipher algorithm from IANA cipher name."""
    # Remove TLS_ prefix and key exchange, extract the cipher part
    parts = iana_cipher_name.split('_WITH_')
    if len(parts) > 1:
        return parts[1]  # Everything after _WITH_
    return iana_cipher_name

def iana_to_openssl_protocol(iana_name):
    """Convert IANA protocol name back to OpenSSL protocol name."""
    reverse_map = {v: k for k, v in IANA_PROTOCOL_MAP.items()}
    return reverse_map.get(iana_name, iana_name)

def iana_to_openssl_cipher(iana_name):
    """Convert IANA cipher name back to OpenSSL cipher name."""
    reverse_map = {v: k for k, v in IANA_CIPHER_MAP.items()}
    return reverse_map.get(iana_name, iana_name)

def calculate_risk_tiers(cipher_suites):
    """Calculate SEV1-SEV5 risk tier counts based on supported protocols and ciphers.
    
    Args:
        cipher_suites: Dictionary from discover_tls_support output
        
    Returns:
        Dictionary with sev1_count through sev5_count
    """
    import re
    
    risk_counts = {
        'sev1_count': 0,
        'sev2_count': 0, 
        'sev3_count': 0,
        'sev4_count': 0,
        'sev5_count': 0
    }
    
    for protocol, key_exchanges in cipher_suites.items():
        for key_exchange, cipher_algos in key_exchanges.items():
            for cipher_algo, status in cipher_algos.items():
                if status != 1:  # Only count supported combinations
                    continue
                    
                # Reconstruct full cipher name for pattern matching
                full_cipher = f"{key_exchange}_WITH_{cipher_algo}"
                
                # Check each severity tier (highest priority first)
                tier_found = False
                
                # SEV5 - Critical (highest priority)
                if (re.search(RISK_TIER_PATTERNS['sev5_protocols'], protocol) or 
                    re.search(RISK_TIER_PATTERNS['sev5_ciphers'], full_cipher)):
                    risk_counts['sev5_count'] += 1
                    tier_found = True
                
                # SEV4 - High
                elif (re.search(RISK_TIER_PATTERNS['sev4_protocols'], protocol) or 
                      re.search(RISK_TIER_PATTERNS['sev4_ciphers'], full_cipher)):
                    risk_counts['sev4_count'] += 1
                    tier_found = True
                
                # SEV3 - Moderate  
                elif (re.search(RISK_TIER_PATTERNS['sev3_protocols'], protocol) or 
                      re.search(RISK_TIER_PATTERNS['sev3_ciphers'], full_cipher)):
                    risk_counts['sev3_count'] += 1
                    tier_found = True
                
                # SEV2 - Low (disabled by default in template)
                elif (re.search(RISK_TIER_PATTERNS['sev2_protocols'], protocol) or 
                      re.search(RISK_TIER_PATTERNS['sev2_ciphers'], full_cipher)):
                    risk_counts['sev2_count'] += 1
                    tier_found = True
                
                # SEV1 - Informational (disabled by default in template)
                elif (re.search(RISK_TIER_PATTERNS['sev1_protocols'], protocol) or 
                      re.search(RISK_TIER_PATTERNS['sev1_ciphers'], full_cipher)):
                    risk_counts['sev1_count'] += 1
                    tier_found = True
                
                # If no tier matched, this is considered acceptable (no risk)
                
    return risk_counts

REVERSE_PROTOCOL_MAP = {v: k for k, v in PROTOCOL_MAP.items()}

def get_available_protocols():
    """Get list of available SSL/TLS protocols on the client system, returned as IANA names."""
    protocols = []
    
    # Check old-style PROTOCOL_* constants first
    for const, openssl_name in PROTOCOL_MAP.items():
        try:
            if hasattr(ssl, const):
                with warnings.catch_warnings():
                    warnings.filterwarnings("ignore", category=DeprecationWarning)
                    ssl.SSLContext(getattr(ssl, const))
                iana_name = openssl_to_iana_protocol(openssl_name)
                protocols.append(iana_name)
                if DEBUG:
                    logger.debug(f"Protocol {iana_name} ({openssl_name}) is available")
        except Exception as e:
            if DEBUG:
                logger.debug(f"Protocol {openssl_name} is NOT available: {e}")
    
    # Check for TLS 1.3 using newer TLSVersion enum (for modern Python/OpenSSL)
    if hasattr(ssl, 'TLSVersion') and hasattr(ssl.TLSVersion, 'TLSv1_3'):
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            if 'TLS_1.3' not in protocols:  # Don't duplicate if already found
                protocols.append('TLS_1.3')
                if DEBUG:
                    logger.debug(f"Protocol TLS_1.3 (TLSv1.3) is available via TLSVersion enum")
        except Exception as e:
            if DEBUG:
                logger.debug(f"Protocol TLS_1.3 is NOT available via TLSVersion enum: {e}")
    
    return protocols

def get_available_ciphers():
    """Get list of available cipher suites from the default SSL context, converted to IANA names."""
    try:
        openssl_ciphers = ssl.create_default_context().get_ciphers()
        iana_ciphers = []
        for cipher in openssl_ciphers:
            iana_name = openssl_to_iana_cipher(cipher["name"])
            iana_ciphers.append({
                "name": iana_name,
                "openssl_name": cipher["name"],
                "description": cipher.get("description", ""),
                "id": cipher.get("id")
            })
        return iana_ciphers
    except Exception as e:
        if DEBUG:
            logger.error(f"Failed to get available ciphers: {e}")
        return []

def create_protocol_cipher_pairs(protocols, ciphers):
    """Create all possible protocol-cipher combinations using IANA names."""
    pairs = []
    for protocol in protocols:
        for cipher in ciphers:
            pairs.append((protocol, cipher["name"]))
    if DEBUG:
        logger.debug(f"Created {len(pairs)} protocol-cipher pairs (IANA format)")
    return pairs

def filter_compatible_pairs(pairs):
    """Filter protocol-cipher pairs to only include client-compatible combinations.
    Input pairs use IANA names, converts to OpenSSL for compatibility testing."""
    compatible = []
    for iana_protocol, iana_cipher in pairs:
        try:
            # Special handling for TLS 1.3
            if iana_protocol == 'TLS_1.3':
                # For TLS 1.3, check if the cipher is a TLS 1.3 cipher suite
                if iana_cipher.startswith('TLS_AES_') or iana_cipher.startswith('TLS_CHACHA20_'):
                    compatible.append((iana_protocol, iana_cipher))
                    if DEBUG:
                        logger.debug(f"Compatible: {iana_protocol} with {iana_cipher}")
                else:
                    if DEBUG:
                        logger.debug(f"Incompatible: {iana_protocol} with {iana_cipher} - TLS 1.3 only supports AEAD ciphers")
                continue
                
            # Traditional handling for TLS 1.0-1.2
            # Convert IANA names to OpenSSL for compatibility testing
            openssl_protocol = iana_to_openssl_protocol(iana_protocol)
            openssl_cipher = iana_to_openssl_cipher(iana_cipher)
            
            proto_const = REVERSE_PROTOCOL_MAP.get(openssl_protocol)
            if not proto_const:
                continue
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", category=DeprecationWarning)
                ctx = ssl.SSLContext(getattr(ssl, proto_const))
            ctx.set_ciphers(openssl_cipher)
            compatible.append((iana_protocol, iana_cipher))
            if DEBUG:
                logger.debug(f"Compatible: {iana_protocol} with {iana_cipher}")
        except Exception as e:
            if DEBUG:
                logger.debug(f"Incompatible: {iana_protocol} with {iana_cipher} - {e}")
    return compatible

def test_tls_connection(host, port, iana_protocol, iana_cipher, timeout=None):
    """Test TLS connection with specific protocol and cipher using IANA names.
    
    Args:
        iana_protocol: IANA protocol name (e.g., 'TLS_1.2')
        iana_cipher: IANA cipher name (e.g., 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384')
    
    Returns:
        0: Connection failed
        1: Connection successful
        2: Protocol/cipher not available on client
    """
    if timeout is None:
        timeout = TLS_TIMEOUT
        
    if DEBUG:
        logger.debug(f"Testing {iana_protocol} with {iana_cipher} on {host}:{port}")
        
    try:
        # Convert IANA names to OpenSSL format for SSL library
        openssl_protocol = iana_to_openssl_protocol(iana_protocol)
        openssl_cipher = iana_to_openssl_cipher(iana_cipher)
        
        # Handle TLS 1.3 using newer TLSVersion enum approach
        if iana_protocol == 'TLS_1.3':
            if not (hasattr(ssl, 'TLSVersion') and hasattr(ssl.TLSVersion, 'TLSv1_3')):
                return 2  # TLS 1.3 not supported
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.minimum_version = ssl.TLSVersion.TLSv1_3
                context.maximum_version = ssl.TLSVersion.TLSv1_3
                # For TLS 1.3, cipher setting is handled differently - cipher suites are negotiated
                # We'll let the context use its default TLS 1.3 cipher suites
            except Exception as e:
                if DEBUG:
                    logger.debug(f"TLS 1.3 context setup failed: {e}")
                return 2
        else:
            # Use traditional approach for TLS 1.0-1.2
            proto_const = REVERSE_PROTOCOL_MAP.get(openssl_protocol)
            if not proto_const or not hasattr(ssl, proto_const):
                return 2
                
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", category=DeprecationWarning)
                context = ssl.SSLContext(getattr(ssl, proto_const))
            context.set_ciphers(openssl_cipher)
        
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return 1
                
    except Exception as e:
        if DEBUG:
            logger.debug(f"Connection failed: {e}")
        return 0

# --- Core Functions (following get_domain_health.py pattern) ---

def discover_tls_support(host, port=443):
    """Discover all TLS protocol-cipher combinations with support status.
    
    Uses IANA names throughout. Returns structured JSON with nested protocol-cipher 
    groupings showing support status (1=supported, 0=not supported) for efficient Zabbix processing.
    """
    try:
        port = int(port)
        iana_protocols = get_available_protocols()  # Already returns IANA names
        iana_ciphers = get_available_ciphers()      # Already returns IANA names
        
        if not iana_protocols:
            return json.dumps({
                'error': 'No SSL/TLS protocols available on client',
                'host': host,
                'port': port
            })
            
        if not iana_ciphers:
            return json.dumps({
                'error': 'No cipher suites available on client',
                'host': host,
                'port': port
            })
            
        pairs = create_protocol_cipher_pairs(iana_protocols, iana_ciphers)
        compatible_pairs = filter_compatible_pairs(pairs)
        
        cipher_suites = {}
        
        for iana_protocol, iana_cipher in compatible_pairs:
            result = test_tls_connection(host, port, iana_protocol, iana_cipher)
            
            # Initialize protocol if not exists
            if iana_protocol not in cipher_suites:
                cipher_suites[iana_protocol] = {}
            
            # Extract key exchange method from IANA cipher name
            key_exchange = extract_iana_key_exchange(iana_cipher)
            if key_exchange not in cipher_suites[iana_protocol]:
                cipher_suites[iana_protocol][key_exchange] = {}
            
            # Extract cipher algorithm from IANA cipher name
            cipher_algo = extract_iana_cipher_algorithm(iana_cipher)
            
            # Store support status: 1=supported, 0=not supported
            cipher_suites[iana_protocol][key_exchange][cipher_algo] = result
        
        return json.dumps({
            'host': host,
            'port': port,
            'cipher_suites': cipher_suites,
            'risk_tiers': calculate_risk_tiers(cipher_suites)
        })
        
    except Exception as e:
        return json.dumps({
            'error': f'TLS discovery failed: {str(e)}',
            'host': host,
            'port': port
        })

def extract_key_exchange(cipher_name):
    """Extract key exchange method from cipher name."""
    if 'ECDHE-ECDSA' in cipher_name:
        return 'ECDHE-ECDSA'
    elif 'ECDHE-RSA' in cipher_name:
        return 'ECDHE-RSA'
    elif 'ECDH-ECDSA' in cipher_name:
        return 'ECDH-ECDSA'
    elif 'ECDH-RSA' in cipher_name:
        return 'ECDH-RSA'
    elif 'DHE-RSA' in cipher_name:
        return 'DHE-RSA'
    elif 'DHE-DSS' in cipher_name:
        return 'DHE-DSS'
    elif 'RSA' in cipher_name:
        return 'RSA'
    elif 'PSK' in cipher_name:
        return 'PSK'
    elif 'ANON' in cipher_name:
        return 'ANON'
    else:
        return 'OTHER'

def extract_cipher_algorithm(cipher_name):
    """Extract cipher algorithm from full cipher name."""
    # Remove key exchange prefix to get cipher algorithm
    for kex in ['ECDHE-ECDSA-', 'ECDHE-RSA-', 'ECDH-ECDSA-', 'ECDH-RSA-', 
                'DHE-RSA-', 'DHE-DSS-', 'RSA-']:
        if cipher_name.startswith(kex):
            return cipher_name[len(kex):]
    
    # Handle cases where cipher name doesn't follow standard pattern
    return cipher_name

def check_tls_support(host, protocol, cipher, port=443):
    """Check if specific protocol-cipher combination is supported.
    
    Expects IANA format protocol/cipher names as primary input.
    
    Returns:
        JSON with result (0=failed, 1=success, 2=unavailable)
    """
    try:
        port = int(port)
        
        # Parse input - expect IANA names but handle discovery format and legacy OpenSSL
        if protocol.startswith('TLS_') or protocol.startswith('SSL_'):
            # IANA format
            iana_protocol = protocol
        else:
            # Legacy OpenSSL format - convert to IANA
            iana_protocol = openssl_to_iana_protocol(protocol)
            
        if cipher.startswith('TLS_'):
            # IANA format (including full format from discovery rule)
            iana_cipher = cipher
        else:
            # Legacy OpenSSL format - convert to IANA
            iana_cipher = openssl_to_iana_cipher(cipher)
        
        # Validate protocol is available (get_available_protocols returns IANA names)
        available_iana_protocols = get_available_protocols()
        if iana_protocol not in available_iana_protocols:
            return json.dumps({
                'result': 2,
                'message': f'Protocol {iana_protocol} not available on client',
                'host': host,
                'port': port,
                'protocol': iana_protocol,
                'cipher': iana_cipher
            })
            
        # Test the specific combination using IANA names (function handles OpenSSL conversion internally)
        result = test_tls_connection(host, port, iana_protocol, iana_cipher)
        
        messages = {
            0: 'Connection failed',
            1: 'Connection successful', 
            2: 'Protocol/cipher not available'
        }
        
        return json.dumps({
            'result': result,
            'message': messages.get(result, 'Unknown result'),
            'host': host,
            'port': port, 
            'protocol': iana_protocol,
            'cipher': iana_cipher
        })
        
    except Exception as e:
        return json.dumps({
            'result': 0,
            'error': f'TLS check failed: {str(e)}',
            'host': host,
            'port': port,
            'protocol': protocol,
            'cipher': cipher
        })

def get_protocols():
    """Get list of available protocols on client system (IANA names)."""
    try:
        iana_protocols = get_available_protocols()  # Returns IANA format
        return json.dumps({
            'protocols': iana_protocols,
            'count': len(iana_protocols)
        })
    except Exception as e:
        return json.dumps({
            'error': f'Failed to get protocols: {str(e)}',
            'protocols': []
        })

def get_ciphers():
    """Get list of available cipher suites on client system (IANA names)."""
    try:
        iana_ciphers = get_available_ciphers()  # Returns IANA format
        cipher_names = [c['name'] for c in iana_ciphers]
        return json.dumps({
            'ciphers': cipher_names,
            'count': len(cipher_names)
        })
    except Exception as e:
        return json.dumps({
            'error': f'Failed to get ciphers: {str(e)}',
            'ciphers': []
        })

def test_single_combination(host, protocol, cipher, port=443):
    """Test a single protocol-cipher combination (alias for check_tls_support)."""
    return check_tls_support(host, protocol, cipher, port)

def get_compatibility_matrix(host, port=443):
    """Get full compatibility matrix of protocol-cipher combinations."""
    try:
        port = int(port)
        protocols = get_available_protocols()
        ciphers = get_available_ciphers()
        
        pairs = create_protocol_cipher_pairs(protocols, ciphers)
        compatible_pairs = filter_compatible_pairs(pairs)
        
        results = []
        for protocol, cipher in compatible_pairs:
            test_result = test_tls_connection(host, port, protocol, cipher)
            results.append({
                'protocol': protocol,
                'cipher': cipher, 
                'result': test_result,
                'status': 'success' if test_result == 1 else 'failed' if test_result == 0 else 'unavailable'
            })
            
        success_count = sum(1 for r in results if r['result'] == 1)
        
        return json.dumps({
            'host': host,
            'port': port,
            'total_combinations': len(results),
            'successful_combinations': success_count,
            'success_rate': round((success_count / len(results)) * 100, 2) if results else 0,
            'results': results
        })
        
    except Exception as e:
        return json.dumps({
            'error': f'Compatibility matrix failed: {str(e)}',
            'results': []
        })

def get_tls_health(host, port=443):
    """Get overall TLS health assessment for the endpoint."""
    try:
        port = int(port)
        protocols = get_available_protocols()
        ciphers = get_available_ciphers()
        
        if not protocols or not ciphers:
            return json.dumps({
                'error': 'No protocols or ciphers available for testing',
                'health_score': 0
            })
            
        pairs = create_protocol_cipher_pairs(protocols, ciphers)
        compatible_pairs = filter_compatible_pairs(pairs)
        
        # Test a representative sample of combinations
        sample_size = min(50, len(compatible_pairs))  # Test up to 50 combinations
        test_pairs = compatible_pairs[:sample_size]
        
        successful = 0
        for protocol, cipher in test_pairs:
            if test_tls_connection(host, port, protocol, cipher) == 1:
                successful += 1
                
        success_rate = (successful / len(test_pairs)) * 100 if test_pairs else 0
        
        # Calculate health score based on success rate and security
        health_score = success_rate
        
        # Security analysis
        secure_protocols = ['TLS_1.2', 'TLS_1.3']
        secure_protocol_support = any(p in protocols for p in secure_protocols)
        
        if secure_protocol_support:
            health_score += 10  # Bonus for modern protocol support
            
        health_score = min(100, health_score)  # Cap at 100
        
        return json.dumps({
            'host': host,
            'port': port,
            'health_score': round(health_score, 2),
            'success_rate': round(success_rate, 2),
            'tested_combinations': len(test_pairs),
            'successful_combinations': successful,
            'available_protocols': protocols,
            'secure_protocol_support': secure_protocol_support,
            'client_cipher_count': len(ciphers)
        })
        
    except Exception as e:
        return json.dumps({
            'error': f'TLS health assessment failed: {str(e)}',
            'health_score': 0
        })

# --- Legacy Support Functions for Backward Compatibility ---

def legacy_discover_mode(host, port=443, verbose=False):
    """Legacy discover mode compatible with original --discover flag."""
    protocols = get_available_protocols()
    ciphers = get_available_ciphers()
    
    if verbose:
        print(" ------------------------------")
        print("| GET CLIENT COMPATIBILITY    |")
        print(" ------------------------------")
        
    pairs = create_protocol_cipher_pairs(protocols, ciphers)
    compatible_pairs = filter_compatible_pairs(pairs)
    
    if verbose:
        print("\n ------------------------------")
        print("| EXECUTING DISCOVER          |")
        print(" ------------------------------")
        
    results = []
    for protocol, cipher in compatible_pairs:
        result = test_tls_connection(host, port, protocol, cipher)
        results.append((result, protocol, cipher))
        
    if verbose:
        print("\n ------------------------------")
        print("| RESULTS                     |")
        print(" ------------------------------")
        print(f"{'STATUS':<8} {' PROTOCOL':<10} {' CIPHER'}")
        print("-" * 60)
        for status, proto, cipher in results:
            s = '✅' if status == 1 else '❌'
            print(f"{s:<8} {proto:<10} {cipher}")
    else:
        data = [{"#PROTOCOL": p, "{#CIPHER}": c} for r, p, c in results if r == 1]
        print(json.dumps({"data": data}, indent=4))

def legacy_check_mode(host, protocol, cipher, port=443, verbose=False):
    """Legacy check mode compatible with original --check flag."""
    if protocol not in get_available_protocols():
        print(2)
        return
        
    try:
        proto_const = REVERSE_PROTOCOL_MAP[protocol]
        context = ssl.SSLContext(getattr(ssl, proto_const))
        context.set_ciphers(cipher)
    except Exception:
        print(2)
        return
        
    result = test_tls_connection(host, port, protocol, cipher)
    print(result)

# --- Main CLI Handler (following get_domain_health.py pattern) ---

def main():
    # Suppress SSL deprecation warnings unless in debug mode
    if not DEBUG:
        warnings.simplefilter("ignore", category=DeprecationWarning)
        
    if len(sys.argv) < 2:
        print(json.dumps({'error': 'Usage: get_tls_health.py <command> <args>'}))
        sys.exit(1)
        
    cmd = sys.argv[1].lower()
    
    if cmd == 'discover':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_tls_health.py discover <HOST> [PORT]'}))
            sys.exit(1)
        host = sys.argv[2]
        port = sys.argv[3] if len(sys.argv) >= 4 else 443
        print(discover_tls_support(host, port))
        
    elif cmd == 'check':
        if len(sys.argv) < 5:
            print(json.dumps({'error': 'Usage: get_tls_health.py check <HOST> <PROTOCOL> <CIPHER> [PORT]'}))
            sys.exit(1)
        host = sys.argv[2]
        protocol = sys.argv[3]
        cipher = sys.argv[4]
        port = sys.argv[5] if len(sys.argv) >= 6 else 443
        print(check_tls_support(host, protocol, cipher, port))
        
    elif cmd == 'protocols':
        print(get_protocols())
        
    elif cmd == 'ciphers':
        print(get_ciphers())
        
    elif cmd == 'test':
        if len(sys.argv) < 5:
            print(json.dumps({'error': 'Usage: get_tls_health.py test <HOST> <PROTOCOL> <CIPHER> [PORT]'}))
            sys.exit(1)
        host = sys.argv[2]
        protocol = sys.argv[3]
        cipher = sys.argv[4]
        port = sys.argv[5] if len(sys.argv) >= 6 else 443
        print(test_single_combination(host, protocol, cipher, port))
        
    elif cmd == 'compatibility':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_tls_health.py compatibility <HOST> [PORT]'}))
            sys.exit(1)
        host = sys.argv[2]
        port = sys.argv[3] if len(sys.argv) >= 4 else 443
        print(get_compatibility_matrix(host, port))
        
    elif cmd == 'health':
        if len(sys.argv) < 3:
            print(json.dumps({'error': 'Usage: get_tls_health.py health <HOST> [PORT]'}))
            sys.exit(1)
        host = sys.argv[2]
        port = sys.argv[3] if len(sys.argv) >= 4 else 443
        print(get_tls_health(host, port))
        
    # Legacy mode support for backward compatibility
    elif len(sys.argv) >= 2 and sys.argv[1] not in ['discover', 'check', 'protocols', 'ciphers', 'test', 'compatibility', 'health']:
        # Check if this is legacy command line format: script.py hostname [options]
        try:
            # Parse legacy argparse-style arguments
            from argparse import ArgumentParser
            
            parser = ArgumentParser(description="TLS Handshake Tester with Zabbix Integration")
            parser.add_argument("host", help="Target host or IP")
            parser.add_argument("-p", "--port", type=int, default=443)
            parser.add_argument("-t", "--timeout", type=int, default=4)
            parser.add_argument("-v", "--verbose", action="store_true")
            parser.add_argument("-d", "--discover", action="store_true")
            parser.add_argument("-c", "--check", action="store_true")
            parser.add_argument("-k", "--protocol", help="Protocol name to check")
            parser.add_argument("-y", "--cipher", help="Cipher name to check")
            
            args = parser.parse_args()
            
            # Handle legacy modes
            if args.discover:
                legacy_discover_mode(args.host, args.port, args.verbose)
            elif args.check:
                if not args.protocol or not args.cipher:
                    print(json.dumps({'error': 'Protocol and cipher required for check mode'}))
                    sys.exit(1)
                legacy_check_mode(args.host, args.protocol, args.cipher, args.port, args.verbose)
            else:
                # Default legacy behavior (discover mode)
                legacy_discover_mode(args.host, args.port, args.verbose)
                
        except Exception as e:
            print(json.dumps({'error': f'Legacy mode failed: {str(e)}'}))
            sys.exit(1)
    else:
        print(json.dumps({'error': f'Unknown command: {cmd}'}))
        sys.exit(1)

if __name__ == "__main__":
    main()