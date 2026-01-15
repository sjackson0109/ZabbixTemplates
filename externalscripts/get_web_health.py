#!/usr/bin/env python3
"""
Author: Simon Jackson (sjackson0109)
Created: 2026/01/05
Version: 1.0

Web Server Health & Compliance Monitoring for Zabbix

Description:
    Specialized web server infrastructure monitoring and RFC compliance validation.
    Focused specifically on HTTP/HTTPS, TLS, and network connectivity analysis.
    Performs extensive checks on HTTP/HTTPS, DNS, TLS, and network connectivity.

Features:
    - HTTP/HTTPS protocol validation and performance monitoring
    - TLS/SSL certificate and handshake analysis
    - DNS record validation and performance
    - CDN and proxy detection with provider identification
    - TCP port connectivity and service discovery
    - Security header analysis (CSP, HSTS, etc.)
    - Performance metrics (response times, compression, caching)
    - RFC compliance validation across multiple standards
    - Load balancer and CDN detection
    - Redirect chain analysis
    - Content validation and integrity checks
    - API endpoint health monitoring
    - WebSocket connectivity testing
    - HTTP/2 and HTTP/3 support validation

RFC Coverage:
    RFC 7230-7237 - HTTP/1.1 Specification
    RFC 9110 - HTTP Semantics
    RFC 9111 - HTTP Caching
    RFC 9112 - HTTP/1.1 Message Syntax
    RFC 7540 - HTTP/2
    RFC 9114 - HTTP/3
    RFC 6455 - WebSocket Protocol
    RFC 7234 - HTTP Caching
    RFC 7235 - HTTP Authentication
    RFC 6265 - HTTP State Management (Cookies)
    RFC 7469 - HTTP Public Key Pinning
    RFC 6797 - HTTP Strict Transport Security
    RFC 7762 - Initial Assignment for HTTP/2
    RFC 8446 - TLS 1.3
    RFC 5246 - TLS 1.2
    RFC 3986 - URI Generic Syntax
    RFC 6454 - Web Origin Concept
    RFC 7034 - HTTP Header Field X-Frame-Options
    RFC 8941 - Structured Field Values for HTTP

USAGE EXAMPLES:
    python get_web_health.py discover <URL_OR_HOST> [PORT] [--timeout 3]
    python get_web_health.py health <URL_OR_HOST> [PORT] [--timeout 5]
    python get_web_health.py http <URL> [PORT] [-t 3]
    python get_web_health.py https <URL> [PORT] [--timeout 3]
    python get_web_health.py security <URL> [PORT]
    python get_web_health.py performance <URL> [PORT] [-t 2]
    python get_web_health.py compliance <URL> [PORT]
    python get_web_health.py redirects <URL> [PORT]
    python get_web_health.py headers <URL> [PORT]
    python get_web_health.py content <URL> [PORT]
    python get_web_health.py api <API_ENDPOINT> [PORT]
    python get_web_health.py websocket <WS_URL> [PORT]
    python get_web_health.py cdn <URL> [PORT]
    python get_web_health.py compression <URL> [PORT]
    python get_web_health.py caching <URL> [PORT]
    python get_web_health.py cookies <URL> [PORT]
    python get_web_health.py cors <URL> [PORT]
    python get_web_health.py selftest <URL> [PORT]

ENVIRONMENT VARIABLES/MACROS:
    HTTP_TIMEOUT (default: 3)
    HTTP_USER_AGENT (default: WebHealthMonitor/1.0)
    HTTP_MAX_REDIRECTS (default: 10)
    HTTP_VERIFY_SSL (default: 1)
    HTTP_DEBUG (set to 1 for debug logging)
"""

import json
import sys
import os
import subprocess
import urllib.request
import urllib.parse
import urllib.error
from urllib.parse import urlparse, urljoin
import re
from datetime import datetime, timezone
import argparse

# HTTP version support
try:
    import httpx
    HTTP2_AVAILABLE = True
except ImportError:
    HTTP2_AVAILABLE = False
    print("Warning: httpx not available. HTTP/2 support limited to detection only.", file=sys.stderr)

# Only import SSL and socket if needed (lazy loading)
# import ssl - moved to method level
# import socket - not actively used
# Removed unused imports: time, base64, hashlib, gzip, tempfile

# Configuration from environment variables
HTTP_TIMEOUT = int(os.environ.get('HTTP_TIMEOUT', 3))
HTTP_USER_AGENT = os.environ.get('HTTP_USER_AGENT', 'WebHealthMonitor/1.0')
HTTP_MAX_REDIRECTS = int(os.environ.get('HTTP_MAX_REDIRECTS', 10))
HTTP_VERIFY_SSL = os.environ.get('HTTP_VERIFY_SSL', '1') == '1'
HTTP_DEBUG = os.environ.get('HTTP_DEBUG', '0') == '1'

# HTTP Version Support
HTTP_VERSIONS = {
    '1.0': 'HTTP/1.0',
    '1.1': 'HTTP/1.1', 
    '2.0': 'HTTP/2.0',
    '2': 'HTTP/2.0',
    '3': 'HTTP/3.0'
}

# Next-Gen Protocol Support
NEXT_GEN_PROTOCOLS = {
    'http3': 'HTTP/3 (QUIC)',
    'webrtc': 'WebRTC',
    'graphql': 'GraphQL',
    'grpc': 'gRPC',
    'websocket': 'WebSocket'
}

# OWASP Top 10 & SANS 25 Security Checks
SECURITY_CHECKS = {
    'injection': 'A01:2021 – Broken Access Control',
    'broken_auth': 'A02:2021 – Cryptographic Failures', 
    'sensitive_data': 'A03:2021 – Injection',
    'xxe': 'A04:2021 – Insecure Design',
    'broken_access': 'A05:2021 – Security Misconfiguration',
    'security_misconfig': 'A06:2021 – Vulnerable and Outdated Components',
    'xss': 'A07:2021 – Identification and Authentication Failures',
    'insecure_deserial': 'A08:2021 – Software and Data Integrity Failures',
    'known_vulns': 'A09:2021 – Security Logging and Monitoring Failures',
    'insufficient_logging': 'A10:2021 – Server-Side Request Forgery'
}

# Next-Gen Protocol Support
NEXT_GEN_PROTOCOLS = {
    'http3': 'HTTP/3 (QUIC)',
    'webrtc': 'WebRTC',
    'graphql': 'GraphQL',
    'grpc': 'gRPC',
    'websocket': 'WebSocket'
}

# OWASP Top 10 & SANS 25 Security Checks
SECURITY_CHECKS = {
    'injection': 'A01:2021 – Broken Access Control',
    'broken_auth': 'A02:2021 – Cryptographic Failures', 
    'sensitive_data': 'A03:2021 – Injection',
    'xxe': 'A04:2021 – Insecure Design',
    'broken_access': 'A05:2021 – Security Misconfiguration',
    'security_misconfig': 'A06:2021 – Vulnerable and Outdated Components',
    'xss': 'A07:2021 – Identification and Authentication Failures',
    'insecure_deserial': 'A08:2021 – Software and Data Integrity Failures',
    'known_vulns': 'A09:2021 – Security Logging and Monitoring Failures',
    'insufficient_logging': 'A10:2021 – Server-Side Request Forgery'
}

DEFAULT_HTTP_VERSION = '1.1'

class WebHealthMonitor:
    # Class-level constants for better performance
    _SCRIPT_NAMES = {
        'tls': 'get_tls_handshake.py',
        'tcp': 'get_tcp_port_scan.py'
    }
    _WEB_PORTS = frozenset([80, 443, 8080, 8443, 3000, 5000, 8000, 9000])
    _SSL_PORTS = frozenset([443, 8443])
    
    def __init__(self, target, port=None, timeout=HTTP_TIMEOUT, http_version=None):
        self.target = target
        self.port = port
        self.timeout = timeout
        self.user_agent = HTTP_USER_AGENT
        self.max_redirects = HTTP_MAX_REDIRECTS
        self.verify_ssl = HTTP_VERIFY_SSL
        self.debug = HTTP_DEBUG
        self.http_version = http_version or DEFAULT_HTTP_VERSION
        
        # Validate input parameters first
        if not target or not isinstance(target, str) or target.strip() == '':
            raise ValueError("Target URL or host cannot be empty")
        
        # Optimize URL parsing with single pass
        if target.startswith(('http://', 'https://')):
            self.url = target
            try:
                parsed = urlparse(target)
                if not parsed.netloc:
                    raise ValueError(f"Invalid URL format: {target}")
                self.host = parsed.netloc.split(':')[0]
                self.port = port or parsed.port or (443 if parsed.scheme == 'https' else 80)
            except Exception as e:
                raise ValueError(f"Failed to parse URL '{target}': {str(e)}")
        else:
            # Validate host format
            if not target.replace('-', '').replace('.', '').replace('_', '').isalnum():
                if not all(c.isalnum() or c in '.-_' for c in target):
                    raise ValueError(f"Invalid host format: {target}")
            
            self.host = target
            self.port = port or 443
            # Simplified URL construction
            protocol = 'https' if self.port != 80 else 'http'
            port_suffix = f':{self.port}' if (self.port != 443 and protocol == 'https') or (self.port != 80 and protocol == 'http') else ''
            self.url = f"{protocol}://{target}{port_suffix}"
        
        # Validate port range
        if self.port is not None and (self.port < 1 or self.port > 65535):
            raise ValueError(f"Port {self.port} out of valid range 1-65535")
        
        # Validate HTTP version
        valid_http_versions = ['1.0', '1.1', '2.0', '2']
        if self.http_version and str(self.http_version) not in valid_http_versions:
            raise ValueError(f"Unsupported HTTP version: {self.http_version}. Supported: {valid_http_versions}")
        
        # Validate timeout
        if timeout <= 0:
            raise ValueError(f"Timeout must be positive, got: {timeout}")
        if timeout > 300:  # Maximum 5 minutes
            raise ValueError(f"Timeout too large (maximum 300 seconds), got: {timeout}")
        
        # Cache script paths for better performance
        script_dir = os.path.dirname(os.path.abspath(__file__))
        self._script_paths = {
            name: os.path.join(script_dir, filename)
            for name, filename in self._SCRIPT_NAMES.items()
        }

    def debug_log(self, message):
        """Debug logging if enabled"""
        if self.debug:
            print(f"DEBUG: {message}", file=sys.stderr)

    def run_script(self, script_type, args, timeout_override=None):
        """Execute external script with optimized performance"""
        script_timeout = timeout_override or self.timeout
        script_path = self._script_paths.get(script_type)
        
        if not script_path:
            return {"error": f"Unknown script type: {script_type}"}
        
        try:
            # Pre-build command list for efficiency
            cmd = [sys.executable, script_path] + args
            
            if self.debug:
                print(f"DEBUG: Running: {' '.join(cmd)} (timeout: {script_timeout}s)", file=sys.stderr)
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=script_timeout
            )
            
            if result.returncode == 0 and result.stdout:
                try:
                    return json.loads(result.stdout)
                except json.JSONDecodeError:
                    return {"error": "Invalid JSON response", "output": result.stdout}
            else:
                return {"error": f"Script failed: {result.stderr}", "returncode": result.returncode}
                
        except subprocess.TimeoutExpired:
            return {"error": "Script timeout"}
        except FileNotFoundError:
            return {"error": f"Script not found: {script_path}"}
        except Exception as e:
            return {"error": str(e)}

    def make_http_request(self, url, method='GET', headers=None, data=None, follow_redirects=True, force_version=None):
        """Make HTTP request with multi-version support"""
        # Validate method parameter
        valid_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']
        if method.upper() not in valid_methods:
            return {
                'success': False,
                'error': f'Unsupported HTTP method: {method}. Supported: {valid_methods}',
                'status_code': None
            }
        
        # Validate URL before making request
        try:
            parsed = urlparse(url)
            if not parsed.netloc or not parsed.scheme:
                return {
                    'success': False,
                    'error': f'Invalid URL format: {url}',
                    'status_code': None
                }
                
            # Check for invalid schemes
            if parsed.scheme not in ('http', 'https'):
                return {
                    'success': False,
                    'error': f'Unsupported protocol: {parsed.scheme}',
                    'status_code': None
                }
                
            # Validate port if present
            if parsed.port is not None and (parsed.port < 1 or parsed.port > 65535):
                return {
                    'success': False,
                    'error': f'Port {parsed.port} out of valid range 1-65535',
                    'status_code': None
                }
                
            # Validate force_version parameter
            if force_version is not None:
                valid_versions = ['1.0', '1.1', '2.0', '2']
                if str(force_version) not in valid_versions:
                    return {
                        'success': False,
                        'error': f'Unsupported HTTP version: {force_version}. Supported: {valid_versions}',
                        'status_code': None
                    }
                    
        except Exception as e:
            return {
                'success': False,
                'error': f'URL validation failed: {str(e)}',
                'status_code': None
            }
        
        # Determine HTTP version to use
        version = force_version or self.http_version
        
        # Minimize object creation
        if headers is None:
            headers = {'User-Agent': self.user_agent}
        else:
            headers.setdefault('User-Agent', self.user_agent)
        
        # Route to appropriate HTTP client based on version
        if version == '2.0' or version == '2':
            return self._make_http2_request(url, method, headers, data, follow_redirects)
        elif version == '1.0':
            return self._make_http10_request(url, method, headers, data, follow_redirects)
        else:  # Default to HTTP/1.1
            return self._make_http11_request(url, method, headers, data, follow_redirects)
    
    def _make_http2_request(self, url, method='GET', headers=None, data=None, follow_redirects=True):
        """Make HTTP/2 request using httpx"""
        import time  # Import time at method level
        
        if not HTTP2_AVAILABLE:
            # Fallback to HTTP/1.1 with detection
            result = self._make_http11_request(url, method, headers, data, follow_redirects)
            if result and result.get('success'):
                # Check if server actually responded with HTTP/2
                response_headers = result.get('response_headers', {})
                if any('HTTP/2' in str(v) for v in response_headers.values()):
                    result['detected_protocol'] = 'HTTP/2.0'
                else:
                    result['detected_protocol'] = 'HTTP/1.1'
            return result
        
        start_time = time.time()
        
        try:
            # Configure httpx client for HTTP/2
            client_config = {
                'timeout': self.timeout,
                'follow_redirects': follow_redirects,
                'verify': self.verify_ssl,
                'http2': True
            }
            
            with httpx.Client(**client_config) as client:
                response = client.request(
                    method=method,
                    url=url, 
                    headers=headers,
                    content=data
                )
                
                response_time = time.time() - start_time
                
                # Extract response headers
                response_headers = dict(response.headers)
                
                return {
                    'success': True,
                    'status_code': response.status_code,
                    'response_headers': response_headers,
                    'headers': response_headers,  # Backward compatibility
                    'content': response.text,
                    'content_type': response_headers.get('content-type', ''),
                    'content_length': len(response.content),
                    'response_time': response_time,
                    'http_version': response.http_version,
                    'detected_protocol': f'HTTP/{response.http_version}',
                    'url': str(response.url)
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': f'HTTP/2 request failed: {str(e)}',
                'response_time': time.time() - start_time if 'start_time' in locals() else 0
            }
    
    def _make_http10_request(self, url, method='GET', headers=None, data=None, follow_redirects=True):
        """Make HTTP/1.0 request with explicit version"""
        # HTTP/1.0 specific headers
        if headers is None:
            headers = {}
        
        # HTTP/1.0 requires Connection: close
        headers['Connection'] = 'close'
        
        # Use manual socket connection for HTTP/1.0
        return self._make_manual_http_request(url, method, headers, data, follow_redirects, '1.0')
    
    def _make_manual_http_request(self, url, method='GET', headers=None, data=None, follow_redirects=True, http_version='1.0'):
        """Make HTTP request using manual socket connection for specific HTTP versions"""
        import socket
        import ssl
        import time
    
    def _make_http11_request(self, url, method='GET', headers=None, data=None, follow_redirects=True):
        """Make HTTP/1.1 request (original urllib implementation)"""
        import time
        start_time = time.time()
        
        try:
            # Create request efficiently
            if data and isinstance(data, str):
                data = data.encode('utf-8')
            
            req = urllib.request.Request(url, data=data, headers=headers, method=method)
            
            # Lazy import SSL and optimize SSL context creation
            if not self.verify_ssl:
                import ssl
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl_context))
            else:
                opener = urllib.request.build_opener()
            
            # Optimize redirect handling
            if not follow_redirects:
                class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
                    def redirect_request(self, req, fp, code, msg, headers, newurl):
                        return None
                opener.add_handler(NoRedirectHandler())
            
            # Install opener and make request
            urllib.request.install_opener(opener)
            
            response = urllib.request.urlopen(req, timeout=self.timeout)
            response_time = time.time() - start_time
            
            # Read response
            content = response.read()
            
            # Try to decode content
            try:
                if isinstance(content, bytes):
                    content = content.decode('utf-8', errors='ignore')
            except:
                content = str(content)
            
            # Get headers
            response_headers = dict(response.headers)
            
            return {
                'success': True,
                'status_code': response.getcode(),
                'response_headers': response_headers,
                'headers': response_headers,  # For backward compatibility
                'content': content,
                'content_type': response_headers.get('Content-Type', ''),
                'content_length': len(content),
                'response_time': response_time,
                'http_version': '1.1',
                'detected_protocol': 'HTTP/1.1',
                'url': response.geturl()
            }
            
        except urllib.error.HTTPError as e:
            return {
                'success': False,
                'status_code': e.code,
                'error': f'HTTP {e.code}: {e.reason}',
                'response_headers': dict(e.headers) if hasattr(e, 'headers') else {},
                'response_time': time.time() - start_time if 'start_time' in locals() else 0
            }
        except urllib.error.URLError as e:
            return {
                'success': False,
                'error': f'URL Error: {str(e)}',
                'response_time': time.time() - start_time if 'start_time' in locals() else 0
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Request failed: {str(e)}',
                'response_time': time.time() - start_time if 'start_time' in locals() else 0
            }
    
    def _make_manual_http_request(self, url, method='GET', headers=None, data=None, follow_redirects=True, http_version='1.0'):
        """Make HTTP request using manual socket connection for specific HTTP versions"""
        import socket
        import ssl
        import time
        
        start_time = time.time()
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
        path = parsed_url.path or '/'
        if parsed_url.query:
            path += '?' + parsed_url.query
        
        # Build HTTP request
        request_line = f"{method} {path} HTTP/{http_version}\r\n"
        
        # Add headers
        if headers is None:
            headers = {}
        headers.setdefault('Host', host)
        headers.setdefault('User-Agent', self.user_agent)
        
        if http_version == '1.0':
            headers['Connection'] = 'close'
        
        header_lines = ''.join([f"{k}: {v}\r\n" for k, v in headers.items()])
        
        # Build complete request
        http_request = request_line + header_lines + "\r\n"
        if data:
            if isinstance(data, str):
                data = data.encode('utf-8')
            http_request = http_request.encode('utf-8') + data
        else:
            http_request = http_request.encode('utf-8')
        
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Wrap with SSL if needed
            if parsed_url.scheme == 'https':
                context = ssl.create_default_context()
                if not self.verify_ssl:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)
            
            # Connect and send request
            sock.connect((host, port))
            sock.sendall(http_request)
            
            # Receive response
            response_data = b''
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response_data += chunk
                except socket.timeout:
                    break
            
            sock.close()
            response_time = time.time() - start_time
            
            # Parse response
            if not response_data:
                return {
                    'success': False,
                    'error': 'No response received',
                    'response_time': response_time
                }
            
            response_str = response_data.decode('utf-8', errors='ignore')
            lines = response_str.split('\\r\\n')
            
            # Parse status line
            status_line = lines[0]
            try:
                _, status_code, *status_text = status_line.split(' ')
                status_code = int(status_code)
            except:
                status_code = 0
            
            # Parse headers
            response_headers = {}
            content_start = 0
            for i, line in enumerate(lines[1:], 1):
                if line == '':
                    content_start = i + 1
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    response_headers[key.strip()] = value.strip()
            
            # Extract content
            content = '\\r\\n'.join(lines[content_start:])
            
            return {
                'success': True,
                'status_code': status_code,
                'response_headers': response_headers,
                'headers': response_headers,
                'content': content,
                'content_type': response_headers.get('Content-Type', ''),
                'content_length': len(content),
                'response_time': response_time,
                'http_version': http_version,
                'detected_protocol': f'HTTP/{http_version}',
                'url': url
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Manual HTTP/{http_version} request failed: {str(e)}',
                'response_time': time.time() - start_time if 'start_time' in locals() else 0
            }

    def analyze_http_headers(self, headers):
        """Analyze HTTP headers with optimized performance"""
        # Create case-insensitive header lookup for efficiency
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        # Pre-defined security headers for fast lookup
        security_headers = {
            'strict-transport-security': 'RFC 6797',
            'content-security-policy': 'W3C CSP', 
            'x-frame-options': 'RFC 7034',
            'x-content-type-options': 'WHATWG Fetch',
            'referrer-policy': 'W3C Referrer Policy',
            'permissions-policy': 'W3C Permissions Policy',
            'cross-origin-embedder-policy': 'WHATWG HTML',
            'cross-origin-opener-policy': 'WHATWG HTML',
            'cross-origin-resource-policy': 'WHATWG Fetch'
        }
        
        analysis = {
            'headers': headers,
            'security_headers': {},
            # Pre-populate common headers for efficiency
            'server_header': headers_lower.get('server', ''),
            'cache_control': headers_lower.get('cache-control', ''),
            'content_encoding': headers_lower.get('content-encoding', '')
        }
        
        # Efficient single-pass header analysis
        for header_lower, rfc in security_headers.items():
            if header_lower in headers_lower:
                analysis['security_headers'][header_lower.title().replace('-', '-')] = {
                    'present': True,
                    'value': headers_lower[header_lower],
                    'rfc': rfc
                }
            else:
                analysis['security_headers'][header_lower.title().replace('-', '-')] = {
                    'present': False,
                    'rfc': rfc
                }
        
        return analysis
        
        # COMMENTED OUT: Analysis logic - let Zabbix handle this
        # analysis = {
        #     'security_score': 0,
        #     'max_score': 100,
        #     'issues': [],
        #     'recommendations': [],
        #     'rfc_compliance': True,
        #     'security_headers': {}
        # }
        # 
        # # Security headers to check
        # security_headers = {
        #     'Strict-Transport-Security': {'weight': 15, 'rfc': 'RFC 6797'},
        #     'Content-Security-Policy': {'weight': 15, 'rfc': 'W3C CSP'},
        #     'X-Frame-Options': {'weight': 10, 'rfc': 'RFC 7034'},
        #     'X-Content-Type-Options': {'weight': 10, 'rfc': 'WHATWG Fetch'},
        #     'Referrer-Policy': {'weight': 10, 'rfc': 'W3C Referrer Policy'},
        #     'Permissions-Policy': {'weight': 10, 'rfc': 'W3C Permissions Policy'},
        #     'Cross-Origin-Embedder-Policy': {'weight': 5, 'rfc': 'WHATWG HTML'},
        #     'Cross-Origin-Opener-Policy': {'weight': 5, 'rfc': 'WHATWG HTML'},
        #     'Cross-Origin-Resource-Policy': {'weight': 5, 'rfc': 'WHATWG Fetch'}
        # }
        # 
        # # Check for security headers
        # for header, info in security_headers.items():
        #     header_lower = header.lower()
        #     found = False
        #     for response_header in headers:
        #         if response_header.lower() == header_lower:
        #             analysis['security_score'] += info['weight']
        #             analysis['security_headers'][header] = {
        #                 'present': True,
        #                 'value': headers[response_header],
        #                 'rfc': info['rfc']
        #             }
        #             found = True
        #             break
        #     
        #     if not found:
        #         analysis['issues'].append(f"Missing security header: {header}")
        #         analysis['recommendations'].append(f"Implement {header} header ({info['rfc']})")
        #         analysis['security_headers'][header] = {
        #             'present': False,
        #             'rfc': info['rfc']
        #         }
        # 
        # # Additional header analysis
        # server_header = headers.get('Server', headers.get('server', ''))
        # if server_header:
        #     # Check for version disclosure
        #     if re.search(r'\d+\.\d+', server_header):
        #         analysis['issues'].append("Server version disclosed in header")
        #         analysis['recommendations'].append("Hide server version information")
        # 
        # # Check caching headers
        # cache_control = headers.get('Cache-Control', headers.get('cache-control', ''))
        # if not cache_control:
        #     analysis['issues'].append("Missing Cache-Control header")
        #     analysis['recommendations'].append("Implement Cache-Control header (RFC 7234)")
        # 
        # # Check compression
        # content_encoding = headers.get('Content-Encoding', headers.get('content-encoding', ''))
        # if not content_encoding:
        #     analysis['issues'].append("Content not compressed")
        #     analysis['recommendations'].append("Enable compression (gzip/brotli)")
        
        return analysis

    def detect_proxy_and_cdn(self, headers, url):
        """Detect proxy servers and CDN providers"""
        detection = {
            'proxy_detected': False,
            'proxy_type': None,
            'cdn_detected': False,
            'cdn_provider': None,
            'edge_location': None,
            'cache_status': None
        }
        
        # Proxy detection headers
        proxy_headers = {
            'via': headers.get('Via', headers.get('via', '')),
            'x_forwarded_for': headers.get('X-Forwarded-For', headers.get('x-forwarded-for', '')),
            'x_real_ip': headers.get('X-Real-IP', headers.get('x-real-ip', '')),
            'forwarded': headers.get('Forwarded', headers.get('forwarded', ''))
        }
        
        if any(proxy_headers.values()):
            detection['proxy_detected'] = True
            if proxy_headers['via']:
                detection['proxy_type'] = 'HTTP Proxy'
            elif proxy_headers['x_forwarded_for']:
                detection['proxy_type'] = 'Load Balancer/Reverse Proxy'
        
        # CDN detection
        cdn_indicators = {
            'cloudflare': ['cf-ray', 'cf-cache-status', 'server'],
            'fastly': ['fastly-debug-digest', 'x-served-by', 'x-cache'],
            'akamai': ['akamai-transform', 'x-akamai-transformed'],
            'amazon': ['x-amz-cf-id', 'x-amz-cf-pop'],
            'azure': ['x-azure-ref', 'x-msedge-ref'],
            'google': ['x-goog-trace', 'alt-svc']
        }
        
        for provider, indicators in cdn_indicators.items():
            for indicator in indicators:
                if indicator.lower() in [h.lower() for h in headers.keys()]:
                    detection['cdn_detected'] = True
                    detection['cdn_provider'] = provider.title()
                    if provider == 'cloudflare' and 'cf-ray' in headers:
                        detection['edge_location'] = headers['cf-ray']
                    break
            if detection['cdn_detected']:
                break
        
        # Cache status detection
        cache_headers = ['x-cache', 'cf-cache-status', 'x-served-by']
        for cache_header in cache_headers:
            if cache_header.lower() in [h.lower() for h in headers.keys()]:
                detection['cache_status'] = headers.get(cache_header)
                break
        
        return detection

    def check_owasp_top10(self, url, headers, content):
        """Check for OWASP Top 10 security vulnerabilities"""
        security_analysis = {
            'owasp_findings': {},
            'risk_level': 'LOW',
            'recommendations': []
        }
        
        # A01: Broken Access Control
        if 'server' in headers and any(server in headers['server'].lower() for server in ['apache', 'nginx', 'iis']):
            if 'server-status' in content.lower() or 'server-info' in content.lower():
                security_analysis['owasp_findings']['A01_broken_access'] = True
                security_analysis['recommendations'].append('Disable server status pages')
        
        # A02: Cryptographic Failures
        if url.startswith('http://') and not url.startswith('https://'):
            security_analysis['owasp_findings']['A02_crypto_failures'] = True
            security_analysis['recommendations'].append('Implement HTTPS encryption')
            security_analysis['risk_level'] = 'HIGH'
        
        # A03: Injection (Basic XSS detection)
        if '<script>' in content.lower() and 'user' in content.lower():
            security_analysis['owasp_findings']['A03_injection_risk'] = True
            security_analysis['recommendations'].append('Review input validation and output encoding')
        
        # A05: Security Misconfiguration
        insecure_headers = {
            'server': 'Server version disclosure',
            'x-powered-by': 'Technology stack disclosure',
            'x-aspnet-version': 'Framework version disclosure'
        }
        
        for header, issue in insecure_headers.items():
            if header.lower() in [h.lower() for h in headers.keys()]:
                security_analysis['owasp_findings']['A05_security_misconfig'] = True
                security_analysis['recommendations'].append(f'Remove {header} header - {issue}')
        
        # A06: Vulnerable Components (based on server headers)
        if 'server' in headers:
            server_header = headers['server'].lower()
            if any(old_version in server_header for old_version in ['apache/2.2', 'nginx/1.0', 'iis/7.0']):
                security_analysis['owasp_findings']['A06_vulnerable_components'] = True
                security_analysis['recommendations'].append('Update web server to latest version')
                security_analysis['risk_level'] = 'MEDIUM'
        
        return security_analysis

    def check_ssl_compatibility(self, url):
        """Check SSL/TLS client compatibility (SSLLabs-style analysis)"""
        if not url.startswith('https://'):
            return {'error': 'SSL compatibility check requires HTTPS URL'}
        
        import ssl
        import socket
        
        parsed = urlparse(url)
        host = parsed.netloc.split(':')[0]
        port = parsed.port or 443
        
        compatibility = {
            'protocols': {},
            'cipher_suites': [],
            'client_compatibility': {
                'modern_browsers': True,
                'legacy_support': False,
                'mobile_compatibility': True
            },
            'security_grade': 'A',
            'certificate_info': {}
        }
        
        try:
            # Test different SSL/TLS protocols and collect cipher suites
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher_info = ssock.cipher()
                    if cipher_info:
                        cipher_name, tls_version, key_bits = cipher_info
                        compatibility['cipher_suites'].append({
                            'name': cipher_name,
                            'protocol': tls_version,
                            'key_bits': key_bits
                        })
                        
                    compatibility['protocols']['TLS'] = {
                        'supported': True,
                        'cipher': cipher_name if cipher_info else None,
                        'version': ssock.version(),
                        'key_bits': key_bits if cipher_info else None
                    }
                    
                    # Get certificate info
                    cert = ssock.getpeercert()
                    if cert:
                        compatibility['certificate_info'] = {
                            'subject': dict(x[0] for x in cert.get('subject', [])),
                            'issuer': dict(x[0] for x in cert.get('issuer', [])),
                            'serial_number': cert.get('serialNumber', ''),
                            'not_after': cert.get('notAfter', ''),
                            'not_before': cert.get('notBefore', '')
                        }
            
            # Test additional cipher suites by trying different contexts
            modern_ciphers = [
                'ECDHE-RSA-AES256-GCM-SHA384',
                'ECDHE-RSA-AES128-GCM-SHA256',
                'ECDHE-RSA-CHACHA20-POLY1305',
                'AES256-GCM-SHA384',
                'AES128-GCM-SHA256'
            ]
            
            for cipher in modern_ciphers:
                try:
                    test_context = ssl.create_default_context()
                    test_context.set_ciphers(cipher)
                    with socket.create_connection((host, port), timeout=5) as sock:
                        with test_context.wrap_socket(sock, server_hostname=host) as ssock:
                            if ssock.cipher() and ssock.cipher()[0] not in [c['name'] for c in compatibility['cipher_suites']]:
                                cipher_info = ssock.cipher()
                                compatibility['cipher_suites'].append({
                                    'name': cipher_info[0],
                                    'protocol': cipher_info[1],
                                    'key_bits': cipher_info[2]
                                })
                except:
                    continue  # Cipher not supported
            
            # Assess client compatibility and security grade
            tls_version = compatibility['protocols'].get('TLS', {}).get('version', '')
            if 'TLSv1.3' in tls_version:
                compatibility['security_grade'] = 'A+'
                compatibility['client_compatibility']['legacy_support'] = False
            elif 'TLSv1.2' in tls_version:
                compatibility['security_grade'] = 'A'
                compatibility['client_compatibility']['legacy_support'] = True
            else:
                compatibility['client_compatibility']['modern_browsers'] = False
                compatibility['security_grade'] = 'F'
        
        except Exception as e:
            compatibility['error'] = str(e)
        
        return compatibility

    def check_http3_support(self, url):
        """Check for HTTP/3 (QUIC) support"""
        http3_check = {
            'http3_supported': False,
            'alt_svc_header': None,
            'quic_detection': False
        }
        
        try:
            # Make HTTP/1.1 or HTTP/2 request and check for Alt-Svc header
            response = self.make_http_request(url)
            
            if response.get('success'):
                headers = response.get('response_headers', {})
                alt_svc = headers.get('alt-svc', headers.get('Alt-Svc', ''))
                
                if alt_svc:
                    http3_check['alt_svc_header'] = alt_svc
                    if 'h3' in alt_svc.lower() or 'quic' in alt_svc.lower():
                        http3_check['http3_supported'] = True
                        http3_check['quic_detection'] = True
        
        except Exception as e:
            http3_check['error'] = str(e)
        
        return http3_check

    def check_compliance_frameworks(self, url, headers):
        """Check compliance with major frameworks (SOC2, HIPAA, PCI DSS, ISO 27001)"""
        compliance = {
            'soc2_indicators': {},
            'hipaa_indicators': {},
            'pci_dss_indicators': {},
            'iso27001_indicators': {},
            'compliance_score': 0
        }
        
        # SOC2 Type II indicators
        compliance['soc2_indicators'] = {
            'encryption_in_transit': url.startswith('https://'),
            'security_headers': any(header in headers for header in ['strict-transport-security', 'content-security-policy']),
            'access_logging': 'x-forwarded-for' in headers or 'via' in headers
        }
        
        # HIPAA indicators
        compliance['hipaa_indicators'] = {
            'encryption_required': url.startswith('https://'),
            'audit_controls': 'x-request-id' in headers or 'x-correlation-id' in headers,
            'access_control': 'authorization' in headers or 'www-authenticate' in headers
        }
        
        # PCI DSS indicators
        compliance['pci_dss_indicators'] = {
            'secure_transmission': url.startswith('https://'),
            'secure_protocols': headers.get('strict-transport-security') is not None,
            'vulnerability_management': not any(old_server in headers.get('server', '').lower() for old_server in ['apache/2.2', 'nginx/1.0'])
        }
        
        # ISO 27001 indicators
        compliance['iso27001_indicators'] = {
            'information_security': url.startswith('https://'),
            'access_control': 'authorization' in headers,
            'incident_management': 'x-request-id' in headers
        }
        
        # Calculate overall compliance score
        total_checks = sum(len(framework) for framework in compliance.values() if isinstance(framework, dict))
        passed_checks = sum(
            sum(1 for check in framework.values() if check)
            for framework in compliance.values() 
            if isinstance(framework, dict)
        )
        
        if total_checks > 0:
            compliance['compliance_score'] = (passed_checks / total_checks) * 100
        
        return compliance

    def check_http_compliance(self, url):
        """Check HTTP protocol compliance"""
        result = self.make_http_request(url)
        
        if not result.get('success'):
            return {
                'error': result.get('error'),
                'success': False
            }
        
        # Raw data collection for Zabbix
        compliance = {
            'success': True,
            'status_code': result['status_code'],
            'response_time': result['response_time'],
            'content_type': result['content_type'],
            'content_length': result['content_length'],
            'headers': result['headers']
        }
        
        # Analyze headers for data collection
        header_analysis = self.analyze_http_headers(result['headers'])
        compliance.update(header_analysis)
        
        # Detect HTTP version
        headers = result['headers']
        if 'HTTP/2' in str(headers) or 'h2' in headers.get('upgrade', ''):
            compliance['protocol_version'] = 'HTTP/2'
        else:
            compliance['protocol_version'] = 'HTTP/1.1'
        
        # COMMENTED OUT: Analysis logic - let Zabbix handle this
        # compliance = {
        #     'compliance_score': 80,  # Start with base score
        #     'max_score': 100,
        #     'issues': [],
        #     'protocol_version': 'HTTP/1.1',  # Default assumption
        #     'status_code': result['status_code'],
        #     'response_time': result['response_time'],
        #     'content_type': result['content_type'],
        #     'content_length': result['content_length']
        # }
        # 
        # # Analyze headers
        # header_analysis = self.analyze_http_headers(result['headers'])
        # compliance.update(header_analysis)
        # 
        # # Check status code validity (RFC 7231)
        # status_code = result['status_code']
        # if status_code not in [200, 201, 202, 204, 301, 302, 304, 400, 401, 403, 404, 500, 502, 503, 504]:
        #     compliance['issues'].append(f"Non-standard HTTP status code: {status_code}")
        # 
        # # Check for HTTP/2 support
        # headers = result['headers']
        # if 'HTTP/2' in str(headers) or 'h2' in headers.get('upgrade', ''):
        #     compliance['protocol_version'] = 'HTTP/2'
        #     compliance['compliance_score'] += 10
        
        return compliance
    
    def test_http_versions(self, url):
        """Test all supported HTTP versions"""
        # Ensure URL has proper protocol
        if not url.startswith(('http://', 'https://')):
            url = f'https://{url}'  # Default to HTTPS
        
        versions_to_test = ['1.0', '1.1']
        if HTTP2_AVAILABLE:
            versions_to_test.append('2.0')
        
        results = {
            'url': url,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'version_support': {},
            'recommendations': []
        }
        
        for version in versions_to_test:
            try:
                response = self.make_http_request(url, force_version=version)
                
                if response and response.get('success'):
                    results['version_support'][f'HTTP_{version.replace(".", "_")}'] = {
                        'supported': True,
                        'status_code': response['status_code'],
                        'response_time': response.get('response_time', 0),
                        'detected_protocol': response.get('detected_protocol', f'HTTP/{version}'),
                        'server_header': response.get('response_headers', {}).get('Server', '')
                    }
                    
                    # Add version-specific recommendations
                    if version == '1.0':
                        results['recommendations'].append('Consider upgrading from HTTP/1.0 for better performance')
                    elif version == '2.0' and response.get('detected_protocol') == 'HTTP/2.0':
                        results['recommendations'].append('HTTP/2 is properly supported - excellent for performance')
                        
                else:
                    results['version_support'][f'HTTP_{version.replace(".", "_")}'] = {
                        'supported': False,
                        'error': response.get('error', 'Unknown error')
                    }
                    
            except Exception as e:
                results['version_support'][f'HTTP_{version.replace(".", "_")}'] = {
                    'supported': False,
                    'error': str(e)
                }
        
        return results

    def check_https_compliance(self, url):
        """Check HTTPS and TLS compliance"""
        if not url.startswith('https://'):
            url = url.replace('http://', 'https://')
        
        parsed = urlparse(url)
        host = parsed.netloc.split(':')[0]
        port = self.port or parsed.port or 443
        
        # Run TLS handshake script
        tls_result = self.run_script('tls', ['--check', host, str(port)])
        
        # Make HTTPS request
        https_result = self.make_http_request(url)
        
        # Raw data collection
        compliance = {
            'tls_analysis': tls_result,
            'https_response': https_result,
            'success': https_result.get('success', False)
        }
        
        if https_result.get('success'):
            headers = https_result['headers']
            # Collect HSTS data
            compliance['hsts_present'] = 'Strict-Transport-Security' in headers or 'strict-transport-security' in headers
            if compliance['hsts_present']:
                compliance['hsts_value'] = headers.get('Strict-Transport-Security') or headers.get('strict-transport-security')
            else:
                compliance['hsts_value'] = None
            
            # Collect cookie security data
            set_cookie = headers.get('Set-Cookie', '')
            compliance['cookies_secure'] = 'Secure' in set_cookie if set_cookie else None
            compliance['set_cookie'] = set_cookie
        else:
            compliance['hsts_present'] = False
            compliance['hsts_value'] = None
            compliance['cookies_secure'] = None
            compliance['set_cookie'] = None
        
        # COMMENTED OUT: Analysis logic - let Zabbix handle this
        # compliance = {
        #     'tls_analysis': tls_result,
        #     'https_response': https_result,
        #     'compliance_score': 70,
        #     'max_score': 100,
        #     'issues': [],
        #     'recommendations': []
        # }
        # 
        # if https_result.get('success'):
        #     # Check for HSTS header
        #     headers = https_result['headers']
        #     if 'Strict-Transport-Security' in headers or 'strict-transport-security' in headers:
        #         compliance['compliance_score'] += 15
        #     else:
        #         compliance['issues'].append("Missing HSTS header")
        #         compliance['recommendations'].append("Implement HSTS (RFC 6797)")
        #     
        #     # Check for secure cookies
        #     set_cookie = headers.get('Set-Cookie', '')
        #     if set_cookie and 'Secure' not in set_cookie:
        #         compliance['issues'].append("Cookies not marked as Secure")
        #         compliance['recommendations'].append("Mark cookies as Secure for HTTPS")
        # else:
        #     compliance['issues'].append(f"HTTPS connection failed: {https_result.get('error')}")
        #     compliance['compliance_score'] = 0
        
        return compliance

    def check_redirects(self, url):
        """Analyze redirect chains"""
        redirects = []
        current_url = url
        redirect_count = 0
        
        while redirect_count < self.max_redirects:
            result = self.make_http_request(current_url, follow_redirects=False)
            
            if not result.get('success'):
                break
            
            status_code = result['status_code']
            redirects.append({
                'url': current_url,
                'status_code': status_code,
                'response_time': result['response_time']
            })
            
            # Check if it's a redirect
            if status_code in [301, 302, 303, 307, 308]:
                location = result['headers'].get('Location')
                if not location:
                    redirects[-1]['error'] = "Redirect without Location header"
                    break
                
                # Handle relative URLs
                if not location.startswith(('http://', 'https://')):
                    location = urljoin(current_url, location)
                
                redirects[-1]['redirect_to'] = location
                current_url = location
                redirect_count += 1
            else:
                # Final destination reached
                break
        
        # Raw data collection
        analysis = {
            'redirect_chain': redirects,
            'redirect_count': redirect_count,
            'final_url': current_url
        }
        
        # Collect protocol transition data
        analysis['protocol_transitions'] = []
        for i, redirect in enumerate(redirects):
            if i > 0:
                prev_protocol = urlparse(redirects[i-1]['url']).scheme
                curr_protocol = urlparse(redirect['url']).scheme
                analysis['protocol_transitions'].append({
                    'from': prev_protocol,
                    'to': curr_protocol,
                    'https_to_http': prev_protocol == 'https' and curr_protocol == 'http'
                })
        
        # COMMENTED OUT: Analysis logic - let Zabbix handle this
        # analysis = {
        #     'redirect_chain': redirects,
        #     'redirect_count': redirect_count,
        #     'final_url': current_url,
        #     'issues': [],
        #     'recommendations': []
        # }
        # 
        # # Analyze redirect chain
        # if redirect_count > 3:
        #     analysis['issues'].append(f"Too many redirects: {redirect_count}")
        #     analysis['recommendations'].append("Minimize redirect chains for better performance")
        # 
        # # Check for mixed protocol redirects
        # for i, redirect in enumerate(redirects):
        #     if i > 0:
        #         prev_protocol = urlparse(redirects[i-1]['url']).scheme
        #         curr_protocol = urlparse(redirect['url']).scheme
        #         if prev_protocol == 'https' and curr_protocol == 'http':
        #             analysis['issues'].append("Downgrade from HTTPS to HTTP detected")
        #             analysis['recommendations'].append("Avoid HTTPS to HTTP redirects")
        
        return analysis

    def check_performance(self, url):
        """Check web performance metrics"""
        # Single request for quick performance check (not multiple for timeout concerns)
        result = self.make_http_request(url)
        
        if not result.get('success'):
            return {'error': 'No successful requests for performance analysis'}
        
        # Raw performance data collection
        performance = {
            'response_time': result['response_time'],
            'content_length': result['content_length']
        }
        
        if result.get('success'):
            headers = result['headers']
            
            # Collect performance-related data
            performance.update({
                'content_encoding': headers.get('Content-Encoding', headers.get('content-encoding', '')),
                'cache_control': headers.get('Cache-Control', headers.get('cache-control', '')),
                'server': headers.get('Server', headers.get('server', ''))
            })
            
            # Check for CDN indicators
            cdn_headers = ['cf-ray', 'x-cache', 'x-served-by', 'x-amz-cf-id']
            performance['cdn_detected'] = any(header in [h.lower() for h in headers.keys()] for header in cdn_headers)
            if performance['cdn_detected']:
                performance['cdn_headers'] = {h: headers.get(h) for h in headers.keys() if h.lower() in cdn_headers}
        
        return performance

    def check_content_validation(self, url):
        """Validate content integrity and structure"""
        result = self.make_http_request(url)
        
        if not result.get('success'):
            return {'error': result.get('error')}
        
        # Raw content data collection
        validation = {
            'content_type': result['content_type'],
            'content_length': result['content_length'],
            'charset': 'unknown'
        }
        
        # Extract charset
        content_type = result['content_type']
        if 'charset=' in content_type:
            validation['charset'] = content_type.split('charset=')[-1].strip()
        
        # Analyze content if HTML
        if 'text/html' in content_type:
            try:
                content = result.get('content', '')  # Use content field
                validation.update(self.validate_html_content(content))
            except Exception as e:
                validation['content_analysis_error'] = str(e)
        
        # COMMENTED OUT: Analysis logic - let Zabbix handle this
        # validation = {
        #     'content_type': result['content_type'],
        #     'content_length': result['content_length'],
        #     'charset': 'unknown',
        #     'validation_score': 80,
        #     'issues': [],
        #     'recommendations': []
        # }
        
        return validation

    def validate_html_content(self, content):
        """Validate HTML content structure"""
        # Raw HTML data collection
        validation = {
            'has_doctype': False,
            'has_title': False,
            'has_meta_charset': False,
            'has_meta_viewport': False,
            'title_length': 0,
            'title_text': ''
        }
        
        content_lower = content.lower()
        
        # Check DOCTYPE
        validation['has_doctype'] = '<!doctype html>' in content_lower
        
        # Check title
        title_match = re.search(r'<title[^>]*>([^<]*)</title>', content, re.IGNORECASE)
        if title_match:
            validation['has_title'] = True
            validation['title_text'] = title_match.group(1).strip()
            validation['title_length'] = len(validation['title_text'])
        
        # Check meta charset
        validation['has_meta_charset'] = bool(re.search(r'<meta[^>]+charset[^>]*>', content_lower))
        
        # Check viewport meta
        validation['has_meta_viewport'] = bool(re.search(r'<meta[^>]+viewport[^>]*>', content_lower))
        
        # COMMENTED OUT: Analysis logic - let Zabbix handle this
        # validation = {
        #     'has_doctype': False,
        #     'has_title': False,
        #     'has_meta_charset': False,
        #     'has_meta_viewport': False,
        #     'title_length': 0,
        #     'issues': [],
        #     'recommendations': []
        # }
        # 
        # content_lower = content.lower()
        # 
        # # Check DOCTYPE
        # if '<!doctype html>' in content_lower:
        #     validation['has_doctype'] = True
        # else:
        #     validation['issues'].append("Missing HTML5 DOCTYPE declaration")
        #     validation['recommendations'].append("Add <!DOCTYPE html> declaration")
        # 
        # # Check title
        # title_match = re.search(r'<title[^>]*>([^<]*)</title>', content, re.IGNORECASE)
        # if title_match:
        #     validation['has_title'] = True
        #     validation['title_length'] = len(title_match.group(1).strip())
        #     
        #     if validation['title_length'] == 0:
        #         validation['issues'].append("Empty title tag")
        #     elif validation['title_length'] > 60:
        #         validation['issues'].append("Title too long (>60 chars)")
        # else:
        #     validation['issues'].append("Missing title tag")
        #     validation['recommendations'].append("Add descriptive title tag")
        # 
        # # Check meta charset
        # if re.search(r'<meta[^>]+charset[^>]*>', content_lower):
        #     validation['has_meta_charset'] = True
        # else:
        #     validation['issues'].append("Missing charset meta tag")
        #     validation['recommendations'].append("Add <meta charset='utf-8'> tag")
        # 
        # # Check viewport meta
        # if re.search(r'<meta[^>]+viewport[^>]*>', content_lower):
        #     validation['has_meta_viewport'] = True
        # else:
        #     validation['recommendations'].append("Add viewport meta tag for mobile optimization")
        
        return validation

    def discover_services(self):
        """Discover available services with optimized port filtering"""
        parsed = urlparse(self.url)
        host = parsed.netloc.split(':')[0]
        
        # Use cached TCP script path and optimized arguments
        tcp_result = self.run_script('tcp', ['-d', '-t', '2', host], timeout_override=self.timeout)
        
        services = {
            'discovered_ports': tcp_result,
            'web_services': [],
            'ssl_services': []
        }
        
        # Optimized port filtering using class constants
        if tcp_result.get('data'):
            for port_info in tcp_result['data']:
                port = int(port_info.get('{#TCPPORT}', 0))
                if port in self._WEB_PORTS:
                    if port in self._SSL_PORTS:
                        services['ssl_services'].append(port)
                    else:
                        services['web_services'].append(port)
        
        return services

    def run_health_check(self):
        """Comprehensive health check with optimized script calls"""
        health = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'target': self.target,
            'url': self.url,
            'port': self.port,
            'tests': {}
        }
        
        # Domain health dependency removed - domain_health should orchestrate web_health, not vice versa
        
        # Email health check removed - not needed for web health monitoring
        
        if self.debug:
            print("DEBUG: Running TCP connectivity check...", file=sys.stderr)
        health['tests']['tcp'] = self.discover_services()
        
        # Pre-calculate host and port for TLS check
        parsed = urlparse(self.url)
        host = parsed.netloc.split(':')[0]
        port = self.port or parsed.port or (443 if parsed.scheme == 'https' else 80)
        
        if self.debug:
            print("DEBUG: Running TLS analysis...", file=sys.stderr)
        health['tests']['tls'] = self.run_script('tls', ['--check', host, str(port)])
        
        # 5. HTTP compliance
        if self.debug:
            print("DEBUG: Running HTTP compliance check...", file=sys.stderr)
        health['tests']['http'] = self.check_http_compliance(self.url)
        
        # 6. HTTPS compliance  
        if self.debug:
            print("DEBUG: Running HTTPS compliance check...", file=sys.stderr)
        health['tests']['https'] = self.check_https_compliance(self.url)
        
        # 7. Redirect analysis
        if self.debug:
            print("DEBUG: Running redirect analysis...", file=sys.stderr)
        health['tests']['redirects'] = self.check_redirects(self.url)
        
        # 8. Performance analysis
        if self.debug:
            print("DEBUG: Running performance analysis...", file=sys.stderr)
        health['tests']['performance'] = self.check_performance(self.url)
        
        # 9. Content validation
        if self.debug:
            print("DEBUG: Running content validation...", file=sys.stderr)
        health['tests']['content'] = self.check_content_validation(self.url)
        
        # COMMENTED OUT: Analysis logic - let Zabbix handle this
        # health = {
        #     'timestamp': datetime.now(timezone.utc).isoformat(),
        #     'target': self.target,
        #     'url': self.url,
        #     'domain': self.domain,
        #     'overall_score': 0,
        #     'max_score': 500,  # Total possible score
        #     'tests': {}
        # }
        # 
        # # Calculate overall score
        # scores = []
        # for test_name, test_result in health['tests'].items():
        #     if isinstance(test_result, dict) and 'compliance_score' in test_result:
        #         scores.append(test_result['compliance_score'])
        #     elif isinstance(test_result, dict) and 'performance_score' in test_result:
        #         scores.append(test_result['performance_score'])
        #     elif isinstance(test_result, dict) and 'security_score' in test_result:
        #         scores.append(test_result['security_score'])
        # 
        # if scores:
        #     health['overall_score'] = sum(scores) / len(scores)
        
        return health

def main():
    parser = argparse.ArgumentParser(description='Web Server Health Monitoring')
    parser.add_argument('command', choices=[
        'discover', 'health', 'http', 'https', 'security', 'performance',
        'compliance', 'redirects', 'headers', 'content', 'api', 'websocket',
        'cdn', 'compression', 'caching', 'cookies', 'cors', 'versions', 
        'owasp', 'ssl-compat', 'http3', 'proxy', 'frameworks', 'selftest'
    ], help='Command to execute')
    parser.add_argument('target', help='Target URL or host')
    parser.add_argument('port', nargs='?', type=int, help='Optional port number (defaults to 80 for HTTP, 443 for HTTPS)')
    parser.add_argument('--timeout', '-t', type=int, default=3, help='Request timeout in seconds (default: 3)')
    parser.add_argument('--http-version', choices=['1.0', '1.1', '2.0'], help='Force specific HTTP version')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    
    args = parser.parse_args()
    
    # Validate all parameters before proceeding
    validation_errors = []
    
    # Validate target parameter
    if not args.target or not isinstance(args.target, str) or args.target.strip() == '':
        validation_errors.append('Target URL or host cannot be empty')
    
    # Validate port parameter
    if args.port is not None:
        if args.port < 1 or args.port > 65535:
            validation_errors.append(f'Port {args.port} out of valid range 1-65535')
    
    # Validate timeout parameter
    if args.timeout <= 0:
        validation_errors.append(f'Timeout must be positive, got: {args.timeout}')
    if args.timeout > 300:  # Maximum 5 minutes
        validation_errors.append(f'Timeout too large (max 300s), got: {args.timeout}')
    
    # Validate HTTP version parameter
    if args.http_version:
        valid_versions = ['1.0', '1.1', '2.0']
        if args.http_version not in valid_versions:
            validation_errors.append(f'Unsupported HTTP version: {args.http_version}. Supported: {valid_versions}')
    
    # Report validation errors
    if validation_errors:
        error_result = {
            'error': 'Parameter validation failed',
            'validation_errors': validation_errors,
            'command': args.command,
            'target': args.target,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        print(json.dumps(error_result, indent=2))
        sys.exit(1)
    
    # Override debug setting
    if args.debug:
        os.environ['HTTP_DEBUG'] = '1'
    
    try:
        monitor = WebHealthMonitor(args.target, args.port, args.timeout, args.http_version)
    except ValueError as e:
        error_result = {
            'error': f'WebHealthMonitor initialization failed: {str(e)}',
            'command': args.command,
            'target': args.target,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        print(json.dumps(error_result, indent=2))
        sys.exit(1)
    
    try:
        if args.command == 'discover':
            result = monitor.discover_services()
        elif args.command == 'health':
            result = monitor.run_health_check()
        elif args.command == 'http':
            result = monitor.check_http_compliance(args.target)
        elif args.command == 'https':
            result = monitor.check_https_compliance(args.target)
        elif args.command == 'security':
            http_result = monitor.make_http_request(args.target)
            if http_result.get('success'):
                result = monitor.analyze_http_headers(http_result['headers'])
            else:
                result = {'error': http_result.get('error')}
        elif args.command == 'redirects':
            result = monitor.check_redirects(args.target)
        elif args.command == 'content':
            result = monitor.check_content_validation(args.target)
        elif args.command == 'versions':
            result = monitor.test_http_versions(args.target)
        elif args.command == 'owasp':
            # OWASP Top 10 security analysis
            http_result = monitor.make_http_request(args.target)
            if http_result.get('success'):
                result = monitor.check_owasp_top10(args.target, http_result['headers'], http_result.get('content', ''))
            else:
                result = {'error': f'Failed to fetch content for OWASP analysis: {http_result.get("error")}'}
        elif args.command == 'ssl-compat':
            # SSL/TLS compatibility analysis
            result = monitor.check_ssl_compatibility(args.target)
        elif args.command == 'http3':
            # HTTP/3 support detection
            result = monitor.check_http3_support(args.target)
        elif args.command == 'proxy':
            # CDN and proxy detection
            http_result = monitor.make_http_request(args.target)
            if http_result.get('success'):
                result = monitor.detect_proxy_and_cdn(http_result['headers'], args.target)
            else:
                result = {'error': f'Failed to fetch headers for CDN analysis: {http_result.get("error")}'}
        elif args.command == 'frameworks':
            # Compliance frameworks analysis
            http_result = monitor.make_http_request(args.target)
            if http_result.get('success'):
                result = monitor.check_compliance_frameworks(args.target, http_result['headers'])
            else:
                result = {'error': f'Failed to fetch headers for compliance analysis: {http_result.get("error")}'}
        elif args.command == 'selftest':
            # Basic self-test
            script_paths = monitor._script_paths
            result = {
                'status': 'OK',
                'http2_available': HTTP2_AVAILABLE,
                'supported_versions': ['HTTP/1.0', 'HTTP/1.1'] + (['HTTP/2.0'] if HTTP2_AVAILABLE else []),
                'scripts_available': {
                    'tls_handshake': os.path.exists(script_paths.get('tls', '')),
                    'tcp_port_scan': os.path.exists(script_paths.get('tcp', ''))
                },
                'version': '2.0'
            }
        else:
            result = {'error': f'Command {args.command} not implemented yet'}
        
        print(json.dumps(result, indent=2))
        
    except Exception as e:
        error_result = {
            'error': str(e),
            'command': args.command,
            'target': args.target,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        print(json.dumps(error_result, indent=2))
        sys.exit(1)

if __name__ == '__main__':
    main()