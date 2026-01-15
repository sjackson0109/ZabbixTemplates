# Web Health & Compliance Monitoring for Zabbix

## Overview

This Zabbix template provides comprehensive web server infrastructure monitoring and RFC compliance validation. It performs extensive HTTP/HTTPS protocol analysis, TLS/SSL security assessment, performance monitoring, and security compliance checks across multiple modern web standards.

## Features

### Core Capabilities
- **Multi-Protocol Support**: HTTP/1.0, HTTP/1.1, HTTP/2.0, and HTTP/3.0 (QUIC) detection
- **TLS/SSL Security Analysis**: Certificate validation, cipher suite analysis, protocol support assessment
- **Performance Monitoring**: Response times, compression analysis, caching optimisation validation
- **Security Compliance**: OWASP Top 10 checks, security headers analysis, vulnerability detection
- **Content Validation**: HTTP headers, cookies, CORS configuration, redirect chain analysis
- **CDN & Infrastructure Detection**: Load balancer identification, proxy detection, hosting provider analysis
- **API Monitoring**: REST API health, GraphQL endpoint testing, WebSocket connectivity
- **Network Analysis**: TCP port scanning, service discovery, connectivity validation

### Protocol Support
- **HTTP/1.0**: Legacy protocol support for older systems
- **HTTP/1.1**: Standard protocol with keep-alive and pipelining
- **HTTP/2.0**: Modern protocol with multiplexing and server push detection
- **HTTP/3.0 (QUIC)**: Next-generation protocol over UDP with enhanced security
- **WebSocket**: Real-time communication protocol validation
- **GraphQL**: API endpoint health and schema validation
- **gRPC**: High-performance RPC framework monitoring

### Security Analysis
- **TLS/SSL Assessment**: 
  - Certificate chain validation and expiry monitoring
  - Cipher suite enumeration and strength analysis
  - Protocol version support (TLS 1.0-1.3)
  - Certificate transparency log validation
  - HPKP (HTTP Public Key Pinning) validation
- **Security Headers Analysis**:
  - HSTS (HTTP Strict Transport Security) configuration
  - CSP (Content Security Policy) validation
  - X-Frame-Options and clickjacking protection
  - X-Content-Type-Options validation
  - Referrer-Policy analysis
  - Feature-Policy and Permissions-Policy validation
- **Cookie Security**: HttpOnly, Secure, SameSite attribute validation
- **OWASP Top 10 Compliance**: Automated security vulnerability assessment
- **Authentication & Authorisation**: HTTP Basic/Digest, OAuth, JWT validation

### Performance Metrics
- **Response Time Analysis**: 
  - DNS resolution time
  - TCP connection establishment
  - TLS handshake duration
  - Time to first byte (TTFB)
  - Content download time
- **Compression Analysis**: Gzip, Brotli, Deflate detection and efficiency
- **Caching Validation**:
  - Cache-Control header analysis
  - ETag and Last-Modified validation
  - CDN cache hit/miss detection
  - Browser caching optimisation
- **Content Optimisation**:
  - Image compression validation
  - Minification detection
  - Resource loading analysis
  - Critical resource prioritisation

### Compliance Framework Assessment
- **SOC 2 Type II**: Security, availability, processing integrity indicators
- **HIPAA**: Healthcare data protection compliance checks
- **PCI DSS**: Payment card industry security standards
- **ISO 27001**: Information security management indicators
- **GDPR**: Data protection and privacy compliance markers
- **NIST Cybersecurity Framework**: Risk assessment and mitigation validation

## RFC Compliance

| RFC | Description | Checks Implemented |
|-----|-------------|-------------------|
| RFC 7230-7237 | HTTP/1.1 Message Syntax and Routing | Header validation, chunked encoding, connection management |
| RFC 9110 | HTTP Semantics | Status codes, methods, headers semantic validation |
| RFC 9111 | HTTP Caching | Cache-Control, ETag, expires validation |
| RFC 9112 | HTTP/1.1 Message Syntax and Routing | Request/response format validation |
| RFC 7540 | HTTP/2 | Protocol detection, settings frame analysis |
| RFC 9114 | HTTP/3 | Alt-Svc header detection, QUIC protocol identification |
| RFC 6455 | WebSocket Protocol | Upgrade handshake, frame validation |
| RFC 8446 | TLS 1.3 | Protocol support, cipher suite validation |
| RFC 5246 | TLS 1.2 | Legacy protocol support assessment |
| RFC 6797 | HTTP Strict Transport Security | HSTS header validation, preload list checking |
| RFC 7469 | HTTP Public Key Pinning | HPKP header analysis, pin validation |
| RFC 6265 | HTTP State Management (Cookies) | Cookie attributes, security flags, SameSite validation |
| RFC 3986 | URI Generic Syntax | URL format validation, encoding verification |
| RFC 6454 | Web Origin Concept | CORS validation, origin policy checking |
| RFC 7034 | X-Frame-Options | Clickjacking protection validation |
| RFC 8941 | Structured Field Values | HTTP header parsing and validation |
| RFC 7231 | HTTP/1.1 Semantics and Content | Content-Type, Accept headers validation |
| RFC 7232 | HTTP/1.1 Conditional Requests | ETag, If-Modified-Since validation |
| RFC 7233 | HTTP/1.1 Range Requests | Partial content support validation |
| RFC 7234 | HTTP/1.1 Caching | Cache directive compliance |
| RFC 7235 | HTTP/1.1 Authentication | WWW-Authenticate, Authorisation headers |
| RFC 6585 | Additional HTTP Status Codes | Extended status code validation |
| RFC 7725 | HTTP/2 Connection Header | HTTP/2 upgrade mechanism validation |

## Requirements

- **Zabbix Version**: Server/Proxy 7.0+ with external script support
- **Python**: 3.6+ with required libraries
- **Network Access**: Outbound HTTPS (443/tcp), HTTP (80/tcp), and custom ports
- **Dependencies**: httpx[http2], dnspython (for enhanced functionality)
- **External Scripts**: 
  - `get_web_health.py` (main monitoring script)
  - `get_tls_handshake.py` (TLS certificate analysis)
  - `get_tcp_port_scan.py` (network connectivity testing)

## Installation

### 1. Deploy External Scripts

Copy the monitoring scripts to your Zabbix external scripts directory:

```bash
# Linux/Unix Installation
sudo mkdir -p /usr/lib/zabbix/externalscripts
sudo cp externalscripts/get_web_health.py /usr/lib/zabbix/externalscripts/
sudo cp externalscripts/get_tls_handshake.py /usr/lib/zabbix/externalscripts/
sudo cp externalscripts/get_tcp_port_scan.py /usr/lib/zabbix/externalscripts/

# Set proper permissions
sudo chmod +x /usr/lib/zabbix/externalscripts/get_web_health.py
sudo chmod +x /usr/lib/zabbix/externalscripts/get_tls_handshake.py
sudo chmod +x /usr/lib/zabbix/externalscripts/get_tcp_port_scan.py

# Set ownership
sudo chown zabbix:zabbix /usr/lib/zabbix/externalscripts/get_web_health.py
sudo chown zabbix:zabbix /usr/lib/zabbix/externalscripts/get_tls_handshake.py
sudo chown zabbix:zabbix /usr/lib/zabbix/externalscripts/get_tcp_port_scan.py
```

```powershell
# Windows Installation
# Copy to Zabbix Agent external scripts directory
Copy-Item "externalscripts\get_web_health.py" -Destination "C:\Program Files\Zabbix Agent\externalscripts\"
Copy-Item "externalscripts\get_tls_handshake.py" -Destination "C:\Program Files\Zabbix Agent\externalscripts\"
Copy-Item "externalscripts\get_tcp_port_scan.py" -Destination "C:\Program Files\Zabbix Agent\externalscripts\"
```

### 2. Install Python Dependencies

Install required Python libraries for enhanced functionality:

```bash
# Using pip
pip3 install httpx[http2] dnspython requests urllib3

# Using package manager (Debian/Ubuntu)
sudo apt-get update
sudo apt-get install python3-pip python3-httpx python3-dnspython

# Using package manager (RHEL/CentOS)
sudo yum install python3-pip
pip3 install --user httpx[http2] dnspython
```

### 3. Import Zabbix Template

Import the Web Health template into Zabbix:

1. Navigate to **Configuration** → **Templates**
2. Click **Import**
3. Select `templates/web_health.yaml`
4. Review import options
5. Click **Import**

### 4. Verify Installation

Test the script installation:

```bash
# Test basic functionality
/usr/lib/zabbix/externalscripts/get_web_health.py discover google.com
/usr/lib/zabbix/externalscripts/get_web_health.py health https://google.com

# Test with timeout
/usr/lib/zabbix/externalscripts/get_web_health.py performance https://example.com --timeout 10

# Verbose testing
/usr/lib/zabbix/externalscripts/get_web_health.py selftest https://httpbin.org
```

## Configuration

### Host Setup

1. **Create Host**: Create a new host in Zabbix for each website/service to monitor
2. **Link Template**: Assign the "Web Health" template to the host
3. **Configure Macros**: Set the required host-level macros (see table below)
4. **Verify Connectivity**: Ensure the Zabbix server/proxy can reach target URLs

### Host Macros

Configure these macros at the host level for each monitored website:

| Macro | Description | Default | Example |
|-------|-------------|---------|---------|
| `{$WEB.URL}` | Target URL or hostname (required) | - | `https://example.com` |
| `{$WEB.PORT}` | Override port number | 443/80 | `8443` |
| `{$WEB.TIMEOUT}` | Request timeout in seconds | 10 | `15` |
| `{$WEB.HTTP_VERSION}` | Preferred HTTP version | `1.1` | `2.0` |
| `{$WEB.USER_AGENT}` | Custom User-Agent string | `WebHealthMonitor/1.0` | `ZabbixMonitor/1.0` |
| `{$WEB.MAX_REDIRECTS}` | Maximum redirect follows | 10 | `5` |
| `{$WEB.VERIFY_SSL}` | SSL certificate verification | `1` | `0` |
| `{$WEB.DEBUG}` | Enable debug logging | `0` | `1` |
| `{$WEB.HEALTH_CRITICAL}` | Health score critical threshold | `70` | `60` |
| `{$WEB.HEALTH_WARNING}` | Health score warning threshold | `85` | `80` |
| `{$WEB.RESPONSE_TIME_CRITICAL}` | Response time critical (ms) | `5000` | `3000` |
| `{$WEB.RESPONSE_TIME_WARNING}` | Response time warning (ms) | `2000` | `1500` |
| `{$WEB.TLS_EXPIRY_WARNING}` | TLS cert expiry warning (days) | `30` | `45` |
| `{$WEB.TLS_EXPIRY_CRITICAL}` | TLS cert expiry critical (days) | `7` | `14` |

### Global Template Macros

These macros can be configured at the template level for default behaviour:

| Macro | Description | Default Value |
|-------|-------------|---------------|
| `{$WEB.DEFAULT_TIMEOUT}` | Default request timeout | `10` |
| `{$WEB.DEFAULT_HTTP_VERSION}` | Default HTTP version | `1.1` |
| `{$WEB.HEALTH_CHECK_INTERVAL}` | Health check frequency | `5m` |
| `{$WEB.PERFORMANCE_CHECK_INTERVAL}` | Performance check frequency | `2m` |
| `{$WEB.SECURITY_CHECK_INTERVAL}` | Security check frequency | `30m` |
| `{$WEB.COMPLIANCE_CHECK_INTERVAL}` | Compliance check frequency | `1h` |

## Usage Examples

### Command Line Interface

The `get_web_health.py` script supports multiple monitoring modes:

```bash
# Service Discovery
get_web_health.py discover example.com
get_web_health.py discover https://api.example.com 8443

# Overall Health Assessment
get_web_health.py health https://example.com
get_web_health.py health example.com 443 --timeout 15

# Protocol-Specific Testing
get_web_health.py http http://example.com
get_web_health.py https https://secure.example.com
get_web_health.py http3 https://modern.example.com

# Security Analysis
get_web_health.py security https://banking.example.com
get_web_health.py tls https://secure.example.com
get_web_health.py headers https://api.example.com

# Performance Testing
get_web_health.py performance https://cdn.example.com
get_web_health.py compression https://static.example.com
get_web_health.py caching https://images.example.com

# Compliance Validation
get_web_health.py compliance https://healthcare.example.com
get_web_health.py owasp https://webapp.example.com
get_web_health.py gdpr https://eu.example.com

# Content Analysis
get_web_health.py content https://www.example.com
get_web_health.py redirects https://old.example.com
get_web_health.py cookies https://shop.example.com

# API & Modern Protocols
get_web_health.py api https://api.example.com/v1/health
get_web_health.py graphql https://api.example.com/graphql
get_web_health.py websocket wss://realtime.example.com

# Infrastructure Analysis
get_web_health.py cdn https://static.example.com
get_web_health.py loadbalancer https://lb.example.com
get_web_health.py proxy https://proxy.example.com

# Self-Testing
get_web_health.py selftest https://httpbin.org
```

### Zabbix Integration Examples

```bash
# Zabbix item key examples
get_web_health.py[health,{$WEB.URL}]
get_web_health.py[performance,{$WEB.URL},{$WEB.PORT}]
get_web_health.py[security,{$WEB.URL}]
get_web_health.py[compliance,{$WEB.URL}]
get_web_health.py[https,{$WEB.URL}]
get_web_health.py[http3,{$WEB.URL}]
```

## Monitoring Capabilities

### Health Score Calculation

The overall health score (0-100%) combines multiple assessment categories:

| Category | Weight | Description |
|----------|--------|-------------|
| **Connectivity** | 25% | Basic HTTP/HTTPS connectivity and response codes |
| **Performance** | 20% | Response times, compression, caching efficiency |
| **Security** | 25% | TLS configuration, security headers, vulnerability assessment |
| **Compliance** | 15% | RFC compliance, best practices adherence |
| **Content** | 10% | Content validity, redirect chains, error handling |
| **Infrastructure** | 5% | CDN, load balancing, hosting optimisation |

### Security Assessment

#### TLS/SSL Analysis
- **Certificate Validation**: Expiry, chain of trust, CA validation
- **Protocol Support**: TLS 1.0-1.3 support matrix
- **Cipher Suites**: Strength analysis, deprecated algorithm detection
- **Certificate Transparency**: CT log validation and monitoring
- **OCSP Stapling**: Certificate revocation checking optimisation

#### Security Headers
- **HSTS**: Strict Transport Security configuration and preload status
- **CSP**: Content Security Policy validation and effectiveness
- **Frame Protection**: X-Frame-Options and frame-ancestors validation
- **Content Type**: X-Content-Type-Options and MIME sniffing protection
- **Referrer Policy**: Information leakage prevention
- **Feature Policy**: Browser feature restriction validation

#### OWASP Top 10 Assessment
- **A01:2021**: Broken Access Control detection
- **A02:2021**: Cryptographic Failures identification
- **A03:2021**: Injection vulnerability indicators
- **A04:2021**: Insecure Design patterns
- **A05:2021**: Security Misconfiguration detection
- **A06:2021**: Vulnerable Components identification
- **A07:2021**: Authentication Failures assessment
- **A08:2021**: Data Integrity Failures detection
- **A09:2021**: Logging and Monitoring assessment
- **A10:2021**: SSRF vulnerability indicators

### Performance Monitoring

#### Response Time Breakdown
- **DNS Resolution**: Domain name lookup time
- **TCP Connection**: Socket establishment time
- **TLS Handshake**: SSL/TLS negotiation time
- **Request Processing**: Server processing time
- **Content Transfer**: Data download time
- **Total Response**: End-to-end response time

#### Optimisation Analysis
- **Compression**: Gzip, Brotli, Deflate efficiency
- **Caching**: Browser and CDN cache configuration
- **Minification**: CSS, JavaScript, HTML optimisation
- **Image Optimisation**: Format selection, compression ratios
- **Resource Loading**: Critical path optimisation

### Content Validation

#### HTTP Analysis
- **Status Codes**: Proper response code usage
- **Headers**: Required and optional header validation
- **Content-Type**: MIME type accuracy and consistency
- **Character Encoding**: UTF-8 and encoding validation
- **Content Length**: Accurate content size reporting

#### Redirect Analysis
- **Redirect Chains**: Hop count and efficiency
- **Status Codes**: 301, 302, 303, 307, 308 usage
- **HTTPS Upgrades**: HTTP to HTTPS redirect validation
- **Canonical URLs**: Proper canonicalisation implementation
- **Redirect Loops**: Circular reference detection

## Items and Triggers

### Master Items

| Item Name | Key | Type | Description |
|-----------|-----|------|-------------|
| Web Health Score | `get_web_health.py[health,{$WEB.URL}]` | External | Overall health percentage (0-100) |
| Web Health Report | `get_web_health.py[health,{$WEB.URL}]` | External | Full JSON health report |
| Performance Metrics | `get_web_health.py[performance,{$WEB.URL}]` | External | Response times and optimisation data |
| Security Assessment | `get_web_health.py[security,{$WEB.URL}]` | External | Security configuration and vulnerabilities |
| Compliance Report | `get_web_health.py[compliance,{$WEB.URL}]` | External | RFC and framework compliance status |

### Dependent Items

#### Performance Items
| Item Name | JSONPath | Units | Description |
|-----------|----------|-------|-------------|
| HTTP Response Time | `$.performance.total_response_time` | ms | Total HTTP response time |
| DNS Resolution Time | `$.performance.dns_time` | ms | DNS lookup duration |
| TCP Connect Time | `$.performance.connect_time` | ms | TCP connection establishment |
| TLS Handshake Time | `$.performance.tls_time` | ms | TLS negotiation time |
| Server Response Time | `$.performance.server_time` | ms | Server processing time |
| Content Download Time | `$.performance.download_time` | ms | Content transfer time |
| Compression Ratio | `$.performance.compression_ratio` | % | Content compression efficiency |
| Cache Hit Ratio | `$.performance.cache_hit_ratio` | % | Cache effectiveness |

#### Security Items
| Item Name | JSONPath | Type | Description |
|-----------|----------|------|-------------|
| TLS Version | `$.security.tls_version` | Text | Highest supported TLS version |
| Certificate Expiry | `$.security.cert_expires_days` | Numeric | Days until certificate expiry |
| Security Headers Score | `$.security.headers_score` | Numeric | Security headers compliance (0-100) |
| HSTS Enabled | `$.security.hsts_enabled` | Numeric | HSTS configuration status (0/1) |
| CSP Enabled | `$.security.csp_enabled` | Numeric | Content Security Policy status (0/1) |
| Vulnerability Count | `$.security.vulnerabilities` | Numeric | Number of detected vulnerabilities |
| OWASP Score | `$.security.owasp_score` | Numeric | OWASP Top 10 compliance (0-100) |

#### Compliance Items  
| Item Name | JSONPath | Type | Description |
|-----------|----------|------|-------------|
| RFC Compliance Score | `$.compliance.rfc_score` | Numeric | RFC compliance percentage (0-100) |
| HTTP/1.1 Compliance | `$.compliance.http11_compliant` | Numeric | HTTP/1.1 RFC compliance (0/1) |
| HTTP/2 Support | `$.compliance.http2_supported` | Numeric | HTTP/2 protocol support (0/1) |
| HTTP/3 Support | `$.compliance.http3_supported` | Numeric | HTTP/3 protocol support (0/1) |
| Cookie Compliance | `$.compliance.cookie_compliant` | Numeric | Cookie RFC compliance (0/1) |
| GDPR Indicators | `$.compliance.gdpr_indicators` | Numeric | GDPR compliance markers count |

### Triggers

#### Critical Triggers
| Trigger Name | Expression | Description |
|--------------|------------|-------------|
| Web Service Down | `last(/Web Health/get_web_health.py[health,{$WEB.URL}])=0` | Service completely unavailable |
| Health Score Critical | `last(/Web Health/get_web_health.py[health,{$WEB.URL}])<{$WEB.HEALTH_CRITICAL}` | Overall health below critical threshold |
| Certificate Expires Soon | `last(/Web Health/web.cert.expires.days)<{$WEB.TLS_EXPIRY_CRITICAL}` | TLS certificate expires within critical period |
| Response Time Critical | `last(/Web Health/web.response.time)>{$WEB.RESPONSE_TIME_CRITICAL}` | Response time exceeds critical threshold |
| Security Vulnerability High | `last(/Web Health/web.security.vulnerabilities)>5` | High number of security vulnerabilities |

#### Warning Triggers  
| Trigger Name | Expression | Description |
|--------------|------------|-------------|
| Health Score Warning | `last(/Web Health/get_web_health.py[health,{$WEB.URL}])<{$WEB.HEALTH_WARNING}` | Health score below warning threshold |
| Certificate Expires Warning | `last(/Web Health/web.cert.expires.days)<{$WEB.TLS_EXPIRY_WARNING}` | Certificate expires within warning period |
| Response Time Warning | `last(/Web Health/web.response.time)>{$WEB.RESPONSE_TIME_WARNING}` | Response time exceeds warning threshold |
| Security Headers Missing | `last(/Web Health/web.security.headers.score)<70` | Important security headers missing |
| Compression Disabled | `last(/Web Health/web.performance.compression.ratio)=0` | Content compression not enabled |

#### Information Triggers
| Trigger Name | Expression | Description |
|--------------|------------|-------------|
| HTTP/3 Available | `last(/Web Health/web.compliance.http3.supported)=1 and last(/Web Health/web.compliance.http3.supported,#2)=0` | HTTP/3 support newly detected |
| Security Headers Improved | `change(/Web Health/web.security.headers.score)>10` | Security headers score significantly improved |
| Performance Improved | `change(/Web Health/web.response.time)<-500` | Response time significantly improved |

## Discovery Rules

### Web Service Discovery
Automatically discovers available web services and protocols:

| Discovery Rule | Key | Description |
|----------------|-----|-------------|
| HTTP Services | `get_web_health.py[discover,{$WEB.URL}]` | Discovers available HTTP/HTTPS services |
| TLS Protocols | `get_web_health.py[tls_discovery,{$WEB.URL}]` | Discovers supported TLS versions |
| API Endpoints | `get_web_health.py[api_discovery,{$WEB.URL}]` | Discovers API endpoints and versions |

### Item Prototypes
- **Service Status**: `web.service.status[{#SERVICE}]`
- **Protocol Support**: `web.protocol.supported[{#PROTOCOL}]`
- **API Health**: `web.api.health[{#ENDPOINT}]`

## Advanced Configuration

### Custom Health Scoring

Customise health score weighting by modifying the script configuration:

```python
# In get_web_health.py, modify HEALTH_WEIGHTS
HEALTH_WEIGHTS = {
    'connectivity': 0.30,    # Increase connectivity weight
    'performance': 0.25,     # Increase performance weight  
    'security': 0.20,        # Reduce security weight
    'compliance': 0.15,      # Keep compliance weight
    'content': 0.05,         # Reduce content weight
    'infrastructure': 0.05   # Keep infrastructure weight
}
```

### Environment Variables

Configure global behaviour using environment variables:

```bash
# HTTP Configuration
export HTTP_TIMEOUT=15
export HTTP_USER_AGENT="CustomMonitor/2.0"
export HTTP_MAX_REDIRECTS=5
export HTTP_VERIFY_SSL=1
export HTTP_DEBUG=1

# Performance Tuning
export HTTP_CONNECTION_POOL_SIZE=10
export HTTP_REQUEST_RETRIES=3
export HTTP_BACKOFF_FACTOR=0.5

# Security Configuration  
export WEB_SECURITY_STRICT_MODE=1
export WEB_OWASP_CHECKS_ENABLED=1
export WEB_VULNERABILITY_SCANNING=1
```

### Custom Compliance Frameworks

Add custom compliance checks by extending the compliance module:

```python
# Custom compliance framework example
CUSTOM_FRAMEWORKS = {
    'financial': {
        'name': 'Financial Services Compliance',
        'checks': [
            'strong_encryption',
            'multi_factor_auth',
            'audit_logging',
            'data_encryption'
        ],
        'weight': 1.0
    }
}
```

## Troubleshooting

### Common Issues

#### Script Execution Errors
```bash
# Check script permissions
ls -l /usr/lib/zabbix/externalscripts/get_web_health.py

# Test script manually
sudo -u zabbix /usr/lib/zabbix/externalscripts/get_web_health.py health google.com

# Check Python dependencies
python3 -c "import httpx, dns.resolver; print('Dependencies OK')"
```

#### SSL Certificate Issues
```bash
# Disable SSL verification for testing
get_web_health.py health https://self-signed.example.com --no-verify-ssl

# Check certificate details
get_web_health.py security https://example.com
```

#### Performance Issues  
```bash
# Increase timeout for slow services
get_web_health.py performance https://slow.example.com --timeout 30

# Enable debug logging
HTTP_DEBUG=1 get_web_health.py health https://example.com
```

### Debug Mode

Enable comprehensive debug logging:

```bash
# Environment variable
export HTTP_DEBUG=1

# Command line flag
get_web_health.py health https://example.com --debug

# Zabbix macro
{$WEB.DEBUG} = 1
```

Debug output includes:
- HTTP request/response headers
- TLS handshake details  
- DNS resolution information
- Timing breakdown
- Security check results
- Compliance validation steps

### Log Analysis

Monitor Zabbix server logs for web health issues:

```bash
# Check Zabbix server log
tail -f /var/log/zabbix/zabbix_server.log | grep "get_web_health"

# Check for timeout issues
grep "timeout" /var/log/zabbix/zabbix_server.log | grep web_health

# Check for permission issues
grep "permission denied" /var/log/zabbix/zabbix_server.log
```

## Integration Examples

### Grafana Dashboard

Create visualisations using Zabbix data source:

```json
{
  "dashboard": {
    "title": "Web Health Overview",
    "panels": [
      {
        "title": "Health Score Trend",
        "type": "stat",
        "targets": [
          {
            "expr": "zabbix_web_health_score",
            "legendFormat": "{{host}}"
          }
        ]
      }
    ]
  }
}
```

### Slack Integration

Configure Zabbix media type for Slack notifications:

```bash
# Webhook URL configuration
{
  "channel": "#web-monitoring",
  "text": "Web Health Alert: {TRIGGER.NAME}",
  "attachments": [
    {
      "color": "danger",
      "fields": [
        {
          "title": "Host",
          "value": "{HOST.NAME}",
          "short": true
        },
        {
          "title": "Health Score", 
          "value": "{ITEM.VALUE}%",
          "short": true
        }
      ]
    }
  ]
}
```

### API Integration

Use Zabbix API to retrieve web health data:

```python
import requests

# Get web health data via Zabbix API
api_data = {
    "jsonrpc": "2.0",
    "method": "item.get",
    "params": {
        "filter": {
            "key_": "get_web_health.py"
        },
        "output": "extend"
    },
    "id": 1,
    "auth": auth_token
}

response = requests.post(zabbix_api_url, json=api_data)
```

## Limitations

### Current Limitations
- **DKIM Validation**: Only checks for DKIM record presence, full signature validation requires email flow analysis
- **Rate Limiting**: Some security checks may trigger rate limiting on target services
- **IPv6 Support**: Limited IPv6 testing capabilities in current version
- **Browser Testing**: No actual browser rendering or JavaScript execution
- **Database Connectivity**: No backend database health checking
- **Mobile Optimisation**: Limited mobile-specific performance validation

### Future Enhancements
- **Real User Monitoring (RUM)**: Browser-based performance metrics
- **Synthetic Transactions**: Complex user workflow simulation  
- **AI-Powered Analysis**: Machine learning for anomaly detection
- **Global Performance**: Multi-region response time comparison
- **Accessibility Testing**: WCAG compliance validation
- **SEO Analysis**: Search engine optimisation assessment

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026/01/05 | Initial release with comprehensive web monitoring |
| 1.1 | TBD | Enhanced HTTP/3 support, improved security scanning |
| 1.2 | TBD | Real User Monitoring integration |
| 2.0 | TBD | AI-powered analysis and predictive monitoring |

## Support

### Documentation
- **Template Documentation**: This document
- **Script Documentation**: Inline comments in `get_web_health.py`
- **RFC References**: Links to relevant RFC documents in script headers

### Community Resources
- **GitHub Repository**: [ZabbixTemplates](https://github.com/sjackson0109/ZabbixTemplates)
- **Issue Tracking**: GitHub Issues for bug reports and feature requests
- **Discussion Forum**: GitHub Discussions for community support

### Professional Support
For enterprise support and custom development:
- **Author**: Simon Jackson (sjackson0109)
- **Email**: Available via GitHub profile
- **Consultation**: Custom compliance frameworks and integration support

## Licence

This template and associated scripts are provided under the MIT Licence. See LICENSE file for details.
python3 get_web_health.py health example.com

# HTTPS security analysis
python3 get_web_health.py https https://example.com

# SSL compatibility check
python3 get_web_health.py ssl-compat https://example.com

# OWASP Top 10 security assessment
python3 get_web_health.py owasp https://example.com

# HTTP version support testing
python3 get_web_health.py versions example.com

# CDN and proxy detection
python3 get_web_health.py proxy https://example.com

# Compliance framework assessment
python3 get_web_health.py frameworks https://example.com

# Self-test script functionality
python3 get_web_health.py selftest example.com
```

### Advanced Options
```bash
# Custom timeout
python3 get_web_health.py health example.com --timeout 15

# Specific HTTP version
python3 get_web_health.py health example.com --http-version 1.1

# Debug output
python3 get_web_health.py health example.com --debug

# Custom port
python3 get_web_health.py health example.com 8443
```

## Monitoring Items

### Core Health Metrics
- **Web Service Availability**: HTTP/HTTPS connectivity status
- **Response Time**: Total request/response time in milliseconds
- **HTTP Status Code**: Response status code (200, 404, 500, etc.)
- **Content Length**: Response body size in bytes
- **HTTP Version**: Detected protocol version (1.0, 1.1, 2.0)

### Security Metrics
- **SSL Certificate Validity**: Certificate expiration and trust status
- **SSL Grade**: Security rating (A+, A, B, C, D, F)
- **HSTS Status**: HTTP Strict Transport Security configuration
- **Security Headers**: CSP, X-Frame-Options, HSTS presence
- **OWASP Compliance Score**: Security vulnerability assessment (0-100)

### Performance Metrics
- **Compression Enabled**: Content compression detection
- **Cache Headers Present**: Caching configuration status
- **CDN Detection**: Content delivery network identification
- **Connection Time**: TCP connection establishment time
- **SSL Handshake Time**: TLS negotiation duration

### Infrastructure Metrics
- **Server Header**: Web server identification
- **CDN Provider**: Detected content delivery network
- **Proxy Detection**: Load balancer/proxy identification
- **Service Discovery**: Available TCP services
- **Compliance Framework Scores**: SOC2, HIPAA, PCI DSS indicators

## Triggers

### Critical Triggers
- **Web Service Down**: HTTP/HTTPS service unavailable
- **SSL Certificate Expired**: Certificate past expiration date
- **SSL Grade F**: Critical SSL/TLS security issues
- **OWASP Critical Issues**: High-severity security vulnerabilities

### Warning Triggers
- **High Response Time**: Request time exceeds threshold (>5 seconds)
- **SSL Certificate Expiring**: Certificate expires within 30 days
- **Missing Security Headers**: HSTS, CSP headers not present
- **Low OWASP Score**: Security compliance below threshold (<70)

### Information Triggers
- **HTTP Only Service**: HTTPS not available or configured
- **Legacy HTTP Version**: HTTP/1.0 usage detected
- **Missing Performance Headers**: Cache headers not optimised

## Troubleshooting

### Common Issues

#### 1. "Target URL or host cannot be empty"
**Solution**: Ensure `{$WEB_URL}` macro is properly configured

#### 2. "HTTP/2 request failed: h2 package not installed"
**Solution**: Install HTTP/2 support
```bash
pip3 install httpx[http2]
```

#### 3. "Script failed: get_tls_handshake.py not found"
**Solution**: Verify dependency scripts are installed and executable
```bash
ls -la /usr/lib/zabbix/externalscripts/get_tls_handshake.py
chmod +x /usr/lib/zabbix/externalscripts/get_tls_handshake.py
```

#### 4. "Connection timeout"
**Solution**: Increase timeout value or check network connectivity
```bash
# Test connectivity
curl -I --max-time 10 https://example.com
```

#### 5. Empty monitoring values
**Solution**: Check script execution and JSON output
```bash
# Test script manually
sudo -u zabbix python3 /usr/lib/zabbix/externalscripts/get_web_health.py health example.com
```

### Debug Mode
Enable debug output for troubleshooting:
```bash
python3 get_web_health.py health example.com --debug
```

### Log Analysis
Check Zabbix server logs for external script errors:
```bash
tail -f /var/log/zabbix/zabbix_server.log | grep "get_web_health"
```

## Performance Considerations

### Optimisation Settings
- **Default Timeout**: 10 seconds (adjustable via macro)
- **Connection Pooling**: HTTP connections reused when possible
- **Concurrent Requests**: Multiple checks executed in parallel
- **Cache Integration**: Supports HTTP caching headers

### Resource Usage
- **Memory**: ~50MB per script execution
- **CPU**: Low impact, primarily I/O bound
- **Network**: Minimal bandwidth usage (~1-5KB per check)
- **Disk**: Log files and temporary SSL certificate storage

### Scaling Recommendations
- **Large Environments**: Consider proxy deployment
- **High Frequency**: Monitor resource usage on Zabbix server
- **Geographic Distribution**: Deploy regional Zabbix proxies

## Security Considerations

### Network Access
- **Outbound HTTPS**: Zabbix server requires internet access for external sites
- **Internal Networks**: Ensure firewall rules allow access to target hosts
- **DNS Resolution**: Verify DNS resolution from Zabbix server

### Credentials
- **No Authentication**: Script does not handle authenticated endpoints
- **Client Certificates**: Not supported in current version
- **API Keys**: Consider separate monitoring for authenticated services

### Data Privacy
- **No Content Storage**: Only metadata and headers collected
- **SSL Certificates**: Temporary analysis only, no permanent storage
- **Compliance**: Suitable for PCI DSS, HIPAA environments

## Version History

- **v2.0**: Enhanced SSL analysis, OWASP Top 10, compliance frameworks
- **v1.8**: HTTP/3 detection, CDN identification, proxy analysis
- **v1.5**: HTTP/2 support, performance optimisation
- **v1.0**: Initial release with basic HTTP/HTTPS monitoring

## Support

### Documentation
- **RFC Compliance**: Follows HTTP/1.1 (RFC 7230-7237), HTTP/2 (RFC 7540)
- **SSL Standards**: TLS 1.2/1.3 (RFC 5246, RFC 8446)
- **Security Standards**: OWASP guidelines, NIST recommendations

### Contributing
- **Issues**: Report bugs and feature requests
- **Testing**: Comprehensive test suite available
- **Development**: Modular architecture for easy extension

## Licence

This monitoring solution is provided under the terms of the original Zabbix project licence and contributor agreements.