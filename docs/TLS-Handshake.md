# TLS Handshake Check Script

### Author: Simon Jackson / sjackson0109  
### Created: 2025/03/03
### Updated: 2026/01/12
### Version: 3.3

## Overview  
**get_tls_handshake.py** is a comprehensive TLS monitoring solution designed for enterprise environments and Zabbix integration. It provides dynamic protocol detection (TLS 1.0 through TLS 1.3), IANA-compliant cipher naming, and comprehensive compliance scoring for security frameworks including PCI DSS, NIST, and BSI TR-02102.

The script supports complete SSL/TLS protocol coverage with modern TLS 1.3 AEAD cipher suites, legacy protocol detection, and enterprise-grade monitoring capabilities. It provides timestamp-free JSON output optimized for Zabbix discard_unchanged processing and includes comprehensive health scoring with risk tier classification.

### Key Capabilities
- **Complete TLS Protocol Support**: TLS 1.0, 1.1, 1.2, and 1.3 with dynamic detection
- **IANA Cipher Compliance**: All cipher names follow IANA standards for consistency
- **Enterprise Integration**: Zabbix-optimized JSON output with comprehensive monitoring metrics
- **Security Compliance**: PCI DSS, NIST, BSI TR-02102 framework compliance scoring
- **Risk Assessment**: SEV1-SEV5 tier classification with health score calculation
- **Production Ready**: Cross-platform support with configurable timeouts and environment variables

## Features  
- ✅ **TLS 1.3 Support**: Complete TLS 1.3 implementation with AEAD cipher suites (TLS_AES_*, TLS_CHACHA20_*)
- ✅ **Dynamic Protocol Detection**: Detects available SSL/TLS protocols (TLS 1.0 through TLS 1.3) using modern TLSVersion enum
- ✅ **IANA Cipher Compliance**: All cipher names follow IANA standards for enterprise consistency  
- ✅ **Comprehensive Discovery**: JSON output with cipher_suites structure and 1/0 support status
- ✅ **Security Framework Compliance**: PCI DSS, NIST, BSI TR-02102 compliance scoring
- ✅ **Risk Tier Classification**: SEV1-SEV5 severity levels with health score calculation
- ✅ **Enterprise Integration**: Timestamp-free output optimized for Zabbix discard_unchanged processing
- ✅ **Modular CLI Architecture**: Function-driven commands for discovery, testing, and validation
- ✅ **Environment Configuration**: Configurable via TLS_TIMEOUT and TLS_DEBUG environment variables
- ✅ **Cross-Platform**: Works on Linux, Windows, and Docker containers with Python 3.7+
- ✅ **Production Ready**: Comprehensive error handling, timeout management, and monitoring integration  

## Installation  
This script runs **natively in Python 3.7+** with no additional dependencies.  

### Prerequisites  
Ensure you have Python 3.7 or higher installed:  
```sh  
python3 --version  
```
**Note**: Tested with Python 3.13.5 and OpenSSL 3.0.16 providing full TLS 1.3 support.

### Download the script
Ensure you download the `get_tls_handshake.py` script:
```bash
git clone https://github.com/sjackson0109/ZabbixTemplates.git  
cd ZabbixTemplates/externalscripts
```

### Environment Variables
The script supports configuration via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `TLS_TIMEOUT` | `4` | Connection timeout in seconds for TLS handshake attempts |
| `TLS_DEBUG` | `0` | Enable debug logging (set to `1` for verbose output) |

#### Setting Environment Variables

**Linux/macOS:**
```bash
export TLS_TIMEOUT=10
export TLS_DEBUG=1
python3 get_tls_handshake.py discover google.com 443
```

**Windows PowerShell:**
```powershell
$env:TLS_TIMEOUT = "10"
$env:TLS_DEBUG = "1"
python get_tls_handshake.py discover google.com 443
```

**Windows Command Prompt:**
```cmd
set TLS_TIMEOUT=10
set TLS_DEBUG=1
python get_tls_handshake.py discover google.com 443
```

## Usage

The script provides multiple operational modes for different monitoring needs:

### Command Structure
```bash
python3 get_tls_handshake.py <COMMAND> <HOST> [ADDITIONAL_ARGS]
```

### Available Commands

| Command | Purpose | Output Format |
|---------|---------|---------------|
| `discover` | Complete cipher suite discovery with support status | JSON with cipher_suites structure |
| `protocols` | List available TLS protocols (client capabilities) | JSON array of supported protocols |
| `ciphers` | List available cipher suites (client capabilities) | JSON array of available ciphers |
| `check` | Test specific protocol-cipher combination | JSON with connection status |
| `test` | Validate TLS handshake capability | JSON with detailed test results |
| `compatibility` | Check protocol-cipher compatibility | JSON compatibility matrix |
| `health` | Generate comprehensive health assessment | JSON with compliance scores |

### Core Usage Examples

#### 1️⃣ Discovery Mode (Primary Zabbix Integration)
```bash
# Complete cipher suite discovery
python3 get_tls_handshake.py discover google.com 443

# Discovery with custom port
python3 get_tls_handshake.py discover example.com 8443
```

#### 2️⃣ Protocol Detection (Client Capabilities)
```bash
# List available TLS protocols on client system
python3 get_tls_handshake.py protocols

# Example output: {"protocols": ["TLS_1.0", "TLS_1.1", "TLS_1.2", "TLS_1.3"], "count": 4}
```

#### 3️⃣ Cipher Suite Listing (Client Capabilities)
```bash
# List available ciphers on client system
python3 get_tls_handshake.py ciphers
```

#### 4️⃣ Specific Protocol-Cipher Testing
```bash
# Test TLS 1.3 with AEAD cipher
python3 get_tls_handshake.py check google.com TLS_1.3 TLS_AES_256_GCM_SHA384 443

# Test TLS 1.2 with ECDHE cipher
python3 get_tls_handshake.py check google.com TLS_1.2 ECDHE-RSA-AES256-GCM-SHA384 443
```

#### 5️⃣ Health Assessment (Enterprise Monitoring)
```bash
# Comprehensive compliance scoring
python3 get_tls_handshake.py health google.com 443
```

## Command-Line Arguments

### Global Parameters
| Parameter | Default | Description |
|-----------|---------|-------------|
| `<HOST>` | **Required** | Hostname, FQDN, or IP address (IPv4/IPv6) to test |
| `[PORT]` | `443` | TCP port number for TLS connection |

### Environment Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `TLS_TIMEOUT` | `4` | Connection timeout in seconds |
| `TLS_DEBUG` | `0` | Debug logging (set to `1` to enable) |

### Command-Specific Arguments

#### Discovery Command
```bash
python3 get_tls_handshake.py discover <HOST> [PORT]
```
- Returns comprehensive cipher_suites JSON structure
- Optimized for Zabbix LLD (Low Level Discovery)
- Timestamp-free for efficient discard_unchanged processing

#### Check Command  
```bash
python3 get_tls_handshake.py check <HOST> <PROTOCOL> <CIPHER> [PORT]
```
- `<PROTOCOL>`: TLS_1.0, TLS_1.1, TLS_1.2, or TLS_1.3
- `<CIPHER>`: IANA-compliant cipher name (e.g., TLS_AES_256_GCM_SHA384)

#### Health Command
```bash
python3 get_tls_handshake.py health <HOST> [PORT]
```
- Generates compliance scores for PCI DSS, NIST, BSI TR-02102
- Provides SEV1-SEV5 risk tier classification
- Returns overall health score (0-100)

## Output

### JSON Output Format
All commands return structured JSON for seamless Zabbix integration:

#### Discovery Output Example
```json
{
  "cipher_suites": {
    "TLS_1.3": {
      "TLS_AES_256_GCM_SHA384": 1,
      "TLS_CHACHA20_POLY1305_SHA256": 1,
      "TLS_AES_128_GCM_SHA256": 0
    },
    "TLS_1.2": {
      "ECDHE-RSA-AES256-GCM-SHA384": 1,
      "ECDHE-RSA-AES128-GCM-SHA256": 1,
      "DHE-RSA-AES256-SHA": 0
    }
  },
  "protocols_detected": ["TLS_1.0", "TLS_1.1", "TLS_1.2", "TLS_1.3"],
  "total_combinations": 68,
  "supported_combinations": 42,
  "host": "google.com",
  "port": 443
}
```

#### Health Assessment Output
```json
{
  "health_score": 85,
  "risk_tier": "SEV2",
  "compliance_scores": {
    "pci_dss": 90,
    "nist": 85,
    "bsi_tr_02102": 80
  },
  "protocol_summary": {
    "tls_1_3_support": true,
    "deprecated_protocols": ["TLS_1.0", "TLS_1.1"],
    "secure_protocols": ["TLS_1.2", "TLS_1.3"]
  },
  "cipher_analysis": {
    "weak_ciphers": 5,
    "strong_ciphers": 15,
    "aead_ciphers": 8
  }
}
```

### Debug Output
When `TLS_DEBUG=1` is set:
```bash
2026-01-12 23:43:05,298 DEBUG: Protocol TLS_1.0 (TLSv1.0) is available
2026-01-12 23:43:05,299 DEBUG: Protocol TLS_1.3 (TLSv1.3) is available via TLSVersion enum
2026-01-12 23:43:05,300 DEBUG: Testing TLS_1.3 with TLS_AES_256_GCM_SHA384
2026-01-12 23:43:05,350 DEBUG: TLS_1.3 handshake successful with google.com:443
```

## Zabbix Integration

### Template Integration
This script is designed for seamless integration with the `tls_compliance_checker.yaml` Zabbix template:

```xml
<!-- Master Item -->
<item>
    <name>TLS Discovery</name>
    <key>tls.discovery[{$TLS.HOST},{$TLS.PORT}]</key>
    <type>EXTERNAL</type>
    <params>get_tls_handshake.py discover {$TLS.HOST} {$TLS.PORT}</params>
    <delay>{$TLS.DISCOVERY.INTERVAL}</delay>
</item>
```

### Environment Variables in Zabbix
Configure script behavior via Zabbix macros:

| Zabbix Macro | Environment Variable | Default | Purpose |
|--------------|---------------------|---------|---------|
| `{$TLS.TIMEOUT}` | `TLS_TIMEOUT` | `4` | Connection timeout |
| `{$TLS.DEBUG}` | `TLS_DEBUG` | `0` | Debug logging |

### Low Level Discovery (LLD)
The discovery command provides LLD-compatible JSON for automatic item creation:

```json
{
  "data": [
    {"{#PROTOCOL}": "TLS_1.3", "{#CIPHER}": "TLS_AES_256_GCM_SHA384"},
    {"{#PROTOCOL}": "TLS_1.2", "{#CIPHER}": "ECDHE-RSA-AES256-GCM-SHA384"}
  ]
}
```

### Dependent Items
Template includes comprehensive dependent items for health metrics:

- **Compliance Scores**: `tls.compliance.pci_dss`, `tls.compliance.nist`, `tls.compliance.bsi`
- **Protocol Support**: `tls.protocols.tls13`, `tls.protocols.deprecated`  
- **Health Assessment**: `tls.health.score`, `tls.health.risk_tier`
- **Cipher Analysis**: `tls.ciphers.weak`, `tls.ciphers.strong`, `tls.ciphers.aead`

## Security Compliance

### Supported Frameworks
- **PCI DSS**: Payment card industry compliance scoring
- **NIST**: National Institute of Standards and Technology guidelines
- **BSI TR-02102**: German Federal Office for Information Security standards

### Risk Tier Classification
| Tier | Score Range | Criteria |
|------|-------------|----------|
| SEV1 | 90-100 | TLS 1.3 support, strong ciphers only |
| SEV2 | 80-89 | TLS 1.2+, minimal weak ciphers |
| SEV3 | 70-79 | TLS 1.2+, some legacy support |
| SEV4 | 60-69 | Mixed protocol support |
| SEV5 | 0-59 | Significant security issues |

## Debugging and Troubleshooting

### Enable Debug Logging
```bash
export TLS_DEBUG=1
python3 get_tls_handshake.py discover google.com 443
```

### Common Issues

#### TLS 1.3 Not Detected
- Ensure Python 3.7+ and OpenSSL 1.1.1+
- Verify TLSVersion enum availability: `python -c "import ssl; print(hasattr(ssl, 'TLSVersion'))"`

#### Connection Timeouts
- Increase timeout: `export TLS_TIMEOUT=10`
- Check network connectivity
- Verify target port accessibility

#### IANA Cipher Name Mismatches
- Script automatically converts OpenSSL names to IANA format
- Check `IANA_CIPHER_MAP` for supported conversions
- Use debug mode to see conversion process

## Return Codes  

The script provides comprehensive status information through JSON output rather than traditional exit codes, optimized for Zabbix monitoring:

### JSON Status Fields
| Field | Type | Description |  
|-------|------|-------------|  
| `error` | String | Present only when critical errors occur |  
| `health_score` | Integer (0-100) | Overall TLS configuration health |  
| `risk_tier` | String (SEV1-SEV5) | Security risk classification |  
| `supported_combinations` | Integer | Number of working protocol-cipher pairs |  

### Error Handling
```json
{
  "error": "Connection timeout",
  "host": "unreachable.example.com",
  "port": 443,
  "details": "Socket timeout after 4 seconds"
}
```

### Success Indicators
- `supported_combinations > 0`: At least one TLS connection successful
- `health_score >= 70`: Acceptable security configuration
- `risk_tier` in `["SEV1", "SEV2", "SEV3"]`: Low to moderate risk
- Presence of `tls_1_3_support: true`: Modern TLS support confirmed

## Version History

### Version 3.3 (2026-01-12)
- ✅ **TLS 1.3 Support**: Complete implementation with AEAD cipher detection
- ✅ **IANA Compliance**: Full OpenSSL-to-IANA cipher name conversion
- ✅ **Enterprise Integration**: 100% Zabbix template alignment
- ✅ **Security Frameworks**: PCI DSS, NIST, BSI TR-02102 compliance scoring
- ✅ **Environment Variables**: TLS_TIMEOUT and TLS_DEBUG configuration support
- ✅ **Risk Assessment**: SEV1-SEV5 tier classification with health scoring

### Version 3.2
- Dynamic protocol detection improvements
- Enhanced cipher compatibility filtering
- Timestamp removal for efficient Zabbix processing

### Version 3.1  
- JSON output standardization
- Cross-platform compatibility enhancements
- Comprehensive error handling

### Version 3.0
- Complete architectural redesign
- Modular command structure implementation
- Zabbix integration optimization 