# SIP/VoIP Compliance Monitoring System

## Overview

The SIP/VoIP Compliance Monitoring System provides comprehensive monitoring and validation of SIP and VoIP infrastructure components. This system integrates multiple testing methodologies including advanced STUN/TURN testing to assess protocol compliance, security posture, media capabilities, and overall service quality.

**V3.0 Enhancements:**
- Native STUN/TURN testing integration (RFC 5389/5766)
- Enhanced compliance scoring with detailed assessment
- Advanced NAT traversal testing capabilities
- Improved monitoring dashboards and visualization

## Features

### Core Monitoring Capabilities
- **SIP Protocol Compliance** - RFC 3261 and extensions validation
- **RTP/RTCP Media Testing** - Audio/video stream capability assessment  
- **STUN/TURN NAT Traversal** - Network connectivity and firewall traversal testing
- **TLS Security Assessment** - Encryption and certificate validation
- **Codec Support Validation** - Audio/video codec compatibility testing
- **Service Discovery** - Automatic detection of VoIP services and transports
- **Quality of Service Metrics** - Performance and reliability measurements
- **Comprehensive Compliance Scoring** - Overall infrastructure assessment

### RFC Compliance Coverage
| RFC | Standard | Description |
|-----|----------|-------------|
| RFC 3261 | SIP: Session Initiation Protocol | Core SIP protocol specification |
| RFC 3262 | Reliability of Provisional Responses | 100rel extension |
| RFC 3263 | SIP: Locating SIP Servers | DNS-based service location |
| RFC 3264 | Offer/Answer Model with SDP | Session negotiation |
| RFC 3265 | SIP-Specific Event Notification | SUBSCRIBE/NOTIFY framework |
| RFC 3311 | SIP UPDATE Method | Mid-call parameter updates |
| RFC 3515 | SIP Refer Method | Call transfer mechanism |
| RFC 3550 | RTP: Real-Time Transport Protocol | Media stream transport |
| RFC 3551 | RTP Audio/Video Profile | Standard media profiles |
| RFC 4566 | SDP: Session Description Protocol | Session description format |
| RFC 5389 | STUN: Session Traversal Utilities for NAT | NAT detection and traversal |
| RFC 5766 | TURN: Traversal Using Relays | Relay-based NAT traversal |
| RFC 6544 | TCP Candidates with ICE | TCP connectivity establishment |

## Installation & Setup

### Prerequisites
- Zabbix 7.0+
- Python 3.6+ with standard libraries
- Network access to SIP/VoIP infrastructure
- Appropriate firewall rules for SIP, RTP, and STUN traffic

### External Script Installation
```bash
# Copy the external script to Zabbix external scripts directory
cp get_sip_voip_compliance.py /usr/lib/zabbix/externalscripts/
chmod +x /usr/lib/zabbix/externalscripts/get_sip_voip_compliance.py

# Test script functionality
python3 /usr/lib/zabbix/externalscripts/get_sip_voip_compliance.py sip_test your.sip.server.com
```

### Template Import
1. Download `sip_voip_compliance.yaml` from the templates directory
2. Import template in Zabbix Administration → General → Import
3. Assign template to VoIP infrastructure hosts
4. Configure macros for your environment

### Environment Configuration
```bash
# Optional environment variables
export SIP_TIMEOUT=30          # SIP request timeout in seconds
export DNS_NAMESERVER=8.8.8.8  # Custom DNS server
export SIP_DEBUG=1             # Enable debug logging
```

## Usage Examples

### Command Line Testing
```bash
# Basic SIP OPTIONS test
python3 get_sip_voip_compliance.py sip_test pbx.example.com

# Test specific port and transport
python3 get_sip_voip_compliance.py sip_test pbx.example.com 5061

# STUN connectivity test
python3 get_sip_voip_compliance.py stun_test pbx.example.com 3478

# RTP capability assessment
python3 get_sip_voip_compliance.py rtp_test pbx.example.com 10000

# Codec support analysis
python3 get_sip_voip_compliance.py codec_test pbx.example.com

# NAT traversal evaluation
python3 get_sip_voip_compliance.py nat_test pbx.example.com

# TLS security assessment
python3 get_sip_voip_compliance.py tls_test pbx.example.com 5061

# Comprehensive compliance assessment
python3 get_sip_voip_compliance.py comprehensive pbx.example.com

# Service discovery
python3 get_sip_voip_compliance.py discover pbx.example.com

# V3.0 Enhanced Commands
# V3.0 comprehensive testing with STUN/TURN
python3 get_sip_voip_compliance.py v3 pbx.example.com 5060

# V3.0 STUN connectivity testing
python3 get_sip_voip_compliance.py stun_v3 pbx.example.com

# V3.0 TURN allocation testing
python3 get_sip_voip_compliance.py turn_v3 pbx.example.com

# RFC compliance assessment
python3 get_sip_voip_compliance.py rfc_compliance pbx.example.com
```

### Zabbix Integration
```bash
# Standard Items
get_sip_voip_compliance.py[sip_test,{HOST.CONN},{$SIP.PORT}]
get_sip_voip_compliance.py[comprehensive,{HOST.CONN}]
get_sip_voip_compliance.py[discover,{HOST.CONN}]

# V3.0 Enhanced Items
get_sip_voip_compliance.py[v3,{HOST.CONN},{$SIP.PORT}]
get_sip_voip_compliance.py[stun_v3,{HOST.CONN}]
get_sip_voip_compliance.py[turn_v3,{HOST.CONN}]
get_sip_voip_compliance.py[rfc_compliance,{HOST.CONN}]
```

## Configuration

### Host Macros
| Macro | Default | Description |
|-------|---------|-------------|
| {$SIP.PORT} | 5060 | Standard SIP port (UDP/TCP) |
| {$SIPS.PORT} | 5061 | Secure SIP port (TLS) |
| {$STUN.PORT} | 3478 | STUN service port |
| {$RTP.PORT} | 10000 | RTP testing port |
| {$SIP.RESPONSE.TIME.WARN} | 2000 | SIP response time warning (ms) |
| {$VOIP.RESPONSE.TIME.WARN} | 3000 | VoIP response time warning (ms) |
| {$SECURITY.SCORE.MIN} | 70 | Minimum security score |
| {$COMPLIANCE.SCORE.MIN} | 60 | Minimum compliance score (%) |
| {$COMPLIANCE.CRITICAL} | 30 | Critical compliance threshold (%) |
| {$V3.COMPLIANCE.MIN} | 75 | V3.0 minimum advanced compliance score (%) |

### Template Components

#### Monitoring Items
- **SIP Protocol Items**
  - OPTIONS response time
  - Service status
  - Response codes
  - Supported methods
  - RFC 3261 compliance

- **Security Items**
  - TLS security score
  - TLS version
  - Certificate validation
  - Cipher suite information

- **Media Items**
  - RTP service status
  - Codec support count
  - Audio/video capabilities

- **NAT Traversal Items**
  - STUN connectivity
  - NAT detection
  - Traversal support

- **Compliance Items**
  - Overall compliance score
  - RFC compliance validation
  - Protocol compliance assessment

- **V3.0 Enhanced Items**
  - V3.0 comprehensive test status
  - V3.0 STUN connectivity status
  - V3.0 TURN allocation status  
  - V3.0 advanced compliance score
  - Component scores
  - Assessment metrics

#### Discovery Rules
- **VoIP Service Discovery**
  - Automatic service detection
  - Transport protocol identification
  - Port mapping
  - Service status monitoring

#### Triggers
- **Availability Triggers**
  - SIP service down
  - STUN connectivity failure
  - Service error responses

- **Performance Triggers**
  - High response times
  - Timeout conditions
  - Performance degradation

- **Compliance Triggers**
  - RFC non-compliance
  - Low security scores
  - Critical compliance failures

- **V3.0 Enhanced Triggers**
  - V3.0 comprehensive test failed
  - V3.0 STUN connectivity failed
  - V3.0 TURN allocation failed
  - V3.0 advanced compliance low score

#### Dashboards
1. **VoIP Service Overview**
   - Compliance scores
   - Service status
   - Response times

2. **Security Assessment**
   - TLS security metrics
   - Compliance gauges
   - Vulnerability indicators

3. **Service Discovery**
   - Discovered services
   - Transport protocols
   - Port mappings

4. **Performance Monitoring**
   - Response time trends
   - Performance summaries
   - Historical data

5. **V3.0 Advanced Monitoring**
   - V3.0 comprehensive test status
   - STUN/TURN connectivity metrics
   - Advanced compliance gauge with thresholds
   - Enhanced trending and visualization

## Monitoring Metrics

### SIP Protocol Metrics
```json
{
  "server": "pbx.example.com",
  "port": 5060,
  "transport": "udp",
  "success": true,
  "response_code": 200,
  "response_time": 45.32,
  "supported_methods": ["INVITE", "ACK", "BYE", "CANCEL", "OPTIONS"],
  "user_agent": "FreeSWITCH-1.10.7",
  "rfc_compliance": {
    "rfc3261": {"compliant": true, "issues": []}
  }
}
```

### Security Assessment Metrics
```json
{
  "server": "pbx.example.com",
  "port": 5061,
  "success": true,
  "tls_version": "TLSv1.3",
  "cipher_suite": "TLS_AES_256_GCM_SHA384",
  "certificate_valid": true,
  "security_score": 85,
  "vulnerabilities": []
}
```

### Compliance Scoring
```json
{
  "server": "pbx.example.com",
  "overall_compliance_score": 87.5,
  "component_scores": {
    "sip_protocol": 100,
    "security": 85,
    "codec_support": 90,
    "nat_traversal": 75,
    "rtp_media": 100
  },
  "recommendations": ["Enhance TLS security configuration"],
  "critical_issues": []
}
```

### V3.0 Enhanced Monitoring Metrics
```json
{
  "server": "pbx.example.com", 
  "v3_comprehensive": {
    "success": true,
    "stun_connectivity": true,
    "turn_allocation": true,
    "advanced_compliance": 92.3,
    "enhanced_features": {
      "nat_traversal_v3": true,
      "media_relay_support": true,
      "ice_connectivity": true
    }
  },
  "compliance_summary": {
    "grade": "A",
    "percentage": 92.3,
    "levels_passed": ["Basic SIP", "Security", "Media", "Advanced NAT"]
  }
}
```

### RFC Compliance Assessment
```json
{
  "server": "pbx.example.com",
  "compliance_results": {
    "rfc_3261_sip": {"compliant": true, "score": 100},
    "rfc_5389_stun": {"compliant": true, "score": 95}, 
    "rfc_5766_turn": {"compliant": true, "score": 90}
  },
  "overall_compliance": {
    "grade": "A",
    "overall_percentage": 95,
    "level_compliance": {
      "basic": {"compliant": true, "name": "Basic SIP"},
      "advanced": {"compliant": true, "name": "Advanced Features"}
    }
  }
}
```

## Integration Examples

### Integration with Existing Scripts
The SIP/VoIP compliance tool integrates with existing monitoring scripts:

```bash
# Combine with TCP port scanning
python3 get_tcp_port_scan.py pbx.example.com 5060,5061,3478

# Integrate with TLS compliance checking  
python3 get_tls_handshake.py pbx.example.com 5061

# STUN/TURN service validation
python3 get_sip_voip_compliance.py stun_test pbx.example.com
```

### Custom Monitoring Workflows
```bash
#!/bin/bash
# VoIP infrastructure health check
SERVER=$1

echo "=== VoIP Infrastructure Assessment ==="
echo "Server: $SERVER"
echo

echo "1. Service Discovery..."
python3 get_sip_voip_compliance.py discover $SERVER

echo "2. SIP Protocol Test..."
python3 get_sip_voip_compliance.py sip_test $SERVER

echo "3. Security Assessment..."
python3 get_sip_voip_compliance.py tls_test $SERVER 5061

echo "4. NAT Traversal Test..."
python3 get_sip_voip_compliance.py nat_test $SERVER

echo "5. Comprehensive Compliance..."
python3 get_sip_voip_compliance.py comprehensive $SERVER
```

## Troubleshooting

### Common Issues

#### SIP Service Not Responding
```json
{
  "success": false,
  "error": "Connection timeout",
  "response_code": null
}
```
**Solutions:**
- Verify SIP service is running
- Check firewall rules for port 5060/5061
- Validate network connectivity
- Confirm correct server hostname/IP

#### TLS Connection Failures
```json
{
  "success": false,
  "error": "SSL handshake failed",
  "tls_version": null
}
```
**Solutions:**
- Check TLS certificate validity
- Verify supported TLS versions
- Review cipher suite compatibility
- Check certificate trust chain

#### STUN Connectivity Issues
```json
{
  "success": false,
  "error": "STUN request timeout",
  "mapped_address": null
}
```
**Solutions:**
- Verify STUN service availability
- Check UDP port 3478 accessibility
- Review NAT/firewall configuration
- Test alternative STUN servers

### Debug Mode
Enable debug logging for detailed troubleshooting:
```bash
export SIP_DEBUG=1
python3 get_sip_voip_compliance.py sip_test pbx.example.com
```

### Performance Optimisation
- Adjust timeout values for slow networks
- Use appropriate check intervals
- Monitor resource usage
- Optimise concurrent connections

## Security Considerations

### Network Security
- Implement appropriate firewall rules
- Monitor for SIP scanning attacks
- Use TLS for sensitive communications
- Validate certificate chains

### Access Control
- Restrict script execution permissions
- Monitor external script usage
- Implement rate limiting
- Use secure credential management

### Data Protection
- Sanitize sensitive information
- Implement audit logging
- Use encrypted communications
- Follow data retention policies

## Performance Benchmarks

### Response Time Thresholds
- **SIP OPTIONS**: < 500ms (excellent), < 1000ms (good), < 2000ms (acceptable)
- **STUN Binding**: < 200ms (excellent), < 500ms (good), < 1000ms (acceptable)
- **TLS Handshake**: < 1000ms (excellent), < 2000ms (good), < 3000ms (acceptable)

### Compliance Scoring
- **90-100%**: Excellent compliance
- **70-89%**: Good compliance
- **50-69%**: Acceptable compliance
- **30-49%**: Poor compliance
- **0-29%**: Critical issues

## Best Practices

### Monitoring Strategy
1. Implement comprehensive service discovery
2. Monitor all critical VoIP components
3. Set appropriate alerting thresholds
4. Regular compliance assessments
5. Trend analysis and capacity planning

### Maintenance Procedures
1. Regular script updates
2. Certificate renewal monitoring
3. Performance baseline reviews
4. Security assessment updates
5. Documentation maintenance

### Integration Guidelines
1. Coordinate with existing monitoring
2. Avoid monitoring conflicts
3. Implement proper error handling
4. Use consistent naming conventions
5. Document all customisations

## V3.0 Enhanced Features

### Advanced STUN/TURN Testing
Version 3.0 includes native STUN/TURN testing capabilities:

- **STUN Connectivity (`stun_v3`)** - Enhanced RFC 5389 compliant testing
- **TURN Allocation (`turn_v3`)** - RFC 5766 relay testing
- **Comprehensive Testing (`v3`)** - Full VoIP stack validation

### Enhanced Monitoring Dashboards
- **V3.0 Advanced Dashboard** - Dedicated monitoring interface
- **Real-time Compliance Gauge** - Visual score monitoring with thresholds
- **Multi-metric Trending** - Enhanced performance visualization

### Improved Compliance Scoring
- **Advanced Scoring Algorithm** - More comprehensive assessment
- **STUN/TURN Integration** - NAT traversal compliance scoring
- **Enhanced RFC Validation** - Broader standards coverage

### Migration to V3.0
1. Update template to latest version
2. Configure new V3.0 macros (`{$V3.COMPLIANCE.MIN}`)
3. Enable V3.0 monitoring items
4. Review dashboard configurations
5. Update alerting thresholds

---

**Author:** Simon Jackson (sjackson0109)  
**Version:** 3.0 Enhanced  
**Updated:** 2026/01/14  
**Template:** sip_voip_compliance.yaml  
**Script:** get_sip_voip_compliance.py