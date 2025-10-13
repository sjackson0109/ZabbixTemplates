# STUN/TURN Checks Template

This template provides comprehensive monitoring for STUN and TURN servers with full authentication support.

## Python Script - `get_stun_turn_check.py`
Enhanced STUN/TURN monitoring script with RFC 5766 TURN authentication support.

**Features:**
- STUN Binding Request/Response (RFC 5389)
- TURN Allocate Request/Response with authentication (RFC 5766)
- Support for UDP, TCP, and TLS transports
- Username/Password authentication with MESSAGE-INTEGRITY
- FINGERPRINT attribute for message integrity
- Comprehensive error handling and reporting

**Parameters:**
1. Transport protocol (UDP/TCP/TLS)
2. Mode (STUN/TURN)
3. Metric to retrieve
4. Target host
5. Target port
6. Username (for TURN authentication)
7. Password (for TURN authentication)  
8. Timeout value

### 3. Zabbix Template - `stun_turn_monitoring.yaml`
Comprehensive Zabbix template with auto-discovery and monitoring items.

**Features:**
- Low-Level Discovery (LLD) for STUN/TURN services
- 7 monitoring items per discovered service:
  - Service status (0/1)
  - Response time (RTT in ms)
  - Public IP address (mapped/relayed)
  - Error code (for troubleshooting)
  - Authentication status
  - TURN allocation lifetime (TURN mode only)
  - Response data size
- Triggers for service availability, performance, and authentication
- Value maps for status interpretation
- Configurable macros for authentication and thresholds

## Installation

### 1. Deploy Python Script
```bash
# Copy the Python script to Zabbix external scripts directory
cp get_stun_turn_check.py /usr/lib/zabbix/externalscripts/
chmod +x /usr/lib/zabbix/externalscripts/get_stun_turn_check.py

# Ensure Python 3 is available
python3 --version
```

### 2. Deploy Shell Wrapper
```bash
# Copy the shell wrapper to Zabbix external scripts directory
cp stun_turn_wrapper.sh /usr/lib/zabbix/externalscripts/
chmod +x /usr/lib/zabbix/externalscripts/stun_turn_wrapper.sh
```

### 3. Import Zabbix Template
1. In Zabbix frontend, go to Configuration → Templates
2. Click "Import"
3. Select `stun_turn_monitoring.yaml`
4. Click "Import"

### 4. Configure Host
1. Create or edit a host
2. Link the "STUN/TURN Server Monitoring" template
3. Configure macros:
   - `{$STUN_TURN_USERNAME}`: TURN authentication username
   - `{$STUN_TURN_PASSWORD}`: TURN authentication password
   - `{$STUN_TURN_TIMEOUT}`: Connection timeout (default: 10)
   - `{$STUN_TURN_MAX_RTT}`: Maximum acceptable response time (default: 3)
   - `{$STUN_TURN_DISCOVERY_SERVICES}`: JSON array of services to discover

## Configuration

### Service Discovery Configuration
The template uses a JSON array to define which STUN/TURN services to monitor:

```json
[
  {"SERVICE": "stun-udp-3478", "TRANSPORT": "UDP", "MODE": "STUN", "PORT": "3478"},
  {"SERVICE": "turn-udp-3478", "TRANSPORT": "UDP", "MODE": "TURN", "PORT": "3478"},
  {"SERVICE": "turn-tcp-3478", "TRANSPORT": "TCP", "MODE": "TURN", "PORT": "3478"},
  {"SERVICE": "turn-tls-5349", "TRANSPORT": "TLS", "MODE": "TURN", "PORT": "5349"}
]
```

### Macro Configuration
Configure these macros on your host or template level:

| Macro | Description | Default | Example |
|-------|-------------|---------|---------|
| `{$STUN_TURN_USERNAME}` | TURN authentication username | (empty) | `testuser` |
| `{$STUN_TURN_PASSWORD}` | TURN authentication password | (empty) | `testpass` |
| `{$STUN_TURN_TIMEOUT}` | Connection timeout in seconds | `10` | `15` |
| `{$STUN_TURN_MAX_RTT}` | Maximum acceptable RTT in seconds | `3` | `5` |

## Monitoring Items

For each discovered service, the template creates these items:

1. **Service Status**: Binary status (1=up, 0=down)
2. **Response Time**: Round-trip time in milliseconds
3. **Mapped IP**: Public IP address discovered via STUN/TURN
4. **Error Code**: STUN/TURN error code (0=success)
5. **Authentication Status**: Authentication result for TURN
6. **Allocation Lifetime**: TURN allocation lifetime in seconds (TURN only)
7. **Response Size**: Size of STUN/TURN response in bytes

## Triggers

The template includes these trigger prototypes:

1. **Service Down**: Triggers when service status = 0
2. **High Response Time**: Triggers when RTT > configured threshold
3. **Authentication Failed**: Triggers when TURN authentication fails (error code 401)

## Testing

### Manual Testing
```bash
# Test STUN binding request
./get_stun_turn_check.py --host stun.example.com --port 3478 --transport UDP --mode STUN

# Test TURN allocation with authentication
./get_stun_turn_check.py --host turn.example.com --port 3478 --transport UDP --mode TURN \
  --username testuser --password testpass

# Test via wrapper script
./stun_turn_wrapper.sh UDP TURN status turn.example.com 3478 testuser testpass 10
```

### Expected Output Format
```json
{
  "stun": {
    "status": 1,
    "rtt": 0.125,
    "mapped_ip": "203.0.113.1",
    "error_code": 0,
    "auth_status": "SUCCESS",
    "lifetime": 600,
    "response_size": 84
  }
}
```

## Troubleshooting

### Common Issues

1. **Permission Errors**
   - Ensure scripts are executable: `chmod +x script_name`
   - Check Zabbix agent user permissions

2. **Python Dependencies**
   - Ensure Python 3 is installed and accessible
   - No external dependencies required (uses standard library)

3. **Network Connectivity**
   - Verify firewall rules allow STUN/TURN traffic
   - Test connectivity from Zabbix server/proxy to STUN/TURN server

4. **Authentication Issues**
   - Verify username/password are correct
   - Check if TURN server requires realm parameter
   - Ensure credentials are properly configured in macros

### Debug Mode
Enable debug output by modifying the Python script:
```python
# Add this line near the top of get_stun_turn_check.py
DEBUG = True
```

## Protocol Details

### STUN Protocol (RFC 5389)
- Uses UDP/TCP transport
- Binding requests discover public IP address
- No authentication required for basic functionality

### TURN Protocol (RFC 5766)  
- Extension of STUN for relay functionality
- Requires authentication (USERNAME/PASSWORD)
- Uses MESSAGE-INTEGRITY attribute (HMAC-SHA1)
- Supports FINGERPRINT attribute (CRC32)
- Provides allocation lifetime management

## Security Considerations

1. **Credential Storage**: TURN credentials are stored as Zabbix macros
2. **Network Security**: Monitor for unauthorized TURN usage
3. **Authentication**: Template monitors authentication failures
4. **Encryption**: Use TLS transport for sensitive environments

## Version History

- v1.0: Basic STUN monitoring
- v2.0: Added full TURN authentication support
- v2.1: Added Zabbix template with comprehensive monitoring

## Support

This template supports:
- Zabbix 5.0+
- Python 3.6+
- Standard STUN/TURN servers (RFC 5389/5766 compliant)
- UDP, TCP, and TLS transports
- Authentication via USERNAME/PASSWORD mechanism