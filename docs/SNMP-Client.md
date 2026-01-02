# SNMPv3 Client with Authentication and Privacy Support

A comprehensive Python-based SNMP client that supports SNMPv1, SNMPv2c, and **full SNMPv3 with authentication and privacy encryption**. Designed for Zabbix integration without requiring external SNMP tools.

## 🚀 Features

- **Multi-version Support**: SNMPv1, SNMPv2c, and SNMPv3
- **Complete SNMPv3 Security**: Authentication + Privacy (AUTH+PRIV)
- **Authentication Methods**: None, MD5, SHA, SHA-224, SHA-256, SHA-384, SHA-512
- **Privacy Encryption**: None, DES, AES (128/192/256 bit) with CFB mode
- **Zabbix Integration**: Built-in discovery, check, and debug modes
- **Cross-Platform**: Works on Linux, Windows, and Docker containers
- **Vendor Compatibility**: Optimised for SonicWall, Cisco, and other enterprise devices
- **Pure Python**: Minimal dependencies with optional crypto library support

## 📋 Requirements

### Core Dependencies
- Python 3.7+
- No external dependencies for basic SNMPv1/v2c functionality

### Optional Dependencies (for SNMPv3 Privacy)
```bash
pip install pycryptodome
```

### For Zabbix Docker Deployment
The provided Dockerfile automatically installs all required dependencies.

## 🔧 Installation

1. **Basic Installation**
   ```bash
   # Clone or download snmp_client.py to your Zabbix externalscripts directory
   cp snmp_client.py /usr/lib/zabbix/externalscripts/
   chmod +x /usr/lib/zabbix/externalscripts/snmp_client.py
   ```

2. **Docker Installation** (Recommended for Zabbix Proxy)
   ```bash
   # Use the provided Dockerfile to build Zabbix Proxy with Python support
   docker build -f dockerfile/zabbix_proxy_mysql_alpine_python3 -t zabbix-proxy-python .
   ```

3. **Install Crypto Libraries** (for SNMPv3 Privacy)
   ```bash
   pip install pycryptodome
   ```

## 📖 Usage

### Command Line Interface

```bash
# Basic SNMPv2c GET
python snmp_client.py get <host> <oid> -v 2c -c public

# SNMPv3 with Authentication Only
python snmp_client.py get <host> <oid> -v 3 -u username -A sha -a authpass

# SNMPv3 with Authentication + Privacy (Full Security)
python snmp_client.py get <host> <oid> -v 3 -u username \
  -A sha -a authpass -X aes128 -x privpass

# Zabbix Discovery Mode
python snmp_client.py --discover

# Zabbix Check Mode (returns 1/0)
python snmp_client.py get <host> <oid> -v 3 -u username \
  -A sha -a authpass -X aes128 -x privpass --check

# Debug Mode (detailed output)
python snmp_client.py get <host> <oid> -v 3 -u username \
  -A sha -a authpass -X aes128 -x privpass --check-d
```

### Parameters

| Parameter | Description | Options |
|-----------|-------------|---------|
| `-v, --version` | SNMP version | `1`, `2c`, `3` |
| `-c, --community` | SNMPv1/v2c community | Default: `public` |
| `-u, --username` | SNMPv3 username | Required for SNMPv3 |
| `-A, --auth-protocol` | Authentication protocol | `none`, `md5`, `sha`, `sha224`, `sha256`, `sha384`, `sha512` |
| `-a, --auth-password` | Authentication password | String |
| `-X, --priv-protocol` | Privacy protocol | `none`, `des`, `aes`, `aes128`, `aes192`, `aes256` |
| `-x, --priv-password` | Privacy password | String |
| `-p, --port` | SNMP port | Default: `161` |
| `-t, --timeout` | Timeout in seconds | Default: `5` |

### Zabbix Integration Modes

| Mode | Description | Output |
|------|-------------|---------|
| `--discover` | Low-Level Discovery | JSON array for Zabbix LLD |
| `--check` | Monitoring check | `1` (success) or `0` (failure) |
| `--check-d` | Debug check | Detailed human-readable output |

## 🏢 Enterprise Examples

### SonicWall Firewall/Switch
```bash
# Full SNMPv3 AUTH+PRIV for SonicWall devices
python snmp_client.py get firewall.example.com 1.3.6.1.2.1.1.1.0 \
  -v 3 -u adminuser \
  -A sha -a "MyAuthPassword123" \
  -X aes128 -x "MyPrivPassword456" \
  --check
```

### Cisco Equipment
```bash
# Cisco with MD5 auth and AES privacy
python snmp_client.py get switch.example.com 1.3.6.1.2.1.1.3.0 \
  -v 3 -u ciscouser \
  -A md5 -a "CiscoAuthKey" \
  -X aes -x "CiscoPrivKey" \
  --check-d
```

### Basic Network Device
```bash
# Simple SNMPv2c for basic devices
python snmp_client.py get router.example.com 1.3.6.1.2.1.1.1.0 \
  -v 2c -c private --check
```

## 🔒 Security Levels

### SNMPv3 Security Levels

1. **noAuthNoPriv**: No authentication, no encryption
   ```bash
   python snmp_client.py get host oid -v 3 -u username
   ```

2. **authNoPriv**: Authentication only
   ```bash
   python snmp_client.py get host oid -v 3 -u username -A sha -a authpass
   ```

3. **authPriv**: Authentication + Privacy (Recommended)
   ```bash
   python snmp_client.py get host oid -v 3 -u username \
     -A sha -a authpass -X aes128 -x privpass
   ```

### Supported Algorithms

**Authentication:**
- MD5 (RFC 3414)
- SHA-1 (RFC 3414)
- SHA-224, SHA-256, SHA-384, SHA-512 (RFC 7630)

**Privacy:**
- DES (RFC 3414)
- AES-128, AES-192, AES-256 CFB (RFC 3826)

## 🐳 Zabbix Docker Integration

### Dockerfile Usage
```dockerfile
FROM zabbix/zabbix-proxy-mysql:alpine-7.0-latest

# Install Python and SNMP client dependencies
RUN apk add --no-cache python3 py3-pip
RUN pip3 install pycryptodome --break-system-packages

# Copy SNMP client script
COPY externalscripts/snmp_client.py /usr/lib/zabbix/externalscripts/
RUN chmod +x /usr/lib/zabbix/externalscripts/snmp_client.py
```

### Zabbix Template Integration
```xml
<!-- Example Zabbix item -->
<item>
  <key>snmp_client.py[{HOST.CONN},1.3.6.1.2.1.1.1.0,-v,3,-u,{$SNMP_USER},-A,sha,-a,{$SNMP_AUTH_PASS},-X,aes128,-x,{$SNMP_PRIV_PASS},--check]</key>
  <name>SNMP System Description</name>
  <type>EXTERNAL</type>
</item>
```

## 🛠️ Advanced Configuration

### Engine Discovery
The script automatically handles SNMPv3 engine discovery with fallback patterns optimised for:
- SonicWall devices
- Cisco equipment  
- Generic SNMPv3 implementations

### Key Derivation
Implements RFC 3414 compliant key derivation:
- Password-to-key conversion using 1MB expansion
- Engine ID-based key localization
- Proper HMAC authentication parameter generation

### Error Handling
- **Network timeouts**: Graceful handling with configurable timeouts
- **Authentication failures**: Clear error messages for debugging
- **Zabbix compatibility**: Always returns appropriate codes (0/1) for monitoring

## 📊 Output Examples

### Discovery Mode Output
```json
{
  "data": [
    {"{#SNMPVERSION}": "1", "{#DESCRIPTION}": "SNMPv1"},
    {"{#SNMPVERSION}": "2c", "{#DESCRIPTION}": "SNMPv2c"}, 
    {"{#SNMPVERSION}": "3", "{#DESCRIPTION}": "SNMPv3"}
  ]
}
```

### Check Mode Output
```bash
# Success
1

# Failure  
0
```

### Debug Mode Output
```bash
SNMP 3 GET firewall.example.com:161 1.3.6.1.2.1.1.1.0
Result: SonicWall NSv 470 Firewall
```

## 🐛 Troubleshooting

### Common Issues

1. **Timeout Errors**
   - Check network connectivity: `ping hostname`
   - Verify SNMP port is accessible: `telnet hostname 161`
   - Confirm device has SNMP enabled

2. **Authentication Failures**
   - Verify username and passwords are correct
   - Check if SNMPv3 user is enabled on device
   - Confirm security level matches (authPriv vs authNoPriv)

3. **Privacy Decryption Errors**
   - Ensure `pycryptodome` is installed: `pip install pycryptodome`
   - Verify privacy password is correct
   - Check if device supports the selected encryption algorithm

4. **Access Denied**
   - Verify SNMP access control lists on device
   - Check if source IP is allowed
   - Confirm OID is accessible with configured view

### Debug Tips

1. **Enable Debug Mode**
   ```bash
   python snmp_client.py get host oid [options] --check-d
   ```

2. **Test Basic Connectivity**
   ```bash
   # Try SNMPv2c first
   python snmp_client.py get host oid -v 2c -c public --check-d
   ```

3. **Test Authentication Only**
   ```bash
   # Test without privacy
   python snmp_client.py get host oid -v 3 -u user -A sha -a pass --check-d
   ```

## 📝 Licence

This project is part of the ZabbixTemplates repository and follows the same licensing terms.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test with different SNMP devices
5. Submit a pull request

## 📞 Support

For issues and questions:
- Check the troubleshooting section above
- Review Zabbix external script documentation
- Test with standard SNMP tools (net-snmp) to verify device configuration
- Open an issue in the GitHub repository

---

**Author**: Simon Jackson (@sjackson0109)  
**Version**: 2.0  
**Last Updated**: October 15, 2025