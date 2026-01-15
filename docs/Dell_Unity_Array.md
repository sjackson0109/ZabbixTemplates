# Dell Unity Array Storage Monitoring Template

## Overview
The Dell Unity Array template provides comprehensive monitoring for Dell EMC Unity XT series storage arrays using REST API integration. It enables real-time monitoring of storage health, capacity, performance, and system status.

## Features
- **REST API Integration**: Direct communication with Unity management interface
- **Comprehensive Discovery**: Automatic discovery of LUNs, pools, disks, ports, and components
- **Health Monitoring**: Real-time system health and alert status
- **Capacity Management**: Storage pool utilisation and capacity forecasting  
- **Performance Metrics**: IOPS, throughput, and response time monitoring
- **Component Status**: Disk health, controller status, and hardware monitoring

## Supported Models
- Dell EMC Unity XT 380/480/680/880
- Dell EMC Unity XT 380F/480F/680F/880F
- Dell EMC Unity 300/400/500/600/650F
- Unity VSA (Virtual Storage Appliance)

## Prerequisites
- Zabbix 7.0 or later
- Dell Unity array with REST API enabled
- Unity management interface accessible from Zabbix server/proxy
- Valid Unity user credentials with monitoring privileges

## Installation

### Unity Array Configuration
1. **Enable REST API**:
   - Access Unity management interface
   - Navigate to Settings → Management → REST API
   - Ensure REST API service is enabled

2. **Create Monitoring User**:
   - Create dedicated user account for Zabbix monitoring
   - Assign minimum required privileges (Operator role recommended)
   - Note username and password for template configuration

### Zabbix Configuration
1. **Import Template**:
   - Import `dell_unity_array.yaml` into Zabbix
   - Navigate to Configuration → Templates → Import

2. **Configure Host**:
   - Create new host for Unity array
   - Assign "Dell Unity Array" template
   - Configure agent interface with Unity management IP

3. **Configure Macros**:
   - `{$UNITY_API_HOST}`: Unity management interface IP/hostname
   - `{$UNITY_USERNAME}`: Unity monitoring user account
   - `{$UNITY_PASSWORD}`: Unity user password
   - `{$UNITY_API_PORT}`: REST API port (default: 443)
   - `{$UNITY_TIMEOUT}`: API request timeout (default: 30)

## Template Components

### Discovery Rules
- **Storage Pool Discovery**: Discovers all configured storage pools
- **LUN Discovery**: Finds all logical units and their mappings
- **Disk Discovery**: Identifies physical disks and their status
- **FC Port Discovery**: Discovers Fibre Channel ports and connections
- **iSCSI Port Discovery**: Finds iSCSI network interfaces
- **Controller Discovery**: Identifies storage processors and controllers

### Monitored Metrics

#### System Health
- Overall system health status
- Alert count and severity levels
- Component fault indicators
- Environmental status (temperature, fans, power)

#### Storage Capacity
- Pool capacity and utilisation percentage
- Available free space per pool
- LUN allocation and usage statistics
- Thin provisioning efficiency ratios

#### Performance Metrics
- Read/write IOPS per pool and LUN
- Throughput (MB/s) for read and write operations
- Average response times and latency
- Queue depth and outstanding I/O operations

#### Hardware Components
- Disk health status and failure predictions
- Controller operational state and failover status
- Network port link status and utilisation
- Power supply and cooling system status

### Triggers
- **Critical Alerts**: System failures, disk failures, pool full conditions
- **Warning Alerts**: High utilisation, performance degradation, component warnings
- **Information**: Status changes, maintenance events, configuration updates

### Graphs
- Storage capacity trends and growth projections
- Performance metrics over time (IOPS, throughput, latency)
- System health and availability statistics
- Component status and failure tracking

## Error Handling

### Common Issues
1. **Authentication Failures**:
   - Verify Unity user credentials and permissions
   - Check account lockout status and password expiry
   - Ensure REST API service is running

2. **Connection Timeouts**:
   - Verify network connectivity to Unity management interface
   - Check firewall rules for HTTPS (port 443) access
   - Increase timeout macro value if needed

3. **Discovery Failures**:
   - Confirm Unity system is fully initialised
   - Check for pending configuration changes
   - Verify sufficient user privileges for discovery operations

### Troubleshooting Steps
1. Test REST API connectivity using curl or similar tools:
   ```bash
   curl -k -u username:password https://unity-mgmt-ip/api/instances/basicSystemInfo
   ```

2. Review Zabbix server logs for API errors and responses
3. Check Unity event logs for authentication and access issues
4. Validate template macros and host configuration

## Best Practices
- Use dedicated monitoring account with minimal required privileges
- Implement proper certificate validation for secure environments
- Monitor API call frequency to avoid overwhelming the Unity system
- Set appropriate data collection intervals based on system size
- Use Zabbix maintenance periods during Unity maintenance windows

## Value Mappings

### Health Status
- 0: Unknown
- 5: OK
- 7: OK but minor warning
- 10: Degraded/Warning
- 15: Minor failure
- 20: Major failure
- 25: Critical failure
- 30: Non-recoverable error

### Disk Status
- 1: Enabled
- 2: Disabled
- 3: Removed
- 4: Missing
- 5: Faulted
- 6: Unknown

## Advanced Configuration

### Custom Thresholds
Adjust capacity and performance thresholds using template macros:
- `{$POOL_UTIL_WARN}`: Pool utilisation warning threshold (%)
- `{$POOL_UTIL_CRIT}`: Pool utilisation critical threshold (%)
- `{$RESPONSE_TIME_WARN}`: Response time warning threshold (ms)
- `{$RESPONSE_TIME_CRIT}`: Response time critical threshold (ms)

### Extended Discovery
Enable additional discovery rules for detailed monitoring:
- Snapshot and replication status
- File system and NAS server monitoring
- Host access and initiator tracking

## References
- [Dell Unity Family REST API Guide](https://www.dell.com/support/manuals/en-us/unity-family/unity-family-rest-api-guide)
- [Unity Management Interface User Guide](https://www.dell.com/support/manuals/en-us/unity-family)
- [Dell Unity Best Practices Guide](https://www.delltechnologies.com/en-us/storage/unity.htm)