# PHP-FPM Process Manager Monitoring Template

## Overview
The PHP-FPM template provides comprehensive monitoring for PHP FastCGI Process Manager (FPM) performance and health metrics. It enables real-time tracking of process pool status, request handling, and resource utilisation.

## Features
- **Process Pool Monitoring**: Track active, idle, and total processes
- **Request Metrics**: Monitor request rates, queue length, and processing times
- **Memory Usage**: Track memory consumption per pool and process
- **Slow Request Detection**: Identify and monitor slow-executing requests
- **Connection Monitoring**: Track accepted connections and listen queue status
- **Multi-Pool Support**: Monitor multiple PHP-FPM pools simultaneously

## Prerequisites
- Zabbix 7.0 or later
- PHP-FPM with status page enabled
- Network access to PHP-FPM status endpoint
- Web server (nginx/Apache) configured to expose PHP-FPM status

## PHP-FPM Configuration

### Enable Status Page
1. **Configure PHP-FPM Pool**:
   Edit your PHP-FPM pool configuration (e.g., `/etc/php/7.4/fpm/pool.d/www.conf`):
   ```ini
   ; Enable status page
   pm.status_path = /status
   
   ; Enable ping page  
   ping.path = /ping
   
   ; Show slow requests
   slowlog = /var/log/php7.4-fpm-slow.log
   request_slowlog_timeout = 5s
   ```

2. **Configure Web Server**:
   
   **Nginx Configuration**:
   ```nginx
   location ~ ^/(status|ping)$ {
       access_log off;
       allow 127.0.0.1;
       allow ::1;
       allow YOUR_ZABBIX_SERVER_IP;
       deny all;
       fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
       fastcgi_index index.php;
       include fastcgi_params;
       fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
   }
   ```
   
   **Apache Configuration**:
   ```apache
   <LocationMatch "/(status|ping)">
       Require ip 127.0.0.1
       Require ip ::1
       Require ip YOUR_ZABBIX_SERVER_IP
       ProxyPassMatch fcgi://127.0.0.1:9000
   </LocationMatch>
   ```

3. **Restart Services**:
   ```bash
   systemctl restart php7.4-fpm
   systemctl restart nginx  # or apache2
   ```

## Zabbix Installation

### Template Import
1. Copy `get_php_fpm.py` to Zabbix external scripts directory:
   ```bash
   cp get_php_fpm.py /usr/lib/zabbix/externalscripts/
   chmod +x /usr/lib/zabbix/externalscripts/get_php_fpm.py
   ```

2. Import the `php-fpm.yaml` template into Zabbix

3. Create host and assign PHP-FPM template

### Host Configuration
Configure the following macros on the host:
- `{$PHP_FPM_STATUS_URL}`: PHP-FPM status URL (e.g., `http://localhost/status`)
- `{$PHP_FPM_PING_URL}`: PHP-FPM ping URL (e.g., `http://localhost/ping`)
- `{$PHP_FPM_TIMEOUT}`: Request timeout in seconds (default: 10)
- `{$PHP_FPM_POOL}`: Pool name to monitor (default: www)

## Monitored Metrics

### Process Management
- **Active Processes**: Currently processing requests
- **Idle Processes**: Available processes waiting for requests
- **Total Processes**: Total number of spawned processes
- **Max Active Processes**: Maximum active processes since start
- **Max Children Reached**: Number of times max children limit reached

### Request Handling
- **Accepted Connections**: Total connections accepted
- **Listen Queue**: Number of requests in listen queue
- **Max Listen Queue**: Maximum listen queue length reached
- **Listen Queue Length**: Current configured queue length
- **Slow Requests**: Number of slow requests detected

### Performance Metrics
- **Request Rate**: Requests per second
- **Average Request Duration**: Average processing time
- **Memory Usage**: Memory consumption per process
- **CPU Usage**: CPU utilisation percentage
- **Start Time**: Process manager start timestamp

## Template Components

### Discovery Rules
- **Pool Discovery**: Automatically discovers PHP-FPM pools
- **Process Discovery**: Identifies individual worker processes
- **Slow Log Discovery**: Finds and monitors slow request logs

### Items
- Process pool status and metrics
- Request rate and response time statistics
- Memory and CPU utilisation tracking
- Connection and queue monitoring
- Service availability checks

### Triggers
- **Critical**: PHP-FPM service down, max children reached consistently
- **Warning**: High request queue, slow requests detected, memory usage high
- **Information**: Process pool restarts, configuration changes

### Graphs
- Process pool utilisation over time
- Request rate and response time trends
- Memory usage and resource consumption
- Queue length and connection statistics

## Troubleshooting

### Common Issues

1. **Status Page Inaccessible**:
   - Verify web server configuration and PHP-FPM status path
   - Check firewall rules and IP restrictions
   - Ensure PHP-FPM service is running

2. **No Data Collection**:
   - Test status URL accessibility from Zabbix server
   - Verify external script permissions and execution
   - Check Zabbix server logs for script errors

3. **Permission Denied**:
   - Ensure Zabbix user has execute permissions on script
   - Check web server access controls and IP restrictions
   - Verify PHP-FPM status page security configuration

### Debugging Steps

1. **Test Status Page Access**:
   ```bash
   curl http://localhost/status
   curl http://localhost/ping
   ```

2. **Test External Script**:
   ```bash
   /usr/lib/zabbix/externalscripts/get_php_fpm.py http://localhost/status
   ```

3. **Check Service Status**:
   ```bash
   systemctl status php7.4-fpm
   systemctl status nginx
   ```

## Performance Tuning

### PHP-FPM Pool Configuration
Optimise pool settings based on monitoring data:

```ini
; Process management
pm = dynamic
pm.max_children = 50
pm.start_servers = 5
pm.min_spare_servers = 5
pm.max_spare_servers = 35
pm.max_requests = 500

; Slow request monitoring
request_slowlog_timeout = 5s
slowlog = /var/log/php-fpm-slow.log

; Process management tuning
pm.process_idle_timeout = 10s
```

### Alerting Thresholds
Configure appropriate alert thresholds:
- `{$PHP_FPM_PROC_WARN}`: Process utilisation warning (80%)
- `{$PHP_FPM_PROC_CRIT}`: Process utilisation critical (95%)
- `{$PHP_FPM_QUEUE_WARN}`: Queue length warning threshold
- `{$PHP_FPM_SLOW_WARN}`: Slow requests warning threshold

## Best Practices
- Monitor process utilisation to right-size pool configuration
- Set appropriate slow request thresholds for application profiling
- Use process recycling (`pm.max_requests`) to prevent memory leaks
- Monitor memory usage trends to detect application issues
- Implement proper access controls for status endpoints
- Use SSL/TLS for status page access in production environments

## Security Considerations
- Restrict status page access to authorised IP addresses only
- Use authentication for status endpoints in public-facing environments
- Disable status pages in production if not actively monitored
- Monitor access logs for unauthorised status page requests
- Consider using Unix sockets instead of TCP for PHP-FPM communication