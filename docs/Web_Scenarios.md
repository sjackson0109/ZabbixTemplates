# Python Web Scenario Monitoring Script

## Overview

`get_web_scenarios.py` is a Python script designed for monitoring HTTP/HTTPS endpoints and web application functionality. It is intended for integration with Zabbix as an external script, enabling automated checks of web services, APIs, and application health.

## Features
- Supports HTTP and HTTPS endpoints
- Customisable request methods (GET, POST, etc.)
- Configurable headers, timeouts, and payloads
- Response code and content validation
- Designed for Zabbix external script integration
- Suitable for both simple uptime checks and advanced web scenario monitoring

## Installation

### Prerequisites
- Python 3.6+
- `requests` library

### Setup
1. Install required dependencies:
   ```bash
   pip install requests
   ```

2. Copy `get_web_scenarios.py` to your Zabbix `externalscripts` directory:
   ```bash
   cp get_web_scenarios.py /usr/lib/zabbix/externalscripts/
   ```

3. Make the script executable:
   ```bash
   chmod +x /usr/lib/zabbix/externalscripts/get_web_scenarios.py
   ```

## Usage

### Command Line
You can run the script directly for ad-hoc checks:

```bash
python get_web_scenarios.py --url https://example.com --method GET --timeout 5
```

**Options:**
- `--url <URL>`: Target URL to check (required)
- `--method <METHOD>`: HTTP method (default: GET)
- `--timeout <SECONDS>`: Request timeout (default: 5)
- `--header <HEADER>`: Custom header(s), can be specified multiple times
- `--data <DATA>`: Payload for POST/PUT requests
- `--expect-code <CODE>`: Expected HTTP status code (default: 200)
- `--expect-content <STRING>`: String that must appear in the response body

### Zabbix Integration
1. Create an item in your Zabbix template or host:
   - Type: External check
   - Key: `get_web_scenarios.py[--url,<URL>,--method,<METHOD>,--timeout,<SECONDS>]`
   - Adjust parameters as needed for your scenario.

## Examples

### Basic Uptime Check
Check if a website is up and returns HTTP 200:
```bash
python get_web_scenarios.py --url https://example.com --expect-code 200
```

### Content Validation
Check for a specific string in the response:
```bash
python get_web_scenarios.py --url https://example.com --expect-content "Welcome"
```

### API Endpoint Monitoring
Monitor a REST API endpoint with custom headers:
```bash
python get_web_scenarios.py --url https://api.example.com/health --header "Authorisation: Bearer token123" --expect-code 200
```

### POST Request Monitoring
Test a form submission endpoint:
```bash
python get_web_scenarios.py --url https://example.com/api/test --method POST --data '{"test": "data"}' --header "Content-Type: application/json"
```

## Output
- Returns `1` if the check passes (expected code/content found)
- Returns `0` if the check fails (unexpected code/content, timeout, or error)
- Prints diagnostic output to stdout/stderr for troubleshooting

## Template Integration

The `web_scenarios_triggers.yaml` template provides:
- Low-level discovery of web endpoints
- Automated item creation for multiple scenarios
- Trigger configuration for availability monitoring
- Dashboard widgets for web service health overview

## Troubleshooting

### Common Issues
- **Permission Denied**: Ensure the script is executable and accessible by the Zabbix user
- **Module Not Found**: Verify the `requests` library is installed in the Python environment used by Zabbix
- **Timeout Errors**: Adjust the `--timeout` parameter for slower endpoints

### Debugging Steps
1. Test the script manually from command line before Zabbix integration
2. Check Zabbix server/proxy logs for script execution errors
3. Verify network connectivity from Zabbix server/proxy to target endpoints
4. Use verbose mode (add `--verbose` flag) for detailed execution information

## Best Practices
- Set appropriate timeout values based on expected response times
- Use content validation for critical application endpoints
- Implement proper error handling in custom scenarios
- Monitor both availability and response time metrics
- Group related endpoints using Zabbix host groups or tags