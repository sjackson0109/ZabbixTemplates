# Email Health & Compliance Monitoring Template

## Overview

The Email Health & Compliance Monitoring template provides comprehensive monitoring of email infrastructure, authentication protocols, and RFC compliance for email domains. This template performs extensive validation of email delivery systems, security protocols, and compliance with major email-related RFCs.

## Purpose

Monitor email infrastructure health, authentication protocols, and RFC compliance for comprehensive email deliverability and security assessment. Designed to ensure email systems meet industry standards and maintain optimal deliverability rates.

## Features

### Email Authentication Analysis
- **SPF (Sender Policy Framework)** - RFC 7208/4408 validation and policy analysis
- **DKIM (DomainKeys Identified Mail)** - RFC 6376 signature discovery and validation
- **DMARC (Domain-based Message Authentication)** - RFC 7489 policy validation and alignment checks

### Advanced Email Security
- **MTA-STS (Mail Transfer Agent Strict Transport Security)** - RFC 8461 policy validation
- **TLS-RPT (SMTP TLS Reporting)** - RFC 8460 reporting configuration
- **BIMI (Brand Indicators for Message Identification)** - Brand indicators validation

### Infrastructure Monitoring
- **MX Record Analysis** - Comprehensive validation, connectivity testing, and preference analysis
- **SMTP Protocol Compliance** - RFC 5321/5322 testing with STARTTLS and AUTH mechanisms
- **Email Blacklist/Reputation Monitoring** - Multiple blacklist checks and reputation scoring

### Deliverability Assessment
- **Comprehensive Scoring** - Weighted metrics for overall email health
- **RFC Compliance Reporting** - Detailed standards validation across all protocols
- **Deliverability Recommendations** - Actionable insights for improving email delivery

## RFC Coverage

This template validates compliance with the following RFCs:

| RFC | Standard | Description |
|-----|----------|-------------|
| RFC 5321 | SMTP Protocol | Simple Mail Transfer Protocol specification |
| RFC 5322 | Internet Message Format | Standard for email message format |
| RFC 3207 | SMTP STARTTLS | SMTP Service Extension for Secure SMTP over Transport Layer Security |
| RFC 4954 | SMTP AUTH | SMTP Service Extension for Authentication |
| RFC 6409 | Message Submission | Message Submission for Mail protocol |
| RFC 7208 | SPF | Sender Policy Framework (SPF) for Authorising Use of Domains in Email |
| RFC 6376 | DKIM | DomainKeys Identified Mail (DKIM) Signatures |
| RFC 7489 | DMARC | Domain-based Message Authentication, Reporting, and Conformance |
| RFC 8460 | TLS-RPT | SMTP TLS Reporting |
| RFC 8461 | MTA-STS | Mail Transfer Agent Strict Transport Security |
| RFC 8463 | A New Cryptographic Signature Method | Enhanced cryptographic signatures |
| RFC 3501 | IMAP4rev1 | Internet Message Access Protocol - Version 4rev1 |
| RFC 1939 | POP3 | Post Office Protocol - Version 3 |
| RFC 2595 | TLS for IMAP and POP3 | Using TLS with IMAP, POP3 and ACAP |

## Files

### Template
- **File**: `templates/email_health.yaml`
- **Type**: Zabbix 7.0+ Template
- **Template Name**: Email Health & Compliance Monitoring
- **Template Group**: Email Infrastructure

### External Script
- **File**: `externalscripts/get_email_health.py`
- **Type**: Python 3.6+ External Script
- **Dependencies**: Standard Python libraries only

## Installation

### Prerequisites
- Zabbix Server/Proxy 7.0+
- Python 3.6+ on Zabbix Server/Proxy
- Network connectivity for DNS queries and SMTP testing
- Appropriate firewall rules for external queries

### Template Installation
1. Import the template file `templates/email_health.yaml` into Zabbix
2. Copy `externalscripts/get_email_health.py` to the Zabbix external scripts directory
3. Ensure the script has execute permissions
4. Configure external script timeout if needed (default: 30 seconds)

### Host Configuration
1. Create hosts with domain names as host names (e.g., `example.com`)
2. Assign the "Email Health & Compliance Monitoring" template to these hosts
3. Ensure hosts are in the appropriate host group for email domains

## Usage

### Script Commands

The external script supports multiple commands for different types of analysis:

#### Discovery and Analysis
```bash
# Discover email services and authentication methods
python get_email_health.py discover <DOMAIN>

# Comprehensive email infrastructure analysis
python get_email_health.py comprehensive <DOMAIN>

# Overall health assessment
python get_email_health.py health <DOMAIN>
```

#### Authentication Analysis
```bash
# SPF record validation
python get_email_health.py spf <DOMAIN>

# DKIM selector discovery
python get_email_health.py dkim_discovery <DOMAIN>

# DKIM record validation (requires selector)
python get_email_health.py dkim <DOMAIN> <SELECTOR>

# DMARC policy analysis
python get_email_health.py dmarc <DOMAIN>
```

#### Security and Compliance
```bash
# MTA-STS policy validation
python get_email_health.py mta_sts <DOMAIN>

# TLS reporting configuration
python get_email_health.py tls_rpt <DOMAIN>

# BIMI brand indicators
python get_email_health.py bimi <DOMAIN>
```

#### Infrastructure Testing
```bash
# MX record analysis and connectivity
python get_email_health.py mx_analysis <DOMAIN>

# SMTP connectivity testing
python get_email_health.py smtp_test <DOMAIN> [PORT]

# Blacklist reputation check
python get_email_health.py blacklist_check <DOMAIN>

# Deliverability assessment
python get_email_health.py deliverability <DOMAIN>
```

### Example Usage
```bash
# Complete analysis of a domain
python get_email_health.py comprehensive example.com

# Check SPF configuration
python get_email_health.py spf example.com

# Test SMTP connectivity
python get_email_health.py smtp_test example.com 25
```

## Monitoring Items

### Core Metrics
- **Overall Email Health Score** - Comprehensive health percentage
- **Email Security Score** - Authentication and security percentage
- **RFC Compliance Score** - Standards compliance percentage
- **Deliverability Score** - Email delivery effectiveness percentage

### Authentication Metrics
- **SPF Record Valid** - SPF record validity status
- **SPF RFC 7208 Compliance** - SPF standards compliance
- **DKIM Selectors Found** - Number of discovered DKIM selectors
- **DMARC Policy Valid** - DMARC policy validity
- **DMARC Policy Type** - Policy enforcement level (none/quarantine/reject)

### Infrastructure Metrics
- **MX Records Count** - Number of configured MX records
- **Primary MX Server Reachable** - Primary MX connectivity status
- **MX RFC 5321 Compliance** - MX configuration compliance

### Security Metrics
- **MTA-STS Policy Found** - MTA-STS availability status
- **TLS-RPT Configuration Valid** - TLS reporting validity
- **BIMI Record Valid** - Brand indicator availability

### Reputation Metrics
- **Email Reputation Score** - Domain reputation percentage
- **Blacklisted Count** - Number of blacklist entries

## Dashboards

The template includes four comprehensive dashboards:

### 1. Email Infrastructure Overview
- Email health score gauges
- Authentication status summary
- Overall infrastructure metrics
- Authentication records status table

### 2. Email RFC Compliance
- RFC compliance summary
- Standards compliance status table
- Compliance issues breakdown

### 3. Email Security Analysis
- Security scores trend graph
- Authentication method status
- Reputation and blacklist monitoring

### 4. Email Deliverability
- Deliverability score gauges
- Reputation monitoring
- Authentication scoring
- Detailed assessment report

## Triggers

### Critical Triggers (DISASTER/HIGH)
- **No MX records found** - Email delivery impossible
- **SPF record missing or invalid** - Authentication failure
- **DMARC policy missing or invalid** - Security vulnerability
- **Primary MX server unreachable** - Service unavailability
- **Domain found on email blacklists** - Reputation damage
- **Poor email deliverability score** - Delivery issues

### Warning Triggers
- **No DKIM selectors found** - Missing authentication
- **DMARC policy set to none** - Minimal protection
- **MX configuration RFC compliance issues** - Standards violations
- **Poor email reputation score** - Reputation concerns
- **Poor overall email health score** - General issues
- **Poor email security score** - Security concerns

### Information Triggers
- **Poor RFC compliance score** - Standards compliance issues

## Configuration

### Environment Variables
The script supports several environment variables for configuration:

- `EMAIL_TIMEOUT` - DNS/SMTP query timeout in seconds (default: 30)
- `DNS_NAMESERVER` - Custom DNS nameserver IP address
- `EMAIL_DEBUG` - Enable debug logging (set to '1')

### Customisation
- **Blacklist Sources** - Modify `EMAIL_BLACKLISTS` array in script
- **DKIM Selectors** - Update `COMMON_DKIM_SELECTORS` list for discovery
- **Timeout Values** - Adjust timeout settings for network conditions
- **Scoring Weights** - Modify scoring algorithms in deliverability assessment

## Troubleshooting

### Common Issues

#### DNS Resolution Problems
- Verify DNS connectivity from Zabbix server/proxy
- Check firewall rules for DNS queries (port 53)
- Validate DNS nameserver configuration

#### SMTP Connectivity Issues
- Ensure outbound SMTP ports (25, 587, 465) are accessible
- Verify no blocking by ISP or firewall
- Check for rate limiting on target mail servers

#### Script Permission Errors
- Verify script has execute permissions
- Check Zabbix external scripts directory path
- Ensure Python interpreter is accessible

#### Template Import Issues
- Validate Zabbix version compatibility (7.0+)
- Check for UUID conflicts with existing templates
- Verify template group exists or create as needed

### Debug Mode
Enable debug mode for detailed logging:
```bash
EMAIL_DEBUG=1 python get_email_health.py comprehensive example.com
```

### Performance Optimisation
- Adjust polling intervals based on domain criticality
- Use discovery rules to automatically manage monitored domains
- Configure appropriate history retention periods
- Consider proxy distribution for large-scale monitoring

## Integration

### With Other Templates
- **DNS Domain Health Template** - Complementary DNS monitoring
- **TLS Compliance Checker** - Enhanced security validation
- **TCP Port Scanner** - Additional connectivity testing

### With External Systems
- **Email Security Gateways** - Correlation with security events
- **DNS Management Systems** - Automated record validation
- **Certificate Management** - TLS certificate monitoring

## Maintenance

### Regular Tasks
- Review and update blacklist sources
- Validate DKIM selector discovery lists
- Monitor script execution times and optimise
- Review scoring algorithms for accuracy

### Updates
- Monitor RFC updates and implement new standards
- Update email authentication protocols as they evolve
- Enhance blacklist sources and reputation services
- Optimise DNS query efficiency

## Support

For issues, enhancements, or questions:
- Review Zabbix logs for script execution errors
- Validate network connectivity and DNS resolution
- Check script permissions and Python environment
- Verify template configuration and item keys

## Licence

This template and script are part of the ZabbixTemplates repository.
Created by Simon Jackson (sjackson0109).

---

**Version**: 1.0  
**Created**: 2026/01/02  
**Zabbix Compatibility**: 7.0+  
**Python Requirements**: 3.6+