# Domain Health & Compliance Monitoring for Zabbix

## Overview

This Zabbix template provides comprehensive domain health and compliance monitoring. It performs DNS record checks, DNSSEC validation, email authentication (SPF/DKIM/DMARC), registrar/WHOIS/RDAP data retrieval, ASN lookup, NS server monitoring, and RFC compliance checks.

## Features

- **DNS Record Validation**: Query and validate A, AAAA, MX, NS, CNAME, SOA, PTR, TXT, SRV, CAA records
- **Email Authentication**: Validate SPF (RFC 7208) and DMARC (RFC 7489) records; check DKIM record presence (full signature validation requires email flow)
- **Legacy SPF Detection**: Monitor deprecated SPF record type 99 for RFC 7208 compliance
- **DNSSEC Validation**: Check DNSSEC presence, trust chain, signature validity, key types (KSK/ZSK), algorithms, RRSIG expiry (RFC 4033-4035)
- **DANE/TLSA Support**: Discover TLSA records, validate certificate associations for TLS services (RFC 6698)
- **Registrar/WHOIS Data**: Retrieve domain expiry, registration status, registrar info
- **RDAP Support**: Modern WHOIS replacement with structured JSON output (RFC 7480-7484)
- **ASN Lookup**: Identify hosting provider and network via Autonomous System Number lookup
- **NS Server Monitoring**: Discover and monitor nameserver availability and latency
- **RFC Compliance**: Detect non-conformity, syntax errors, and common misconfigurations
- **Health Score**: Overall health score (0-100) based on compliance checks
- **LLD Discovery**: Automatic discovery of DNS record types and NS servers

## RFC Compliance

| RFC | Description | Checks Implemented |
|-----|-------------|-------------------|
| RFC 1034, 1035 | Core DNS protocol and record types | A, AAAA, MX, NS, CNAME, SOA, PTR, TXT, SRV validation |
| RFC 1912 | Common DNS operational errors | Lame delegation, missing records, configuration errors |
| RFC 2181 | DNS specification clarifications | TTL, CNAME rules, authoritative answers |
| RFC 2182 | Secondary server selection | NS diversity analysis, geographic/network distribution |
| RFC 4033-4035 | DNSSEC | DNSKEY, RRSIG, DS, NSEC validation, key types (KSK/ZSK), algorithm identification, chain of trust |
| RFC 4255 | SSHFP Records | SSH host key fingerprint publication in DNS |
| RFC 5782 | DNSBL/Blacklist | DNS-based blackhole list checking against major providers |
| RFC 6186 | Email SRV Records | Email client autoconfiguration via SRV records |
| RFC 6698 | DANE | TLSA record discovery, syntax validation, certificate association verification |
| RFC 7208 | SPF | SPF TXT record syntax and policy validation, legacy type 99 detection |
| RFC 7489 | DMARC | DMARC TXT record syntax and required tags |
| RFC 6376 | DKIM | DKIM TXT record presence only (see [Limitations](#limitations)) |
| RFC 6844 | CAA | CAA record syntax and CA policy |
| RFC 2782 | SRV records | SRV record syntax validation |
| RFC 3596 | IPv6 (AAAA) | AAAA record syntax validation |
| RFC 7480-7484 | RDAP | Registration Data Access Protocol queries |
| RFC 7673 | DANE for SMTP/MX | TLSA records for MX server TLS validation |
| RFC 7929 | OPENPGPKEY | OpenPGP public key publication in DNS |
| RFC 8162 | SMIMEA | S/MIME certificate association in DNS |
| RFC 8461 | MTA-STS | Mail Transfer Agent Strict Transport Security policy detection |
| RFC 8460 | TLS-RPT | TLS Reporting for SMTP connectivity issues |
| RFC 8624 | DNSSEC Algorithm Status | Algorithm recommendation validation |
| RFC 9471 | Glue Records | Glue record validation for in-bailiwick nameservers |

## Requirements

- Zabbix Server/Proxy 7.0+
- Python 3.6+ (for external script)
- Network access to DNS servers, WHOIS services, and RDAP endpoints

## Installation

### 1. Deploy the External Script

Copy `get_domain_health.py` to your Zabbix external scripts directory:

```bash
# Linux
cp externalscripts/get_domain_health.py /usr/lib/zabbix/externalscripts/
chmod +x /usr/lib/zabbix/externalscripts/get_domain_health.py

# Windows
copy externalscripts\get_domain_health.py "C:\Program Files\Zabbix Agent\externalscripts\"
```

### 2. Import the Template

Import `templates/domain_health.yaml` into Zabbix:

1. Go to **Configuration** → **Templates**
2. Click **Import**
3. Select `domain_health.yaml`
4. Click **Import**

### 3. Configure Hosts

1. Create a host for each domain to monitor
2. Set the **{$DNS_DOMAIN}** macro to the domain name (e.g., `example.com`)
3. Link the **DNS Domain Health** template

## Macros

| Macro | Default | Description |
|-------|---------|-------------|
| `{$DNS_DOMAIN}` | *(required)* | Domain name to monitor |
| `{$DNS_TIMEOUT}` | `10` | DNS query timeout in seconds |
| `{$DNS_NAMESERVER}` | *(system resolver)* | DNS nameserver to use |
| `{$DNS_HEALTH_CRITICAL}` | `50` | Health score threshold for critical alerts |
| `{$DNS_HEALTH_WARNING}` | `75` | Health score threshold for warning alerts |
| `{$DNS_EXPIRY_WARNING}` | `45` | Days until expiry threshold for warning alerts |
| `{$DNS_EXPIRY_INFO}` | `90` | Days until expiry threshold for info alerts |
| `{$DNS_NS_LATENCY_WARNING}` | `200` | NS server latency threshold in ms for warning alerts |
| `{$DNS_LATENCY_WARNING}` | `500` | DNS query latency threshold in ms for warning alerts |

## Items

### Master Items
| Item | Description |
|------|-------------|
| DNS Health Score | Overall health score (0-100) |
| DNS Health Full Report | Full JSON health report |

### Dependent Items (DNS Validation)
| Item | Description |
|------|-------------|
| DNS SOA Record Valid | SOA record validation status |
| DNS NS Records Valid | NS records validation status |
| DNS MX Records Valid | MX records validation status |
| DNS A Records Valid | A records presence |
| DNS AAAA Records Valid | AAAA records presence |
| DNS CAA Records Valid | CAA records validation status |
| DNS SPF Record Valid | SPF record validation status |
| DNS SPF Error | SPF validation error message |
| DNS DMARC Record Valid | DMARC record validation status |
| DNS DMARC Error | DMARC validation error message |
| DNS DKIM Record Valid | DKIM record found (checks common selectors for record presence only) |
| DNS DKIM Error | DKIM lookup error message |
| DNS DNSSEC Enabled | DNSSEC enabled status |
| DNS DNSSEC Valid | DNSSEC validation status |

### WHOIS Items
| Item | Description |
|------|-------------|
| WHOIS Full Data | Full WHOIS response data |
| WHOIS Registrar | Domain registrar |
| WHOIS Expiry Date | Domain expiry date |
| WHOIS Days Until Expiry | Days until domain registration expires |

### RDAP Items (RFC 7480-7484)
| Item | Description |
|------|-------------|
| RDAP Full Data | Full RDAP JSON response (modern WHOIS replacement) |
| RDAP Registrar | Registrar name from RDAP |
| RDAP Days Until Expiry | Days until expiry from RDAP data |
| RDAP Creation Date | Domain registration date |
| RDAP Expiry Date | Domain expiry date in ISO 8601 format |
| RDAP Nameservers | Comma-separated list of nameservers |
| RDAP Server | RDAP server URL used for the query |
| RDAP Status List | Comma-separated list of all domain status codes |
| RDAP Status Count | Number of status codes applied |
| RDAP Domain Age (Days) | Days since domain registration (newly registered domains may indicate phishing risk) |

#### RDAP Registrar Lock Status Items
These items indicate whether specific registrar-level locks are in place (1=Yes, 0=No):

| Item | Description |
|------|-------------|
| RDAP Client Transfer Prohibited | Prevents unauthorized domain transfers |
| RDAP Client Delete Prohibited | Prevents accidental domain deletion |
| RDAP Client Update Prohibited | Prevents unauthorized DNS/contact changes |

#### RDAP Registry Lock Status Items
These items indicate whether specific registry-level locks are in place (1=Yes, 0=No):

| Item | Description |
|------|-------------|
| RDAP Server Transfer Prohibited | Registry-level transfer lock |
| RDAP Server Delete Prohibited | Registry-level delete protection |
| RDAP Server Update Prohibited | Registry-level update protection |

### ASN Items (Autonomous System Number)
| Item | Description |
|------|-------------|
| ASN Full Data | Full ASN lookup response for domain IPs |
| ASN Count | Number of unique ASNs hosting this domain |
| ASN Primary | Primary ASN number |
| ASN Primary Name | Name of primary AS (e.g., "GOOGLE, US") |

### DNS Performance Items
| Item | Description |
|------|-------------|
| DNS Query Latency | Full latency measurement data |
| DNS Query Latency (ms) | DNS resolution time in milliseconds |

### Email Security Items (MTA-STS, TLS-RPT, BIMI)
| Item | Description |
|------|-------------|
| MTA-STS Full Data | Full MTA-STS (RFC 8461) policy record data |
| MTA-STS Configured | Indicates if MTA-STS is configured (1=Yes, 0=No) |
| MTA-STS Policy ID | MTA-STS policy ID (changes when policy is updated) |
| TLS-RPT Full Data | Full TLS-RPT (RFC 8460) record data |
| TLS-RPT Configured | Indicates if TLS-RPT is configured (1=Yes, 0=No) |
| TLS-RPT Reporting URI | Email address for receiving TLS connectivity reports |
| BIMI Full Data | Full BIMI record data |
| BIMI Configured | Indicates if BIMI is configured (1=Yes, 0=No) |
| BIMI Logo URL | BIMI logo URL (SVG image location) |
| Legacy SPF Records Data | Full legacy SPF type 99 detection and RFC 7208 compliance check |
| Legacy SPF Records Found | Indicates if deprecated SPF type 99 records exist (1=Found, 0=Not Found) |
| Legacy SPF Records Count | Number of deprecated SPF type 99 records found |
| Email Security Full Data | Comprehensive email security status (SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI) |
| Email Security Score | Email security score (0-6) counting configured mechanisms |

### DNSSEC Detailed Items (RFC 4033-4035)
| Item | Description |
|------|-------------|
| DNSSEC Detailed Data | Full DNSSEC analysis JSON (DNSKEY, DS, RRSIG, chain validation) |
| DNSSEC DNSKEY Count | Total number of DNSKEY records |
| DNSSEC KSK Count | Key Signing Keys (flag 257) - sign DNSKEY RRsets |
| DNSSEC ZSK Count | Zone Signing Keys (flag 256) - sign zone records |
| DNSSEC Algorithms | Algorithms in use (e.g., RSASHA256, ECDSAP256SHA256, ED25519) |
| DNSSEC DS Record Count | Delegation Signer records at parent zone |
| DNSSEC RRSIG Count | Number of RRSIG signature records |
| DNSSEC RRSIG Nearest Expiry Days | Days until soonest RRSIG expires (negative = expired) |
| DNSSEC Chain Valid | Chain of trust validation status (requires dnspython) |
| DNSSEC Failure Reason | Machine-readable failure reason code (e.g., `missing_dnskey`, `missing_ds`) |
| DNSSEC Failure Description | Human-readable description of why DNSSEC validation failed |
| DNSSEC Algorithm Compliant | RFC 8624 algorithm compliance (1=OK, 0=deprecated algorithms in use) |
| DNSSEC Deprecated Algorithms | List of deprecated/weak algorithms if any |

### RFC 2181 Validation Items
| Item | Description |
|------|-------------|
| RFC 2181 Validation Data | Full RFC 2181 compliance check data |
| RFC 2181 Compliant | Overall compliance status (1=OK, 0=violations found) |
| RFC 2181 CNAME Coexists | Indicates CNAME coexists with other records (1=violation, 0=OK) |

### DANE/TLSA Items (RFC 6698)
| Item | Description |
|------|-------------|
| DANE Full Data | Full DANE check data including TLSA records and validation |
| DANE TLSA Record Count | Number of TLSA records for _443._tcp.domain |
| DANE Valid | TLSA validation passed (1=Valid, 0=Invalid/Not configured) |
| DANE Library Status | Status of crypto libraries (dnspython, cryptography, pyopenssl) |

**Note**: Full DANE certificate validation requires optional dependencies (see below).

### DNSBL/Blacklist Items (RFC 5782)
| Item | Description |
|------|-------------|
| DNSBL Status Data | Full DNSBL check against major blacklist providers |
| DNSBL Clean Status | Indicates if domain IPs are not listed (1=Clean, 0=Listed) |
| DNSBL Total Listings | Count of blacklist listings across all providers |

### Email SRV Records Items (RFC 6186)
| Item | Description |
|------|-------------|
| Email SRV Records Data | Email client autoconfiguration SRV records |
| Email SRV Services Found | Count of email SRV records (IMAP, POP3, Submission, Autodiscover) |

### SSHFP Records Items (RFC 4255)
| Item | Description |
|------|-------------|
| SSHFP Records Data | SSH host key fingerprints published in DNS |
| SSHFP Record Count | Number of SSHFP records for domain |

### DANE for MX Items (RFC 7673)
| Item | Description |
|------|-------------|
| DANE MX Data | DANE TLSA records for MX servers |
| DANE MX Coverage Percent | Percentage of MX servers with DANE protection (0-100%) |

### NS Glue Records Items (RFC 9471)
| Item | Description |
|------|-------------|
| NS Glue Records Data | Glue record validation for in-bailiwick nameservers |
| Glue Records Valid | Indicates proper glue record configuration (1=Valid, 0=Missing) |

### NS Diversity Items (RFC 2182)
| Item | Description |
|------|-------------|
| NS Diversity Data | Nameserver distribution analysis (networks, ASNs, geography) |
| NS Diversity Score | Diversity score (0-100) - higher is better for resilience |
| NS Count | Total number of authoritative nameservers |

## Database Write Optimisations

This template uses advanced Zabbix preprocessing to minimize unnecessary database writes:

### DISCARD_UNCHANGED
Applied to validation and status items that only change when DNS/security configuration is modified:
- DNS A/AAAA Records Valid
- Legacy SPF Records Found/Count
- **Estimated savings**: ~75-90% reduction in writes for DNS validation items

### DISCARD_UNCHANGED_HEARTBEAT
Applied to static domain information with periodic heartbeat updates:
- WHOIS Full Data (12h heartbeat)
- WHOIS Registrar (1d heartbeat)
- RDAP Full Data (12h heartbeat)
- **Purpose**: Ensures critical changes aren't missed while avoiding duplicate writes

### Per-Domain Impact
- **High-frequency validation items**: ~40 fewer writes/day (-83%)
- **Static domain data**: Optimal heartbeat intervals prevent data staleness
- **Per nameserver discovered**: Up to ~694 fewer writes/day with full optimisation
- **Typical domain (3 NS servers)**: ~2,122 fewer database writes per day

## Optional Dependencies

For enhanced DNSSEC and DANE validation, install these Python packages:

| Package | Purpose | Installation |
|---------|---------|--------------|
| `dnspython` | Enhanced DNS operations, DNSSEC chain validation, RRSIG retrieval | `pip install dnspython` |
| `cryptography` | TLSA hash computation, certificate parsing | `pip install cryptography` |
| `pyOpenSSL` | TLS certificate retrieval from servers | `pip install pyOpenSSL` |

Without these packages, the script uses stdlib DNS and provides:
- ✅ TLSA record discovery and syntax validation
- ✅ DNSSEC record enumeration
- ✅ RFC 2181 compliance checks
- ✅ RFC 8624 algorithm compliance checks
- ❌ Limited cryptographic signature verification
- ❌ Limited TLSA-to-certificate matching
- ❌ RRSIG records not visible (EDNS0/DO bit limitation)

## Discovery Rules

### DNS Record Type Discovery
Discovers all DNS record types for the domain and creates:
- **DNS {#RECORD_TYPE} Records Count**: Count of records
- **DNS {#RECORD_TYPE} Records Data**: Record data (JSON)
- **Graph**: DNS {#RECORD_TYPE} Record Count over time

### NS Server Discovery
Discovers all authoritative nameservers and creates:
- **NS Server {#NS_SERVER} Check**: Full check data (master item)
- **NS Server {#NS_SERVER} Available**: Availability status (0/1)
- **NS Server {#NS_SERVER} Latency**: Query latency in milliseconds
- **Trigger**: NS Server Unavailable (HIGH priority)
- **Trigger**: NS Server High Latency (WARNING priority)
- **Graph**: NS Server Latency over time

## Triggers

### Health & Compliance Triggers
| Trigger | Severity | Description |
|---------|----------|-------------|
| DNS Health Score Critical | HIGH | Health score below 50 |
| DNS Health Score Warning | WARNING | Health score below 75 |
| DNS SPF Record Invalid | AVERAGE | SPF record missing or invalid |
| DNS DMARC Record Invalid | AVERAGE | DMARC record missing or invalid |
| DNS DKIM Record Invalid | WARNING | DKIM record missing or invalid |
| DNS DNSSEC Not Enabled | INFO | DNSSEC not enabled |
| DNS NS Records Invalid | HIGH | NS records missing or < 2 |
| DNS SOA Record Invalid | HIGH | SOA record missing or invalid |
| DNS MX Records Invalid | AVERAGE | MX records missing |
| DNS A Records Missing | WARNING | A records missing |
| DNS CAA Records Missing | INFO | CAA records missing |

### DNSSEC Triggers
| Trigger | Severity | Description |
|---------|----------|-------------|
| DNSSEC RRSIG Expiring Soon (7 days) | HIGH | Signatures expire within 7 days - DNSSEC will fail |
| DNSSEC RRSIG Expiring (14 days) | WARNING | Signatures expire within 14 days - plan re-signing |
| DNSSEC Chain Invalid | HIGH | DNSSEC enabled but chain of trust validation failed |
| DNSSEC Broken Chain: DS exists but DNSKEY missing | HIGH | DS record in parent but no DNSKEY - broken DNSSEC |
| DNSSEC Incomplete: DNSKEY exists but DS missing | WARNING | DNSKEY present but no DS in parent - incomplete setup |
| DNSSEC RRSIG Not Visible | INFO | RRSIG not visible (may be EDNS0/DO bit limitation) |
| DNSSEC Missing KSK | HIGH | No Key Signing Key found (flags=257) |
| DNSSEC Missing ZSK | HIGH | No Zone Signing Key found (flags=256) |
| DNSSEC Deprecated Algorithm in use | WARNING | Using weak/deprecated algorithms per RFC 8624 |

### RFC 2181 Triggers
| Trigger | Severity | Description |
|---------|----------|-------------|
| RFC 2181 Violation: CNAME coexists | AVERAGE | CNAME record coexists with other record types |
| RFC 2181 Compliance Failed | WARNING | RFC 2181 DNS specification compliance failed |

### DANE Triggers
| Trigger | Severity | Description |
|---------|----------|-------------|
| DANE TLSA Validation Failed | WARNING | TLSA records exist but don't match server certificate |

### DNS Performance Triggers
| Trigger | Severity | Description |
|---------|----------|-------------|
| DNS Query Latency High | WARNING | DNS resolution time exceeds threshold (default 500ms) |

### Email Security Triggers
| Trigger | Severity | Description |
|---------|----------|-------------|
| MTA-STS Not Configured | INFO | MTA-STS (RFC 8461) not configured |
| TLS-RPT Not Configured | INFO | TLS-RPT (RFC 8460) not configured |
| Legacy SPF Record Type Detected | WARNING | Deprecated SPF type 99 records found - migrate to TXT records (RFC 7208) |
| Email Security Score Low | WARNING | Email security score 2 or lower (missing mechanisms) |

### DNSBL/Blacklist Triggers (RFC 5782)
| Trigger | Severity | Description |
|---------|----------|-------------|
| Domain IP Listed on DNSBL | HIGH | Domain IP listed on one or more blacklists (impacts email deliverability) |

### NS Diversity Triggers (RFC 2182)
| Trigger | Severity | Description |
|---------|----------|-------------|
| NS Diversity Score Low | WARNING | Diversity score below 50 (risk of DNS outages) |
| Insufficient NS Count | AVERAGE | Less than 2 nameservers (single point of failure) |

### Glue Records Triggers (RFC 9471)
| Trigger | Severity | Description |
|---------|----------|-------------|
| Glue Records Missing or Invalid | AVERAGE | Missing glue for in-bailiwick nameservers |

### Domain Security Triggers
| Trigger | Severity | Description |
|---------|----------|-------------|
| Domain Age Under 30 Days | WARNING | Newly registered domain (potential phishing risk) |
| Domain Transfer Lock Disabled | WARNING | Client transfer prohibited not set (vulnerable to hijacking) |

### Domain Expiry Triggers
| Trigger | Severity | Description |
|---------|----------|-------------|
| Domain Expiry Warning | WARNING | Domain expires within 45 days |
| Domain Expiry Notice | INFO | Domain expires within 90 days |

### NS Server Triggers (Discovery)
| Trigger | Severity | Description |
|---------|----------|-------------|
| NS Server {#NS_SERVER} Unavailable | HIGH | Nameserver not responding |
| NS Server {#NS_SERVER} High Latency | WARNING | Latency exceeds threshold |

## Dashboards

The template includes a comprehensive dashboard with:
- **Health Summary**: Gauge widget for health score, check status table, health score trend graph
- **Email Authentication**: SPF, DMARC, DKIM status and errors
- **DNSSEC & Security**: DNSSEC and CAA status
- **Registrar Info**: WHOIS/RDAP data display
- **Active Triggers**: Trigger overview
- **DNS Performance**: DNS query latency gauge, latency trend graph, domain age
- **Email Security**: Email security score gauge, SPF/DKIM/DMARC/MTA-STS/TLS-RPT/BIMI status grid
- **DNSSEC Details**: Key counts (KSK/ZSK), chain validation, RRSIG expiry, algorithms, failure reasons

## Command Line Usage

The external script can be used standalone for testing:

```bash
# Discover DNS record types
python get_domain_health.py discover example.com

# Get specific record type
python get_domain_health.py records example.com A

# Check DNSSEC (basic)
python get_domain_health.py dnssec example.com

# Check DNSSEC (detailed - key types, algorithms, expiry)
python get_domain_health.py dnssec_detailed example.com

# Check DANE/TLSA (default port 443)
python get_domain_health.py dane example.com

# Check DANE/TLSA for specific port
python get_domain_health.py dane example.com 25

# Discover DANE ports
python get_domain_health.py discover_dane example.com

# Check SPF
python get_domain_health.py spf example.com

# Check DMARC
python get_domain_health.py dmarc example.com

# Check DKIM
python get_domain_health.py dkim example.com selector1

# Check CAA
python get_domain_health.py caa example.com

# Get WHOIS data
python get_domain_health.py whois example.com

# Get RDAP data (modern WHOIS)
python get_domain_health.py rdap example.com

# Get ASN information
python get_domain_health.py asn example.com

# Discover NS servers
python get_domain_health.py discover_ns example.com

# Check NS server availability/latency
python get_domain_health.py ns_check example.com ns1.example.com

# RFC 2181 compliance check (CNAME rules, TTL consistency)
python get_domain_health.py rfc2181 example.com

# Check MTA-STS (RFC 8461)
python get_domain_health.py mta_sts example.com

# Check TLS-RPT (RFC 8460)
python get_domain_health.py tls_rpt example.com

# Check BIMI record
python get_domain_health.py bimi example.com

# Check DNS query latency
python get_domain_health.py latency example.com

# Check for deprecated SPF type 99 records (RFC 7208 compliance)
python get_domain_health.py legacy_spf example.com

# Comprehensive email security check (SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI)
python get_domain_health.py email_security example.com

# Check DNSBL/Blacklist status (RFC 5782)
python get_domain_health.py dnsbl example.com

# Check DNSBL for MX server IPs
python get_domain_health.py dnsbl_mx example.com

# Check Email SRV records (RFC 6186)
python get_domain_health.py email_srv example.com

# Check SSHFP records (RFC 4255)
python get_domain_health.py sshfp example.com

# Check DANE for MX servers (RFC 7673)
python get_domain_health.py dane_mx example.com

# Check NS glue records (RFC 9471)
python get_domain_health.py glue example.com

# Check NS diversity (RFC 2182)
python get_domain_health.py ns_diversity example.com

# Check Extended DNS Errors (RFC 8914)
python get_domain_health.py dns_errors example.com

# Check DNS Error Reporting (RFC 9567)
python get_domain_health.py error_reporting example.com

# Check SMIMEA records (RFC 8162)
python get_domain_health.py smimea example.com local_part

# Check OPENPGPKEY records (RFC 7929)
python get_domain_health.py openpgpkey example.com local_part

# Full health check
python get_domain_health.py health example.com

# Self-test
python get_domain_health.py selftest example.com
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DNS_TIMEOUT` | `10` | DNS query timeout in seconds |
| `DNS_NAMESERVER` | *(system resolver)* | DNS nameserver to use |
| `DNS_DEBUG` | `0` | Set to `1` for debug logging |

## Troubleshooting

### No data returned
- Check network connectivity to DNS servers
- Verify the external script is executable
- Check Zabbix server/proxy logs for errors

### WHOIS errors
- Some TLDs may not be supported
- WHOIS servers may rate limit queries
- Network firewalls may block port 43

### RDAP errors
- RDAP server discovery requires HTTPS access to IANA bootstrap
- Some TLDs may not have RDAP servers yet
- Falls back to WHOIS if RDAP unavailable

### ASN lookup issues
- Requires access to Team Cymru DNS services
- May return no data for private/reserved IP ranges

### NS server checks failing
- NS servers may be behind firewalls
- Some NS servers may not respond to external queries
- Check network routing to NS server IPs

### DNSSEC showing disabled
- Many domains do not have DNSSEC enabled
- This is informational, not necessarily an error

## Limitations

### DNSSEC RRSIG Visibility

When using Python's standard library (stdlib) for DNS queries, the script **cannot retrieve RRSIG records attached to other record types**. This is because:

1. **EDNS0 with DO bit required**: DNSSEC-aware responses (including RRSIG records) require the DNS query to set the EDNS0 "DO" (DNSSEC OK) bit
2. **Stdlib limitation**: Python's stdlib `socket` module sends basic DNS queries without EDNS0 extensions
3. **Result**: DNSKEY and DS records are returned (they are standalone record types), but RRSIG attached to A, NS, MX records etc. are not visible

**Impact on validation:**
- `enabled: true` - DNSKEY records found → DNSSEC is configured
- `valid: false` with `failure_reason: rrsig_not_visible` - RRSIG not returned due to query method limitation

**Workaround**: Install `dnspython` library which properly implements EDNS0 with DO bit:
```bash
pip install dnspython
```

When `dnspython` is available, the script automatically uses it for DNSSEC queries and can retrieve RRSIG records.

**Understanding DNSSEC failure reasons:**

| `failure_reason` | Description |
|------------------|-------------|
| `not_configured` | No DNSKEY or DS records found - DNSSEC not enabled |
| `missing_dnskey` | DS record exists in parent zone but no DNSKEY in zone - broken chain |
| `missing_ds` | DNSKEY present but no DS in parent - chain of trust not established |
| `rrsig_not_visible` | Keys and DS present but RRSIG not visible (likely EDNS0/DO limitation) |
| `missing_ksk` | No Key Signing Key (flags=257) found |
| `missing_zsk` | No Zone Signing Key (flags=256) found |
| `deprecated_algorithm` | Using deprecated/weak algorithms per RFC 8624 |

### DKIM Checking
DKIM validation from DNS alone is **limited**. This template checks 20+ common selectors including:
- Generic: `default`, `dkim`, `mail`, `email`, `smtp`, `mta`, `mx`, `s1`, `s2`
- Microsoft 365: `selector1`, `selector2`
- Google Workspace: `google`, `google2`
- Mailchimp: `k1`, `k2`, `k3`, `mandrill`
- Other providers: `cm` (Campaign Monitor), `pm` (Postmark), `amazonses`, `sendgrid`, `smtpapi`

This template can:
- ✅ Check if a DKIM TXT record exists for common selectors
- ✅ Verify record syntax (e.g., `v=DKIM1; k=rsa; p=...`)
- ✅ Confirm a public key is present

This template **cannot**:
- ❌ Verify DKIM signatures (requires actual email with DKIM-Signature header)
- ❌ Test that signing is working (requires email flow)
- ❌ Discover custom selector names (selectors are unpredictable)

**Note**: A "DKIM Record Found" status means a record was found for one of the common selectors. This does not guarantee DKIM is properly configured for all email. Full DKIM validation requires sending test emails and inspecting headers.

## Author

Simon Jackson / @sjackson0109

## Licence

See Licence.md in the repository root.
