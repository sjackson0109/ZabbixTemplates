<#
Agent Ping Check (Boolean)
Author: Simon Jackson (@sjackson0109)
Version: 1.1
Description:
    - Performs ICMP ping checks to a target IP address.
    - Returns 1 if at least one ping reply is received, otherwise 0.
    - Designed for Zabbix Agent 2 UserParameter integration as a boolean availability check.

Usage (Zabbix UserParameter):
    UserParameter=custom.ping.bool[*],powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\Zabbix Agent 2\Scripts\agent_ping_check_bool.ps1" -Target "$1" -Count "$2" -Timeout "$3" -BufferSize "$4" -TimeToLive "$5" -DontFragment "$6"

Parameters:
    -Target       : Target IP address to ping (string)
    -Count        : Number of echo requests to send (int)
    -Timeout      : Timeout per request in ms (int)
    -BufferSize   : Size of payload in bytes (int)
    -TimeToLive   : TTL value (int)
    -DontFragment : Set to '1' to enable 'do not fragment' (string, '1' or '0')

Returns:
    1 if reachable, 0 if unreachable or error
#>
<#
Author: Simon Jackson (@sjackson0109)
Created: 2025/07/21
Version: 1.2
Description:
    - Perform PING checks on a Target(FQDN/IP-Address) from the Zabbix Agent
    - Returns the average round-trip time of pings to the specified Target
    - Supports custom parameters for ping count, timeout, buffer size, TTL, and fragmentation
    - Returns a single line numeric value: average latency in ms, or -1 on failure
    
Instructions:
    - Place this script in the Zabbix Agent scripts directory
    - Ensure the script is executable by the Zabbix user
    - Configure the Zabbix Agent to allow remote commands if necessary
#>
param(
    [Parameter(Mandatory=$true)][string]$Target,
    [Parameter(Mandatory=$true)][int]$Count,
    [Parameter(Mandatory=$true)][int]$Timeout,
    [Parameter(Mandatory=$true)][int]$BufferSize,
    [Parameter(Mandatory=$true)][int]$TimeToLive,
    [Parameter(Mandatory=$true)][string]$DontFragment
)

try {
    $pingOptions = New-Object System.Net.NetworkInformation.PingOptions
    $pingOptions.Ttl = $TimeToLive
    $pingOptions.DontFragment = ($DontFragment -eq '1')
    $buffer = New-Object byte[] $BufferSize
    $ping = New-Object System.Net.NetworkInformation.Ping
    $success = $false
    for ($i = 0; $i -lt $Count; $i++) {
        $reply = $ping.Send($Target, $Timeout, $buffer, $pingOptions)
        if ($reply.Status -eq 'Success') {
            $success = $true
            break
        }
    }
    if ($success) {
        1
    } else {
        0
    }
} catch {
    0
}
