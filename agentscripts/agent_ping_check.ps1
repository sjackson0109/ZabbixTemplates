<#
Author: Simon Jackson (@sjackson0109)
Created: 2025/07/21
Version: 1.0
Description:
    - Perform PING checks on an IP address from the Zabbix Agent
    - Returns the average round-trip time of pings to the specified IP address 
    - Supports custom parameters for ping count, timeout, buffer size, TTL, and fragmentation

Instructions:
    - Place this script in the Zabbix Agent scripts directory
    - Ensure the script is executable by the Zabbix user
    - Configure the Zabbix Agent to allow remote commands if necessary
#>
param(
    [Parameter(Mandatory=$true)][string]$Ip,
    [Parameter(Mandatory=$true)][int]$Count,
    [Parameter(Mandatory=$true)][int]$Timeout,
    [Parameter(Mandatory=$true)][int]$BufferSize,
    [Parameter(Mandatory=$true)][int]$TimeToLive,
    [Parameter(Mandatory=$true)][int]$DontFragment
)

try {
    $pingOptions = New-Object System.Net.NetworkInformation.PingOptions
    $pingOptions.Ttl = $TimeToLive
    $pingOptions.DontFragment = [bool]$DontFragment
    $buffer = New-Object byte[] $BufferSize
    $ping = New-Object System.Net.NetworkInformation.Ping
    $results = @()
    for ($i = 0; $i -lt $Count; $i++) {
        $reply = $ping.Send($Ip, $Timeout, $buffer, $pingOptions)
        if ($reply.Status -eq 'Success') {
            $results += $reply.RoundtripTime
        }
    }
    if ($results.Count -gt 0) {
        [math]::Round(($results | Measure-Object -Average).Average, 2)
    } else {
        -1
    }
} catch {
    -1
}

# Collect successful round‑trip times
$times = [System.Collections.Generic.List[long]]::new()

for ($i = 1; $i -le $Count; $i++) {
    try {
        $reply = $pingSender.Send($Ip, $Timeout, $buffer, $pingOptions)
        if ($reply.Status -eq 'Success') {
            [void]$times.Add($reply.RoundtripTime)
        }
    }
    catch {
        # Suppress any exceptions (DNS failures etc)
    }
}

# Output result
if ($times.Count -eq 0) {
    # No successful pings
    Write-Output -1
}
else {
    # Compute and output the average, to two decimal places
    $avg = ($times | Measure-Object -Average).Average
    Write-Output ([math]::Round($avg, 2))
}