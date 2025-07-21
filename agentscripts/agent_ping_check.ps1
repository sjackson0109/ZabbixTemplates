"""
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
"""
param (
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Ip,

    [Parameter(Mandatory = $false)]
    [int]$Count = 4,

    [Parameter(Mandatory = $false)]
    [int]$Timeout = 1000,

    [Parameter(Mandatory = $false)]
    [int]$BufferSize = 32,

    [Parameter(Mandatory = $false)]
    [int]$TimeToLive = 128,

    [Parameter(Mandatory = $false)]
    [switch]$DontFragment
)

# Initialise Ping sender and options
$pingSender = [System.Net.NetworkInformation.Ping]::new()
$pingOptions = [System.Net.NetworkInformation.PingOptions]::new($TimeToLive, $DontFragment.IsPresent)

# Prepare buffer of the requested size (filled with ASCII 'a')
$buffer = [Text.Encoding]::ASCII.GetBytes(('a' * $BufferSize))

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
