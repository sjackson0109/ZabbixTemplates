<#
Author: Simon Jackson (@sjackson0109)
Created: 2025/07/21
Version: 1.0
Description:
    - Perform PING checks on an IP address from the Zabbix Agent
    - Returns the average round-trip time of pings to the specified IP address 
    - Supports custom parameters for ping count, timeout, buffer size, TTL, and fragmentation
    - Returns a single line numeric value: average latency in ms, or -1 on failure
    
Instructions:
    - Place this script in the Zabbix Agent scripts directory
    - Ensure the script is executable by the Zabbix user
    - Configure the Zabbix Agent to allow remote commands if necessary
#>


# Support both direct named parameters and a single string argument (for Zabbix bracketed key usage)
param(
    [string]$ScriptName,
    [string]$Target,
    [int]$Count,
    [int]$Timeout,
    [int]$BufferSize,
    [int]$TimeToLive,
    [string]$DontFragment,
    [string]$Mode,
    [Parameter(ValueFromRemainingArguments=$true)][string[]]$ExtraArgs
)

# If only one argument is passed and it looks like a single string, parse it
if ($args.Count -eq 1 -and $args[0] -is [string] -and $args[0] -match "^-ScriptName ") {
    $pattern = '((?:"[^"]*")|(?:\S+))'
    $splitArgs = @()
    foreach ($match in [regex]::Matches($args[0], $pattern)) {
        $splitArgs += $match.Value.Trim('"')
    }
    $psBound = @{}
    for ($i = 0; $i -lt $splitArgs.Count; $i += 2) {
        $key = $splitArgs[$i].TrimStart('-')
        $val = $splitArgs[$i+1]
        $psBound[$key] = $val
    }
    $ScriptName   = $psBound['ScriptName']
    $Target       = $psBound['Target']
    $Count        = [int]$psBound['Count']
    $Timeout      = [int]$psBound['Timeout']
    $BufferSize   = [int]$psBound['BufferSize']
    $TimeToLive   = [int]$psBound['TimeToLive']
    $DontFragment = $psBound['DontFragment']
    $Mode         = $psBound['Mode']
}

try {
    if (-not $Target)      { Write-Output '{"status":"fail","available":0}'; exit }
    if (-not $Count -or $Count -le 0)      { $Count = 3 }
    if (-not $Timeout -or $Timeout -le 0)  { $Timeout = 1000 }
    if (-not $BufferSize -or $BufferSize -le 0) { $BufferSize = 32 }
    if (-not $TimeToLive -or $TimeToLive -le 0) { $TimeToLive = 64 }
    if ($DontFragment -eq $null) { $DontFragment = '0' }
} catch {
    Write-Output '{"status":"fail","available":0}'; exit
}

# Ensure absolutely quiet behaviour
$ErrorActionPreference = 'SilentlyContinue'
$WarningPreference     = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'

try {
    $buffer = New-Object byte[] $BufferSize
    for ($i = 0; $i -lt $buffer.Length; $i++) { $buffer[$i] = 0x61 }
} catch {
    Write-Output '{"status":"fail","available":0}'; exit
}

# Prepare ping options

$pingOptions = [System.Net.NetworkInformation.PingOptions]::new()
$pingOptions.Ttl          = [Math]::Max(1, $TimeToLive)
$pingOptions.DontFragment = ($DontFragment -eq '1')


$ping   = [System.Net.NetworkInformation.Ping]::new()
$times  = New-Object System.Collections.Generic.List[double]

try {
    for ($i = 0; $i -lt [Math]::Max(1, $Count); $i++) {
        $reply = $ping.Send($Target, [Math]::Max(1, $Timeout), $buffer, $pingOptions)
        if ($null -ne $reply -and $reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
            $times.Add([double]$reply.RoundtripTime) | Out-Null
        }
    }
} catch {
    Write-Output '{"status":"fail","available":0}'; exit
} finally {
    if ($ping) { $ping.Dispose() }
}

# Emit exactly one line to STDOUT, JSON with latency and availability
if ($times.Count -eq 0) {
    $result = @{ status = "fail"; target = $Target; available = 0 }
    Write-Output ($result | ConvertTo-Json -Compress)
} else {
    $avg = ($times | Measure-Object -Average).Average
    $min = ($times | Measure-Object -Minimum).Minimum
    $max = ($times | Measure-Object -Maximum).Maximum
    $value = [Math]::Round([double]$avg, 2, [System.MidpointRounding]::AwayFromZero)
    $result = @{
        status = "success"
        target = $Target
        averageTime = $value
        minTime = $min
        maxTime = $max
        successCount = $times.Count
        failCount = [Math]::Max(0, $Count - $times.Count)
        available = 1
    }
    Write-Output ($result | ConvertTo-Json -Compress)
}
