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
    $success = $false
    for ($i = 0; $i -lt $Count; $i++) {
        $reply = $ping.Send($Ip, $Timeout, $buffer, $pingOptions)
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
