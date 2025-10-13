# zabbix_ping_wrapper.ps1
# This script splits a single string of arguments and calls the real ping check script with them as named parameters
param(
    [string]$AllArgs
)

# Split the string into an array, preserving quoted substrings
$splitArgs = @()
$pattern = '((?:"[^"]*")|(?:\S+))'
foreach ($match in [regex]::Matches($AllArgs, $pattern)) {
    $arg = $match.Value.Trim('"')
    $splitArgs += $arg
}

# Call the real script with splatted arguments
& 'C:\Program Files\Zabbix Agent 2\Scripts\agent_ping_check.ps1' @splitArgs
