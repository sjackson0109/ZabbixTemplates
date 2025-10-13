# PowerShell script to discover all .ps1 files in the agentscripts directory and output JSON for Zabbix LLD
$scriptDir = "C:\Program Files\Zabbix Agent 2\Scripts"
$files = Get-ChildItem -Path $scriptDir -Filter *.ps1 -Name

$discovery = @()
foreach ($file in $files) {
    $discovery += @{ "{#SCRIPT.NAME}" = $file }
}

$result = @{ "data" = $discovery }
$result | ConvertTo-Json -Compress
