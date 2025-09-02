<#
Author: Simon Jackson (@sjackson0109)
Created: 2025/07/21
Version: 1.0
Description:
    - Perform HTTP/S checks on a URL from the Zabbix Agent
    - Returns the average round-trip time of pings to the specified IP address 
    - Supports custom parameters for HTTP method, timeout, headers, body, and status code validation

Instructions:
    - Place this script in the Zabbix Agent scripts directory
    - Ensure the script is executable by the Zabbix user
    - Configure the Zabbix Agent to allow remote commands if necessary
#>
param(
    [string]$Url,
    [int]$Timeout = 5000,
    [int]$ExpectCode = 200,
    [string]$ExpectContent = "",
    [string]$Username = "",
    [string]$Password = "",
    [string]$Headers = ""
)

$result = @{ available = 0; time_ms = -1; status = 0; content_match = 0 }
try {
    $handler = New-Object System.Net.Http.HttpClientHandler
    $client = New-Object System.Net.Http.HttpClient($handler)
    $client.Timeout = [System.TimeSpan]::FromMilliseconds($Timeout)

    # Basic Auth
    if ($Username -and $Password) {
        $pair = "$Username:$Password"
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($pair)
        $base64 = [Convert]::ToBase64String($bytes)
        $client.DefaultRequestHeaders.Authorization = "Basic $base64"
    }

    # Custom Headers
    if ($Headers) {
        try {
            $headerObj = $null
            if ($Headers.Trim().StartsWith('{')) {
                $headerObj = $Headers | ConvertFrom-Json
            } else {
                $headerObj = @{}
                foreach ($kv in $Headers -split ';') {
                    if ($kv -match '=') {
                        $k,$v = $kv -split '=',2
                        $headerObj[$k.Trim()] = $v.Trim()
                    }
                }
            }
            foreach ($name in $headerObj.Keys) {
                $client.DefaultRequestHeaders.Add($name, $headerObj[$name])
            }
        } catch {}
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $response = $client.GetAsync($Url).Result
    $sw.Stop()
    $result.time_ms = [math]::Round($sw.Elapsed.TotalMilliseconds,2)
    $result.status = [int]$response.StatusCode
    $body = $response.Content.ReadAsStringAsync().Result
    if ($result.status -eq $ExpectCode) {
        $result.available = 1
    }
    if ($ExpectContent) {
        if ($body -match $ExpectContent) {
            $result.content_match = 1
        }
    } else {
        $result.content_match = 1
    }
} catch {
    $result.available = 0
    $result.time_ms = -1
    $result.status = 0
    $result.content_match = 0
}
Write-Output ($result | ConvertTo-Json -Compress)