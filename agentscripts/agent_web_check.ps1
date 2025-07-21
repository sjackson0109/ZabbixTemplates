"""
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
"""
param (
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Url,

    [ValidateSet('GET','HEAD','POST','PUT','DELETE','OPTIONS','TRACE','PATCH')]
    [string]$Method = 'HEAD',

    [int]$Timeout        = 30,     # Total request timeout, in seconds
    [switch]$AllowInvalidCert,     # Bypass SSL certificate errors

    [switch]$FollowRedirect,       # Whether to follow 3xx redirects
    [int]$MaxRedirects    = 5,     # Maximum number of automatic redirects

    [hashtable]$Headers,           # Custom request headers, as a name/value map

    [string]$Body,                 # Request body (for POST, PUT, etc)
    [string]$ContentType    = 'application/json',  # MIME type for the body

    [int]    $MinStatusCode = 200,  # Lower bound of “acceptable” status
    [int]    $MaxStatusCode = 599,  # Upper bound of “acceptable” status
    [int[]]  $ExcludeStatusCodes = @(502,503,504)  # Specific codes to treat as failure
)

# --- Initialise handler and client ---
$handler = [System.Net.Http.HttpClientHandler]::new()
$handler.AllowAutoRedirect = $FollowRedirect.IsPresent
$handler.MaxAutomaticRedirections = $MaxRedirects
if ($AllowInvalidCert.IsPresent) {
    # Globally accept any cert
    $handler.ServerCertificateCustomValidationCallback = { return $true }
}

$client = [System.Net.Http.HttpClient]::new($handler)
$client.Timeout = [System.TimeSpan]::FromSeconds($Timeout)

# --- Apply custom headers if provided ---
if ($Headers) {
    foreach ($name in $Headers.Keys) {
        # Remove any pre‑existing header of the same name
        if ($client.DefaultRequestHeaders.Contains($name)) {
            $client.DefaultRequestHeaders.Remove($name)
        }
        $client.DefaultRequestHeaders.Add($name, $Headers[$name])
    }
}

# --- Build the request message ---
$request = [System.Net.Http.HttpRequestMessage]::new($Method, $Url)
if ($Body) {
    $request.Content = [System.Net.Http.StringContent]::new(
        $Body,
        [System.Text.Encoding]::UTF8,
        $ContentType
    )
}

# --- Send synchronously and capture status code ---
try {
    $response   = $client.SendAsync($request).Result
    $statusCode = [int]$response.StatusCode
}
catch {
    # Network failure, DNS error, timeout etc
    Write-Output 0
    return
}
finally {
    # Clean up disposable objects
    if ($response) { $response.Dispose() }
    $client.Dispose()
}

# --- Determine success or failure ---
if (($statusCode -ge $MinStatusCode) -and
    ($statusCode -le $MaxStatusCode) -and
    ($statusCode -notin $ExcludeStatusCodes)) {
    Write-Output 1
}
else {
    Write-Output 0
}
