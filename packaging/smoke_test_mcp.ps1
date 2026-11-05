param(
    [Parameter(Mandatory)][string]$Executable,
    [Parameter(Mandatory)][string]$WorkRoot
)

$ErrorActionPreference = "Stop"
$Executable = (Resolve-Path -LiteralPath $Executable).Path
$smokeRoot = Join-Path $WorkRoot "mcp-smoke"
$appData = Join-Path $smokeRoot "localappdata"
$configDir = Join-Path $appData "SyslogMonitor"
New-Item -ItemType Directory -Force $configDir | Out-Null

$portProbe = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
$portProbe.Start()
$port = ([System.Net.IPEndPoint]$portProbe.LocalEndpoint).Port
$portProbe.Stop()
[System.IO.File]::WriteAllText(
    (Join-Path $configDir "settings.json"),
    "{`"autostart_listener`":false,`"mcp_port`":$port}",
    [System.Text.UTF8Encoding]::new($false)
)

$oldLocalAppData = $env:LOCALAPPDATA
$oldQtPlatform = $env:QT_QPA_PLATFORM
$env:LOCALAPPDATA = $appData
$env:QT_QPA_PLATFORM = "offscreen"
$process = $null
$client = [System.Net.Http.HttpClient]::new()
$content = $null
$response = $null
try {
    $process = Start-Process -FilePath $Executable -PassThru
    $client.Timeout = [TimeSpan]::FromSeconds(2)
    $client.DefaultRequestHeaders.Accept.Add(
        [System.Net.Http.Headers.MediaTypeWithQualityHeaderValue]::new("application/json")
    )
    $client.DefaultRequestHeaders.Accept.Add(
        [System.Net.Http.Headers.MediaTypeWithQualityHeaderValue]::new("text/event-stream")
    )
    $payload = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"release-smoke-test","version":"1.0"}}}'
    $content = [System.Net.Http.StringContent]::new(
        $payload, [System.Text.Encoding]::UTF8, "application/json"
    )

    $lastError = "No response from the packaged MCP server."
    for ($attempt = 0; $attempt -lt 80; $attempt++) {
        if ($process.HasExited) {
            throw "Packaged application exited with code $($process.ExitCode)."
        }
        try {
            $response = $client.PostAsync("http://127.0.0.1:$port/mcp", $content).GetAwaiter().GetResult()
            $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            if (-not $response.IsSuccessStatusCode) {
                throw "MCP initialization failed: HTTP $([int]$response.StatusCode): $body"
            }
            if (-not $body.Contains('"protocolVersion":"2025-06-18"')) {
                throw "MCP initialization returned an unexpected response: $body"
            }
            Write-Host "Packaged MCP server responded successfully on port $port."
            return
        } catch [System.Net.Http.HttpRequestException] {
            $lastError = $_.Exception.Message
            Start-Sleep -Milliseconds 250
        } catch [System.Threading.Tasks.TaskCanceledException] {
            $lastError = $_.Exception.Message
            Start-Sleep -Milliseconds 250
        }
    }
    throw "Packaged MCP server did not start: $lastError"
} finally {
    if ($response) {
        $response.Dispose()
    }
    if ($content) {
        $content.Dispose()
    }
    $client.Dispose()
    if ($process -and -not $process.HasExited) {
        Stop-Process -Id $process.Id -Force
    }
    $env:LOCALAPPDATA = $oldLocalAppData
    $env:QT_QPA_PLATFORM = $oldQtPlatform
}
