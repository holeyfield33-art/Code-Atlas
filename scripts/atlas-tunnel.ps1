<#
  Connect ChatGPT to your local Code Atlas MCP server through OpenAI's Secure MCP Tunnel
  (`tunnel-client`). Windows PowerShell 5.1+ or PowerShell 7.

    .\scripts\atlas-tunnel.ps1 install                       download + checksum-verify tunnel-client
    .\scripts\atlas-tunnel.ps1 setup -TunnelId tunnel_...    create the profile (remembers the id)
    .\scripts\atlas-tunnel.ps1 doctor                        check everything (asks for the runtime key)
    .\scripts\atlas-tunnel.ps1 run                           start the tunnel; leave it running

  You supply two values from OpenAI Platform (see docs/mcp-setup.md, "ChatGPT"):
    - the tunnel id        (Tunnels management)   -> `setup -TunnelId`, then remembered in .env
    - a RUNTIME API key    (Runtime API keys)     -> typed at a hidden prompt, or set CONTROL_PLANE_API_KEY.
                                                     It is never written to disk by this script.
  The profile file DOES contain your Atlas MCP key (it is in the URL the tunnel forwards to).
  Keep it on this machine; do not share or commit it.
#>
param(
  [Parameter(Position = 0)][string]$Command = "help",
  [string]$TunnelId,
  [string]$ProfileDir,          # override (tests); default is tunnel-client's own profile directory
  [switch]$NoSave               # do not record the tunnel id in .env (tests)
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$Version = "v0.0.16"
$Profile = "code-atlas"
$HealthAddr = "127.0.0.1:18080"
$installDir = Join-Path $env:LOCALAPPDATA "code-atlas\tunnel-client"

function Get-EnvValue([string]$name) {
  if (Test-Path .env) { foreach ($l in Get-Content .env) { if ($l -match "^\s*$name\s*=\s*(.+?)\s*$") { return $Matches[1] } } }
  return $null
}
function Set-EnvValue([string]$name, [string]$value) {
  $lines = @(); if (Test-Path .env) { $lines = @(Get-Content .env) }
  $found = $false
  $lines = $lines | ForEach-Object { if ($_ -match "^\s*$name\s*=") { $found = $true; "$name=$value" } else { $_ } }
  if (-not $found) { $lines += "$name=$value" }
  Set-Content -Path .env -Value $lines -Encoding ascii
}
function Find-Client {
  if ($env:ATLAS_TUNNEL_CLIENT -and (Test-Path $env:ATLAS_TUNNEL_CLIENT)) { return $env:ATLAS_TUNNEL_CLIENT }
  $p = Join-Path $installDir "tunnel-client.exe"; if (Test-Path $p) { return $p }
  $c = Get-Command tunnel-client -ErrorAction SilentlyContinue; if ($c) { return $c.Source }
  throw "tunnel-client is not installed. Run: .\scripts\atlas-tunnel.ps1 install"
}
function Install-Client {
  New-Item -ItemType Directory -Force $installDir | Out-Null
  $zip = "tunnel-client-$Version-windows-amd64.zip"
  $base = "https://github.com/openai/tunnel-client/releases/download/$Version"
  $zipPath = Join-Path $installDir $zip; $sumPath = Join-Path $installDir "SHA256SUMS.txt"
  Write-Host "Downloading $zip ..."
  Invoke-WebRequest "$base/$zip" -OutFile $zipPath -UseBasicParsing
  Invoke-WebRequest "$base/SHA256SUMS.txt" -OutFile $sumPath -UseBasicParsing
  $line = Get-Content $sumPath | Where-Object { $_ -match [regex]::Escape($zip) } | Select-Object -First 1
  if (-not $line) { throw "No checksum listed for $zip in SHA256SUMS.txt." }
  $expected = ($line -split '\s+')[0].ToLower()
  $actual = (Get-FileHash $zipPath -Algorithm SHA256).Hash.ToLower()
  if ($expected -ne $actual) { Remove-Item $zipPath -Force; throw "Checksum mismatch (expected $expected, got $actual). Download discarded." }
  Expand-Archive -LiteralPath $zipPath -DestinationPath $installDir -Force
  Write-Host "Installed and checksum-verified: $(Join-Path $installDir 'tunnel-client.exe')"
}
function Atlas-Url {
  $key = Get-EnvValue "ATLAS_MCP_API_KEY"
  if (-not $key -or $key.Length -lt 32) { throw "No ATLAS_MCP_API_KEY in .env. Run: .\scripts\atlas.ps1 key" }
  if ((Get-EnvValue "ATLAS_ALLOW_URL_KEY") -ne "1") { throw "URL keys are off. Add ATLAS_ALLOW_URL_KEY=1 to .env and run: .\scripts\atlas.ps1 restart mcp" }
  $port = Get-EnvValue "ATLAS_MCP_PORT"; if (-not $port) { $port = "8000" }
  return "http://127.0.0.1:$port/mcp?key=$key"
}
function Test-Atlas([string]$url) {
  # GET on the MCP endpoint with a valid key answers 405 (POST only); a bad key would be 401.
  try { $r = Invoke-WebRequest $url -UseBasicParsing -ErrorAction Stop; $code = [int]$r.StatusCode }
  catch { if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode } else { throw "The Atlas MCP server is not reachable. Run: .\scripts\atlas.ps1 start mcp" } }
  if ($code -eq 405) { return }
  if ($code -eq 401 -or $code -eq 404) { throw "The Atlas MCP server rejected the URL key (HTTP $code). Check ATLAS_ALLOW_URL_KEY=1 in .env, then: .\scripts\atlas.ps1 restart mcp" }
  throw "Unexpected answer from the Atlas MCP server (HTTP $code)."
}
function Need-RuntimeKey {
  if ($env:CONTROL_PLANE_API_KEY) { return }
  $s = Read-Host "OpenAI RUNTIME API key (input hidden; kept in this process only)" -AsSecureString
  $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s)
  try { $env:CONTROL_PLANE_API_KEY = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
  if (-not $env:CONTROL_PLANE_API_KEY) { throw "No runtime API key entered." }
}
function Client-Args { if ($ProfileDir) { return @("--profile-dir", $ProfileDir) } else { return @() } }

switch ($Command.ToLower()) {
  "install" { Install-Client }
  "setup" {
    $exe = Find-Client
    if (-not $TunnelId) { $TunnelId = Get-EnvValue "ATLAS_TUNNEL_ID" }
    if (-not $TunnelId) { $TunnelId = $env:CONTROL_PLANE_TUNNEL_ID }
    if (-not $TunnelId -or $TunnelId -notmatch '^tunnel_[0-9a-f]{32}$') {
      throw "Pass your tunnel id: .\scripts\atlas-tunnel.ps1 setup -TunnelId tunnel_<32 hex characters>  (OpenAI Platform > Tunnels)"
    }
    $url = Atlas-Url; Test-Atlas $url
    $env:CONTROL_PLANE_API_KEY = $(if ($env:CONTROL_PLANE_API_KEY) { $env:CONTROL_PLANE_API_KEY } else { "unset-until-run" })  # init only records the env: reference
    & $exe init --sample sample_mcp_remote_no_auth --profile $Profile --tunnel-id $TunnelId --mcp-server-url $url --health-listen-addr $HealthAddr --force @(Client-Args) 2>&1 | ForEach-Object { "$_" -replace 'key=[0-9a-f]{64}','key=<hidden>' } | Select-Object -First 3
    if (-not $NoSave) { Set-EnvValue "ATLAS_TUNNEL_ID" $TunnelId }
    Write-Host ""
    Write-Host "Profile '$Profile' is ready. Next: .\scripts\atlas-tunnel.ps1 doctor   then   .\scripts\atlas-tunnel.ps1 run"
  }
  "doctor" {
    $exe = Find-Client; Test-Atlas (Atlas-Url); Need-RuntimeKey
    & $exe doctor --profile $Profile --explain @(Client-Args) 2>&1 | ForEach-Object { "$_" -replace 'key=[0-9a-f]{64}','key=<hidden>' }
  }
  "run" {
    $exe = Find-Client; Test-Atlas (Atlas-Url); Need-RuntimeKey
    Write-Host "Starting the tunnel. Leave this window open; Ctrl+C stops it. Local admin UI: http://$HealthAddr/ui"
    Write-Host "Create/verify the connector in ChatGPT only while this is running: https://chatgpt.com/#settings/Connectors"
    & $exe run --profile $Profile @(Client-Args)
  }
  default {
    Write-Host @"
Usage: .\scripts\atlas-tunnel.ps1 <command> [-TunnelId tunnel_...]

  install                      download and checksum-verify tunnel-client $Version
  setup -TunnelId tunnel_...   create the '$Profile' profile (id is remembered in .env)
  doctor                       run tunnel-client's checks (prompts for the runtime key)
  run                          start the tunnel in this window; leave it running

You need: a tunnel id and a RUNTIME API key from OpenAI Platform. See docs/mcp-setup.md.
"@
  }
}
