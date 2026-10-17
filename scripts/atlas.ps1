<#
  Start/stop Code Atlas in Docker (Windows PowerShell 5.1+ or PowerShell 7).
  Run from anywhere:   .\scripts\atlas.ps1 <command>

    start [app|mcp|all]   start the web app and/or the MCP server   (default: all)
    stop                  stop and remove the containers
    restart [app|mcp|all]
    status                what is running, and on which URLs
    logs [app|mcp]        follow logs (Ctrl+C to leave)
    build <path>          scan a project into .\atlas (source is mounted read-only)
    key                   create a random MCP API key in .env if none exists
    mcp-config            print ready-to-paste client settings (contains your key)
    projects              list named projects (each has its own bundle, port and MCP server)
    help

  Add -Project <name> to run an extra, independent MCP server for another codebase next to the
  default one, e.g.   .\scripts\atlas.ps1 build C:\path\to\app -Project myapp
                      .\scripts\atlas.ps1 start -Project myapp
#>
param(
  [Parameter(Position = 0)][string]$Command = "help",
  [Parameter(Position = 1, ValueFromRemainingArguments = $true)][string[]]$Rest,
  [string]$Project
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$placeholder = "replace-with-64-random-hex-characters"

function Need-Docker {
  if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw "Docker is not installed or not on PATH." }
  docker info *> $null
  if ($LASTEXITCODE -ne 0) { throw "Docker is installed but not running. Start Docker Desktop and retry." }
}
function Get-EnvValue([string]$name) {
  if (Test-Path .env) {
    foreach ($l in Get-Content .env) { if ($l -match "^\s*$name\s*=\s*(.+?)\s*$") { return $Matches[1] } }
  }
  return $null
}
function New-Key {
  $b = New-Object byte[] 32
  $rng = [Security.Cryptography.RandomNumberGenerator]::Create(); $rng.GetBytes($b); $rng.Dispose()
  return (($b | ForEach-Object { $_.ToString("x2") }) -join "")
}
function Ensure-Key {
  $k = Get-EnvValue "ATLAS_MCP_API_KEY"
  if ($k -and $k -ne $placeholder -and $k.Length -ge 32) { return $k }
  $k = New-Key
  if (-not (Test-Path .env)) { Copy-Item .env.example .env }
  $lines = @(Get-Content .env)
  $found = $false
  $lines = $lines | ForEach-Object { if ($_ -match "^\s*ATLAS_MCP_API_KEY\s*=") { $found = $true; "ATLAS_MCP_API_KEY=$k" } else { $_ } }
  if (-not $found) { $lines += "ATLAS_MCP_API_KEY=$k" }
  Set-Content -Path .env -Value $lines -Encoding ascii
  Write-Host "Created a new MCP API key in .env (git-ignored)."
  return $k
}
# ---- named projects: -Project <name> runs an independent MCP server next to the default one.
# Same image and API key; its own bundle folder (atlas\<name>), port and containers
# (compose project code-atlas-<name>). The default instance is untouched.
$script:composeProject = @()
$dataRel = "atlas"
function Set-EnvValue([string]$name, [string]$value) {
  if (Test-Path .env) { $lines = @(Get-Content .env) } else { $lines = @(Get-Content .env.example) }
  $found = $false
  $lines = $lines | ForEach-Object { if ($_ -match "^\s*$name\s*=") { $found = $true; "$name=$value" } else { $_ } }
  if (-not $found) { $lines += "$name=$value" }
  Set-Content -Path .env -Value $lines -Encoding ascii
}
function Project-Port([string]$name) {
  $key = "ATLAS_MCP_PORT_" + ($name.ToUpper() -replace '-', '_')
  $v = Get-EnvValue $key; if ($v) { return $v }
  $base = Get-EnvValue "ATLAS_MCP_PORT"; if (-not $base) { $base = "8000" }
  $used = @([int]$base)
  if (Test-Path .env) { foreach ($l in Get-Content .env) { if ($l -match '^\s*ATLAS_MCP_PORT_[A-Z0-9_]+\s*=\s*(\d+)') { $used += [int]$Matches[1] } } }
  $port = ([int]($used | Measure-Object -Maximum).Maximum) + 1
  Set-EnvValue $key "$port"
  return "$port"
}
if ($Project) {
  if ($Project -notmatch '^[a-z0-9][a-z0-9-]{0,30}$') { throw "-Project must be lowercase letters, digits and dashes (for example: myapp)." }
  $script:composeProject = @("-p", "code-atlas-$Project")
  $dataRel = "atlas\$Project"
  $env:ATLAS_DATA_DIR = "./atlas/$Project"
  $env:ATLAS_MCP_PORT = Project-Port $Project
}

# Run `docker compose ...`. Windows PowerShell 5.1 turns ANY stderr output from a native
# command into a terminating error under $ErrorActionPreference = "Stop", and Docker
# writes normal progress to stderr; so run it with errors non-terminating and judge
# success by the exit code only.
function Dc {
  $old = $ErrorActionPreference; $ErrorActionPreference = "Continue"
  try { & docker compose @script:composeProject @args 2>&1 | ForEach-Object { Write-Host "$_" }; $script:dcExit = $LASTEXITCODE }
  finally { $ErrorActionPreference = $old }
  if ($script:dcExit -ne 0) { throw "docker compose failed (exit $script:dcExit)." }
}
# Build the image only when it does not exist yet (the build log is long). After you
# update Code Atlas, run `rebuild`.
function Ensure-Image {
  $old = $ErrorActionPreference; $ErrorActionPreference = "Continue"
  docker image inspect code-atlas:local *> $null; $have = ($LASTEXITCODE -eq 0)
  $ErrorActionPreference = $old
  if (-not $have) { Write-Host "Building the Code Atlas image (first run only; takes a minute or two)..."; Dc build }
}
function Has-Bundle { Test-Path (Join-Path $root "$dataRel\atlas.bundle.json") }
function Port([string]$name, [string]$default) { $v = Get-EnvValue $name; if ($v) { $v } else { $default } }

# MCP port for the selected instance (a named project has its own).
function Mcp-Port { if ($Project) { return $env:ATLAS_MCP_PORT } else { return (Port "ATLAS_MCP_PORT" "8000") } }
$target = if ($Rest -and $Rest.Count -gt 0) { $Rest[0] } else { if ($Project) { "mcp" } else { "all" } }
if ($Project -and $target -ne "mcp" -and $Command.ToLower() -in @("start", "restart")) { throw "A named project runs only the MCP server (use: -Project $Project)." }

switch ($Command.ToLower()) {
  "start" {
    Need-Docker
    $svcs = @()
    if ($target -in @("app", "all")) { $svcs += "app" }
    if ($target -in @("mcp", "all")) {
      if (Has-Bundle) { Ensure-Key | Out-Null; $svcs += "mcp" }
      elseif ($target -eq "mcp") { throw "No bundle yet. Run:  .\scripts\atlas.ps1 build C:\path\to\your\project$(if ($Project) { " -Project $Project" })" }
      else { Write-Host "Skipping the MCP server: no bundle yet. Run '.\scripts\atlas.ps1 build <path>' then 'start mcp'." }
    }
    if ($svcs.Count -eq 0) { throw "Nothing to start (use app, mcp or all)." }
    Ensure-Image
    Dc up -d @svcs
    if ($svcs -contains "app") { Write-Host ("App:  http://127.0.0.1:{0}" -f (Port "ATLAS_APP_PORT" "4173")) }
    if ($svcs -contains "mcp") { Write-Host ("MCP:  http://127.0.0.1:{0}/mcp   (run 'mcp-config' for client settings)" -f (Mcp-Port)) }
  }
  "stop"    { Need-Docker; Dc down }
  "restart" {
    # Recreate, don't `docker compose restart`: restart keeps the OLD image and OLD environment,
    # so a rebuilt image or an edited .env would silently not take effect.
    Need-Docker
    $svcs = @()
    if ($target -in @("app", "all")) { $svcs += "app" }
    if ($target -in @("mcp", "all") -and (Has-Bundle)) { Ensure-Key | Out-Null; $svcs += "mcp" }
    if ($svcs.Count -eq 0) { throw "Nothing to restart (use app, mcp or all; mcp needs a bundle)." }
    Dc up -d --force-recreate @svcs
  }
  "status"  {
    Need-Docker
    Dc ps
    Write-Host ""
    Write-Host ("Bundle: " + $(if (Has-Bundle) { "$dataRel\atlas.bundle.json present" } else { "none (run build <path>)" }))
  }
  "logs"    { Need-Docker; if ($Rest -and $Rest.Count -gt 0) { Dc logs -f --tail 100 $Rest[0] } else { Dc logs -f --tail 100 } }
  "build"   {
    Need-Docker
    if (-not $Rest -or $Rest.Count -eq 0) { throw "Usage: .\scripts\atlas.ps1 build <path-to-project>" }
    $src = (Resolve-Path -LiteralPath $Rest[0]).Path
    New-Item -ItemType Directory -Force -Path (Join-Path $root $dataRel) | Out-Null
    $env:ATLAS_SRC = $src
    # Name the project in the bundle: the -Project name, else the source folder's name.
    $env:ATLAS_LABEL = $(if ($Project) { $Project } else { Split-Path -Leaf $src })
    Dc --profile tools run --rm build
    Write-Host "Bundle written to $dataRel\atlas.bundle.json (viewer: $dataRel\viewer.html)."
  }
  "tunnel-url" {
    # The MCP URL with the key embedded, for clients that cannot send a header (a tunnel client
    # run on THIS machine). Needs ATLAS_ALLOW_URL_KEY=1 in .env. Copied to the clipboard, not printed.
    $k = Ensure-Key
    if ((Get-EnvValue "ATLAS_ALLOW_URL_KEY") -ne "1") {
      throw "URL keys are off. Add ATLAS_ALLOW_URL_KEY=1 to .env, then run: .\scripts\atlas.ps1 restart mcp"
    }
    $u = "http://127.0.0.1:{0}/mcp?key={1}" -f (Mcp-Port), $k
    Set-Clipboard -Value $u
    Write-Host "Copied to the clipboard: http://127.0.0.1:$(Mcp-Port)/mcp?key=<your key>"
    Write-Host "This URL contains your key: use it only in a client running on this machine (see docs/mcp-setup.md)."
  }
  "projects" {
    Need-Docker
    $rows = @([pscustomobject]@{ Project = "(default)"; Port = (Port "ATLAS_MCP_PORT" "8000"); Bundle = (Test-Path (Join-Path $root "atlas\atlas.bundle.json")); Name = "code-atlas-mcp-1" })
    if (Test-Path (Join-Path $root "atlas")) {
      foreach ($d in Get-ChildItem (Join-Path $root "atlas") -Directory) {
        if (-not (Test-Path (Join-Path $d.FullName "atlas.bundle.json"))) { continue }
        $key = "ATLAS_MCP_PORT_" + ($d.Name.ToUpper() -replace '-', '_')
        $pt = Get-EnvValue $key; if (-not $pt) { $pt = "(not started)" }
        $rows += [pscustomobject]@{ Project = $d.Name; Port = $pt; Bundle = $true; Name = "code-atlas-$($d.Name)-mcp-1" }
      }
    }
    $old = $ErrorActionPreference; $ErrorActionPreference = "Continue"
    $running = @(docker ps --format "{{.Names}}" 2>$null); $ErrorActionPreference = $old
    $rows | ForEach-Object { "{0,-16} port {1,-14} bundle: {2,-5} server: {3}" -f $_.Project, $_.Port, $_.Bundle, $(if ($running -contains $_.Name) { "running" } else { "stopped" }) }
  }
  "rebuild" { Need-Docker; Dc build; Write-Host "Image rebuilt. Run 'restart' to use it." }
  "key"     { $k = Ensure-Key; Write-Host "ATLAS_MCP_API_KEY is set in .env ($($k.Length) characters)." }
  "mcp-config" {
    $k = Ensure-Key
    $url = "http://127.0.0.1:{0}/mcp" -f (Mcp-Port)
    $srv = if ($Project) { "atlas-$Project" } else { "code-atlas" }
    Write-Host "URL:    $url"
    Write-Host "Header: Authorization: Bearer $k"
    Write-Host ""
    Write-Host "Claude Code:"
    Write-Host "  claude mcp add --transport http --scope user $srv $url --header `"Authorization: Bearer $k`""
    Write-Host "Generic JSON (clients with url + headers):"
    Write-Host ('  {{ "mcpServers": {{ "{2}": {{ "url": "{0}", "headers": {{ "Authorization": "Bearer {1}" }} }} }} }}' -f $url, $k, $srv)
    Write-Host "More clients: docs/mcp-setup.md"
  }
  default {
    Write-Host @"
Usage: .\scripts\atlas.ps1 <command>

  start [app|mcp|all]    start the web app and/or the MCP server (default: all)
  stop                   stop and remove the containers
  restart [app|mcp|all]
  status                 what is running
  logs [app|mcp]         follow logs (Ctrl+C to leave)
  build <path>           scan a project into .\atlas (source mounted read-only)
  rebuild                rebuild the image after updating Code Atlas
  key                    create a random MCP API key in .env if none exists
  mcp-config             print ready-to-paste client settings (contains your key)
  tunnel-url             copy the MCP URL with the key embedded (needs ATLAS_ALLOW_URL_KEY=1)
  projects               list named projects: bundle, port, running or stopped

Add -Project <name> to start/stop/restart/status/logs/build/mcp-config to work with an independent
MCP server for another codebase (own bundle folder atlas\<name>, own port, same image and key):
  .\scripts\atlas.ps1 build C:\path\to\app -Project myapp
  .\scripts\atlas.ps1 start -Project myapp
"@
  }
}
