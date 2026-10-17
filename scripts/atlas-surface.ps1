<#
  Pair the routes found in a project's code with the endpoints SurfaceTrace has observed, and write a worklist.
  READ-ONLY on both sides: it makes one GET to SurfaceTrace's campaign index on loopback and runs a report in a
  container; nothing is replayed, sent to the target, or changed in SurfaceTrace. Testing stays in SurfaceTrace,
  with its scope, preview and approval gates.

    .\scripts\atlas-surface.ps1 -Project surfacetrace
    .\scripts\atlas-surface.ps1 -Project myapp -AppHost app.example.test
    .\scripts\atlas-surface.ps1 -Project myapp -Campaign C:\path\to\saved-campaign-index.json

  -Project   a named project built with scripts\atlas.ps1 build ... -Project <name> (omit for the default bundle)
  -Campaign  SurfaceTrace's index URL (default http://127.0.0.1:5173/api/campaign/index; loopback only) or a saved JSON file
  -AppHost   only endpoints observed on this host
  Output:    atlas\<project>\worklist.md  and  campaign.json (a copy of the observed traffic: private, git-ignored)
#>
param(
  [string]$Project,
  [string]$Campaign = "http://127.0.0.1:5173/api/campaign/index",
  [string]$AppHost
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if ($Project -and $Project -notmatch '^[a-z0-9][a-z0-9-]{0,24}$') { throw "-Project must be lowercase letters, digits and dashes." }
$dir = if ($Project) { Join-Path $root "atlas\$Project" } else { Join-Path $root "atlas" }
if (-not (Test-Path (Join-Path $dir "atlas.bundle.json"))) { throw "No bundle at $dir. Build one first: .\scripts\atlas.ps1 build <path>$(if ($Project) { " -Project $Project" })" }

$campaignFile = Join-Path $dir "campaign.json"
if ($Campaign -match '^https?://') {
  $u = [Uri]$Campaign
  if ($u.Host -notin @("127.0.0.1", "localhost", "[::1]")) { throw "Only a loopback URL is read. Save the JSON to a file for anything else." }
  Write-Host "Reading $Campaign ..."
  Invoke-WebRequest -UseBasicParsing -Uri $u -TimeoutSec 120 -OutFile $campaignFile
} else {
  Copy-Item -LiteralPath (Resolve-Path -LiteralPath $Campaign).Path -Destination $campaignFile -Force
}

$args2 = @("run", "--rm", "--read-only", "--tmpfs", "/tmp", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
  "-v", "${dir}:/data", "code-atlas:local", "correlate", "/data", "--campaign", "/data/campaign.json", "-o", "/data/worklist.md")
if ($AppHost) { $args2 += @("--host", $AppHost) }
$old = $ErrorActionPreference; $ErrorActionPreference = "Continue"
try { $out = & docker @args2 2>&1; $code = $LASTEXITCODE } finally { $ErrorActionPreference = $old }
if ($code -ne 0) { throw ("correlate failed: " + (($out | Select-Object -Last 5) -join " | ")) }

$report = Join-Path $dir "worklist.md"
$head = Get-Content -LiteralPath $report -TotalCount 3
$head | ForEach-Object { Write-Host $_ }
Write-Host "`nWorklist: $report"
Write-Host "Read its 'Read this first' section: pairs are by path shape, not proof."
