<#
  Split a repository too large for one bundle into shards and build each as its own named
  project (Windows PowerShell 5.1+ or PowerShell 7). Each shard is a bundle of up to -MaxFiles files,
  made from a group of folders, so every file of the repo lands in exactly one shard.

    .\scripts\atlas-shard.ps1 plan  -Source <path>                 show the split; builds nothing
    .\scripts\atlas-shard.ps1 build -Source <path> -Name gdk       build every shard -> atlas\gdk-01, gdk-02, ...
    .\scripts\atlas-shard.ps1 build -Source <path> -Name gdk -Only 2,5      only those shards

    -Source     a Windows folder, or a Linux path inside WSL (starts with "/", e.g. /home/me/gdk/gitlab);
                Docker then runs through WSL so the source is read in place
    -MaxFiles   files per shard (default 3000; a 2,000-file bundle is ~66 MB)
    -Skip       folders to leave out (comma-separated; default: test folders). A bare name matches at any depth,
                a path with "/" is root-relative.  -Skip "" scans tests too.
    -Distro     the WSL distro (default Ubuntu)

  Then run a shard's MCP server:  .\scripts\atlas.ps1 start -Project gdk-02
  Cross-shard calls and imports are not drawn (a relationship resolves only inside one bundle);
  each shard's coverage record says what it left out.
#>
param(
  [Parameter(Position = 0)][string]$Command = "help",
  [string]$Source,
  [string]$Name = "shard",
  [int]$MaxFiles = 3000,
  [string]$Skip = "spec,test,tests,__tests__,__mocks__,fixtures",
  [string]$Only,
  [string]$Distro = "Ubuntu"
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if ($Command.ToLower() -eq "help" -or -not $Source) {
  Get-Content $PSCommandPath | Select-Object -Skip 1 -First 20 | ForEach-Object { $_ -replace '^\s{2}', '' } | Write-Host
  return
}
if ($Name -notmatch '^[a-z0-9][a-z0-9-]{0,24}$') { throw "-Name must be lowercase letters, digits and dashes (for example: gdk)." }
$viaWsl = $Source.StartsWith("/")
if (-not $viaWsl) { $Source = (Resolve-Path -LiteralPath $Source).Path }

# Windows path -> the path WSL sees (C:\a\b -> /mnt/c/a/b)
function To-Wsl([string]$p) {
  # (a scriptblock replacement would be neater but only exists in PowerShell 6+)
  if ($p -match '^([A-Za-z]):\\(.*)$') { return '/mnt/' + $Matches[1].ToLower() + '/' + ($Matches[2] -replace '\\', '/') }
  return ($p -replace '\\', '/')
}

# Run `docker run ... code-atlas:local <mode> ...` (through WSL when the source is a Linux path). Returns output lines.
function Run-Atlas([string[]]$envArgs, [string]$dataDir, [string[]]$modeArgs) {
  $src = $Source
  $docker = @("run", "--rm", "--read-only", "--tmpfs", "/tmp", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "-v", "${src}:/src:ro")
  if ($dataDir) { $d = if ($viaWsl) { To-Wsl $dataDir } else { $dataDir }; $docker += @("-v", "${d}:/data") }
  $docker += $envArgs + @("code-atlas:local") + $modeArgs
  $old = $ErrorActionPreference; $ErrorActionPreference = "Continue"
  try {
    $out = if ($viaWsl) { & wsl -d $Distro -e docker @docker 2>&1 } else { & docker @docker 2>&1 }
    $script:exit = $LASTEXITCODE
  } finally { $ErrorActionPreference = $old }
  if ($script:exit -ne 0) { throw ("docker failed (exit $script:exit): " + (($out | Select-Object -Last 5) -join " | ")) }
  return @($out | ForEach-Object { "$_" })
}

$skipArgs = @(); if ($Skip) { $skipArgs = @("--skip", $Skip) }
"Planning (max $MaxFiles files per shard$(if ($Skip) { ", skipping $Skip" }))..." | Write-Host
$json = (Run-Atlas @() $null (@("plan", "--json", "--max-files", "$MaxFiles") + $skipArgs)) -join "`n"
$plan = $json | ConvertFrom-Json
$total = ($plan.shards | Measure-Object -Property files -Sum).Sum
"{0:n0} analyzable files -> {1} shard(s)" -f $total, @($plan.shards).Count | Write-Host
foreach ($s in $plan.shards) {
  $inc = @($s.include); $brief = if ($inc.Count -eq 0) { "(whole tree)" } elseif ($inc.Count -le 4) { $inc -join ", " } else { ($inc[0..3] -join ", ") + "  (+$($inc.Count - 4) more folders)" }
  "  {0:00}  {1,5} files{2}  [{3}]  {4}" -f $s.index, $s.files, $(if ($s.oversize) { " (OVERSIZE)" } else { "" }), $s.hint, $brief | Write-Host
}
New-Item -ItemType Directory -Force -Path (Join-Path $root "atlas") | Out-Null
$json | Set-Content -Path (Join-Path $root "atlas\$Name-plan.json") -Encoding utf8

if ($Command.ToLower() -ne "build") { Write-Host "`n(plan only: run with 'build' to make the bundles)"; return }

# NB: PowerShell variable names are case-insensitive, so a local named $only would overwrite the typed [string]$Only parameter.
$wanted = @(); if ($Only) { $wanted = @($Only -split ',' | ForEach-Object { [int]$_.Trim() }) }
$rows = @()
foreach ($s in $plan.shards) {
  if ($wanted.Count -and ($wanted -notcontains [int]$s.index)) { continue }
  $proj = "{0}-{1:00}" -f $Name, $s.index
  $dir = Join-Path $root "atlas\$proj"
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  $t0 = Get-Date
  Write-Host ("Building {0} ({1} files)..." -f $proj, $s.files)
  $envArgs = @("-e", "ATLAS_LABEL=$proj", "-e", "ATLAS_SKIP=$Skip")
  if (@($s.include).Count) { $envArgs += @("-e", ("ATLAS_INCLUDE=" + ((@($s.include)) -join ","))) }
  # The scanner's own default cap is 2,000 files; a shard may hold up to -MaxFiles, so pass it explicitly
  # (without this a 2,514-file shard silently lost 514 files: the bundle's coverage showed overCap).
  $out = Run-Atlas $envArgs $dir @("build", "--max-files", "$([Math]::Max($MaxFiles, [int]$s.files))")
  $line = $out | Where-Object { $_ -match 'nodes \(' } | Select-Object -Last 1
  # Safety check: the bundle must hold exactly the files the plan promised.
  $cov = $out | Where-Object { $_ -match 'coverage: analyzed (\d+)/' } | Select-Object -Last 1
  if ($cov -and $cov -match 'analyzed (\d+)/' -and [int]$Matches[1] -ne [int]$s.files) {
    Write-Warning ("{0}: planned {1} files but the bundle analyzed {2}: some files were left out (see its coverage)." -f $proj, $s.files, $Matches[1])
  }
  Write-Host ("  " + ($line -replace '^\s+', '') + ("  [{0:n0}s]" -f ((Get-Date) - $t0).TotalSeconds))
  $rows += $proj
}
Write-Host "`nBuilt: $($rows -join ', ')"
Write-Host "Run one:    .\scripts\atlas.ps1 start -Project <name>      (e.g. $($rows | Select-Object -First 1))"
Write-Host "Register:   .\scripts\atlas.ps1 mcp-config -Project <name>   (prints the claude mcp add command)"
Write-Host "Servers use roughly 0.3-0.5 GB each: run the shards you are working on, not all at once."
