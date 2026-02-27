param(
  [Parameter(Mandatory = $true)]
  [ValidateSet('nsec', 'nsec3')]
  [string]$Mode,
  [switch]$RunSigner
)

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$childDir = Join-Path $repoRoot "bind9"
$parentDir = Join-Path $repoRoot "bind9_parent"

$childTarget = Join-Path $childDir "named.conf"
$parentTarget = Join-Path $parentDir "named.conf"

switch ($Mode) {
  'nsec' {
    $childSource = Join-Path $childDir "named.inline.conf"
    $parentSource = Join-Path $parentDir "named.inline.conf"
  }
  'nsec3' {
    $childSource = Join-Path $childDir "named.offline.conf"
    $parentSource = Join-Path $parentDir "named.offline.conf"
  }
}

if (!(Test-Path $childSource)) {
  throw "Missing child config template: $childSource"
}
if (!(Test-Path $parentSource)) {
  throw "Missing parent config template: $parentSource"
}

Copy-Item -Force $childSource $childTarget
Copy-Item -Force $parentSource $parentTarget

Write-Host "Applied signing mode: $Mode"
Write-Host "Child config:  $childTarget"
Write-Host "Parent config: $parentTarget"

if ($Mode -eq 'nsec3') {
  if ($RunSigner) {
    Write-Host "Running offline signer..."
    docker compose run --rm signer
  } else {
    Write-Host "Offline NSEC3 requires signed zone files. Run:"
    Write-Host "  docker compose run --rm signer"
  }

  Write-Host "Then restart authoritative containers:"
  Write-Host "  docker compose restart authoritative_parent authoritative_child"
  Write-Host "If keys changed, refresh DS + trust anchor:"
  Write-Host "  docker compose run --rm ds_recompute"
  Write-Host "  docker compose run --rm anchor_export"
  Write-Host "  docker compose restart resolver"
} else {
  Write-Host "Inline NSEC mode uses BIND auto-signing."
  Write-Host "Restart authoritative containers to apply:"
  Write-Host "  docker compose restart authoritative_parent authoritative_child"
}
