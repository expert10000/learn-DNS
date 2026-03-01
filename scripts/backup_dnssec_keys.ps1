param(
  [string]$OutDir = "backups"
)

$ts = Get-Date -Format "yyyyMMdd-HHmmss"
$dest = Join-Path $OutDir ("dnssec-keys-" + $ts + ".zip")

if (-not (Test-Path $OutDir)) {
  New-Item -ItemType Directory -Path $OutDir | Out-Null
}

$paths = @(
  ".\\bind9\\keys\\*",
  ".\\bind9_parent\\keys\\*"
)

Write-Host "Creating backup: $dest"
Compress-Archive -Path $paths -DestinationPath $dest -Force
Write-Host "Done."
