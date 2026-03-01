param(
  [switch]$Force
)

if (-not $Force) {
  throw "This will delete DNSSEC keys. Re-run with -Force to proceed."
}

Write-Host "Stopping authoritative and resolver containers..."
docker compose stop authoritative_parent authoritative_child resolver resolver_plain | Out-Null

Write-Host "Removing keys and signed zones..."
Remove-Item -Recurse -Force .\\bind9\\keys\\* -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force .\\bind9_parent\\keys\\* -ErrorAction SilentlyContinue
Remove-Item -Force .\\bind9\\zones\\*.signed* -ErrorAction SilentlyContinue
Remove-Item -Force .\\bind9_parent\\zones\\*.signed* -ErrorAction SilentlyContinue

Write-Host "Starting authoritative servers..."
docker compose start authoritative_parent authoritative_child | Out-Null

Write-Host "Recomputing DS + exporting trust anchor..."
docker compose run --rm ds_recompute | Out-Null
docker compose run --rm anchor_export | Out-Null

Write-Host "Restarting resolvers..."
docker compose start resolver resolver_plain | Out-Null

Write-Host "Done."
