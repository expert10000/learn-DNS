param(
  [ValidateSet('trusted', 'untrusted', 'mgmt')]
  [string]$Profile = 'trusted',
  [string]$Resolver = '172.32.0.20',
  [string]$Name = 'www.example.test',
  [ValidateSet('A', 'AAAA', 'TXT', 'MX', 'NS')]
  [string]$Qtype = 'A',
  [int]$Count = 200,
  [int]$Qps = 20
)

if ($Count -lt 1 -or $Count -gt 600) {
  throw "Count must be between 1 and 600."
}
if ($Qps -lt 1 -or $Qps -gt 100) {
  throw "Qps must be between 1 and 100."
}

$container = switch ($Profile) {
  'trusted' { 'dns_client' }
  'untrusted' { 'dns_untrusted' }
  'mgmt' { 'dns_mgmt_client' }
}

$sleep = [math]::Round(1 / $Qps, 3)
$loop = "for i in $(seq 1 $Count); do dig @$Resolver $Name $Qtype +time=1 +tries=1 >/dev/null; "
if ($sleep -gt 0) {
  $loop += "sleep $sleep; "
}
$loop += "done"

Write-Host "Running load: $Count queries at ~$Qps qps via $Profile ($Resolver)"
docker compose exec $container sh -lc $loop
