# Usage: .\pki\pki.ps1 <init|issue-leaf|renew-intermediate|export-env|verify|status> [host] [-Dir D:\pki-nm]
# Runs OpenSSL in Docker. -Dir must be OUTSIDE this repository (it holds CA private keys).
param(
  [Parameter(Mandatory)][ValidateSet('init', 'issue-leaf', 'renew-intermediate', 'export-env', 'verify', 'status')][string]$Command,
  [string]$HostName = 'mqtt.mattediworks.com',
  [string]$Dir = 'D:\pki-nm'
)
$ErrorActionPreference = 'Stop'

$repo = (Resolve-Path "$PSScriptRoot\..").Path
New-Item -ItemType Directory -Force $Dir | Out-Null
$full = (Resolve-Path $Dir).Path
if ($full.TrimEnd('\') -ieq $repo -or $full.StartsWith($repo + '\', 'OrdinalIgnoreCase')) {
  throw "Refusing to use ${full}: it is inside the repository."
}

docker run --rm -v "${full}:/pki" -v "${PSScriptRoot}:/scripts:ro" `
  --entrypoint sh alpine/openssl /scripts/pki.sh $Command $HostName
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
