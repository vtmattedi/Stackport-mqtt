# Usage: .\scripts\smoke-test.ps1 -Username <user> -Topic <topic> -CaFile <nm-root-ca.crt> [-HostName ..] [-Port 8883]
# PowerShell equivalent of smoke-test.sh. Needs Docker; the password is prompted without echo.
param(
  [Parameter(Mandatory)][string]$Username,
  [Parameter(Mandatory)][string]$Topic,
  [Parameter(Mandatory)][string]$CaFile,
  [string]$HostName = 'mqtt.mattediworks.com',
  [int]$Port = 8883
)
$ErrorActionPreference = 'Stop'

$ca = (Resolve-Path $CaFile).Path
$secure = Read-Host "Password for $Username" -AsSecureString
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try { $password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }

$image = 'eclipse-mosquitto:2.1.2-alpine'
$name = "mqtt-smoke-$PID"
$message = "stackport-smoke-$PID"
try {
  docker run -d --name $name -v "${ca}:/ca.crt:ro" $image `
    mosquitto_sub -h $HostName -p $Port --cafile /ca.crt -u $Username -P $password -t $Topic -C 1 -W 15 | Out-Null
  Start-Sleep 1
  docker run --rm -v "${ca}:/ca.crt:ro" $image `
    mosquitto_pub -h $HostName -p $Port --cafile /ca.crt -u $Username -P $password -t $Topic -m $message
  if ($LASTEXITCODE -ne 0) { throw 'Publish failed.' }

  $status = (docker wait $name).Trim()
  $logs = (docker logs $name 2>&1 | Out-String).Trim()
  if ($status -ne '0' -or $logs -ne $message) {
    Write-Error "Round trip failed (exit $status): $logs"
    exit 1
  }
  Write-Host "Authenticated TLS publish/subscribe round trip passed on $Topic."
}
finally {
  docker rm -f $name 2>&1 | Out-Null
}
