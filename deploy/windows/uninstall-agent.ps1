$ErrorActionPreference = 'Stop'
Stop-Service -Name NetworkEXAgent
& "$env:SystemRoot\System32\sc.exe" delete NetworkEXAgent
if ($LASTEXITCODE -ne 0) { throw "Service removal failed" }
Write-Host 'Private state and binaries retained for explicit administrator review; revoke/forget device separately.'
