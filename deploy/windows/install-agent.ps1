param([Parameter(Mandatory=$true)][string]$Agent,[Parameter(Mandatory=$true)][string]$Wintun)
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw "Run from an elevated PowerShell" }
if (Get-Service -Name NetworkEXAgent -ErrorAction SilentlyContinue) { throw "Existing service; stop and uninstall before upgrade" }
if ((Get-AuthenticodeSignature -LiteralPath $Wintun).Status -ne 'Valid') { throw "Supply the official, verified signed Wintun DLL for the matching architecture" }
$root = Join-Path $env:ProgramData 'Network EX'
$bin = Join-Path $env:ProgramFiles 'Network EX Agent'
$admin = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
# Refuse preexisting binary directory. Private state is retained on uninstall;
# existing state must be verified by an administrator rather than trusting a writable tree.
if (Test-Path -LiteralPath $bin) { throw "Existing program directory; verify and remove it before reinstall" }
if (Test-Path -LiteralPath $root) { throw "Existing state; verify owner/ACL and explicitly migrate before reinstall" }
foreach ($dir in @($root,$bin)) {
 New-Item -ItemType Directory -Path $dir | Out-Null
 $acl = [Security.AccessControl.DirectorySecurity]::new()
 $acl.SetOwner($admin)
 $acl.SetAccessRuleProtection($true,$false)
 foreach ($sid in @($admin,$system)) {
  $rule = [Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
  $acl.AddAccessRule($rule)
 }
 Set-Acl -LiteralPath $dir -AclObject $acl
}
$exe = Join-Path $bin 'network-ex-agent.exe'
Copy-Item -LiteralPath $Agent -Destination $exe
Copy-Item -LiteralPath $Wintun -Destination (Join-Path $bin 'wintun.dll')
$command = '"' + $exe + '" daemon -state-root "' + $root + '" -interface nex0'
New-Service -Name NetworkEXAgent -DisplayName 'Network EX Agent' -BinaryPathName $command -StartupType Automatic
Start-Service -Name NetworkEXAgent
Write-Host 'M4 developer build: the named pipe currently requires elevated local administrators. Standard-user group authorization and driver installation verification are pending.'
