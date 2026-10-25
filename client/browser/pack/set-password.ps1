<#
.SYNOPSIS
  Stores the mesh password for the browser extension's connection (this user only). Run it after `install.ps1 -NoPassword`.
.DESCRIPTION
  Asks for the password without echo and hands it to `oneqclient native-host set-password` on its standard input (never on a command line). The oneq connection
  manager keeps it in a file only this user can read; the extension itself never stores it. You can also type the password in the extension's Settings.
#>
param([string]$Client)
$ErrorActionPreference = 'Stop'
if (-not $Client) {
  foreach ($c in @((Join-Path $env:LOCALAPPDATA 'oneq
pnclient.exe'), (Join-Path $env:ProgramFiles 'oneq
pnclient.exe'))) { if (Test-Path $c) { $Client = $c; break } }
}
if (-not $Client -or -not (Test-Path $Client)) { throw 'oneqclient.exe not found: pass -Client PATH' }
$sec = Read-Host 'Password of the mesh account' -AsSecureString
$plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
if (-not $plain) { throw 'empty password' }
$plain | & $Client native-host set-password
$plain = $null
Write-Host 'open the extension: it connects by itself.'
