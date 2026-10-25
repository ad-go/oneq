<#
.SYNOPSIS
  Removes what install.ps1 put on this computer: the scheduled task, the copied extension and, with -Purge, the saved password and the proxy's node key.
  The extension itself must be removed in the browser (extensions page -> Remove).
#>
param(
  [string]$Dest = (Join-Path $env:LOCALAPPDATA 'oneq\browser'),
  [string]$TaskName = 'oneq proxy',
  [switch]$Purge
)
$ErrorActionPreference = 'Stop'
$t = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($t) {
  Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
  Write-Host "scheduled task '$TaskName' removed"
}
if (Test-Path $Dest) {
  if ($Purge) { Remove-Item -Recurse -Force $Dest; Write-Host "removed $Dest (including the saved password)" }
  else {
    Remove-Item -Recurse -Force (Join-Path $Dest 'extension') -ErrorAction SilentlyContinue
    Remove-Item -Force (Join-Path $Dest 'proxy-command.txt') -ErrorAction SilentlyContinue
    Write-Host "removed the extension copy in $Dest (kept proxy.pass; -Purge deletes it)"
  }
}
if ($Purge) {
  $key = Join-Path $env:APPDATA 'oneq\proxy.key'
  if (Test-Path $key) { Remove-Item -Force $key; Write-Host 'removed the proxy node key (the node stays in the registry until an administrator removes it)' }
}
Write-Host 'Now remove "oneq mesh" from the browser: brave://extensions (or chrome://extensions) -> Remove.'
