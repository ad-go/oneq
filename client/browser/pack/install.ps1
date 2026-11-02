<#
.SYNOPSIS
  Installs the oneq browser extension (Brave, Chrome, Edge) and, optionally, starts `oneqclient proxy` at every logon.

.DESCRIPTION
  1. copies the extension to %LOCALAPPDATA%\oneq\browser\extension (a stable folder: the browser loads it from there);
  2. with -Relay/-Community/-User: registers a scheduled task that runs `oneqclient proxy` at logon (no administrator rights) and starts it;
  3. opens the browser's extensions page and puts the folder path on the clipboard: turn on Developer mode, press "Load unpacked", paste the path.
  A browser only loads an unpacked extension from its own extensions page (there is no way to do that silently), so step 3 is yours.

.EXAMPLE
  .\install.ps1 -Relay https://relay.example.org:8443 -Community lan -User alice -CaFile C:\path\ca.pem
  (asks for the password and keeps it in a file only you can read)
.EXAMPLE
  .\install.ps1            # only the extension; start the proxy yourself: oneqclient proxy --relay ...
#>
param(
  [string[]]$Relay, [string]$Community, [string]$User, [string]$PasswordFile, [string]$CaFile, [string]$Name,
  [string]$Dest = (Join-Path $env:LOCALAPPDATA 'oneq\browser'),
  [string]$Client,
  [ValidateSet('auto', 'brave', 'chrome', 'edge')][string]$Browser = 'auto',
  [string]$TaskName = 'oneq proxy',
  [switch]$StartAtLogon, [switch]$NoStartNow, [switch]$NoOpen,   # -StartAtLogon: also run the proxy at every logon, without the browser
  [string[]]$ExtensionId,  # id(s) of a store-installed Chromium extension, if you install from a store instead of the folder
  [string[]]$ProxyArgs,    # extra arguments for oneqclient proxy, e.g. --allow-process,mybrowser or --allow-any-local
  [switch]$NoPassword      # do not ask for the password now: run set-password.ps1 afterwards (it asks, stores it for this user only and starts the proxy)
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$src = Join-Path $here 'extension'
if (-not (Test-Path (Join-Path $src 'manifest.json'))) { throw "the extension folder is missing next to this script: $src" }

# 1. the extension
$extDir = Join-Path $Dest 'extension'
New-Item -ItemType Directory -Force -Path $Dest | Out-Null
if (Test-Path $extDir) { Remove-Item -Recurse -Force $extDir }
Copy-Item -Recurse -Force $src $extDir
$ver = (Get-Content (Join-Path $extDir 'manifest.json') -Raw | ConvertFrom-Json).version
Write-Host "extension $ver copied to $extDir"

# 2. the connection manager: the extension asks the native host (oneqclient native-host) to run the proxy, so the whole setup can be done in the extension.
# The settings given here are stored in the host; the password too, when it is given (-PasswordFile, or asked now unless -NoPassword).
if (-not $Client) {
  foreach ($c in @((Join-Path $here 'oneqclient.exe'), (Join-Path $env:LOCALAPPDATA 'oneq
pnclient.exe'), (Join-Path $env:ProgramFiles 'oneq
pnclient.exe'))) { if (Test-Path $c) { $Client = $c; break } }
  if (-not $Client) { $g = Get-Command oneqclient.exe -ErrorAction SilentlyContinue; if ($g) { $Client = $g.Source } }
}
if ($Client -and (Test-Path $Client)) {
  $idArgs = @(); foreach ($i in $ExtensionId) { if ($i) { $idArgs += @('--extension-id', $i) } }
  & $Client native-host install @idArgs
  if ($Relay -and $Community -and $User) {
    $cfg = @('native-host', 'configure', '--community', $Community, '--user', $User)
    foreach ($r in $Relay) { $cfg += @('--relay', $r) }
    if ($CaFile) { $cfg += @('--cafile', (Resolve-Path $CaFile).Path) }
    if ($Name) { $cfg += @('--name', $Name) }
    if ($PasswordFile) { $cfg += @('--password-file', (Resolve-Path $PasswordFile).Path) }
    & $Client @cfg
    if (-not $PasswordFile -and -not $NoPassword) {
      $sec = Read-Host "Password of $User in community $Community" -AsSecureString
      $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
      $plain | & $Client native-host set-password
      $plain = $null
    } elseif (-not $PasswordFile) {
      Write-Host 'no password stored yet: type it in the extension (Settings), or run  .\set-password.ps1'
    }
  }
} else {
  Write-Host 'oneqclient.exe not found: the extension cannot start the connection by itself (install the oneq client, then run: oneqclient native-host install)'
}

# 2b. optional: the proxy at every logon, independent of the browser (the extension-managed proxy lives only as long as the browser)
if ($Relay -and $Community -and $User -and $StartAtLogon) {
  if (-not $Client) {
    foreach ($c in @((Join-Path $here 'oneqclient.exe'), (Join-Path $env:ProgramFiles 'oneq\oneqclient.exe'), (Join-Path $env:LOCALAPPDATA 'oneq\oneqclient.exe'))) { if (Test-Path $c) { $Client = $c; break } }
    if (-not $Client) { $g = Get-Command oneqclient.exe -ErrorAction SilentlyContinue; if ($g) { $Client = $g.Source } }
  }
  if (-not $Client -or -not (Test-Path $Client)) { throw 'oneqclient.exe not found: install the oneq client first or pass -Client PATH' }
  if (-not $PasswordFile -and $NoPassword) {
    $PasswordFile = Join-Path $Dest 'proxy.pass'
    if (-not (Test-Path $PasswordFile)) { $NoStartNow = $true }
  } elseif (-not $PasswordFile) {
    $PasswordFile = Join-Path $Dest 'proxy.pass'
    $sec = Read-Host "Password of $User in community $Community" -AsSecureString
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
    Set-Content -Path $PasswordFile -Value $plain -NoNewline -Encoding ascii
    $plain = $null
    icacls $PasswordFile /inheritance:r /grant:r "$($env:USERNAME):F" | Out-Null      # only this user
  }
  $argList = @('proxy')
  foreach ($r in $Relay) { $argList += @('--relay', $r) }
  $argList += @('--community', $Community, '--user', $User, '--password-file', $PasswordFile)
  if ($ProxyArgs) { $argList += $ProxyArgs }
  if ($CaFile) {
    $caCopy = Join-Path $Dest 'ca.pem'                       # a copy next to the extension: the task must not depend on a file somewhere else
    Copy-Item -Force (Resolve-Path $CaFile).Path $caCopy
    $argList += @('--cafile', $caCopy)
  }
  if ($Name) { $argList += @('--name', $Name) }
  $q = { param($s) if ($s -match '[\s"]') { '"' + ($s -replace '"', '\"') + '"' } else { $s } }
  $argString = ($argList | ForEach-Object { & $q $_ }) -join ' '
  Set-Content -Path (Join-Path $Dest 'proxy-command.txt') -Value "`"$Client`" $argString" -Encoding ascii
  $action = New-ScheduledTaskAction -Execute $Client -Argument $argString
  $trigger = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"
  $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
  $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited
  Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force `
    -Description 'oneq mesh: SOCKS5 proxy for the browser extension (no TUN, no administrator rights)' | Out-Null
  Write-Host "scheduled task '$TaskName' registered (runs at logon as $env:USERNAME)"
  if (-not $NoStartNow) { Start-ScheduledTask -TaskName $TaskName; Write-Host 'proxy started' }
  elseif ($NoPassword) { Write-Host "the proxy is configured but has no password yet: run  .\set-password.ps1  (asks once, stores it for this user only, starts the proxy)" }
  Copy-Item -Force (Join-Path $here 'set-password.ps1') (Join-Path $Dest 'set-password.ps1') -ErrorAction SilentlyContinue
} elseif ($StartAtLogon) {
  Write-Host 'the logon task was not created (-Relay, -Community and -User are all needed)'
}

# 3. the browser
$browsers = [ordered]@{
  brave  = @("$env:ProgramFiles\BraveSoftware\Brave-Browser\Application\brave.exe", "${env:ProgramFiles(x86)}\BraveSoftware\Brave-Browser\Application\brave.exe", "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\Application\brave.exe")
  chrome = @("$env:ProgramFiles\Google\Chrome\Application\chrome.exe", "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe", "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe")
  edge   = @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe", "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe")
}
$scheme = @{ brave = 'brave'; chrome = 'chrome'; edge = 'edge' }
$chosen = $null
foreach ($b in $browsers.Keys) {
  if ($Browser -ne 'auto' -and $Browser -ne $b) { continue }
  $exe = $browsers[$b] | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
  if ($exe) { $chosen = @{ name = $b; exe = $exe }; break }
}
try { Set-Clipboard -Value $extDir } catch { }
Write-Host ''
Write-Host 'Last step, in the browser (it cannot be done for you):'
Write-Host "  1. open the extensions page ($(if ($chosen) { $scheme[$chosen.name] } else { 'brave|chrome|edge' })://extensions)"
Write-Host '  2. turn on "Developer mode" (top right)'
Write-Host '  3. press "Load unpacked" and choose this folder (it is on the clipboard: paste it into the file dialog):'
Write-Host "       $extDir"
if ($chosen -and -not $NoOpen) { Start-Process $chosen.exe "$($scheme[$chosen.name])://extensions"; Write-Host "(opened $($chosen.name))" }
elseif (-not $chosen) { Write-Host '(no Brave, Chrome or Edge found in the usual places)' }
