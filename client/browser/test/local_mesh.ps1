<#
.SYNOPSIS
  A throw-away mesh on this PC for the browser tests: a relay on 127.0.0.1, one member with a tiny web page, nothing else. Windows, run elevated (the web member uses a TUN adapter).
.DESCRIPTION
  .\local_mesh.ps1            start it; prints the member's mesh address
  .\local_mesh.ps1 -Stop      stop everything and delete the work directory
  Result (in -Work): rd\ca.crt (the relay's CA), pw (the password of the test user alice in community btest), webip (the member's mesh address), www\index.html (title NPNBT).
  Use it with client\browser\test\chrome_native_e2e.py and firefox_native_e2e.py:
    python chrome_native_e2e.py CHROME https://127.0.0.1:28443 WORK\rd\ca.crt btest alice WORK\pw NPNBT webnode
  The browser tests need the native host registered for the browser (oneqclient native-host install --only chrome,firefox) and remove it afterwards (native-host uninstall).
  Needs: target\release\oneqclient.exe and the relay bundle (client\relay\build-bundle.py --platform windows-x64 --out client\relay\dist\windows-x64).
#>
param(
  [string]$Work = (Join-Path $env:TEMP 'oneq-bt'),
  [string]$Client = (Join-Path $PSScriptRoot '..\..\target\release\oneqclient.exe'),
  [string]$RelayHome = (Join-Path $PSScriptRoot '..\..\relay\dist\windows-x64'),
  [int]$Port = 28443,
  [switch]$Stop
)
$ErrorActionPreference = 'Stop'
$N = (Resolve-Path $Client).Path
$H = (Resolve-Path $RelayHome).Path
$rule = 'oneq local test mesh'
function Stop-Mesh {
  Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -eq $N -or $_.CommandLine -like "*$Work*" } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
  netsh advfirewall firewall delete rule name=$rule | Out-Null
  Start-Sleep 2
  Remove-Item $Work -Recurse -Force -ErrorAction SilentlyContinue
}
Stop-Mesh
if ($Stop) { 'stopped'; return }

$D = Join-Path $Work 'rd'
New-Item -ItemType Directory $Work, (Join-Path $Work 'www') | Out-Null
& $N relay init --home $H --data $D --name 127.0.0.1 --ip 127.0.0.1 --port $Port --no-admin | Select-Object -First 1
$pw = -join ((48..57 + 97..122) | Get-Random -Count 20 | ForEach-Object { [char]$_ })
[IO.File]::WriteAllText("$Work\pw", $pw)
& $N relay admin community-add btest 10.95.0.0/24 --home $H --data $D | Select-Object -Last 1
& $N relay admin user-add btest alice --password-file "$Work\pw" --home $H --data $D | Select-Object -Last 1
Start-Process $N -ArgumentList 'relay', 'run', '--home', "`"$H`"", '--data', $D -WindowStyle Hidden -RedirectStandardOutput "$Work\relay.out" -RedirectStandardError "$Work\relay.err"
Start-Sleep 6
'<html><head><title>NPNBT</title></head><body>mesh ok</body></html>' | Set-Content "$Work\www\index.html" -Encoding ascii
Start-Process $N -ArgumentList 'up', '--relay', "https://127.0.0.1:$Port", '--cafile', "$D\ca.crt", '--community', 'btest', '--user', 'alice', '--password-file', "$Work\pw", '--name', 'webnode', '--ifname', 'oneqbt', '--key-file', "$Work\web.key" -WindowStyle Hidden -RedirectStandardError "$Work\web.err" -RedirectStandardOutput "$Work\web.out"
Start-Sleep 12
$ip = (Get-Content "$Work\web.err", "$Work\web.out" -ErrorAction SilentlyContinue | ForEach-Object { $_ -replace '\x1b\[[0-9;]*m', '' } | Select-String 'status: address (10\.\d+\.\d+\.\d+)/' | Select-Object -Last 1).Matches[0].Groups[1].Value
if (-not $ip) { throw "the web member did not get a mesh address: see $Work\web.err" }
Set-Content "$Work\webip" $ip -Encoding ascii
netsh advfirewall firewall add rule name=$rule dir=in action=allow program=$N | Out-Null
Start-Process (Join-Path $H 'python\python.exe') -ArgumentList '-m', 'http.server', '80', '--bind', $ip, '--directory', "$Work\www" -WindowStyle Hidden -RedirectStandardError "$Work\http.err"
Start-Sleep 2
"mesh up: relay https://127.0.0.1:$Port, member webnode at $ip, work directory $Work"
