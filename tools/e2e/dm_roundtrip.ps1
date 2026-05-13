# SPDX-License-Identifier: AGPL-3.0-or-later
#
# End-to-end test: spin up fb_server.exe + two fb-cli.exe peers, exchange
# a DM, and assert (a) the recipient decrypts it and (b) the server log
# never contained the plaintext. PowerShell equivalent of
# tools/e2e/dm_roundtrip.sh — the Linux version uses bash; this version
# is what build-windows.yml runs on windows-latest to prove the Windows
# binaries deliver the same E2E behaviour.
#
# Usage: pwsh tools/e2e/dm_roundtrip.ps1 [-Build <dir>] [-Marker <text>]
#   -Build  defaults to .\build\win-msvc-release
#   -Marker defaults to a random magic string used as the message body
#
# Exits 0 on success, non-zero on any failure mode.

[CmdletBinding()]
param(
    [string]$Build  = "build/win-msvc-release",
    [string]$Marker = ""
)

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"

if (-not $Marker) {
    $bytes = New-Object byte[] 16
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $hex = -join ($bytes | ForEach-Object { $_.ToString("x2") })
    $Marker = "FBE2E-$hex-MAGIC"
}

# Locate the executables. The Visual Studio generator nests them under
# the configuration name (RelWithDebInfo) so we glob for them.
$server = Get-ChildItem -Recurse -Path $Build `
    -Filter fb_server.exe | Select-Object -First 1
$cli    = Get-ChildItem -Recurse -Path $Build `
    -Filter fb-cli.exe    | Select-Object -First 1
if (-not $server) { throw "fb_server.exe not found under $Build" }
if (-not $cli)    { throw "fb-cli.exe not found under $Build"    }
Write-Host "== using server: $($server.FullName)"
Write-Host "== using fb-cli: $($cli.FullName)"

# Free-port picker — bind 0 and let Windows hand us an ephemeral, then
# release. Tiny race with another process grabbing it before we
# re-bind, but vanishingly unlikely on a CI runner.
$listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
$listener.Start()
$port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
$listener.Stop()

$scratch = New-Item -ItemType Directory -Path (Join-Path $env:TEMP "fbe2e-$([Guid]::NewGuid())")
$serverLog = Join-Path $scratch "server.log"
$bobOut    = Join-Path $scratch "bob.stdout"
$bobErr    = Join-Path $scratch "bob.stderr"
$aliceOut  = Join-Path $scratch "alice.stdout"
$aliceErr  = Join-Path $scratch "alice.stderr"

Write-Host "== launching fb_server on 127.0.0.1:$port"
$srv = Start-Process -FilePath $server.FullName `
    -ArgumentList @("--host", "127.0.0.1", "--port", "$port") `
    -RedirectStandardOutput $serverLog `
    -RedirectStandardError "$serverLog.stderr" `
    -PassThru
try {
    # Wait for the server to bind.
    $ready = $false
    for ($i = 0; $i -lt 50; $i++) {
        try {
            $probe = New-Object System.Net.Sockets.TcpClient
            $probe.Connect("127.0.0.1", $port)
            $probe.Close()
            $ready = $true
            break
        } catch { Start-Sleep -Milliseconds 100 }
    }
    if (-not $ready) { throw "server did not bind on 127.0.0.1:$port" }

    Write-Host "== launching fb-cli listen as bob"
    $bob = Start-Process -FilePath $cli.FullName `
        -ArgumentList @("--user", "bob", "--listen", "--wait-ms", "5000",
                         "--server", "127.0.0.1:$port") `
        -RedirectStandardOutput $bobOut `
        -RedirectStandardError $bobErr `
        -PassThru    Start-Sleep -Milliseconds 400

    Write-Host "== launching fb-cli send as alice"
    $alice = Start-Process -FilePath $cli.FullName `
        -ArgumentList @("--user", "alice", "--send", "--peer", "bob",
                         "--text", $Marker, "--server", "127.0.0.1:$port") `
        -RedirectStandardOutput $aliceOut `
        -RedirectStandardError $aliceErr `
        -PassThru -WindowStyle Hidden -Wait

    # Wait for bob to print the message + exit.
    $bob.WaitForExit(8000) | Out-Null
    if (-not $bob.HasExited) {
        Write-Host "##[warning]bob did not exit within 8 s; force-killing"
        $bob.Kill()
    }
    # Small drain interval — Start-Process holds the redirect handle
    # briefly after the child exits on Windows; giving it 300 ms lets
    # the OS flush the last buffered writes before we read.
    Start-Sleep -Milliseconds 300

    # Always dump captured output before assertions — makes a failed
    # run self-diagnosing without needing a re-run with extra logs.
    Write-Host ""
    Write-Host "== captured output =="
    foreach ($f in @($bobOut, $bobErr, $aliceOut, $aliceErr, $serverLog, "$serverLog.stderr")) {
        if (Test-Path $f) {
            $sz = (Get-Item $f).Length
            Write-Host "  $(Split-Path -Leaf $f): $sz bytes"
        } else {
            Write-Host "  $(Split-Path -Leaf $f): MISSING"
        }
    }
    Write-Host "-- bob.stdout --"
    Get-Content $bobOut    -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "    $_" }
    Write-Host "-- bob.stderr --"
    Get-Content $bobErr    -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "    $_" }
    Write-Host "-- alice.stdout --"
    Get-Content $aliceOut  -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "    $_" }
    Write-Host "-- alice.stderr --"
    Get-Content $aliceErr  -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "    $_" }
    Write-Host "-- server.log (stdout) --"
    Get-Content $serverLog -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "    $_" }
    Write-Host "-- server.log.stderr --"
    Get-Content "$serverLog.stderr" -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "    $_" }
    Write-Host ""
    Write-Host "== checks =="

    # Use [System.IO.File]::ReadAllText to bypass Get-Content's BOM /
    # encoding heuristics — fb-cli writes plain ASCII, but Powershell's
    # Get-Content has historically misread UTF-8-without-BOM as ASCII
    # and dropped trailing bytes.
    function Read-All([string]$p) {
        if (-not (Test-Path $p)) { return "" }
        return [System.IO.File]::ReadAllText($p)
    }
    $bobStdout = Read-All $bobOut
    if (-not $bobStdout -or -not $bobStdout.Contains("MSG: $Marker")) {
        throw "FAIL: bob did not decrypt the marker (see captured output above)"
    }
    Write-Host "  OK bob received MSG: $Marker"

    # Server log must NOT contain the plaintext marker — the relay is
    # supposed to be blind to envelope contents. Same canary test the
    # Linux e2e runs.
    $serverContents = (Read-All $serverLog) + (Read-All "$serverLog.stderr")
    if ($serverContents -and $serverContents.Contains($Marker)) {
        throw "FAIL: server log contained plaintext marker — server is NOT blind! (see captured output above)"
    }
    Write-Host "  OK server log never saw plaintext"

    Write-Host ""
    Write-Host "PASS: dm_roundtrip on Windows (port=$port, marker=$Marker)" `
               -ForegroundColor Green
} finally {
    if ($srv -and -not $srv.HasExited) { $srv.Kill() }
    Remove-Item -Recurse -Force $scratch -ErrorAction SilentlyContinue
}
