# SPDX-License-Identifier: AGPL-3.0-or-later
# =============================================================================
# fetch-mlspp.ps1 — Windows equivalent of fetch-mlspp.sh.
#
# Vendors cisco/mlspp under third_party/mlspp so the MLS feature
# (FB_FEATURE_MLS=ON) has the implementation it needs.
#
# Usage:
#   pwsh scripts/fetch-mlspp.ps1
#   pwsh scripts/fetch-mlspp.ps1 -Force
#   pwsh scripts/fetch-mlspp.ps1 -Pin <ref>
#
# After this, configure with -DFB_FEATURE_MLS=ON.
# =============================================================================

[CmdletBinding()]
param(
    [switch]$Force,
    [string]$Pin = "main"
)

$ErrorActionPreference = "Stop"

$RepoUrl   = "https://github.com/cisco/mlspp.git"
$ScriptDir = Split-Path -Parent $PSCommandPath
$Target    = Join-Path (Split-Path -Parent $ScriptDir) "third_party/mlspp"

if ($Force -and (Test-Path $Target)) {
    Write-Host "== removing existing $Target"
    Remove-Item -Recurse -Force $Target
}

if ((Test-Path "$Target/.git") -or (Test-Path "$Target/lib/hpke")) {
    Write-Host "== mlspp already present at $Target (-Force to re-fetch)"
    exit 0
}

Write-Host "== cloning mlspp (pin=$Pin) into $Target"
$parent = Split-Path -Parent $Target
if (-not (Test-Path $parent)) {
    New-Item -ItemType Directory -Path $parent | Out-Null
}
& git clone --depth 1 --branch $Pin $RepoUrl $Target
if ($LASTEXITCODE -ne 0) { throw "git clone failed (exit $LASTEXITCODE)" }

$patchDir = Join-Path $ScriptDir "mlspp-patches"
if (Test-Path $patchDir) {
    $patches = Get-ChildItem -Path $patchDir -Filter "*.patch" -ErrorAction SilentlyContinue
    foreach ($p in $patches) {
        Write-Host "== applying $($p.Name)"
        Push-Location $Target
        try {
            # --ignore-whitespace is belt-and-braces against any
            # CRLF that slipped past .gitattributes (windows-latest
            # runners default to core.autocrlf=true). The patch
            # itself is pinned eol=lf so this should never bite,
            # but if it does we don't want a one-byte difference
            # to fail the whole MLS build.
            & git apply --whitespace=nowarn --ignore-whitespace $p.FullName
            if ($LASTEXITCODE -ne 0) {
                throw "git apply of $($p.Name) failed (exit $LASTEXITCODE)"
            }
        } finally {
            Pop-Location
        }
    }
}

Write-Host "== removing mlspp's .git so the vendored tree doesn't appear as a submodule"
Remove-Item -Recurse -Force (Join-Path $Target ".git") -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "mlspp vendored under third_party/mlspp."
Write-Host "Configure with:"
Write-Host "  cmake --preset win-msvc-release-mls"
Write-Host "  cmake --build --preset win-msvc-release-mls"
