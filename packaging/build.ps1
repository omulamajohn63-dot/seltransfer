<#
.SYNOPSIS
    Build the SELTRANSFER Windows executable and verify the result.

.DESCRIPTION
    Reproducible build: cleans previous output, runs PyInstaller against
    packaging\seltransfer.spec, then runs the checks that can be automated
    without a second device - the executable starts, finds its bundled web
    assets, and reports a version that matches the source tree.

    The remaining items on the clean-machine checklist cannot be automated here
    because they need a machine without Python and a second device. See
    packaging\CLEAN_MACHINE_CHECKLIST.md.

.PARAMETER SkipTests
    Skip the pre-build test run. Not recommended.

.PARAMETER NoArchive
    Produce a single-file executable instead of a folder. Slower to start and
    noisier for antivirus, so it is opt-in.

.EXAMPLE
    .\packaging\build.ps1
    .\packaging\build.ps1 -NoArchive
#>
[CmdletBinding()]
param(
    [switch]$SkipTests,
    [switch]$NoArchive
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $RepoRoot

function Write-Step($message) {
    Write-Host ''
    Write-Host "==> $message" -ForegroundColor Cyan
}

function Fail($message) {
    Write-Host "FAILED: $message" -ForegroundColor Red
    exit 1
}

try {
    Write-Step "Environment"
    python --version
    if ($LASTEXITCODE -ne 0) { Fail "python is not on PATH" }
    python -c "import PyInstaller; print('PyInstaller', PyInstaller.__version__)"
    if ($LASTEXITCODE -ne 0) { Fail "PyInstaller is not installed. pip install pyinstaller" }

    if (-not $SkipTests) {
        Write-Step "Test suite (the build is not worth shipping if this fails)"
        python -m pytest -p no:warnings
        if ($LASTEXITCODE -ne 0) { Fail "pytest" }
        python -m ruff check .
        if ($LASTEXITCODE -ne 0) { Fail "ruff" }
        python -m mypy src
        if ($LASTEXITCODE -ne 0) { Fail "mypy" }
        node tests\web\test_app.js
        if ($LASTEXITCODE -ne 0) { Fail "browser client tests" }
    }

    Write-Step "Version"
    $version = python -c "from seltransfer import __version__; print(__version__)"
    if ($LASTEXITCODE -ne 0) { Fail "could not read the package version" }
    Write-Host "  building SELTRANSFER $version"

    Write-Step "Clean previous output"
    foreach ($target in @('build', 'dist')) {
        if (Test-Path $target) {
            Remove-Item -Recurse -Force $target
            Write-Host "  removed $target"
        }
    }

    Write-Step "PyInstaller"
    # The spec decides the layout, and PyInstaller rejects --onefile/--onedir when
    # a .spec is supplied, so the choice is passed through the environment.
    if ($NoArchive) {
        $env:SELTRANSFER_ONEFILE = '1'
    }
    else {
        $env:SELTRANSFER_ONEFILE = '0'
    }
    python -m PyInstaller --noconfirm packaging\seltransfer.spec
    if ($LASTEXITCODE -ne 0) { Fail "PyInstaller" }

    $exe = if ($NoArchive) {
        Join-Path $RepoRoot 'dist\SELTRANSFER.exe'
    } else {
        Join-Path $RepoRoot 'dist\SELTRANSFER\SELTRANSFER.exe'
    }
    if (-not (Test-Path $exe)) { Fail "expected executable not found at $exe" }
    $sizeMb = [math]::Round((Get-Item $exe).Length / 1MB, 1)
    Write-Host "  built $exe ($sizeMb MB)"

    Write-Step "Bundled web assets are actually served"
    # Checked over HTTP rather than by looking for files on disk. The resolver
    # searches the bundle at runtime, so "the file exists somewhere" is not the
    # property that matters - "the server returns it" is. This also works for a
    # onefile build, where the assets live inside the executable and never appear
    # as loose files.
    $port = 18771
    $server = $null
    try {
        $env:SELTRANSFER_APP_DIR = Join-Path $env:TEMP "seltransfer-smoke-$PID"
        $server = Start-Process -FilePath $exe `
            -ArgumentList @('start', '--port', $port, '--host', '127.0.0.1') `
            -PassThru -NoNewWindow `
            -RedirectStandardOutput (Join-Path $env:TEMP 'seltransfer-smoke-out.txt') `
            -RedirectStandardError (Join-Path $env:TEMP 'seltransfer-smoke-err.txt')

        $ready = $false
        for ($attempt = 0; $attempt -lt 40; $attempt++) {
            Start-Sleep -Milliseconds 500
            try {
                $health = Invoke-RestMethod -Uri "http://127.0.0.1:$port/api/health" `
                    -TimeoutSec 2
                $ready = $true
                break
            } catch {
                if ($server.HasExited) {
                    $stderr = Get-Content (Join-Path $env:TEMP 'seltransfer-smoke-err.txt') -Raw -ErrorAction SilentlyContinue
                    Fail "the executable exited during startup. $stderr"
                }
            }
        }
        if (-not $ready) { Fail "the server did not become ready on port $port" }
        # /api/health is a bare {"status":"ok"} liveness probe with no version
        # field, so read the version from /api/status instead. Under
        # Set-StrictMode an absent property is a terminating error, which is what
        # made this step abort a build whose executable was already fine.
        Write-Host "  server started, /api/health ok"

        # -UseBasicParsing is required, not stylistic: without it Windows
        # PowerShell 5.1 drives Invoke-WebRequest through the IE engine, which
        # dies on a null reference while parsing the response and takes the whole
        # build down over an executable that already works.
        $page = Invoke-WebRequest -Uri "http://127.0.0.1:$port/" -TimeoutSec 5 -UseBasicParsing
        if ($page.StatusCode -ne 200) { Fail "GET / returned $($page.StatusCode)" }
        if ($page.Content -notmatch '<html') { Fail "GET / did not return an HTML page" }
        Write-Host "  ok GET / ($($page.Content.Length) bytes)"

        foreach ($asset in @('/static/app.js', '/static/style.css')) {
            $response = Invoke-WebRequest -Uri "http://127.0.0.1:$port$asset" -TimeoutSec 5 -UseBasicParsing
            if ($response.StatusCode -ne 200) { Fail "GET $asset returned $($response.StatusCode)" }
            if ($response.Content.Length -lt 100) { Fail "GET $asset returned only $($response.Content.Length) bytes" }
            Write-Host "  ok GET $asset ($($response.Content.Length) bytes)"
        }

        $status = Invoke-RestMethod -Uri "http://127.0.0.1:$port/api/status" -TimeoutSec 5
        if ($status.status -ne 'online') { Fail "/api/status reported '$($status.status)'" }
        # The executable must not drift from the source tree it was built from.
        if ($status.version -ne $version) {
            Fail "the running executable reports version '$($status.version)' but the source tree is $version"
        }
        Write-Host "  ok GET /api/status (version $($status.version))"
    }
    finally {
        if ($server -and -not $server.HasExited) {
            # /T kills the child too. A onefile build's bootloader spawns the real
            # process and exits, so Stop-Process on the parent leaves an orphan
            # holding the port and failing the next build's smoke test.
            taskkill /PID $server.Id /T /F 2>&1 | Out-Null
            $server.WaitForExit(10000) | Out-Null
        }
        Remove-Item Env:\SELTRANSFER_APP_DIR -ErrorAction SilentlyContinue
        Remove-Item -Recurse -Force (Join-Path $env:TEMP "seltransfer-smoke-$PID") -ErrorAction SilentlyContinue
    }

    Write-Step "Executable smoke test"
    $actual = & $exe version
    if ($LASTEXITCODE -ne 0) { Fail "'SELTRANSFER.exe version' exited $LASTEXITCODE" }
    Write-Host "  version: $actual"
    if ($actual -notmatch [regex]::Escape($version)) {
        Fail "executable reports '$actual' but the source tree is $version"
    }

    & $exe --help | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "'SELTRANSFER.exe --help' exited $LASTEXITCODE" }
    Write-Host "  --help ok"

    & $exe devices | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "'SELTRANSFER.exe devices' exited $LASTEXITCODE" }
    Write-Host "  devices ok"

    & $exe doctor | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "'SELTRANSFER.exe doctor' exited $LASTEXITCODE" }
    Write-Host "  doctor ok"

    Write-Step "Artifact"
    if (-not $NoArchive) {
        $zip = Join-Path $RepoRoot "dist\SELTRANSFER-$version-windows-x64.zip"
        if (Test-Path $zip) { Remove-Item -Force $zip }
        Compress-Archive -Path (Join-Path $RepoRoot 'dist\SELTRANSFER\*') `
                          -DestinationPath $zip -Force
        $zipMb = [math]::Round((Get-Item $zip).Length / 1MB, 1)
        Write-Host "  portable zip: $zip ($zipMb MB)"
    }

    Write-Host ''
    Write-Host "Build complete." -ForegroundColor Green
    Write-Host "Automated checks passed. The remaining items need a machine"
    Write-Host "without Python and a second device:"
    Write-Host "  packaging\CLEAN_MACHINE_CHECKLIST.md"
    Write-Host ''
    Write-Host "Note: the executable writes user data to %LOCALAPPDATA%\SELTRANSFER,"
    Write-Host "not beside itself, so the folder can be deleted to uninstall."
}
catch {
    Write-Host ''
    Write-Host "Build aborted: $_" -ForegroundColor Red
    exit 1
}
finally {
    Pop-Location
}
