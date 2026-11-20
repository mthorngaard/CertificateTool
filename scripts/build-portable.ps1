<#
.SYNOPSIS
  Builds a portable Windows bundle that runs without installing Python.

.DESCRIPTION
  Downloads the official, Python Software Foundation-signed Python build from python.org,
  verifies its SHA-256 hash, installs the 'cryptography' package into it, adds the app and
  a launcher, and produces CertificateTool-windows-x64.zip.

  No code signing is needed: the only executables are the PSF-signed python/pythonw.exe;
  the app itself is plain Python source.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\build-portable.ps1
#>
param(
    [string]$OutDir = (Join-Path $env:LOCALAPPDATA 'CertificateTool-build'),
    [string]$PythonVersion = '3.14.6',
    [string]$PythonSha256 = '75afa83f93b284d19040e24bc440ab741c09582c0d5310504d607a4e08c3dbaf'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$repo = Split-Path $PSScriptRoot -Parent
$root = Join-Path $OutDir 'CertificateTool'
$pyZip = Join-Path $OutDir "python-$PythonVersion-amd64.zip"
$outZip = Join-Path $OutDir 'CertificateTool-windows-x64.zip'

New-Item -ItemType Directory -Force $OutDir | Out-Null
if (Test-Path $root) { Remove-Item $root -Recurse -Force }
if (Test-Path $outZip) { Remove-Item $outZip -Force }

if (-not (Test-Path $pyZip)) {
    Write-Host "Downloading Python $PythonVersion..."
    Invoke-WebRequest "https://www.python.org/ftp/python/$PythonVersion/python-$PythonVersion-amd64.zip" -OutFile $pyZip
}
$hash = (Get-FileHash $pyZip -Algorithm SHA256).Hash.ToLower()
if ($hash -ne $PythonSha256.ToLower()) {
    Remove-Item $pyZip -Force
    throw "SHA-256 mismatch for Python download (got $hash). Aborting."
}

Write-Host 'Extracting Python...'
New-Item -ItemType Directory $root | Out-Null
Expand-Archive $pyZip (Join-Path $root 'python')
$py = Join-Path $root 'python\python.exe'

Write-Host 'Installing cryptography...'
& $py -m pip install --no-warn-script-location --disable-pip-version-check -r (Join-Path $repo 'requirements.txt')
if ($LASTEXITCODE -ne 0) { throw 'pip install failed' }

Write-Host 'Pruning...'
$site = Join-Path $root 'python\Lib\site-packages'
Get-ChildItem $site -Directory | Where-Object { $_.Name -like 'pip*' } | Remove-Item -Recurse -Force
foreach ($d in 'Doc', 'include', 'libs', 'Lib\test', 'Lib\idlelib', 'Lib\turtledemo', 'Lib\ensurepip') {
    Remove-Item (Join-Path $root "python\$d") -Recurse -Force -ErrorAction SilentlyContinue
}
Get-ChildItem (Join-Path $root 'python') -Recurse -Directory -Filter '__pycache__' |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

Write-Host 'Adding app and launcher...'
New-Item -ItemType Directory (Join-Path $root 'app') | Out-Null
Copy-Item (Join-Path $repo 'app.py'), (Join-Path $repo 'csrgen.py') (Join-Path $root 'app')
Copy-Item (Join-Path $repo 'README.md'), (Join-Path $repo 'LICENSE') $root
# -E: ignore PYTHON* env vars, -s: ignore user site-packages, so the bundle is self-contained
Set-Content -Encoding ascii (Join-Path $root 'CertificateTool.bat') (
    "@echo off`r`nstart `"`" `"%~dp0python\pythonw.exe`" -E -s `"%~dp0app\app.py`"`r`n")

Write-Host 'Smoke test...'
$test = Join-Path $OutDir 'smoke_test.py'
@"
import sys
sys.path.insert(0, r'$root\app')
import app
a = app.App()
a.ss_form.v_cn.set('smoke.example.com'); a._ss_generate(); a.update()
assert 'BEGIN CERTIFICATE' in a.ss_out.get('1.0', 'end')
a.csr_form.v_cn.set('smoke.example.com'); a._generate(); a.update()
assert 'BEGIN CERTIFICATE REQUEST' in a.csr_out.get('1.0', 'end')
a.ss_saved = a.key_saved = True
a.destroy()
print('ok')
"@ | Set-Content -Encoding utf8 $test
& $py -E -s $test
if ($LASTEXITCODE -ne 0) { throw 'smoke test failed' }
Remove-Item $test

Write-Host 'Creating zip...'
# tar.exe (built into Windows 10+) writes standard zips with forward slashes;
# .NET Framework's ZipFile (Windows PowerShell 5.1) writes backslashes.
& tar.exe -a -c -f $outZip -C $OutDir 'CertificateTool'
if ($LASTEXITCODE -ne 0) { throw 'tar failed' }
'{0}  ({1:N1} MB)' -f $outZip, ((Get-Item $outZip).Length / 1MB)
