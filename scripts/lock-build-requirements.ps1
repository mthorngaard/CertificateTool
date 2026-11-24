<#
.SYNOPSIS
  Regenerates requirements-build.txt: exact versions + SHA-256 hashes of every wheel the portable
  Windows bundle needs (Python 3.14, win_amd64). Run it when requirements.txt changes.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\lock-build-requirements.ps1
#>
param(
    [string]$PythonVersion = '3.14'
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('certtool-lock-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $tmp | Out-Null
try {
    python -m pip download -r (Join-Path $repo 'requirements.txt') --platform win_amd64 `
        --python-version $PythonVersion --only-binary=:all: -d $tmp --disable-pip-version-check
    if ($LASTEXITCODE -ne 0) { throw 'pip download failed' }

    $lines = @(
        "# Locked build dependencies for the portable Windows bundle (Python $PythonVersion, win_amd64).",
        '# Regenerate with scripts\lock-build-requirements.ps1 when requirements.txt changes.'
    )
    foreach ($f in Get-ChildItem $tmp -Filter *.whl | Sort-Object Name) {
        $parts = $f.Name -split '-'
        $hash = (Get-FileHash $f.FullName -Algorithm SHA256).Hash.ToLower()
        $lines += "$($parts[0])==$($parts[1]) --hash=sha256:$hash"
    }
    Set-Content -Encoding ascii (Join-Path $repo 'requirements-build.txt') $lines
    $lines
}
finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
