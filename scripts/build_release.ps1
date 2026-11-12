param([string]$Go = 'go', [string]$Output = '.local/release')
$ErrorActionPreference = 'Stop'
$project_root = Split-Path -Parent $PSScriptRoot
$release_dir = [IO.Path]::GetFullPath((Join-Path $project_root $Output))
$version = (Get-Content -LiteralPath (Join-Path $project_root 'version') -Raw).Trim()
if (Test-Path -LiteralPath $release_dir) { throw 'Output already exists; choose a new empty release directory.' }
New-Item -ItemType Directory -Path (Join-Path $release_dir 'bin') -Force | Out-Null
$original_goos = $env:GOOS
$original_goarch = $env:GOARCH
$original_cgo = $env:CGO_ENABLED
try {
    $env:GOOS = 'linux'
    $env:GOARCH = 'amd64'
    $env:CGO_ENABLED = '0'
    foreach ($component in @('web', 'control')) {
        Push-Location (Join-Path $project_root "ui/$component")
        try {
            & $Go build -trimpath -ldflags "-s -w -buildid= -X main.version=$version" -o (Join-Path $release_dir "bin/awg_$component") .
            if ($LASTEXITCODE -ne 0) { throw "Build failed: $component" }
        } finally { Pop-Location }
    }
} finally {
    $env:GOOS = $original_goos
    $env:GOARCH = $original_goarch
    $env:CGO_ENABLED = $original_cgo
}
foreach ($item in @('scripts', 'systemd', 'compose.yaml', 'install.sh', 'awg_vps_control.sh', 'license', 'version')) {
    $source_path = Join-Path $project_root $item
    if (Test-Path -LiteralPath $source_path -PathType Leaf) {
        Copy-Item -LiteralPath $source_path -Destination $release_dir
        continue
    }
    foreach ($file in (Get-ChildItem -LiteralPath $source_path -Recurse -File)) {
        if ($file.FullName -match '[\\/]__pycache__[\\/]' -or $file.Extension -eq '.pyc') { continue }
        $destination = Join-Path $release_dir ([IO.Path]::GetRelativePath($project_root, $file.FullName))
        New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
        Copy-Item -LiteralPath $file.FullName -Destination $destination
    }
}
$source_revision = (& git -C $project_root rev-parse HEAD).Trim()
if (& git -C $project_root status --porcelain) { $source_revision += '-dirty' }
[IO.File]::WriteAllText((Join-Path $release_dir 'source_revision'), ($source_revision + "`n"), [Text.UTF8Encoding]::new($false))
$manifest = @()
foreach ($file in (Get-ChildItem -LiteralPath $release_dir -Recurse -File | Sort-Object FullName)) {
    if ($file.FullName -match '__pycache__') { continue }
    $relative = [IO.Path]::GetRelativePath($release_dir, $file.FullName).Replace('\','/')
    $manifest += (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant() + '  ' + $relative
}
[IO.File]::WriteAllText((Join-Path $release_dir 'manifest.sha256'), (($manifest -join "`n") + "`n"), [Text.UTF8Encoding]::new($false))
Write-Output "Release ${version}: $release_dir"
