param(
    [string]$Go = 'go',
    [string]$Output = ''
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
if (-not $Output) { $Output = Join-Path $projectRoot 'dist/desktop' }
$outputRoot = [IO.Path]::GetFullPath($Output)
New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null
$binary = Join-Path $outputRoot 'awg_vps_desktop.exe'
$archive = Join-Path $outputRoot 'awg_vps_desktop_windows_amd64.zip'
$version = (Get-Content -LiteralPath (Join-Path $projectRoot 'version') -Raw).Trim()
if ($version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$') { throw 'Некорректная версия приложения' }
$oldGOOS = $env:GOOS
$oldGOARCH = $env:GOARCH
$oldGOWORK = $env:GOWORK
try {
    $env:GOOS = 'windows'
    $env:GOARCH = 'amd64'
    $env:GOWORK = 'off'
    & $Go -C (Join-Path $projectRoot 'desktop') build -tags mygo_noinspector -trimpath -ldflags "-s -w -H windowsgui -X main.version=$version" -o $binary .
    if ($LASTEXITCODE -ne 0) { throw 'Сборка desktop завершилась ошибкой' }
    Compress-Archive -LiteralPath $binary -DestinationPath $archive -Force
    $checksum = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText("$archive.sha256", "$checksum  $([IO.Path]::GetFileName($archive))`n", [Text.UTF8Encoding]::new($false))
    Write-Output "Создано: $archive"
} finally {
    $env:GOOS = $oldGOOS
    $env:GOARCH = $oldGOARCH
    $env:GOWORK = $oldGOWORK
}
