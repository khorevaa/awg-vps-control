param([Parameter(Mandatory=$true)][string]$SshTarget, [int]$LocalPort = 8787)
if ($LocalPort -lt 1024 -or $LocalPort -gt 65535) { throw 'Invalid local port' }
if ($SshTarget.StartsWith('-') -or $SshTarget -match '[\s\x00-\x1f]') { throw 'Invalid SSH target' }
Write-Host 'Keep this terminal open. Use the URL returned by awg-vps-control ui-access.'
ssh -N -o ExitOnForwardFailure=yes -L "localhost:${LocalPort}:/run/awg_vps_web/web.sock" $SshTarget
exit $LASTEXITCODE
