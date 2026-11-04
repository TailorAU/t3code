#Requires -Version 7.2
# Tailor fork: tests for the pure planning functions of ServiceAccounts.psm1.
# Run: pwsh -NoProfile -File tailor/policy/tests/ServiceAccounts.Tests.ps1  (exit 0 = pass)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..' 'ServiceAccounts.psm1') -Force

$failures = [System.Collections.Generic.List[string]]::new()
function Assert-True([bool] $condition, [string] $message) { if (-not $condition) { $failures.Add($message) } }

# Passwords: long, every class present, different each time.
$seen = [System.Collections.Generic.HashSet[string]]::new()
for ($n = 0; $n -lt 50; $n++) {
  $chars = New-ServiceAccountPasswordChars
  $text = [string]::new($chars)
  Assert-True ($text.Length -eq 40) 'password is 40 characters'
  Assert-True ($text -cmatch '[A-Z]' -and $text -cmatch '[a-z]' -and $text -match '[0-9]' -and $text -match '[^A-Za-z0-9]') 'password has every character class'
  Assert-True ($seen.Add($text)) 'passwords do not repeat'
  [Array]::Clear($chars, 0, $chars.Length)
  Assert-True ([string]::new($chars).Trim([char]0).Length -eq 0) 'the char array can be zeroed'
}

# User rights: add, idempotent, keep other lines byte for byte, create missing lines, remove.
$sid = 'S-1-5-21-1-2-3-1001'
$inf = "[Unicode]`r`nUnicode=yes`r`n[Privilege Rights]`r`nSeBatchLogonRight = *S-1-5-32-544,*S-1-5-32-551`r`nSeShutdownPrivilege = *S-1-5-32-545`r`n[Version]`r`nsignature=`"`$CHICAGO`$`"`r`nRevision=1"
$plan = Get-ServiceAccountRightsPlan -Sid $sid
$updated = Update-UserRightsInf -InfText $inf -Changes $plan
Assert-True ($updated -match 'SeBatchLogonRight = \*S-1-5-32-544,\*S-1-5-32-551,\*S-1-5-21-1-2-3-1001') 'batch logon right added to the existing line'
foreach ($right in 'SeDenyInteractiveLogonRight', 'SeDenyRemoteInteractiveLogonRight', 'SeDenyNetworkLogonRight') {
  Assert-True ($updated -match "$right = \*$([regex]::Escape($sid))") "$right line created"
}
Assert-True ($updated.Contains('SeShutdownPrivilege = *S-1-5-32-545')) 'unrelated rights kept'
Assert-True ($updated.Contains("`r`n")) 'CRLF kept'
$denyIndex = $updated.IndexOf('SeDenyInteractiveLogonRight'); $versionIndex = $updated.IndexOf('[Version]')
Assert-True ($denyIndex -lt $versionIndex) 'new lines stay inside [Privilege Rights]'
Assert-True ((Update-UserRightsInf -InfText $updated -Changes $plan) -eq $updated) 'adding again changes nothing'
$remove = [ordered]@{}; foreach ($right in $plan.Keys) { $remove[$right] = @{ Remove = $sid } }
$removed = Update-UserRightsInf -InfText $updated -Changes $remove
Assert-True ($removed -match 'SeBatchLogonRight = \*S-1-5-32-544,\*S-1-5-32-551(\r?\n)') 'removal restores the original batch line'
Assert-True ($removed -notmatch 'SeDenyInteractiveLogonRight') 'removal drops a line it left empty'
Assert-True ($removed -eq $inf) 'add then remove returns the original text'

# Task plan: the account, never elevated, at startup, restarts, password logon.
$task = Get-ServiceTaskPlan -TaskName 'T3 server' -Account 't3agent' -PwshPath 'C:\Program Files\PowerShell\7\pwsh.exe' -LauncherPath 'C:\ProgramData\T3CodePolicy\service\start-t3.ps1'
Assert-True ($task.User -eq '.\t3agent') 'task runs as the local account'
Assert-True ($task.LogonType -eq 'Password' -and $task.RunLevel -eq 'Limited') 'password logon, not elevated'
Assert-True ($task.Trigger -eq 'AtStartup' -and $task.RestartCount -gt 0) 'starts at boot and restarts'
Assert-True ($task.Arguments.Contains('-File "C:\ProgramData\T3CodePolicy\service\start-t3.ps1"')) 'runs the launcher'

# Access plan: no Users, no interactive user, token only for the bridge.
$access = Get-T3AccessPlan -PolicyDir 'C:\ProgramData\T3CodePolicy' -AgentAccount 't3agent' -BridgeAccount 't3bridge'
foreach ($entry in $access) {
  Assert-True (-not ($entry.Access -match '^Users')) "no BUILTIN\Users access on $($entry.Path)"
}
$connector = $access | Where-Object { $_.Path.EndsWith('\connector') }
Assert-True (($connector.Access -join ';') -notmatch 't3agent') 't3agent cannot read the connector token'
Assert-True (($connector.Access -join ';') -match 't3bridge: read') 't3bridge reads the connector token'
$home3 = $access | Where-Object { $_.Path.EndsWith('\t3-home') }
Assert-True (($home3.Access -join ';') -notmatch 't3bridge') 't3bridge has no access to the T3 home'

# Launchers: fixed environment, unsets, restart loop; hostile names refused.
$launcher = Get-T3LauncherText -T3Exe 'C:\Program Files\T3Code\t3.exe' -T3Home 'C:\ProgramData\T3CodePolicy\t3-home' `
  -Environment ([ordered]@{ T3CODE_HOST = '127.0.0.1'; T3CODE_LAN = 'false' }) -MustBeUnset @('HTTPS_PROXY', 'NODE_OPTIONS')
Assert-True ($launcher.Contains("`$env:T3CODE_HOST = '127.0.0.1'")) 'launcher sets the policy environment'
Assert-True ($launcher.Contains("Remove-Item -LiteralPath 'Env:HTTPS_PROXY'")) 'launcher clears proxy variables'
Assert-True ($launcher.Contains("`$env:T3CODE_HOME = 'C:\ProgramData\T3CodePolicy\t3-home'")) 'launcher pins the T3 home'
Assert-True ($launcher.Contains('serve')) 'launcher runs t3 serve'
$refused = $false
try { [void](Get-T3LauncherText -T3Exe 'x.exe' -T3Home 'h' -Environment ([ordered]@{ 'PATH' = 'x' }) -MustBeUnset @()) } catch { $refused = $true }
Assert-True $refused 'launcher refuses non-T3CODE variables'
$quoted = Get-T3LauncherText -T3Exe "C:\it's\t3.exe" -T3Home 'h' -Environment ([ordered]@{}) -MustBeUnset @()
Assert-True ($quoted.Contains("'C:\it''s\t3.exe'")) 'launcher quotes paths safely'
$bridge = Get-BridgeLauncherText -BridgeExe 'C:\Program Files\T3Bridge\bridge.exe' -TokenPath 'C:\ProgramData\T3CodePolicy\connector\token' `
  -KeyPath 'C:\ProgramData\T3CodePolicy\bridge\tailor-api-key' -T3Url 'http://127.0.0.1:3773' -MustBeUnset @('HTTPS_PROXY')
Assert-True ($bridge.Contains("`$env:T3_BRIDGE_TOKEN_FILE = 'C:\ProgramData\T3CodePolicy\connector\token'")) 'bridge gets the token path, not the token'

if ($failures.Count -gt 0) {
  $failures | Select-Object -Unique | ForEach-Object { Write-Host "FAIL: $_" }
  exit 1
}
Write-Host 'ServiceAccounts: all checks passed.'
exit 0
