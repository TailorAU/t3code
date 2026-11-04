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

# Task XML: the account, LeastPrivilege, password logon; SYSTEM only for the mover.
$xml = [xml](Get-ServiceTaskXml -Description 'T3 server' -Account 't3agent' -PwshPath 'C:\Program Files\PowerShell\7\pwsh.exe' -LauncherPath 'C:\ProgramData\T3CodePolicy\service\start-t3.ps1')
$principal = $xml.Task.Principals.Principal
Assert-True ($principal.UserId -eq '.\t3agent') 'task runs as the local account'
Assert-True ($principal.LogonType -eq 'Password' -and $principal.RunLevel -eq 'LeastPrivilege') 'password logon, never elevated'
Assert-True ($null -ne $xml.Task.Triggers.BootTrigger -and [int]$xml.Task.Settings.RestartOnFailure.Count -gt 0) 'starts at boot and restarts'
Assert-True ($xml.Task.Actions.Exec.Arguments.Contains('-File "C:\ProgramData\T3CodePolicy\service\start-t3.ps1"')) 'runs the launcher'
$moverXml = [xml](Get-ServiceTaskXml -Description 'mover' -System -PwshPath 'p.exe' -LauncherPath 'm.ps1' -Trigger Every10Minutes)
Assert-True ($moverXml.Task.Principals.Principal.UserId -eq 'S-1-5-18' -and $null -eq $moverXml.Task.Principals.Principal.SelectSingleNode('*[local-name()="LogonType"]')) 'mover runs as SYSTEM'
Assert-True ($moverXml.Task.Triggers.TimeTrigger.Repetition.Interval -eq 'PT10M') 'mover runs every ten minutes'
$daily = [xml](Get-ServiceTaskXml -Description 'issuer' -Account 't3agent' -PwshPath 'p.exe' -LauncherPath 'i.ps1' -Trigger Daily)
Assert-True ($null -ne $daily.Task.Triggers.CalendarTrigger -and $daily.Task.Settings.ExecutionTimeLimit -eq 'PT15M') 'issuer runs daily with a time limit'
$both = $false; try { [void](Get-ServiceTaskXml -Description 'x' -Account 'a' -System -PwshPath 'p' -LauncherPath 'l') } catch { $both = $true }
Assert-True $both 'account and SYSTEM together are refused'
$escaped = Get-ServiceTaskXml -Description 'a<b>&"' -Account 't3agent' -PwshPath 'p.exe' -LauncherPath 'C:\x&y\l.ps1'
Assert-True ($null -ne ([xml]$escaped)) 'task XML escapes descriptions and paths'

# Folder ACL plan: no Users, interactive user or Everyone anywhere; token for the bridge only.
$plan = Get-T3FolderAclPlan -PolicyDir 'C:\ProgramData\T3CodePolicy' -ClaudeHomeName 'claude-home' -ExtraWorkspaceRoots @('D:\work')
$principals = @($plan | ForEach-Object { $_.Grants } | ForEach-Object Principal | Select-Object -Unique)
Assert-True (@($principals | Where-Object { @('agent', 'bridge', 'OwnerRights') -notcontains $_ }).Count -eq 0) 'only the service accounts and OWNER RIGHTS are granted anything'
$byName = @{}; foreach ($e in $plan) { $byName[$e.Name] = $e }
Assert-True (@($byName['connector'].Grants | Where-Object Principal -eq 'agent').Count -eq 0) 't3agent cannot read the connector token'
Assert-True (@($byName['connector'].Grants | Where-Object Principal -eq 'bridge').Count -eq 1) 't3bridge reads the connector token'
Assert-True (@($byName['t3-home'].Grants | Where-Object Principal -eq 'bridge').Count -eq 0) 't3bridge has no access to the T3 home'
$readBits = [int64][Security.AccessControl.FileSystemRights]'ReadData, ReadExtendedAttributes, ReadAttributes'
$dropAgent = @($byName['connector-drop'].Grants | Where-Object Principal -eq 'agent')
Assert-True (@($dropAgent | Where-Object { ([int64][Security.AccessControl.FileSystemRights]$_.Rights -band $readBits) -ne 0 }).Count -eq 0) 't3agent cannot read or list the drop folder or its files'
Assert-True ($byName['workspace-1'].Path -eq 'D:\work') 'extra workspace roots are planned'
Assert-True ((Format-T3AclPlanEntry $byName['claude-home']) -match 'inside only') 'plan text shows inherit-only grants'

# ACL comparison: exact match passes; extra, missing, inherited and unprotected entries fail.
$sidMap = @{ Administrators = 'S-1-5-32-544'; SYSTEM = 'S-1-5-18'; OwnerRights = 'S-1-3-4'; agent = 'S-1-5-21-9-1001'; bridge = 'S-1-5-21-9-1002' }
function New-Rule($sid, $rights, $inherit = 'ContainerInherit, ObjectInherit', $propagate = 'None', $inherited = $false) {
  [pscustomobject]@{ Sid = $sid; Rights = [int64][Security.AccessControl.FileSystemRights]$rights; Inherit = $inherit; Propagate = $propagate; Allow = $true; IsInherited = $inherited }
}
$good = @((New-Rule 'S-1-5-32-544' 'FullControl'), (New-Rule 'S-1-5-18' 'FullControl'), (New-Rule 'S-1-5-21-9-1002' 'ReadAndExecute, Synchronize'))
$compare = { param($actual, $protected = $true, $owner = 'S-1-5-32-544') @(Compare-T3Acl -Entry $byName['connector'] -Actual $actual -Protected $protected -Owner $owner -SidMap $sidMap).Count }
Assert-True ((& $compare $good) -eq 0) 'the planned ACL matches'
Assert-True ((& $compare ($good + (New-Rule 'S-1-5-32-545' 'ReadAndExecute'))) -gt 0) 'an extra Users entry fails'
Assert-True ((& $compare $good[0..1]) -gt 0) 'a missing grant fails'
Assert-True ((& $compare $good $false) -gt 0) 'inheritance on fails'
Assert-True ((& $compare $good $true 'S-1-5-21-9-1001') -gt 0) 'a non-admin owner fails'
Assert-True ((& $compare ($good + (New-Rule 'S-1-5-21-9-1001' 'Modify' -inherited $true))) -gt 0) 'an inherited entry fails'
$fileRules = @((New-Rule 'S-1-5-32-544' 'FullControl' 'None'), (New-Rule 'S-1-5-18' 'FullControl' 'None'), (New-Rule 'S-1-5-21-9-1002' 'Read, Synchronize' 'None'))
$tokenEntry = [pscustomobject]@{ Grants = @([pscustomobject]@{ Principal = 'bridge'; Rights = 'Read, Synchronize'; Inherit = 'None'; Propagate = 'None' }) }
Assert-True (@(Compare-T3Acl -Entry $tokenEntry -Actual $fileRules -Protected $true -Owner 'S-1-5-32-544' -SidMap $sidMap -File).Count -eq 0) 'a file ACL compares without inheritance flags'

# Groups: only BUILTIN\Users is allowed.
Assert-True ((Get-DisallowedGroups -Groups @([pscustomobject]@{ Name = 'Users'; Sid = 'S-1-5-32-545' })).Count -eq 0) 'Users is allowed'
foreach ($g in @(@('Administrators', 'S-1-5-32-544'), @('Remote Desktop Users', 'S-1-5-32-555'), @('Backup Operators', 'S-1-5-32-551'), @('Hyper-V Administrators', 'S-1-5-32-578'), @('Remote Management Users', 'S-1-5-32-580'))) {
  Assert-True ((Get-DisallowedGroups -Groups @([pscustomobject]@{ Name = $g[0]; Sid = $g[1] })).Count -eq 1) "$($g[0]) is refused"
}

# Launchers: verified-marker check first, fixed environment, unsets, restart loop.
function Test-Parses([string] $text) { $errors = $null; [void][Management.Automation.Language.Parser]::ParseInput($text, [ref]$null, [ref]$errors); return ($errors.Count -eq 0) }
$launcher = Get-T3LauncherText -T3Exe 'C:\Program Files\T3Code\t3.exe' -T3Home 'C:\ProgramData\T3CodePolicy\t3-home' `
  -Environment ([ordered]@{ T3CODE_HOST = '127.0.0.1'; T3CODE_LAN = 'false' }) -MustBeUnset @('HTTPS_PROXY', 'NODE_OPTIONS') `
  -MarkerPath 'C:\ProgramData\T3CodePolicy\service\verified.json' -RequiredFiles @('C:\Program Files\T3Code\t3.exe') -SettingsSeedPath 'C:\ProgramData\T3CodePolicy\service\t3-settings.seed.json' `
  -ServerPidFile 'C:\ProgramData\T3CodePolicy\run\t3-server.json'
Assert-True (Test-Parses $launcher) 'the T3 launcher parses'
Assert-True ($launcher.IndexOf('PSModulePath') -lt $launcher.IndexOf('while')) 'the launcher pins its module path'
Assert-True ($launcher.Contains('t3-server.json') -and $launcher.IndexOf('-PassThru') -lt $launcher.IndexOf('WriteAllText($pidFile')) 'the launcher publishes the server PID it started'
Assert-True ($launcher.Contains("`$env:T3CODE_HOST = '127.0.0.1'")) 'launcher sets the policy environment'
Assert-True ($launcher.Contains("Remove-Item -LiteralPath 'Env:HTTPS_PROXY'")) 'launcher clears proxy variables'
Assert-True ($launcher.Contains("`$env:T3CODE_HOME = 'C:\ProgramData\T3CodePolicy\t3-home'")) 'launcher pins the T3 home'
$loop = $launcher.IndexOf('while')
Assert-True ($launcher.IndexOf('Test-T3Verified', $loop) -gt $loop -and $launcher.IndexOf('Test-T3Verified', $loop) -lt $launcher.IndexOf('Start-Process')) 'launcher checks the marker before every start'
Assert-True ($launcher.Contains('t3-settings.seed.json')) 'the launcher (t3agent) seeds T3 settings, not the installer'
$refused = $false
try { [void](Get-T3LauncherText -T3Exe 'x.exe' -T3Home 'h' -Environment ([ordered]@{ 'PATH' = 'x' }) -MustBeUnset @() -MarkerPath 'm' -RequiredFiles @('x') -ServerPidFile 'p') } catch { $refused = $true }
Assert-True $refused 'launcher refuses non-T3CODE variables'
$quoted = Get-T3LauncherText -T3Exe "C:\it's\t3.exe" -T3Home 'h' -Environment ([ordered]@{}) -MustBeUnset @() -MarkerPath 'm' -RequiredFiles @("C:\it's\t3.exe") -ServerPidFile 'p'
Assert-True ($quoted.Contains("'C:\it''s\t3.exe'") -and (Test-Parses $quoted)) 'launcher quotes paths safely'
$bridge = Get-BridgeLauncherText -BridgeExe 'C:\Program Files\T3Bridge\bridge.exe' -TokenPath 'C:\ProgramData\T3CodePolicy\connector\token' `
  -KeyPath 'C:\ProgramData\T3CodePolicy\bridge\tailor-api-key' -T3Url 'http://127.0.0.1:3773' -MustBeUnset @('HTTPS_PROXY') -MarkerPath 'm' -RequiredFiles @('b') `
  -ServerPidFile 'C:\ProgramData\T3CodePolicy\run\t3-server.json' -AgentSid 'S-1-5-21-9-1001' -T3Port 3773
Assert-True ($bridge.Contains("`$env:T3_BRIDGE_TOKEN_FILE = 'C:\ProgramData\T3CodePolicy\connector\token'") -and (Test-Parses $bridge)) 'bridge gets the token path, not the token'
$bridgeLoop = $bridge.IndexOf('while')
Assert-True ($bridge.IndexOf('Test-T3ServerListener', $bridgeLoop) -gt $bridgeLoop -and $bridge.IndexOf('Test-T3ServerListener', $bridgeLoop) -lt $bridge.IndexOf('bridge.exe', $bridgeLoop)) 'the bridge starts only after the listener check'
Assert-True ($bridge.Contains('-LocalPort 3773') -and $bridge.Contains("'S-1-5-21-9-1001'") -and $bridge.Contains('T3_BRIDGE_SERVER_PID_FILE')) 'the listener check uses the port, the agent SID and the PID file'
$issuer = Get-TokenIssuerText -T3Exe 't3.exe' -T3Home 'h' -DropPath 'C:\ProgramData\T3CodePolicy\connector-drop\token' -Ttl '7d' -MustBeUnset @() -MarkerPath 'm' -RequiredFiles @('t3.exe')
Assert-True (Test-Parses $issuer) 'the issuer parses'
Assert-True ($issuer.IndexOf('CreateNew') -lt $issuer.IndexOf('session issue')) 'the issuer claims the drop file before issuing'
Assert-True ($issuer.Contains('RevokeAllPrevious') -and $issuer.Contains('-Skip $keep') -and $issuer -notmatch 'Write-(Host|Output)[^\n]*issued') 'daily keeps one previous token, -RevokeAllPrevious keeps none, and the token is never printed'
Assert-True ($issuer.Contains('$attempt -le 2') -or $issuer.Contains('`$attempt -le 2')) 'issuing is retried once'
Assert-True ($issuer.Contains('sessionId -ne $newSession')) 'the new session is never revoked'
$mover = Get-TokenMoverText -DropPath 'C:\d\token' -TokenPath 'C:\c\token' -AgentSid 'S-1-5-21-9-1001' -BridgeSid 'S-1-5-21-9-1002'
Assert-True (Test-Parses $mover) 'the mover parses'
Assert-True ($mover.Contains('ReparsePoint') -and $mover.Contains('hardlink') -and $mover.Contains("'S-1-5-21-9-1001'")) 'the mover refuses links and foreign owners'
Assert-True ($mover.Contains('FileSystemAclExtensions]::Create') -and $mover.Contains('Move(')) 'the mover sets the ACL at creation, then renames'
Assert-True ($mover.Contains('[byte[]]::new(4097)') -and -not $mover.Contains('$in.Length') -and -not $mover.Contains('$item.Length')) 'the mover reads a bounded number of bytes from the open handle'
Assert-True ($mover.IndexOf('Sweep') -lt $mover.IndexOf('Test-Path -LiteralPath $drop')) 'the mover sweeps the drop folder first'
Assert-True ($mover.Contains('PSModulePath')) 'the mover pins its module path'

# Marker check: refuses without a marker, and refuses a marker a non-admin owns.
$work = Join-Path ([IO.Path]::GetTempPath()) ('t3sa-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
try {
  $target = Join-Path $work 'tool.exe'; Set-Content -LiteralPath $target -Value 'one' -NoNewline
  $markerPath = Join-Path $work 'verified.json'
  . ([scriptblock]::Create((Get-MarkerCheckText -MarkerPath $markerPath -RequiredFiles @($target))))
  Assert-True ((Test-T3Verified) -match 'no verified marker') 'no marker: refused'
  @{ files = @(@{ path = $target; sha256 = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant() }) } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $markerPath
  $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isAdmin) {
    Assert-True ((Test-T3Verified) -match 'not owned by an administrator') 'a marker owned by a non-admin is refused'
  }
} finally { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }


# Folder plan: probe (create only), run (agent modify, bridge read), git-config (agent read).
$plan2 = Get-T3FolderAclPlan -PolicyDir 'C:\P' -ClaudeHomeName 'claude-home'
$by2 = @{}; foreach ($e in $plan2) { $by2[$e.Name] = $e }
Assert-True ($null -ne $by2['probe'] -and @($by2['probe'].Grants | Where-Object { $_.Principal -eq 'agent' -and $_.Rights -match 'Read' -and $_.Rights -notmatch 'ReadPermissions' }).Count -eq 0) 'the agent cannot read the probe folder'
Assert-True (@($by2['run'].Grants | Where-Object Principal -eq 'bridge').Count -eq 1 -and @($by2['run'].Grants | Where-Object { $_.Principal -eq 'bridge' -and $_.Rights -match 'Modify|Write' }).Count -eq 0) 'the bridge reads the run folder only'
Assert-True (@($by2['git-config'].Grants | Where-Object { $_.Principal -eq 'agent' -and $_.Rights -match 'Modify|Write' }).Count -eq 0) 'the agent cannot change the global git config'

# Listener ownership (bridge).
Assert-True ($null -eq (Test-ListenerOwnership -ListenerPids @(4242) -PublishedPid 4242)) 'the published T3 PID holding the port passes'
Assert-True ($null -ne (Test-ListenerOwnership -ListenerPids @(999) -PublishedPid 4242)) 'another process on the port fails'
Assert-True ($null -ne (Test-ListenerOwnership -ListenerPids @(4242, 999) -PublishedPid 4242)) 'a second listener fails'
Assert-True ($null -ne (Test-ListenerOwnership -ListenerPids @() -PublishedPid 4242)) 'nothing listening fails'
Assert-True ($null -ne (Test-ListenerOwnership -ListenerPids @(4242) -PublishedPid $null)) 'no published PID fails'
$listenerText = Get-ListenerCheckText -ServerPidFile 'C:\P\run\t3-server.json' -AgentSid 'S-1-5-21-9-1001' -T3Port 3773
Assert-True (Test-Parses $listenerText) 'the listener check parses'

# User rights: only our SIDs added to our four rights.
$sidA = 'S-1-5-21-9-1001'; $sidB = 'S-1-5-21-9-1002'
$before = "[Unicode]`r`nUnicode=yes`r`n[Privilege Rights]`r`nSeBatchLogonRight = *S-1-5-32-544`r`nSeShutdownPrivilege = *S-1-5-32-545`r`n"
$after = Update-UserRightsInf -InfText $before -Changes (Get-ServiceAccountRightsPlan -Sid $sidA)
$after = Update-UserRightsInf -InfText $after -Changes (Get-ServiceAccountRightsPlan -Sid $sidB)
Assert-True (@(Compare-UserRightsSnapshot -BeforeText $before -AfterText $after -AllowedSids @($sidA, $sidB)).Count -eq 0) 'the install diff is exactly our four rights'
$extraRight = Update-UserRightsInf -InfText $after -Changes ([ordered]@{ SeServiceLogonRight = @{ Add = $sidA } })
Assert-True (@(Compare-UserRightsSnapshot -BeforeText $before -AfterText $extraRight -AllowedSids @($sidA, $sidB)).Count -eq 1) 'another right for our account is reported'
$otherSid = Update-UserRightsInf -InfText $after -Changes ([ordered]@{ SeBatchLogonRight = @{ Add = 'S-1-5-21-9-7777' } })
Assert-True (@(Compare-UserRightsSnapshot -BeforeText $before -AfterText $otherSid -AllowedSids @($sidA, $sidB)).Count -eq 1) 'another SID in our right is reported'
$lost = Update-UserRightsInf -InfText $after -Changes ([ordered]@{ SeShutdownPrivilege = @{ Remove = 'S-1-5-32-545' } })
Assert-True (@(Compare-UserRightsSnapshot -BeforeText $before -AfterText $lost -AllowedSids @($sidA, $sidB)).Count -eq 1) 'a removed right is reported'
Assert-True (@(Compare-UserRightsSnapshot -BeforeText $before -AfterText $after).Count -gt 0) 'with no allowed SIDs (uninstall), any change is reported'

# Uninstall diff against the pre-install snapshot.
$snapBefore = [ordered]@{ variables = [ordered]@{ T3CODE_X = 'a' }; tasks = @(); taskFolder = $false; firewallRules = @(); managedSettings = '{"a":1}'; rights = $before }
$same = [ordered]@{ variables = [ordered]@{ T3CODE_X = 'a' }; tasks = @(); taskFolder = $false; firewallRules = @(); managedSettings = '{"a":1}'; rights = $before }
Assert-True (@(Compare-PreInstallSnapshot -Before ($snapBefore | ConvertTo-Json -Depth 5 | ConvertFrom-Json) -After $same).Count -eq 0) 'a clean uninstall shows no difference'
$dirty = [ordered]@{ variables = [ordered]@{ T3CODE_X = 'b'; T3CODE_Y = '1' }; tasks = @('\T3CodePolicy\T3 server'); taskFolder = $true; firewallRules = @('T3Policy-1'); managedSettings = '{"a":2}'; rights = $after }
$diff = @(Compare-PreInstallSnapshot -Before $snapBefore -After $dirty)
foreach ($want in 'T3CODE_X', 'T3CODE_Y', 'task \T3CodePolicy', 'task folder', 'firewall rule', 'managed-settings', 'user rights') {
  Assert-True (@($diff | Where-Object { $_.Contains($want) }).Count -gt 0) "the uninstall diff reports $want"
}

# Task security descriptors: only admins may change, start or stop.
Assert-True (@(Get-TaskSecurityIssues -Sddl 'D:(A;;FA;;;BA)(A;;FA;;;SY)(A;;FR;;;AU)').Count -eq 0) 'admins full, others read: fine'
Assert-True (@(Get-TaskSecurityIssues -Sddl 'D:(A;;FA;;;BA)(A;;FRFX;;;AU)').Count -eq 1) 'others may run it: reported'
Assert-True (@(Get-TaskSecurityIssues -Sddl 'D:(A;;GA;;;BU)').Count -eq 1) 'users full: reported'

# The agent probe and its judgement.
$probeTests = [ordered]@{ 'read-token' = @{ Path = 'C:\P\connector\token'; Mode = 'Read' }; 'create-in-service' = @{ Path = 'C:\P\service'; Mode = 'CreateIn' } }
$probeText = Get-AgentProbeText -ResultPath 'C:\P\probe\result.json' -Tests $probeTests
Assert-True (Test-Parses $probeText) 'the probe parses'
Assert-True ($probeText.Contains('whoami.exe" /priv') -and $probeText.Contains('/groups') -and $probeText.Contains('CreateNew')) 'the probe records privileges and groups and writes create-only'
Assert-True ($probeText -notmatch 'ReadAll|Get-Content') 'the probe never reads file content'
$badName = $false; try { [void](Get-AgentProbeText -ResultPath 'r' -Tests ([ordered]@{ 'x; rm' = @{ Path = 'p'; Mode = 'Read' } })) } catch { $badName = $true }
Assert-True $badName 'probe test names are restricted'
$goodResult = [pscustomobject]@{ user = $sidA; privileges = @('SeChangeNotifyPrivilege', 'SeIncreaseWorkingSetPrivilege'); groups = @('S-1-5-32-545', 'S-1-16-8192'); tests = [pscustomobject]@{ 'read-token' = 'denied'; 'create-in-service' = 'denied' } }
$expectedProbe = [ordered]@{ 'read-token' = 'denied'; 'create-in-service' = 'denied' }
Assert-True (@(Test-AgentProbeResult -Result $goodResult -Expected $expectedProbe -AgentSid $sidA).Count -eq 0) 'a standard agent passes'
$badResult = [pscustomobject]@{ user = $sidA; privileges = @('SeChangeNotifyPrivilege', 'SeDebugPrivilege'); groups = @('S-1-5-32-544', 'S-1-16-12288'); tests = [pscustomobject]@{ 'read-token' = 'allowed'; 'create-in-service' = 'denied' } }
Assert-True (@(Test-AgentProbeResult -Result $badResult -Expected $expectedProbe -AgentSid $sidA).Count -eq 4) 'extra privilege, admin group, high integrity and a readable token are all reported'
Assert-True (@(Test-AgentProbeResult -Result $goodResult -Expected $expectedProbe -AgentSid $sidB).Count -eq 1) 'a probe run as another account is reported'

# git version floor.
Assert-True (Test-GitVersionAtLeast -VersionText 'git version 2.51.2.windows.1' -Minimum '2.50.1') '2.51.2 passes 2.50.1'
Assert-True (-not (Test-GitVersionAtLeast -VersionText 'git version 2.49.0.windows.1' -Minimum '2.50.1')) '2.49.0 fails'
Assert-True (-not (Test-GitVersionAtLeast -VersionText 'nonsense' -Minimum '2.50.1')) 'an unreadable version fails'

# Task XML extra arguments (the rotate-now task) and their restriction.
$withArgs = [xml](Get-ServiceTaskXml -Description 'rotate now' -Account 't3agent' -PwshPath 'p.exe' -LauncherPath 'i.ps1' -Trigger OnDemand -ExtraArguments '-RevokeAllPrevious')
Assert-True ($withArgs.Task.Actions.Exec.Arguments.EndsWith('"i.ps1" -RevokeAllPrevious')) 'extra arguments follow the launcher'
$badArgs = $false; try { [void](Get-ServiceTaskXml -Description 'x' -Account 'a' -PwshPath 'p' -LauncherPath 'l' -ExtraArguments '; calc') } catch { $badArgs = $true }
Assert-True $badArgs 'extra arguments are restricted'

# The managed copy of a password can be wiped in place.
$secret = [string]::new([char[]]'not-a-real-password')
Clear-ManagedString $secret
Assert-True ($secret.Trim([char]0).Length -eq 0) 'the managed string copy is zeroed'

# Emergency revoke: the plan, in order, touching only the expected targets.
$tasks = [ordered]@{ Server = 'T3 server'; Bridge = 'T3 bridge'; Issuer = 'T3 token issuer'; Mover = 'T3 token mover'; Rotate = 'T3 key rotation'; RotateToken = 'T3 token rotate now'; Probe = 'T3 self-check probe' }
$revoke = Get-EmergencyRevokePlan -Tasks $tasks -Accounts @('t3agent', 't3bridge') -MarkerPath 'C:\P\service\verified.json' `
  -TokenPath 'C:\P\connector\token' -DropDir 'C:\P\connector-drop' -RevokeLogPath 'C:\P\state\revoke-log.json'
$actions = @($revoke | ForEach-Object Action)
$indexOf = { param($action, $target) for ($n = 0; $n -lt $revoke.Count; $n++) { if ($revoke[$n].Action -eq $action -and ($null -eq $target -or $revoke[$n].Target -eq $target)) { return $n } }; return -1 }
Assert-True ($actions[0] -eq 'RemoveMarker') 'the marker goes first, so nothing restarts during the revoke'
foreach ($name in 'T3 server', 'T3 bridge', 'T3 token issuer', 'T3 token mover', 'T3 token rotate now') {
  Assert-True ((& $indexOf 'DisableTask' $name) -ge 0) "$name is disabled"
  Assert-True ((& $indexOf 'DisableTask' $name) -lt (& $indexOf 'RotateKeys' $null)) "$name is disabled before the keys rotate"
}
Assert-True ((& $indexOf 'KillProcesses' 't3agent') -lt (& $indexOf 'RotateKeys' 'T3 key rotation')) 'processes are stopped before the rotation'
Assert-True ((& $indexOf 'KillProcesses' 't3bridge') -ge 0) 'bridge processes are stopped'
Assert-True ((& $indexOf 'DeleteFile' 'C:\P\connector\token') -gt (& $indexOf 'RotateKeys' $null)) 'the token is deleted'
Assert-True ((& $indexOf 'EmptyFolder' 'C:\P\connector-drop') -ge 0) 'the drop folder is emptied'
Assert-True ($actions[-1] -eq 'AppendRevokeLog') 'the revoke is logged last'
Assert-True (@($revoke | Where-Object { $_.Action -eq 'EnableTask' -or $_.Action -eq 'StartTask' }).Count -eq 0) 'nothing is enabled or started'
$text = ($revoke | ForEach-Object { "$($_.Action) $($_.Target) $($_.Detail)" }) -join "`n"
Assert-True ($text -notmatch 'tailor_sk_|Bearer ') 'the plan names no secret'

# Key rotation script: runs as t3agent, checks t3.exe's hash, uses T3's own CLI, prints no key.
$rotate = Get-KeyRotationText -T3Exe 'C:\Program Files\T3Code\t3.exe' -T3Home 'C:\P\t3-home' -PolicyPath 'C:\P\t3-policy.json' -MustBeUnset @('NODE_OPTIONS')
Assert-True (Test-Parses $rotate) 'the rotation script parses'
Assert-True ($rotate.IndexOf('t3ExeSha256') -lt $rotate.IndexOf('rotate-signing-keys')) 'it checks the t3 hash before rotating'
Assert-True ($rotate.Contains("auth rotate-signing-keys --base-dir")) 'it uses T3''s own rotation command'
Assert-True ($rotate -notmatch 'Get-Content[^\n]*secrets') 'it never reads a key'
$onDemand = [xml](Get-ServiceTaskXml -Description 'rotate' -Account 't3agent' -PwshPath 'p.exe' -LauncherPath 'r.ps1' -Trigger OnDemand)
Assert-True ($onDemand.Task.Triggers.ChildNodes.Count -eq 0 -and $onDemand.Task.Principals.Principal.LogonType -eq 'Password') 'the rotation task has no trigger and runs as the account'

# Signing key freshness against the revoke log.
$t0 = [DateTime]::new(2026, 11, 5, 1, 0, 0, [DateTimeKind]::Utc)
Assert-True (Test-SigningKeyFresh -KeyWrittenUtc $t0 -LastRevokeUtc $null).Ok 'no revoke recorded: pass'
Assert-True (Test-SigningKeyFresh -KeyWrittenUtc $t0.AddSeconds(5) -LastRevokeUtc $t0).Ok 'a key written after the revoke passes'
Assert-True (-not (Test-SigningKeyFresh -KeyWrittenUtc $t0.AddSeconds(-5) -LastRevokeUtc $t0).Ok) 'an older key fails'
Assert-True (-not (Test-SigningKeyFresh -KeyWrittenUtc $null -LastRevokeUtc $t0).Ok) 'a missing key after a revoke fails'
Assert-True ($null -eq (Get-LastRevokeTime -LogText $null)) 'no log: no revoke time'
$logText = (@(@{ at = '2026-11-05T01:00:00.0000000Z' }, @{ at = '2026-11-05T03:00:00.0000000Z' }, @{ at = '2026-11-05T02:00:00.0000000Z' }) | ConvertTo-Json)
Assert-True ((Get-LastRevokeTime -LogText $logText) -eq [DateTime]::new(2026, 11, 5, 3, 0, 0, [DateTimeKind]::Utc)) 'the latest revoke counts'
$single = (ConvertTo-Json -InputObject @(@{ at = '2026-11-05T01:00:00.0000000Z' }))
Assert-True ((Get-LastRevokeTime -LogText $single) -eq $t0) 'a one-entry log is read'

# The installer refuses to run from anywhere but the protected copy (here: the repository).
$installer = Join-Path $PSScriptRoot '..' 'install-policy.ps1'
$output = & pwsh -NoProfile -NonInteractive -File $installer -ExpectedSha256 'script=0' -T3Exe 'C:\none\t3.exe' -ClaudeExe 'C:\none\claude.exe' -WhatIf 2>&1 | Out-String
Assert-True ($output -match 'protected copy') "the installer refuses to run outside the protected copy: $output"
Assert-True ($LASTEXITCODE -ne 0) 'and exits non-zero'

if ($failures.Count -gt 0) {
  $failures | Select-Object -Unique | ForEach-Object { Write-Host "FAIL: $_" }
  exit 1
}
Write-Host 'ServiceAccounts: all checks passed.'
exit 0
