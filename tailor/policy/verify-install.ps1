#Requires -Version 7.2
<#
.SYNOPSIS
  Read-only self-check of a T3 Code policy install. Run elevated, any time.

.DESCRIPTION
  install-policy.ps1 runs this at the end of every install. It reports PASS or FAIL per check
  and changes nothing on the machine, with two exceptions: on a full PASS it writes the
  verified marker (%ProgramData%\T3CodePolicy\service\verified.json, written by
  administrators only, readable by the service accounts) and on any FAIL it removes it. The
  launchers refuse to start t3 serve, the bridge or the token issuer without a marker whose
  recorded SHA-256 values match the files they use. (Two checks use scratch files in the
  temp folder: a secedit export and a throwaway git repository.)

  Checks:
    installer      the protected copy is admin-controlled and matches the installed hashes
    acl:<folder>   every planned folder exists with exactly the planned ACL (Get-T3FolderAclPlan)
    token          the connector token (once issued) is readable by t3bridge only; no ACE for
                   the interactive user, Users, Authenticated Users, Everyone or INTERACTIVE on
                   the token or the policy folders
    account:<name> exists, enabled, in no group but Users, batch logon granted, interactive,
                   RDP and network logon denied, no other right assigned to it directly
    task:<name>    registered, runs as the right account, LogonType Password (SYSTEM for the
                   mover), RunLevel LeastPrivilege, runs the right launcher
    firewall       every profile on; each program has its Block rules with the right image path
    managed        the machine managed-settings entries are present, parentSettingsBehavior is
                   "merge", and everything else equals the install-time baseline
    hashes         t3, Claude, the bridge and every service file match what was installed
    git-hooks      the hooks folder is empty, and with T3's git settings a repository hook
                   does not run
  Then it prints the checks that need a person (first-run checklist).
#>
[CmdletBinding()]
param(
  # Used by install-policy.ps1, which has already loaded the modules from verified bytes.
  [switch] $AlreadyLoaded,
  # Report only; leave any marker as it is.
  [switch] $NoMarker
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$ProgramDataFolder = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
$PolicyDir = Join-Path $ProgramDataFolder 'T3CodePolicy'
$InstallerDir = Join-Path $PolicyDir 'installer'
$ServiceDir = Join-Path $PolicyDir 'service'
$MarkerPath = Join-Path $ServiceDir 'verified.json'
$InstalledPath = Join-Path $PolicyDir 't3-policy.json'
$BaselinePath = Join-Path $PolicyDir 'state\managed-settings.baseline.json'
$TokenPath = Join-Path $PolicyDir 'connector\token'
$AdminSids = @('S-1-5-32-544', 'S-1-5-18', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
$WriteMask = 0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000

$results = [System.Collections.Generic.List[object]]::new()
function Add-Check([string] $name, [bool] $ok, [string] $detail = '') {
  $results.Add([pscustomobject]@{ Check = $name; Result = $(if ($ok) { 'PASS' } else { 'FAIL' }); Detail = $detail })
}
function Invoke-Check([string] $name, [scriptblock] $body) {
  try { $detail = & $body; Add-Check $name $true ([string]$detail) } catch { Add-Check $name $false $_.Exception.Message }
}
function Get-Sha([string] $path) { return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Assert-AdminOnlyWrite([string] $path) {
  $item = Get-Item -LiteralPath $path -Force
  if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "$path is a reparse point" }
  $acl = Get-Acl -LiteralPath $path
  $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
  if ($AdminSids -notcontains $owner) { throw "$path is owned by $owner" }
  foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
    if ($rule.AccessControlType -ne 'Allow' -or $AdminSids -contains $rule.IdentityReference.Value) { continue }
    if (($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
    if (([int64]$rule.FileSystemRights -band $WriteMask) -ne 0) { throw "$($rule.IdentityReference) can write $path" }
  }
}

$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host 'FAIL  elevated: run verify-install.ps1 from an elevated PowerShell.'
  return $false
}
if (-not (Test-Path -LiteralPath $InstalledPath)) {
  Write-Host "FAIL  installed: $InstalledPath not found; run install-policy.ps1 first."
  return $false
}
$policy = Get-Content -LiteralPath $InstalledPath -Raw | ConvertFrom-Json
$installed = $policy.installed

# Modules: from the install run, or loaded here from bytes that match the installed hashes.
Invoke-Check 'installer' {
  Assert-AdminOnlyWrite $InstallerDir
  $expected = @{}
  foreach ($pair in ([string]$installed.installerSha256).Split(',')) { $kv = $pair.Split('=', 2); $expected[$kv[0]] = $kv[1] }
  $files = [ordered]@{ script = 'install-policy.ps1'; verify = 'verify-install.ps1'; template = 't3-policy.template.json'; module = 'ManagedSettingsMerge.psm1'; accounts = 'ServiceAccounts.psm1' }
  foreach ($key in $files.Keys) {
    $path = Join-Path $InstallerDir $files[$key]
    Assert-AdminOnlyWrite $path
    $data = [IO.File]::ReadAllBytes($path)
    if ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($data)).ToLowerInvariant() -ne $expected[$key]) { throw "$($files[$key]) differs from the installed version" }
    if (-not $AlreadyLoaded -and ($key -eq 'module' -or $key -eq 'accounts')) {
      $text = [Text.UTF8Encoding]::new($false).GetString($data) -replace '(?m)^#Requires.*$', ''
      New-Module -Name $(if ($key -eq 'module') { 'ManagedSettingsMerge' } else { 'ServiceAccounts' }) -ScriptBlock ([scriptblock]::Create($text)) | Import-Module -Force -Global
    }
  }
  'protected copy matches the installed hashes'
}
if (-not (Get-Command Compare-T3Acl -ErrorAction SilentlyContinue)) {
  $results | ForEach-Object { Write-Host ("{0,-5} {1}: {2}" -f $_.Result, $_.Check, $_.Detail) }
  Write-Host 'FAIL  modules: could not load the installer modules from the protected copy.'
  return $false
}

$agentSid = (Get-LocalUser -Name $installed.agentAccount -ErrorAction SilentlyContinue)?.SID.Value
$bridgeSid = (Get-LocalUser -Name $installed.bridgeAccount -ErrorAction SilentlyContinue)?.SID.Value
$sidMap = @{ Administrators = 'S-1-5-32-544'; SYSTEM = 'S-1-5-18'; OwnerRights = 'S-1-3-4'; agent = $agentSid; bridge = $bridgeSid }
$defaultWorkspaces = Join-Path $PolicyDir 'workspaces'
$extraRoots = @($installed.workspaceRoots | Where-Object { $_ -ne $defaultWorkspaces })
$plan = Get-T3FolderAclPlan -PolicyDir $PolicyDir -ClaudeHomeName $installed.claudeHomeName -ExtraWorkspaceRoots $extraRoots

function Get-ActualRules([string] $path) {
  $acl = Get-Acl -LiteralPath $path
  $rules = foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
    [pscustomobject]@{ Sid = $rule.IdentityReference.Value; Rights = [int64]$rule.FileSystemRights; Inherit = $rule.InheritanceFlags
      Propagate = $rule.PropagationFlags; Allow = ($rule.AccessControlType -eq 'Allow'); IsInherited = $rule.IsInherited }
  }
  return [pscustomobject]@{ Rules = @($rules); Protected = $acl.AreAccessRulesProtected; Owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value }
}

# ---------- ACLs ----------
foreach ($entry in $plan) {
  Invoke-Check "acl:$($entry.Name)" {
    if (-not (Test-Path -LiteralPath $entry.Path)) { throw "$($entry.Path) is missing" }
    if ((Get-Item -LiteralPath $entry.Path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "$($entry.Path) is a reparse point" }
    $actual = Get-ActualRules $entry.Path
    $issues = Compare-T3Acl -Entry $entry -Actual $actual.Rules -Protected $actual.Protected -Owner $actual.Owner -SidMap $sidMap
    if ($issues.Count -gt 0) { throw ($issues -join '; ') }
    Format-T3AclPlanEntry $entry
  }
}

# ---------- token and interactive-user access ----------
Invoke-Check 'token' {
  $forbidden = @('S-1-5-32-545', 'S-1-5-11', 'S-1-1-0', 'S-1-5-4')
  $interactive = (Get-CimInstance Win32_ComputerSystem).UserName
  if ($interactive) {
    try { $forbidden += ([Security.Principal.NTAccount]$interactive).Translate([Security.Principal.SecurityIdentifier]).Value } catch { }
  }
  $paths = @($PolicyDir, (Join-Path $PolicyDir 'connector'), (Join-Path $PolicyDir 'connector-drop'), (Join-Path $PolicyDir 'bridge'), $ServiceDir)
  if (Test-Path -LiteralPath $TokenPath) { $paths += $TokenPath }
  foreach ($path in $paths) {
    foreach ($rule in (Get-ActualRules $path).Rules) {
      if ($rule.Allow -and $forbidden -contains $rule.Sid) { throw "$($rule.Sid) has access to $path" }
    }
  }
  if (-not (Test-Path -LiteralPath $TokenPath)) { return 'not issued yet (the issuer task runs after a PASS); folders give the interactive user nothing' }
  $actual = Get-ActualRules $TokenPath
  $entry = [pscustomobject]@{ Grants = @([pscustomobject]@{ Principal = 'bridge'; Rights = 'Read, Synchronize'; Inherit = 'None'; Propagate = 'None' }) }
  $issues = Compare-T3Acl -Entry $entry -Actual $actual.Rules -Protected $actual.Protected -Owner $actual.Owner -SidMap $sidMap -File
  if ($issues.Count -gt 0) { throw ($issues -join '; ') }
  'readable by the bridge account only'
}

# ---------- accounts ----------
$rightsText = $null
try {
  $work = Join-Path ([IO.Path]::GetTempPath()) ('t3verify-' + [guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $work | Out-Null
  & "$env:SystemRoot\System32\secedit.exe" /export /cfg (Join-Path $work 'rights.inf') /areas USER_RIGHTS /quiet | Out-Null
  $rightsText = [IO.File]::ReadAllText((Join-Path $work 'rights.inf'))
} finally { if ($work) { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue } }
foreach ($account in @(@{ Name = $installed.agentAccount; Sid = $agentSid }, @{ Name = $installed.bridgeAccount; Sid = $bridgeSid })) {
  Invoke-Check "account:$($account.Name)" {
    $user = Get-LocalUser -Name $account.Name -ErrorAction SilentlyContinue
    if ($null -eq $user) { throw 'missing' }
    if (-not $user.Enabled) { throw 'disabled' }
    $bad = Get-DisallowedGroups -Groups (Get-AccountGroups -Name $account.Name)
    if ($bad.Count -gt 0) { throw "in $($bad -join ', ')" }
    $assigned = @{}
    foreach ($line in ($rightsText -split "`r?`n")) {
      if ($line -match '^\s*(Se\w+)\s*=\s*(.*)$' -and ($Matches[2].Split(',') | ForEach-Object Trim) -contains "*$($account.Sid)") { $assigned[$Matches[1]] = $true }
    }
    $want = @('SeBatchLogonRight', 'SeDenyInteractiveLogonRight', 'SeDenyRemoteInteractiveLogonRight', 'SeDenyNetworkLogonRight')
    $missing = @($want | Where-Object { -not $assigned[$_] })
    $extra = @($assigned.Keys | Where-Object { $want -notcontains $_ })
    if ($missing.Count -gt 0) { throw "rights missing: $($missing -join ', ')" }
    if ($extra.Count -gt 0) { throw "extra rights: $($extra -join ', ')" }
    'batch logon only; groups: Users'
  }
}

# ---------- tasks ----------
$service = Join-Path $PolicyDir 'service'
$taskPlan = @(
  @{ Name = $installed.tasks.Server; User = $installed.agentAccount; Launcher = (Join-Path $service 'start-t3.ps1') }
  @{ Name = $installed.tasks.Issuer; User = $installed.agentAccount; Launcher = (Join-Path $service 'issue-token.ps1') }
  @{ Name = $installed.tasks.Mover; User = 'SYSTEM'; Launcher = (Join-Path $service 'move-token.ps1') }
)
if ($installed.PSObject.Properties['bridgeExe']) { $taskPlan += @{ Name = $installed.tasks.Bridge; User = $installed.bridgeAccount; Launcher = (Join-Path $service 'start-bridge.ps1') } }
foreach ($t in $taskPlan) {
  Invoke-Check "task:$($t.Name)" {
    $task = Get-ScheduledTask -TaskName $t.Name -TaskPath '\T3CodePolicy\' -ErrorAction SilentlyContinue
    if ($null -eq $task) { throw 'not registered' }
    $p = $task.Principal
    if ($t.User -eq 'SYSTEM') {
      if ($p.UserId -notin @('SYSTEM', 'S-1-5-18', 'NT AUTHORITY\SYSTEM')) { throw "runs as $($p.UserId)" }
    } else {
      if ($p.UserId -notmatch "(^|\\)$([regex]::Escape($t.User))$") { throw "runs as $($p.UserId)" }
      if ([string]$p.LogonType -ne 'Password') { throw "LogonType $($p.LogonType)" }
    }
    if ([string]$p.RunLevel -ne 'Limited') { throw "RunLevel $($p.RunLevel)" }
    $action = @($task.Actions)[0]
    if ($action.Execute -ne $installed.pwshExe -or $action.Arguments -notlike "*-File `"$($t.Launcher)`"*") { throw "runs $($action.Execute) $($action.Arguments)" }
    "as $($p.UserId), $($p.LogonType), LeastPrivilege"
  }
}

# ---------- firewall ----------
Invoke-Check 'firewall' {
  $off = @(Get-NetFirewallProfile | Where-Object { -not $_.Enabled } | ForEach-Object Name)
  if ($off.Count -gt 0) { throw "profiles off: $($off -join ', ')" }
  $rules = @(Get-NetFirewallRule -Group $installed.ruleGroup -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq 'True' -and $_.Action -eq 'Block' })
  $want = @(@{ Program = $installed.t3Exe; Direction = 'Outbound' }, @{ Program = $installed.t3Exe; Direction = 'Inbound' }, @{ Program = $installed.claudeExe; Direction = 'Outbound' })
  if ($installed.PSObject.Properties['bridgeExe']) { $want += @{ Program = $installed.bridgeExe; Direction = 'Outbound' }, @{ Program = $installed.bridgeExe; Direction = 'Inbound' } }
  foreach ($w in $want) {
    $match = @($rules | Where-Object { [string]$_.Direction -eq $w.Direction -and ($_ | Get-NetFirewallApplicationFilter).Program -eq $w.Program })
    if ($match.Count -eq 0) { throw "no enabled $($w.Direction) Block rule for $($w.Program)" }
  }
  "all profiles on; $($rules.Count) block rules with the installed image paths"
}

# ---------- machine managed settings ----------
Invoke-Check 'managed' {
  if (-not $installed.PSObject.Properties['machineManagedSettings']) { return 'skipped at install (-SkipMachineManagedSettings)' }
  $record = $installed.machineManagedSettings
  if (-not (Test-Path -LiteralPath $record.path)) { throw "$($record.path) is missing" }
  $baseline = (Get-Content -LiteralPath $BaselinePath -Raw | ConvertFrom-Json).text
  $result = Test-ManagedSettingsUnchanged -CurrentText ([IO.File]::ReadAllText($record.path)) -BackupText $baseline -Added @($record.added) -Created $record.created
  if (-not $result.Ok) { throw $result.Reason }
  "$(@($record.added).Count) deny entries, parentSettingsBehavior merge, nothing else changed"
}

# ---------- hashes ----------
$serviceFiles = @('start-t3.ps1', 'issue-token.ps1', 'move-token.ps1', 't3-settings.seed.json') | ForEach-Object { Join-Path $service $_ }
if ($installed.PSObject.Properties['bridgeExe']) { $serviceFiles += Join-Path $service 'start-bridge.ps1' }
Invoke-Check 'hashes' {
  $pairs = @(@($installed.t3Exe, $installed.t3ExeSha256), @($installed.claudeExe, $installed.claudeExeSha256))
  if ($installed.PSObject.Properties['bridgeExe']) { $pairs += , @($installed.bridgeExe, $installed.bridgeExeSha256) }
  foreach ($pair in $pairs) {
    Assert-AdminOnlyWrite $pair[0]
    if ((Get-Sha $pair[0]) -ne $pair[1]) { throw "$($pair[0]) differs from the installed hash" }
  }
  foreach ($file in $serviceFiles + @($InstalledPath)) { Assert-AdminOnlyWrite $file }
  'binaries match the installed SHA-256; service files are admin-written'
}

# ---------- git hooks ----------
Invoke-Check 'git-hooks' {
  $hooks = $installed.gitHooksDir
  if (@(Get-ChildItem -LiteralPath $hooks -Force).Count -ne 0) { throw "$hooks is not empty" }
  $git = Get-Command git -ErrorAction SilentlyContinue
  if ($null -eq $git) { return 'folder empty; git not on PATH here, so the hook test is in the manual list' }
  $repo = Join-Path ([IO.Path]::GetTempPath()) ('t3verify-git-' + [guid]::NewGuid().ToString('N'))
  try {
    & $git.Source init -q $repo
    $hook = Join-Path $repo '.git\hooks\pre-commit'
    $flag = Join-Path $repo 'hook-ran'
    Set-Content -LiteralPath $hook -Value "#!/bin/sh`necho ran > `"$($flag.Replace('\', '/'))`"`n" -NoNewline
    # The same settings T3 applies to every git call (apps/server/src/tailor/gitHardening.ts).
    $env:GIT_CONFIG_COUNT = '4'
    $env:GIT_CONFIG_KEY_0 = 'core.hooksPath'; $env:GIT_CONFIG_VALUE_0 = $hooks
    $env:GIT_CONFIG_KEY_1 = 'safe.bareRepository'; $env:GIT_CONFIG_VALUE_1 = 'explicit'
    $env:GIT_CONFIG_KEY_2 = 'core.fsmonitor'; $env:GIT_CONFIG_VALUE_2 = 'false'
    $env:GIT_CONFIG_KEY_3 = 'protocol.ext.allow'; $env:GIT_CONFIG_VALUE_3 = 'never'
    & $git.Source -C $repo -c user.name=t3verify -c user.email=t3verify@example.com commit -q --allow-empty -m check 2>$null | Out-Null
    if (Test-Path -LiteralPath $flag) { throw 'a repository hook ran with the T3 git settings' }
    $effective = (& $git.Source -C $repo config --get core.hooksPath)
    if ($effective -ne $hooks) { throw "core.hooksPath resolves to $effective" }
  } finally {
    foreach ($n in 'GIT_CONFIG_COUNT', 'GIT_CONFIG_KEY_0', 'GIT_CONFIG_VALUE_0', 'GIT_CONFIG_KEY_1', 'GIT_CONFIG_VALUE_1', 'GIT_CONFIG_KEY_2', 'GIT_CONFIG_VALUE_2', 'GIT_CONFIG_KEY_3', 'GIT_CONFIG_VALUE_3') { Remove-Item -LiteralPath "Env:$n" -ErrorAction SilentlyContinue }
    Remove-Item -LiteralPath $repo -Recurse -Force -ErrorAction SilentlyContinue
  }
  'folder empty; a repository hook does not run with the T3 git settings'
}

# ---------- report, marker ----------
Write-Host ''
$results | ForEach-Object { Write-Host ("{0,-5} {1}: {2}" -f $_.Result, $_.Check, $_.Detail) }
$failed = @($results | Where-Object Result -eq 'FAIL')
$allPassed = ($failed.Count -eq 0)
if (-not $NoMarker) {
  if (Test-Path -LiteralPath $MarkerPath) { [IO.File]::Delete($MarkerPath) }
  if ($allPassed) {
    $files = @($installed.t3Exe, $installed.claudeExe, $InstalledPath) + $serviceFiles
    if ($installed.PSObject.Properties['bridgeExe']) { $files += $installed.bridgeExe }
    $marker = [ordered]@{
      version = 1
      verifiedAt = [DateTime]::UtcNow.ToString('o')
      files = @($files | ForEach-Object { [ordered]@{ path = $_; sha256 = (Get-Sha $_) } })
    }
    $security = [Security.AccessControl.FileSecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    $security.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    $grants = @(@('S-1-5-32-544', 'FullControl'), @('S-1-5-18', 'FullControl'))
    foreach ($sid in $agentSid, $bridgeSid) { if ($sid) { $grants += , @($sid, 'Read, Synchronize') } }
    foreach ($g in $grants) {
      $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($g[0]), [Security.AccessControl.FileSystemRights]$g[1], 'Allow'))
    }
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes((($marker | ConvertTo-Json -Depth 5) + "`n"))
    $stream = [IO.FileSystemAclExtensions]::Create([IO.FileInfo]::new($MarkerPath), [IO.FileMode]::CreateNew,
      [Security.AccessControl.FileSystemRights]'Write, Synchronize', [IO.FileShare]::None, 4096, [IO.FileOptions]::None, $security)
    try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
    Write-Host "PASS: all $($results.Count) checks. Verified marker written: $MarkerPath"
  } else {
    Write-Host "FAIL: $($failed.Count) of $($results.Count) checks. No verified marker: the launchers will not start."
  }
}

Write-Host @"

Manual first-run checks (a person does these; they cannot be scripted from here):
  1. From a NON-elevated prompt as the interactive user:
       Get-Content "$TokenPath"      -> must fail: access denied
       Get-ChildItem "$PolicyDir"    -> must fail: access denied
  2. runas /user:$($installed.agentAccount) cmd   -> must fail: logon type not granted
  3. In T3, pick Full access or Auto-accept edits: the thread still asks before every edit
     and command (the build ceiling is Supervised).
  4. In a T3 thread, ask Claude to read "$TokenPath" and "$PolicyDir\t3-policy.json":
     both refused.
  5. In a T3 workspace repository, add .git/hooks/post-checkout that writes a file, then
     create a worktree or switch branch from T3: the file must not appear.
  6. Create a project outside $(@($installed.workspaceRoots) -join ' or '): T3 must refuse it.
  7. Run the live egress capture while one turn runs (SECURITY-REVIEW.md, T3-01).
"@
return $allPassed
