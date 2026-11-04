#Requires -Version 7.2
<#
  Tailor fork (TailorAU/t3code): the two local service accounts the installer runs things as.

    t3agent   runs t3 serve and the Claude it launches. Owns the T3 home and the Claude home.
    t3bridge  runs the T3 bridge (the connector's T3 source) and is the only account that can
              read the connector token and the bridge's tailor.au key.

  Both are standard (non-admin) local users with a random password that is generated in
  memory, handed straight to Task Scheduler and discarded: it is never written to disk or to
  any log. Interactive, RDP and network logon are denied by local policy (secedit, user
  rights area only); "log on as a batch job" is granted so the scheduled task can run.

  Tasks are registered through the Task Scheduler COM API from XML (LogonType Password,
  RunLevel LeastPrivilege), never with the password as a cmdlet parameter.

  The pure planning functions (no side effects) are tested by
  tests/ServiceAccounts.Tests.ps1. The functions that change the machine are used only by
  install-policy.ps1, elevated.
#>
Set-StrictMode -Version 3.0

$script:PasswordAlphabet = @{
  Upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
  Lower = 'abcdefghijkmnopqrstuvwxyz'
  Digit = '23456789'
  Symbol = '!#%+-=?@^_~'
}

# ---------- pure planning ----------

<# A random password as a char array (caller zeroes it). Every class appears at least once. #>
function New-ServiceAccountPasswordChars {
  param([ValidateRange(24, 128)][int] $Length = 40)
  $classes = @($script:PasswordAlphabet.Upper, $script:PasswordAlphabet.Lower, $script:PasswordAlphabet.Digit, $script:PasswordAlphabet.Symbol)
  $all = ($classes -join '').ToCharArray()
  $chars = [char[]]::new($Length)
  for ($i = 0; $i -lt $Length; $i++) {
    $pool = if ($i -lt $classes.Count) { $classes[$i].ToCharArray() } else { $all }
    $chars[$i] = $pool[[Security.Cryptography.RandomNumberGenerator]::GetInt32($pool.Length)]
  }
  # Fisher-Yates shuffle so the guaranteed classes are not always first.
  for ($i = $Length - 1; $i -gt 0; $i--) {
    $j = [Security.Cryptography.RandomNumberGenerator]::GetInt32($i + 1)
    $tmp = $chars[$i]; $chars[$i] = $chars[$j]; $chars[$j] = $tmp
  }
  return , $chars
}

<# The user-rights changes the installer makes for one account SID. #>
function Get-ServiceAccountRightsPlan {
  param([Parameter(Mandatory)][string] $Sid)
  return [ordered]@{
    SeBatchLogonRight = @{ Add = $Sid }
    SeDenyInteractiveLogonRight = @{ Add = $Sid }
    SeDenyRemoteInteractiveLogonRight = @{ Add = $Sid }
    SeDenyNetworkLogonRight = @{ Add = $Sid }
  }
}

<#
  Applies add/remove changes to a secedit USER_RIGHTS export. Pure text in, text out.
  $Changes: right name -> @{ Add = '<sid>' } or @{ Remove = '<sid>' }. Lines for rights not
  mentioned are kept byte for byte; a missing right line is created under [Privilege Rights].
#>
function Update-UserRightsInf {
  param([Parameter(Mandatory)][string] $InfText, [Parameter(Mandatory)][System.Collections.IDictionary] $Changes)
  $newline = if ($InfText.Contains("`r`n")) { "`r`n" } else { "`n" }
  $lines = [System.Collections.Generic.List[string]]::new()
  $InfText -split "`r?`n" | ForEach-Object { $lines.Add($_) }
  $sectionIndex = $lines.FindIndex({ param($l) $l.Trim() -eq '[Privilege Rights]' })
  if ($sectionIndex -lt 0) {
    $lines.Add('[Privilege Rights]')
    $sectionIndex = $lines.Count - 1
  }
  foreach ($right in $Changes.Keys) {
    $change = $Changes[$right]
    $index = -1
    for ($i = $sectionIndex + 1; $i -lt $lines.Count; $i++) {
      if ($lines[$i].TrimStart().StartsWith('[')) { break }
      if ($lines[$i] -match "^\s*$([regex]::Escape($right))\s*=") { $index = $i; break }
    }
    $members = [System.Collections.Generic.List[string]]::new()
    if ($index -ge 0) {
      ($lines[$index] -split '=', 2)[1].Split(',') | ForEach-Object { $m = $_.Trim(); if ($m) { $members.Add($m) } }
    }
    if ($change.Contains('Add')) {
      $entry = '*' + $change.Add
      if (-not $members.Contains($entry)) { $members.Add($entry) }
    }
    if ($change.Contains('Remove')) { [void]$members.Remove('*' + $change.Remove) }
    $line = "$right = " + ($members -join ',')
    if ($index -ge 0) {
      if ($members.Count -eq 0) { $lines.RemoveAt($index) } else { $lines[$index] = $line }
    } elseif ($members.Count -gt 0) {
      $lines.Insert($sectionIndex + 1, $line)
    }
  }
  return ($lines -join $newline)
}

<#
  The scheduled task for one service as Task Scheduler XML. Pure; shown by -WhatIf and checked
  by verify-install.ps1. Registered through the Task Scheduler COM API (Register-ServiceTask),
  so the account password is never a cmdlet parameter that module logging would record.

  -Account '<name>'  runs as that local account, LogonType Password, RunLevel LeastPrivilege.
  -System            runs as SYSTEM (used only for the fixed token mover).
  -Trigger           Startup (restart on failure), Daily (one run a day at 03:00) or Every10Minutes.
#>
function Get-ServiceTaskXml {
  param(
    [Parameter(Mandatory)][string] $Description,
    [string] $Account,
    [switch] $System,
    [Parameter(Mandatory)][string] $PwshPath,
    [Parameter(Mandatory)][string] $LauncherPath,
    [ValidateSet('Startup', 'Daily', 'Every10Minutes')][string] $Trigger = 'Startup'
  )
  if ($System -eq [bool]$Account) { throw 'Pass exactly one of -Account or -System.' }
  $x = { param($v) [Security.SecurityElement]::Escape([string]$v) }
  $principal = if ($System) {
    '<UserId>S-1-5-18</UserId><RunLevel>LeastPrivilege</RunLevel>'
  } else {
    "<UserId>.\$(& $x $Account)</UserId><LogonType>Password</LogonType><RunLevel>LeastPrivilege</RunLevel>"
  }
  $triggers = switch ($Trigger) {
    'Startup' { '<BootTrigger><Enabled>true</Enabled></BootTrigger>' }
    'Daily' { '<BootTrigger><Enabled>true</Enabled><Delay>PT2M</Delay></BootTrigger><CalendarTrigger><StartBoundary>2026-01-01T03:00:00</StartBoundary><Enabled>true</Enabled><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger>' }
    'Every10Minutes' { '<TimeTrigger><Repetition><Interval>PT10M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition><StartBoundary>2026-01-01T00:00:00</StartBoundary><Enabled>true</Enabled></TimeTrigger><BootTrigger><Enabled>true</Enabled><Delay>PT5M</Delay></BootTrigger>' }
  }
  $restart = if ($Trigger -eq 'Startup') { '<RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure>' } else { '' }
  $limit = if ($Trigger -eq 'Startup') { 'PT0S' } else { 'PT15M' }
  $arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$LauncherPath`""
  return @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>$(& $x $Description)</Description></RegistrationInfo>
  <Triggers>$triggers</Triggers>
  <Principals><Principal id="Author">$principal</Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>$limit</ExecutionTimeLimit>
    $restart
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author"><Exec><Command>$(& $x $PwshPath)</Command><Arguments>$(& $x $arguments)</Arguments></Exec></Actions>
</Task>
"@
}

<#
  The folder ACL plan: every folder the installer owns and exactly who may do what there.
  Principals are 'Administrators', 'SYSTEM', 'OwnerRights', 'agent' and 'bridge'. The
  interactive user, BUILTIN\Users, Authenticated Users and Everyone never appear. The
  installer creates folders from this plan and verify-install.ps1 compares the live ACLs to it.
#>
function Get-T3FolderAclPlan {
  param(
    [Parameter(Mandatory)][string] $PolicyDir,
    [Parameter(Mandatory)][string] $ClaudeHomeName,
    [string[]] $ExtraWorkspaceRoots = @()
  )
  $read = 'ReadAndExecute, Synchronize'
  $g = { param($who, $rights, $inherit = 'ContainerInherit, ObjectInherit', $propagate = 'None')
    [pscustomobject]@{ Principal = $who; Rights = $rights; Inherit = $inherit; Propagate = $propagate } }
  $plan = @(
    [pscustomobject]@{ Name = 'policy'; Path = $PolicyDir; Grants = @((& $g 'agent' $read 'None')) }
    [pscustomobject]@{ Name = 'installer'; Path = (Join-Path $PolicyDir 'installer'); Grants = @() }
    [pscustomobject]@{ Name = 'state'; Path = (Join-Path $PolicyDir 'state'); Grants = @() }
    [pscustomobject]@{ Name = 'service'; Path = (Join-Path $PolicyDir 'service'); Grants = @((& $g 'agent' $read), (& $g 'bridge' $read)) }
    [pscustomobject]@{ Name = 'git-hooks'; Path = (Join-Path $PolicyDir 'git-hooks'); Grants = @((& $g 'agent' $read)) }
    [pscustomobject]@{ Name = 't3-home'; Path = (Join-Path $PolicyDir 't3-home'); Grants = @((& $g 'agent' 'Modify, Synchronize')) }
    [pscustomobject]@{ Name = 'claude-home'; Path = (Join-Path $PolicyDir $ClaudeHomeName); Grants = @(
        (& $g 'agent' 'ReadAndExecute, CreateDirectories, Synchronize' 'None'),
        (& $g 'agent' 'Modify, Synchronize' 'ContainerInherit, ObjectInherit' 'InheritOnly')) }
    [pscustomobject]@{ Name = 'connector-drop'; Path = (Join-Path $PolicyDir 'connector-drop'); Grants = @(
        (& $g 'agent' 'CreateFiles, Synchronize' 'None'),
        (& $g 'agent' 'Write, ReadPermissions, Synchronize' 'ObjectInherit' 'InheritOnly'),
        # OWNER RIGHTS with nothing useful: the file's owner (t3agent) gets no implicit WRITE_DAC.
        (& $g 'OwnerRights' 'Synchronize' 'ObjectInherit' 'None')) }
    [pscustomobject]@{ Name = 'connector'; Path = (Join-Path $PolicyDir 'connector'); Grants = @((& $g 'bridge' $read)) }
    [pscustomobject]@{ Name = 'bridge'; Path = (Join-Path $PolicyDir 'bridge'); Grants = @((& $g 'bridge' $read)) }
    [pscustomobject]@{ Name = 'workspaces'; Path = (Join-Path $PolicyDir 'workspaces'); Grants = @((& $g 'agent' 'Modify, Synchronize')) }
  )
  $index = 0
  foreach ($root in $ExtraWorkspaceRoots) {
    $index++
    $plan += [pscustomobject]@{ Name = "workspace-$index"; Path = $root; Grants = @((& $g 'agent' 'Modify, Synchronize')) }
  }
  return $plan
}

<# A one-line text view of a plan entry, for the plan printout and the README. #>
function Format-T3AclPlanEntry {
  param([Parameter(Mandatory)] $Entry)
  $parts = @('Administrators: full', 'SYSTEM: full') + @($Entry.Grants | ForEach-Object {
      $scope = if ($_.Propagate -eq 'InheritOnly') { ' (inside only)' } elseif ($_.Inherit -eq 'None') { ' (this folder only)' } else { '' }
      "$($_.Principal): $($_.Rights)$scope" })
  return "$($Entry.Path): $($parts -join '; ')"
}

<#
  Compares one folder's live ACL to its plan entry. Pure. $Actual: objects with Sid (string),
  Rights ([int64] or FileSystemRights), Inherit, Propagate, Allow ([bool]), IsInherited ([bool]).
  $Protected says whether inheritance is off; $Owner is the owner SID. $SidMap maps plan
  principals to SIDs. Returns the list of differences (empty = matches).
#>
function Compare-T3Acl {
  param(
    [Parameter(Mandatory)] $Entry,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]] $Actual,
    [Parameter(Mandatory)][bool] $Protected,
    [Parameter(Mandatory)][string] $Owner,
    [Parameter(Mandatory)][System.Collections.IDictionary] $SidMap,
    # A file: no inheritance flags on any entry.
    [switch] $File
  )
  $issues = [System.Collections.Generic.List[string]]::new()
  if (-not $Protected) { $issues.Add('inheritance is on') }
  if (@('S-1-5-32-544', 'S-1-5-18') -notcontains $Owner) { $issues.Add("owner is $Owner") }
  $key = { param($sid, $rights, $inherit, $propagate)
    $mask = [int64]([Security.AccessControl.FileSystemRights]$rights) -bor 0x100000   # Synchronize is always implied
    "$sid|$mask|$([int][Security.AccessControl.InheritanceFlags]$inherit)|$([int][Security.AccessControl.PropagationFlags]$propagate)" }
  $expected = [System.Collections.Generic.HashSet[string]]::new()
  $all = if ($File) { 'None' } else { 'ContainerInherit, ObjectInherit' }
  foreach ($sid in 'S-1-5-32-544', 'S-1-5-18') { [void]$expected.Add((& $key $sid 'FullControl' $all 'None')) }
  foreach ($grant in $Entry.Grants) {
    $sid = $SidMap[$grant.Principal]
    if (-not $sid) { $issues.Add("no SID for $($grant.Principal)"); continue }
    [void]$expected.Add((& $key $sid $grant.Rights $grant.Inherit $grant.Propagate))
  }
  $seen = [System.Collections.Generic.HashSet[string]]::new()
  foreach ($rule in $Actual) {
    if (-not $rule.Allow) { continue }   # deny entries only take access away
    if ($rule.IsInherited) { $issues.Add("inherited entry for $($rule.Sid)"); continue }
    $k = & $key $rule.Sid $rule.Rights $rule.Inherit $rule.Propagate
    if (-not $expected.Contains($k)) { $issues.Add("unexpected entry $k") } else { [void]$seen.Add($k) }
  }
  foreach ($k in $expected) { if (-not $seen.Contains($k)) { $issues.Add("missing entry $k") } }
  return $issues.ToArray()
}

<#
  Local groups a service account may be in. Anything else (Administrators, Remote Desktop
  Users, Backup Operators, Hyper-V Administrators, Remote Management Users, Event Log Readers,
  Distributed COM Users and so on) makes the installer refuse.
  BUILTIN\Users stays: Program Files and System32 grant read and execute through it, so the
  accounts could not start pwsh, t3 or Claude without it (SECURITY-REVIEW.md, T3-51).
#>
$script:AllowedGroupSids = @('S-1-5-32-545')
function Get-DisallowedGroups {
  param([Parameter(Mandatory)][AllowEmptyCollection()][object[]] $Groups)   # objects with Name, Sid
  return , @($Groups | Where-Object { $script:AllowedGroupSids -notcontains [string]$_.Sid } | ForEach-Object { "$($_.Name) ($($_.Sid))" })
}

$script:LauncherQuote = { param($v) "'" + ([string]$v -replace "'", "''") + "'" }

<#
  Shared launcher prologue: refuses to go on unless the verified marker exists, is owned by an
  administrator principal, is not writable by this account, and every file it lists that this
  launcher depends on still has the recorded SHA-256.
#>
function Get-MarkerCheckText {
  param([Parameter(Mandatory)][string] $MarkerPath, [Parameter(Mandatory)][string[]] $RequiredFiles)
  $q = $script:LauncherQuote
  $required = ($RequiredFiles | ForEach-Object { & $q $_ }) -join ', '
  return @"
function Test-T3Verified {
  `$marker = $(& $q $MarkerPath)
  if (-not (Test-Path -LiteralPath `$marker -PathType Leaf)) { return 'no verified marker: run verify-install.ps1 as an administrator' }
  `$acl = Get-Acl -LiteralPath `$marker
  if (@('S-1-5-32-544', 'S-1-5-18') -notcontains `$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value) { return 'marker not owned by an administrator principal' }
  `$me = [Security.Principal.WindowsIdentity]::GetCurrent()
  `$mine = @(`$me.User.Value) + @(`$me.Groups | ForEach-Object Value)
  foreach (`$rule in `$acl.GetAccessRules(`$true, `$true, [Security.Principal.SecurityIdentifier])) {
    if (`$rule.AccessControlType -eq 'Allow' -and `$mine -contains `$rule.IdentityReference.Value -and
        ([int64]`$rule.FileSystemRights -band 0x500d0156) -ne 0) { return 'marker is writable by this account' }
  }
  `$recorded = @{}
  foreach (`$file in (Get-Content -LiteralPath `$marker -Raw | ConvertFrom-Json).files) { `$recorded[`$file.path.ToLowerInvariant()] = `$file.sha256 }
  foreach (`$path in @($required)) {
    `$want = `$recorded[`$path.ToLowerInvariant()]
    if (-not `$want) { return "marker does not cover `$path" }
    `$have = (Get-FileHash -LiteralPath `$path -Algorithm SHA256).Hash.ToLowerInvariant()
    if (`$have -ne `$want) { return "`$path changed since verification" }
  }
  return `$null
}
"@
}

function Get-UnsetText([string[]] $MustBeUnset) {
  $lines = foreach ($name in $MustBeUnset) {
    if ($name -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') { throw "Refusing variable name '$name'." }
    "Remove-Item -LiteralPath 'Env:$name' -ErrorAction SilentlyContinue"
  }
  return ($lines -join "`n")
}

<#
  The launcher for t3 serve: verified-marker check, fixed environment, unsets, seeds T3's
  settings from the admin-written seed on first run (as t3agent: no admin code in the T3 home),
  restart loop.
#>
function Get-T3LauncherText {
  param(
    [Parameter(Mandatory)][string] $T3Exe,
    [Parameter(Mandatory)][string] $T3Home,
    [Parameter(Mandatory)][System.Collections.IDictionary] $Environment,
    [AllowEmptyCollection()][string[]] $MustBeUnset = @(),
    [Parameter(Mandatory)][string] $MarkerPath,
    [Parameter(Mandatory)][string[]] $RequiredFiles,
    [string] $SettingsSeedPath
  )
  $q = $script:LauncherQuote
  $set = foreach ($name in $Environment.Keys) {
    if ($name -notmatch '^T3CODE_[A-Z0-9_]+$') { throw "Refusing launcher variable '$name'." }
    "`$env:$name = $(& $q ([string]$Environment[$name]))"
  }
  $seed = if ($SettingsSeedPath) {
    @"
`$userdata = Join-Path `$env:T3CODE_HOME 'userdata'
if (-not (Test-Path -LiteralPath (Join-Path `$userdata 'settings.json'))) {
  New-Item -ItemType Directory -Path `$userdata -Force | Out-Null
  Copy-Item -LiteralPath $(& $q $SettingsSeedPath) -Destination (Join-Path `$userdata 'settings.json')
}
"@
  } else { '' }
  return @"
# Generated by install-policy.ps1. Runs as the t3agent account under Task Scheduler.
`$ErrorActionPreference = 'Stop'
$(Get-MarkerCheckText -MarkerPath $MarkerPath -RequiredFiles $RequiredFiles)
$(Get-UnsetText $MustBeUnset)
$($set -join "`n")
`$env:T3CODE_HOME = $(& $q $T3Home)
$seed
while (`$true) {
  `$refusal = Test-T3Verified
  if (`$refusal) { Write-Warning "T3 not started: `$refusal"; Start-Sleep -Seconds 60; continue }
  & $(& $q $T3Exe) serve
  Start-Sleep -Seconds 10
}
"@
}

<# The launcher for the bridge: verified-marker check; token and key paths only; no listener. #>
function Get-BridgeLauncherText {
  param(
    [Parameter(Mandatory)][string] $BridgeExe,
    [Parameter(Mandatory)][string] $TokenPath,
    [Parameter(Mandatory)][string] $KeyPath,
    [Parameter(Mandatory)][string] $T3Url,
    [AllowEmptyCollection()][string[]] $MustBeUnset = @(),
    [Parameter(Mandatory)][string] $MarkerPath,
    [Parameter(Mandatory)][string[]] $RequiredFiles
  )
  $q = $script:LauncherQuote
  return @"
# Generated by install-policy.ps1. Runs as the t3bridge account under Task Scheduler.
`$ErrorActionPreference = 'Stop'
$(Get-MarkerCheckText -MarkerPath $MarkerPath -RequiredFiles $RequiredFiles)
$(Get-UnsetText $MustBeUnset)
`$env:T3_BRIDGE_T3_URL = $(& $q $T3Url)
`$env:T3_BRIDGE_TOKEN_FILE = $(& $q $TokenPath)
`$env:T3_BRIDGE_TAILOR_KEY_FILE = $(& $q $KeyPath)
while (`$true) {
  `$refusal = Test-T3Verified
  if (`$refusal) { Write-Warning "Bridge not started: `$refusal"; Start-Sleep -Seconds 60; continue }
  & $(& $q $BridgeExe)
  Start-Sleep -Seconds 10
}
"@
}

<#
  The token issuer, run by t3agent (daily and once at install): issues a tailor:connector token
  with T3's own CLI against the T3 home, writes it into the drop folder (t3agent may create a
  file there but not read, list or delete), and revokes all but the two newest connector
  sessions so the bridge's current token stays valid until the mover replaces it.
  No administrator code ever runs against the T3 home.
#>
function Get-TokenIssuerText {
  param(
    [Parameter(Mandatory)][string] $T3Exe,
    [Parameter(Mandatory)][string] $T3Home,
    [Parameter(Mandatory)][string] $DropPath,
    [Parameter(Mandatory)][ValidatePattern('^\d+[dh]$')][string] $Ttl,
    [AllowEmptyCollection()][string[]] $MustBeUnset = @(),
    [Parameter(Mandatory)][string] $MarkerPath,
    [Parameter(Mandatory)][string[]] $RequiredFiles
  )
  $q = $script:LauncherQuote
  return @"
# Generated by install-policy.ps1. Runs as the t3agent account under Task Scheduler.
# Issues the connector token; never prints it.
`$ErrorActionPreference = 'Stop'
$(Get-MarkerCheckText -MarkerPath $MarkerPath -RequiredFiles $RequiredFiles)
$(Get-UnsetText $MustBeUnset)
`$refusal = Test-T3Verified
if (`$refusal) { Write-Warning "Token not issued: `$refusal"; exit 1 }
`$env:T3CODE_HOME = $(& $q $T3Home)
`$t3 = $(& $q $T3Exe)
`$drop = $(& $q $DropPath)
# This account may create the drop file but not see or delete it: claim it first, then issue.
try {
  `$stream = [IO.FileStream]::new(`$drop, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
} catch [IO.IOException] { Write-Warning 'The previous token has not been moved yet; nothing issued.'; exit 0 }
try {
  `$issued = (& `$t3 auth session issue --base-dir `$env:T3CODE_HOME --scope tailor:connector --label connector --ttl $Ttl --json) | ConvertFrom-Json
  if (`$LASTEXITCODE -ne 0 -or -not `$issued.token) { throw 'Issuing the connector token failed (the mover discards the empty drop file).' }
  `$bytes = [Text.UTF8Encoding]::new(`$false).GetBytes([string]`$issued.token)
  `$issued = `$null
  try { `$stream.Write(`$bytes, 0, `$bytes.Length) } finally { [Array]::Clear(`$bytes, 0, `$bytes.Length) }
} finally { `$stream.Dispose() }
`$sessions = @((& `$t3 auth session list --base-dir `$env:T3CODE_HOME --json) | ConvertFrom-Json |
  Where-Object { @(`$_.scopes) -contains 'tailor:connector' } | Sort-Object { [DateTime]`$_.issuedAt } -Descending)
foreach (`$old in (`$sessions | Select-Object -Skip 2)) {
  & `$t3 auth session revoke --base-dir `$env:T3CODE_HOME `$old.sessionId | Out-Null
}
"@
}

<#
  The token mover, run by SYSTEM every ten minutes. Fixed code in the admin-only service
  folder. Takes the drop file only if it is a plain file (no reparse point, one link) owned by
  t3agent and holds one printable token; creates connector\token.new with its ACL set at
  creation (Administrators, SYSTEM, t3bridge read), renames it over connector\token, then
  deletes the drop file. It never parses or runs anything t3agent wrote.
#>
function Get-TokenMoverText {
  param(
    [Parameter(Mandatory)][string] $DropPath,
    [Parameter(Mandatory)][string] $TokenPath,
    [Parameter(Mandatory)][string] $AgentSid,
    [Parameter(Mandatory)][string] $BridgeSid
  )
  $q = $script:LauncherQuote
  return @"
# Generated by install-policy.ps1. Runs as SYSTEM under Task Scheduler.
`$ErrorActionPreference = 'Stop'
`$drop = $(& $q $DropPath)
`$token = $(& $q $TokenPath)
if (-not (Test-Path -LiteralPath `$drop)) { exit 0 }
`$item = Get-Item -LiteralPath `$drop -Force
`$reject = `$null
if (`$item.Attributes -band [IO.FileAttributes]::ReparsePoint) { `$reject = 'reparse point' }
elseif (`$item.PSIsContainer) { `$reject = 'not a file' }
elseif ((Get-Acl -LiteralPath `$drop).GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $(& $q $AgentSid)) { `$reject = 'not owned by the agent account' }
elseif (`$item.Length -lt 16 -or `$item.Length -gt 4096) { `$reject = 'unexpected size' }
elseif (@(& "`$env:SystemRoot\System32\fsutil.exe" hardlink list `$drop).Count -ne 1) { `$reject = 'has other hard links' }
if (`$reject) {
  Write-Warning "Connector token drop rejected: `$reject"
  # Removing the entry (a link is removed as a link) is safe: the folder is admin-controlled.
  if (`$item.PSIsContainer -and -not (`$item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { [IO.Directory]::Delete(`$drop, `$false) } else { [IO.File]::Delete(`$drop) }
  exit 1
}
try {
  `$in = [IO.FileStream]::new(`$drop, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
} catch { exit 0 }   # still being written; the next run takes it
try {
  `$bytes = [byte[]]::new(`$in.Length); `$read = 0
  while (`$read -lt `$bytes.Length) { `$n = `$in.Read(`$bytes, `$read, `$bytes.Length - `$read); if (`$n -le 0) { break }; `$read += `$n }
} finally { `$in.Dispose() }
try {
  foreach (`$b in `$bytes) { if (`$b -lt 0x21 -or `$b -gt 0x7e) { [IO.File]::Delete(`$drop); throw 'The drop file is not one printable token; discarded.' } }
  `$security = [Security.AccessControl.FileSecurity]::new()
  `$security.SetAccessRuleProtection(`$true, `$false)
  `$security.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
  foreach (`$grant in @(@('S-1-5-32-544', 'FullControl'), @('S-1-5-18', 'FullControl'), @($(& $q $BridgeSid), 'Read, Synchronize'))) {
    `$security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new(`$grant[0]), [Security.AccessControl.FileSystemRights]`$grant[1], 'Allow'))
  }
  `$next = "`$token.new"
  if (Test-Path -LiteralPath `$next) { [IO.File]::Delete(`$next) }
  `$out = [IO.FileSystemAclExtensions]::Create([IO.FileInfo]::new(`$next), [IO.FileMode]::CreateNew,
    [Security.AccessControl.FileSystemRights]'Write, Synchronize', [IO.FileShare]::None, 4096, [IO.FileOptions]::None, `$security)
  try { `$out.Write(`$bytes, 0, `$bytes.Length) } finally { `$out.Dispose() }
  [IO.File]::Move(`$next, `$token, `$true)
  [IO.File]::Delete(`$drop)
} finally {
  [Array]::Clear(`$bytes, 0, `$bytes.Length)
}
"@
}

# ---------- machine changes (elevated, used by install-policy.ps1) ----------

<# The local groups an account is in, as objects with Name and Sid. #>
function Get-AccountGroups {
  param([Parameter(Mandatory)][string] $Name)
  $groups = foreach ($group in Get-LocalGroup) {
    $members = @(Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue)
    if ($members | Where-Object { $_.Name -match "\\$([regex]::Escape($Name))$" -and $_.PrincipalSource -eq 'Local' }) {
      [pscustomobject]@{ Name = $group.Name; Sid = $group.SID.Value }
    }
  }
  return , @($groups)
}

<#
  Creates the account, or resets its password, and returns the password as a SecureString.
  Refuses an existing account that is in any group but BUILTIN\Users.
#>
function Set-ServiceAccount {
  [CmdletBinding(SupportsShouldProcess)]
  param([Parameter(Mandatory)][string] $Name, [Parameter(Mandatory)][string] $Description)
  $existing = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
  if ($null -ne $existing) {
    $bad = Get-DisallowedGroups -Groups (Get-AccountGroups -Name $Name)
    if ($bad.Count -gt 0) {
      throw "Refusing: the existing account $Name is in $($bad -join ', '). Remove it from those groups (or delete the account) and re-run."
    }
  }
  $chars = New-ServiceAccountPasswordChars
  $secure = [Security.SecureString]::new()
  foreach ($c in $chars) { $secure.AppendChar($c) }
  [Array]::Clear($chars, 0, $chars.Length)
  $secure.MakeReadOnly()
  if ($null -eq $existing) {
    if ($PSCmdlet.ShouldProcess($Name, 'Create local standard user with a random password (never stored)')) {
      New-LocalUser -Name $Name -Password $secure -Description $Description -PasswordNeverExpires `
        -AccountNeverExpires -UserMayNotChangePassword | Out-Null
    }
  } elseif ($PSCmdlet.ShouldProcess($Name, 'Reset password to a new random one (never stored)')) {
    Set-LocalUser -Name $Name -Password $secure -PasswordNeverExpires $true -AccountNeverExpires
  }
  return $secure
}

function Invoke-SeceditUserRights {
  [CmdletBinding(SupportsShouldProcess)]
  param([Parameter(Mandatory)][System.Collections.IDictionary] $Changes, [string] $Description = 'user rights')
  if ($WhatIfPreference) {
    Write-Host "What if: Update local security policy: $Description"
    foreach ($right in $Changes.Keys) { Write-Host "    $right : $(($Changes[$right].Keys | ForEach-Object { "$_ $($Changes[$right][$_])" }) -join ', ')" }
    return
  }
  $work = Join-Path ([IO.Path]::GetTempPath()) ('t3policy-secedit-' + [guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $work | Out-Null
  try {
    $exported = Join-Path $work 'current.inf'
    & "$env:SystemRoot\System32\secedit.exe" /export /cfg $exported /areas USER_RIGHTS /quiet | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "secedit /export failed ($LASTEXITCODE)." }
    $text = [IO.File]::ReadAllText($exported)
    $updated = Update-UserRightsInf -InfText $text -Changes $Changes
    if ($updated -eq $text) { Write-Host "  unchanged: $Description"; return }
    if ($PSCmdlet.ShouldProcess('Local security policy', "Update $Description")) {
      $cfg = Join-Path $work 'updated.inf'
      [IO.File]::WriteAllText($cfg, $updated, [Text.UnicodeEncoding]::new($false, $true))
      & "$env:SystemRoot\System32\secedit.exe" /configure /db (Join-Path $work 'secedit.sdb') /cfg $cfg /areas USER_RIGHTS /quiet | Out-Null
      if ($LASTEXITCODE -ne 0) { throw "secedit /configure failed ($LASTEXITCODE)." }
    }
  } finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
  }
}

<#
  Registers a task through the Task Scheduler COM API. The password goes from the SecureString
  to a BSTR to the COM call and the BSTR is zeroed; it is never a cmdlet parameter, so module
  and script-block logging cannot record it. Task Scheduler keeps it as an LSA secret.
#>
function Register-ServiceTask {
  [CmdletBinding(SupportsShouldProcess)]
  param(
    [Parameter(Mandatory)][string] $TaskName,
    [Parameter(Mandatory)][string] $Xml,
    [string] $Account,
    [Security.SecureString] $Password,
    [switch] $System
  )
  $who = if ($System) { 'SYSTEM' } else { $Account }
  if (-not $PSCmdlet.ShouldProcess("\T3CodePolicy\$TaskName", "Register task as $who")) { return }
  $service = New-Object -ComObject 'Schedule.Service'
  $service.Connect()
  $root = $service.GetFolder('\')
  $folder = try { $service.GetFolder('\T3CodePolicy') } catch { $root.CreateFolder('T3CodePolicy') }
  $definition = $service.NewTask(0)
  $definition.XmlText = $Xml
  if ($System) {
    [void]$folder.RegisterTaskDefinition($TaskName, $definition, 6, 'SYSTEM', $null, 5)   # TASK_LOGON_SERVICE_ACCOUNT
    return
  }
  $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
  try {
    [void]$folder.RegisterTaskDefinition($TaskName, $definition, 6, ".\$Account",
      [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr), 1)   # TASK_LOGON_PASSWORD
  } finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
  }
}

function Remove-ServiceTask {
  [CmdletBinding(SupportsShouldProcess)]
  param([Parameter(Mandatory)][string] $TaskName)
  $task = Get-ScheduledTask -TaskName $TaskName -TaskPath '\T3CodePolicy\' -ErrorAction SilentlyContinue
  if ($task -and $PSCmdlet.ShouldProcess("\T3CodePolicy\$TaskName", 'Stop and unregister task')) {
    Stop-ScheduledTask -TaskName $TaskName -TaskPath '\T3CodePolicy\' -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -TaskPath '\T3CodePolicy\' -Confirm:$false
  }
}

<# Stops every process running as the account, then removes its rights, the account and its profile. #>
function Remove-ServiceAccount {
  [CmdletBinding(SupportsShouldProcess)]
  param([Parameter(Mandatory)][string] $Name)
  $user = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
  if ($null -eq $user) { return $null }
  $sid = $user.SID.Value
  foreach ($process in Get-CimInstance Win32_Process) {
    $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid -ErrorAction SilentlyContinue
    if ($owner -and $owner.Sid -eq $sid -and $PSCmdlet.ShouldProcess("$($process.Name) ($($process.ProcessId))", "Stop process running as $Name")) {
      Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
    }
  }
  $remove = [ordered]@{}
  foreach ($right in (Get-ServiceAccountRightsPlan -Sid $sid).Keys) { $remove[$right] = @{ Remove = $sid } }
  Invoke-SeceditUserRights -Changes $remove -Description "rights for $Name" -WhatIf:$WhatIfPreference
  if ($PSCmdlet.ShouldProcess($Name, 'Remove local user')) { Remove-LocalUser -SID $sid }
  $profile = Get-CimInstance Win32_UserProfile -Filter "SID='$sid'" -ErrorAction SilentlyContinue
  if ($profile -and $PSCmdlet.ShouldProcess($profile.LocalPath, 'Remove profile')) { $profile | Remove-CimInstance }
  return $sid
}

Export-ModuleMember -Function New-ServiceAccountPasswordChars, Get-ServiceAccountRightsPlan, Update-UserRightsInf,
  Get-ServiceTaskXml, Get-T3FolderAclPlan, Format-T3AclPlanEntry, Compare-T3Acl, Get-DisallowedGroups,
  Get-MarkerCheckText, Get-T3LauncherText, Get-BridgeLauncherText, Get-TokenIssuerText, Get-TokenMoverText,
  Get-AccountGroups, Set-ServiceAccount, Invoke-SeceditUserRights, Register-ServiceTask, Remove-ServiceTask,
  Remove-ServiceAccount
