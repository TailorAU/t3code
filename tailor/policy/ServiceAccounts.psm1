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
  -Trigger           Startup (restart on failure), Daily (one run a day at 03:00), Every10Minutes,
                     or OnDemand (no trigger; started by the installer).
#>
function Get-ServiceTaskXml {
  param(
    [Parameter(Mandatory)][string] $Description,
    [string] $Account,
    [switch] $System,
    [Parameter(Mandatory)][string] $PwshPath,
    [Parameter(Mandatory)][string] $LauncherPath,
    [ValidateSet('Startup', 'Daily', 'Every10Minutes', 'OnDemand')][string] $Trigger = 'Startup',
    [ValidatePattern('^[A-Za-z0-9 -]*$')][string] $ExtraArguments = ''
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
    'OnDemand' { '' }
    'Every10Minutes' { '<TimeTrigger><Repetition><Interval>PT10M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition><StartBoundary>2026-01-01T00:00:00</StartBoundary><Enabled>true</Enabled></TimeTrigger><BootTrigger><Enabled>true</Enabled><Delay>PT5M</Delay></BootTrigger>' }
  }
  $restart = if ($Trigger -eq 'Startup') { '<RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure>' } else { '' }
  $limit = if ($Trigger -eq 'Startup') { 'PT0S' } else { 'PT15M' }
  $arguments = ("-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$LauncherPath`" " + $ExtraArguments).TrimEnd()
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
    [pscustomobject]@{ Name = 'git-config'; Path = (Join-Path $PolicyDir 'git-config'); Grants = @((& $g 'agent' $read)) }
    # The self-check's probe task (t3agent) leaves its result here: create only, like the drop.
    [pscustomobject]@{ Name = 'probe'; Path = (Join-Path $PolicyDir 'probe'); Grants = @(
        (& $g 'agent' 'CreateFiles, Synchronize' 'None'),
        (& $g 'agent' 'Write, ReadPermissions, Synchronize' 'ObjectInherit' 'InheritOnly'),
        (& $g 'OwnerRights' 'Synchronize' 'ObjectInherit' 'None')) }
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

$script:PinModulesText = '$env:PSModulePath = "$PSHOME\Modules;$env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules"'

function Get-UnsetText([string[]] $MustBeUnset) {
  $lines = @(foreach ($name in $MustBeUnset) {
    if ($name -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') { throw "Refusing variable name '$name'." }
    "Remove-Item -LiteralPath 'Env:$name' -ErrorAction SilentlyContinue"
  })
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
    [string] $SettingsSeedPath,
    # The bridge pipe shim (Get-BridgePipeShimText) and the pwsh that runs it.
    [Parameter(Mandatory)][string] $PipeShimPath,
    [Parameter(Mandatory)][string] $PwshPath,
    # The only PATH T3 and its children get: admin-owned folders (installer-checked).
    [Parameter(Mandatory)][string[]] $ServerPath
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
$($script:PinModulesText)
`$ErrorActionPreference = 'Stop'
$(Get-MarkerCheckText -MarkerPath $MarkerPath -RequiredFiles $RequiredFiles)
$(Get-UnsetText $MustBeUnset)
$($set -join "`n")
`$env:T3CODE_HOME = $(& $q $T3Home)
`$env:PATH = $(& $q ($ServerPath -join ';'))
$seed
while (`$true) {
  `$refusal = Test-T3Verified
  if (`$refusal) { Write-Warning "T3 not started: `$refusal"; Start-Sleep -Seconds 60; continue }
  `$server = Start-Process -FilePath $(& $q $T3Exe) -ArgumentList 'serve' -NoNewWindow -PassThru
  # The bridge pipe (as this account), relaying only to the t3 serve just started.
  `$shim = Start-Process -FilePath $(& $q $PwshPath) -NoNewWindow -PassThru -ArgumentList @(
    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $(& $q $PipeShimPath), '-ServerPid', [string]`$server.Id)
  while (-not `$server.HasExited) {
    if (`$shim.HasExited) {
      if (`$shim.ExitCode -eq 3) {
        Write-Error 'BRIDGE PIPE REFUSED: another process already holds the T3 bridge pipe name. The bridge cannot reach T3 until it is gone.' -ErrorAction Continue
      }
      Start-Sleep -Seconds 5
      # Restarted while T3 is up: the bridge must never find the name free for long.
      `$shim = Start-Process -FilePath $(& $q $PwshPath) -NoNewWindow -PassThru -ArgumentList @(
        '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $(& $q $PipeShimPath), '-ServerPid', [string]`$server.Id)
    }
    [void]`$server.WaitForExit(2000)
  }
  if (-not `$shim.HasExited) { Stop-Process -Id `$shim.Id -Force -ErrorAction SilentlyContinue }
  Start-Sleep -Seconds 10
}
"@
}

<#
  The launcher for the bridge: verified-marker check; token and key paths, the pipe and the
  owner the bridge must find on it (bridge contract, README). No TCP address is given: the
  bridge never falls back to loopback TCP.
#>
function Get-BridgeLauncherText {
  param(
    [Parameter(Mandatory)][string] $BridgeExe,
    [Parameter(Mandatory)][string] $TokenPath,
    [Parameter(Mandatory)][string] $KeyPath,
    [AllowEmptyCollection()][string[]] $MustBeUnset = @(),
    [Parameter(Mandatory)][string] $MarkerPath,
    [Parameter(Mandatory)][string[]] $RequiredFiles,
    [Parameter(Mandatory)][string] $AgentSid
  )
  $q = $script:LauncherQuote
  return @"
# Generated by install-policy.ps1. Runs as the t3bridge account under Task Scheduler.
$($script:PinModulesText)
`$ErrorActionPreference = 'Stop'
$(Get-MarkerCheckText -MarkerPath $MarkerPath -RequiredFiles $RequiredFiles)
$(Get-UnsetText $MustBeUnset)
`$env:T3_BRIDGE_PIPE = $(& $q (Get-T3BridgePipePath))
`$env:T3_BRIDGE_SERVER_OWNER_SID = $(& $q $AgentSid)
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
param([switch] `$RevokeAllPrevious)
$($script:PinModulesText)
`$ErrorActionPreference = 'Stop'
$(Get-MarkerCheckText -MarkerPath $MarkerPath -RequiredFiles $RequiredFiles)
$(Get-UnsetText $MustBeUnset)
`$refusal = Test-T3Verified
if (`$refusal) { Write-Warning "Token not issued: `$refusal"; exit 1 }
`$env:T3CODE_HOME = $(& $q $T3Home)
`$t3 = $(& $q $T3Exe)
`$drop = $(& $q $DropPath)
function Get-ConnectorSessions {
  `$listed = & `$t3 auth session list --base-dir `$env:T3CODE_HOME --json
  if (`$LASTEXITCODE -ne 0) { throw "Listing sessions failed (`$LASTEXITCODE)." }
  @(`$listed | ConvertFrom-Json | Where-Object { @(`$_.scopes) -contains 'tailor:connector' } | Sort-Object { [DateTime]`$_.issuedAt } -Descending)
}
function Revoke-ConnectorSession([string] `$sessionId) {
  & `$t3 auth session revoke --base-dir `$env:T3CODE_HOME `$sessionId | Out-Null
  if (`$LASTEXITCODE -ne 0) { throw "Revoking a connector session failed (`$LASTEXITCODE)." }
}
if (`$RevokeAllPrevious) {
  # Rotate now: every existing connector session goes first, whatever happens next.
  foreach (`$old in (Get-ConnectorSessions)) { Revoke-ConnectorSession `$old.sessionId }
  if (@(Get-ConnectorSessions).Count -ne 0) { Write-Error 'Connector sessions remain after revoking them all.' -ErrorAction Continue; exit 4 }
}
# This account may create the drop file but not see or delete it: claim it first, then issue.
try {
  `$stream = [IO.FileStream]::new(`$drop, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
} catch [IO.IOException] {
  if (`$RevokeAllPrevious) {
    Write-Error 'Every previous connector session was revoked, but an unmoved token still sits in the drop folder, so no new token was issued. Run -RotateConnectorToken again after the mover has run (within ten minutes).' -ErrorAction Continue
    exit 2
  }
  Write-Warning 'The previous token has not been moved yet; nothing issued.'; exit 0
}
`$newSession = `$null
try {
  # One retry: a busy database or a slow first start should not cost a day's rotation.
  for (`$attempt = 1; `$attempt -le 2 -and -not `$newSession; `$attempt++) {
    `$issued = (& `$t3 auth session issue --base-dir `$env:T3CODE_HOME --scope tailor:connector --label connector --ttl $Ttl --json) | ConvertFrom-Json
    if (`$LASTEXITCODE -ne 0 -or -not `$issued.token) { `$issued = `$null; if (`$attempt -lt 2) { Start-Sleep -Seconds 20 }; continue }
    `$bytes = [Text.UTF8Encoding]::new(`$false).GetBytes([string]`$issued.token)
    `$newSession = [string]`$issued.sessionId
    `$issued = `$null
    try { `$stream.Write(`$bytes, 0, `$bytes.Length) } finally { [Array]::Clear(`$bytes, 0, `$bytes.Length) }
  }
  if (-not `$newSession) { throw 'Issuing the connector token failed twice (the mover discards the empty drop file).' }
} finally { `$stream.Dispose() }
`$sessions = @(Get-ConnectorSessions | Where-Object { `$_.sessionId -ne `$newSession })
# Daily: keep the newest previous token, which the bridge still holds until the mover runs.
# -RevokeAllPrevious (install -RotateConnectorToken): revoke every previous connector session.
`$keep = if (`$RevokeAllPrevious) { 0 } else { 1 }
foreach (`$old in (`$sessions | Select-Object -Skip `$keep)) { Revoke-ConnectorSession `$old.sessionId }
# Proven, not assumed: re-list; only the new session (and, daily, one previous) may remain.
`$left = @(Get-ConnectorSessions | Where-Object { `$_.sessionId -ne `$newSession })
if (`$left.Count -gt `$keep) { Write-Error "`$(`$left.Count) previous connector sessions remain; expected at most `$keep." -ErrorAction Continue; exit 4 }
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
$($script:PinModulesText)
`$ErrorActionPreference = 'Stop'
`$drop = $(& $q $DropPath)
`$dropDir = Split-Path -Parent `$drop
`$token = $(& $q $TokenPath)
# Removing an entry (a link is removed as a link) is safe: the folder is admin-controlled.
function Remove-DropEntry([IO.FileSystemInfo] `$entry) {
  if (`$entry.PSIsContainer -and -not (`$entry.Attributes -band [IO.FileAttributes]::ReparsePoint)) { Remove-Item -LiteralPath `$entry.FullName -Recurse -Force }
  elseif (`$entry.PSIsContainer) { [IO.Directory]::Delete(`$entry.FullName, `$false) }
  else { [IO.File]::Delete(`$entry.FullName) }
}
# Sweep: anything but the token file is deleted on every run.
foreach (`$entry in @(Get-ChildItem -LiteralPath `$dropDir -Force | Where-Object { `$_.FullName -ne `$drop })) { Remove-DropEntry `$entry }
if (-not (Test-Path -LiteralPath `$drop)) { exit 0 }
`$item = Get-Item -LiteralPath `$drop -Force
`$reject = `$null
if (`$item.Attributes -band [IO.FileAttributes]::ReparsePoint) { `$reject = 'reparse point' }
elseif (`$item.PSIsContainer) { `$reject = 'not a file' }
elseif ((Get-Acl -LiteralPath `$drop).GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $(& $q $AgentSid)) { `$reject = 'not owned by the agent account' }
elseif (@(& "`$env:SystemRoot\System32\fsutil.exe" hardlink list `$drop).Count -ne 1) { `$reject = 'has other hard links' }
if (`$reject) { Write-Warning "Connector token drop rejected: `$reject"; Remove-DropEntry `$item; exit 1 }
try {
  `$in = [IO.FileStream]::new(`$drop, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
} catch { exit 0 }   # still being written; the next run takes it
# Bounded read from the open handle: at most 4097 bytes, never a size read from the path.
`$bytes = [byte[]]::new(4097); `$read = 0
try {
  while (`$read -lt `$bytes.Length) { `$n = `$in.Read(`$bytes, `$read, `$bytes.Length - `$read); if (`$n -le 0) { break }; `$read += `$n }
} finally { `$in.Dispose() }
try {
  if (`$read -lt 16 -or `$read -gt 4096) { [IO.File]::Delete(`$drop); throw 'The drop file has an unexpected size; discarded.' }
  `$bytes = [byte[]](`$bytes[0..(`$read - 1)])
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

# ---------- emergency revoke (pure planning) ----------

<#
  The key-rotation script, run by t3agent through the on-demand task 'T3 key rotation' (used by
  -EmergencyRevoke and -Uninstall). It checks t3.exe against the installed hash, then runs
  T3's own `t3 auth rotate-signing-keys` against the T3 home: every signing key is replaced and
  every session revoked, so every token issued before stops working. Not gated on the verified
  marker: a revoke must work on a broken install. Prints counts only.
#>
function Get-KeyRotationText {
  param(
    [Parameter(Mandatory)][string] $T3Exe,
    [Parameter(Mandatory)][string] $T3Home,
    [Parameter(Mandatory)][string] $PolicyPath,
    [AllowEmptyCollection()][string[]] $MustBeUnset = @()
  )
  $q = $script:LauncherQuote
  return @"
# Generated by install-policy.ps1. Runs as the t3agent account under Task Scheduler, on demand.
$($script:PinModulesText)
`$ErrorActionPreference = 'Stop'
$(Get-UnsetText $MustBeUnset)
`$t3 = $(& $q $T3Exe)
`$want = (Get-Content -LiteralPath $(& $q $PolicyPath) -Raw | ConvertFrom-Json).installed.t3ExeSha256
if ((Get-FileHash -LiteralPath `$t3 -Algorithm SHA256).Hash.ToLowerInvariant() -ne `$want) { throw 't3.exe differs from the installed hash; keys not rotated.' }
`$env:T3CODE_HOME = $(& $q $T3Home)
& `$t3 auth rotate-signing-keys --base-dir `$env:T3CODE_HOME
exit `$LASTEXITCODE
"@
}

<#
  The emergency revoke, as an ordered list of steps. Pure; -EmergencyRevoke runs exactly these
  and prints each one. Nothing here reads or prints a secret.
#>
function Get-EmergencyRevokePlan {
  param(
    [Parameter(Mandatory)][System.Collections.IDictionary] $Tasks,
    [Parameter(Mandatory)][string[]] $Accounts,
    [Parameter(Mandatory)][string] $MarkerPath,
    [Parameter(Mandatory)][string] $TokenPath,
    [Parameter(Mandatory)][string] $DropDir,
    [Parameter(Mandatory)][string] $RevokeLogPath,
    [string] $ProbeDir
  )
  $step = { param($action, $target, $detail) [pscustomobject]@{ Action = $action; Target = $target; Detail = $detail } }
  $plan = @(& $step 'RemoveMarker' $MarkerPath 'remove the verified marker: no launcher starts until install verifies again')
  foreach ($key in @('Server', 'Bridge', 'Issuer', 'Mover', 'RotateToken', 'Probe') | Where-Object { $Tasks.Contains($_) }) {
    $plan += & $step 'DisableTask' $Tasks[$key] 'disable (install re-enables it)'
    $plan += & $step 'StopTask' $Tasks[$key] 'stop if running'
  }
  foreach ($account in $Accounts) { $plan += & $step 'KillProcesses' $account 'stop every process running as this account, until none is left' }
  # The start time is what the self-check compares the new signing key with: the key is
  # written after it, so a reinstall after a successful revoke verifies.
  $plan += & $step 'RecordRevokeStart' $RevokeLogPath 'record the revoke start time (before the keys rotate)'
  $plan += & $step 'RotateKeys' $Tasks['Rotate'] 'run once as the agent account: new signing keys, every session and pairing link revoked'
  $plan += & $step 'DeleteFile' $TokenPath 'delete the connector token'
  $plan += & $step 'EmptyFolder' $DropDir 'delete anything in the token drop folder'
  if ($ProbeDir) { $plan += & $step 'EmptyFolder' $ProbeDir 'delete any stale probe result' }
  $plan += & $step 'AppendRevokeLog' $RevokeLogPath 'record how the revoke ended (verify-install checks the keys are newer than its start)'
  return $plan
}

<#
  verify-install.ps1: the signing key must have been written after the last recorded revoke.
  Uses the key's last-write time: NTFS file-name tunnelling can give a file renamed into a
  recently deleted name the old creation time, so creation time is not reliable here.
#>
function Test-SigningKeyFresh {
  param([AllowNull()][object] $KeyWrittenUtc, [AllowNull()][object] $LastRevokeUtc)
  if ($null -eq $LastRevokeUtc) {
    return [pscustomobject]@{ Ok = $true; Reason = 'no revoke recorded' }
  }
  if ($null -eq $KeyWrittenUtc) {
    return [pscustomobject]@{ Ok = $false; Reason = "a revoke was recorded at $(([DateTime]$LastRevokeUtc).ToString('o')) but there is no signing key: run -EmergencyRevoke again" }
  }
  if ([DateTime]$KeyWrittenUtc -le [DateTime]$LastRevokeUtc) {
    return [pscustomobject]@{ Ok = $false; Reason = "the signing key ($(([DateTime]$KeyWrittenUtc).ToString('o'))) is not newer than the last revoke ($(([DateTime]$LastRevokeUtc).ToString('o'))): run -EmergencyRevoke again" }
  }
  return [pscustomobject]@{ Ok = $true; Reason = "rotated after the last revoke ($(([DateTime]$LastRevokeUtc).ToString('o')))" }
}

<#
  The last revoke's START time in a revoke log (JSON array of records with 'startedAt', or for
  older records only 'at'), or $null. The start is recorded before the keys rotate, so a key
  written by that revoke is newer than it.
#>
function Get-LastRevokeTime {
  param([AllowNull()][object] $LogText)
  if ([string]::IsNullOrWhiteSpace([string]$LogText)) { return $null }
  # ConvertFrom-Json may already have turned the times into DateTime values.
  $toUtc = { param($v) if ($v -is [DateTime]) { $v.ToUniversalTime() } else { ([DateTimeOffset]::Parse([string]$v, [Globalization.CultureInfo]::InvariantCulture)).UtcDateTime } }
  $times = @(([string]$LogText | ConvertFrom-Json) | ForEach-Object {
      $start = $_.PSObject.Properties['startedAt']?.Value
      if ($null -ne $start) { & $toUtc $start } else { & $toUtc $_.at } })
  if ($times.Count -eq 0) { return $null }
  return ($times | Sort-Object -Descending | Select-Object -First 1)
}


# ---------- bridge pipe (the bridge authenticates the server) ----------

<#
  The T3 bridge reaches T3 only through the named pipe \\.\pipe\t3code-bridge, never loopback
  TCP. The pipe is created by the shim (service\bridge-pipe.ps1) that the T3 launcher starts as
  t3agent next to t3 serve:

    - FILE_FLAG_FIRST_PIPE_INSTANCE: creation fails if anyone already holds the name, and the
      shim refuses to run and says so;
    - owner t3agent; protected DACL: t3bridge read/write, SYSTEM read/write, t3agent (the
      owner) create-instance only; nobody else, not Users, not the interactive user, not
      Administrators; the security descriptor of the first instance is the pipe's for every
      later instance;
    - PIPE_REJECT_REMOTE_CLIENTS.

  The bridge (client) opens the pipe, reads the owner through its own handle, and sends
  nothing unless the owner is t3agent's SID from the admin-written policy file
  (Connect-T3BridgePipe is the reference). The connector token is still required over it.
#>
$script:BridgePipeName = 't3code-bridge'

$script:PipeNativeSource = @'
[StructLayout(LayoutKind.Sequential)]
public struct SECURITY_ATTRIBUTES { public int nLength; public IntPtr lpSecurityDescriptor; public int bInheritHandle; }
[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
static extern Microsoft.Win32.SafeHandles.SafePipeHandle CreateNamedPipeW(string name, uint openMode, uint pipeMode, uint maxInstances, uint outBuffer, uint inBuffer, uint timeout, ref SECURITY_ATTRIBUTES sa);
[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);
[DllImport("advapi32.dll", SetLastError = true)]
static extern uint GetSecurityInfo(Microsoft.Win32.SafeHandles.SafeFileHandle handle, int objectType, int info, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr sd);
[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(IntPtr sd, uint revision, int info, out IntPtr text, out uint length);
[DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr p);
[DllImport("kernel32.dll", SetLastError = true)]
static extern bool GetNamedPipeServerSessionId(Microsoft.Win32.SafeHandles.SafePipeHandle pipe, out uint sessionId);
/// The session of the process that created the pipe instance the client is connected to.
public static uint ServerSessionId(Microsoft.Win32.SafeHandles.SafePipeHandle pipe) {
  uint session;
  if (!GetNamedPipeServerSessionId(pipe, out session)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
  return session;
}
/// PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED (| FILE_FLAG_FIRST_PIPE_INSTANCE);
/// PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS.
public static Microsoft.Win32.SafeHandles.SafePipeHandle Create(string path, byte[] securityDescriptor, bool firstInstance, uint maxInstances) {
  var pinned = GCHandle.Alloc(securityDescriptor, GCHandleType.Pinned);
  try {
    var sa = new SECURITY_ATTRIBUTES { nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES)), lpSecurityDescriptor = pinned.AddrOfPinnedObject(), bInheritHandle = 0 };
    uint open = 0x3u | 0x40000000u | (firstInstance ? 0x00080000u : 0u);
    var handle = CreateNamedPipeW(path, open, 0x8u, maxInstances, 65536, 65536, 0, ref sa);
    if (handle.IsInvalid) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), path);
    return handle;
  } finally { pinned.Free(); }
}
/// Owner and DACL of an existing pipe, read through a READ_CONTROL handle (SDDL).
public static string ReadSddl(string path) {
  // READ_CONTROL, opened as a client with SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION so
  // the pipe's server can identify the reader but never act as it.
  using (var handle = CreateFileW(path, 0x00020000u, 0, IntPtr.Zero, 3, 0x00110000u, IntPtr.Zero)) {
    if (handle.IsInvalid) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), path);
    IntPtr owner, group, dacl, sacl, sd;
    uint result = GetSecurityInfo(handle, 1, 0x1 | 0x4, out owner, out group, out dacl, out sacl, out sd);
    if (result != 0) throw new System.ComponentModel.Win32Exception((int)result, path);
    try {
      IntPtr text; uint length;
      if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, 1, 0x1 | 0x4, out text, out length)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
      try { return Marshal.PtrToStringUni(text); } finally { LocalFree(text); }
    } finally { LocalFree(sd); }
  }
}
'@

function Initialize-T3PipeNative {
  if (-not ('T3Policy.PipeNative' -as [type])) {
    Add-Type -Namespace T3Policy -Name PipeNative -MemberDefinition $script:PipeNativeSource
  }
}

function Get-T3BridgePipePath([string] $Name = $script:BridgePipeName) {
  return ([string][char]92) * 2 + '.' + [char]92 + 'pipe' + [char]92 + $Name
}

<# The pipe's security descriptor. Pure. #>
function New-T3BridgePipeSecurity {
  param([Parameter(Mandatory)][string] $OwnerSid, [Parameter(Mandatory)][string] $BridgeSid)
  $security = [System.IO.Pipes.PipeSecurity]::new()
  $security.SetAccessRuleProtection($true, $false)
  $security.SetOwner([Security.Principal.SecurityIdentifier]::new($OwnerSid))
  $rule = { param($sid, $rights) [System.IO.Pipes.PipeAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid), [System.IO.Pipes.PipeAccessRights]$rights, 'Allow') }
  $security.AddAccessRule((& $rule $BridgeSid 'ReadWrite'))
  $security.AddAccessRule((& $rule 'S-1-5-18' 'ReadWrite'))
  # Only the owner may add instances: FILE_CREATE_PIPE_INSTANCE plus read/write, which
  # CreateNamedPipe needs for a further instance (0x12019f). Nobody else gets create-instance.
  $security.AddAccessRule((& $rule $OwnerSid 'ReadWrite, CreateNewInstance, Synchronize'))
  return $security
}

<#
  Checks a pipe's SDDL against the plan: owner t3agent; protected DACL; t3agent exactly
  read/write + create-instance (0x12019f); t3bridge and SYSTEM read/write, without
  create-instance, WRITE_DAC or WRITE_OWNER; nobody else. Pure.
#>
function Get-T3BridgePipeIssues {
  param([Parameter(Mandatory)][string] $Sddl, [Parameter(Mandatory)][string] $AgentSid, [Parameter(Mandatory)][string] $BridgeSid)
  $sd = [Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
  $issues = [System.Collections.Generic.List[string]]::new()
  if ($sd.Owner.Value -ne $AgentSid) { $issues.Add("owner is $($sd.Owner.Value), not the agent account") }
  if (($sd.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -eq 0) { $issues.Add('the DACL is not protected') }
  if ($null -eq $sd.DiscretionaryAcl) { $issues.Add('no DACL'); return $issues.ToArray() }
  $createInstance = 0x4
  $seen = @{}
  foreach ($ace in $sd.DiscretionaryAcl) {
    if ($ace.AceType -ne [Security.AccessControl.AceType]::AccessAllowed) { continue }
    $sid = $ace.SecurityIdentifier.Value; $mask = [int64]$ace.AccessMask
    $seen[$sid] = $true
    if ($sid -eq $AgentSid) {
      if ($mask -ne 0x12019f) { $issues.Add("the agent account has 0x$('{0:x}' -f $mask), not exactly read/write + create-instance (0x12019f)") }
    } elseif ($sid -eq $BridgeSid -or $sid -eq 'S-1-5-18') {
      if (($mask -band $createInstance) -ne 0) { $issues.Add("$sid may create pipe instances") }
      if (($mask -band (0x40000 -bor 0x80000)) -ne 0) { $issues.Add("$sid may change the pipe's DACL or owner") }
      if ($sid -eq $BridgeSid -and ($mask -band 0x3) -ne 0x3) { $issues.Add('the bridge account cannot read and write the pipe') }
    } else {
      $issues.Add("$sid has access (0x$('{0:x}' -f $mask))")
    }
  }
  foreach ($need in $BridgeSid, 'S-1-5-18', $AgentSid) { if (-not $seen.ContainsKey($need)) { $issues.Add("no entry for $need") } }
  return $issues.ToArray()
}

<#
  Reference bridge client: opens the pipe, reads the owner through its own handle, and returns
  the stream only if the owner is the expected SID; otherwise it closes the handle without
  writing a byte and throws. Never falls back to TCP.
#>
function Connect-T3BridgePipe {
  param(
    [Parameter(Mandatory)][string] $ExpectedOwnerSid,
    [string] $Name = $script:BridgePipeName,
    [int] $TimeoutMs = 5000,
    # The T3 server runs as a scheduled task in session 0. Tests that create their own pipe
    # in an interactive session turn this off.
    [bool] $RequireServiceSession = $true
  )
  Initialize-T3PipeNative
  # TokenImpersonationLevel.Identification: SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, so
  # the server can identify the bridge but never act as it.
  $client = [System.IO.Pipes.NamedPipeClientStream]::new('.', $Name, [System.IO.Pipes.PipeDirection]::InOut,
    [System.IO.Pipes.PipeOptions]::Asynchronous, [Security.Principal.TokenImpersonationLevel]::Identification)
  try {
    $client.Connect($TimeoutMs)
    $owner = [System.IO.Pipes.PipesAclExtensions]::GetAccessControl($client).GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -ne $ExpectedOwnerSid) { throw "Refusing the T3 pipe: owned by $owner, not $ExpectedOwnerSid. Nothing was sent." }
    if ($RequireServiceSession) {
      $session = [T3Policy.PipeNative]::ServerSessionId($client.SafePipeHandle)
      if ($session -ne 0) { throw "Refusing the T3 pipe: its server runs in session $session, not the service session 0. Nothing was sent." }
    }
    return $client
  } catch {
    $client.Dispose()
    throw
  }
}

<#
  The shim t3agent runs next to t3 serve: the first pipe instance (FIRST_PIPE_INSTANCE), then
  one more listening instance per connection, each relayed to T3's loopback listener. Before
  relaying, it checks that the connection it opened was accepted by the t3 serve process the
  launcher started (-ServerPid): t3agent can see its own processes, and the check runs on the
  established connection, so there is no check-then-connect gap.
#>
function Get-BridgePipeShimText {
  param([Parameter(Mandatory)][string] $AgentSid, [Parameter(Mandatory)][string] $BridgeSid, [Parameter(Mandatory)][int] $T3Port, [string] $Name = $script:BridgePipeName)
  $q = $script:LauncherQuote
  return @"
# Generated by install-policy.ps1. Runs as the t3agent account, started by start-t3.ps1.
param([Parameter(Mandatory)][int] `$ServerPid)
$($script:PinModulesText)
`$ErrorActionPreference = 'Stop'
Add-Type -Namespace T3Policy -Name PipeNative -MemberDefinition @'
$($script:PipeNativeSource)
'@
`$path = ([string][char]92) * 2 + '.' + [char]92 + 'pipe' + [char]92 + $(& $q $Name)
`$security = [System.IO.Pipes.PipeSecurity]::new()
`$security.SetAccessRuleProtection(`$true, `$false)
`$security.SetOwner([Security.Principal.SecurityIdentifier]::new($(& $q $AgentSid)))
foreach (`$g in @(@($(& $q $BridgeSid), 'ReadWrite'), @('S-1-5-18', 'ReadWrite'), @($(& $q $AgentSid), 'ReadWrite, CreateNewInstance, Synchronize'))) {
  `$security.AddAccessRule([System.IO.Pipes.PipeAccessRule]::new([Security.Principal.SecurityIdentifier]::new(`$g[0]), [System.IO.Pipes.PipeAccessRights]`$g[1], 'Allow'))
}
`$descriptor = `$security.GetSecurityDescriptorBinaryForm()
`$relays = [System.Collections.Generic.List[object]]::new()
function Remove-FinishedRelays {
  foreach (`$r in @(`$relays | Where-Object { `$_.Task.IsCompleted })) { `$r.Pipe.Dispose(); `$r.Tcp.Dispose(); [void]`$relays.Remove(`$r) }
}
try {
  `$next = [T3Policy.PipeNative]::Create(`$path, `$descriptor, `$true, 8)
} catch {
  Write-Error "REFUSED: `$path already exists (another process created it first). The bridge pipe is not started. Find and stop that process."
  exit 3
}
while (`$true) {
  `$pipe = [System.IO.Pipes.NamedPipeServerStream]::new([System.IO.Pipes.PipeDirection]::InOut, `$true, `$false, `$next)
  `$wait = `$pipe.WaitForConnectionAsync()
  while (-not `$wait.Wait(1000)) {
    Remove-FinishedRelays
    if (-not (Get-Process -Id `$ServerPid -ErrorAction SilentlyContinue)) { exit 0 }
  }
  # The next instance is listening before this one is handed off, so the name is never free.
  `$next = `$null
  while (`$null -eq `$next) {
    try { `$next = [T3Policy.PipeNative]::Create(`$path, `$descriptor, `$false, 8) } catch { Remove-FinishedRelays; Start-Sleep -Milliseconds 200 }
  }
  `$tcp = [Net.Sockets.TcpClient]::new()
  try {
    `$tcp.Connect([Net.IPAddress]::Loopback, $T3Port)
    `$mine = [Net.IPEndPoint]`$tcp.Client.LocalEndPoint
    `$theirs = [Net.IPEndPoint]`$tcp.Client.RemoteEndPoint
    # The accepting side of this very connection (all four of its address and port values)
    # must be the t3 serve the launcher started.
    `$accepted = @(Get-NetTCPConnection -State Established -LocalAddress `$theirs.Address.ToString() -LocalPort `$theirs.Port ``
      -RemoteAddress `$mine.Address.ToString() -RemotePort `$mine.Port -ErrorAction SilentlyContinue | ForEach-Object OwningProcess)
    if (`$theirs.Port -ne $T3Port -or `$accepted.Count -ne 1 -or `$accepted[0] -ne `$ServerPid) { throw "the T3 port is not served by T3 (PID `$(`$accepted -join ', '))" }
  } catch {
    Write-Warning "Bridge connection refused: `$(`$_.Exception.Message)"
    `$tcp.Dispose(); `$pipe.Dispose(); continue
  }
  `$net = `$tcp.GetStream()
  `$relays.Add([pscustomobject]@{ Pipe = `$pipe; Tcp = `$tcp; Task = [Threading.Tasks.Task]::WhenAny(`$pipe.CopyToAsync(`$net), `$net.CopyToAsync(`$pipe)) })
}
"@
}

<#
  The SYSTEM pipe probe (on-demand task 'T3 pipe probe'): SYSTEM is in the pipe's DACL, so it
  reads the security descriptor the pipe was created with, without being its owner, and writes
  it to probe\pipe.json for verify-install.ps1.
#>
function Get-PipeProbeText {
  param([Parameter(Mandatory)][string] $ResultPath)
  $q = $script:LauncherQuote
  return @"
# Generated by install-policy.ps1. Runs as SYSTEM, on demand, for verify-install.ps1.
$($script:PinModulesText)
`$ErrorActionPreference = 'Stop'
Add-Type -Namespace T3Policy -Name PipeNative -MemberDefinition @'
$($script:PipeNativeSource)
'@
`$path = ([string][char]92) * 2 + '.' + [char]92 + 'pipe' + [char]92 + $(& $q $script:BridgePipeName)
`$result = [ordered]@{ present = `$false }
try { `$result.sddl = [T3Policy.PipeNative]::ReadSddl(`$path); `$result.present = `$true }
catch {
  `$code = `$_.Exception.InnerException.NativeErrorCode
  `$result.error = `$_.Exception.Message
  `$result.errorCode = `$code
  # 231 = ERROR_PIPE_BUSY: the pipe exists but no instance is listening, which is a failure.
  `$result.busy = (`$code -eq 231)
}
`$result.at = [DateTime]::UtcNow.ToString('o')
`$out = $(& $q $ResultPath)
if (Test-Path -LiteralPath `$out) { [IO.File]::Delete(`$out) }
`$security = [Security.AccessControl.FileSecurity]::new()
`$security.SetAccessRuleProtection(`$true, `$false)
`$security.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-18'))
foreach (`$sid in 'S-1-5-32-544', 'S-1-5-18') {
  `$security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new(`$sid), 'FullControl', 'Allow'))
}
`$bytes = [Text.UTF8Encoding]::new(`$false).GetBytes((`$result | ConvertTo-Json))
`$stream = [IO.FileSystemAclExtensions]::Create([IO.FileInfo]::new(`$out), [IO.FileMode]::CreateNew,
  [Security.AccessControl.FileSystemRights]'Write, Synchronize', [IO.FileShare]::None, 4096, [IO.FileOptions]::None, `$security)
try { `$stream.Write(`$bytes, 0, `$bytes.Length) } finally { `$stream.Dispose() }
"@
}

# ---------- pinned binaries (pure planning) ----------

<#
  The deliberate update of a pinned binary (install-policy.ps1 -UpdatePinned). The pinned
  copies are used only by T3 and never update themselves.

    Claude, T3, Node: -From is the new single-file binary; it is copied over the pinned path
                      (the old one kept as a backup in state\pinned-backup\).
    Git:              Git is a whole install, not one file. -From must be the pinned git.exe
                      itself, after an administrator upgraded that admin-owned install in
                      place; the new hash is recorded (no copy, no backup).

  Returns @{ Refused = <reason or $null>; Steps = <ordered steps> }. Pure.
#>
function Get-PinnedUpdatePlan {
  param(
    [Parameter(Mandatory)][ValidateSet('Claude', 'Git', 'Node', 'T3')][string] $Kind,
    [AllowNull()][string] $InstalledPath,
    [Parameter(Mandatory)][string] $FromPath,
    [Parameter(Mandatory)][string] $BackupDir,
    # The SHA-256 the operator expects the new binary to have (required except for a rollback
    # from the backup folder, whose hash is in state\pinned-updates.json).
    [switch] $HasExpectedSha256,
    [string[]] $Accounts = @('t3agent', 't3bridge')
  )
  $refuse = { param($why) [pscustomobject]@{ Refused = $why; Steps = @() } }
  if (-not $InstalledPath) { return & $refuse "No pinned $Kind is recorded in t3-policy.json; install with it first." }
  if (-not [IO.Path]::IsPathRooted($FromPath)) { return & $refuse '-From must be a full path.' }
  $same = [string]::Equals([IO.Path]::GetFullPath($FromPath).TrimEnd('\'), [IO.Path]::GetFullPath($InstalledPath).TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)
  if ($Kind -eq 'Git' -and -not $same) {
    return & $refuse "Git is a whole install: upgrade the pinned Git in place ($InstalledPath) with its own installer, then run -UpdatePinned Git -From $InstalledPath. To move Git, re-run the install with -GitExe."
  }
  if ($Kind -ne 'Git' -and $same) { return & $refuse "-From is the pinned $Kind itself; give the new binary." }
  # Inside the backup folder itself: the prefix ends with a separator, so a sibling such as
  # 'pinned-backup-x\' never counts.
  $prefix = [IO.Path]::GetFullPath($BackupDir).TrimEnd('\') + '\'
  $fromBackup = [IO.Path]::GetFullPath($FromPath).StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
  if ($Kind -ne 'Git' -and -not $HasExpectedSha256 -and -not $fromBackup) {
    return & $refuse "-ExpectedSha256 is required for a new $Kind binary (only a rollback from $prefix may omit it)."
  }
  $step = { param($action, $detail) [pscustomobject]@{ Action = $action; Detail = $detail; Target = $null } }
  $steps = @(
    (& $step 'StopTasks' 'stop every T3 task'))
  # Stop-ScheduledTask leaves the launcher's t3.exe and claude.exe children running: stop
  # every process of the service accounts, until none is left, before anything is swapped.
  foreach ($account in $Accounts) {
    $kill = & $step 'KillProcesses' "stop every process running as $account, until none is left"
    $kill.Target = $account
    $steps += $kill
  }
  $steps += @(
    (& $step 'RemoveMarker' 'remove the verified marker: nothing starts until verification passes'),
    (& $step 'CheckSource' 'the source is a plain file (no link) with the expected SHA-256; Git: the whole install admin-owned, no links, then its version'))
  if ($Kind -ne 'Git') {
    $steps += & $step 'BackupCurrent' "move the current $Kind into $BackupDir (kept for a rollback)"
    $steps += & $step 'WriteNew' 'write the new binary next to the pinned path (CreateNew, protected DACL: Administrators/SYSTEM full, Users read and execute), then move it into place'
  }
  $steps += & $step 'RecordHash' 'record the new SHA-256 in t3-policy.json'
  $steps += & $step 'LogUpdate' 'append the old and new SHA-256 to state\pinned-updates.json'
  $steps += & $step 'Verify' 'run verify-install.ps1'
  $steps += & $step 'StartOnPass' 'start the tasks only on a full PASS; otherwise leave T3 stopped and print the rollback'
  return [pscustomobject]@{ Refused = $null; Steps = $steps; FromBackup = $fromBackup }
}

# ---------- self-check helpers (pure) ----------

<# [Privilege Rights] of a secedit export as right -> sorted member list. #>
function ConvertFrom-UserRightsInf {
  param([AllowNull()][string] $InfText)
  $rights = [ordered]@{}
  if (-not $InfText) { return $rights }
  $inSection = $false
  foreach ($line in ($InfText -split "`r?`n")) {
    $trimmed = $line.Trim()
    if ($trimmed.StartsWith('[')) { $inSection = ($trimmed -eq '[Privilege Rights]'); continue }
    if ($inSection -and $trimmed -match '^(\w+)\s*=\s*(.*)$') {
      $rights[$Matches[1]] = @($Matches[2].Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Sort-Object)
    }
  }
  return $rights
}

<#
  Differences between two user-rights exports. Allowed: the given SIDs added to the four
  service-account rights. Anything else (a removal, another right, another SID) is reported.
  With no allowed SIDs it checks that two exports are the same (uninstall).
#>
function Compare-UserRightsSnapshot {
  param([AllowNull()][string] $BeforeText, [AllowNull()][string] $AfterText, [string[]] $AllowedSids = @())
  $ours = @('SeBatchLogonRight', 'SeDenyInteractiveLogonRight', 'SeDenyRemoteInteractiveLogonRight', 'SeDenyNetworkLogonRight')
  $before = ConvertFrom-UserRightsInf $BeforeText
  $after = ConvertFrom-UserRightsInf $AfterText
  $issues = [System.Collections.Generic.List[string]]::new()
  foreach ($right in (@($before.Keys) + @($after.Keys) | Select-Object -Unique)) {
    $b = @(if ($before.Contains($right)) { $before[$right] }); $a = @(if ($after.Contains($right)) { $after[$right] })
    foreach ($m in $a) {
      if ($b -notcontains $m) {
        $allowed = $ours -contains $right -and $AllowedSids -contains $m.TrimStart('*')
        if (-not $allowed) { $issues.Add("$right gained $m") }
      }
    }
    foreach ($m in $b) { if ($a -notcontains $m) { $issues.Add("$right lost $m") } }
  }
  return $issues.ToArray()
}

<#
  Differences between the pre-install snapshot and the machine now (uninstall). Each side is
  an object with: variables (T3CODE_* name -> value), tasks (task paths under \T3CodePolicy\),
  taskFolder (bool), firewallRules (names in the rule group), managedSettings (canonical text
  or $null), rights (secedit export text).
#>
function Compare-PreInstallSnapshot {
  param([Parameter(Mandatory)] $Before, [Parameter(Mandatory)] $After)
  $issues = [System.Collections.Generic.List[string]]::new()
  $get = { param($o, $n) if ($o -is [System.Collections.IDictionary]) { $o[$n] } else { $o.PSObject.Properties[$n]?.Value } }
  $bv = & $get $Before 'variables'; $av = & $get $After 'variables'
  $names = @(@(if ($bv) { if ($bv -is [System.Collections.IDictionary]) { $bv.Keys } else { $bv.PSObject.Properties.Name } }) +
      @(if ($av) { if ($av -is [System.Collections.IDictionary]) { $av.Keys } else { $av.PSObject.Properties.Name } }) | Select-Object -Unique)
  foreach ($n in $names) {
    $x = if ($bv) { & $get $bv $n }; $y = if ($av) { & $get $av $n }
    if ($x -ne $y) { $issues.Add("machine variable $n was '$x', now '$y'") }
  }
  foreach ($t in @(& $get $After 'tasks')) { if ($t -and @(& $get $Before 'tasks') -notcontains $t) { $issues.Add("task $t still registered") } }
  if ((& $get $After 'taskFolder') -and -not (& $get $Before 'taskFolder')) { $issues.Add('task folder \T3CodePolicy still exists') }
  foreach ($r in @(& $get $After 'firewallRules')) { if ($r -and @(& $get $Before 'firewallRules') -notcontains $r) { $issues.Add("firewall rule $r still present") } }
  if ([string](& $get $Before 'managedSettings') -ne [string](& $get $After 'managedSettings')) { $issues.Add('machine managed-settings.json differs from before the install') }
  foreach ($d in (Compare-UserRightsSnapshot -BeforeText (& $get $Before 'rights') -AfterText (& $get $After 'rights'))) { $issues.Add("user rights: $d") }
  return $issues.ToArray()
}

<#
  A scheduled task's security descriptor (SDDL): only Administrators and SYSTEM may change,
  delete, start or stop it. Read access for others is allowed.
#>
<#
  The security descriptor every task is registered with: Administrators and SYSTEM only. The
  flags 0x16 (TASK_CREATE_OR_UPDATE | TASK_DONT_ADD_PRINCIPAL_ACE) stop Task Scheduler adding
  read access for the run-as account.
#>
$script:TaskSddl = 'D:P(A;;FA;;;BA)(A;;FA;;;SY)'

function Get-TaskSecurityIssues {
  param([Parameter(Mandatory)][string] $Sddl)
  # GENERIC_ALL|GENERIC_WRITE|GENERIC_EXECUTE, FILE_WRITE_DATA|APPEND|WRITE_EA|EXECUTE|WRITE_ATTRIBUTES, DELETE, WRITE_DAC, WRITE_OWNER
  $mask = 0x10000000 -bor 0x40000000 -bor 0x20000000 -bor 0x2 -bor 0x4 -bor 0x10 -bor 0x20 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000
  $sd = [Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
  $issues = [System.Collections.Generic.List[string]]::new()
  if ($null -eq $sd.DiscretionaryAcl) { return @('the task has no DACL: everyone has full access') }
  foreach ($ace in $sd.DiscretionaryAcl) {
    if ($ace.AceType -ne [Security.AccessControl.AceType]::AccessAllowed) { continue }
    $sid = $ace.SecurityIdentifier.Value
    if (@('S-1-5-32-544', 'S-1-5-18') -contains $sid) { continue }
    # Registered with Administrators and SYSTEM only: nobody else, the run-as account
    # included, may read, run, change or stop it.
    $what = if (([int64]$ace.AccessMask -band $mask) -ne 0) { 'may change, start or stop the task' } else { 'may read the task' }
    $issues.Add("$sid $what (mask 0x$('{0:x}' -f $ace.AccessMask))")
  }
  return $issues.ToArray()
}

<#
  The probe the self-check runs once as t3agent (on-demand task 'T3 self-check probe'): the
  account's privileges, groups and integrity level, and live access tests. It writes one JSON
  result into probe\ (create only) and never reads a secret's content: a read test opens the
  file and closes it.
#>
function Get-AgentProbeText {
  param(
    [Parameter(Mandatory)][string] $ResultPath,
    [Parameter(Mandatory)][System.Collections.IDictionary] $Tests   # name -> @{ Path; Mode = 'Read'|'WriteFile'|'CreateIn' }
  )
  $q = $script:LauncherQuote
  $lines = foreach ($name in $Tests.Keys) {
    if ($name -notmatch '^[A-Za-z0-9-]+$') { throw "Refusing probe test name '$name'." }
    $t = $Tests[$name]
    if ($t.Mode -notin 'Read', 'WriteFile', 'CreateIn') { throw "Unknown probe mode $($t.Mode)." }
    "`$tests[$(& $q $name)] = Test-Access $(& $q $t.Path) $(& $q $t.Mode)"
  }
  return @"
# Generated by install-policy.ps1. Runs as the t3agent account, on demand, for verify-install.ps1.
$($script:PinModulesText)
`$ErrorActionPreference = 'Stop'
function Test-Access([string] `$path, [string] `$mode) {
  try {
    switch (`$mode) {
      'Read' { [IO.File]::Open(`$path, 'Open', 'Read', 'ReadWrite').Dispose() }
      'WriteFile' { [IO.File]::Open(`$path, 'Open', 'Write', 'ReadWrite').Dispose() }
      'CreateIn' { `$f = Join-Path `$path ('.t3probe-' + [guid]::NewGuid().ToString('N')); [IO.File]::Open(`$f, 'CreateNew', 'Write').Dispose(); Remove-Item -LiteralPath `$f -Force -ErrorAction SilentlyContinue }
    }
    return 'allowed'
  } catch [UnauthorizedAccessException] { return 'denied' } catch { return "error: `$(`$_.Exception.GetType().Name)" }
}
`$tests = [ordered]@{}
$($lines -join "`n")
# The bridge pipe, if it is up: its security descriptor (read as the owner), and two negative
# tests: a second first instance must fail, and an instance claiming another owner must not
# change the pipe's owner (the first instance's descriptor is the pipe's).
Add-Type -Namespace T3Policy -Name PipeNative -MemberDefinition @'
$($script:PipeNativeSource)
'@
`$pipePath = ([string][char]92) * 2 + '.' + [char]92 + 'pipe' + [char]92 + $(& $q $script:BridgePipeName)
`$pipe = [ordered]@{ present = `$false }
try { `$pipe.sddl = [T3Policy.PipeNative]::ReadSddl(`$pipePath); `$pipe.present = `$true } catch { `$pipe.error = `$_.Exception.Message }
if (`$pipe.present) {
  `$other = [System.IO.Pipes.PipeSecurity]::new()
  `$other.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
  `$other.AddAccessRule([System.IO.Pipes.PipeAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-1-0'), 'FullControl', 'Allow'))
  try { [T3Policy.PipeNative]::Create(`$pipePath, `$other.GetSecurityDescriptorBinaryForm(), `$true, 8).Dispose(); `$pipe.firstInstance = 'created' } catch { `$pipe.firstInstance = 'refused' }
  try { [T3Policy.PipeNative]::Create(`$pipePath, `$other.GetSecurityDescriptorBinaryForm(), `$false, 8).Dispose() } catch { }
  try { `$pipe.sddlAfter = [T3Policy.PipeNative]::ReadSddl(`$pipePath) } catch { `$pipe.sddlAfter = `$pipe.sddl }
}
`$privileges = @(& "`$env:SystemRoot\System32\whoami.exe" /priv /fo csv | ConvertFrom-Csv | ForEach-Object { `$_.'Privilege Name' })
`$groups = @(& "`$env:SystemRoot\System32\whoami.exe" /groups /fo csv | ConvertFrom-Csv | ForEach-Object { `$_.SID })
`$result = [ordered]@{ user = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value; privileges = `$privileges; groups = `$groups; tests = `$tests; pipe = `$pipe; at = [DateTime]::UtcNow.ToString('o') }
`$bytes = [Text.UTF8Encoding]::new(`$false).GetBytes((`$result | ConvertTo-Json -Depth 4))
`$stream = [IO.FileStream]::new($(& $q $ResultPath), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try { `$stream.Write(`$bytes, 0, `$bytes.Length) } finally { `$stream.Dispose() }
"@
}

<#
  Judges a probe result. Privileges: only those a standard batch logon gets. Groups: none of the
  privileged builtin groups, not High or System integrity. Tests: as expected.
#>
$script:StandardPrivileges = @('SeChangeNotifyPrivilege', 'SeIncreaseWorkingSetPrivilege', 'SeTimeZonePrivilege', 'SeShutdownPrivilege', 'SeUndockPrivilege')
$script:PrivilegedGroupSids = @('S-1-5-32-544', 'S-1-5-32-547', 'S-1-5-32-548', 'S-1-5-32-549', 'S-1-5-32-550', 'S-1-5-32-551', 'S-1-5-32-552',
  'S-1-5-32-555', 'S-1-5-32-556', 'S-1-5-32-558', 'S-1-5-32-559', 'S-1-5-32-562', 'S-1-5-32-568', 'S-1-5-32-569', 'S-1-5-32-573',
  'S-1-5-32-578', 'S-1-5-32-579', 'S-1-5-32-580', 'S-1-5-32-583', 'S-1-16-12288', 'S-1-16-16384')
function Test-AgentProbeResult {
  param(
    [Parameter(Mandatory)] $Result,
    [Parameter(Mandatory)][System.Collections.IDictionary] $Expected,
    [Parameter(Mandatory)][string] $AgentSid,
    # With these, the bridge pipe is judged too; -RequirePipe fails when it is not up.
    [string] $BridgeSid,
    [switch] $RequirePipe
  )
  $issues = [System.Collections.Generic.List[string]]::new()
  if ($BridgeSid) {
    $pipe = $Result.PSObject.Properties['pipe']?.Value
    if ($null -eq $pipe -or -not $pipe.present) {
      if ($RequirePipe) { $issues.Add('the bridge pipe is not up') }
    } else {
      foreach ($i in (Get-T3BridgePipeIssues -Sddl ([string]$pipe.sddl) -AgentSid $AgentSid -BridgeSid $BridgeSid)) { $issues.Add("pipe: $i") }
      if ($pipe.firstInstance -ne 'refused') { $issues.Add('pipe: a second first instance could be created') }
      if ([string]$pipe.sddlAfter -ne [string]$pipe.sddl) { $issues.Add('pipe: an instance with another owner changed the pipe security') }
    }
  }
  if ([string]$Result.user -ne $AgentSid) { $issues.Add("the probe ran as $($Result.user), not the agent account") }
  foreach ($p in @($Result.privileges)) { if ($script:StandardPrivileges -notcontains $p) { $issues.Add("extra privilege $p") } }
  foreach ($g in @($Result.groups)) { if ($script:PrivilegedGroupSids -contains $g) { $issues.Add("privileged group or integrity $g") } }
  foreach ($name in $Expected.Keys) {
    $got = if ($Result.tests -is [System.Collections.IDictionary]) { $Result.tests[$name] } else { $Result.tests.PSObject.Properties[$name]?.Value }
    if ($got -ne $Expected[$name]) { $issues.Add("$name : expected $($Expected[$name]), got $got") }
  }
  return $issues.ToArray()
}

<# A minimal git version check: 'git version 2.51.2.windows.1' against '2.50.1'. #>
function Test-GitVersionAtLeast {
  param([Parameter(Mandatory)][string] $VersionText, [Parameter(Mandatory)][string] $Minimum)
  if ($VersionText -notmatch '(\d+)\.(\d+)\.(\d+)') { return $false }
  $have = [version]"$($Matches[1]).$($Matches[2]).$($Matches[3])"
  return $have -ge [version]$Minimum
}

# ---------- machine changes (elevated, used by install-policy.ps1) ----------

<#
  The local groups an account is in, as objects with Name and Sid, read by SID through ADSI
  (WinNT provider; Get-LocalGroupMember fails on orphaned members and compares names). Any
  error throws: callers fail closed.
#>
function Get-AccountGroups {
  param([Parameter(Mandatory)][string] $Name)
  $user = [ADSI]"WinNT://$env:COMPUTERNAME/$Name,user"
  $groups = foreach ($group in @($user.Groups())) {
    $sidBytes = $group.GetType().InvokeMember('objectSid', 'GetProperty', $null, $group, $null)
    $groupName = $group.GetType().InvokeMember('Name', 'GetProperty', $null, $group, $null)
    [pscustomobject]@{ Name = [string]$groupName; Sid = ([Security.Principal.SecurityIdentifier]::new([byte[]]$sidBytes, 0)).Value }
  }
  return , @($groups)
}

<#
  Creates the account, or resets its password, and returns the password as a SecureString.
  Refuses an existing account that is in any group but BUILTIN\Users.
#>
function Set-ServiceAccount {
  [CmdletBinding(SupportsShouldProcess)]
  param(
    [Parameter(Mandatory)][string] $Name,
    [Parameter(Mandatory)][string] $Description,
    # The SID recorded when this installer created the account; $null if it never did.
    [AllowNull()][string] $CreatedSid
  )
  $existing = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
  if ($null -ne $existing -and $existing.SID.Value -ne $CreatedSid) {
    throw "Refusing: a local account named $Name already exists and was not created by this installer. Pick another name with -AgentAccount/-BridgeAccount; this installer never resets or deletes an account it did not create."
  }
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

<# Overwrites a managed string's characters in place (pinned), so the copy does not linger. #>
function Clear-ManagedString([string] $text) {
  if ([string]::IsNullOrEmpty($text)) { return }
  $handle = [Runtime.InteropServices.GCHandle]::Alloc($text, [Runtime.InteropServices.GCHandleType]::Pinned)
  try {
    $address = $handle.AddrOfPinnedObject()
    for ($i = 0; $i -lt $text.Length; $i++) { [Runtime.InteropServices.Marshal]::WriteInt16($address, $i * 2, 0) }
  } finally { $handle.Free() }
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
    [void]$folder.RegisterTaskDefinition($TaskName, $definition, 0x16, 'SYSTEM', $null, 5, $script:TaskSddl)   # TASK_LOGON_SERVICE_ACCOUNT
    return
  }
  $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
  $plain = $null
  try {
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    [void]$folder.RegisterTaskDefinition($TaskName, $definition, 0x16, ".\$Account", $plain, 1, $script:TaskSddl)   # TASK_LOGON_PASSWORD
  } finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    if ($null -ne $plain) { Clear-ManagedString $plain; $plain = $null }
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

<#
  Runs $Body with the registry root of the account's HKCU: its loaded hive, or its NTUSER.DAT
  loaded for the call and unloaded after. $null when the account has no profile yet.
#>
function Invoke-WithUserHive {
  param([Parameter(Mandatory)][string] $Sid, [Parameter(Mandatory)][scriptblock] $Body)
  if (Test-Path -LiteralPath "Registry::HKEY_USERS\$Sid") { return & $Body "Registry::HKEY_USERS\$Sid" }
  $profile = Get-CimInstance Win32_UserProfile -Filter "SID='$Sid'" -ErrorAction SilentlyContinue
  $hive = if ($profile) { Join-Path $profile.LocalPath 'NTUSER.DAT' } else { $null }
  if (-not $hive -or -not (Test-Path -LiteralPath $hive)) { return & $Body $null }
  $mount = 'T3Policy_' + [guid]::NewGuid().ToString('N')
  & "$env:SystemRoot\System32\reg.exe" load "HKU\$mount" $hive | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "Could not load the hive of $Sid ($LASTEXITCODE)." }
  try { return & $Body "Registry::HKEY_USERS\$mount" }
  finally {
    [GC]::Collect(); [GC]::WaitForPendingFinalizers()
    & "$env:SystemRoot\System32\reg.exe" unload "HKU\$mount" | Out-Null
  }
}

<#
  The account's HKCU\Software\Policies: owned by Administrators, protected, Administrators and
  SYSTEM full, the account read only, so it cannot create a Claude policy for itself.
#>
function Set-UserPoliciesKeyAcl {
  [CmdletBinding(SupportsShouldProcess)]
  param([Parameter(Mandatory)][string] $Root, [Parameter(Mandatory)][string] $AccountSid)
  $key = "$Root\Software\Policies"
  if (-not $PSCmdlet.ShouldProcess($key, 'Admin-only ACL (the account reads only)')) { return }
  if (-not (Test-Path -LiteralPath $key)) { New-Item -Path $key -Force | Out-Null }
  $security = [Security.AccessControl.RegistrySecurity]::new()
  $security.SetAccessRuleProtection($true, $false)
  $security.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
  foreach ($g in @(@('S-1-5-32-544', 'FullControl'), @('S-1-5-18', 'FullControl'), @($AccountSid, 'ReadKey'))) {
    $security.AddAccessRule([Security.AccessControl.RegistryAccessRule]::new([Security.Principal.SecurityIdentifier]::new($g[0]),
        [Security.AccessControl.RegistryRights]$g[1], 'ContainerInherit', 'None', 'Allow'))
  }
  Set-Acl -LiteralPath $key -AclObject $security
}

function Get-UserPoliciesKeyIssues {
  param([Parameter(Mandatory)][string] $Root, [Parameter(Mandatory)][string] $AccountSid)
  $key = "$Root\Software\Policies"
  if (-not (Test-Path -LiteralPath $key)) { return @("$key is missing") }
  $acl = Get-Acl -LiteralPath $key
  $issues = [System.Collections.Generic.List[string]]::new()
  if (-not $acl.AreAccessRulesProtected) { $issues.Add('inheritance is on') }
  if (@('S-1-5-32-544', 'S-1-5-18') -notcontains $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value) { $issues.Add('not owned by an administrator principal') }
  $write = [int64][Security.AccessControl.RegistryRights]'SetValue, CreateSubKey, CreateLink, Delete, ChangePermissions, TakeOwnership'
  foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
    if ($rule.AccessControlType -ne 'Allow' -or @('S-1-5-32-544', 'S-1-5-18') -contains $rule.IdentityReference.Value) { continue }
    if ($rule.IdentityReference.Value -ne $AccountSid) { $issues.Add("$($rule.IdentityReference.Value) has access"); continue }
    if (([int64]$rule.RegistryRights -band $write) -ne 0) { $issues.Add('the account can write it') }
  }
  return $issues.ToArray()
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
  Get-KeyRotationText, Get-EmergencyRevokePlan, Test-SigningKeyFresh, Get-LastRevokeTime,
  Initialize-T3PipeNative, Get-T3BridgePipePath, New-T3BridgePipeSecurity, Get-T3BridgePipeIssues, Connect-T3BridgePipe,
  Get-BridgePipeShimText, Get-PipeProbeText, Get-PinnedUpdatePlan, ConvertFrom-UserRightsInf, Compare-UserRightsSnapshot,
  Compare-PreInstallSnapshot, Get-TaskSecurityIssues, Get-AgentProbeText, Test-AgentProbeResult,
  Test-GitVersionAtLeast, Clear-ManagedString,
  Invoke-WithUserHive, Set-UserPoliciesKeyAcl, Get-UserPoliciesKeyIssues,
  Get-AccountGroups, Set-ServiceAccount, Invoke-SeceditUserRights, Register-ServiceTask, Remove-ServiceTask,
  Remove-ServiceAccount
