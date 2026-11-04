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

<# What the scheduled task for one service looks like. Pure data, shown by -WhatIf. #>
function Get-ServiceTaskPlan {
  param(
    [Parameter(Mandatory)][string] $TaskName,
    [Parameter(Mandatory)][string] $Account,
    [Parameter(Mandatory)][string] $PwshPath,
    [Parameter(Mandatory)][string] $LauncherPath
  )
  return [pscustomobject]@{
    TaskName = $TaskName
    TaskPath = '\T3CodePolicy\'
    User = ".\$Account"
    LogonType = 'Password'          # "Run whether user is logged on or not"
    RunLevel = 'Limited'            # never elevated
    Trigger = 'AtStartup'
    Execute = $PwshPath
    Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$LauncherPath`""
    RestartCount = 999
    RestartIntervalMinutes = 1
    ExecutionTimeLimit = 'None'
    MultipleInstances = 'IgnoreNew'
  }
}

<#
  The access plan for the folders the installer owns. Principals are names; the interactive
  user and BUILTIN\Users never appear except where stated (none).
#>
function Get-T3AccessPlan {
  param(
    [Parameter(Mandatory)][string] $PolicyDir,
    [Parameter(Mandatory)][string] $AgentAccount,
    [Parameter(Mandatory)][string] $BridgeAccount
  )
  $admin = @('Administrators: full', 'SYSTEM: full')
  return @(
    [pscustomobject]@{ Path = $PolicyDir; Access = $admin + @("${AgentAccount}: read (t3-policy.json, seed)") }
    [pscustomobject]@{ Path = (Join-Path $PolicyDir 'installer'); Access = $admin }
    [pscustomobject]@{ Path = (Join-Path $PolicyDir 'service'); Access = $admin + @("${AgentAccount}: read", "${BridgeAccount}: read") }
    [pscustomobject]@{ Path = (Join-Path $PolicyDir 't3-home'); Access = $admin + @("${AgentAccount}: modify") }
    [pscustomobject]@{ Path = (Join-Path $PolicyDir 'claude-home'); Access = $admin + @("${AgentAccount}: read + create subfolders at the root; modify .claude.json and inside subfolders") }
    [pscustomobject]@{ Path = (Join-Path $PolicyDir 'connector'); Access = $admin + @("${BridgeAccount}: read") }
    [pscustomobject]@{ Path = (Join-Path $PolicyDir 'bridge'); Access = $admin + @("${BridgeAccount}: read") }
  )
}

<# The launcher script text for t3 serve: fixed environment, unsets, restart loop. #>
function Get-T3LauncherText {
  param(
    [Parameter(Mandatory)][string] $T3Exe,
    [Parameter(Mandatory)][string] $T3Home,
    [Parameter(Mandatory)][System.Collections.IDictionary] $Environment,
    [AllowEmptyCollection()][string[]] $MustBeUnset = @()
  )
  $quote = { param($v) "'" + ($v -replace "'", "''") + "'" }
  $set = foreach ($name in $Environment.Keys) {
    if ($name -notmatch '^T3CODE_[A-Z0-9_]+$') { throw "Refusing launcher variable '$name'." }
    "`$env:$name = $(& $quote ([string]$Environment[$name]))"
  }
  $unset = foreach ($name in $MustBeUnset) {
    if ($name -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') { throw "Refusing variable name '$name'." }
    "Remove-Item -LiteralPath 'Env:$name' -ErrorAction SilentlyContinue"
  }
  return @"
# Generated by install-policy.ps1. Runs as the t3agent account under Task Scheduler.
`$ErrorActionPreference = 'Stop'
$($unset -join "`n")
$($set -join "`n")
`$env:T3CODE_HOME = $(& $quote $T3Home)
while (`$true) {
  & $(& $quote $T3Exe) serve
  Start-Sleep -Seconds 10
}
"@
}

<# The launcher for the bridge: no listener of its own; token and key paths only. #>
function Get-BridgeLauncherText {
  param(
    [Parameter(Mandatory)][string] $BridgeExe,
    [Parameter(Mandatory)][string] $TokenPath,
    [Parameter(Mandatory)][string] $KeyPath,
    [Parameter(Mandatory)][string] $T3Url,
    [AllowEmptyCollection()][string[]] $MustBeUnset = @()
  )
  $quote = { param($v) "'" + ($v -replace "'", "''") + "'" }
  $unset = foreach ($name in $MustBeUnset) {
    if ($name -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') { throw "Refusing variable name '$name'." }
    "Remove-Item -LiteralPath 'Env:$name' -ErrorAction SilentlyContinue"
  }
  return @"
# Generated by install-policy.ps1. Runs as the t3bridge account under Task Scheduler.
`$ErrorActionPreference = 'Stop'
$($unset -join "`n")
`$env:T3_BRIDGE_T3_URL = $(& $quote $T3Url)
`$env:T3_BRIDGE_TOKEN_FILE = $(& $quote $TokenPath)
`$env:T3_BRIDGE_TAILOR_KEY_FILE = $(& $quote $KeyPath)
while (`$true) {
  & $(& $quote $BridgeExe)
  Start-Sleep -Seconds 10
}
"@
}

# ---------- machine changes (elevated, used by install-policy.ps1) ----------

<# Creates the account, or resets its password, and returns the password as a SecureString. #>
function Set-ServiceAccount {
  [CmdletBinding(SupportsShouldProcess)]
  param([Parameter(Mandatory)][string] $Name, [Parameter(Mandatory)][string] $Description)
  $chars = New-ServiceAccountPasswordChars
  $secure = [Security.SecureString]::new()
  foreach ($c in $chars) { $secure.AppendChar($c) }
  [Array]::Clear($chars, 0, $chars.Length)
  $secure.MakeReadOnly()
  $existing = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
  if ($null -eq $existing) {
    if ($PSCmdlet.ShouldProcess($Name, 'Create local standard user with a random password (never stored)')) {
      New-LocalUser -Name $Name -Password $secure -Description $Description -PasswordNeverExpires `
        -AccountNeverExpires -UserMayNotChangePassword | Out-Null
    }
  } elseif ($PSCmdlet.ShouldProcess($Name, 'Reset password to a new random one (never stored)')) {
    Set-LocalUser -Name $Name -Password $secure -PasswordNeverExpires $true -AccountNeverExpires
  }
  if ($PSCmdlet.ShouldProcess($Name, 'Make sure the account is not an administrator')) {
    $admins = Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "\\$([regex]::Escape($Name))$" }
    if ($admins) { Remove-LocalGroupMember -SID 'S-1-5-32-544' -Member $Name }
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

<# Registers the task with the account's password, then the caller discards the SecureString. #>
function Register-ServiceTask {
  [CmdletBinding(SupportsShouldProcess)]
  param([Parameter(Mandatory)] $Plan, [Parameter(Mandatory)][Security.SecureString] $Password)
  if (-not $PSCmdlet.ShouldProcess("$($Plan.TaskPath)$($Plan.TaskName)", "Register task as $($Plan.User): $($Plan.Execute) $($Plan.Arguments)")) { return }
  $action = New-ScheduledTaskAction -Execute $Plan.Execute -Argument $Plan.Arguments
  $trigger = New-ScheduledTaskTrigger -AtStartup
  $settings = New-ScheduledTaskSettingsSet -RestartCount $Plan.RestartCount `
    -RestartInterval (New-TimeSpan -Minutes $Plan.RestartIntervalMinutes) -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
  $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
  try {
    Register-ScheduledTask -TaskName $Plan.TaskName -TaskPath $Plan.TaskPath -Action $action -Trigger $trigger `
      -Settings $settings -User $Plan.User -Password ([Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)) `
      -RunLevel Limited -Force | Out-Null
  } finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
  }
}

<# Removes the task, the account, its rights and its profile. #>
function Remove-ServiceAccount {
  [CmdletBinding(SupportsShouldProcess)]
  param([Parameter(Mandatory)][string] $Name, [Parameter(Mandatory)][string] $TaskName)
  $task = Get-ScheduledTask -TaskName $TaskName -TaskPath '\T3CodePolicy\' -ErrorAction SilentlyContinue
  if ($task -and $PSCmdlet.ShouldProcess("\T3CodePolicy\$TaskName", 'Stop and unregister task')) {
    Stop-ScheduledTask -TaskName $TaskName -TaskPath '\T3CodePolicy\' -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -TaskPath '\T3CodePolicy\' -Confirm:$false
  }
  $user = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
  if ($null -eq $user) { return }
  $sid = $user.SID.Value
  $remove = [ordered]@{}
  foreach ($right in (Get-ServiceAccountRightsPlan -Sid $sid).Keys) { $remove[$right] = @{ Remove = $sid } }
  Invoke-SeceditUserRights -Changes $remove -Description "rights for $Name"
  if ($PSCmdlet.ShouldProcess($Name, 'Remove local user')) { Remove-LocalUser -SID $sid }
  $profile = Get-CimInstance Win32_UserProfile -Filter "SID='$sid'" -ErrorAction SilentlyContinue
  if ($profile -and $PSCmdlet.ShouldProcess($profile.LocalPath, 'Remove profile')) { $profile | Remove-CimInstance }
}

Export-ModuleMember -Function New-ServiceAccountPasswordChars, Get-ServiceAccountRightsPlan, Update-UserRightsInf,
  Get-ServiceTaskPlan, Get-T3AccessPlan, Get-T3LauncherText, Get-BridgeLauncherText, Set-ServiceAccount,
  Invoke-SeceditUserRights, Register-ServiceTask, Remove-ServiceAccount
