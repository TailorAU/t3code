#Requires -Version 7.2
<#
.SYNOPSIS
  Installs the T3 Code lock-down policy on one Windows machine. Run once, elevated.

.DESCRIPTION
  T3 Code v0.1.6 has no managed-policy file of its own (tailor/policy/README.md). This
  script applies the nearest equivalent from t3-policy.template.json. The server built
  from this fork reads the installed policy from the fixed path
  %ProgramData%\T3CodePolicy\t3-policy.json and refuses to start Claude unless the
  Claude instance uses the Claude home and binary recorded there (fail closed).

    0. Requires -ExpectedSha256 (script, template, both modules) unless it runs as the
       protected copy; copies itself into %ProgramData%\T3CodePolicy\installer (admin-only)
       and continues from there.
    1. Creates two local standard accounts with random passwords that are never stored:
       t3agent (runs t3 serve and its Claude) and t3bridge (runs the T3 bridge, the only
       reader of the connector token). Grants them batch logon and denies interactive, RDP
       and network logon (secedit, user rights area only).
    2. Creates the folders under %ProgramData%\T3CodePolicy with protected ACLs set at
       creation: no BUILTIN\Users and no interactive user anywhere. Refuses reparse points
       and folders not owned by Administrators or SYSTEM.
    3. Writes the Claude instance settings; t3agent may only create subfolders and modify
       .claude.json in the Claude home.
    4. Merges deny entries for the policy folder into Claude Code's machine-wide
       managed-settings.json (only those entries; every other setting is kept).
    5. Writes t3-policy.json (with binary hashes) and seeds T3's settings in the T3 home.
    6. Writes the launchers and registers the scheduled tasks (at startup, restart on
       failure, "run whether user is logged on or not") with the account passwords, which are
       then discarded. Starts T3.
    7. Issues a tailor:connector token into connector\token, readable by t3bridge only, never
       printed (-RotateConnectorToken replaces it and revokes the previous ones).
    8. Sets the policy's T3CODE_* variables at machine scope.
    9. Replaces its Windows Firewall rules: builds the new set first, then removes the old.
         - t3.exe: loopback only, in and out.
         - the Claude binary: loopback and the model endpoints (or loopback only).
         - the bridge: loopback and -TailorApiHosts out; nothing in.

  Windows Firewall matches IP addresses, not host names, and a Block rule always beats
  an Allow rule. The rules are therefore Block rules whose remote address is the
  complement of the allowed set, computed from DNS at install time. Re-run the protected
  copy to refresh, pass provider-published ranges with -ExtraAllowedAddresses, or use
  -ClaudeEgress LoopbackOnly with a host-name allowlisting proxy on loopback.

  Per-program rules do not cover child processes. Commands an agent runs (shell, git,
  curl) are separate programs and are NOT contained by these rules; Supervised approvals
  are the control for them. The stronger option is to run the Claude binary under a
  separate low-privilege local account (SECURITY-REVIEW.md, T3-03).

  The script holds no credentials and reads none. It is idempotent; -WhatIf previews
  every change (accounts, tasks and ACLs included); -Uninstall removes the tasks, accounts,
  profiles, rights, rules, variables, token, installed policy and the machine-file entries.

.PARAMETER T3Exe
  Full path of the t3.exe the connector starts (built from this fork).

.PARAMETER ClaudeExe
  Full path of the Claude binary T3's Claude instance uses. Use a dedicated copy in an
  admin-only folder that only T3 runs: the firewall rule applies to that path.

.PARAMETER ExpectedSha256
  SHA-256 of this script and of the template, as 'script=<hex>,template=<hex>', taken
  from the reviewed commit. The script refuses to run when either differs.

.EXAMPLE
  pwsh -NoProfile -ExecutionPolicy Bypass -File .\install-policy.ps1 `
    -T3Exe 'C:\Program Files\T3Code\t3.exe' -ClaudeExe 'C:\Program Files\T3Code\claude\claude.exe' -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [Parameter(Mandatory = $true)][string] $T3Exe,
  [Parameter(Mandatory = $true)][string] $ClaudeExe,
  # Defaults to t3-policy.template.json beside this script.
  [string] $PolicyTemplate,
  # Folder name under %ProgramData%\T3CodePolicy for the Claude home.
  [ValidatePattern('^[A-Za-z0-9._-]+$')][string] $ClaudeHomeName = 'claude-home',
  # Local standard account that runs t3 serve and its Claude (created by this installer).
  [ValidatePattern('^[A-Za-z0-9_-]{1,20}$')][string] $AgentAccount = 't3agent',
  # Local standard account that runs the T3 bridge and alone can read the connector token.
  [ValidatePattern('^[A-Za-z0-9_-]{1,20}$')][string] $BridgeAccount = 't3bridge',
  # The T3 bridge executable (the connector's T3 source). Without it the bridge account and the
  # protected token are still created, but no bridge task is registered.
  [string] $BridgeExe,
  # tailor.au API host names the bridge may reach (no default; for example api.example.com).
  [string[]] $TailorApiHosts = @(),
  # Issue a new connector token and revoke the previous ones.
  [switch] $RotateConnectorToken,
  [ValidateRange(1024, 65535)][int] $T3Port = 3773,
  # Host names the Claude binary may reach. Defaults to the template's egress.allowedHosts.
  [string[]] $AllowedHosts,
  # Extra IPv4/IPv6 addresses or CIDR ranges to allow, e.g. a provider's published API range.
  [string[]] $ExtraAllowedAddresses = @(),
  [ValidateSet('Resolve', 'LoopbackOnly')][string] $ClaudeEgress = 'Resolve',
  [string] $ExpectedSha256,
  [string] $RuleGroup = 'T3 Code egress policy',
  # Claude Code's machine-wide admin tier. Affects EVERY Claude session on the PC; the
  # installer only adds deny entries for the T3 home and the policy folder.
  [string] $MachineManagedSettingsPath = 'C:\Program Files\ClaudeCode\managed-settings.json',
  [switch] $SkipMachineManagedSettings,
  [switch] $Uninstall
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# The server reads the policy from the ProgramData known folder, not the ProgramData
# environment variable (machinePolicy.ts); this does the same.
$ProgramDataFolder = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
$PolicyDir = Join-Path $ProgramDataFolder 'T3CodePolicy'
$ClaudeConfigDir = Join-Path $PolicyDir $ClaudeHomeName
$InstallerDir = Join-Path $PolicyDir 'installer'
$ServiceDir = Join-Path $PolicyDir 'service'
$T3Home = Join-Path $PolicyDir 't3-home'
$ConnectorDir = Join-Path $PolicyDir 'connector'
$BridgeDir = Join-Path $PolicyDir 'bridge'
$TokenPath = Join-Path $ConnectorDir 'token'
$BridgeKeyPath = Join-Path $BridgeDir 'tailor-api-key'
$T3TaskName = 'T3 server'
$BridgeTaskName = 'T3 bridge'

function Assert-Elevated {
  $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    if ($WhatIfPreference) { Write-Warning 'Not elevated: previewing only.'; return }
    throw 'Run this script from an elevated PowerShell (Run as administrator).'
  }
}

# ---------- address arithmetic (IPv4 and IPv6 as BigInteger ranges) ----------
Add-Type -AssemblyName System.Numerics

function ConvertTo-BigInt([Net.IPAddress] $ip) {
  $bytes = $ip.GetAddressBytes()
  [Array]::Reverse($bytes)
  return [Numerics.BigInteger]::new([byte[]]($bytes + [byte]0))
}

function ConvertFrom-BigInt([Numerics.BigInteger] $value, [int] $length) {
  $raw = $value.ToByteArray()
  $bytes = New-Object byte[] $length
  for ($i = 0; $i -lt [Math]::Min($raw.Length, $length); $i++) { $bytes[$i] = $raw[$i] }
  [Array]::Reverse($bytes)
  return ([Net.IPAddress]::new($bytes)).ToString()
}

function ConvertTo-Range([string] $entry) {
  $parts = $entry.Trim().Split('/')
  $ip = [Net.IPAddress]::Parse($parts[0])
  if ($ip.IsIPv4MappedToIPv6) { $ip = $ip.MapToIPv4() }
  $bits = if ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) { 32 } else { 128 }
  $prefix = if ($parts.Length -gt 1) { [int]$parts[1] } else { $bits }
  $size = [Numerics.BigInteger]::Pow(2, $bits - $prefix)
  $start = (ConvertTo-BigInt $ip) / $size * $size
  return [pscustomobject]@{ Bits = $bits; Start = $start; End = $start + $size - 1 }
}

function Format-Range([string] $from, [string] $to) {
  if ($from -eq $to) { return $from }
  return "$from-$to"
}

# Ranges of one family that cover everything NOT in $allowed, as "a-b" strings.
function Get-Complement([object[]] $allowed, [int] $bits) {
  $max = [Numerics.BigInteger]::Pow(2, $bits) - 1
  $length = $bits / 8
  $sorted = @($allowed | Where-Object { $_.Bits -eq $bits } | Sort-Object { $_.Start })
  $result = New-Object System.Collections.Generic.List[string]
  $next = [Numerics.BigInteger]::Zero
  foreach ($range in $sorted) {
    if ($range.Start -gt $next) {
      $from = ConvertFrom-BigInt $next $length
      $to = ConvertFrom-BigInt ($range.Start - 1) $length
      $result.Add((Format-Range $from $to))
    }
    if ($range.End + 1 -gt $next) { $next = $range.End + 1 }
  }
  if ($next -le $max) {
    $from = ConvertFrom-BigInt $next $length
    $to = ConvertFrom-BigInt $max $length
    $result.Add((Format-Range $from $to))
  }
  return $result
}

function Get-BlockedAddresses([string[]] $allowedEntries) {
  $ranges = @($allowedEntries | Where-Object { $_ } | ForEach-Object { ConvertTo-Range $_ })
  return @(Get-Complement $ranges 32) + @(Get-Complement $ranges 128)
}

$Loopback = @('127.0.0.0/8', '::1/128')

function Resolve-AllowedHosts([string[]] $hosts) {
  $addresses = New-Object System.Collections.Generic.List[string]
  foreach ($name in $hosts) {
    $found = @()
    foreach ($type in 'A', 'AAAA') {
      try {
        $found += @(Resolve-DnsName -Name $name -Type $type -DnsOnly -ErrorAction Stop |
            Where-Object { $_.PSObject.Properties['IPAddress'] -and $_.IPAddress } |
            ForEach-Object { $_.IPAddress })
      } catch { }
    }
    if ($found.Count -eq 0) { Write-Warning "No addresses resolved for $name; it stays blocked." }
    else { Write-Host ("  {0}: {1}" -f $name, ($found -join ', ')) }
    $found | ForEach-Object { $addresses.Add($_) }
  }
  return $addresses
}


# ---------- ACLs, files, variables ----------
$SidAdministrators = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
$SidSystem = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
$SidTrustedInstaller = New-Object Security.Principal.SecurityIdentifier('S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
$AdminOwners = @($SidAdministrators, $SidSystem, $SidTrustedInstaller)

$InheritAll = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
$InheritNone = [Security.AccessControl.InheritanceFlags]::None
$PropagateNone = [Security.AccessControl.PropagationFlags]::None
$PropagateInheritOnly = [Security.AccessControl.PropagationFlags]::InheritOnly
$Allow = [Security.AccessControl.AccessControlType]::Allow
$RightsFull = [Security.AccessControl.FileSystemRights]::FullControl
$RightsRead = [Security.AccessControl.FileSystemRights]::ReadAndExecute
$RightsModify = [Security.AccessControl.FileSystemRights]::Modify

# A grant: @{ Sid = <SecurityIdentifier or $null in a preview>; Rights; Inherit; Propagate }.
function New-Grant($sid, $rights, $inherit = $InheritAll, $propagate = $PropagateNone) {
  return @{ Sid = $sid; Rights = $rights; Inherit = $inherit; Propagate = $propagate }
}

# Administrators and SYSTEM full, inheritance off, owner Administrators, plus the given grants.
# BUILTIN\Users and the interactive user are never added.
function New-ProtectedSecurity([bool] $isDirectory, [object[]] $grants = @()) {
  $security = if ($isDirectory) { New-Object Security.AccessControl.DirectorySecurity } else { New-Object Security.AccessControl.FileSecurity }
  $security.SetAccessRuleProtection($true, $false)
  $security.SetOwner($SidAdministrators)
  $inherit = if ($isDirectory) { $InheritAll } else { $InheritNone }
  $security.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($SidAdministrators, $RightsFull, $inherit, $PropagateNone, $Allow)))
  $security.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($SidSystem, $RightsFull, $inherit, $PropagateNone, $Allow)))
  foreach ($grant in $grants) {
    if ($null -eq $grant.Sid) { continue }
    $grantInherit = if ($isDirectory) { $grant.Inherit } else { $InheritNone }
    $grantPropagate = if ($isDirectory) { $grant.Propagate } else { $PropagateNone }
    $security.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($grant.Sid, $grant.Rights, $grantInherit, $grantPropagate, $Allow)))
  }
  return $security
}

function Assert-SafeExisting([string] $path) {
  $item = Get-Item -LiteralPath $path -Force
  if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw "Refusing to use $path : it is a reparse point (junction or symbolic link). Remove it and re-run."
  }
  $owner = (Get-Acl -LiteralPath $path).GetOwner([Security.Principal.SecurityIdentifier])
  if ($AdminOwners -notcontains $owner) {
    throw "Refusing to use $path : owned by $owner, not Administrators or SYSTEM. Remove it and re-run."
  }
}

# Creates the folder with its protected ACL in the same call, or checks and resets an existing one.
function Ensure-ProtectedDirectory([string] $path, [object[]] $grants = @(), [string] $describe = 'Administrators/SYSTEM only') {
  if (Test-Path -LiteralPath $path) {
    Assert-SafeExisting $path
    if ($PSCmdlet.ShouldProcess($path, "Reset ACL: $describe")) {
      Set-Acl -LiteralPath $path -AclObject (New-ProtectedSecurity $true $grants)
    }
    return
  }
  if ($PSCmdlet.ShouldProcess($path, "Create directory with ACL: $describe")) {
    [void][IO.FileSystemAclExtensions]::Create([IO.DirectoryInfo]::new($path), (New-ProtectedSecurity $true $grants))
    Assert-SafeExisting $path
  }
}

# Replaces a file inside a protected folder: deletes whatever is there (a planted link is
# removed, never written through), creates the new file with CreateNew, then sets its ACL.
function Write-ProtectedFile([string] $path, [byte[]] $bytes, [object[]] $grants = @(), [switch] $Secret) {
  $current = $null
  if (Test-Path -LiteralPath $path) {
    $item = Get-Item -LiteralPath $path -Force
    if (-not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { $current = [IO.File]::ReadAllBytes($path) }
  }
  $label = if ($Secret) { 'secret file (contents not shown)' } else { 'file' }
  if ($null -ne $current -and [Linq.Enumerable]::SequenceEqual([byte[]]$current, $bytes)) {
    Write-Host "  unchanged: $path"
  } elseif ($PSCmdlet.ShouldProcess($path, "Replace $label")) {
    if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
    $stream = [IO.FileStream]::new($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
  }
  if ((Test-Path -LiteralPath $path) -and $PSCmdlet.ShouldProcess($path, 'Set protected file ACL')) {
    Set-Acl -LiteralPath $path -AclObject (New-ProtectedSecurity $false $grants)
  }
}

function Get-Utf8Bytes([string] $text) { return [Text.UTF8Encoding]::new($false).GetBytes($text) }

function Set-MachineVariable([string] $name, [AllowNull()][object] $value) {
  if ($name -notmatch '^T3CODE_[A-Z0-9_]+$') { throw "Refusing machine variable '$name': only T3CODE_* names are allowed." }
  $current = [Environment]::GetEnvironmentVariable($name, 'Machine')
  if ($current -eq $value) { Write-Host "  unchanged: $name"; return }
  $action = if ($null -eq $value) { 'Remove machine variable' } else { "Set machine variable to '$value'" }
  if ($PSCmdlet.ShouldProcess($name, $action)) { [Environment]::SetEnvironmentVariable($name, $value, 'Machine') }
}

function Get-BytesSha256([byte[]] $bytes) {
  return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
}

# The binary and its folder must be owned by an admin principal and give no write to anyone else.
function Assert-AdminControlledBinary([string] $path) {
  # WriteData/CreateFiles, AppendData/CreateDirectories, WriteExtendedAttributes, DeleteSubdirectoriesAndFiles,
  # WriteAttributes, Delete, ChangePermissions, TakeOwnership, GENERIC_ALL, GENERIC_WRITE.
  $writeMask = 0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000
  foreach ($target in @($path, (Split-Path -Parent $path))) {
    $acl = Get-Acl -LiteralPath $target
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier])
    if ($AdminOwners -notcontains $owner) { throw "Refusing $target : owned by $owner, not an administrator principal." }
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
      if ($rule.AccessControlType -ne $Allow) { continue }
      if ($AdminOwners -contains $rule.IdentityReference) { continue }
      # An inherit-only entry (such as CREATOR OWNER) does not apply to the object itself.
      if (($rule.PropagationFlags -band $PropagateInheritOnly) -ne 0) { continue }
      if (([int64]$rule.FileSystemRights -band $writeMask) -ne 0) {
        throw "Refusing $target : $($rule.IdentityReference) can write it. Put the binary in an admin-only folder."
      }
    }
  }
}

function Resolve-Executable([string] $label, [string] $value) {
  if (-not [IO.Path]::IsPathRooted($value)) { throw "-$label must be a full path." }
  $full = [IO.Path]::GetFullPath($value)
  if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { throw "Not found: $full" }
  if ([IO.Path]::GetExtension($full) -ne '.exe') { throw "-$label must be an .exe: $full" }
  Assert-AdminControlledBinary $full
  return $full
}

# Claude permission-rule form of an absolute path (matches claudeDenyRules.ts).
function ConvertTo-ClaudeRulePath([string] $path) {
  $posix = $path.Replace('\', '/').TrimEnd('/')
  if ($posix -match '^([A-Za-z]):/(.*)$') { return '//' + $Matches[1].ToLowerInvariant() + '/' + $Matches[2] }
  return '/' + $posix
}

# Runs the T3 CLI against the T3 home and returns its standard output. Output is never printed.
function Invoke-T3Cli([string[]] $arguments) {
  $info = [Diagnostics.ProcessStartInfo]::new($T3Exe)
  foreach ($a in $arguments) { $info.ArgumentList.Add($a) }
  $info.RedirectStandardOutput = $true
  $info.RedirectStandardError = $true
  $info.UseShellExecute = $false
  $info.Environment['T3CODE_HOME'] = $T3Home
  foreach ($name in @($policy.serverEnvironmentMustBeUnset)) { [void]$info.Environment.Remove($name) }
  $process = [Diagnostics.Process]::Start($info)
  $stdout = $process.StandardOutput.ReadToEnd()
  [void]$process.StandardError.ReadToEnd()
  $process.WaitForExit()
  if ($process.ExitCode -ne 0) { throw "t3 $($arguments[0..2] -join ' ') failed with exit code $($process.ExitCode)." }
  return $stdout
}

# ---------- main ----------
Assert-Elevated
$scriptPath = $MyInvocation.MyCommand.Path
$runningProtected = $scriptPath.StartsWith($InstallerDir + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)
$here = Split-Path -Parent $scriptPath
if (-not $PolicyTemplate) { $PolicyTemplate = Join-Path $here 't3-policy.template.json' }
$mergeModule = Join-Path $here 'ManagedSettingsMerge.psm1'
$accountsModule = Join-Path $here 'ServiceAccounts.psm1'

# 0. Integrity. Read each file once; hash and use the same bytes.
$scriptBytes = [IO.File]::ReadAllBytes($scriptPath)
$templateBytes = [IO.File]::ReadAllBytes($PolicyTemplate)
$moduleBytes = [IO.File]::ReadAllBytes($mergeModule)
$accountsBytes = [IO.File]::ReadAllBytes($accountsModule)
$hashes = [ordered]@{
  script = Get-BytesSha256 $scriptBytes
  template = Get-BytesSha256 $templateBytes
  module = Get-BytesSha256 $moduleBytes
  accounts = Get-BytesSha256 $accountsBytes
}
$hashText = ($hashes.Keys | ForEach-Object { "$_=$($hashes[$_])" }) -join ','
Write-Host "Installer SHA-256: $hashText"
if ($ExpectedSha256) {
  $expected = @{}
  foreach ($pair in $ExpectedSha256.Split(',')) { $kv = $pair.Split('=', 2); if ($kv.Length -eq 2) { $expected[$kv[0].Trim()] = $kv[1].Trim().ToLowerInvariant() } }
  foreach ($key in $hashes.Keys) {
    if ($expected[$key] -ne $hashes[$key]) { throw "Hash mismatch for $key : not the reviewed version. Nothing was changed." }
  }
} elseif (-not $runningProtected) {
  throw "Pass -ExpectedSha256 $(($hashes.Keys | ForEach-Object { "$_=<hex>" }) -join ',') from the reviewed commit. Only the protected copy may run without it."
}
$policy = [Text.UTF8Encoding]::new($false).GetString($templateBytes) | ConvertFrom-Json
Import-Module $mergeModule -Force
Import-Module $accountsModule -Force

# Copy into the admin-only installer folder first and run from there.
if (-not $runningProtected -and -not $Uninstall) {
  Ensure-ProtectedDirectory $PolicyDir
  Ensure-ProtectedDirectory $InstallerDir
  Write-ProtectedFile (Join-Path $InstallerDir 'install-policy.ps1') $scriptBytes
  Write-ProtectedFile (Join-Path $InstallerDir 't3-policy.template.json') $templateBytes
  Write-ProtectedFile (Join-Path $InstallerDir 'ManagedSettingsMerge.psm1') $moduleBytes
  Write-ProtectedFile (Join-Path $InstallerDir 'ServiceAccounts.psm1') $accountsBytes
  if (-not $WhatIfPreference) {
    Write-Host "Continuing from the protected copy in $InstallerDir"
    $forward = @{} + $PSBoundParameters
    $forward.Remove('PolicyTemplate') | Out-Null
    & (Join-Path $InstallerDir 'install-policy.ps1') @forward
    exit $LASTEXITCODE
  }
  Write-Warning 'Preview: a real run continues from the protected copy.'
}

$serverVariables = [ordered]@{}
foreach ($variable in $policy.serverEnvironment.PSObject.Properties) {
  if ($variable.Name -notmatch '^T3CODE_[A-Z0-9_]+$') { throw "Template serverEnvironment has a non-T3CODE name: $($variable.Name)" }
  $serverVariables[$variable.Name] = [string]$variable.Value
}
$serverVariables['T3CODE_PORT'] = [string]$T3Port
$mustBeUnset = @($policy.serverEnvironmentMustBeUnset)

$installedPath = Join-Path $PolicyDir 't3-policy.json'
$previousInstalled = $null
if (Test-Path -LiteralPath $installedPath) {
  try { $previousInstalled = (Get-Content -LiteralPath $installedPath -Raw | ConvertFrom-Json).installed } catch { $previousInstalled = $null }
}

# ---------- machine-wide Claude admin tier helpers ----------
function Get-MachineDenyEntries {
  $entries = [System.Collections.Generic.List[string]]::new()
  $rule = ConvertTo-ClaudeRulePath $PolicyDir
  foreach ($tool in 'Read', 'Edit', 'Write') { $entries.Add("$tool($rule/**)") }
  return $entries.ToArray()
}

function Update-MachineManagedSettings([string[]] $entries) {
  $path = $MachineManagedSettingsPath
  $existing = if (Test-Path -LiteralPath $path) { [IO.File]::ReadAllText($path) } else { $null }
  $merge = Get-ManagedSettingsMerge -ExistingText $existing -Entries $entries   # throws on a malformed file
  if ($merge.Added.Count -eq 0) { Write-Host "  unchanged: $path"; return $null }
  Write-Host "  $path : adding to permissions.deny:"
  $merge.Added | ForEach-Object { Write-Host "    + $_" }
  if ($PSCmdlet.ShouldProcess($path, "Merge $($merge.Added.Count) deny entries (every other key unchanged)")) {
    if ($null -ne $existing) {
      $backup = Get-ManagedSettingsBackupPath $path
      Copy-Item -LiteralPath $path -Destination $backup
      Write-Host "  backup: $backup"
    }
    Write-ManagedSettingsAtomically -Path $path -Text $merge.Text
  }
  return [ordered]@{ path = $path; added = $merge.Added; created = $merge.Created }
}

function Undo-MachineManagedSettings($record) {
  if ($null -eq $record -or -not (Test-Path -LiteralPath $record.path)) { return }
  $existing = [IO.File]::ReadAllText($record.path)
  $removal = Get-ManagedSettingsRemoval -ExistingText $existing -Added @($record.added) -Created $record.created
  Write-Host "  $($record.path) : removing only the entries this installer added:"
  @($record.added) | ForEach-Object { Write-Host "    - $_" }
  if ($PSCmdlet.ShouldProcess($record.path, 'Remove the recorded deny entries')) {
    Copy-Item -LiteralPath $record.path -Destination (Get-ManagedSettingsBackupPath $record.path)
    if ($removal.DeleteFile) { Remove-Item -LiteralPath $record.path -Force }
    else { Write-ManagedSettingsAtomically -Path $record.path -Text $removal.Text }
  }
}

# ---------- uninstall ----------
if ($Uninstall) {
  foreach ($account in @(@{ Name = $AgentAccount; Task = $T3TaskName }, @{ Name = $BridgeAccount; Task = $BridgeTaskName })) {
    Remove-ServiceAccount -Name $account.Name -TaskName $account.Task -WhatIf:$WhatIfPreference
  }
  $previousRules = @(Get-NetFirewallRule -Group $RuleGroup -ErrorAction SilentlyContinue)
  if ($previousRules.Count -gt 0 -and $PSCmdlet.ShouldProcess($RuleGroup, "Remove $($previousRules.Count) firewall rule(s)")) { $previousRules | Remove-NetFirewallRule }
  foreach ($name in $serverVariables.Keys) { Set-MachineVariable $name $null }
  if ($null -ne $previousInstalled -and $previousInstalled.PSObject.Properties['machineManagedSettings']) {
    Undo-MachineManagedSettings $previousInstalled.machineManagedSettings
  }
  foreach ($path in @($TokenPath, $installedPath)) {
    if ((Test-Path -LiteralPath $path) -and $PSCmdlet.ShouldProcess($path, 'Remove')) { Remove-Item -LiteralPath $path -Force }
  }
  Write-Host 'Uninstalled. The T3 home, Claude home and bridge folder under T3CodePolicy are left for an administrator to delete.'
  Write-Host 'With the policy removed, a Windows server refuses to run Claude until it is installed again.'
  return
}

# ---------- validate every input before changing anything ----------
$T3Exe = Resolve-Executable 'T3Exe' $T3Exe
$ClaudeExe = Resolve-Executable 'ClaudeExe' $ClaudeExe
if ($BridgeExe) {
  $BridgeExe = Resolve-Executable 'BridgeExe' $BridgeExe
  if ($TailorApiHosts.Count -eq 0) { throw '-BridgeExe needs -TailorApiHosts (the tailor.au API host names it may reach).' }
}
# The service accounts need a machine-wide PowerShell 7: the Microsoft Store package is per user.
$pwshCandidate = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) 'PowerShell\7\pwsh.exe'
if (-not (Test-Path -LiteralPath $pwshCandidate)) {
  $pwshCandidate = (Get-Process -Id $PID).Path
  if ($pwshCandidate -match '\\WindowsApps\\') {
    if ($WhatIfPreference) { Write-Warning 'PowerShell 7 is the Store package; a real install needs the machine-wide MSI (Program Files\PowerShell\7).' }
    else { throw 'Install PowerShell 7 machine-wide (MSI, Program Files\PowerShell\7): the Store package cannot run as the service accounts.' }
  }
}
$PwshPath = Resolve-Executable 'pwsh' $pwshCandidate
if (-not $AllowedHosts) { $AllowedHosts = @($policy.egress.allowedHosts) }
foreach ($hostName in @($AllowedHosts) + @($TailorApiHosts)) {
  if ($hostName -notmatch '^(?=.{1,253}$)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$') { throw "Not a host name: $hostName" }
}
foreach ($entry in $ExtraAllowedAddresses) { [void](ConvertTo-Range $entry) }
$disabledProfiles = @(Get-NetFirewallProfile | Where-Object { -not $_.Enabled })
if ($disabledProfiles.Count -gt 0) {
  throw "Windows Firewall is off for: $(($disabledProfiles | ForEach-Object Name) -join ', '). Turn it on; the egress rules do nothing while it is off."
}

Write-Host 'Plan:'
Write-Host "  accounts: $AgentAccount (runs t3 serve and its Claude), $BridgeAccount (runs the bridge; only reader of the connector token)"
Write-Host "  tasks: \T3CodePolicy\$T3TaskName as $AgentAccount" $(if ($BridgeExe) { "; \T3CodePolicy\$BridgeTaskName as $BridgeAccount" } else { '; no bridge task (no -BridgeExe)' })
foreach ($entry in (Get-T3AccessPlan -PolicyDir $PolicyDir -AgentAccount $AgentAccount -BridgeAccount $BridgeAccount)) {
  Write-Host "  ACL $($entry.Path): $($entry.Access -join '; ')"
}

# Build the new firewall rule set before touching the old one.
$generation = [guid]::NewGuid().ToString('N').Substring(0, 8)
$serverBlocked = Get-BlockedAddresses $Loopback
$claudeAllowed = @($Loopback) + @($ExtraAllowedAddresses)
if ($ClaudeEgress -eq 'Resolve') {
  Write-Host 'Resolving model hosts:'
  $claudeAllowed += @(Resolve-AllowedHosts $AllowedHosts)
}
$rules = @(
  @{ Name = "T3Policy-$generation-server-out"; DisplayName = 'T3 server: block outbound except loopback'; Program = $T3Exe; Direction = 'Outbound'; RemoteAddress = $serverBlocked },
  @{ Name = "T3Policy-$generation-server-in"; DisplayName = 'T3 server: block inbound except loopback'; Program = $T3Exe; Direction = 'Inbound'; RemoteAddress = $serverBlocked },
  @{ Name = "T3Policy-$generation-claude-out"; DisplayName = "T3 Claude: block outbound except loopback and model endpoints ($ClaudeEgress)"; Program = $ClaudeExe; Direction = 'Outbound'; RemoteAddress = (Get-BlockedAddresses $claudeAllowed) }
)
if ($BridgeExe) {
  Write-Host 'Resolving tailor.au API hosts:'
  $bridgeAllowed = @($Loopback) + @(Resolve-AllowedHosts $TailorApiHosts)
  $rules += @{ Name = "T3Policy-$generation-bridge-out"; DisplayName = 'T3 bridge: block outbound except loopback and the tailor.au API'; Program = $BridgeExe; Direction = 'Outbound'; RemoteAddress = (Get-BlockedAddresses $bridgeAllowed) }
  # The bridge opens no listener: block every inbound connection to it.
  $rules += @{ Name = "T3Policy-$generation-bridge-in"; DisplayName = 'T3 bridge: block all inbound'; Program = $BridgeExe; Direction = 'Inbound'; RemoteAddress = (Get-BlockedAddresses @()) }
}
$previousRules = @(Get-NetFirewallRule -Group $RuleGroup -ErrorAction SilentlyContinue)

# ---------- 1. accounts ----------
Write-Host '1. Service accounts (random passwords, never stored)'
$agentPassword = Set-ServiceAccount -Name $AgentAccount -Description 'Runs T3 Code and its Claude (T3CodePolicy).' -WhatIf:$WhatIfPreference
$bridgePassword = Set-ServiceAccount -Name $BridgeAccount -Description 'Runs the T3 bridge; reads the connector token (T3CodePolicy).' -WhatIf:$WhatIfPreference
function Get-AccountSid([string] $name) {
  $user = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
  if ($null -eq $user) { return $null }   # only in a preview, before the account exists
  return $user.SID
}
$agentSid = Get-AccountSid $AgentAccount
$bridgeSid = Get-AccountSid $BridgeAccount
foreach ($pair in @(@{ Name = $AgentAccount; Sid = $agentSid }, @{ Name = $BridgeAccount; Sid = $bridgeSid })) {
  $sidText = if ($null -eq $pair.Sid) { '<new account SID>' } else { $pair.Sid.Value }
  Invoke-SeceditUserRights -Changes (Get-ServiceAccountRightsPlan -Sid $sidText) -Description "batch logon granted, interactive/RDP/network logon denied for $($pair.Name)" -WhatIf:$WhatIfPreference
}

# ---------- 2. folders ----------
Write-Host "2. Folders under $PolicyDir (no BUILTIN\Users, no interactive user)"
Ensure-ProtectedDirectory $PolicyDir @((New-Grant $agentSid $RightsRead $InheritNone)) "Administrators/SYSTEM; $AgentAccount read (this folder's files)"
Ensure-ProtectedDirectory $InstallerDir
Ensure-ProtectedDirectory $ServiceDir @((New-Grant $agentSid $RightsRead), (New-Grant $bridgeSid $RightsRead)) "Administrators/SYSTEM; $AgentAccount and $BridgeAccount read"
Ensure-ProtectedDirectory $T3Home @((New-Grant $agentSid $RightsModify)) "Administrators/SYSTEM; $AgentAccount modify"
Ensure-ProtectedDirectory $ClaudeConfigDir @() 'Administrators/SYSTEM (grants follow once its files exist)'
Ensure-ProtectedDirectory $ConnectorDir @((New-Grant $bridgeSid $RightsRead)) "Administrators/SYSTEM; $BridgeAccount read"
Ensure-ProtectedDirectory $BridgeDir @((New-Grant $bridgeSid $RightsRead)) "Administrators/SYSTEM; $BridgeAccount read"

# ---------- 3. Claude home ----------
Write-Host "3. Claude settings -> $ClaudeConfigDir"
$agentRead = @((New-Grant $agentSid $RightsRead))
Write-ProtectedFile (Join-Path $ClaudeConfigDir 'settings.json') (Get-Utf8Bytes (($policy.claudeInstance.settings | ConvertTo-Json -Depth 10) + "`n")) $agentRead
$claudeJson = Join-Path $ClaudeConfigDir '.claude.json'
if (-not (Test-Path -LiteralPath $claudeJson)) { Write-ProtectedFile $claudeJson (Get-Utf8Bytes "{}`n") }
if ($PSCmdlet.ShouldProcess($ClaudeConfigDir, "Grant ${AgentAccount}: read the home, create subfolders, modify only .claude.json and inside subfolders")) {
  Set-Acl -LiteralPath $ClaudeConfigDir -AclObject (New-ProtectedSecurity $true @(
      (New-Grant $agentSid ([Security.AccessControl.FileSystemRights]'ReadAndExecute, CreateDirectories') $InheritNone),
      (New-Grant $agentSid $RightsModify $InheritAll $PropagateInheritOnly)
    ))
  Set-Acl -LiteralPath $claudeJson -AclObject (New-ProtectedSecurity $false @((New-Grant $agentSid $RightsModify)))
  Set-Acl -LiteralPath (Join-Path $ClaudeConfigDir 'settings.json') -AclObject (New-ProtectedSecurity $false $agentRead)
}

# ---------- 4. machine-wide admin tier ----------
Write-Host '4. Machine-wide Claude admin tier (deny entries only)'
$machineRecord = $null
if (-not $SkipMachineManagedSettings) {
  $machineRecord = Update-MachineManagedSettings (Get-MachineDenyEntries)
  if ($null -eq $machineRecord -and $null -ne $previousInstalled -and $previousInstalled.PSObject.Properties['machineManagedSettings']) {
    $machineRecord = $previousInstalled.machineManagedSettings
  }
}

# ---------- 5. installed policy, T3 settings ----------
Write-Host '5. Installed policy and T3 settings'
$installed = [ordered]@{
  t3Exe = $T3Exe
  t3ExeSha256 = Get-BytesSha256 ([IO.File]::ReadAllBytes($T3Exe))
  claudeExe = $ClaudeExe
  claudeExeSha256 = Get-BytesSha256 ([IO.File]::ReadAllBytes($ClaudeExe))
  claudeConfigDir = $ClaudeConfigDir
  t3Home = $T3Home
  agentAccount = $AgentAccount
  bridgeAccount = $BridgeAccount
  instanceEnvironmentAllowlist = @($policy.claudeInstance.environmentAllowlist)
  installerSha256 = $hashText
}
if ($BridgeExe) { $installed['bridgeExe'] = $BridgeExe; $installed['bridgeExeSha256'] = Get-BytesSha256 ([IO.File]::ReadAllBytes($BridgeExe)) }
if ($null -ne $machineRecord) { $installed['machineManagedSettings'] = $machineRecord }
$policy | Add-Member -NotePropertyName installed -NotePropertyValue $installed -Force
Write-ProtectedFile $installedPath (Get-Utf8Bytes (($policy | ConvertTo-Json -Depth 12) + "`n")) $agentRead

# T3's own settings live in the T3 home, which only t3agent and administrators can reach. They
# are seeded once; the server enforces the policy whatever they say (machinePolicy.ts).
$userdata = Join-Path $T3Home 'userdata'
if (-not (Test-Path -LiteralPath $userdata)) {
  $seed = [ordered]@{}
  foreach ($p in $policy.t3SettingsSeed.PSObject.Properties) { $seed[$p.Name] = $p.Value }
  $seed['providerInstances'] = [ordered]@{
    ($policy.claudeInstance.instanceId) = [ordered]@{
      driver = $policy.claudeInstance.driver
      enabled = $true
      config = [ordered]@{ binaryPath = $ClaudeExe; homePath = $ClaudeConfigDir }
    }
  }
  Ensure-ProtectedDirectory $userdata @((New-Grant $agentSid $RightsModify)) "Administrators/SYSTEM; $AgentAccount modify"
  Write-ProtectedFile (Join-Path $userdata 'settings.json') (Get-Utf8Bytes (($seed | ConvertTo-Json -Depth 10) + "`n")) @((New-Grant $agentSid $RightsModify))
} else {
  Assert-SafeExisting $userdata
  Write-Host "  T3 settings already exist in $userdata; not reseeded."
}

# ---------- 6. launchers and tasks ----------
Write-Host '6. Launchers and scheduled tasks'
$t3Launcher = Join-Path $ServiceDir 'start-t3.ps1'
Write-ProtectedFile $t3Launcher (Get-Utf8Bytes (Get-T3LauncherText -T3Exe $T3Exe -T3Home $T3Home -Environment $serverVariables -MustBeUnset $mustBeUnset)) $agentRead
Register-ServiceTask -Plan (Get-ServiceTaskPlan -TaskName $T3TaskName -Account $AgentAccount -PwshPath $PwshPath -LauncherPath $t3Launcher) -Password $agentPassword -WhatIf:$WhatIfPreference
if ($BridgeExe) {
  $bridgeLauncher = Join-Path $ServiceDir 'start-bridge.ps1'
  Write-ProtectedFile $bridgeLauncher (Get-Utf8Bytes (Get-BridgeLauncherText -BridgeExe $BridgeExe -TokenPath $TokenPath -KeyPath $BridgeKeyPath -T3Url "http://127.0.0.1:$T3Port" -MustBeUnset $mustBeUnset)) @((New-Grant $bridgeSid $RightsRead))
  Register-ServiceTask -Plan (Get-ServiceTaskPlan -TaskName $BridgeTaskName -Account $BridgeAccount -PwshPath $PwshPath -LauncherPath $bridgeLauncher) -Password $bridgePassword -WhatIf:$WhatIfPreference
}
# The passwords are no longer needed anywhere.
$agentPassword.Dispose(); $bridgePassword.Dispose()
$agentPassword = $null; $bridgePassword = $null
if ($PSCmdlet.ShouldProcess("\T3CodePolicy\$T3TaskName", 'Start now')) {
  Start-ScheduledTask -TaskName $T3TaskName -TaskPath '\T3CodePolicy\'
}

# ---------- 7. connector token ----------
Write-Host "7. Connector token -> $TokenPath (readable by $BridgeAccount only; never printed)"
if ((-not (Test-Path -LiteralPath $TokenPath)) -or $RotateConnectorToken) {
  if ($PSCmdlet.ShouldProcess($TokenPath, 'Issue a tailor:connector token and store it (contents not shown)')) {
    $previous = @()
    try {
      $listed = Invoke-T3Cli @('auth', 'session', 'list', '--json', '--base-dir', $T3Home) | ConvertFrom-Json
      $previous = @($listed | Where-Object { @($_.scopes) -contains 'tailor:connector' } | ForEach-Object { $_.sessionId })
    } catch { $previous = @() }
    $issuedJson = Invoke-T3Cli @('auth', 'session', 'issue', '--base-dir', $T3Home, '--scope', 'tailor:connector', '--label', 'connector', '--ttl', '7d', '--json')
    $issued = $issuedJson | ConvertFrom-Json
    $issuedJson = $null
    $tokenBytes = Get-Utf8Bytes ([string]$issued.token)
    $newSession = [string]$issued.sessionId
    $issued = $null
    try {
      Write-ProtectedFile $TokenPath $tokenBytes @((New-Grant $bridgeSid $RightsRead)) -Secret
    } finally {
      [Array]::Clear($tokenBytes, 0, $tokenBytes.Length)
    }
    foreach ($sessionId in $previous) {
      if ($sessionId -and $sessionId -ne $newSession) {
        [void](Invoke-T3Cli @('auth', 'session', 'revoke', '--base-dir', $T3Home, $sessionId))
        Write-Host "  revoked previous connector session $sessionId"
      }
    }
  }
} else {
  Write-Host '  token exists; pass -RotateConnectorToken to replace it.'
}

# ---------- 8. machine environment ----------
Write-Host '8. Machine environment (T3CODE_* only)'
foreach ($name in $serverVariables.Keys) { Set-MachineVariable $name $serverVariables[$name] }

# ---------- 9. firewall ----------
Write-Host '9. Firewall (new rules first, then the previous ones are removed)'
foreach ($rule in $rules) {
  if ($PSCmdlet.ShouldProcess($rule.DisplayName, "Add block rule for $($rule.Program) ($($rule.RemoteAddress.Count) ranges)")) {
    New-NetFirewallRule -Name $rule.Name -Group $RuleGroup -DisplayName $rule.DisplayName -Program $rule.Program `
      -Direction $rule.Direction -Action Block -Profile Any -RemoteAddress $rule.RemoteAddress -Enabled True | Out-Null
  }
}
if ($previousRules.Count -gt 0 -and $PSCmdlet.ShouldProcess($RuleGroup, "Remove $($previousRules.Count) previous firewall rule(s)")) {
  $previousRules | Remove-NetFirewallRule
}

Write-Host ''
Write-Host 'Done. Next steps (not done by this script):'
Write-Host "  - Refresh later with the protected copy: $InstallerDir\install-policy.ps1"
Write-Host '  - Enter the model credential on the Claude provider instance as a sensitive value (provider-config.md).'
Write-Host "  - As an administrator, put the bridge's tailor.au key in $BridgeKeyPath (the folder ACL keeps it $BridgeAccount-only)."
Write-Host '  - Run the live egress capture (SECURITY-REVIEW.md, T3-01).'
