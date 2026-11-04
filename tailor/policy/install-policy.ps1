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

    0. Verifies its own SHA-256 and the template's against -ExpectedSha256 (when given),
       then copies both into %ProgramData%\T3CodePolicy\installer, which only
       Administrators and SYSTEM can write. Later refreshes run that copy.
    1. Creates %ProgramData%\T3CodePolicy and the Claude home with a protected ACL set
       at creation (inheritance off, owner Administrators). It refuses to continue if a
       folder already exists as a reparse point (junction, symlink) or is owned by
       anyone other than Administrators or SYSTEM, and resets (never adds to) the ACL.
    2. Writes the installed policy (template plus the installed paths) and a T3 settings
       seed into that folder. It never writes into a user-writable folder.
    3. Sets the policy's T3CODE_* server variables at machine scope (only T3 reads them).
    4. Writes the Claude instance settings file, read-only to non-admins.
    5. Replaces its Windows Firewall rules: validates every input and builds the new rules
       first, and removes the previous rules only after the new ones exist.
         - T3 server (-T3Exe): no inbound or outbound traffic except loopback.
         - T3's Claude binary (-ClaudeExe): no outbound traffic except loopback and the
           addresses of -AllowedHosts (or loopback only, with -ClaudeEgress LoopbackOnly).

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
  every change; -Uninstall removes the rules, variables and installed policy.

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
  # The account that runs t3 serve. It gets Modify on the Claude home, read-only on its settings.json.
  [string] $RunAsUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name,
  # Host names the Claude binary may reach. Defaults to the template's egress.allowedHosts.
  [string[]] $AllowedHosts,
  # Extra IPv4/IPv6 addresses or CIDR ranges to allow, e.g. a provider's published API range.
  [string[]] $ExtraAllowedAddresses = @(),
  [ValidateSet('Resolve', 'LoopbackOnly')][string] $ClaudeEgress = 'Resolve',
  [string] $ExpectedSha256,
  [string] $RuleGroup = 'T3 Code egress policy',
  # The T3 home of the account that runs t3 serve (its base dir). Defaults to <profile>\.t3.
  [string] $T3Home,
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
$SidUsers = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')
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

# Administrators and SYSTEM full, inheritance off, owner Administrators. -UsersRead adds
# BUILTIN\Users read (the policy folder only, so the server can read t3-policy.json).
function New-AdminOnlySecurity([bool] $isDirectory, [switch] $UsersRead) {
  $security = if ($isDirectory) { New-Object Security.AccessControl.DirectorySecurity } else { New-Object Security.AccessControl.FileSecurity }
  $security.SetAccessRuleProtection($true, $false)
  $security.SetOwner($SidAdministrators)
  $inherit = if ($isDirectory) { $InheritAll } else { $InheritNone }
  $security.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($SidAdministrators, $RightsFull, $inherit, $PropagateNone, $Allow)))
  $security.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($SidSystem, $RightsFull, $inherit, $PropagateNone, $Allow)))
  if ($UsersRead) { $security.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($SidUsers, $RightsRead, $inherit, $PropagateNone, $Allow))) }
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
function Ensure-AdminOnlyDirectory([string] $path, [switch] $UsersRead) {
  $security = New-AdminOnlySecurity $true -UsersRead:$UsersRead
  if (Test-Path -LiteralPath $path) {
    Assert-SafeExisting $path
    if ($PSCmdlet.ShouldProcess($path, 'Reset ACL to Administrators/SYSTEM' + $(if ($UsersRead) { ' (Users read)' } else { ' only' }))) {
      Set-Acl -LiteralPath $path -AclObject $security
    }
    return
  }
  if ($PSCmdlet.ShouldProcess($path, 'Create directory with an admin-only ACL')) {
    [void][IO.FileSystemAclExtensions]::Create([IO.DirectoryInfo]::new($path), $security)
    Assert-SafeExisting $path
  }
}

# Replaces a file inside an admin-only folder: deletes whatever is there (a planted link is
# removed, never written through), creates the new file with CreateNew, then sets its ACL.
function Write-AdminOnlyFile([string] $path, [byte[]] $bytes, [switch] $UsersRead) {
  $current = $null
  if (Test-Path -LiteralPath $path) {
    $item = Get-Item -LiteralPath $path -Force
    if (-not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { $current = [IO.File]::ReadAllBytes($path) }
  }
  if ($null -ne $current -and [Linq.Enumerable]::SequenceEqual([byte[]]$current, $bytes)) {
    Write-Host "  unchanged: $path"
  } elseif ($PSCmdlet.ShouldProcess($path, 'Replace file')) {
    if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
    $stream = [IO.FileStream]::new($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
  }
  if ((Test-Path -LiteralPath $path) -and $PSCmdlet.ShouldProcess($path, 'Set file ACL (admin-only' + $(if ($UsersRead) { ', Users read' } else { '' }) + ')')) {
    Set-Acl -LiteralPath $path -AclObject (New-AdminOnlySecurity $false -UsersRead:$UsersRead)
  }
}

function Get-Utf8Bytes([string] $text) { return [Text.UTF8Encoding]::new($false).GetBytes($text) }

function Set-MachineVariable([string] $name, [string] $value) {
  if ($name -notmatch '^T3CODE_[A-Z0-9_]+$') { throw "Refusing machine variable '$name': only T3CODE_* names are allowed." }
  $current = [Environment]::GetEnvironmentVariable($name, 'Machine')
  if ($current -eq $value) { Write-Host "  unchanged: $name"; return }
  $action = if ($null -eq $value) { 'Remove machine variable' } else { "Set machine variable to '$value'" }
  if ($PSCmdlet.ShouldProcess($name, $action)) {
    [Environment]::SetEnvironmentVariable($name, $value, 'Machine')
  }
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
      if (($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
      if (([int64]$rule.FileSystemRights -band $writeMask) -ne 0) {
        throw "Refusing $target : $($rule.IdentityReference) can write it. Put the binary in an admin-only folder."
      }
    }
  }
}

# Claude permission-rule form of an absolute path (matches claudeDenyRules.ts).
function ConvertTo-ClaudeRulePath([string] $path) {
  $posix = $path.Replace('\', '/').TrimEnd('/')
  if ($posix -match '^([A-Za-z]):/(.*)$') { return '//' + $Matches[1].ToLowerInvariant() + '/' + $Matches[2] }
  return '/' + $posix
}

# ---------- main ----------
Assert-Elevated
$scriptPath = $MyInvocation.MyCommand.Path
$runningProtected = $scriptPath.StartsWith($InstallerDir + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)
if (-not $PolicyTemplate) { $PolicyTemplate = Join-Path (Split-Path -Parent $scriptPath) 't3-policy.template.json' }
$mergeModule = Join-Path (Split-Path -Parent $scriptPath) 'ManagedSettingsMerge.psm1'

# 0. Integrity. Read each file once; hash and use the same bytes.
$scriptBytes = [IO.File]::ReadAllBytes($scriptPath)
$templateBytes = [IO.File]::ReadAllBytes($PolicyTemplate)
$moduleBytes = [IO.File]::ReadAllBytes($mergeModule)
$scriptHash = Get-BytesSha256 $scriptBytes
$templateHash = Get-BytesSha256 $templateBytes
$moduleHash = Get-BytesSha256 $moduleBytes
Write-Host "Installer SHA-256: script=$scriptHash,template=$templateHash,module=$moduleHash"
if ($ExpectedSha256) {
  $expected = @{}
  foreach ($pair in $ExpectedSha256.Split(',')) { $kv = $pair.Split('=', 2); if ($kv.Length -eq 2) { $expected[$kv[0].Trim()] = $kv[1].Trim().ToLowerInvariant() } }
  if ($expected['script'] -ne $scriptHash -or $expected['template'] -ne $templateHash -or $expected['module'] -ne $moduleHash) {
    throw 'Hash mismatch: this installer, its template or its module is not the reviewed version. Nothing was changed.'
  }
} elseif (-not $runningProtected) {
  throw 'Pass -ExpectedSha256 script=<hex>,template=<hex>,module=<hex> from the reviewed commit. Only the protected copy may run without it.'
}
$policy = [Text.UTF8Encoding]::new($false).GetString($templateBytes) | ConvertFrom-Json
Import-Module $mergeModule -Force

# Copy into the admin-only installer folder first and run from there.
if (-not $runningProtected -and -not $Uninstall) {
  Ensure-AdminOnlyDirectory $PolicyDir -UsersRead
  Ensure-AdminOnlyDirectory $InstallerDir
  Write-AdminOnlyFile (Join-Path $InstallerDir 'install-policy.ps1') $scriptBytes
  Write-AdminOnlyFile (Join-Path $InstallerDir 't3-policy.template.json') $templateBytes
  Write-AdminOnlyFile (Join-Path $InstallerDir 'ManagedSettingsMerge.psm1') $moduleBytes
  if (-not $WhatIfPreference) {
    Write-Host "Continuing from the protected copy in $InstallerDir"
    $forward = @{} + $PSBoundParameters
    $forward.Remove('PolicyTemplate') | Out-Null
    & (Join-Path $InstallerDir 'install-policy.ps1') @forward
    exit $LASTEXITCODE
  }
  Write-Warning 'Preview: a real run continues from the protected copy.'
}

$serverVariables = @($policy.serverEnvironment.PSObject.Properties)
foreach ($variable in $serverVariables) {
  if ($variable.Name -notmatch '^T3CODE_[A-Z0-9_]+$') { throw "Template serverEnvironment has a non-T3CODE name: $($variable.Name)" }
}

# Validate every input before changing anything.
$installedPath = Join-Path $PolicyDir 't3-policy.json'
$previousInstalled = $null
if (Test-Path -LiteralPath $installedPath) {
  try { $previousInstalled = (Get-Content -LiteralPath $installedPath -Raw | ConvertFrom-Json).installed } catch { $previousInstalled = $null }
}
if (-not $Uninstall) {
  foreach ($name in 'T3Exe', 'ClaudeExe') {
    $value = (Get-Variable -Name $name).Value
    if (-not [IO.Path]::IsPathRooted($value)) { throw "-$name must be a full path." }
    $full = [IO.Path]::GetFullPath($value)
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { throw "Not found: $full" }
    if ([IO.Path]::GetExtension($full) -ne '.exe') { throw "-$name must be an .exe: $full" }
    Assert-AdminControlledBinary $full
    Set-Variable -Name $name -Value $full -WhatIf:$false
  }
  if (-not $AllowedHosts) { $AllowedHosts = @($policy.egress.allowedHosts) }
  foreach ($hostName in $AllowedHosts) {
    if ($hostName -notmatch '^(?=.{1,253}$)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$') { throw "Not a host name: $hostName" }
  }
  foreach ($entry in $ExtraAllowedAddresses) { [void](ConvertTo-Range $entry) }
  $runAsSid = (New-Object Security.Principal.NTAccount($RunAsUser)).Translate([Security.Principal.SecurityIdentifier])
  if (-not $T3Home) {
    $profilePath = (Get-CimInstance Win32_UserProfile -Filter "SID='$($runAsSid.Value)'").LocalPath
    if (-not $profilePath) { throw "No profile found for $RunAsUser; pass -T3Home." }
    $T3Home = Join-Path $profilePath '.t3'
  }
  $disabledProfiles = @(Get-NetFirewallProfile | Where-Object { -not $_.Enabled })
  if ($disabledProfiles.Count -gt 0) {
    throw "Windows Firewall is off for: $(($disabledProfiles | ForEach-Object Name) -join ', '). Turn it on; the egress rules do nothing while it is off."
  }
}

# Build the new firewall rule set before touching the old one.
$generation = [guid]::NewGuid().ToString('N').Substring(0, 8)
$rules = @()
if (-not $Uninstall) {
  $serverBlocked = Get-BlockedAddresses $Loopback
  $claudeAllowed = @($Loopback) + @($ExtraAllowedAddresses)
  if ($ClaudeEgress -eq 'Resolve') {
    Write-Host 'Resolving allowed hosts:'
    $claudeAllowed += @(Resolve-AllowedHosts $AllowedHosts)
  }
  $claudeBlocked = Get-BlockedAddresses $claudeAllowed
  $rules = @(
    @{ Name = "T3Policy-$generation-server-out"; DisplayName = 'T3 server: block outbound except loopback'; Program = $T3Exe; Direction = 'Outbound'; RemoteAddress = $serverBlocked },
    @{ Name = "T3Policy-$generation-server-in"; DisplayName = 'T3 server: block inbound except loopback'; Program = $T3Exe; Direction = 'Inbound'; RemoteAddress = $serverBlocked },
    @{ Name = "T3Policy-$generation-claude-out"; DisplayName = "T3 Claude: block outbound except loopback and model endpoints ($ClaudeEgress)"; Program = $ClaudeExe; Direction = 'Outbound'; RemoteAddress = $claudeBlocked }
  )
}
$previousRules = @(Get-NetFirewallRule -Group $RuleGroup -ErrorAction SilentlyContinue)

# The machine-wide admin tier: deny the agent the T3 home and the policy folder. Only these.
function Get-MachineDenyEntries([string] $t3Home) {
  $entries = [System.Collections.Generic.List[string]]::new()
  foreach ($root in @($PolicyDir, $t3Home)) {
    $rule = ConvertTo-ClaudeRulePath $root
    foreach ($tool in 'Read', 'Edit', 'Write') { $entries.Add("$tool($rule/**)") }
  }
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

if ($Uninstall) {
  if ($previousRules.Count -gt 0 -and $PSCmdlet.ShouldProcess($RuleGroup, "Remove $($previousRules.Count) firewall rule(s)")) { $previousRules | Remove-NetFirewallRule }
  foreach ($variable in $serverVariables) { Set-MachineVariable $variable.Name $null }
  if ($null -ne $previousInstalled -and $previousInstalled.PSObject.Properties['machineManagedSettings']) {
    Undo-MachineManagedSettings $previousInstalled.machineManagedSettings
  }
  if ((Test-Path -LiteralPath $installedPath) -and $PSCmdlet.ShouldProcess($installedPath, 'Remove installed policy')) { Remove-Item -LiteralPath $installedPath -Force }
  Write-Host 'Uninstalled. With the policy removed, a Windows server refuses to run Claude until it is installed again.'
  return
}

Write-Host "1. Admin-only folders under $PolicyDir"
Ensure-AdminOnlyDirectory $PolicyDir -UsersRead
Ensure-AdminOnlyDirectory $InstallerDir
# The Claude home starts admin-only; its files are written before the run-as account gets any access.
Ensure-AdminOnlyDirectory $ClaudeConfigDir

Write-Host "2. Claude settings -> $ClaudeConfigDir"
Write-AdminOnlyFile (Join-Path $ClaudeConfigDir 'settings.json') (Get-Utf8Bytes (($policy.claudeInstance.settings | ConvertTo-Json -Depth 10) + "`n"))
$claudeJson = Join-Path $ClaudeConfigDir '.claude.json'
if (-not (Test-Path -LiteralPath $claudeJson)) { Write-AdminOnlyFile $claudeJson (Get-Utf8Bytes "{}`n") }
if ($PSCmdlet.ShouldProcess($ClaudeConfigDir, "Grant ${RunAsUser}: read the home, create subfolders, modify only .claude.json and inside subfolders")) {
  $acl = Get-Acl -LiteralPath $ClaudeConfigDir
  # Root: read and create subfolders, but no file creation and no change to settings.json.
  $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($runAsSid, [Security.AccessControl.FileSystemRights]'ReadAndExecute, CreateDirectories', $InheritNone, $PropagateNone, $Allow)))
  # Inside subfolders (Claude's projects, todos, sessions and so on): modify.
  $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($runAsSid, $RightsModify, [Security.AccessControl.InheritanceFlags]::ContainerInherit, $PropagateInheritOnly, $Allow)))
  $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($runAsSid, $RightsModify, $InheritAll, $PropagateInheritOnly, $Allow)))
  Set-Acl -LiteralPath $ClaudeConfigDir -AclObject $acl
  $fileAcl = Get-Acl -LiteralPath $claudeJson
  $fileAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($runAsSid, $RightsModify, $InheritNone, $PropagateNone, $Allow)))
  Set-Acl -LiteralPath $claudeJson -AclObject $fileAcl
  $settingsAcl = Get-Acl -LiteralPath (Join-Path $ClaudeConfigDir 'settings.json')
  $settingsAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($runAsSid, $RightsRead, $InheritNone, $PropagateNone, $Allow)))
  Set-Acl -LiteralPath (Join-Path $ClaudeConfigDir 'settings.json') -AclObject $settingsAcl
}

Write-Host '3. Machine-wide Claude admin tier (deny entries only)'
$machineRecord = $null
if (-not $SkipMachineManagedSettings) {
  $machineRecord = Update-MachineManagedSettings (Get-MachineDenyEntries $T3Home)
  if ($null -eq $machineRecord -and $null -ne $previousInstalled -and $previousInstalled.PSObject.Properties['machineManagedSettings']) {
    $machineRecord = $previousInstalled.machineManagedSettings
  }
}

Write-Host '4. Installed policy and T3 settings seed'
$installed = [ordered]@{
  t3Exe = $T3Exe
  t3ExeSha256 = Get-BytesSha256 ([IO.File]::ReadAllBytes($T3Exe))
  claudeExe = $ClaudeExe
  claudeExeSha256 = Get-BytesSha256 ([IO.File]::ReadAllBytes($ClaudeExe))
  claudeConfigDir = $ClaudeConfigDir
  t3Home = $T3Home
  runAsUser = $RunAsUser
  instanceEnvironmentAllowlist = @($policy.claudeInstance.environmentAllowlist)
  installerSha256 = "script=$scriptHash,template=$templateHash,module=$moduleHash"
}
if ($null -ne $machineRecord) { $installed['machineManagedSettings'] = $machineRecord }
$policy | Add-Member -NotePropertyName installed -NotePropertyValue $installed -Force
Write-AdminOnlyFile $installedPath (Get-Utf8Bytes (($policy | ConvertTo-Json -Depth 12) + "`n")) -UsersRead

$seed = [ordered]@{}
foreach ($p in $policy.t3SettingsSeed.PSObject.Properties) { $seed[$p.Name] = $p.Value }
$seed['providerInstances'] = [ordered]@{
  ($policy.claudeInstance.instanceId) = [ordered]@{
    driver = $policy.claudeInstance.driver
    enabled = $true
    config = [ordered]@{ binaryPath = $ClaudeExe; homePath = $ClaudeConfigDir }
  }
}
Write-AdminOnlyFile (Join-Path $PolicyDir 't3-settings.seed.json') (Get-Utf8Bytes (($seed | ConvertTo-Json -Depth 10) + "`n")) -UsersRead

Write-Host '5. Machine environment (T3CODE_* only)'
foreach ($variable in $serverVariables) { Set-MachineVariable $variable.Name ([string]$variable.Value) }
foreach ($name in @($policy.serverEnvironmentMustBeUnset)) {
  if ([Environment]::GetEnvironmentVariable($name, 'Machine')) { Write-Warning "$name is set machine-wide; it must be unset for t3 serve (the connector clears it)." }
  if ([Environment]::GetEnvironmentVariable($name, 'User')) { Write-Warning "$name is set for the current user; it must be unset for t3 serve (the connector clears it)." }
}

Write-Host '6. Firewall (new rules first, then the previous ones are removed)'
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
Write-Host "  - Start t3 serve only through the connector, with the policy's serverEnvironment and t3-settings.seed.json."
Write-Host '  - Enter the model credential on the Claude provider instance as a sensitive value (provider-config.md).'
Write-Host "  - Issue the connector token: $($policy.connectorToken.issueCommand)"
Write-Host '  - Run the live egress capture (SECURITY-REVIEW.md, T3-01).'
