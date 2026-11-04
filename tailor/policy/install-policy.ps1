#Requires -Version 7.2
<#
.SYNOPSIS
  Installs the T3 Code lock-down policy on one Windows machine. Run elevated, from the
  protected copy only (see "First step" below).

.DESCRIPTION
  T3 Code v0.1.6 has no managed-policy file of its own (tailor/policy/README.md). This
  script applies the nearest equivalent from t3-policy.template.json. The server built
  from this fork reads the installed policy from %ProgramData%\T3CodePolicy\t3-policy.json
  and refuses to start Claude unless the Claude instance uses the Claude home and binary
  recorded there, with the recorded SHA-256 (fail closed).

  First step (documented in README.md, done by hand, elevated): create
  %ProgramData%\T3CodePolicy\installer with an Administrators/SYSTEM-only ACL set at creation,
  copy the five reviewed files into it (this script, verify-install.ps1, the template and the
  two modules), check them there with Get-FileHash against the reviewed commit, and run this
  script from there with -ExpectedSha256. The script refuses to run from anywhere else, or if
  that folder or any file in it is writable by a non-administrator. It hashes the five files
  once and loads the modules, the template and the verifier from those same bytes
  (New-Module -ScriptBlock), never by reading the paths again.

    1. Creates two local standard accounts with random passwords that are never stored:
       t3agent (runs t3 serve and its Claude) and t3bridge (runs the T3 bridge, the only
       reader of the connector token). Refuses an existing account in any group but
       BUILTIN\Users. Grants batch logon and denies interactive, RDP and network logon.
    2. Creates the folders under %ProgramData%\T3CodePolicy from Get-T3FolderAclPlan, with
       protected ACLs set at creation (an existing folder is checked for reparse points and
       owner, then reset through an opened handle). No BUILTIN\Users, no interactive user.
    3. Writes the Claude instance settings into the Claude home.
    4. Records the undo state first, then merges deny entries for the policy folder (and
       parentSettingsBehavior "merge" if absent) into Claude Code's machine-wide
       managed-settings.json; every other setting is kept.
    5. Writes t3-policy.json (binary hashes, workspace roots) and the service files: the
       launchers, the T3 settings seed (t3agent copies it into the T3 home on first start),
       the token issuer (runs as t3agent) and the token mover (runs as SYSTEM).
    6. Registers the scheduled tasks through the Task Scheduler COM API (LogonType Password,
       RunLevel LeastPrivilege; the mover as SYSTEM). Passwords are then discarded.
    7. Sets the policy's T3CODE_* variables at machine scope, recording the previous values.
    8. Replaces its Windows Firewall rules: builds the new set first, then removes the old.
    9. Runs verify-install.ps1. Only on a full PASS does it write the verified marker and
       start the tasks; the launchers refuse to start without a current marker.

  -EmergencyRevoke (same protected copy and hash rules; -ExpectedSha256 may be left out, then
  the hashes recorded at install are used) stops and disables the tasks, kills the accounts'
  processes, has t3agent rotate every T3 signing key with T3's own CLI (every token and session
  becomes invalid), deletes the connector token and the drop folder's contents, removes the
  verified marker and records the revoke in state\revoke-log.json. Re-running the install
  mints a fresh token and verifies again.

  No administrator code runs inside the T3 home or the workspaces: the connector token is
  issued there by the t3agent task and moved into connector\ by the fixed SYSTEM task.

  Windows Firewall matches IP addresses, not host names, and a Block rule always beats an
  Allow rule. The rules are therefore Block rules whose remote address is the complement of
  the allowed set, computed from DNS at install time. Per-program rules do not cover child
  processes (SECURITY-REVIEW.md, T3-03).

  The script holds no credentials and reads none. It is idempotent; -WhatIf previews every
  change; -Uninstall (also from the protected copy) removes what it created.

.PARAMETER ExpectedSha256
  SHA-256 of the five files, as
  'script=<hex>,verify=<hex>,template=<hex>,module=<hex>,accounts=<hex>', from the reviewed commit.

.EXAMPLE
  pwsh -NoProfile -File "$env:ProgramData\T3CodePolicy\installer\install-policy.ps1" -ExpectedSha256 $reviewed `
    -T3Exe 'C:\Program Files\T3Code\t3.exe' -ClaudeExe 'C:\Program Files\T3Code\claude\claude.exe' -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [string] $T3Exe,
  [string] $ClaudeExe,
  # Required, except with -EmergencyRevoke, which checks the protected copy against the hashes
  # recorded in the admin-only t3-policy.json at install time.
  [string] $ExpectedSha256,
  # Folder name under %ProgramData%\T3CodePolicy for the Claude home.
  [ValidatePattern('^[A-Za-z0-9._-]+$')][string] $ClaudeHomeName = 'claude-home',
  [ValidatePattern('^[A-Za-z0-9_-]{1,20}$')][string] $AgentAccount = 't3agent',
  [ValidatePattern('^[A-Za-z0-9_-]{1,20}$')][string] $BridgeAccount = 't3bridge',
  # The T3 bridge executable. Without it the bridge account and the token are still created,
  # but no bridge task is registered.
  [string] $BridgeExe,
  # The git.exe the self-check uses (admin-only folder; its version must be at least
  # $MinimumGitVersion). Defaults to the git on PATH.
  [string] $GitExe,
  # Optional node.exe whose folder T3's PATH may include (admin-only folder).
  [string] $NodeExe,
  # Required with -BridgeExe until the bridge client is reviewed: the operator attests the
  # bridge build talks to T3 only through the pipe and has no TCP fallback (Windows Firewall
  # does not filter loopback, so a TCP fallback would bypass the pipe).
  [switch] $BridgeUsesPipeOnly,
  # tailor.au API host names the bridge may reach (no default; for example api.example.com).
  [string[]] $TailorApiHosts = @(),
  # More project roots for t3agent besides %ProgramData%\T3CodePolicy\workspaces. Each is
  # created (or reset) with an ACL for Administrators, SYSTEM and t3agent only; its parent
  # must not be writable by non-administrators.
  [string[]] $WorkspaceRoots = @(),
  # Lifetime of each connector token. The t3agent task issues a new one every day and keeps
  # the two newest, so a token is replaced long before it expires.
  [ValidateRange(2, 30)][int] $ConnectorTokenDays = 7,
  # Issue a new connector token now (the daily task does this anyway).
  [switch] $RotateConnectorToken,
  [ValidateRange(1024, 65535)][int] $T3Port = 3773,
  [string[]] $AllowedHosts,
  [string[]] $ExtraAllowedAddresses = @(),
  [ValidateSet('Resolve', 'LoopbackOnly')][string] $ClaudeEgress = 'Resolve',
  [string] $RuleGroup = 'T3 Code egress policy',
  # Claude Code's machine-wide admin tier. Affects EVERY Claude session on the PC.
  [string] $MachineManagedSettingsPath = 'C:\Program Files\ClaudeCode\managed-settings.json',
  [switch] $SkipMachineManagedSettings,
  [switch] $Uninstall,
  # Emergency revoke: stop everything, rotate T3's signing keys (every token and session
  # becomes invalid), delete the connector token, leave the tasks disabled and the verified
  # marker removed. Nothing starts until the operator runs the install again.
  [switch] $EmergencyRevoke,
  # Upgrades from an install that did not record account ownership: adopt existing
  # t3agent/t3bridge accounts once, only if their description is exactly this installer's and
  # they are in no group but Users.
  [switch] $AdoptExistingAccounts
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# Modules only from PowerShell's own folder and System32, imported by full path: nothing on a
# user-writable module path can shadow a cmdlet this script runs elevated.
$env:PSModulePath = "$PSHOME\Modules;$env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules"
foreach ($module in 'Microsoft.PowerShell.LocalAccounts', 'ScheduledTasks', 'NetSecurity', 'NetTCPIP') {
  $manifest = Get-ChildItem -LiteralPath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules\$module" -Filter "$module.psd1" -Recurse -Depth 1 -File |
    Select-Object -First 1
  if ($null -eq $manifest) { throw "Windows module $module not found in System32." }
  Import-Module $manifest.FullName -ErrorAction Stop
}
$MinimumGitVersion = '2.50.1'

$ProgramDataFolder = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
$PolicyDir = Join-Path $ProgramDataFolder 'T3CodePolicy'
$InstallerDir = Join-Path $PolicyDir 'installer'
$StateDir = Join-Path $PolicyDir 'state'
$ServiceDir = Join-Path $PolicyDir 'service'
$T3Home = Join-Path $PolicyDir 't3-home'
$ClaudeConfigDir = Join-Path $PolicyDir $ClaudeHomeName
$ConnectorDir = Join-Path $PolicyDir 'connector'
$DropDir = Join-Path $PolicyDir 'connector-drop'
$BridgeDir = Join-Path $PolicyDir 'bridge'
$HooksDir = Join-Path $PolicyDir 'git-hooks'
$GitConfigDir = Join-Path $PolicyDir 'git-config'
$GitGlobalConfig = Join-Path $GitConfigDir 'gitconfig'
$ProbeDir = Join-Path $PolicyDir 'probe'
$DefaultWorkspaces = Join-Path $PolicyDir 'workspaces'
$TokenPath = Join-Path $ConnectorDir 'token'
$DropPath = Join-Path $DropDir 'token'
$BridgeKeyPath = Join-Path $BridgeDir 'tailor-api-key'
$InstalledPath = Join-Path $PolicyDir 't3-policy.json'
$UndoPath = Join-Path $StateDir 'undo.json'
$BaselinePath = Join-Path $StateDir 'managed-settings.baseline.json'
$MarkerPath = Join-Path $ServiceDir 'verified.json'
$Tasks = [ordered]@{ Server = 'T3 server'; Bridge = 'T3 bridge'; Issuer = 'T3 token issuer'; Mover = 'T3 token mover'; Rotate = 'T3 key rotation'
  RotateToken = 'T3 token rotate now'; Probe = 'T3 self-check probe'; PipeProbe = 'T3 pipe probe' }
$PreInstallPath = Join-Path $StateDir 'pre-install.json'
$RevokeLogPath = Join-Path $StateDir 'revoke-log.json'
$RotateScript = Join-Path $ServiceDir 'rotate-keys.ps1'
$InstallerFiles = [ordered]@{
  script = 'install-policy.ps1'; verify = 'verify-install.ps1'; template = 't3-policy.template.json'
  module = 'ManagedSettingsMerge.psm1'; accounts = 'ServiceAccounts.psm1'
}

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
$Allow = [Security.AccessControl.AccessControlType]::Allow
$PropagateInheritOnly = [Security.AccessControl.PropagationFlags]::InheritOnly

# Sets owner and a protected DACL on an already-open handle (opened without following a
# reparse point). Used for folders that exist from an earlier run; new folders and files get
# their ACL at creation. Never sets an ACL by path.
Add-Type -Namespace T3Policy -Name Handle -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool GetFileInformationByHandle(Microsoft.Win32.SafeHandles.SafeFileHandle handle, out ByHandleInfo info);
[DllImport("advapi32.dll", SetLastError = true)]
public static extern bool SetKernelObjectSecurity(Microsoft.Win32.SafeHandles.SafeFileHandle handle, uint information, byte[] descriptor);
[StructLayout(LayoutKind.Sequential, Pack = 4)]
public struct ByHandleInfo { public uint Attributes; public long Created; public long Accessed; public long Written; public uint Volume; public uint SizeHigh; public uint SizeLow; public uint Links; public uint IndexHigh; public uint IndexLow; }
public static void SetProtectedSecurity(string path, byte[] descriptor) {
  // READ_CONTROL | WRITE_DAC | WRITE_OWNER | FILE_READ_ATTRIBUTES; BACKUP_SEMANTICS | OPEN_REPARSE_POINT.
  using (var handle = CreateFileW(path, 0x00020000 | 0x00040000 | 0x00080000 | 0x80, 7, IntPtr.Zero, 3, 0x02000000 | 0x00200000, IntPtr.Zero)) {
    if (handle.IsInvalid) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), path);
    ByHandleInfo info;
    if (!GetFileInformationByHandle(handle, out info)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), path);
    if ((info.Attributes & 0x400) != 0) throw new InvalidOperationException("Refusing " + path + ": it is a reparse point.");
    if ((info.Attributes & 0x10) == 0 && info.Links != 1) throw new InvalidOperationException("Refusing " + path + ": it has other hard links.");
    // OWNER | DACL | PROTECTED_DACL
    if (!SetKernelObjectSecurity(handle, 0x1 | 0x4 | 0x80000000, descriptor)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), path);
  }
}
'@

function New-PlanSecurity($entry, [bool] $isDirectory) {
  $security = if ($isDirectory) { [Security.AccessControl.DirectorySecurity]::new() } else { [Security.AccessControl.FileSecurity]::new() }
  $security.SetAccessRuleProtection($true, $false)
  $security.SetOwner($SidAdministrators)
  $all = if ($isDirectory) { [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit' } else { [Security.AccessControl.InheritanceFlags]::None }
  foreach ($sid in $SidAdministrators, $SidSystem) {
    $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', $all, 'None', $Allow))
  }
  foreach ($grant in @($entry.Grants)) {
    $sid = $SidMap[$grant.Principal]
    if ($null -eq $sid) { continue }   # preview before the account exists
    $inherit = if ($isDirectory) { [Security.AccessControl.InheritanceFlags]$grant.Inherit } else { 'None' }
    $propagate = if ($isDirectory) { [Security.AccessControl.PropagationFlags]$grant.Propagate } else { 'None' }
    $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new([string]$sid), [Security.AccessControl.FileSystemRights]$grant.Rights, $inherit, $propagate, $Allow))
  }
  return $security
}

# A file ACL: Administrators/SYSTEM full plus the named principals with the given rights.
function New-FileEntry([hashtable] $grants) {
  return [pscustomobject]@{ Grants = @($grants.Keys | ForEach-Object {
        [pscustomobject]@{ Principal = $_; Rights = $grants[$_]; Inherit = 'None'; Propagate = 'None' } }) }
}

function Assert-NotReparse([string] $path) {
  $item = Get-Item -LiteralPath $path -Force
  if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw "Refusing $path : it is a reparse point (junction or symbolic link). Remove it and re-run."
  }
  return $item
}

# Walks a tree without following links and refuses any reparse point in it.
function Assert-NoReparseTree([string] $path) {
  $item = Assert-NotReparse $path
  if ($item.PSIsContainer) {
    foreach ($child in Get-ChildItem -LiteralPath $path -Force) { Assert-NoReparseTree $child.FullName }
  }
}

function Assert-SafeExisting([string] $path) {
  [void](Assert-NotReparse $path)
  $owner = (Get-Acl -LiteralPath $path).GetOwner([Security.Principal.SecurityIdentifier])
  if ($AdminOwners -notcontains $owner) {
    throw "Refusing $path : owned by $owner, not Administrators or SYSTEM. Remove it and re-run."
  }
}

# The path, and (unless -SkipParent) its folder, are owned by an admin principal and give no
# write to anyone else.
function Assert-AdminControlled([string] $path, [switch] $SkipParent) {
  # WriteData/CreateFiles, AppendData/CreateDirectories, WriteExtendedAttributes, DeleteSubdirectoriesAndFiles,
  # WriteAttributes, Delete, ChangePermissions, TakeOwnership, GENERIC_ALL, GENERIC_WRITE.
  $writeMask = 0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000
  $targets = if ($SkipParent) { @($path) } else { @($path, (Split-Path -Parent $path)) }
  foreach ($target in $targets) {
    [void](Assert-NotReparse $target)
    $acl = Get-Acl -LiteralPath $target
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier])
    if ($AdminOwners -notcontains $owner) { throw "Refusing $target : owned by $owner, not an administrator principal." }
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
      if ($rule.AccessControlType -ne $Allow) { continue }
      if ($AdminOwners -contains $rule.IdentityReference) { continue }
      if (($rule.PropagationFlags -band $PropagateInheritOnly) -ne 0) { continue }
      if (([int64]$rule.FileSystemRights -band $writeMask) -ne 0) {
        throw "Refusing $target : $($rule.IdentityReference) can write it. Use an admin-only folder."
      }
    }
  }
}

# Creates the folder with its ACL at creation, or checks an existing one (no reparse point,
# admin owner, nothing planted inside where admin code works) and resets its ACL by handle.
function Ensure-PlannedDirectory($entry, [switch] $CheckTree) {
  $path = $entry.Path
  $text = Format-T3AclPlanEntry $entry
  if (Test-Path -LiteralPath $path) {
    Assert-SafeExisting $path
    if ($CheckTree) { Assert-NoReparseTree $path }
    if ($PSCmdlet.ShouldProcess($path, "Reset ACL by handle: $text")) {
      [T3Policy.Handle]::SetProtectedSecurity($path, (New-PlanSecurity $entry $true).GetSecurityDescriptorBinaryForm())
    }
    return
  }
  if ($PSCmdlet.ShouldProcess($path, "Create directory with ACL: $text")) {
    [void][IO.FileSystemAclExtensions]::Create([IO.DirectoryInfo]::new($path), (New-PlanSecurity $entry $true))
    Assert-SafeExisting $path
  }
}

# Replaces a file in an admin-controlled folder: a planted link is deleted, never written
# through; the new file gets its ACL at creation (CreateNew). An unchanged file keeps its
# content and has its ACL reset by handle.
function Write-ProtectedFile([string] $path, [byte[]] $bytes, $entry = (New-FileEntry @{}), [switch] $Secret) {
  $label = if ($Secret) { 'secret file (contents not shown)' } else { 'file' }
  $current = $null
  if (Test-Path -LiteralPath $path) {
    $item = Get-Item -LiteralPath $path -Force
    if ($item.PSIsContainer) { throw "Refusing $path : a folder is in the way." }
    if (-not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { $current = [IO.File]::ReadAllBytes($path) }
  }
  $security = New-PlanSecurity $entry $false
  if ($null -ne $current -and [Linq.Enumerable]::SequenceEqual([byte[]]$current, $bytes)) {
    if ($PSCmdlet.ShouldProcess($path, "Unchanged $label; reset its ACL by handle")) {
      [T3Policy.Handle]::SetProtectedSecurity($path, $security.GetSecurityDescriptorBinaryForm())
    }
    return
  }
  if ($PSCmdlet.ShouldProcess($path, "Replace $label (ACL set at creation)")) {
    if (Test-Path -LiteralPath $path) { [IO.File]::Delete($path) }
    $stream = [IO.FileSystemAclExtensions]::Create([IO.FileInfo]::new($path), [IO.FileMode]::CreateNew,
      [Security.AccessControl.FileSystemRights]'Write, Synchronize', [IO.FileShare]::None, 4096, [IO.FileOptions]::None, $security)
    try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
  }
}

function Get-Utf8Bytes([string] $text) { return [Text.UTF8Encoding]::new($false).GetBytes($text) }

function Get-BytesSha256([byte[]] $bytes) {
  return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
}

function Get-FileSha256([string] $path) { return Get-BytesSha256 ([IO.File]::ReadAllBytes($path)) }

function Resolve-Executable([string] $label, [string] $value) {
  if (-not $value) { throw "-$label is required." }
  if (-not [IO.Path]::IsPathRooted($value)) { throw "-$label must be a full path." }
  $full = [IO.Path]::GetFullPath($value)
  if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { throw "Not found: $full" }
  if ([IO.Path]::GetExtension($full) -ne '.exe') { throw "-$label must be an .exe: $full" }
  Assert-AdminControlled $full
  return $full
}

# Claude permission-rule form of an absolute path (matches claudeDenyRules.ts).
function ConvertTo-ClaudeRulePath([string] $path) {
  $posix = $path.Replace('\', '/').TrimEnd('/')
  if ($posix -match '^([A-Za-z]):/(.*)$') { return '//' + $Matches[1].ToLowerInvariant() + '/' + $Matches[2] }
  return '/' + $posix
}

# The undo record: written before each change it describes, merged across reruns.
function Read-UndoRecord {
  if (-not (Test-Path -LiteralPath $UndoPath)) { return [ordered]@{ version = 1; variables = [ordered]@{}; createdWorkspaceRoots = @() } }
  [void](Assert-NotReparse $UndoPath)
  $record = Get-Content -LiteralPath $UndoPath -Raw | ConvertFrom-Json -AsHashtable
  if (-not $record.Contains('variables')) { $record['variables'] = [ordered]@{} }
  if (-not $record.Contains('createdWorkspaceRoots')) { $record['createdWorkspaceRoots'] = @() }
  return $record
}
function Save-UndoRecord($record) {
  if ($WhatIfPreference) { return }
  Write-ProtectedFile $UndoPath (Get-Utf8Bytes (($record | ConvertTo-Json -Depth 12) + "`n"))
}

function Set-MachineVariable([string] $name, [AllowNull()][object] $value, $undo) {
  if ($name -notmatch '^T3CODE_[A-Z0-9_]+$') { throw "Refusing machine variable '$name': only T3CODE_* names are allowed." }
  $current = [Environment]::GetEnvironmentVariable($name, 'Machine')
  if ($current -eq $value) { Write-Host "  unchanged: $name"; return }
  if ($null -ne $undo -and -not $undo.variables.Contains($name)) {
    # Recorded once, on the first run that changes it: uninstall restores this value.
    $undo.variables[$name] = [ordered]@{ previous = $current }
    Save-UndoRecord $undo
  }
  $action = if ($null -eq $value) { 'Remove machine variable' } else { "Set machine variable to '$value'" }
  if ($PSCmdlet.ShouldProcess($name, $action)) { [Environment]::SetEnvironmentVariable($name, $value, 'Machine') }
}

# Deletes a tree without following links: a link is removed as a link. Used by -Uninstall
# only after the accounts that could change the tree are gone.
function Remove-TreeNoFollow([string] $path) {
  if (-not (Test-Path -LiteralPath $path)) { return }
  if (-not $PSCmdlet.ShouldProcess($path, 'Delete (links removed, never followed)')) { return }
  $stack = [System.Collections.Generic.Stack[string]]::new()
  $order = [System.Collections.Generic.List[IO.FileSystemInfo]]::new()
  $stack.Push($path)
  while ($stack.Count -gt 0) {
    $current = Get-Item -LiteralPath $stack.Pop() -Force
    $order.Add($current)
    if ($current.PSIsContainer -and -not ($current.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
      foreach ($child in Get-ChildItem -LiteralPath $current.FullName -Force) { $stack.Push($child.FullName) }
    }
  }
  for ($i = $order.Count - 1; $i -ge 0; $i--) {
    $item = $order[$i]
    for ($attempt = 0; $attempt -lt 2; $attempt++) {
      try {
        $item.Attributes = $item.Attributes -band (-bnot [IO.FileAttributes]::ReadOnly)
        if ($item.PSIsContainer) { [IO.Directory]::Delete($item.FullName, $false) } else { [IO.File]::Delete($item.FullName) }
        break
      } catch [UnauthorizedAccessException] {
        if ($attempt -gt 0) { throw }
        # The removed account may have locked its own files: take them back, this item only.
        & "$env:SystemRoot\System32\takeown.exe" /f $item.FullName /a | Out-Null
        & "$env:SystemRoot\System32\icacls.exe" $item.FullName /grant '*S-1-5-32-544:F' /l /q | Out-Null
      }
    }
  }
}

# ---------- main ----------
Assert-Elevated
# Started with -NoProfile, and the commands this script relies on are the real cmdlets from
# their modules: no profile, function or alias stands in for them.
$hostArgs = @([Environment]::GetCommandLineArgs() | ForEach-Object { $_.ToLowerInvariant() })
if (-not ($hostArgs | Where-Object { $_ -in '-noprofile', '-nop', '/noprofile' })) {
  throw 'Start this script with pwsh -NoProfile -File (README.md). Nothing was changed.'
}
foreach ($required in @(
    @('Get-Acl', 'Microsoft.PowerShell.Security'), @('Get-FileHash', 'Microsoft.PowerShell.Utility'),
    @('Get-ChildItem', 'Microsoft.PowerShell.Management'), @('Remove-Item', 'Microsoft.PowerShell.Management'),
    @('Copy-Item', 'Microsoft.PowerShell.Management'), @('Get-LocalUser', 'Microsoft.PowerShell.LocalAccounts'),
    @('New-LocalUser', 'Microsoft.PowerShell.LocalAccounts'), @('Get-ScheduledTask', 'ScheduledTasks'),
    @('New-NetFirewallRule', 'NetSecurity'), @('Import-Module', 'Microsoft.PowerShell.Core'))) {
  $found = @(Get-Command -Name $required[0] -All -ErrorAction SilentlyContinue)
  if ($found.Count -ne 1 -or $found[0].CommandType -notin 'Cmdlet', 'Function' -or $found[0].ModuleName -ne $required[1]) {
    throw "$($required[0]) is not the real command from $($required[1]) (found: $(($found | ForEach-Object { "$($_.CommandType) $($_.Source)" }) -join ', ')). Nothing was changed."
  }
}
$scriptPath = $MyInvocation.MyCommand.Path
$here = Split-Path -Parent $scriptPath

# 0. Integrity: run only from the protected copy; hash every file once and use those bytes.
if (-not [string]::Equals($here.TrimEnd('\'), $InstallerDir, [StringComparison]::OrdinalIgnoreCase)) {
  throw "Run this script from the protected copy in $InstallerDir (README.md, First step). Nothing was changed."
}
Assert-AdminControlled $here
Assert-NoReparseTree $here
$bytes = [ordered]@{}
$hashes = [ordered]@{}
foreach ($key in $InstallerFiles.Keys) {
  $path = Join-Path $here $InstallerFiles[$key]
  Assert-AdminControlled $path -SkipParent
  $bytes[$key] = [IO.File]::ReadAllBytes($path)
  $hashes[$key] = Get-BytesSha256 $bytes[$key]
}
$hashText = ($hashes.Keys | ForEach-Object { "$_=$($hashes[$_])" }) -join ','
Write-Host "Installer SHA-256: $hashText"
if (-not $ExpectedSha256) {
  if (-not $EmergencyRevoke) { throw 'Pass -ExpectedSha256 from the reviewed commit (README.md, First step). Nothing was changed.' }
  # Emergency revoke: the hashes recorded at install, from the admin-only policy file.
  Assert-AdminControlled $InstalledPath -SkipParent
  $ExpectedSha256 = [string](Get-Content -LiteralPath $InstalledPath -Raw | ConvertFrom-Json).installed.installerSha256
  Write-Host 'Checking the protected copy against the hashes recorded at install.'
}
$expected = @{}
foreach ($pair in $ExpectedSha256.Split(',')) { $kv = $pair.Split('=', 2); if ($kv.Length -eq 2) { $expected[$kv[0].Trim()] = $kv[1].Trim().ToLowerInvariant() } }
foreach ($key in $hashes.Keys) {
  if ($expected[$key] -ne $hashes[$key]) { throw "Hash mismatch for $key : not the reviewed version. Nothing was changed." }
}
function Import-FromBytes([string] $name, [byte[]] $data) {
  $text = [Text.UTF8Encoding]::new($false).GetString($data) -replace '(?m)^#Requires.*$', ''
  New-Module -Name $name -ScriptBlock ([scriptblock]::Create($text)) | Import-Module -Force -Global
}
Import-FromBytes 'ManagedSettingsMerge' $bytes.module
Import-FromBytes 'ServiceAccounts' $bytes.accounts
$policy = [Text.UTF8Encoding]::new($false).GetString($bytes.template) | ConvertFrom-Json
$verifyBlock = [scriptblock]::Create(([Text.UTF8Encoding]::new($false).GetString($bytes.verify) -replace '(?m)^#Requires.*$', ''))

$serverVariables = [ordered]@{}
foreach ($variable in $policy.serverEnvironment.PSObject.Properties) {
  if ($variable.Name -notmatch '^T3CODE_[A-Z0-9_]+$') { throw "Template serverEnvironment has a non-T3CODE name: $($variable.Name)" }
  $serverVariables[$variable.Name] = [string]$variable.Value
}
$serverVariables['T3CODE_PORT'] = [string]$T3Port
$mustBeUnset = @($policy.serverEnvironmentMustBeUnset)

$previousInstalled = $null
if (Test-Path -LiteralPath $InstalledPath) {
  try { $previousInstalled = (Get-Content -LiteralPath $InstalledPath -Raw | ConvertFrom-Json).installed } catch { $previousInstalled = $null }
}
$SidMap = @{ Administrators = 'S-1-5-32-544'; SYSTEM = 'S-1-5-18'; OwnerRights = 'S-1-3-4'; agent = $null; bridge = $null }

# ---------- machine-wide Claude admin tier ----------
function Get-MachineDenyEntries {
  $rule = ConvertTo-ClaudeRulePath $PolicyDir
  return @('Read', 'Edit', 'Write' | ForEach-Object { "$_($rule/**)" })
}

function Update-MachineManagedSettings([string[]] $entries, $undo) {
  $path = $MachineManagedSettingsPath
  $existing = if (Test-Path -LiteralPath $path) { [void](Assert-NotReparse $path); [IO.File]::ReadAllText($path) } else { $null }
  $merge = Get-ManagedSettingsMerge -ExistingText $existing -Entries $entries   # throws on a malformed file or a conflicting parentSettingsBehavior
  $previous = if ($undo.Contains('machineManagedSettings')) { $undo.machineManagedSettings } else { $null }
  $record = Merge-ManagedSettingsRecord -Previous $previous -Path $path -Added $merge.Added -Created $merge.Created
  # Undo record first, then the file.
  $undo['machineManagedSettings'] = $record
  Save-UndoRecord $undo
  if ($merge.Added.Count -eq 0 -and -not $merge.Created.parentSettingsBehavior) {
    Write-Host "  unchanged: $path"
  } else {
    Write-Host "  $path : adding"
    $merge.Added | ForEach-Object { Write-Host "    + permissions.deny: $_" }
    if ($merge.Created.parentSettingsBehavior) { Write-Host '    + parentSettingsBehavior: "merge"' }
    if ($PSCmdlet.ShouldProcess($path, 'Merge (every other key unchanged)')) {
      if ($null -ne $existing) {
        $backup = Get-ManagedSettingsBackupPath $path
        Copy-Item -LiteralPath $path -Destination $backup
        Write-Host "  backup: $backup"
      }
      Write-ManagedSettingsAtomically -Path $path -Text $merge.Text
    }
  }
  # The baseline verify-install.ps1 compares against: the file with our entries taken out.
  $now = if ($WhatIfPreference) { $merge.Text } else { [IO.File]::ReadAllText($path) }
  $removal = Get-ManagedSettingsRemoval -ExistingText $now -Added @($record.added) -Created $record.created
  $baseline = [ordered]@{ text = $(if ($removal.DeleteFile) { $null } else { $removal.Text }) }
  if (-not $WhatIfPreference) { Write-ProtectedFile $BaselinePath (Get-Utf8Bytes (($baseline | ConvertTo-Json) + "`n")) }
  return $record
}

function Undo-MachineManagedSettings($record) {
  if ($null -eq $record -or -not (Test-Path -LiteralPath $record.path)) { return }
  [void](Assert-NotReparse $record.path)
  $existing = [IO.File]::ReadAllText($record.path)
  $removal = Get-ManagedSettingsRemoval -ExistingText $existing -Added @($record.added) -Created $record.created
  Write-Host "  $($record.path) : removing only what this installer added"
  @($record.added) | ForEach-Object { Write-Host "    - $_" }
  if ($PSCmdlet.ShouldProcess($record.path, 'Remove the recorded entries')) {
    Copy-Item -LiteralPath $record.path -Destination (Get-ManagedSettingsBackupPath $record.path)
    if ($removal.DeleteFile) { Remove-Item -LiteralPath $record.path -Force }
    else { Write-ManagedSettingsAtomically -Path $record.path -Text $removal.Text }
  }
}

# Starts a registered task and waits for it to finish. Returns its result code ($null if it
# did not run or did not finish in time).
function Invoke-TaskAndWait([string] $name, [int] $timeoutSeconds = 180) {
  $task = Get-ScheduledTask -TaskName $name -TaskPath '\T3CodePolicy\' -ErrorAction SilentlyContinue
  if ($null -eq $task) { return $null }
  if ($task.State -eq 'Disabled') { Enable-ScheduledTask -TaskName $name -TaskPath '\T3CodePolicy\' | Out-Null }
  $started = [DateTime]::Now.AddSeconds(-2)
  Start-ScheduledTask -TaskName $name -TaskPath '\T3CodePolicy\'
  $deadline = [DateTime]::Now.AddSeconds($timeoutSeconds)
  do {
    Start-Sleep -Seconds 2
    $info = Get-ScheduledTaskInfo -TaskName $name -TaskPath '\T3CodePolicy\'
    $state = (Get-ScheduledTask -TaskName $name -TaskPath '\T3CodePolicy\').State
  } while (($state -eq 'Running' -or $info.LastRunTime -lt $started) -and [DateTime]::Now -lt $deadline)
  if ($state -eq 'Running' -or $info.LastRunTime -lt $started) { return $null }
  return [int64]$info.LastTaskResult
}

# Stops every process running as the account (by owner SID), without removing the account.
function Stop-AccountProcesses([string] $name) {
  $user = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
  if ($null -eq $user) { Write-Host "  no account $name"; return 0 }
  $found = 0; $stopped = 0
  foreach ($process in Get-CimInstance Win32_Process) {
    $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid -ErrorAction SilentlyContinue
    if ($owner -and $owner.Sid -eq $user.SID.Value) {
      $found++
      if ($PSCmdlet.ShouldProcess("$($process.Name) ($($process.ProcessId))", "Stop process running as $name")) {
        # Counted only when Stop-Process succeeds (or the process is already gone).
        try { Stop-Process -Id $process.ProcessId -Force -ErrorAction Stop; $stopped++ }
        catch { if (-not (Get-Process -Id $process.ProcessId -ErrorAction SilentlyContinue)) { $stopped++ } }
      }
    }
  }
  return [pscustomobject]@{ Found = $found; Stopped = $stopped }
}

# The parts of the machine an install changes, for the pre-install snapshot and the uninstall diff.
function Get-MachineSnapshot {
  $variables = [ordered]@{}
  foreach ($entry in [Environment]::GetEnvironmentVariables('Machine').GetEnumerator()) {
    if ($entry.Key -match '^T3CODE_') { $variables[$entry.Key] = [string]$entry.Value }
  }
  $folderExists = $true
  try { $svc = New-Object -ComObject 'Schedule.Service'; $svc.Connect(); [void]$svc.GetFolder('\T3CodePolicy') } catch { $folderExists = $false }
  $managed = $null
  if (Test-Path -LiteralPath $MachineManagedSettingsPath) {
    $managed = (ConvertFrom-ManagedSettingsText ([IO.File]::ReadAllText($MachineManagedSettingsPath))) | ConvertTo-Json -Depth 100 -Compress
  }
  $rights = $null
  $work = Join-Path ([IO.Path]::GetTempPath()) ('t3policy-snapshot-' + [guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $work | Out-Null
  try {
    & "$env:SystemRoot\System32\secedit.exe" /export /cfg (Join-Path $work 'rights.inf') /areas USER_RIGHTS /quiet | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "secedit /export failed ($LASTEXITCODE)." }
    $rights = [IO.File]::ReadAllText((Join-Path $work 'rights.inf'))
  } finally { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
  return [ordered]@{
    at = [DateTime]::UtcNow.ToString('o')
    variables = $variables
    tasks = @(Get-ScheduledTask -TaskPath '\T3CodePolicy\' -ErrorAction SilentlyContinue | ForEach-Object { "$($_.TaskPath)$($_.TaskName)" })
    taskFolder = $folderExists
    firewallRules = @(Get-NetFirewallRule -Group $RuleGroup -ErrorAction SilentlyContinue | ForEach-Object Name)
    managedSettings = $managed
    managedSettingsDirExisted = (Test-Path -LiteralPath (Split-Path -Parent $MachineManagedSettingsPath))
    rights = $rights
  }
}

# ---------- emergency revoke ----------
if ($EmergencyRevoke) {
  Write-Host 'EMERGENCY REVOKE'
  $plan = Get-EmergencyRevokePlan -Tasks $Tasks -Accounts @($AgentAccount, $BridgeAccount) -MarkerPath $MarkerPath `
    -TokenPath $TokenPath -DropDir $DropDir -RevokeLogPath $RevokeLogPath -ProbeDir $ProbeDir
  $done = [System.Collections.Generic.List[string]]::new()
  $failed = [System.Collections.Generic.List[string]]::new()
  $rotated = $false
  foreach ($step in $plan) {
    $line = "$($step.Action) $($step.Target): $($step.Detail)"
    if (-not $PSCmdlet.ShouldProcess($step.Target, "$($step.Action): $($step.Detail)")) { continue }
    try {
      switch ($step.Action) {
        'RemoveMarker' { if (Test-Path -LiteralPath $step.Target) { [IO.File]::Delete($step.Target); $line += ' (removed)' } else { $line += ' (none)' } }
        'DisableTask' {
          if (Get-ScheduledTask -TaskName $step.Target -TaskPath '\T3CodePolicy\' -ErrorAction SilentlyContinue) {
            Disable-ScheduledTask -TaskName $step.Target -TaskPath '\T3CodePolicy\' | Out-Null; $line += ' (disabled)'
          } else { $line += ' (not registered)' }
        }
        'StopTask' { Stop-ScheduledTask -TaskName $step.Target -TaskPath '\T3CodePolicy\' -ErrorAction SilentlyContinue }
        'KillProcesses' {
          # Until none is left: a task restart or a child could otherwise slip through.
          $total = 0; $left = -1
          for ($round = 1; $round -le 10; $round++) {
            $pass = Stop-AccountProcesses $step.Target
            $total += $pass.Stopped
            $left = $pass.Found - $pass.Stopped
            if ($pass.Found -eq 0) { break }
            Start-Sleep -Milliseconds 500
          }
          if ($pass.Found -ne 0) { throw "processes of $($step.Target) remain after 10 rounds ($left could not be stopped)" }
          $line += " ($total stopped; none left)"
        }
        'RecordRevokeStart' {
          $log = @()
          if (Test-Path -LiteralPath $step.Target) { [void](Assert-NotReparse $step.Target); $log = @(Get-Content -LiteralPath $step.Target -Raw | ConvertFrom-Json) }
          $revokeStart = [DateTime]::UtcNow.ToString('o')
          $log += [ordered]@{ startedAt = $revokeStart; at = $null; keysRotated = $false; by = [Security.Principal.WindowsIdentity]::GetCurrent().Name }
          Write-ProtectedFile $step.Target (Get-Utf8Bytes ((ConvertTo-Json -InputObject @($log) -Depth 4) + "`n"))
          $line += " ($revokeStart)"
        }
        'RotateKeys' {
          $result = Invoke-TaskAndWait $step.Target
          Disable-ScheduledTask -TaskName $step.Target -TaskPath '\T3CodePolicy\' -ErrorAction SilentlyContinue | Out-Null
          if ($result -ne 0) { throw "the key rotation task did not succeed (result: $(if ($null -eq $result) { 'did not run or finish' } else { $result }))" }
          $rotated = $true
          $line += ' (every signing key replaced, every session and pairing link revoked)'
        }
        'DeleteFile' {
          foreach ($file in @($step.Target, "$($step.Target).new")) {
            if (Test-Path -LiteralPath $file) { [void](Assert-NotReparse (Split-Path -Parent $file)); [IO.File]::Delete($file); $line += " (deleted $(Split-Path -Leaf $file))" }
          }
        }
        'EmptyFolder' {
          if (Test-Path -LiteralPath $step.Target) {
            [void](Assert-NotReparse $step.Target)
            $children = @(Get-ChildItem -LiteralPath $step.Target -Force)
            foreach ($child in $children) { Remove-TreeNoFollow $child.FullName }
            $line += " ($($children.Count) removed)"
          }
        }
        'AppendRevokeLog' {
          $log = @()
          if (Test-Path -LiteralPath $step.Target) { [void](Assert-NotReparse $step.Target); $log = @(Get-Content -LiteralPath $step.Target -Raw | ConvertFrom-Json) }
          $last = if ($log.Count -gt 0) { $log[-1] } else { $null }
          if ($null -ne $last -and $last.PSObject.Properties['startedAt'] -and $null -eq $last.at) {
            $last.at = [DateTime]::UtcNow.ToString('o'); $last.keysRotated = $rotated
          } else {
            $log += [ordered]@{ startedAt = [DateTime]::UtcNow.ToString('o'); at = [DateTime]::UtcNow.ToString('o'); keysRotated = $rotated; by = [Security.Principal.WindowsIdentity]::GetCurrent().Name }
          }
          Write-ProtectedFile $step.Target (Get-Utf8Bytes ((ConvertTo-Json -InputObject @($log) -Depth 4) + "`n"))
        }
      }
      $done.Add($line)
    } catch {
      $failed.Add("$line -- FAILED: $($_.Exception.Message)")
    }
  }
  Write-Host ''
  Write-Host 'Done:'
  $done | ForEach-Object { Write-Host "  $_" }
  if ($failed.Count -gt 0) {
    Write-Host 'FAILED:'
    $failed | ForEach-Object { Write-Host "  $_" }
  }
  Write-Host ''
  Write-Host 'Every task is disabled and the verified marker is gone: nothing starts until you run the install again'
  Write-Host '(from the protected copy, with -ExpectedSha256), which mints a fresh connector token and re-verifies.'
  if (-not $rotated) {
    Write-Warning 'The signing keys were NOT rotated: tokens issued before may still be valid. Fix the failure and run -EmergencyRevoke again.'
    exit 1
  }
  return
}

# ---------- uninstall ----------
if ($Uninstall) {
  $undo = Read-UndoRecord
  $preInstall = $null
  if (Test-Path -LiteralPath $PreInstallPath) { [void](Assert-NotReparse $PreInstallPath); $preInstall = Get-Content -LiteralPath $PreInstallPath -Raw | ConvertFrom-Json }
  # First make every issued token and session invalid (t3agent rotates the keys), then the T3
  # home, keys included, is deleted below.
  foreach ($key in 'Server', 'Bridge', 'Issuer', 'Mover', 'RotateToken', 'Probe') {
    if ((Get-ScheduledTask -TaskName $Tasks[$key] -TaskPath '\T3CodePolicy\' -ErrorAction SilentlyContinue) -and $PSCmdlet.ShouldProcess($Tasks[$key], 'Stop')) {
      Stop-ScheduledTask -TaskName $Tasks[$key] -TaskPath '\T3CodePolicy\' -ErrorAction SilentlyContinue
    }
  }
  if ($PSCmdlet.ShouldProcess($Tasks.Rotate, 'Rotate every T3 signing key before removing the T3 home')) {
    [void](Stop-AccountProcesses $AgentAccount).Stopped
    $rotation = Invoke-TaskAndWait $Tasks.Rotate
    if ($rotation -eq 0) { Write-Host '  signing keys rotated; every issued token is invalid' }
    else { Write-Warning 'Key rotation did not run; the keys are destroyed with the T3 home below.' }
  }
  foreach ($task in $Tasks.Values) { Remove-ServiceTask -TaskName $task -WhatIf:$WhatIfPreference }
  $removedSids = @()
  foreach ($name in $AgentAccount, $BridgeAccount) {
    # Only an account this installer created (its SID recorded) is ever removed.
    $recorded = if ($undo.Contains('createdAccounts') -and $undo.createdAccounts.Contains($name)) { [string]$undo.createdAccounts[$name] } else { $null }
    $user = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
    if ($null -eq $user) { continue }
    if ($user.SID.Value -ne $recorded) { Write-Warning "Not removing $name : this installer did not create it."; continue }
    $sid = Remove-ServiceAccount -Name $name -WhatIf:$WhatIfPreference
    if ($sid) { $removedSids += $sid }
  }
  if ($PSCmdlet.ShouldProcess('\T3CodePolicy', 'Remove the task folder if empty')) {
    try { $svc = New-Object -ComObject 'Schedule.Service'; $svc.Connect(); $svc.GetFolder('\').DeleteFolder('T3CodePolicy', 0) } catch { }
  }
  $previousRules = @(Get-NetFirewallRule -Group $RuleGroup -ErrorAction SilentlyContinue)
  if ($previousRules.Count -gt 0 -and $PSCmdlet.ShouldProcess($RuleGroup, "Remove $($previousRules.Count) firewall rule(s)")) { $previousRules | Remove-NetFirewallRule }
  # Only the T3CODE_* variables this installer changed, back to what they were.
  foreach ($name in @($undo.variables.Keys)) {
    if ($name -notmatch '^T3CODE_[A-Z0-9_]+$') { continue }
    $previous = $undo.variables[$name].previous
    $action = if ($null -eq $previous) { 'Remove machine variable (it did not exist before)' } else { "Restore machine variable to '$previous'" }
    if ($PSCmdlet.ShouldProcess($name, $action)) { [Environment]::SetEnvironmentVariable($name, $previous, 'Machine') }
  }
  $managedRecord = if ($undo.Contains('machineManagedSettings')) { $undo.machineManagedSettings }
    elseif ($null -ne $previousInstalled -and $previousInstalled.PSObject.Properties['machineManagedSettings']) { $previousInstalled.machineManagedSettings }
    else { $null }
  Undo-MachineManagedSettings $managedRecord
  # Backups (managed-settings.json.t3bak-*) are kept on purpose: delete them once satisfied.
  $managedDir = Split-Path -Parent $MachineManagedSettingsPath
  if ($undo.Contains('createdManagedSettingsDir') -and $undo.createdManagedSettingsDir -and (Test-Path -LiteralPath $managedDir) -and
      @(Get-ChildItem -LiteralPath $managedDir -Force | Where-Object { $_.Name -notlike '*.t3bak-*' }).Count -eq 0 -and
      @(Get-ChildItem -LiteralPath $managedDir -Force).Count -eq 0 -and $PSCmdlet.ShouldProcess($managedDir, 'Remove the folder this installer created (empty)')) {
    [IO.Directory]::Delete($managedDir, $false)
  }
  foreach ($dir in $ServiceDir, $ConnectorDir, $DropDir, $BridgeDir, $HooksDir, $GitConfigDir, $ProbeDir, $T3Home, $ClaudeConfigDir) { Remove-TreeNoFollow $dir }
  foreach ($file in $InstalledPath) { if ((Test-Path -LiteralPath $file) -and $PSCmdlet.ShouldProcess($file, 'Remove')) { [IO.File]::Delete($file) } }
  # Workspaces hold the operator's code: they are kept, minus the removed accounts' entries.
  $workspaceRoots = @($DefaultWorkspaces)
  if ($null -ne $previousInstalled -and $previousInstalled.PSObject.Properties['workspaceRoots']) { $workspaceRoots += @($previousInstalled.workspaceRoots) }
  foreach ($root in ($workspaceRoots | Select-Object -Unique)) {
    if (-not (Test-Path -LiteralPath $root)) { continue }
    foreach ($sid in $removedSids) {
      if ($PSCmdlet.ShouldProcess($root, "Remove ACL entries for the deleted account $sid (whole tree, links not followed)")) {
        & "$env:SystemRoot\System32\icacls.exe" $root /remove:g "*$sid" /t /c /l /q | Out-Null
      }
    }
  }
  Remove-TreeNoFollow $StateDir
  Remove-TreeNoFollow $InstallerDir
  if (Test-Path -LiteralPath $PolicyDir) {
    $left = @(Get-ChildItem -LiteralPath $PolicyDir -Force)
    if ($left.Count -eq 0) { Remove-TreeNoFollow $PolicyDir }
    elseif ($PSCmdlet.ShouldProcess($PolicyDir, 'Reset ACL by handle to Administrators/SYSTEM only (drops the deleted accounts)')) {
      [T3Policy.Handle]::SetProtectedSecurity($PolicyDir, (New-PlanSecurity ([pscustomobject]@{ Grants = @() }) $true).GetSecurityDescriptorBinaryForm())
      Write-Host "  kept: $(($left | ForEach-Object Name) -join ', ') (workspaces hold code; delete them yourself when done)"
    }
  }
  Write-Host ''
  if ($null -eq $preInstall) {
    Write-Warning 'No pre-install snapshot was recorded: the machine cannot be compared with its state before the install.'
  } elseif (-not $WhatIfPreference) {
    $diff = Compare-PreInstallSnapshot -Before $preInstall -After (Get-MachineSnapshot)
    if ($diff.Count -eq 0) { Write-Host "Compared with before the install ($($preInstall.at)): managed settings, user rights, tasks, firewall rules and T3CODE_* variables are the same." }
    else { Write-Warning 'Differences from before the install:'; $diff | ForEach-Object { Write-Host "  - $_" } }
  }
  Write-Host 'Uninstalled. Managed-settings backups (*.t3bak-*) are kept. With the policy removed, a Windows server refuses to run Claude until it is installed again.'
  return
}

# ---------- validate every input before changing anything ----------
$T3Exe = Resolve-Executable 'T3Exe' $T3Exe
$ClaudeExe = Resolve-Executable 'ClaudeExe' $ClaudeExe
if ($BridgeExe) {
  # The bridge reaches T3 only through the bridge pipe (README, "Bridge contract"); its task
  # starts only after the pipe is up and checked (step 9).
  if (-not $BridgeUsesPipeOnly) {
    throw '-BridgeExe needs -BridgeUsesPipeOnly: confirm the bridge build reaches T3 only through the pipe, with no TCP fallback (README, "Bridge contract"). Nothing was changed.'
  }
  $BridgeExe = Resolve-Executable 'BridgeExe' $BridgeExe
  if ($TailorApiHosts.Count -eq 0) { throw '-BridgeExe needs -TailorApiHosts (the tailor.au API host names it may reach).' }
}
if (-not $GitExe) {
  $found = Get-Command git -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($null -eq $found) { throw 'git not found: pass -GitExe with the full path of git.exe.' }
  $GitExe = $found.Source
}
$GitExe = Resolve-Executable 'GitExe' $GitExe
if ($NodeExe) { $NodeExe = Resolve-Executable 'NodeExe' $NodeExe }
# T3's PATH: admin-owned folders only, set by the launcher. No WindowsApps, no user folders;
# the server does not re-read PATH from the user environment while the policy is installed.
$ServerPath = @(
  (Join-Path $env:SystemRoot 'System32'), $env:SystemRoot, (Join-Path $env:SystemRoot 'System32\Wbem'),
  (Split-Path -Parent $PwshPath), (Split-Path -Parent $GitExe), (Split-Path -Parent $ClaudeExe), (Split-Path -Parent $T3Exe)
) + $(if ($NodeExe) { @(Split-Path -Parent $NodeExe) } else { @() }) | Select-Object -Unique
foreach ($dir in $ServerPath) {
  if ($dir -match '\\WindowsApps(\\|$)') { throw "Refusing $dir on T3's PATH (WindowsApps)." }
  Assert-AdminControlled $dir -SkipParent
}
$gitVersion = (& $GitExe --version)
if (-not (Test-GitVersionAtLeast -VersionText $gitVersion -Minimum $MinimumGitVersion)) {
  throw "$gitVersion is older than $MinimumGitVersion (security fixes). Update git and re-run."
}
# Settings in the machine tier that loosen T3's lock for every session, or a Claude policy in
# the registry, would win over T3's own lock: refuse until an administrator removes them.
if (-not $SkipMachineManagedSettings -and (Test-Path -LiteralPath $MachineManagedSettingsPath)) {
  $looseners = Get-ManagedSettingsLooseners ([IO.File]::ReadAllText($MachineManagedSettingsPath))
  if ($looseners.Count -gt 0) {
    throw "$MachineManagedSettingsPath sets $($looseners -join ', '), which loosen the lock for every Claude session including T3's. Remove them deliberately and re-run. Nothing was changed."
  }
}
if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Policies\ClaudeCode') {
  throw 'HKLM\SOFTWARE\Policies\ClaudeCode exists: a registry Claude policy would apply alongside T3''s. Remove it deliberately and re-run. Nothing was changed.'
}
$pwshCandidate = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) 'PowerShell\7\pwsh.exe'
if (-not (Test-Path -LiteralPath $pwshCandidate)) {
  $pwshCandidate = (Get-Process -Id $PID).Path
  if ($pwshCandidate -match '\\WindowsApps\\') {
    if ($WhatIfPreference) { Write-Warning 'PowerShell 7 is the Store package; a real install needs the machine-wide MSI (Program Files\PowerShell\7).' }
    else { throw 'Install PowerShell 7 machine-wide (MSI, Program Files\PowerShell\7): the Store package cannot run as the service accounts.' }
  }
}
$PwshPath = Resolve-Executable 'pwsh' $pwshCandidate
$extraRoots = @()
foreach ($root in $WorkspaceRoots) {
  if (-not [IO.Path]::IsPathRooted($root)) { throw "-WorkspaceRoots entries must be full paths: $root" }
  $full = [IO.Path]::GetFullPath($root).TrimEnd('\')
  if ($full.StartsWith($PolicyDir, [StringComparison]::OrdinalIgnoreCase)) { throw "Workspace roots outside the policy folder only: $full" }
  $parent = Split-Path -Parent $full
  if (-not (Test-Path -LiteralPath $parent)) { throw "The parent of $full does not exist." }
  Assert-AdminControlled $parent -SkipParent   # nobody else can swap the folder under us
  # An existing non-empty folder keeps its children's old ACLs (the operator's, Users'): refuse.
  if ((Test-Path -LiteralPath $full) -and @(Get-ChildItem -LiteralPath $full -Force).Count -gt 0) {
    throw "-WorkspaceRoots $full exists and is not empty. Give a new or empty folder; copy code in afterwards (README, Getting code in and out). Nothing was changed."
  }
  $extraRoots += $full
}
if (-not $AllowedHosts) { $AllowedHosts = @($policy.egress.allowedHosts) }
foreach ($hostName in @($AllowedHosts) + @($TailorApiHosts)) {
  if ($hostName -notmatch '^(?=.{1,253}$)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$') { throw "Not a host name: $hostName" }
}
foreach ($entry in $ExtraAllowedAddresses) { [void](ConvertTo-Range $entry) }
$disabledProfiles = @(Get-NetFirewallProfile | Where-Object { -not $_.Enabled })
if ($disabledProfiles.Count -gt 0) {
  throw "Windows Firewall is off for: $(($disabledProfiles | ForEach-Object Name) -join ', '). Turn it on; the egress rules do nothing while it is off."
}
$aclPlan = Get-T3FolderAclPlan -PolicyDir $PolicyDir -ClaudeHomeName $ClaudeHomeName -ExtraWorkspaceRoots $extraRoots

Write-Host 'Plan:'
Write-Host "  accounts: $AgentAccount (runs t3 serve, its Claude and the token issuer), $BridgeAccount (runs the bridge; only reader of the connector token)"
Write-Host "  tasks: $(($Tasks.Values | ForEach-Object { "\T3CodePolicy\$_" }) -join ', ')$(if (-not $BridgeExe) { ' (no bridge task: no -BridgeExe)' })"
foreach ($entry in $aclPlan) { Write-Host "  ACL $(Format-T3AclPlanEntry $entry)" }

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
  # No loopback: the bridge talks to T3 over the pipe only.
  $bridgeAllowed = @(Resolve-AllowedHosts $TailorApiHosts)
  $rules += @{ Name = "T3Policy-$generation-bridge-out"; DisplayName = 'T3 bridge: block outbound except the tailor.au API'; Program = $BridgeExe; Direction = 'Outbound'; RemoteAddress = (Get-BlockedAddresses $bridgeAllowed) }
  $rules += @{ Name = "T3Policy-$generation-bridge-in"; DisplayName = 'T3 bridge: block all inbound'; Program = $BridgeExe; Direction = 'Inbound'; RemoteAddress = (Get-BlockedAddresses @()) }
}
$previousRules = @(Get-NetFirewallRule -Group $RuleGroup -ErrorAction SilentlyContinue)

# Until verify-install.ps1 passes again, nothing starts: stop the services, drop the marker.
foreach ($task in $Tasks.Values) {
  if ((Get-ScheduledTask -TaskName $task -TaskPath '\T3CodePolicy\' -ErrorAction SilentlyContinue) -and $PSCmdlet.ShouldProcess("\T3CodePolicy\$task", 'Stop for the install')) {
    Stop-ScheduledTask -TaskName $task -TaskPath '\T3CodePolicy\' -ErrorAction SilentlyContinue
  }
}
if ((Test-Path -LiteralPath $MarkerPath) -and $PSCmdlet.ShouldProcess($MarkerPath, 'Remove the verified marker (verification runs again at the end)')) { [IO.File]::Delete($MarkerPath) }

# ---------- 1. accounts ----------
# The policy and state folders first, so the undo record and the pre-install snapshot exist
# before anything else changes (the accounts' grants are added in step 2).
foreach ($entry in $aclPlan | Where-Object { $_.Name -in 'policy', 'state' }) { Ensure-PlannedDirectory $entry -CheckTree:($entry.Name -eq 'state') }
$undo = Read-UndoRecord
if (-not $undo.Contains('createdAccounts')) { $undo['createdAccounts'] = [ordered]@{} }
if (-not (Test-Path -LiteralPath $PreInstallPath) -and -not $WhatIfPreference) {
  # First install: the machine as it was, for the self-check and the uninstall diff. An
  # upgrade of an install that never took one records the machine now, marked as an unknown
  # baseline: the self-check then checks only our four rights.
  $snapshot = Get-MachineSnapshot
  $snapshot['baselineKnown'] = ($null -eq $previousInstalled)
  if (-not $snapshot.baselineKnown) { $snapshot.rights = $null }
  Write-ProtectedFile $PreInstallPath (Get-Utf8Bytes (($snapshot | ConvertTo-Json -Depth 6) + "`n"))
}
if (-not $undo.Contains('createdManagedSettingsDir')) {
  $undo['createdManagedSettingsDir'] = -not (Test-Path -LiteralPath (Split-Path -Parent $MachineManagedSettingsPath))
  Save-UndoRecord $undo
}
Write-Host '1. Service accounts (created by this installer only; random passwords, never stored; refused if in any group but Users)'
function Set-OurAccount([string] $name, [string] $description) {
  $existing = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
  $recorded = if ($undo.createdAccounts.Contains($name)) { [string]$undo.createdAccounts[$name] } else { $null }
  if ($null -eq $existing) {
    # Record the intent before creating, so an interrupted run still knows the account is ours.
    $undo.createdAccounts[$name] = 'pending'; Save-UndoRecord $undo
    $recorded = 'pending'
  } elseif ($recorded -eq 'pending') {
    $recorded = $existing.SID.Value
  } elseif ($null -eq $recorded -and $AdoptExistingAccounts) {
    # One-time adoption for upgrades: exactly our description, and no group but Users.
    $groups = Get-AccountGroups -Name $name
    if ($existing.Description -ne $description -or @($groups).Count -ne 1 -or @($groups)[0].Sid -ne 'S-1-5-32-545') {
      throw "Refusing to adopt $name : its description or groups are not exactly this installer's. Nothing was changed."
    }
    $recorded = $existing.SID.Value
    $undo.createdAccounts[$name] = $recorded; Save-UndoRecord $undo
    Write-Host "  adopted the existing account $name (recorded as this installer's)"
  }
  $password = Set-ServiceAccount -Name $name -Description $description -CreatedSid $(if ($null -eq $existing) { $null } else { $recorded }) -WhatIf:$WhatIfPreference
  $now = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
  if ($null -ne $now) { $undo.createdAccounts[$name] = $now.SID.Value; Save-UndoRecord $undo }
  return $password
}
$agentPassword = Set-OurAccount $AgentAccount 'Runs T3 Code and its Claude (T3CodePolicy).'
$bridgePassword = Set-OurAccount $BridgeAccount 'Runs the T3 bridge; reads the connector token (T3CodePolicy).'
function Get-AccountSid([string] $name) {
  $user = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
  if ($null -eq $user) { return $null }   # only in a preview, before the account exists
  return $user.SID.Value
}
$SidMap.agent = Get-AccountSid $AgentAccount
$SidMap.bridge = Get-AccountSid $BridgeAccount
foreach ($pair in @(@{ Name = $AgentAccount; Sid = $SidMap.agent }, @{ Name = $BridgeAccount; Sid = $SidMap.bridge })) {
  $sidText = if ($null -eq $pair.Sid) { '<new account SID>' } else { $pair.Sid }
  Invoke-SeceditUserRights -Changes (Get-ServiceAccountRightsPlan -Sid $sidText) -Description "batch logon granted, interactive/RDP/network logon denied for $($pair.Name)" -WhatIf:$WhatIfPreference
}

# ---------- 2. folders ----------
Write-Host "2. Folders (ACL at creation; existing ones reset by handle)"
$planByName = @{}
foreach ($entry in $aclPlan) { $planByName[$entry.Name] = $entry }
foreach ($entry in $aclPlan) {
  # Admin code works inside these folders, so nothing may be planted in them. The T3 home,
  # the Claude home's subfolders and the workspaces are t3agent's: admin code never goes in.
  $checkTree = @('policy', 't3-home', 'claude-home', 'workspaces', 'connector-drop', 'probe', 'run') -notcontains $entry.Name -and $entry.Name -notlike 'workspace-*'
  $existed = Test-Path -LiteralPath $entry.Path
  # Recorded before it is created, so an interrupted run still knows the root is ours.
  if ($entry.Name -like 'workspace-*' -and -not $existed -and @($undo.createdWorkspaceRoots) -notcontains $entry.Path) {
    $undo.createdWorkspaceRoots = @($undo.createdWorkspaceRoots) + $entry.Path
    Save-UndoRecord $undo
  }
  Ensure-PlannedDirectory $entry -CheckTree:$checkTree
}
# The empty global git config every T3 git call uses (GIT_CONFIG_GLOBAL, gitHardening.ts).
Write-ProtectedFile $GitGlobalConfig ([byte[]]@()) (New-FileEntry @{ agent = 'ReadAndExecute, Synchronize' })
if ((Test-Path -LiteralPath $HooksDir) -and @(Get-ChildItem -LiteralPath $HooksDir -Force).Count -gt 0) {
  throw "$HooksDir must be empty: it is the hooks path for every git command T3 runs. Empty it and re-run."
}

# ---------- 3. Claude home ----------
Write-Host "3. Claude settings -> $ClaudeConfigDir"
$claudeSettings = Join-Path $ClaudeConfigDir 'settings.json'
Write-ProtectedFile $claudeSettings (Get-Utf8Bytes (($policy.claudeInstance.settings | ConvertTo-Json -Depth 10) + "`n")) (New-FileEntry @{ agent = 'ReadAndExecute, Synchronize' })
$claudeJson = Join-Path $ClaudeConfigDir '.claude.json'
if (-not (Test-Path -LiteralPath $claudeJson)) {
  Write-ProtectedFile $claudeJson (Get-Utf8Bytes "{}`n") (New-FileEntry @{ agent = 'Modify, Synchronize' })
} else {
  [void](Assert-NotReparse $claudeJson)   # t3agent's file: left as it is
}

# ---------- 4. machine-wide admin tier ----------
Write-Host '4. Machine-wide Claude admin tier (undo record first; deny entries and parentSettingsBehavior only)'
$machineRecord = $null
if (-not $SkipMachineManagedSettings) {
  $machineRecord = Update-MachineManagedSettings (Get-MachineDenyEntries) $undo
}

# ---------- 5. installed policy and service files ----------
Write-Host '5. Installed policy and service files'
$readAgent = New-FileEntry @{ agent = 'ReadAndExecute, Synchronize' }
$readBoth = New-FileEntry @{ agent = 'ReadAndExecute, Synchronize'; bridge = 'ReadAndExecute, Synchronize' }
$installed = [ordered]@{
  t3Exe = $T3Exe
  t3ExeSha256 = Get-FileSha256 $T3Exe
  claudeExe = $ClaudeExe
  claudeExeSha256 = Get-FileSha256 $ClaudeExe
  pwshExe = $PwshPath
  claudeConfigDir = $ClaudeConfigDir
  t3Home = $T3Home
  agentAccount = $AgentAccount
  bridgeAccount = $BridgeAccount
  claudeHomeName = $ClaudeHomeName
  workspaceRoots = @($DefaultWorkspaces) + $extraRoots
  gitHooksDir = $HooksDir
  gitGlobalConfig = $GitGlobalConfig
  gitExe = $GitExe
  gitExeSha256 = Get-FileSha256 $GitExe
  minimumGitVersion = $MinimumGitVersion
  bridgePipe = (Get-T3BridgePipePath)
  serverPath = @($ServerPath)
  t3Port = $T3Port
  instanceEnvironmentAllowlist = @($policy.claudeInstance.environmentAllowlist)
  installerSha256 = $hashText
  ruleGroup = $RuleGroup
  tasks = $Tasks
}
if ($BridgeExe) { $installed['bridgeExe'] = $BridgeExe; $installed['bridgeExeSha256'] = Get-FileSha256 $BridgeExe }
if ($null -ne $machineRecord) { $installed['machineManagedSettings'] = $machineRecord }
$policy | Add-Member -NotePropertyName installed -NotePropertyValue $installed -Force
Write-ProtectedFile $InstalledPath (Get-Utf8Bytes (($policy | ConvertTo-Json -Depth 12) + "`n")) $readBoth

$seed = [ordered]@{}
foreach ($p in $policy.t3SettingsSeed.PSObject.Properties) { $seed[$p.Name] = $p.Value }
$seed['providerInstances'] = [ordered]@{
  ($policy.claudeInstance.instanceId) = [ordered]@{
    driver = $policy.claudeInstance.driver
    enabled = $true
    config = [ordered]@{ binaryPath = $ClaudeExe; homePath = $ClaudeConfigDir }
  }
}
$seedPath = Join-Path $ServiceDir 't3-settings.seed.json'
Write-ProtectedFile $seedPath (Get-Utf8Bytes (($seed | ConvertTo-Json -Depth 10) + "`n")) $readAgent

$t3Launcher = Join-Path $ServiceDir 'start-t3.ps1'
$pipeShim = Join-Path $ServiceDir 'bridge-pipe.ps1'
$issuer = Join-Path $ServiceDir 'issue-token.ps1'
$mover = Join-Path $ServiceDir 'move-token.ps1'
$bridgeLauncher = Join-Path $ServiceDir 'start-bridge.ps1'
$agentId = if ($SidMap.agent) { $SidMap.agent } else { 'S-1-0-0' }
$bridgeId = if ($SidMap.bridge) { $SidMap.bridge } else { 'S-1-0-0' }
Write-ProtectedFile $pipeShim (Get-Utf8Bytes (Get-BridgePipeShimText -AgentSid $agentId -BridgeSid $bridgeId -T3Port $T3Port)) $readAgent
Write-ProtectedFile $t3Launcher (Get-Utf8Bytes (Get-T3LauncherText -T3Exe $T3Exe -T3Home $T3Home -Environment $serverVariables -MustBeUnset $mustBeUnset `
      -MarkerPath $MarkerPath -RequiredFiles @($T3Exe, $ClaudeExe, $InstalledPath, $t3Launcher, $seedPath, $pipeShim) -SettingsSeedPath $seedPath `
      -PipeShimPath $pipeShim -PwshPath $PwshPath -ServerPath $ServerPath)) $readAgent
Write-ProtectedFile $issuer (Get-Utf8Bytes (Get-TokenIssuerText -T3Exe $T3Exe -T3Home $T3Home -DropPath $DropPath -Ttl "$($ConnectorTokenDays)d" `
      -MustBeUnset $mustBeUnset -MarkerPath $MarkerPath -RequiredFiles @($T3Exe, $InstalledPath, $issuer))) $readAgent
Write-ProtectedFile $RotateScript (Get-Utf8Bytes (Get-KeyRotationText -T3Exe $T3Exe -T3Home $T3Home -PolicyPath $InstalledPath -MustBeUnset $mustBeUnset)) $readAgent
$probe = Join-Path $ServiceDir 'probe-agent.ps1'
$probeResult = Join-Path $ProbeDir 'result.json'
$probeTests = [ordered]@{
  'read-token' = @{ Path = $TokenPath; Mode = 'Read' }
  'read-marker' = @{ Path = $MarkerPath; Mode = 'Read' }
  'read-policy' = @{ Path = $InstalledPath; Mode = 'Read' }
  'write-policy' = @{ Path = $InstalledPath; Mode = 'WriteFile' }
  'create-in-service' = @{ Path = $ServiceDir; Mode = 'CreateIn' }
  'create-in-claude-home-root' = @{ Path = $ClaudeConfigDir; Mode = 'CreateIn' }
  'create-in-git-hooks' = @{ Path = $HooksDir; Mode = 'CreateIn' }
  'write-git-config' = @{ Path = $GitGlobalConfig; Mode = 'WriteFile' }
  'create-in-connector' = @{ Path = $ConnectorDir; Mode = 'CreateIn' }
  'create-in-installer' = @{ Path = $InstallerDir; Mode = 'CreateIn' }
  'read-bridge-key' = @{ Path = $BridgeKeyPath; Mode = 'Read' }
  'write-t3-launcher' = @{ Path = $t3Launcher; Mode = 'WriteFile' }
  'write-issuer' = @{ Path = $issuer; Mode = 'WriteFile' }
  'write-pipe-shim' = @{ Path = $pipeShim; Mode = 'WriteFile' }
}
Write-ProtectedFile $probe (Get-Utf8Bytes (Get-AgentProbeText -ResultPath $probeResult -Tests $probeTests)) $readAgent
$pipeProbe = Join-Path $ServiceDir 'probe-pipe.ps1'
Write-ProtectedFile $pipeProbe (Get-Utf8Bytes (Get-PipeProbeText -ResultPath (Join-Path $ProbeDir 'pipe.json'))) (New-FileEntry @{})
Write-ProtectedFile $mover (Get-Utf8Bytes (Get-TokenMoverText -DropPath $DropPath -TokenPath $TokenPath -AgentSid $agentId -BridgeSid $bridgeId)) (New-FileEntry @{})
if ($BridgeExe) {
  Write-ProtectedFile $bridgeLauncher (Get-Utf8Bytes (Get-BridgeLauncherText -BridgeExe $BridgeExe -TokenPath $TokenPath -KeyPath $BridgeKeyPath `
        -MustBeUnset $mustBeUnset -MarkerPath $MarkerPath -RequiredFiles @($BridgeExe, $bridgeLauncher) -AgentSid $agentId)) (New-FileEntry @{ bridge = 'ReadAndExecute, Synchronize' })
}

# ---------- 6. tasks ----------
Write-Host '6. Scheduled tasks (Task Scheduler COM API; passwords never on a command line)'
Register-ServiceTask -TaskName $Tasks.Server -Account $AgentAccount -Password $agentPassword -WhatIf:$WhatIfPreference `
  -Xml (Get-ServiceTaskXml -Description 'Runs t3 serve (T3CodePolicy).' -Account $AgentAccount -PwshPath $PwshPath -LauncherPath $t3Launcher -Trigger Startup)
Register-ServiceTask -TaskName $Tasks.Issuer -Account $AgentAccount -Password $agentPassword -WhatIf:$WhatIfPreference `
  -Xml (Get-ServiceTaskXml -Description 'Issues the connector token into the drop folder (T3CodePolicy).' -Account $AgentAccount -PwshPath $PwshPath -LauncherPath $issuer -Trigger Daily)
Register-ServiceTask -TaskName $Tasks.Rotate -Account $AgentAccount -Password $agentPassword -WhatIf:$WhatIfPreference `
  -Xml (Get-ServiceTaskXml -Description 'Rotates the T3 signing keys on demand (emergency revoke, uninstall) (T3CodePolicy).' -Account $AgentAccount -PwshPath $PwshPath -LauncherPath $RotateScript -Trigger OnDemand)
Register-ServiceTask -TaskName $Tasks.RotateToken -Account $AgentAccount -Password $agentPassword -WhatIf:$WhatIfPreference `
  -Xml (Get-ServiceTaskXml -Description 'Issues a connector token now and revokes every previous one (T3CodePolicy).' -Account $AgentAccount -PwshPath $PwshPath -LauncherPath $issuer -Trigger OnDemand -ExtraArguments '-RevokeAllPrevious')
Register-ServiceTask -TaskName $Tasks.Probe -Account $AgentAccount -Password $agentPassword -WhatIf:$WhatIfPreference `
  -Xml (Get-ServiceTaskXml -Description 'Runs the self-check probe as the agent account (T3CodePolicy).' -Account $AgentAccount -PwshPath $PwshPath -LauncherPath $probe -Trigger OnDemand)
Register-ServiceTask -TaskName $Tasks.PipeProbe -System -WhatIf:$WhatIfPreference `
  -Xml (Get-ServiceTaskXml -Description 'Reads the bridge pipe security descriptor for the self-check (T3CodePolicy).' -System -PwshPath $PwshPath -LauncherPath $pipeProbe -Trigger OnDemand)
Register-ServiceTask -TaskName $Tasks.Mover -System -WhatIf:$WhatIfPreference `
  -Xml (Get-ServiceTaskXml -Description 'Moves the connector token from the drop folder (T3CodePolicy).' -System -PwshPath $PwshPath -LauncherPath $mover -Trigger Every10Minutes)
if ($BridgeExe) {
  Register-ServiceTask -TaskName $Tasks.Bridge -Account $BridgeAccount -Password $bridgePassword -WhatIf:$WhatIfPreference `
    -Xml (Get-ServiceTaskXml -Description 'Runs the T3 bridge (T3CodePolicy).' -Account $BridgeAccount -PwshPath $PwshPath -LauncherPath $bridgeLauncher -Trigger Startup)
}
$agentPassword.Dispose(); $bridgePassword.Dispose()
$agentPassword = $null; $bridgePassword = $null

# ---------- 7. machine environment ----------
Write-Host '7. Machine environment (T3CODE_* only; previous values recorded for uninstall)'
foreach ($name in $serverVariables.Keys) { Set-MachineVariable $name $serverVariables[$name] $undo }

# ---------- 8. firewall ----------
Write-Host '8. Firewall (new rules first, then the previous ones are removed)'
foreach ($rule in $rules) {
  if ($PSCmdlet.ShouldProcess($rule.DisplayName, "Add block rule for $($rule.Program) ($($rule.RemoteAddress.Count) ranges)")) {
    New-NetFirewallRule -Name $rule.Name -Group $RuleGroup -DisplayName $rule.DisplayName -Program $rule.Program `
      -Direction $rule.Direction -Action Block -Profile Any -RemoteAddress $rule.RemoteAddress -Enabled True | Out-Null
  }
}
if ($previousRules.Count -gt 0 -and $PSCmdlet.ShouldProcess($RuleGroup, "Remove $($previousRules.Count) previous firewall rule(s)")) {
  $previousRules | Remove-NetFirewallRule
}

# ---------- 9. verify, then start ----------
Write-Host '9. Self-check (verify-install.ps1)'
if ($WhatIfPreference) {
  Write-Host 'What if: run verify-install.ps1; on a full PASS write the marker and start the tasks.'
  return
}
$passed = & $verifyBlock -AlreadyLoaded
if (-not $passed) {
  Write-Warning 'Self-check FAILED: nothing was started. Fix the failed checks and run verify-install.ps1 again (it starts nothing; re-run this installer to start).'
  exit 1
}
foreach ($task in @($Tasks.Server, $Tasks.Mover)) {
  if ($PSCmdlet.ShouldProcess("\T3CodePolicy\$task", 'Start now')) { Start-ScheduledTask -TaskName $task -TaskPath '\T3CodePolicy\' }
}
# The bridge starts only once T3's pipe is up with the planned owner and DACL (probe as t3agent).
if ($BridgeExe) {
  Write-Host 'Waiting for the T3 bridge pipe, then checking it...'
  $pipeUp = $false
  for ($i = 0; $i -lt 30 -and -not $pipeUp; $i++) { Start-Sleep -Seconds 2; $pipeUp = [IO.Directory]::GetFiles(([string][char]92) * 2 + '.' + [char]92 + 'pipe' + [char]92) -contains (Get-T3BridgePipePath) }
  $pipePassed = $pipeUp -and (& $verifyBlock -AlreadyLoaded -NoMarker -RequirePipe)
  if (-not $pipePassed) {
    Write-Warning 'The bridge pipe is missing or not as planned: the bridge was NOT started. Check the T3 server task, then re-run the installer.'
    exit 1
  }
  if ($PSCmdlet.ShouldProcess("\T3CodePolicy\$($Tasks.Bridge)", 'Start now')) { Start-ScheduledTask -TaskName $Tasks.Bridge -TaskPath '\T3CodePolicy\' }
}
if ($RotateConnectorToken -and $PSCmdlet.ShouldProcess("\T3CodePolicy\$($Tasks.RotateToken)", 'Issue a connector token now and revoke every previous connector session')) {
  $rotation = Invoke-TaskAndWait $Tasks.RotateToken
  if ($rotation -ne 0) {
    Write-Warning "Connector token rotation FAILED (result: $(if ($null -eq $rotation) { 'did not run or finish' } else { $rotation })). Previous sessions may already be revoked; see the task's history, then run -RotateConnectorToken again."
    exit 1
  }
  Write-Host '  connector token rotated: every previous connector session revoked; the mover places the new token within ten minutes'
} elseif ((-not (Test-Path -LiteralPath $TokenPath)) -and $PSCmdlet.ShouldProcess("\T3CodePolicy\$($Tasks.Issuer)", 'Issue a connector token now (moved into connector\ within ten minutes)')) {
  Start-ScheduledTask -TaskName $Tasks.Issuer -TaskPath '\T3CodePolicy\'
}

Write-Host ''
Write-Host 'Done. Next steps (not done by this script):'
Write-Host '  - Work through the manual checks verify-install.ps1 printed.'
Write-Host "  - If anything looks wrong: pwsh -NoProfile -File `"$InstallerDir\install-policy.ps1`" -EmergencyRevoke"
Write-Host '  - Enter the model credential on the Claude provider instance as a sensitive value (provider-config.md).'
Write-Host "  - As an administrator, put the bridge's tailor.au key in $BridgeKeyPath (the folder ACL keeps it $BridgeAccount-only)."
Write-Host '  - Run the live egress capture (SECURITY-REVIEW.md, T3-01).'
