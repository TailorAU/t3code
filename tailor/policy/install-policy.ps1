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
  [switch] $Uninstall
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# The server reads the policy from this fixed path (tailorPolicyMarkerPath in ClaudeAdapterV2.ts).
$PolicyDir = Join-Path $env:ProgramData 'T3CodePolicy'
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

function New-ProtectedSecurity([bool] $isDirectory, [string] $readUser, [string] $modifyUser) {
  $security = if ($isDirectory) { New-Object Security.AccessControl.DirectorySecurity } else { New-Object Security.AccessControl.FileSecurity }
  $security.SetAccessRuleProtection($true, $false)
  $security.SetOwner($SidAdministrators)
  $inherit = if ($isDirectory) { [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit' } else { [Security.AccessControl.InheritanceFlags]::None }
  $none = [Security.AccessControl.PropagationFlags]::None
  $allow = [Security.AccessControl.AccessControlType]::Allow
  $full = [Security.AccessControl.FileSystemRights]::FullControl
  $read = [Security.AccessControl.FileSystemRights]::ReadAndExecute
  $security.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($SidAdministrators, $full, $inherit, $none, $allow)))
  $security.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($SidSystem, $full, $inherit, $none, $allow)))
  $security.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($SidUsers, $read, $inherit, $none, $allow)))
  if ($readUser) { $security.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($readUser, $read, $inherit, $none, $allow))) }
  if ($modifyUser) {
    $modify = [Security.AccessControl.FileSystemRights]::Modify
    $security.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($modifyUser, $modify, $inherit, $none, $allow)))
  }
  return $security
}

function Assert-SafeExisting([string] $path) {
  $item = Get-Item -LiteralPath $path -Force
  if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw "Refusing to use $path : it is a reparse point (junction or symbolic link). Remove it and re-run."
  }
  $owner = (Get-Acl -LiteralPath $path).GetOwner([Security.Principal.SecurityIdentifier])
  if ($owner -ne $SidAdministrators -and $owner -ne $SidSystem) {
    throw "Refusing to use $path : owned by $owner, not Administrators or SYSTEM. Remove it and re-run."
  }
}

# Creates the folder with its protected ACL in one call, or checks and resets an existing one.
function Ensure-ProtectedDirectory([string] $path, [string] $modifyUser) {
  $security = New-ProtectedSecurity $true $null $modifyUser
  if (Test-Path -LiteralPath $path) {
    Assert-SafeExisting $path
    if ($PSCmdlet.ShouldProcess($path, 'Reset ACL (Administrators/SYSTEM full, Users read' + $(if ($modifyUser) { ", $modifyUser modify" } else { '' }) + ')')) {
      Set-Acl -LiteralPath $path -AclObject $security
    }
    return
  }
  if ($PSCmdlet.ShouldProcess($path, 'Create directory with protected ACL')) {
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
      [void][IO.Directory]::CreateDirectory($path, $security)
    } else {
      [void][IO.FileSystemAclExtensions]::Create((New-Object IO.DirectoryInfo($path)), $security)
    }
    Assert-SafeExisting $path
  }
}

# Replaces a file inside a protected folder: deletes whatever is there (so a planted hard
# link or reparse point is removed, never written through), then writes and locks the new file.
function Write-ProtectedFile([string] $path, [string] $content, [string] $readUser) {
  $current = $null
  if (Test-Path -LiteralPath $path) {
    $item = Get-Item -LiteralPath $path -Force
    if (-not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { $current = [IO.File]::ReadAllText($path) }
  }
  if ($current -eq $content) {
    Write-Host "  unchanged: $path"
  } elseif ($PSCmdlet.ShouldProcess($path, 'Replace file')) {
    if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
    [IO.File]::WriteAllText($path, $content, (New-Object Text.UTF8Encoding($false)))
  }
  if ((Test-Path -LiteralPath $path) -and $PSCmdlet.ShouldProcess($path, 'Reset file ACL (read-only to non-admins)')) {
    Set-Acl -LiteralPath $path -AclObject (New-ProtectedSecurity $false $readUser $null)
  }
}

function Set-MachineVariable([string] $name, [string] $value) {
  $current = [Environment]::GetEnvironmentVariable($name, 'Machine')
  if ($current -eq $value) { Write-Host "  unchanged: $name"; return }
  $action = if ($null -eq $value) { 'Remove machine variable' } else { "Set machine variable to '$value'" }
  if ($PSCmdlet.ShouldProcess($name, $action)) {
    [Environment]::SetEnvironmentVariable($name, $value, 'Machine')
  }
  $user = [Environment]::GetEnvironmentVariable($name, 'User')
  if ($null -ne $value -and $null -ne $user -and $user -ne $value) {
    Write-Warning "$name is also set for the current user ('$user'). The connector passes the policy value explicitly."
  }
}

function Get-FileSha256([string] $path) {
  # Not Get-FileHash: Windows PowerShell 5.1 skips it under -WhatIf.
  $sha = [Security.Cryptography.SHA256]::Create()
  try { $bytes = $sha.ComputeHash([IO.File]::ReadAllBytes($path)) } finally { $sha.Dispose() }
  return (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

# ---------- main ----------
Assert-Elevated
$scriptPath = $MyInvocation.MyCommand.Path
if (-not $PolicyTemplate) { $PolicyTemplate = Join-Path (Split-Path -Parent $scriptPath) 't3-policy.template.json' }

# 0. Integrity: hash check, then a protected copy of the installer.
$scriptHash = Get-FileSha256 $scriptPath
$templateHash = Get-FileSha256 $PolicyTemplate
Write-Host "Installer SHA-256: script=$scriptHash,template=$templateHash"
if ($ExpectedSha256) {
  $expected = @{}
  foreach ($pair in $ExpectedSha256.Split(',')) { $kv = $pair.Split('=', 2); if ($kv.Length -eq 2) { $expected[$kv[0].Trim()] = $kv[1].Trim().ToLowerInvariant() } }
  if ($expected['script'] -ne $scriptHash -or $expected['template'] -ne $templateHash) {
    throw 'Hash mismatch: this installer or its template is not the reviewed version. Nothing was changed.'
  }
} elseif (-not $scriptPath.StartsWith($InstallerDir, [StringComparison]::OrdinalIgnoreCase)) {
  Write-Warning 'No -ExpectedSha256 given. Pass the hashes from the reviewed commit for a first install.'
}

$policy = Get-Content -LiteralPath $PolicyTemplate -Raw | ConvertFrom-Json
$serverVariables = @($policy.serverEnvironment.PSObject.Properties)

# Validate every input before changing anything.
if (-not $Uninstall) {
  foreach ($name in 'T3Exe', 'ClaudeExe') {
    $value = (Get-Variable -Name $name).Value
    if (-not [IO.Path]::IsPathRooted($value)) { throw "-$name must be a full path." }
    $full = [IO.Path]::GetFullPath($value)
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { throw "Not found: $full" }
    if ([IO.Path]::GetExtension($full) -ne '.exe') { throw "-$name must be an .exe: $full" }
    Set-Variable -Name $name -Value $full -WhatIf:$false
  }
  if (-not $AllowedHosts) { $AllowedHosts = @($policy.egress.allowedHosts) }
  foreach ($hostName in $AllowedHosts) {
    if ($hostName -notmatch '^(?=.{1,253}$)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$') { throw "Not a host name: $hostName" }
  }
  foreach ($entry in $ExtraAllowedAddresses) { [void](ConvertTo-Range $entry) }
  [void](New-Object Security.Principal.NTAccount($RunAsUser)).Translate([Security.Principal.SecurityIdentifier])
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

if ($Uninstall) {
  if ($previousRules.Count -gt 0 -and $PSCmdlet.ShouldProcess($RuleGroup, "Remove $($previousRules.Count) firewall rule(s)")) { $previousRules | Remove-NetFirewallRule }
  foreach ($variable in $serverVariables) { Set-MachineVariable $variable.Name $null }
  $policyFile = Join-Path $PolicyDir 't3-policy.json'
  if ((Test-Path -LiteralPath $policyFile) -and $PSCmdlet.ShouldProcess($policyFile, 'Remove installed policy')) { Remove-Item -LiteralPath $policyFile -Force }
  Write-Host 'Uninstalled. With the policy removed the server no longer requires the policy Claude home.'
  return
}

Write-Host "1. Protected folders under $PolicyDir"
Ensure-ProtectedDirectory $PolicyDir $null
Ensure-ProtectedDirectory $InstallerDir $null
Ensure-ProtectedDirectory $ClaudeConfigDir $RunAsUser

Write-Host '   Protected installer copy'
if (-not $scriptPath.StartsWith($InstallerDir, [StringComparison]::OrdinalIgnoreCase)) {
  Write-ProtectedFile (Join-Path $InstallerDir 'install-policy.ps1') ([IO.File]::ReadAllText($scriptPath)) $null
  Write-ProtectedFile (Join-Path $InstallerDir 't3-policy.template.json') ([IO.File]::ReadAllText($PolicyTemplate)) $null
}

Write-Host '2. Installed policy and T3 settings seed'
$installed = [ordered]@{ t3Exe = $T3Exe; claudeExe = $ClaudeExe; claudeConfigDir = $ClaudeConfigDir; runAsUser = $RunAsUser; installerSha256 = "script=$scriptHash,template=$templateHash" }
$policy | Add-Member -NotePropertyName installed -NotePropertyValue $installed -Force
Write-ProtectedFile (Join-Path $PolicyDir 't3-policy.json') (($policy | ConvertTo-Json -Depth 12) + "`n") $null

$seed = [ordered]@{}
foreach ($p in $policy.t3SettingsSeed.PSObject.Properties) { $seed[$p.Name] = $p.Value }
$instances = [ordered]@{}
foreach ($driver in @($policy.disabledDrivers)) { $instances[$driver] = [ordered]@{ driver = $driver; enabled = $false } }
$instances[$policy.claudeInstance.instanceId] = [ordered]@{
  driver = $policy.claudeInstance.driver
  enabled = $true
  config = [ordered]@{ binaryPath = $ClaudeExe; homePath = $ClaudeConfigDir }
  environment = @($policy.claudeInstance.environment.PSObject.Properties |
      Where-Object { $_.Name -ne '$comment' } |
      ForEach-Object { [ordered]@{ name = $_.Name; value = [string]$_.Value; sensitive = $false } })
}
$seed['providerInstances'] = $instances
# The seed stays in the protected folder; the connector applies it. The server does not trust it:
# it enforces the Claude home and binary from t3-policy.json itself.
Write-ProtectedFile (Join-Path $PolicyDir 't3-settings.seed.json') (($seed | ConvertTo-Json -Depth 10) + "`n") $null

Write-Host '3. Machine environment (T3CODE_* only)'
foreach ($variable in $serverVariables) { Set-MachineVariable $variable.Name ([string]$variable.Value) }
foreach ($name in @($policy.serverEnvironmentMustBeUnset)) {
  if ([Environment]::GetEnvironmentVariable($name, 'Machine')) { Write-Warning "$name is set machine-wide; the policy requires it unset for t3 serve (the connector clears it)." }
  if ([Environment]::GetEnvironmentVariable($name, 'User')) { Write-Warning "$name is set for the current user; the policy requires it unset for t3 serve (the connector clears it)." }
}

Write-Host "4. Claude settings -> $ClaudeConfigDir"
Write-ProtectedFile (Join-Path $ClaudeConfigDir 'settings.json') (($policy.claudeInstance.settings | ConvertTo-Json -Depth 10) + "`n") $RunAsUser

Write-Host '5. Firewall (new rules first, then the previous ones are removed)'
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
