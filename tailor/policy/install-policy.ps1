<#
.SYNOPSIS
  Installs the T3 Code lock-down policy on one Windows machine. Run once, elevated.

.DESCRIPTION
  T3 Code v0.1.6 has no managed-policy file of its own (tailor/policy/README.md). This
  script applies the nearest equivalent from t3-policy.template.json:

    1. Copies the policy to -PolicyDir, writable only by Administrators and SYSTEM.
    2. Sets the policy's T3CODE_* server variables at machine scope (only T3 reads them).
    3. Writes a Claude settings file for T3's Claude instance (-ClaudeConfigDir) that
       disables Bypass and Auto mode. The file is read-only to non-admins, so neither
       the user nor an agent running as the user can loosen it.
    4. Adds Windows Firewall rules:
         - T3 server (-T3Exe): no inbound or outbound traffic except loopback.
         - T3's Claude binary (-ClaudeExe): no outbound traffic except loopback and the
           addresses of -AllowedHosts (or loopback only, with -ClaudeEgress LoopbackOnly).

  Windows Firewall matches IP addresses, not host names, and a Block rule always beats
  an Allow rule. The rules are therefore Block rules whose remote address is the
  complement of the allowed set, computed from DNS at install time. Model endpoints sit
  behind CDNs whose addresses change: re-run this script to refresh (it is idempotent),
  pass provider-published ranges with -ExtraAllowedAddresses, or use
  -ClaudeEgress LoopbackOnly with a host-name allowlisting proxy on loopback.

  Per-program rules do not cover child processes. Commands an agent runs (shell, git,
  curl) are separate programs and are NOT contained by these rules; Supervised mode
  (every command needs an approval) is the control for them. See SECURITY-REVIEW.md.

  The script holds no credentials and reads none. It is idempotent: rules in its group
  are replaced, files and variables are rewritten only when they differ. Use -WhatIf to
  preview every change, and -Uninstall to remove the rules, variables and policy copy.

.PARAMETER T3Exe
  Full path of the t3.exe the connector starts (built from this fork).

.PARAMETER ClaudeExe
  Full path of the Claude binary T3's Claude instance uses. Use a dedicated copy that
  only T3 runs: the firewall rule applies to every process started from this path.

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
  [string] $PolicyDir = (Join-Path $env:ProgramData 'T3CodePolicy'),
  [string] $ClaudeConfigDir = (Join-Path (Join-Path $env:ProgramData 'T3CodePolicy') 'claude-home'),
  # The account that runs t3 serve. It gets Modify on -ClaudeConfigDir, read-only on its settings.json.
  [string] $RunAsUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name,
  # Host names the Claude binary may reach. Defaults to the template's egress.allowedHosts.
  [string[]] $AllowedHosts,
  # Extra IPv4/IPv6 addresses or CIDR ranges to allow, e.g. a provider's published API range.
  [string[]] $ExtraAllowedAddresses = @(),
  [ValidateSet('Resolve', 'LoopbackOnly')][string] $ClaudeEgress = 'Resolve',
  # Optional: T3's settings.json (<T3 home>\userdata\settings.json). Seeded only if absent.
  [string] $SeedT3SettingsPath,
  [string] $RuleGroup = 'T3 Code egress policy',
  [switch] $Uninstall
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

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

# ---------- files, ACLs, variables ----------
function Set-ProtectedAcl([string] $path, [string] $readOnlyUser) {
  $acl = Get-Acl -LiteralPath $path
  $acl.SetAccessRuleProtection($true, $false)
  foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRule($rule) }
  $full = [Security.AccessControl.FileSystemRights]::FullControl
  $read = [Security.AccessControl.FileSystemRights]::ReadAndExecute
  $allow = [Security.AccessControl.AccessControlType]::Allow
  $administrators = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
  $system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
  $users = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')
  $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($administrators, $full, $allow)))
  $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($system, $full, $allow)))
  $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($users, $read, $allow)))
  if ($readOnlyUser) { $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($readOnlyUser, $read, $allow))) }
  Set-Acl -LiteralPath $path -AclObject $acl
}

function Write-FileIfChanged([string] $path, [string] $content) {
  $current = if (Test-Path -LiteralPath $path) { [IO.File]::ReadAllText($path) } else { $null }
  if ($current -eq $content) { Write-Host "  unchanged: $path"; return $false }
  if ($PSCmdlet.ShouldProcess($path, 'Write policy file')) {
    if ((Test-Path -LiteralPath $path) -and ((Get-Item -LiteralPath $path).IsReadOnly)) {
      (Get-Item -LiteralPath $path).IsReadOnly = $false
    }
    [IO.File]::WriteAllText($path, $content, (New-Object Text.UTF8Encoding($false)))
  }
  return $true
}

function Ensure-Directory([string] $path) {
  if (-not (Test-Path -LiteralPath $path) -and $PSCmdlet.ShouldProcess($path, 'Create directory')) {
    New-Item -ItemType Directory -Path $path -Force | Out-Null
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
    Write-Warning "$name is also set for the current user ('$user'), which overrides the machine value in that user's shells. The connector passes the policy value explicitly."
  }
}

# ---------- main ----------
Assert-Elevated
if (-not $PolicyTemplate) {
  $PolicyTemplate = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 't3-policy.template.json'
}
$policy = Get-Content -LiteralPath $PolicyTemplate -Raw | ConvertFrom-Json
$serverVariables = @($policy.serverEnvironment.PSObject.Properties)

Write-Host "Removing existing firewall rules in group '$RuleGroup'"
$existing = @(Get-NetFirewallRule -Group $RuleGroup -ErrorAction SilentlyContinue)
if ($existing.Count -gt 0 -and $PSCmdlet.ShouldProcess($RuleGroup, "Remove $($existing.Count) firewall rule(s)")) {
  $existing | Remove-NetFirewallRule
}

if ($Uninstall) {
  foreach ($variable in $serverVariables) { Set-MachineVariable $variable.Name $null }
  $policyFile = Join-Path $PolicyDir 't3-policy.json'
  if ((Test-Path -LiteralPath $policyFile) -and $PSCmdlet.ShouldProcess($policyFile, 'Remove policy file')) {
    Remove-Item -LiteralPath $policyFile -Force
  }
  Write-Host 'Uninstalled. The Claude settings file in the Claude config directory is left in place.'
  return
}

$T3Exe = [IO.Path]::GetFullPath($T3Exe)
$ClaudeExe = [IO.Path]::GetFullPath($ClaudeExe)
foreach ($program in $T3Exe, $ClaudeExe) {
  if (-not (Test-Path -LiteralPath $program -PathType Leaf)) { throw "Not found: $program" }
}
if (-not $AllowedHosts) { $AllowedHosts = @($policy.egress.allowedHosts) }

Write-Host "1. Policy file -> $PolicyDir"
Ensure-Directory $PolicyDir
$policyFile = Join-Path $PolicyDir 't3-policy.json'
[void](Write-FileIfChanged $policyFile (Get-Content -LiteralPath $PolicyTemplate -Raw))
if ((Test-Path -LiteralPath $policyFile) -and $PSCmdlet.ShouldProcess($policyFile, 'Restrict to Administrators and SYSTEM (Users read)')) {
  Set-ProtectedAcl $policyFile $null
}

Write-Host '2. Machine environment (T3CODE_* only)'
foreach ($variable in $serverVariables) { Set-MachineVariable $variable.Name ([string]$variable.Value) }
foreach ($name in @($policy.serverEnvironmentMustBeUnset)) {
  if ([Environment]::GetEnvironmentVariable($name, 'Machine')) { Set-MachineVariable $name $null }
  if ([Environment]::GetEnvironmentVariable($name, 'User')) { Write-Warning "$name is set for the current user; the policy requires it unset." }
}

Write-Host "3. Claude settings -> $ClaudeConfigDir"
Ensure-Directory $ClaudeConfigDir
if ((Test-Path -LiteralPath $ClaudeConfigDir) -and $PSCmdlet.ShouldProcess($ClaudeConfigDir, "Grant $RunAsUser Modify")) {
  $acl = Get-Acl -LiteralPath $ClaudeConfigDir
  $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
  $rule = New-Object Security.AccessControl.FileSystemAccessRule($RunAsUser, 'Modify', $inherit, 'None', 'Allow')
  $acl.AddAccessRule($rule)
  Set-Acl -LiteralPath $ClaudeConfigDir -AclObject $acl
}
$claudeSettingsFile = Join-Path $ClaudeConfigDir 'settings.json'
[void](Write-FileIfChanged $claudeSettingsFile (($policy.claudeInstance.settings | ConvertTo-Json -Depth 10) + "`n"))
if ((Test-Path -LiteralPath $claudeSettingsFile) -and $PSCmdlet.ShouldProcess($claudeSettingsFile, "Make read-only for $RunAsUser and Users")) {
  # Modify on the folder does not include Delete Child, so the user cannot delete or replace this file.
  Set-ProtectedAcl $claudeSettingsFile $RunAsUser
}

if ($SeedT3SettingsPath) {
  Write-Host "   T3 settings seed -> $SeedT3SettingsPath"
  if (Test-Path -LiteralPath $SeedT3SettingsPath) {
    Write-Warning 'T3 settings.json exists; not overwritten. Apply t3SettingsSeed in Settings, or remove the file while T3 is stopped.'
  } else {
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
    Ensure-Directory (Split-Path -Parent $SeedT3SettingsPath)
    [void](Write-FileIfChanged $SeedT3SettingsPath (($seed | ConvertTo-Json -Depth 10) + "`n"))
  }
}

Write-Host '4. Firewall'
$serverBlocked = Get-BlockedAddresses $Loopback
$claudeAllowed = @($Loopback) + @($ExtraAllowedAddresses)
if ($ClaudeEgress -eq 'Resolve') {
  Write-Host '   Resolving allowed hosts:'
  $claudeAllowed += @(Resolve-AllowedHosts $AllowedHosts)
}
$claudeBlocked = Get-BlockedAddresses $claudeAllowed
$rules = @(
  @{ DisplayName = 'T3 server: block outbound except loopback'; Program = $T3Exe; Direction = 'Outbound'; RemoteAddress = $serverBlocked },
  @{ DisplayName = 'T3 server: block inbound except loopback'; Program = $T3Exe; Direction = 'Inbound'; RemoteAddress = $serverBlocked },
  @{ DisplayName = "T3 Claude: block outbound except loopback and model endpoints ($ClaudeEgress)"; Program = $ClaudeExe; Direction = 'Outbound'; RemoteAddress = $claudeBlocked }
)
foreach ($rule in $rules) {
  if ($PSCmdlet.ShouldProcess($rule.DisplayName, "Add block rule for $($rule.Program) ($($rule.RemoteAddress.Count) ranges)")) {
    New-NetFirewallRule -Group $RuleGroup -DisplayName $rule.DisplayName -Program $rule.Program `
      -Direction $rule.Direction -Action Block -Profile Any -RemoteAddress $rule.RemoteAddress -Enabled True | Out-Null
  }
}

Write-Host ''
Write-Host 'Done. Next steps (not done by this script):'
Write-Host "  - Start t3 serve only through the connector, with the policy's serverEnvironment."
Write-Host '  - Enter the model credential on the Claude provider instance as a sensitive value (provider-config.md).'
Write-Host "  - Issue the connector token: $($policy.connectorToken.issueCommand)"
Write-Host '  - Run the live egress capture (SECURITY-REVIEW.md, T3-01) and re-run this script when endpoint addresses change.'
