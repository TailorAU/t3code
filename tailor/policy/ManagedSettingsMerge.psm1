#Requires -Version 7.2
<#
  Tailor fork (TailorAU/t3code): merge deny entries into Claude Code's machine-wide
  managed-settings.json without touching anything else.

  That file is the administrator tier for EVERY Claude Code session on the PC, so this module
  only ever adds entries to permissions.deny (de-duplicated), keeps every other key and value
  as it is (unknown keys included), refuses a malformed file, writes through a temp file and
  an atomic rename after re-parsing the result, and on removal takes out only the entries it
  recorded as added.
#>
Set-StrictMode -Version 3.0

function ConvertFrom-ManagedSettingsText([string] $text) {
  try {
    $parsed = $text | ConvertFrom-Json -AsHashtable -Depth 100 -ErrorAction Stop
  } catch {
    throw "managed-settings.json is not valid JSON; nothing was changed. $($_.Exception.Message)"
  }
  if ($parsed -isnot [System.Collections.IDictionary]) {
    throw 'managed-settings.json is not a JSON object; nothing was changed.'
  }
  return $parsed
}

function ConvertTo-ManagedSettingsText($settings) {
  return ($settings | ConvertTo-Json -Depth 100) + "`n"
}

<#
  Returns the merged settings and exactly what was added. Pure: no file access.
  $existingText = $null means there is no file yet.
#>
function Get-ManagedSettingsMerge {
  # [object], not [string]: PowerShell turns a $null string argument into "".
  param([AllowNull()][object] $ExistingText, [Parameter(Mandatory)][string[]] $Entries)
  $created = [ordered]@{ file = ($null -eq $ExistingText); permissions = $false; deny = $false; parentSettingsBehavior = $false }
  $settings = if ($null -eq $ExistingText) { [ordered]@{} } else { ConvertFrom-ManagedSettingsText $ExistingText }
  if (-not $settings.Contains('permissions')) { $settings['permissions'] = [ordered]@{}; $created.permissions = $true }
  $permissions = $settings['permissions']
  if ($permissions -isnot [System.Collections.IDictionary]) {
    throw 'managed-settings.json has a "permissions" value that is not an object; nothing was changed.'
  }
  if (-not $permissions.Contains('deny')) { $permissions['deny'] = @(); $created.deny = $true }
  $deny = $permissions['deny']
  if ($null -ne $deny -and $deny -isnot [System.Collections.IList]) {
    throw 'managed-settings.json has a "permissions.deny" value that is not a list; nothing was changed.'
  }
  $current = [System.Collections.Generic.List[object]]::new()
  if ($null -ne $deny) { foreach ($item in $deny) { $current.Add($item) } }
  $added = [System.Collections.Generic.List[string]]::new()
  foreach ($entry in ($Entries | Select-Object -Unique)) {
    if (-not $current.Contains($entry)) { $current.Add($entry); $added.Add($entry) }
  }
  $permissions['deny'] = $current.ToArray()
  # Claude Agent SDK 0.3.276 drops an embedding app's managedSettings when a machine managed
  # tier exists, unless that tier sets parentSettingsBehavior "merge" (sdk.d.ts). Add it only
  # if absent; never change an administrator's other choice.
  if (-not $settings.Contains('parentSettingsBehavior')) {
    $settings['parentSettingsBehavior'] = 'merge'
    $created.parentSettingsBehavior = $true
  } elseif ($settings['parentSettingsBehavior'] -ne 'merge') {
    throw ('managed-settings.json sets parentSettingsBehavior to "' + $settings['parentSettingsBehavior'] +
      '". T3 needs "merge" so its own deny rules are not dropped; change it deliberately or pass -SkipMachineManagedSettings. Nothing was changed.')
  }
  $text = ConvertTo-ManagedSettingsText $settings
  # Validate the merged result by parsing it again before anyone writes it.
  [void](ConvertFrom-ManagedSettingsText $text)
  return [pscustomobject]@{ Text = $text; Added = $added.ToArray(); Created = $created }
}

<# Removes only $Added; removes keys only if the merge created them and they are now empty. #>
function Get-ManagedSettingsRemoval {
  param([Parameter(Mandatory)][string] $ExistingText, [string[]] $Added = @(), $Created)
  $settings = ConvertFrom-ManagedSettingsText $ExistingText
  if ($settings.Contains('permissions') -and $settings['permissions'] -is [System.Collections.IDictionary]) {
    $permissions = $settings['permissions']
    if ($permissions.Contains('deny') -and $permissions['deny'] -is [System.Collections.IList]) {
      $kept = @($permissions['deny'] | Where-Object { $Added -notcontains $_ })
      $permissions['deny'] = $kept
      if ($kept.Count -eq 0 -and $null -ne $Created -and $Created.deny) { $permissions.Remove('deny') }
    }
    if ($permissions.Count -eq 0 -and $null -ne $Created -and $Created.permissions) { $settings.Remove('permissions') }
  }
  if ($null -ne $Created -and $Created.Contains('parentSettingsBehavior') -and $Created.parentSettingsBehavior -and
      $settings.Contains('parentSettingsBehavior')) {
    $settings.Remove('parentSettingsBehavior')
  }
  $deleteFile = ($settings.Count -eq 0 -and $null -ne $Created -and $Created.file)
  $text = if ($deleteFile) { $null } else { ConvertTo-ManagedSettingsText $settings }
  if ($null -ne $text) { [void](ConvertFrom-ManagedSettingsText $text) }
  return [pscustomobject]@{ Text = $text; DeleteFile = $deleteFile }
}

<# Writes $Text to $Path via a temp file in the same folder and an atomic replace. #>
function Write-ManagedSettingsAtomically {
  param([Parameter(Mandatory)][string] $Path, [Parameter(Mandatory)][string] $Text)
  $directory = Split-Path -Parent $Path
  if (-not (Test-Path -LiteralPath $directory)) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
  $temp = Join-Path $directory ('.managed-settings.' + [guid]::NewGuid().ToString('N') + '.tmp')
  [IO.File]::WriteAllText($temp, $Text, [Text.UTF8Encoding]::new($false))
  try {
    [void](ConvertFrom-ManagedSettingsText ([IO.File]::ReadAllText($temp)))
    [IO.File]::Move($temp, $Path, $true)
  } finally {
    if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force }
  }
}

function Get-ManagedSettingsBackupPath([string] $Path) {
  return "$Path.t3bak-" + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
}

<#
  Combines the undo record from an earlier run with this run's merge, so "created by us" and
  "added by us" survive reruns (a rerun that finds our entries already there adds nothing,
  but they are still ours to remove).
#>
function Merge-ManagedSettingsRecord {
  param($Previous, [Parameter(Mandatory)][string] $Path, [string[]] $Added = @(), $Created)
  $all = [System.Collections.Generic.List[string]]::new()
  $flags = [ordered]@{ file = $false; permissions = $false; deny = $false; parentSettingsBehavior = $false }
  foreach ($source in @($Previous, [pscustomobject]@{ added = $Added; created = $Created })) {
    if ($null -eq $source) { continue }
    foreach ($entry in @($source.added)) { if ($entry -and -not $all.Contains([string]$entry)) { $all.Add([string]$entry) } }
    if ($null -ne $source.created) {
      foreach ($name in @($flags.Keys)) {
        $value = if ($source.created -is [System.Collections.IDictionary]) { $source.created[$name] } else { $source.created.PSObject.Properties[$name]?.Value }
        if ($value) { $flags[$name] = $true }
      }
    }
  }
  return [ordered]@{ path = $Path; added = $all.ToArray(); created = $flags }
}

<#
  verify-install.ps1: true when the file holds every recorded entry, parentSettingsBehavior is
  "merge", and with our entries taken out it equals the pre-merge backup ($BackupText; $null
  when the installer created the file).
#>
function Test-ManagedSettingsUnchanged {
  param([Parameter(Mandatory)][string] $CurrentText, [AllowNull()][object] $BackupText, [string[]] $Added = @(), $Created)
  $current = ConvertFrom-ManagedSettingsText $CurrentText
  $deny = @()
  if ($current.Contains('permissions') -and $current['permissions'] -is [System.Collections.IDictionary] -and $current['permissions'].Contains('deny')) {
    $deny = @($current['permissions']['deny'])
  }
  $missing = @($Added | Where-Object { $deny -notcontains $_ })
  if ($missing.Count -gt 0) { return [pscustomobject]@{ Ok = $false; Reason = "missing deny entries: $($missing -join ', ')" } }
  if ($current['parentSettingsBehavior'] -ne 'merge') { return [pscustomobject]@{ Ok = $false; Reason = 'parentSettingsBehavior is not "merge"' } }
  $removal = Get-ManagedSettingsRemoval -ExistingText $CurrentText -Added $Added -Created $Created
  if ($null -eq $BackupText) {
    if ($removal.DeleteFile) { return [pscustomobject]@{ Ok = $true; Reason = '' } }
    return [pscustomobject]@{ Ok = $false; Reason = 'the file has settings this installer did not add (no backup to compare)' }
  }
  $canonical = { param($text) (ConvertFrom-ManagedSettingsText $text) | ConvertTo-Json -Depth 100 -Compress }
  $before = & $canonical $BackupText
  $after = if ($removal.DeleteFile) { '{}' } else { & $canonical $removal.Text }
  if ($before -ne $after) { return [pscustomobject]@{ Ok = $false; Reason = 'other settings differ from the pre-install backup' } }
  return [pscustomobject]@{ Ok = $true; Reason = '' }
}

<#
  The machine managed tier may hold only keys on this ALLOWLIST: T3's own entries and settings
  that can only restrict Claude. Anything else (allow or ask rules, modes, env, helpers that
  run programs, MCP server switches, keys this module does not know) is reported, and the
  installer refuses and verify-install.ps1 fails until an administrator removes it.
  Pure; $ExistingText = $null means there is no file.
#>
$script:AllowedManagedKeys = @{
  '$schema' = 'documentation only'
  'parentSettingsBehavior' = 'must be "merge" (checked separately)'
  'disableAllHooks' = 'only true restricts'
  'allowManagedHooksOnly' = 'restricts hooks to this tier'
  'allowManagedPermissionRulesOnly' = 'restricts permission rules to this tier'
  'allowManagedMcpServersOnly' = 'restricts MCP servers to this tier'
  'deniedMcpServers' = 'deny list'
  'disableBypassPermissionsMode' = 'restricts modes'
  'disableAutoMode' = 'restricts modes'
  'cleanupPeriodDays' = 'local transcript retention'
}
$script:AllowedManagedPermissionKeys = @('deny', 'disableBypassPermissionsMode', 'disableAutoMode')
function Get-ManagedSettingsLooseners {
  param([AllowNull()][object] $ExistingText)
  if ($null -eq $ExistingText) { return @() }
  $settings = ConvertFrom-ManagedSettingsText ([string]$ExistingText)
  $found = [System.Collections.Generic.List[string]]::new()
  foreach ($key in @($settings.Keys)) {
    if ($key -eq 'permissions') {
      if ($settings['permissions'] -isnot [System.Collections.IDictionary]) { $found.Add('permissions'); continue }
      foreach ($inner in @($settings['permissions'].Keys)) {
        if ($script:AllowedManagedPermissionKeys -notcontains $inner) { $found.Add("permissions.$inner") }
      }
    } elseif ($key -eq 'disableAllHooks' -and -not ($settings[$key] -is [bool] -and $settings[$key])) {
      $found.Add('disableAllHooks (not true)')
    } elseif (-not $script:AllowedManagedKeys.ContainsKey($key)) {
      $found.Add($key)
    }
  }
  return $found.ToArray()
}

<#
  The same allowlist for a registry policy key (HKLM or HKCU \SOFTWARE\Policies\ClaudeCode):
  a value whose data is a JSON object is checked as a settings file; any other value is
  checked by its name. $Values: name -> data. Pure.
#>
function Get-RegistryPolicyLooseners {
  param([Parameter(Mandatory)][System.Collections.IDictionary] $Values)
  $found = [System.Collections.Generic.List[string]]::new()
  foreach ($name in @($Values.Keys)) {
    $data = $Values[$name]
    $text = [string]$data
    $parsed = $null
    if ($text.TrimStart().StartsWith('{')) { try { $parsed = $text | ConvertFrom-Json -AsHashtable -ErrorAction Stop } catch { $parsed = $null } }
    if ($parsed -is [System.Collections.IDictionary]) {
      foreach ($item in (Get-ManagedSettingsLooseners $text)) { $found.Add("$name/$item") }
    } else {
      $single = @{ $name = $data } | ConvertTo-Json -Depth 5
      foreach ($item in (Get-ManagedSettingsLooseners $single)) { $found.Add($item) }
    }
  }
  return $found.ToArray()
}

<#
  Every Claude Code policy source on this machine checked against the allowlist: the machine
  file, every managed-settings.d\*.json drop-in beside it, and the registry policy keys
  (HKLM, the administrator's HKCU, and the agent account's HKCU, whose hive the caller loads).
  Returns "source: key" strings; empty means nothing loosens the lock. Reads only.
#>
function Get-ClaudePolicySourceLooseners {
  param([Parameter(Mandatory)][string] $ManagedSettingsPath, [string] $AgentHiveRoot)
  $found = [System.Collections.Generic.List[string]]::new()
  if (Test-Path -LiteralPath $ManagedSettingsPath) {
    foreach ($item in (Get-ManagedSettingsLooseners ([IO.File]::ReadAllText($ManagedSettingsPath)))) { $found.Add("${ManagedSettingsPath}: $item") }
  }
  $dropIns = Join-Path (Split-Path -Parent $ManagedSettingsPath) 'managed-settings.d'
  if (Test-Path -LiteralPath $dropIns) {
    foreach ($file in Get-ChildItem -LiteralPath $dropIns -Force) {
      if ($file.PSIsContainer -or $file.Extension -ne '.json') { $found.Add("$($file.FullName): unexpected entry"); continue }
      try { $items = Get-ManagedSettingsLooseners ([IO.File]::ReadAllText($file.FullName)) } catch { $items = @('not valid JSON') }
      foreach ($item in $items) { $found.Add("$($file.FullName): $item") }
    }
  }
  $keys = @('HKLM:\SOFTWARE\Policies\ClaudeCode', 'HKCU:\SOFTWARE\Policies\ClaudeCode')
  if ($AgentHiveRoot) { $keys += "$AgentHiveRoot\SOFTWARE\Policies\ClaudeCode" }
  foreach ($key in $keys) {
    if (-not (Test-Path -LiteralPath $key)) { continue }
    $item = Get-Item -LiteralPath $key
    $values = [ordered]@{}
    foreach ($name in $item.Property) { $values[$name] = $item.GetValue($name) }
    foreach ($entry in (Get-RegistryPolicyLooseners -Values $values)) { $found.Add("${key}: $entry") }
    foreach ($sub in @(Get-ChildItem -LiteralPath $key -ErrorAction SilentlyContinue)) { $found.Add("${key}: subkey $($sub.PSChildName)") }
  }
  return $found.ToArray()
}

Export-ModuleMember -Function Get-ClaudePolicySourceLooseners, Get-RegistryPolicyLooseners, Get-ManagedSettingsLooseners, Merge-ManagedSettingsRecord, Test-ManagedSettingsUnchanged, Get-ManagedSettingsMerge, Get-ManagedSettingsRemoval, Write-ManagedSettingsAtomically, Get-ManagedSettingsBackupPath, ConvertFrom-ManagedSettingsText
