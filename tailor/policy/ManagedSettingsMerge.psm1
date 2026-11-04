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
  $created = [ordered]@{ file = ($null -eq $ExistingText); permissions = $false; deny = $false }
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

Export-ModuleMember -Function Get-ManagedSettingsMerge, Get-ManagedSettingsRemoval, Write-ManagedSettingsAtomically, Get-ManagedSettingsBackupPath, ConvertFrom-ManagedSettingsText
