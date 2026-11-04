#Requires -Version 7.2
# Tailor fork: fixture tests for the machine-wide managed-settings.json merge.
# Run: pwsh -NoProfile -File tailor/policy/tests/ManagedSettingsMerge.Tests.ps1  (exit 0 = pass)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..' 'ManagedSettingsMerge.psm1') -Force

$failures = [System.Collections.Generic.List[string]]::new()
function Assert-True([bool] $condition, [string] $message) { if (-not $condition) { $failures.Add($message) } }
function Same-Json([string] $a, [string] $b) {
  return (($a | ConvertFrom-Json -AsHashtable -Depth 100 | ConvertTo-Json -Depth 100 -Compress) -eq
    ($b | ConvertFrom-Json -AsHashtable -Depth 100 | ConvertTo-Json -Depth 100 -Compress))
}

$ours = @('Read(//c/ProgramData/T3CodePolicy/**)', 'Edit(//c/ProgramData/T3CodePolicy/**)', 'Read(//c/Users/svc/.t3/**)')
$workRoot = Join-Path ([IO.Path]::GetTempPath()) ('t3-managed-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $workRoot | Out-Null

try {
  # (a) No file: our entries only, everything recorded as created.
  $a = Get-ManagedSettingsMerge -ExistingText $null -Entries $ours
  $aParsed = $a.Text | ConvertFrom-Json -AsHashtable
  Assert-True ($a.Added.Count -eq 3) '(a) adds all three entries'
  Assert-True (@($aParsed.permissions.deny).Count -eq 3) '(a) deny has exactly our entries'
  Assert-True ($a.Created.file -and $a.Created.permissions -and $a.Created.deny) '(a) records what it created'

  # (b) Existing file with other permissions, hooks, env and an unknown key: all survive.
  $original = @'
{
  "permissions": {
    "allow": ["Bash(git status)"],
    "deny": ["Read(./.env)", "Read(//c/Users/svc/.t3/**)"],
    "disableBypassPermissionsMode": "disable"
  },
  "hooks": { "PreToolUse": [{ "matcher": "Bash", "hooks": [{ "type": "command", "command": "audit.cmd" }] }] },
  "env": { "HTTPS_PROXY": "http://proxy.example:8080" },
  "someFutureKey": { "nested": [1, 2, { "x": true }] }
}
'@
  $b = Get-ManagedSettingsMerge -ExistingText $original -Entries $ours
  $bParsed = $b.Text | ConvertFrom-Json -AsHashtable -Depth 100
  Assert-True ($b.Added.Count -eq 2) '(b) adds only the two missing entries'
  Assert-True (@($bParsed.permissions.deny | Where-Object { $_ -eq 'Read(//c/Users/svc/.t3/**)' }).Count -eq 1) '(b) no duplicate of an entry already present'
  Assert-True (@($bParsed.permissions.deny)[0] -eq 'Read(./.env)') '(b) existing deny entries keep their order'
  Assert-True (@($bParsed.permissions.allow)[0] -eq 'Bash(git status)') '(b) allow kept'
  Assert-True ($bParsed.permissions.disableBypassPermissionsMode -eq 'disable') '(b) other permission keys kept'
  Assert-True ($bParsed.hooks.PreToolUse[0].hooks[0].command -eq 'audit.cmd') '(b) hooks kept'
  Assert-True ($bParsed.env.HTTPS_PROXY -eq 'http://proxy.example:8080') '(b) env kept'
  Assert-True ($bParsed.someFutureKey.nested[2].x -eq $true) '(b) unknown keys kept'
  Assert-True (-not ($b.Created.file -or $b.Created.permissions -or $b.Created.deny)) '(b) created no keys it did not need'
  Assert-True ($bParsed.parentSettingsBehavior -eq 'merge' -and $b.Created.parentSettingsBehavior) '(b) adds parentSettingsBehavior merge and records it'

  # parentSettingsBehavior: kept when already "merge", refused when set to anything else.
  $already = Get-ManagedSettingsMerge -ExistingText '{ "parentSettingsBehavior": "merge" }' -Entries $ours
  Assert-True (-not $already.Created.parentSettingsBehavior) 'an existing merge value is not recorded as ours'
  $refusedParent = $false
  try { [void](Get-ManagedSettingsMerge -ExistingText '{ "parentSettingsBehavior": "replace" }' -Entries $ours) } catch { $refusedParent = $true }
  Assert-True $refusedParent 'a different parentSettingsBehavior is refused'

  # (c) Re-install is idempotent.
  $c = Get-ManagedSettingsMerge -ExistingText $b.Text -Entries $ours
  Assert-True ($c.Added.Count -eq 0) '(c) re-install adds nothing'
  Assert-True ($c.Text -eq $b.Text) '(c) re-install leaves the text unchanged'

  # (d) A malformed file is refused and left untouched on disk.
  $malformedPath = Join-Path $workRoot 'managed-settings.json'
  $malformed = '{ "permissions": { "deny": [ "Read(x)" ] '
  [IO.File]::WriteAllText($malformedPath, $malformed)
  $refused = $false
  try { [void](Get-ManagedSettingsMerge -ExistingText ([IO.File]::ReadAllText($malformedPath)) -Entries $ours) } catch { $refused = $true }
  Assert-True $refused '(d) malformed file is refused'
  Assert-True ([IO.File]::ReadAllText($malformedPath) -eq $malformed) '(d) malformed file untouched'
  $refusedShape = $false
  try { [void](Get-ManagedSettingsMerge -ExistingText '{ "permissions": { "deny": "Read(x)" } }' -Entries $ours) } catch { $refusedShape = $true }
  Assert-True $refusedShape '(d) a non-list deny is refused'

  # (e) Uninstall after (b) restores the original semantically, other entries unchanged.
  $e = Get-ManagedSettingsRemoval -ExistingText $b.Text -Added $b.Added -Created $b.Created
  Assert-True (-not $e.DeleteFile) '(e) keeps a file we did not create'
  Assert-True (Same-Json $e.Text $original) '(e) uninstall restores the original content'
  # And uninstall after (a) deletes the file it created.
  $ea = Get-ManagedSettingsRemoval -ExistingText $a.Text -Added $a.Added -Created $a.Created
  Assert-True $ea.DeleteFile '(e) deletes a file it created once it is empty'

  # Atomic write lands the exact text and leaves no temp file.
  $target = Join-Path $workRoot 'out' 'managed-settings.json'
  Write-ManagedSettingsAtomically -Path $target -Text $b.Text
  Assert-True ([IO.File]::ReadAllText($target) -eq $b.Text) 'atomic write lands the text'
  Assert-True (@(Get-ChildItem (Split-Path $target) -Filter '*.tmp' -Force).Count -eq 0) 'atomic write leaves no temp file'
  Assert-True ((Get-ManagedSettingsBackupPath $target) -match '\.t3bak-\d{8}T\d{6}Z$') 'backup name carries a UTC timestamp'
} finally {
  Remove-Item -LiteralPath $workRoot -Recurse -Force -ErrorAction SilentlyContinue
}

# Undo record survives reruns: a rerun that adds nothing keeps what the first run added and created.
$first = Get-ManagedSettingsMerge -ExistingText $null -Entries $ours
$record1 = Merge-ManagedSettingsRecord -Previous $null -Path 'C:\x\managed-settings.json' -Added $first.Added -Created $first.Created
$second = Get-ManagedSettingsMerge -ExistingText $first.Text -Entries $ours
Assert-True ($second.Added.Count -eq 0 -and -not $second.Created.parentSettingsBehavior) 'a rerun adds nothing'
$record2 = Merge-ManagedSettingsRecord -Previous ($record1 | ConvertTo-Json -Depth 5 | ConvertFrom-Json) -Path 'C:\x\managed-settings.json' -Added $second.Added -Created $second.Created
Assert-True (@($record2.added).Count -eq @($ours | Select-Object -Unique).Count) 'the rerun record keeps every entry the first run added'
Assert-True ($record2.created.file -and $record2.created.parentSettingsBehavior) 'and what it created'
$undone = Get-ManagedSettingsRemoval -ExistingText $second.Text -Added @($record2.added) -Created $record2.created
Assert-True $undone.DeleteFile 'uninstall after a rerun still removes a file the installer created'

# Verify: unchanged against the baseline passes; another changed setting or a removed entry fails.
$baselineText = '{ "model": "x", "permissions": { "deny": ["Bash(rm:*)"] } }'
$merged = Get-ManagedSettingsMerge -ExistingText $baselineText -Entries $ours
$ok = Test-ManagedSettingsUnchanged -CurrentText $merged.Text -BackupText $baselineText -Added $merged.Added -Created $merged.Created
Assert-True $ok.Ok "verify passes on an untouched merge ($($ok.Reason))"
$tampered = $merged.Text.Replace('"x"', '"y"')
Assert-True (-not (Test-ManagedSettingsUnchanged -CurrentText $tampered -BackupText $baselineText -Added $merged.Added -Created $merged.Created).Ok) 'verify fails when another setting changed'
$dropped = ($merged.Text | ConvertFrom-Json -AsHashtable)
$dropped.permissions.deny = @($dropped.permissions.deny | Where-Object { $_ -ne $merged.Added[0] })
Assert-True (-not (Test-ManagedSettingsUnchanged -CurrentText ($dropped | ConvertTo-Json -Depth 10) -BackupText $baselineText -Added $merged.Added -Created $merged.Created).Ok) 'verify fails when one of our entries is gone'
$noMerge = ($merged.Text | ConvertFrom-Json -AsHashtable); $noMerge.parentSettingsBehavior = 'replace'
Assert-True (-not (Test-ManagedSettingsUnchanged -CurrentText ($noMerge | ConvertTo-Json -Depth 10) -BackupText $baselineText -Added $merged.Added -Created $merged.Created).Ok) 'verify fails without parentSettingsBehavior merge'
$fresh = Get-ManagedSettingsMerge -ExistingText $null -Entries $ours
Assert-True (Test-ManagedSettingsUnchanged -CurrentText $fresh.Text -BackupText $null -Added $fresh.Added -Created $fresh.Created).Ok 'verify passes on a file the installer created'

# Machine-tier settings that loosen the lock are found.
Assert-True (@(Get-ManagedSettingsLooseners $null).Count -eq 0) 'no file: nothing to report'
Assert-True (@(Get-ManagedSettingsLooseners '{ "permissions": { "deny": ["Bash"] }, "model": "x" }').Count -eq 0) 'deny rules and other keys are fine'
$loose = @(Get-ManagedSettingsLooseners '{ "permissions": { "allow": ["Bash"], "ask": ["Edit"], "defaultMode": "acceptEdits" }, "env": { "A": "1" }, "defaultMode": "x", "hooks": {} }')
foreach ($k in 'permissions.allow', 'permissions.ask', 'permissions.defaultMode', 'env', 'defaultMode', 'hooks') { Assert-True ($loose -contains $k) "$k is reported" }
$helpers = @(Get-ManagedSettingsLooseners '{ "otelHeadersHelper": "x", "awsAuthRefresh": "x", "awsCredentialExport": "x", "gcpAuthRefresh": "x", "enableAllProjectMcpServers": true, "enabledMcpjsonServers": ["a"] }')
Assert-True ($helpers.Count -eq 6) 'credential helpers and project MCP server switches are reported'

if ($failures.Count -gt 0) {
  $failures | ForEach-Object { Write-Host "FAIL: $_" }
  exit 1
}
Write-Host 'ManagedSettingsMerge: all checks passed.'
exit 0
