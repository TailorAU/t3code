# Lock-down policy

## T3 Code has no managed-policy file

T3 Code v0.1.6 reads no admin or machine policy of its own: there is no policy file,
registry key or "locked" setting in upstream `apps/server`. Its settings live in a
user-writable `settings.json` under the T3 home (`~/.t3/userdata/settings.json` by
default) that any client with `settings:write` can change, and its server options come
from `T3CODE_*` environment variables and CLI flags. Upstream's default runtime mode is
**Full access**.

This fork therefore puts the parts that must always win into the build, and uses
configuration only for the rest. The policy always wins over user settings.

| Requirement | How it is enforced | Where |
| --- | --- | --- |
| Most permissive mode capped at Supervised | Compile-time ceiling `TAILOR_MAX_RUNTIME_MODE = "approval-required"`, applied to every command, launch, settings read, provider turn and MCP caller; Claude's `acceptEdits`, `auto` and `bypassPermissions` all become `default` | Build (cannot be configured) |
| Default mode Supervised | `DEFAULT_RUNTIME_MODE = "approval-required"`; the connector also always sends it | Build |
| Repository and user Claude settings, hooks and `.mcp.json` ignored | Every Claude query, the probe and `claude -p`: no setting sources, strict MCP, compiled deny rules in both `managedSettings` and the flag-tier settings, permission mode capped whatever the launch arguments say; `claude -p` runs in an empty temporary folder | Build |
| Repository git hooks and config-driven commands off | Every git command T3 runs: no global or system config (`GIT_CONFIG_GLOBAL` = an empty admin-owned file, `GIT_CONFIG_NOSYSTEM=1`), `core.hooksPath` = the empty admin-owned `git-hooks\`, `safe.bareRepository=explicit`, `core.fsmonitor=false`, `protocol.ext.allow=never`, `protocol.file.allow=user`, no credential helper, `core.sshCommand=ssh`, no signing, `--no-ext-diff --no-textconv`; edits to `.git/**`, `~/.gitconfig`, `~/.config/git/**`, `.gitattributes`, `.gitmodules`, `.githooks` and `.husky` denied | Build |
| Projects and worktrees stay in their roots | Projects only inside the workspace roots; worktrees only inside their project or T3's worktree folder; real paths compared | Build reads the admin-only file |
| Policy Claude home and binary required | With `%ProgramData%\T3CodePolicy\t3-policy.json` present, a Claude query refuses to start unless the instance uses the recorded Claude home and binary; an unreadable policy also refuses | Build reads the admin-only file |
| No standing grants | "Accept for session" approves one call only | Build |
| Agent kept out of T3's own state | Compiled deny rules for `~/.t3/**` and `T3CODE_HOME` (Claude file tools); Bash needs an approval per call | Build; stronger option: a separate account (SECURITY-REVIEW.md, T3-21) |
| No web tools | `WebSearch` and `WebFetch` always disallowed | Build |
| Local browser client only; no Connect, pairing, Tailscale, LAN | `T3CODE_HOST=127.0.0.1`, `T3CODE_LAN=false`, `T3CODE_TAILSCALE_SERVE=false`, relay variables unset; builds refuse Clerk and relay values; firewall blocks all non-loopback traffic to and from `t3.exe` | Firewall, build guard, environment |
| Browser egress | Google favicon service and Open VSX off; web app CSP; agent-made HTML pages get `default-src 'none'` with `connect-src 'none'` and a sandbox | Build |
| Telemetry off | Fork default off; `T3CODE_OTEL_SDK_DISABLED=true`; Claude instance `DISABLE_TELEMETRY`, `DISABLE_ERROR_REPORTING`, `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC`; firewall | Build, environment, firewall |
| Updates off | `enableProviderUpdateChecks=false`; connector token lacks `environment:maintain`; firewall blocks GitHub and npm for `t3.exe`; Claude `DISABLE_AUTOUPDATER=1`. `T3CODE_DISABLE_AUTO_UPDATE` affects only the desktop app | Settings, scope, firewall (weaker than a switch) |
| Proxy variables unset for `t3 serve` | `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`, `NODE_OPTIONS` must be unset; the connector starts it with an explicit environment | Connector |
| Claude only | The build contains the Claude driver only (`TAILOR_CLAUDE_ONLY`) | Build |
| Instance settings cannot loosen the policy | With the policy installed, the driver takes the Claude binary and home from `t3-policy.json`, ignores launch arguments and `--settings`, and keeps only allowlisted instance variables | Build reads the admin-only file |
| Connector reaches only its contract | `tailor:connector` scope: the five contract RPCs and five dispatch commands, nothing else | Build |


## The machine-wide Claude file

The installer also changes `C:\Program Files\ClaudeCode\managed-settings.json`. **That file is
Claude Code's administrator tier and affects every Claude session on this PC**, not only T3's.
The installer therefore only:

- adds deny entries for Claude's file tools on the `T3CodePolicy` folder;
- adds `"parentSettingsBehavior": "merge"` if the key is absent. Without it, Claude Agent SDK
  0.3.276 drops T3's own compiled deny rules (`managedSettings`) whenever a machine tier
  exists. If the key is present with another value the installer refuses and changes nothing;
  T3 also repeats its deny rules in each query's flag settings, so they hold either way.

Every other setting is kept exactly as it was, but the machine tier may hold only keys on an
allowlist (`ManagedSettingsMerge.psm1`): `permissions.deny`, `permissions.disableBypassPermissionsMode`,
`permissions.disableAutoMode`, `parentSettingsBehavior`, `disableAllHooks` (true only),
`allowManagedHooksOnly`, `allowManagedPermissionRulesOnly`, `allowManagedMcpServersOnly`,
`deniedMcpServers`, `disableBypassPermissionsMode`, `disableAutoMode`, `cleanupPeriodDays` and
`$schema`, all of which can only restrict. Anything else makes the installer refuse and the
self-check fail until an administrator removes it. The same allowlist applies to every
`managed-settings.d\*.json` drop-in beside the file and to the `SOFTWARE\Policies\ClaudeCode`
registry keys in HKLM, the administrator's HKCU and `t3agent`'s HKCU.

Anthropic's organisation-wide remote (server-managed) settings are delivered to Claude Code
sessions signed in with a Claude for Teams or Enterprise account. T3's Claude authenticates
with an API key or Bedrock, so to our understanding they do not apply to it; this has not been
verified on a live install, and the Claude home's `remote-settings.json` is unreadable to the
agent either way. It refuses a malformed file, writes the undo
record before the file, backs the old file up, writes atomically, keeps "created by us" across
re-runs, and on uninstall removes only what it added. Pass `-SkipMachineManagedSettings` to
leave the file alone.

## Install prerequisites

T3 runs only binaries an administrator controls. The installer refuses any of these that sits
in a folder a non-administrator can write (a per-user install, Downloads, the Store build), so
put them in place first:

- **PowerShell 7, machine-wide**: the MSI from Microsoft, installed to
  `C:\Program Files\PowerShell\7`. The Microsoft Store build is per user and is refused.
- **A pinned copy of Claude Code** for T3 only, in an admin-owned folder, for example
  `C:\Program Files\T3Code\claude\claude.exe`. From an elevated prompt:

  ```powershell
  $dir = 'C:\Program Files\T3Code\claude'
  New-Item -ItemType Directory -Path $dir -Force | Out-Null      # inherits Program Files' admin-only ACL
  Copy-Item -LiteralPath '<path to the claude.exe you reviewed>' -Destination $dir
  Get-FileHash -LiteralPath "$dir\claude.exe" -Algorithm SHA256   # record it; the installer records it too
  ```

- **Git for Windows** installed machine-wide (for example `C:\Program Files\Git`), version
  2.50.1 or later; pass `-GitExe 'C:\Program Files\Git\cmd\git.exe'`.
- **Node.js**, only if T3 needs it on its PATH: an admin-owned install; pass `-NodeExe`.
- **`t3.exe`** built from this fork, in an admin-owned folder (for example
  `C:\Program Files\T3Code\t3.exe`).

These are **pinned copies used only by T3. They never update themselves.** The operator's
everyday Claude Code in their own user folder is untouched and keeps updating as normal for
their other sessions. To update a pinned binary, deliberately:

```powershell
pwsh -NoProfile -File "$env:ProgramData\T3CodePolicy\installer\install-policy.ps1" -UpdatePinned Claude -From 'D:\reviewed\claude.exe' -ExpectedSha256 <sha256 of the new file>
```

`-UpdatePinned Claude|T3|Node` stops every task, removes the verified marker, checks the new
file (plain file, the SHA-256 you give), keeps the current binary as a backup in
`state\pinned-backup\`, writes the new one into the pinned path (CreateNew with a protected
ACL: Administrators/SYSTEM full, Users read and execute), records the new SHA-256 in
`t3-policy.json` and the old and new hashes in `state\pinned-updates.json`, runs the
self-check, and starts T3 only on a full PASS. On any failure T3 stays stopped and it prints
the rollback command (`-UpdatePinned <kind> -From <backup>`). Git is a whole install, not one
file: upgrade the pinned Git in place with its own installer, then run
`-UpdatePinned Git -From 'C:\Program Files\Git\cmd\git.exe'` to verify and record it; to move
Git elsewhere, re-run the install with `-GitExe`.

## First step: the protected copy

The installer only runs from `%ProgramData%\T3CodePolicy\installer`, and refuses if that
folder, its parent or any file in it is writable by anyone but Administrators, SYSTEM or
TrustedInstaller, or contains a link. From an elevated PowerShell 7, in a checkout of the
reviewed commit:

```powershell
$policy = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'T3CodePolicy'
$dest = Join-Path $policy 'installer'
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetAccessRuleProtection($true, $false)
$acl.SetOwner([Security.Principal.SecurityIdentifier]'S-1-5-32-544')
foreach ($sid in 'S-1-5-32-544', 'S-1-5-18') {
  $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]$sid, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
}
foreach ($dir in $policy, $dest) {   # ACL set at creation; refuse anything already there
  if (Test-Path -LiteralPath $dir) { throw "$dir exists: check it is yours and admin-only, or remove it" }
  [void][IO.FileSystemAclExtensions]::Create([IO.DirectoryInfo]::new($dir), $acl)
}
$files = 'install-policy.ps1', 'verify-install.ps1', 't3-policy.template.json', 'ManagedSettingsMerge.psm1', 'ServiceAccounts.psm1'
foreach ($f in $files) { Copy-Item -LiteralPath ".\tailor\policy\$f" -Destination $dest }
# Check the copies, in the protected folder, against the hashes from the reviewed commit.
Get-FileHash -LiteralPath ($files | ForEach-Object { Join-Path $dest $_ }) -Algorithm SHA256 | Format-Table Hash, Path
```

Compare each hash with the reviewed commit's, then run from there, passing the same hashes:

```powershell
pwsh -NoProfile -File "$dest\install-policy.ps1" -WhatIf `
  -ExpectedSha256 'script=<hex>,verify=<hex>,template=<hex>,module=<hex>,accounts=<hex>' `
  -T3Exe 'C:\Program Files\T3Code\t3.exe' -ClaudeExe 'C:\Program Files\T3Code\claude\claude.exe'
```

Always start the scripts with `pwsh -NoProfile -File`: no profile runs elevated, and both
scripts refuse to run otherwise. They also pin `PSModulePath` to PowerShell's own folder and
System32, import the Windows modules they use by full path, and refuse if a command they rely
on is not the real one from its module (a function or alias standing in). Every generated
script pins `PSModulePath` as its first statement.

The script reads each file once, checks its hash, and loads the modules, the template and the
self-check from those bytes (`New-Module -ScriptBlock`), never by reading the paths again. A
re-install, a refresh or `-Uninstall` runs the same way, from the same folder. After an
upgrade, copy the new reviewed files over the old ones the same way.

## Files

| File | Purpose |
| --- | --- |
| `t3-policy.template.json` | Generic policy. No hostnames, paths, accounts or credentials; the installer adds those. |
| `install-policy.ps1` | Run elevated with PowerShell 7.2+ from the protected copy. Idempotent, `-WhatIf` friendly, `-Uninstall` reverses it. |
| `verify-install.ps1` | Read-only self-check; runs at the end of every install and any time after. Writes the verified marker on a full PASS. |
| `ManagedSettingsMerge.psm1` | The machine-wide `managed-settings.json` merge and its check; tests in `tests/`. |
| `ServiceAccounts.psm1` | Accounts, rights, the folder ACL plan, task XML, launchers, token issuer and mover; tests in `tests/`. |
| `provider-config.md` | Model provider as configuration only (API key or Bedrock in Sydney, model pin). |

What the installer writes, all under `%ProgramData%\T3CodePolicy`. Folders get their ACL at
creation; an existing folder is checked (no link, owned by Administrators or SYSTEM, and for
the folders admin code works in, no link anywhere inside) and its ACL reset through an opened
handle, never by path. No folder grants anything to the interactive user, `Users`,
`Authenticated Users` or `Everyone`.

| Path | Who | Contents |
| --- | --- | --- |
| `t3-policy.json` | admins; both accounts read | The template plus an `installed` block (binary paths and hashes, homes, accounts, workspace roots, installer hashes). The server reads this fixed path. |
| `installer\` | admins | The protected copy. |
| `state\` | admins | The undo record and the managed-settings baseline. |
| `service\` | admins; both accounts read | Launchers, the T3 settings seed, the token issuer and mover, and `verified.json` (the marker). |
| `git-hooks\` | admins; `t3agent` read | Empty. `core.hooksPath` for every git command T3 runs. |
| `git-config\` | admins; `t3agent` read | `gitconfig`, empty: `GIT_CONFIG_GLOBAL` for every git command T3 runs. |
| `probe\` | admins; `t3agent` create only | The self-check probe's result, read and deleted by the self-check. |
| `t3-home\` | admins; `t3agent` modify | T3's base dir. On first start the launcher (as `t3agent`) copies the seed into `userdata\settings.json`. No admin code runs here. |
| `claude-home\` | admins; `t3agent` see below | Claude home. `t3agent` may read it, create subfolders, modify `.claude.json` and work inside subfolders, but cannot create or replace files at the root. |
| `connector-drop\` | admins; `t3agent` create only | Where the issuer leaves a new token. `t3agent` can create a file but not list, read or delete. |
| `connector\` | admins; `t3bridge` read | `token`, written by the SYSTEM mover with its ACL set at creation. |
| `bridge\` | admins; `t3bridge` read | The bridge's tailor.au key, placed by an administrator. |
| `workspaces\` | admins; `t3agent` modify | The default project root (see below). |

## Installer parameters

| Parameter | Required | Default | Meaning |
| --- | --- | --- | --- |
| `-ExpectedSha256` | yes (optional with `-EmergencyRevoke`) | none | `script=<hex>,verify=<hex>,template=<hex>,module=<hex>,accounts=<hex>` from the reviewed commit |
| `-T3Exe` | to install | | Full path of the `t3.exe` built from this fork (admin-only folder) |
| `-ClaudeExe` | to install | | Full path of a Claude binary used only by T3's Claude instance, in an admin-only folder (the firewall rule applies to that path) |
| `-ClaudeHomeName` | no | `claude-home` | Folder name of the Claude home under `%ProgramData%\T3CodePolicy` |
| `-AgentAccount` | no | `t3agent` | Local account created to run `t3 serve`, its Claude and the token issuer |
| `-BridgeAccount` | no | `t3bridge` | Local account created to run the bridge and read the connector token |
| `-BridgeExe` | no | none | The bridge executable; registers its task (admin-only folder, hash recorded) |
| `-GitExe` | no | `git` on PATH | The git every T3 git call and the self-check use (admin-only folder, at least 2.50.1, hash recorded) |
| `-NodeExe` | no | none | A node.exe whose folder goes on T3's PATH (admin-only folder) |
| `-BridgeUsesPipeOnly` | with `-BridgeExe` | | Attests the bridge build reaches T3 only through the pipe, with no TCP fallback |
| `-TailorApiHosts` | with `-BridgeExe` | none | tailor.au API host names the bridge may reach (for example api.example.com) |
| `-WorkspaceRoots` | no | none | More project roots besides `workspaces\`; each gets an admins + `t3agent` ACL, and its parent must be admin-only |
| `-ConnectorTokenDays` | no | `7` | Lifetime of each connector token (2 to 30); a new one is issued daily |
| `-RotateConnectorToken` | no | | Revoke every connector session, issue a new token, wait for the result (non-zero exit on failure) |
| `-UpdatePinned` | no | | `Claude`, `T3`, `Node` or `Git`: deliberately update a pinned binary (see Install prerequisites) |
| `-From` | with `-UpdatePinned` | | The new binary (Git: the pinned git.exe after an in-place upgrade); with `-UpdatePinned`, `-ExpectedSha256` is its SHA-256 |
| `-AdoptExistingAccounts` | no | | Upgrades only: adopt existing `t3agent`/`t3bridge` accounts that an older install created, if their description is exactly this installer's and their only group is `Users` |
| `-T3Port` | no | `3773` | Loopback port of `t3 serve` |
| `-AllowedHosts` | no | template `egress.allowedHosts` | Model endpoints the Claude binary may reach |
| `-ExtraAllowedAddresses` | no | none | Provider-published IP ranges (CIDR) to allow in addition to DNS results |
| `-ClaudeEgress` | no | `Resolve` | `Resolve` = allow the DNS addresses of `-AllowedHosts` now; `LoopbackOnly` = loopback only, for an allowlisting proxy |
| `-MachineManagedSettingsPath` | no | `C:\Program Files\ClaudeCode\managed-settings.json` | Claude Code's machine-wide admin tier |
| `-SkipMachineManagedSettings` | no | | Do not touch the machine-wide file |
| `-RuleGroup` | no | `T3 Code egress policy` | Firewall rule group the installer owns and replaces |
| `-Uninstall` | no | | Remove what the installer created (below) |
| `-EmergencyRevoke` | no | | Stop everything, invalidate every token and session, delete the connector token (below) |

## The connector token

No administrator code runs inside the T3 home. The token is issued and rotated with no admin
step:

All tasks are registered with an explicit security descriptor: Administrators and SYSTEM
only, with `TASK_DONT_ADD_PRINCIPAL_ACE` so Task Scheduler does not add read access for the
run-as account; nobody else can read, run, change or stop them. The self-check also requires
each task's last result to be success (or running, not yet run, or stopped by the installer).

1. `\T3CodePolicy\T3 token issuer` runs as `t3agent` daily (and once after install). It claims
   `connector-drop\token` (create only), issues a `tailor:connector` token with T3's own CLI
   against the T3 home (retrying once), writes it there, and revokes every connector session
   but the new one and the one before it, which the bridge still holds until the mover runs.
   `-RotateConnectorToken` runs the same script through `T3 token rotate now` with
   `-RevokeAllPrevious`: every previous connector session is revoked first, then a new token is
   issued; if an unmoved token blocks the drop folder it fails loudly, and the installer waits
   for the result and exits non-zero on a failure. The token is
   never printed.
2. `\T3CodePolicy\T3 token mover` runs as SYSTEM every ten minutes, from fixed code in
   `service\`. It deletes anything else in the drop folder, then takes the drop file only if
   it is a plain file with one link, owned by `t3agent`, holding one printable token (read
   from the open handle, at most 4096 bytes); writes `connector\token.new` with its ACL
   (admins, `t3bridge` read) set at creation; renames it over `connector\token`; deletes the
   drop file. It never parses or runs anything `t3agent` wrote.

A token lives `-ConnectorTokenDays` (default 7) and is replaced daily, so the bridge always
holds one of the two valid tokens.

## Emergency revoke

If anything looks wrong (a token may have leaked, the self-check fails unexpectedly, the bridge
behaves oddly), from an elevated PowerShell 7:

```powershell
pwsh -NoProfile -File "$env:ProgramData\T3CodePolicy\installer\install-policy.ps1" -EmergencyRevoke
```

It runs from the protected copy under the same rules (it refuses a writable or changed copy;
without `-ExpectedSha256` it checks the files against the hashes recorded at install) and:

1. removes the verified marker, then disables and stops the T3 server, bridge, token issuer
   and token mover tasks, and stops every process running as `t3agent` or `t3bridge`;
2. runs the on-demand task `T3 key rotation` as `t3agent`: after checking `t3.exe` against
   its installed hash, T3's own `t3 auth rotate-signing-keys` writes new random values for
   every signing key (`server-signing-key`, `mcp-oauth-signing-key`, `guest-share-signing-key`,
   `asset-access-signing-key`) and revokes every session. Every bearer token, browser session,
   websocket ticket, MCP token and share link issued before fails its signature check. No
   administrator code touches the T3 home;
3. deletes `connector\token` and everything in `connector-drop\`;
4. records the time in `state\revoke-log.json`, leaves every task disabled and the marker
   gone, and prints each step it took and its outcome, never a secret. If the key rotation
   failed it says so and exits non-zero: run it again.

Nothing starts until you run the install again (from the protected copy, with
`-ExpectedSha256`). That re-enables the tasks, verifies (the self-check fails unless T3's
signing key was written after the last revoke's start time, which is recorded before the keys
rotate), and only then starts T3 and issues a fresh connector token. Uninstall also rotates
the keys first and then deletes the T3 home with them.

**What revoke covers.** It invalidates leaked T3 credentials: every bearer token, browser
session, websocket ticket, MCP token, share link and pairing link, and stops everything
until a verified reinstall. It does **not** recover a compromised `t3agent` (the agent
account, or anything that ran as it, could have changed the T3 home or the workspaces): for
that, `-Uninstall`, wipe the workspaces you do not trust, and install fresh. It does not
rotate credentials held outside T3; rotate these by hand:

- the bridge's tailor.au key (`bridge\tailor-api-key`), at tailor.au;
- the model credential on the Claude provider instance (API key, or the Bedrock credential),
  at the provider;
- any repository credential you gave `t3agent`.

## T3's PATH and programs

The T3 launcher sets the only PATH T3 and its children get: System32, the Windows folder,
`System32\Wbem`, and the folders of PowerShell 7, the policy's git, Claude, `t3.exe` and
`-NodeExe` (each must be admin-only; WindowsApps is refused). While the policy is present the
server never re-reads PATH from the user environment or a PowerShell profile. On Windows every
bare program name is resolved from PATH's absolute entries only; a name found nowhere is
refused and nothing is spawned (there is no fallback path). A `shell: true` launch runs only
if it starts with an existing absolute program path. Claude may not edit the folders that
could reach t3agent's PATH or its shell start (`%APPDATA%\npm`, pnpm, WindowsApps,
`~\.local\bin`, scoop, volta, bun, and the PowerShell profile folders).

## Getting code in and out

While the policy is installed T3 refuses a project outside the workspace roots
(`workspaces\` and any `-WorkspaceRoots`) or T3's own managed folders in the T3 home, and
refuses a thread worktree outside its project or T3's worktree folder. Paths are compared
after resolving junctions and links, case-insensitively; nothing else under `T3CodePolicy`
is allowed.

- **In.** Clone through T3 (the clone runs as `t3agent`, into a workspace root), or as an
  administrator copy a tree into `workspaces\<name>` with `Copy-Item` (not `robocopy /SEC`
  or anything that copies ACLs): it inherits the folder's ACL. `-WorkspaceRoots` refuses a
  folder that exists and is not empty, because its children would keep their old ACLs; give a
  new or empty folder and copy code in afterwards. The self-check walks every workspace tree
  and fails on any entry for anyone but Administrators, SYSTEM and `t3agent`.
- **Out.** Push from T3 (each git command is a Supervised approval; `t3agent` needs its own
  repository credential, which is a separate decision and not set up here), or as an
  administrator copy the tree out.
- The operator's own account cannot read `workspaces\`; that is deliberate.

## Self-check and the verified marker

`verify-install.ps1` (elevated, `pwsh -NoProfile -File`, only from the protected copy) reports
PASS or FAIL per check:

- the protected copy's hashes; every folder ACL against the plan; the workspace trees;
- the token readable by `t3bridge` only (recorded: an elevated administrator can read it); the
  bridge key's ACL;
- the accounts: groups read by SID, no group but `Users`, batch logon only, and a diff of all
  user rights against the pre-install export in `state\pre-install.json` that allows only the
  four service-account rights for the two accounts;
- a live probe: the on-demand task `T3 self-check probe` runs as `t3agent` and records its
  privileges, groups and integrity level and tries to read the token and to write the policy
  file, `service\`, the Claude home root, `git-hooks\`, the global git config, `connector\`
  and `installer\`; every attempt must be denied (reading the policy must work);
- every task: account, password logon, LeastPrivilege, exactly one action running the right
  launcher, and a security descriptor that lets only Administrators and SYSTEM change, start
  or stop it;
- firewall profiles and rules; the machine managed tier (our entries, nothing that loosens the
  lock, no `HKLM\SOFTWARE\Policies\ClaudeCode`); binary and service-file hashes;
- git: the installed `git.exe` by full path, at least version 2.50.1, an empty global config,
  and a repository hook that does not run with T3's git settings;
- after an emergency revoke, the signing key is newer than the revoke.

Any FAIL removes the marker and also stops the T3 and bridge tasks. It then prints the checks
a person has to do, with exact prompts and commands: non-elevated access, `runas`, Supervised
enforcement, deny variants (case, 8.3 name, `C:\Users\All Users\...`, `\\?\`), fail-closed
tests (policy file removed, one byte of `claude.exe` changed), hooks and Bash approvals,
projects outside the roots, and egress (DNS, the browser, both CSPs).

On a full PASS it writes `service\verified.json` (admin-owned, the accounts read) with the
SHA-256 of every file the launchers use; on any FAIL it removes it. Each launcher refuses to
start `t3 serve`, the bridge or the issuer unless the marker exists, is admin-owned, is not
writable by its account, and every listed file still matches. The installer removes the
marker and stops the tasks at the start of a run, and starts them only after a PASS.

## Host names versus firewall addresses

Windows Firewall matches addresses, not names, and a Block rule always wins over an Allow
rule, so "allow these hosts, block the rest" cannot be two rules. The installer writes one
Block rule per program whose remote addresses are the complement of the allowed set. It
builds the new rules completely, adds them, and only then removes the previous ones. With
`-ClaudeEgress Resolve` the allowed set is what DNS returned at install time. CDN and AWS
endpoints rotate addresses, so:

- re-run the protected copy to refresh, on a schedule or when a model call fails with a
  connection error;
- prefer provider-published ranges through `-ExtraAllowedAddresses`;
- or use `-ClaudeEgress LoopbackOnly` with a loopback proxy that allowlists by host name,
  set as `HTTPS_PROXY` on the Claude provider instance only (never on `t3 serve`). The
  proxy is not part of this PR.


## Service accounts

The installer creates two local standard accounts. Their passwords are random, generated in
memory and handed to Task Scheduler through its COM API (`RegisterTaskDefinition`), never as a
cmdlet parameter, so module and script-block logging cannot record them. Task Scheduler keeps
them as LSA secrets (readable by SYSTEM, as for any "run whether user is logged on or not"
task). They are never written to disk or a log. Local policy grants "log on as a batch job" and
denies interactive, Remote Desktop and network logon. An existing account in any group but
`Users` (Administrators, Remote Desktop Users, Backup Operators, Hyper-V Administrators, Remote
Management Users and so on) makes the installer refuse. Groups are read by SID through ADSI;
any error reading them fails closed. The installer creates the accounts itself and records
their SIDs before anything else; it refuses an account of the same name it did not create.
An install from before this ownership record can adopt its accounts once with
`-AdoptExistingAccounts`, only if each has exactly this installer's description and no group
but `Users`.

Both accounts stay in `BUILTIN\Users`: `Program Files` and `System32` grant read and execute
through `Users`, so without it the accounts could not start PowerShell, `t3` or Claude. Nothing
under `T3CodePolicy` grants `Users` anything.

| Account | Runs | Can reach |
| --- | --- | --- |
| `t3agent` | `t3 serve` and its Claude (`T3 server`, at startup, restarts), the token issuer (`T3 token issuer`, daily) | `t3-home\`, `claude-home\` as above, `workspaces\`, `service\` and `t3-policy.json` (read), `connector-drop\` (create only) |
| `t3bridge` | The T3 bridge, if `-BridgeExe` is given (`T3 bridge`) | `connector\` and `bridge\` (read), `service\` (read) |

## Bridge contract: the bridge authenticates the server

The bridge reaches T3 only through the named pipe `\\.\pipe\t3code-bridge`, never loopback
TCP: while T3 is stopped any account can bind the T3 port, and a PID check before connecting
leaves a gap. The T3 launcher (as `t3agent`) starts the pipe shim `service\bridge-pipe.ps1`
next to `t3 serve`:

- the first instance is created with `FILE_FLAG_FIRST_PIPE_INSTANCE`, so it fails if anyone
  already holds the name; the shim then refuses to run and the launcher logs
  `BRIDGE PIPE REFUSED` loudly;
- its security descriptor: owner `t3agent`; protected DACL with `t3bridge` read/write
  (`0x12019b`), SYSTEM read/write, and `t3agent` (the owner) read/write plus create-instance
  (`0x12019f`, what a further instance needs); nobody else, not `Users`, not the interactive
  user, not Administrators. Only the owner can add instances. The first instance's descriptor is the pipe's: a later
  instance cannot change the owner or the DACL (checked by the self-check probe);
- `PIPE_REJECT_REMOTE_CLIENTS`;
- the next instance is listening before a connected one is handed off, so the name is never
  free while T3 runs;
- each connection is relayed to T3's loopback listener only after the shim checks, on that
  very connection (its full four-tuple: both addresses and ports), that the accepting process
  is the `t3 serve` the launcher started (`t3agent` can see its own processes); the launcher
  restarts the shim if it dies while T3 runs.

The connector token is still required over the pipe: the pipe is defence in depth, not
authentication by itself. The bridge (tailor-app builds it) must, for every connection:

1. open the pipe with `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION` (the server may
   identify the bridge, never act as it);
2. read the pipe's owner through its own handle (`GetSecurityInfo`, `READ_CONTROL`) and require
   it to be `t3agent`'s SID, from `T3_BRIDGE_SERVER_OWNER_SID` (taken from the admin-written
   policy); require `GetNamedPipeServerSessionId` to be 0 (the service session);
3. only then send anything; otherwise close the handle without sending a byte;
4. never fall back to TCP. The bridge launcher gives it no TCP address, and the firewall allows
   it only the tailor.au API hosts.

`Connect-T3BridgePipe` in `ServiceAccounts.psm1` is the reference client (tested). The bridge
task starts only after the installer has seen the pipe up with the planned owner and DACL, read
by a SYSTEM probe task (`T3 pipe probe`) that opens it as SYSTEM, not as its owner.

Until the real bridge client exists and has been reviewed, `-BridgeExe` also requires
`-BridgeUsesPipeOnly`: the operator attests that the bridge build reaches T3 only through the
pipe. **Windows Firewall does not filter loopback traffic**, so a bridge with a TCP fallback
to `127.0.0.1` would bypass the pipe and its owner check entirely.

## Design choice: who can hold the T3 token

- **Threat.** The connector and every Claude lane on this PC run as the operator's account. Any file
  the connector can read, a lane can read too, and could use to drive T3 directly.
- **Decision.** A dedicated `t3bridge` account holds the `tailor:connector` token
  (`connector\token`: Administrators, SYSTEM and `t3bridge` read; not the operator, not Users,
  not `t3agent`). The T3 bridge (the connector's T3 source, coming later in tailor-app) runs as
  `t3bridge`, opens no local listener, reaches T3 only through the bridge pipe (bridge
  contract), and dials out only over HTTPS to the tailor.au API hosts passed as
  `-TailorApiHosts`. Its tailor.au key sits in `bridge\`, also
  `t3bridge`-only.
- **What it relies on.** tailor.au accepts steering commands only from the operator's
  interactive sign-in (plan stage 2), never from an agent key. Until stage 2 ships, the bridge
  executes nothing.
- **Residual.** An administrator on the PC can read everything.

## Uninstall

`-Uninstall` (from the protected copy) first has `t3agent` rotate every signing key (so every
issued token is invalid even before the files go), then stops and removes the tasks and the
`\T3CodePolicy` task folder, stops every process running as either account, and removes the
accounts, their rights and profiles, but only accounts this installer created (their SIDs are
recorded; an account that already existed is never reset or deleted, and the install refuses
to use one). It removes the firewall rules, restores only the `T3CODE_*` machine variables it
changed to their earlier values, and removes only what it added to the machine
managed-settings file. The `*.t3bak-*` backups of that file are kept on purpose; the
`Program Files\ClaudeCode` folder is removed only if the installer created it and it is
empty. It then deletes `service\`, `connector\`, `connector-drop\`, `bridge\`, `git-hooks\`,
`git-config\`, `run\`, `probe\`, `t3-home\`, `claude-home\`, `t3-policy.json`, `state\` and
`installer\` (links are removed, never followed), and finally prints a diff of managed
settings, user rights, tasks, firewall rules and `T3CODE_*` variables against the
pre-install snapshot. Workspaces
hold code, so they are kept, with the deleted accounts' ACL entries removed from the whole
tree; the policy folder is kept only if something is left in it, with its ACL reset to
admins only.

## Not done yet

- **Elevated verification.** Everything that needs an elevated run (accounts, rights, tasks
  through COM, the handle-based ACL reset, the token issuer and mover, the firewall rules, the
  self-check and the marker) has only been parse-checked and unit-tested. The first elevated
  run on a real machine is the test.
- **The bridge's own pipe check.** T3's side of the pipe, the reference client and the
  self-check are here; the bridge (tailor-app) must implement the client contract.
- **The agent and its own shell share `t3agent`.** Claude and the commands it runs are the
  same account as `t3 serve`, so ACLs cannot separate them. Hence the Supervised ceiling
  (SECURITY-REVIEW.md, T3-42).
