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
| Repository git hooks and config-driven commands off | Every git command T3 runs: `core.hooksPath` = the empty admin-owned `git-hooks\`, `safe.bareRepository=explicit`, `core.fsmonitor=false`, `protocol.ext.allow=never`, `--no-ext-diff --no-textconv`; edits to `.git/hooks`, `.git/config`, `.githooks` and `.husky` denied | Build |
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

Every other setting is kept exactly as it was. It refuses a malformed file, writes the undo
record before the file, backs the old file up, writes atomically, keeps "created by us" across
re-runs, and on uninstall removes only what it added. Pass `-SkipMachineManagedSettings` to
leave the file alone.

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
& "$dest\install-policy.ps1" -WhatIf `
  -ExpectedSha256 'script=<hex>,verify=<hex>,template=<hex>,module=<hex>,accounts=<hex>' `
  -T3Exe 'C:\Program Files\T3Code\t3.exe' -ClaudeExe 'C:\Program Files\T3Code\claude\claude.exe'
```

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
| `t3-home\` | admins; `t3agent` modify | T3's base dir. On first start the launcher (as `t3agent`) copies the seed into `userdata\settings.json`. No admin code runs here. |
| `claude-home\` | admins; `t3agent` see below | Claude home. `t3agent` may read it, create subfolders, modify `.claude.json` and work inside subfolders, but cannot create or replace files at the root. |
| `connector-drop\` | admins; `t3agent` create only | Where the issuer leaves a new token. `t3agent` can create a file but not list, read or delete. |
| `connector\` | admins; `t3bridge` read | `token`, written by the SYSTEM mover with its ACL set at creation. |
| `bridge\` | admins; `t3bridge` read | The bridge's tailor.au key, placed by an administrator. |
| `workspaces\` | admins; `t3agent` modify | The default project root (see below). |

## Installer parameters

| Parameter | Required | Default | Meaning |
| --- | --- | --- | --- |
| `-ExpectedSha256` | yes | none | `script=<hex>,verify=<hex>,template=<hex>,module=<hex>,accounts=<hex>` from the reviewed commit |
| `-T3Exe` | to install | | Full path of the `t3.exe` built from this fork (admin-only folder) |
| `-ClaudeExe` | to install | | Full path of a Claude binary used only by T3's Claude instance, in an admin-only folder (the firewall rule applies to that path) |
| `-ClaudeHomeName` | no | `claude-home` | Folder name of the Claude home under `%ProgramData%\T3CodePolicy` |
| `-AgentAccount` | no | `t3agent` | Local account created to run `t3 serve`, its Claude and the token issuer |
| `-BridgeAccount` | no | `t3bridge` | Local account created to run the bridge and read the connector token |
| `-BridgeExe` | no | none | The bridge executable; registers its task (admin-only folder, hash recorded) |
| `-TailorApiHosts` | with `-BridgeExe` | none | tailor.au API host names the bridge may reach (for example api.example.com) |
| `-WorkspaceRoots` | no | none | More project roots besides `workspaces\`; each gets an admins + `t3agent` ACL, and its parent must be admin-only |
| `-ConnectorTokenDays` | no | `7` | Lifetime of each connector token (2 to 30); a new one is issued daily |
| `-RotateConnectorToken` | no | | Issue a new connector token now |
| `-T3Port` | no | `3773` | Loopback port of `t3 serve` |
| `-AllowedHosts` | no | template `egress.allowedHosts` | Model endpoints the Claude binary may reach |
| `-ExtraAllowedAddresses` | no | none | Provider-published IP ranges (CIDR) to allow in addition to DNS results |
| `-ClaudeEgress` | no | `Resolve` | `Resolve` = allow the DNS addresses of `-AllowedHosts` now; `LoopbackOnly` = loopback only, for an allowlisting proxy |
| `-MachineManagedSettingsPath` | no | `C:\Program Files\ClaudeCode\managed-settings.json` | Claude Code's machine-wide admin tier |
| `-SkipMachineManagedSettings` | no | | Do not touch the machine-wide file |
| `-RuleGroup` | no | `T3 Code egress policy` | Firewall rule group the installer owns and replaces |
| `-Uninstall` | no | | Remove what the installer created (below) |

## The connector token

No administrator code runs inside the T3 home. The token is issued and rotated with no admin
step:

1. `\T3CodePolicy\T3 token issuer` runs as `t3agent` daily (and once after install). It claims
   `connector-drop\token` (create only), issues a `tailor:connector` token with T3's own CLI
   against the T3 home, writes it there, and revokes every connector session but the two
   newest. The token is never printed.
2. `\T3CodePolicy\T3 token mover` runs as SYSTEM every ten minutes, from fixed code in
   `service\`. It takes the drop file only if it is a plain file with one link, owned by
   `t3agent`, holding one printable token; writes `connector\token.new` with its ACL
   (admins, `t3bridge` read) set at creation; renames it over `connector\token`; deletes the
   drop file. It never parses or runs anything `t3agent` wrote.

A token lives `-ConnectorTokenDays` (default 7) and is replaced daily, so the bridge always
holds one of the two valid tokens.

## Getting code in and out

While the policy is installed T3 refuses a project outside the workspace roots
(`workspaces\` and any `-WorkspaceRoots`) or T3's own managed folders in the T3 home, and
refuses a thread worktree outside its project or T3's worktree folder. Paths are compared
after resolving junctions and links, case-insensitively; nothing else under `T3CodePolicy`
is allowed.

- **In.** Clone through T3 (the clone runs as `t3agent`, into a workspace root), or as an
  administrator copy a tree into `workspaces\<name>`: it inherits the folder's ACL.
- **Out.** Push from T3 (each git command is a Supervised approval; `t3agent` needs its own
  repository credential, which is a separate decision and not set up here), or as an
  administrator copy the tree out.
- The operator's own account cannot read `workspaces\`; that is deliberate.

## Self-check and the verified marker

`verify-install.ps1` (elevated, from the protected copy) reports PASS or FAIL per check: the
protected copy's hashes, every folder ACL against the plan, the token readable by `t3bridge`
only, the accounts (no group but `Users`, batch logon only), the tasks (password logon,
LeastPrivilege, the right launcher; the mover as SYSTEM), the firewall profiles and rules,
the machine managed-settings entries against the install-time baseline, the binary and
service-file hashes, and that a repository hook does not run with T3's git settings. It then
prints the checks a person has to do (non-elevated access denied to the token, `runas` refused,
Supervised enforced, projects outside the roots refused, the egress capture).

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
Management Users and so on) makes the installer refuse.

Both accounts stay in `BUILTIN\Users`: `Program Files` and `System32` grant read and execute
through `Users`, so without it the accounts could not start PowerShell, `t3` or Claude. Nothing
under `T3CodePolicy` grants `Users` anything.

| Account | Runs | Can reach |
| --- | --- | --- |
| `t3agent` | `t3 serve` and its Claude (`T3 server`, at startup, restarts), the token issuer (`T3 token issuer`, daily) | `t3-home\`, `claude-home\` as above, `workspaces\`, `service\` and `t3-policy.json` (read), `connector-drop\` (create only) |
| `t3bridge` | The T3 bridge, if `-BridgeExe` is given (`T3 bridge`) | `connector\` and `bridge\` (read), `service\` (read) |

## Design choice: who can hold the T3 token

- **Threat.** The connector and every Claude lane on this PC run as the operator's account. Any file
  the connector can read, a lane can read too, and could use to drive T3 directly.
- **Decision.** A dedicated `t3bridge` account holds the `tailor:connector` token
  (`connector\token`: Administrators, SYSTEM and `t3bridge` read; not the operator, not Users,
  not `t3agent`). The T3 bridge (the connector's T3 source, coming later in tailor-app) runs as
  `t3bridge`, opens no local listener, and only dials out: loopback to T3 and HTTPS to the
  tailor.au API hosts passed as `-TailorApiHosts`. Its tailor.au key sits in `bridge\`, also
  `t3bridge`-only.
- **What it relies on.** tailor.au accepts steering commands only from the operator's
  interactive sign-in (plan stage 2), never from an agent key. Until stage 2 ships, the bridge
  executes nothing.
- **Residual.** An administrator on the PC can read everything.

## Uninstall

`-Uninstall` (from the protected copy) stops and removes the four tasks, stops every process
running as either account, removes the accounts, their rights and profiles, the firewall
rules, and restores only the `T3CODE_*` machine variables it changed to their earlier values.
It removes only what it added to the machine managed-settings file, then deletes `service\`,
`connector\`, `connector-drop\`, `bridge\`, `git-hooks\`, `t3-home\`, `claude-home\`,
`t3-policy.json`, `state\` and `installer\` (links are removed, never followed). Workspaces
hold code, so they are kept, with the deleted accounts' ACL entries removed from the whole
tree; the policy folder is kept only if something is left in it, with its ACL reset to
admins only.

## Not done yet

- **Elevated verification.** Everything that needs an elevated run (accounts, rights, tasks
  through COM, the handle-based ACL reset, the token issuer and mover, the firewall rules, the
  self-check and the marker) has only been parse-checked and unit-tested. The first elevated
  run on a real machine is the test.
- **The agent and its own shell share `t3agent`.** Claude and the commands it runs are the
  same account as `t3 serve`, so ACLs cannot separate them. Hence the Supervised ceiling
  (SECURITY-REVIEW.md, T3-42).
