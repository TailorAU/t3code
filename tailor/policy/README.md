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
| Most permissive mode capped at Auto-accept edits | Compile-time ceiling `TAILOR_MAX_RUNTIME_MODE`, applied to every command, launch, settings read, provider turn and MCP caller | Build (cannot be configured) |
| Default mode Supervised | `DEFAULT_RUNTIME_MODE = "approval-required"`; the connector also always sends it | Build |
| Repository and user Claude settings, hooks and `.mcp.json` ignored | Every Claude query: `settingSources: []`, `strictMcpConfig: true`, compiled deny rules (`managedSettings`), permission mode capped whatever the launch arguments say | Build |
| Policy Claude home and binary required | With `%ProgramData%\T3CodePolicy\t3-policy.json` present, a Claude query refuses to start unless the instance uses the recorded Claude home and binary; an unreadable policy also refuses | Build reads the admin-only file |
| No standing grants | "Accept for session" approves one call only | Build |
| Agent kept out of T3's own state | Compiled deny rules for `~/.t3/**` and `T3CODE_HOME` (Claude file tools); Bash needs an approval per call | Build; stronger option: a separate account (SECURITY-REVIEW.md, T3-21) |
| No web tools | `WebSearch` and `WebFetch` always disallowed | Build |
| Local browser client only; no Connect, pairing, Tailscale, LAN | `T3CODE_HOST=127.0.0.1`, `T3CODE_LAN=false`, `T3CODE_TAILSCALE_SERVE=false`, relay variables unset; builds refuse Clerk and relay values; firewall blocks all non-loopback traffic to and from `t3.exe` | Firewall, build guard, environment |
| Browser egress | Google favicon service and Open VSX off; web app CSP `connect-src 'self'; img-src 'self' data: blob:` | Build |
| Telemetry off | Fork default off; `T3CODE_OTEL_SDK_DISABLED=true`; Claude instance `DISABLE_TELEMETRY`, `DISABLE_ERROR_REPORTING`, `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC`; firewall | Build, environment, firewall |
| Updates off | `enableProviderUpdateChecks=false`; connector token lacks `environment:maintain`; firewall blocks GitHub and npm for `t3.exe`; Claude `DISABLE_AUTOUPDATER=1`. `T3CODE_DISABLE_AUTO_UPDATE` affects only the desktop app | Settings, scope, firewall (weaker than a switch) |
| Proxy variables unset for `t3 serve` | `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`, `NODE_OPTIONS` must be unset; the connector starts it with an explicit environment | Connector |
| Claude only | The build contains the Claude driver only (`TAILOR_CLAUDE_ONLY`) | Build |
| Instance settings cannot loosen the policy | With the policy installed, the driver takes the Claude binary and home from `t3-policy.json`, ignores launch arguments and `--settings`, and keeps only allowlisted instance variables | Build reads the admin-only file |
| Connector reaches only its contract | `tailor:connector` scope: the five contract RPCs and five dispatch commands, nothing else | Build |

## The machine-wide Claude file

The installer also adds deny entries to `C:\Program Files\ClaudeCode\managed-settings.json`.
**That file is Claude Code's administrator tier and affects every Claude session on this PC**,
not only T3's. The installer therefore only adds entries that deny Claude's file tools the T3
home and the `T3CodePolicy` folder, keeps every other setting in the file exactly as it was,
refuses a malformed file, backs the old file up, and on uninstall removes only the entries it
added. Pass `-SkipMachineManagedSettings` to leave the file alone.

## Files

| File | Purpose |
| --- | --- |
| `t3-policy.template.json` | Generic policy. No hostnames, paths, accounts or credentials; the installer adds those. |
| `install-policy.ps1` | Run elevated with PowerShell 7.2+, per machine. Idempotent, `-WhatIf` friendly, `-Uninstall` reverses it. |
| `ManagedSettingsMerge.psm1` | The machine-wide `managed-settings.json` merge; tests in `tests/`. |
| `provider-config.md` | Model provider as configuration only (API key or Bedrock in Sydney, model pin). |

What the installer writes, all under `%ProgramData%\T3CodePolicy` (folders created with a
protected ACL; existing reparse points or folders not owned by Administrators or SYSTEM are
refused):

| Path | Contents |
| --- | --- |
| `t3-policy.json` | The template plus an `installed` block (T3 and Claude binary paths, Claude home, run-as account, installer hashes). The server reads this fixed path. |
| `t3-settings.seed.json` | T3 settings for the connector to apply (Supervised default, update checks off, other drivers off, the Claude instance pointing at the policy home and binary). |
| `claude-home\` | The Claude instance home. Admin-only at the root; the run-as account may read it, create subfolders, modify `.claude.json` and work inside subfolders, but cannot create or replace files at the root (`settings.json`, `remote-settings.json`). |
| `installer\` | A protected copy of the installer and template for later refreshes. |

## Installer parameters

| Parameter | Required | Default | Meaning |
| --- | --- | --- | --- |
| `-T3Exe` | yes | | Full path of the `t3.exe` built from this fork that the connector starts |
| `-ClaudeExe` | yes | | Full path of a Claude binary used only by T3's Claude instance, in an admin-only folder (the firewall rule applies to that path) |
| `-ExpectedSha256` | yes, except the protected copy | none | `script=<hex>,template=<hex>,module=<hex>` from the reviewed commit; the installer refuses to run without it or on a mismatch |
| `-ClaudeHomeName` | no | `claude-home` | Folder name of the Claude home under `%ProgramData%\T3CodePolicy` |
| `-RunAsUser` | no | the account running the installer | Account that runs `t3 serve`; gets Modify on the Claude home only |
| `-AllowedHosts` | no | template `egress.allowedHosts` | Model endpoints the Claude binary may reach; add a gateway host if one is used |
| `-ExtraAllowedAddresses` | no | none | Provider-published IP ranges (CIDR) to allow in addition to DNS results |
| `-ClaudeEgress` | no | `Resolve` | `Resolve` = allow the DNS addresses of `-AllowedHosts` now; `LoopbackOnly` = allow loopback only, for use with an allowlisting proxy |
| `-T3Home` | no | `<run-as profile>\.t3` | The T3 base dir, denied to Claude in the machine-wide file |
| `-MachineManagedSettingsPath` | no | `C:\Program Files\ClaudeCode\managed-settings.json` | Claude Code's machine-wide admin tier |
| `-SkipMachineManagedSettings` | no | | Do not touch the machine-wide file |
| `-RuleGroup` | no | `T3 Code egress policy` | Firewall rule group the installer owns and replaces |
| `-Uninstall` | no | | Remove the rules, machine variables and installed policy |

Get the hashes from the reviewed commit, on any machine:

```powershell
(Get-FileHash .\tailor\policy\install-policy.ps1 -Algorithm SHA256).Hash.ToLower()
(Get-FileHash .\tailor\policy\t3-policy.template.json -Algorithm SHA256).Hash.ToLower()
(Get-FileHash .\tailor\policy\ManagedSettingsMerge.psm1 -Algorithm SHA256).Hash.ToLower()
```

Example (preview only):

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\tailor\policy\install-policy.ps1 `
  -T3Exe 'C:\Program Files\T3Code\t3.exe' `
  -ClaudeExe 'C:\Program Files\T3Code\claude\claude.exe' `
  -ExpectedSha256 'script=<hex>,template=<hex>,module=<hex>' -WhatIf
```

Later refreshes run the protected copy:
`%ProgramData%\T3CodePolicy\installer\install-policy.ps1` with the same parameters.

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

## Not done yet

- **Dedicated service account.** T3 and its Claude still run as the interactive user. Moving
  them to a password-less local service account (T3 home in that profile, so the user's shell
  cannot mint tokens or edit T3 settings) needs a service wrapper for `t3 serve`; next stage.
- **Connector token issuance.** Issue `--scope tailor:connector` by hand for now; the installer
  will write it into an admin-protected file readable only by the connector's account once the
  service account exists.
