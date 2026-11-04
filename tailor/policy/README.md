# Lock-down policy

## T3 Code has no managed-policy file

T3 Code v0.1.6 reads no admin or machine policy of its own: there is no policy file,
registry key or "locked" setting in `apps/server`. Its settings live in a
user-writable `settings.json` under the T3 home (`~/.t3/userdata/settings.json` by
default) that any client with `settings:write` can change, and its server options
come from `T3CODE_*` environment variables and CLI flags. Upstream's default runtime
mode is **Full access** (`DEFAULT_RUNTIME_MODE = "full-access"` in
`packages/contracts/src/providerPolicy.ts`).

The nearest equivalent is built from the four controls T3 does honour, plus the
supervising connector:

| Requirement | How it is enforced | Strength |
| --- | --- | --- |
| Local browser client only; no Connect, pairing, Tailscale, LAN | `T3CODE_HOST=127.0.0.1`, `T3CODE_LAN=false`, `T3CODE_TAILSCALE_SERVE=false`, `T3CODE_RELAY_URL` unset; firewall blocks all non-loopback traffic to and from `t3.exe` | Strong (firewall), environment as a second layer |
| SSH off | No SSH device hosts in settings; `ssh` is never started by the server unless a user adds a device host (needs `settings:write`); firewall blocks `t3.exe`'s own sockets | Medium: an agent's shell is a separate program (see review) |
| Telemetry off | Fork default `T3CODE_TELEMETRY_ENABLED=false` (code change), plus `T3CODE_OTEL_SDK_DISABLED=true`; Claude instance `DISABLE_TELEMETRY`, `DISABLE_ERROR_REPORTING`, `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC`; firewall | Strong |
| Updates off | `enableProviderUpdateChecks=false`, `continueThreadsAfterServerUpdate=false`, `T3CODE_DISABLE_AUTO_UPDATE=1`, Claude `DISABLE_AUTOUPDATER=1`; the connector token lacks `environment:maintain`, so it cannot call `server.updateServer`; firewall blocks GitHub and npm for `t3.exe` | Strong |
| Default mode Supervised (`approval-required`) | Settings seed `defaultRuntimeMode`, and the connector always sends `runtimeMode: "approval-required"` | Medium: the local browser UI can still pick another mode |
| Most permissive mode capped | Claude instance `settings.json` with `disableBypassPermissionsMode` and `disableAutoMode` set to `disable`, read-only to non-admins. T3 reads it (`resolveBypassAvailability` in `ClaudeAdapterV2.ts`) and runs Full access, and (fork patch) Auto, as Supervised; unreadable settings fail closed | Strong for Claude; the cap is **Auto-accept edits** (Claude has no switch to disable it) |
| Other providers off | `disabledDrivers` in the settings seed; Cursor removed at compile time | Medium (seed) / Strong (Cursor) |

T3 also keeps a `runtimeModeCeiling` for MCP client sessions only; it does not apply
to WebSocket tokens, so the connector does not rely on it.

## Files

| File | Purpose |
| --- | --- |
| `t3-policy.template.json` | Generic policy. No hostnames, paths, accounts or credentials; the installer takes those as parameters. |
| `install-policy.ps1` | Run once, elevated, per machine. Idempotent, `-WhatIf` friendly, `-Uninstall` reverses it. |
| `provider-config.md` | Model provider as configuration only (API key or Bedrock in Sydney, model pin). |

## Installer parameters

| Parameter | Required | Default | Meaning |
| --- | --- | --- | --- |
| `-T3Exe` | yes | | Full path of the `t3.exe` built from this fork that the connector starts |
| `-ClaudeExe` | yes | | Full path of a Claude binary used only by T3's Claude instance (the firewall rule applies to that path) |
| `-PolicyDir` | no | `%ProgramData%\T3CodePolicy` | Where the policy copy goes (Administrators/SYSTEM write, Users read) |
| `-ClaudeConfigDir` | no | `%ProgramData%\T3CodePolicy\claude-home` | The Claude instance's `CLAUDE_CONFIG_DIR`; its `settings.json` is read-only to non-admins |
| `-RunAsUser` | no | the account running the installer | Account that runs `t3 serve`; gets Modify on `-ClaudeConfigDir` |
| `-AllowedHosts` | no | template `egress.allowedHosts` | Model endpoints the Claude binary may reach; add a gateway host if one is used |
| `-ExtraAllowedAddresses` | no | none | Provider-published IP ranges (CIDR) to allow in addition to DNS results |
| `-ClaudeEgress` | no | `Resolve` | `Resolve` = allow the DNS addresses of `-AllowedHosts` now; `LoopbackOnly` = allow loopback only, for use with an allowlisting proxy |
| `-SeedT3SettingsPath` | no | none | T3's `settings.json`; written only if it does not exist |
| `-RuleGroup` | no | `T3 Code egress policy` | Firewall rule group the installer owns and replaces |
| `-Uninstall` | no | | Remove the rules, machine variables and policy copy |

Example (preview only):

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\tailor\policy\install-policy.ps1 `
  -T3Exe 'C:\Program Files\T3Code\t3.exe' `
  -ClaudeExe 'C:\Program Files\T3Code\claude\claude.exe' -WhatIf
```

## Host names versus firewall addresses

Windows Firewall matches addresses, not names, and a Block rule always wins over an
Allow rule, so "allow these hosts, block the rest" cannot be two rules. The installer
writes one Block rule per program whose remote addresses are the complement of the
allowed set. With `-ClaudeEgress Resolve` the allowed set is what DNS returned at
install time. CDN and AWS endpoints rotate addresses, so:

- re-run the installer to refresh (it replaces its own rules), on a schedule or when
  a model call fails with a connection error;
- prefer provider-published ranges through `-ExtraAllowedAddresses` where the
  provider publishes them;
- or use `-ClaudeEgress LoopbackOnly` with a loopback proxy that allowlists by host
  name (`HTTPS_PROXY` on the Claude instance). The proxy is not part of this PR.
