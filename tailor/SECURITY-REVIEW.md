# Security review: T3 Code v0.1.6 server and the stage 0 patch

Scope: the vendored server (`apps/server`, `packages/contracts`, `packages/shared`,
`apps/web`, provider packages) at upstream tag `v0.1.6`, plus this fork's stage 0 patch.
Method: adversarial source review, then an independent adversarial review of the first
draft, whose findings are recorded below as T3-17 to T3-27 with their fixes. Nothing here
was observed on a running install.

**The live egress capture is still TODO** (T3-01). It must be run on a real install
after the policy is installed. Until it passes, this review is not a pass.

Severity: Critical, High, Medium, Low, Info. Status: Fixed (in this PR), Mitigated
(config or firewall; residual risk stated), Open (needs follow-up), TODO.

## Summary

| ID | Finding | Severity | Status |
| --- | --- | --- | --- |
| T3-01 | Live egress capture not yet run | High | TODO |
| T3-02 | `t3.exe` calls out to analytics, GitHub, npm and other hosts by default | High | Mitigated |
| T3-03 | Per-program firewall rules do not cover the commands an agent runs | High | Mitigated, residual |
| T3-04 | MCP TypeScript SDK 1.29.0 (advisories up to CVSS 8.6); Cursor SDK bundles its own copy | High | Fixed |
| T3-05 | `proxy-addr` 2.0.7, IP spoofing via IPv4-mapped IPv6 (CVSS 9.1) | Critical | Fixed |
| T3-06 | Default runtime mode is Full access and there is no admin lock | High | Fixed (compile-time ceiling, T3-17) |
| T3-07 | `orchestration:operate` is broader than the connector needs | Medium | Fixed by T3-37 |
| T3-08 | Listener exposure and bind address | Medium | Mitigated |
| T3-09 | WebSocket upgrade Origin check (corrected: it exists) | Info | No action |
| T3-10 | Remote layers (Connect relay, pairing, Tailscale, SSH, peer links, guest share) ship in the binary | Medium | Mitigated, residual |
| T3-11 | Terminal and exec surfaces | Medium | Mitigated, residual |
| T3-12 | Product analytics on by default | Low | Fixed |
| T3-13 | Upstream release binaries do not contain this patch | High | Open |
| T3-14 | Firewall allowlist is IP-based; Bedrock addresses rotate | Medium | Open |
| T3-15 | Claude binary's own dependencies are outside our lockfile | Info | Accepted |
| T3-16 | Other high/critical dependency advisories in the lockfile | High | Fixed for the server path; `seroval` Open |
| T3-17 | Mode cap applied only inside Claude; T3's own MCP tools saw Full access | High | Fixed |
| T3-18 | Repository-supplied Claude settings, hooks and MCP files applied to agents | High | Fixed |
| T3-19 | Installer privilege escalation through `%ProgramData%` | High | Fixed |
| T3-20 | Policy did not fail closed; relied on a user-writable settings seed | High | Fixed |
| T3-21 | Agent could read T3's signing key and session store | Medium-High | Mitigated |
| T3-22 | Installer removed old firewall rules before the new ones were built | Medium | Fixed |
| T3-23 | Installer integrity before running elevated | Medium | Fixed |
| T3-24 | Standing grants from "accept for session" | Medium | Fixed |
| T3-25 | Browser egress (Google favicon service, Open VSX, no CSP); hosted values compiled in | Medium | Fixed |
| T3-26 | Unused upstream workflows and unpinned actions | Medium | Fixed |
| T3-27 | Web tools and proxy variables | Low | Fixed |
| T3-28 | Build guard file not committed (ignored by `build/`) | Blocker | Fixed |
| T3-29 | User launch arguments and `--settings` got past the lock | High | Fixed |
| T3-30 | Capabilities probe and `claude -p` text generation were not locked | High | Fixed |
| T3-31 | Policy configuration was user-writable (drivers, instance env, launch args, run-as account) | High | Fixed (service accounts UNVERIFIED until an elevated run) |
| T3-32 | Claude home writable at its root; Users could read it | Medium | Fixed |
| T3-33 | No machine-wide admin-tier deny rules | Medium | Fixed (merge, opt-out switch) |
| T3-34 | Policy location from an environment variable; Windows ran without a policy | Medium | Fixed |
| T3-35 | Installer integrity, input validation and file-write ordering | Medium | Fixed |
| T3-36 | Binaries in user-writable folders; no binary hash check | Medium | Fixed (Claude checked at start; T3 recorded) |
| T3-37 | Connector token broader than the five contract RPCs | Medium | Fixed (`tailor:connector`, issued by the installer; UNVERIFIED) |
| T3-38 | CSP covered connect and images only | Medium | Fixed |
| T3-39 | T3-home deny rules did not follow `--base-dir`; attachments | Medium | Fixed |
| T3-40 | Managed service defaulted to private-network bind; pnpm not pinned by integrity | Medium | Fixed |
| T3-41 | Claude lanes share the operator's account, so any token the connector can read they can read | High | Fixed by design (t3bridge); relies on stage 2 |
| T3-42 | Ceiling was Auto-accept edits while Claude and T3 share `t3agent` | High | Fixed (Supervised); raising it is an open design item |
| T3-43 | SDK 0.3.276 drops `managedSettings` under a machine tier without `parentSettingsBehavior: "merge"` | High | Fixed |
| T3-44 | Installer copied itself from an unprotected folder and imported modules by path | High | Fixed (UNVERIFIED elevated) |
| T3-45 | Administrator code ran inside the T3 home; ACLs set by path | High | Fixed (UNVERIFIED elevated) |
| T3-46 | Repository git hooks and config-driven commands ran for T3's git calls | High | Fixed |
| T3-47 | `claude -p` loaded user/project setting sources and ran in the project (corrects T3-30) | High | Fixed |
| T3-48 | Agent-made HTML pages could reach the network | Medium | Fixed |
| T3-49 | `worktreePath` not validated | Medium | Fixed |
| T3-50 | Projects could be created anywhere | Medium | Fixed |
| T3-51 | Service accounts' groups not checked | Medium | Fixed (privileged groups refused; Users kept, documented) |
| T3-52 | Uninstall leftovers, variable restore, undo ordering, password logging, probe hash | Low | Fixed (UNVERIFIED elevated) |
| T3-53 | No self-check of an install | Medium | Fixed (`verify-install.ps1`; UNVERIFIED elevated) |
| T3-54 | No way to invalidate every issued token at once | High | Fixed (`-EmergencyRevoke`; UNVERIFIED elevated) |
| T3-55 | Review-guide `claude -p` run allowed `git diff/log/show` without approval | High | Fixed |
| T3-56 | Git still read global/system config and repository-configured programs | High | Fixed (filters: controlled by config denial, documented) |
| T3-57 | Machine managed tier or a registry policy could loosen the lock | High | Fixed |
| T3-58 | Extra workspace roots kept their children's old ACLs | Medium | Fixed (refused; tree walked by the self-check) |
| T3-59 | Agent HTML could open as a top-level page | Medium | Fixed (frame only, otherwise a download) |
| T3-60 | `thread.metadata.update` and MCP worktree paths not checked | Medium | Fixed |
| T3-61 | `-RotateConnectorToken` kept old connector sessions valid | Medium | Fixed |
| T3-62 | Group membership read by name; errors ignored | Medium | Fixed (by SID through ADSI, fail closed) |
| T3-63 | Mover read the size from the path; drop folder not swept; no issue retry | Low | Fixed |
| T3-64 | Profiles and user module paths in elevated runs | Low | Fixed (`pwsh -NoProfile`, pinned `PSModulePath`) |
| T3-65 | Uninstall and account ownership gaps; the password's managed copy | Low | Fixed (UNVERIFIED elevated) |
| T3-66 | The bridge could send the token to an impostor listener | High | Fixed (named pipe owned by t3agent; T3 side and reference client); the bridge's own client is Open |
| T3-67 | Self-check missed first-run checks | Medium | Fixed (automated where possible, the rest printed as exact steps) |
| T3-68 | A revoke could never be verified (key compared with the revoke's end) | High | Fixed (start time) |
| T3-69 | `-RotateConnectorToken` could succeed without revoking anything | High | Fixed |
| T3-70 | Bare command names resolved in the working directory (planted `git.exe`) | High | Fixed |
| T3-71 | A worktree's `.git` file could point git anywhere | High | Fixed |
| T3-72 | Revoke left pairing links; one kill pass; scope not stated | Medium | Fixed |
| T3-73 | Delta review: investigation tools, git knobs, managed-tier helpers, HTML caching, tasks' own accounts, workspace owners, upgrade baselines, host checks, account adoption | Medium | Fixed (UNVERIFIED elevated where noted) |
| T3-74 | Upstream MCP tests outside the gate failed under the Supervised ceiling | Low | Fixed (rewritten; `src/mcp` in the gate) |
| T3-75 | An unresolved command ran a fixed substitute path any user could plant | High | Fixed (refused, nothing spawned) |
| T3-76 | The bridge pipe as built could not add instances; descriptor read as owner | High | Fixed |
| T3-77 | Task Scheduler added read access for each task's own account | High | Fixed (`TASK_DONT_ADD_PRINCIPAL_ACE`) |
| T3-78 | Delta review 3: rotation proof, libuv note, `.git` links, kill counting, bridge attestation, PATH, four-tuple, managed-tier allowlist, race coverage | Medium | Fixed (UNVERIFIED elevated where noted) |
| T3-79 | Lows from review 4: policy drop-ins and registry, probe result forgery, `.cmd` launches, probe SQOS and busy, missing-account kill, shell profiles, pipe WRITE_DAC, stricter task results | Low | Fixed (UNVERIFIED elevated where noted) |
| T3-80 | No deliberate update path for the pinned binaries | Medium | Fixed (`-UpdatePinned`; UNVERIFIED elevated) |
| T3-81 | Final review: update kills processes, required hash, Git tree, ancestor chains, agent HKCU policies, shell gate | Medium | Fixed (UNVERIFIED elevated) |

## Findings

### T3-01 Live egress capture not yet run (High, TODO)

Source review cannot prove what the binaries send. Required before stage 0 passes,
on the target machine after `install-policy.ps1` has run:

1. Start `t3 serve` through the connector with the policy's `serverEnvironment`.
2. Capture for at least one full session (startup, a Supervised turn with one
   approval, an interrupt, idle for over an hour so hourly refreshes fire, shutdown):
   `pktmon start --capture --comp nics --file-name t3-egress.etl` (or Wireshark),
   plus `Get-NetTCPConnection -OwningProcess <t3 and claude PIDs>` every 10 s, plus
   the firewall log (`Set-NetFirewallProfile -LogBlocked True`) for blocked attempts.
3. Pass criteria: `t3.exe` makes no non-loopback connection at all; the Claude binary
   connects only to the configured model endpoint; blocked-attempt log shows which
   hosts the binaries tried (expected: the PostHog ingest host, GitHub raw content,
   GitHub API, npm registry, Anthropic telemetry hosts). Any connection to Clerk,
   Cloudflare, PostHog, Axiom, GitHub or npm that is not blocked is a fail.

### T3-02 Outbound endpoints in source (High, Mitigated)

Every outbound host found in the server source, and what stops it:

| Endpoint | Caller | Default | Control in this PR |
| --- | --- | --- | --- |
| PostHog (`ingest.t3.codes`, project key built in) | `telemetry/AnalyticsService.ts` | **on** | Fork default off (T3-12), `T3CODE_TELEMETRY_ENABLED=false`, firewall |
| OTLP / Axiom (`X-Axiom-Dataset` header) | `packages/shared/otelEnvironment.ts`, `relayTracing.ts` | off unless an endpoint is configured; relay tracing follows the relay | `T3CODE_OTEL_SDK_DISABLED=true`, OTLP variables must be unset, firewall |
| Clerk (Connect sign-in, publishable key built in at release) | `cloud/CliTokenManager.ts`, `cloud/publicConfig.ts`, `shared/connectAuth.ts` | only on `t3 connect` / `t3 up` | Not linked, `T3CODE_RELAY_URL` unset, firewall |
| Cloudflare relay and `cloudflared` tunnel | `cloud/CloudLink.ts`, `RelayClient.layerCloudflared`, `cloud/managedTunnelStartup.ts` | only when linked (`not_linked` takes no action at startup) | Not linked, firewall; `cloudInstallRelayClient` needs `relay:write` |
| GitHub raw: model manifest, hourly | `provider/ModelManifest.ts` | on | `enableProviderUpdateChecks=false`, firewall |
| GitHub raw / API: LiteLLM price table | `usage/UsageService.ts` | when usage pricing loads | Firewall only (no switch); usage RPCs need `diagnostics:read` |
| GitHub releases / API: CLI update, pinned runtime | `cli/update.ts`, `cloud/pinnedRuntime.ts`, `shared/cliRelease.ts` | on `t3 update` / service install | Not run; firewall; `server.updateServer` needs `environment:maintain`. `T3CODE_DISABLE_AUTO_UPDATE` is read only by the desktop app, so for `t3 serve` "updates off" rests on the firewall, the missing scope and `enableProviderUpdateChecks=false`, which is weaker than a switch |
| npm registry (`registry.npmjs.org/t3`) | `cloud/npmRelease.ts` | on client request | Firewall. Note: `server.getNpmRelease` needs only `orchestration:read` |
| Chrome for Testing (`storage.googleapis.com`) | `preview/PreviewBrowser.ts` | when the preview browser is first used | `enableAgentBrowserAccess=false`, firewall |
| ACP registry CDN | `packages/contracts/acpRegistry.ts` | when the ACP registry is browsed | Driver disabled, firewall |
| Provider sign-in hosts (OpenAI, ChatGPT, Google, x.ai, Cursor, OpenCode) | provider packages | when those drivers run | Drivers disabled; Cursor removed (T3-04); firewall |
| Source-control hosts (GitHub, GitLab, Bitbucket, Gitea, Codeberg) | `packages/source-control-*` | on PR and clone features | Separate `git`/`gh` programs (T3-03); those RPCs need `source-control:write` |
| Tailscale | `packages/tailscale` (local `tailscale` CLI) | off | `T3CODE_TAILSCALE_SERVE=false` |
| Google favicon service (`www.google.com/s2/favicons`) | `packages/shared/favicon.ts`, from the browser | on | Off at compile time (T3-25) |
| Open VSX (`open-vsx.org`) theme search and import | `apps/web/openVsxThemes.ts`, from the browser | on use | Off at compile time (T3-25) |
| Anthropic API / Bedrock | the Claude binary | on | The only hosts the Claude rule allows |

The firewall rule on `t3.exe` blocks every non-loopback address, so the server needs
no allowlist at all: model traffic leaves from the Claude binary, not from `t3.exe`.

### T3-03 Child processes escape per-program rules (High, Mitigated, residual)

Windows Firewall program rules match the executable path of the process that owns
the socket. Commands an agent runs (shell, `git`, `curl`, `node`, package managers)
are other programs and are not blocked. Neither are `git.exe`/`gh.exe` started by the
server's source-control features, or `ssh.exe` for SSH device hosts.

Controls: Supervised mode with the cap (T3-06) means every command is an approval
card; the server-side never-send and never-pay rules stay on the Tailor side.
Residual: an approved command can reach any host. Follow-up: run `t3 serve` under a
dedicated low-privilege local account and filter egress by that account (WFP filter
on the user SID, or an AppContainer), or force all agent traffic through the
allowlisting proxy in T3-14.

### T3-04 MCP SDK advisories (High, Fixed)

`@modelcontextprotocol/sdk` 1.29.0 (peer of `@anthropic-ai/claude-agent-sdk`) is
affected by GHSA-22jm-h49p-29qw (8.6), GHSA-f897-62hf-6gxq (7.5),
GHSA-46jr-4wx8-v453 (7.5), GHSA-6qxp-vccf-f47h (7.5), GHSA-rvq5-wwqv-78pq (6.8) and
GHSA-6prh-2h8m-c8cw (6.5). Minimum fixed: 1.32.0. Pinned by workspace override to
1.32.2 (latest patch of the fixed line), lockfile regenerated.

`@cursor/sdk` 1.0.38 bundles its own MCP SDK inside its Webpack chunks, which no
override reaches. The Cursor driver is removed from `BUILT_IN_DRIVERS` and
`BUILT_IN_USAGE_DRIVERS` behind `TAILOR_CURSOR_DRIVER_ENABLED = false`
(`apps/server/src/provider/builtInDrivers.ts`), so no Cursor instance can be created
or run. Residual (Low): `@cursor/sdk` is still installed, and the Cursor account and
SDK layers in `server.ts` and `ProviderOrchestrationAdapterInfrastructure.ts` still
load its module at startup without running it. Follow-up: drop the package and
those layers.

### T3-05 proxy-addr IP spoofing (Critical, Fixed)

GHSA-jqcg-44mw-7w3h (9.1): `proxy-addr` < 2.0.8 trusts IPv4-mapped IPv6 addresses
against IPv4 trust subnets. Pulled in by `express` 5.2.1 under the MCP SDK's HTTP
transports. Pinned to 2.0.8 by override. Exploitability on a loopback-only server
is low, but it is fixed regardless.

### T3-06 Full access by default, no admin lock (High, Fixed)

Upstream `DEFAULT_RUNTIME_MODE` is `full-access` and T3 has no admin policy file
(tailor/policy/README.md). The fork sets the default to `approval-required` and compiles in
a ceiling that no setting can raise: `auto-accept-edits` at first (T3-17), Supervised since round 3 (T3-42).

### T3-07 Connector token scope (Medium, Open)

Scopes exist as documented: `t3 auth session issue --scope <scope>` is repeatable
and **replaces** the default set, which includes `terminal:operate`,
`filesystem:write`, `settings:write` and `providers:manage`. Always pass the scopes.
The read+operate token without terminal or access management is:

```
t3 auth session issue --scope orchestration:read --scope orchestration:operate --label connector --token-only --ttl 7d
```

The server checks exact scopes and never expands grants
(`auth/RpcAuthorization.ts`), and `apps/server/src/tailor/connectorScopes.test.ts`
proves this token reaches no `terminal.*`, guest share, peer link, auth access,
self-update or relay RPC. But `orchestration:operate` also allows:
`thread.runtime-mode.set`, `thread.delete` and every other dispatch command;
scheduled tasks (create, run now, rotate webhook tokens); `server.prepareTriage`
(starts an agent with access to logs and the database); `shell.openInEditor`
(launches an editor on the host); `provider.uploadFeedback`; `mcpApps.callTool`;
`projects.createNew`; `agentSessions.import`; device actions. Default token lifetime
is 30 days.

Follow-up: a fork middleware that refuses, for tokens with label `connector`, any
method or dispatch command not in `tailor/contract/connector-rpc-contract.json`.
Until then the connector is the allowlist, the token never leaves the connector's
store, and it is rotated with `--ttl`.

### T3-08 Listeners and bind address (Medium, Mitigated)

One HTTP server per process carries the web app, `/ws` RPC, `/mcp` (agent MCP,
bearer token), auth, attachments and media, guest share and scheduled-task webhook
routes. Port: `T3CODE_PORT` or 3773 (first free port when busy). Bind: an explicit
`T3CODE_HOST` wins; a managed service with no `T3CODE_LAN` binds `0.0.0.0` limited
to private networks; otherwise `127.0.0.1` (`cli/config.ts`, `server.ts`). Policy:
`T3CODE_HOST=127.0.0.1`, `T3CODE_LAN=false`, plus an inbound Block rule for every
non-loopback address on `t3.exe`.

### T3-09 WebSocket upgrade Origin check (Info, corrected)

The first draft said `/ws` had no Origin check. That was wrong:
`isBrowserOriginAllowed` in `auth/EnvironmentAuth.ts` rejects a browser Origin unless it is
same-origin by `Sec-Fetch-Site`, a trusted app origin, or matches the request's `Host`
(host and port) or `X-Forwarded-Host`. A cross-site page cannot set those headers on a
WebSocket handshake. No action.

### T3-10 Remote layers (Medium, Mitigated, residual)

Present in the binary: T3 Connect relay (Clerk sign-in, Cloudflare relay and
`cloudflared`), pairing codes and one-time tokens (`t3 auth pairing`), Tailscale
serve, SSH device hosts and remote environments (`packages/ssh`), peer links and
guest share links. All are off by configuration; peer links, guest share and pairing
need `access:write`, relay install needs `relay:write`, and the firewall blocks
`t3.exe` from reaching any relay. Residual: anyone with the local user's shell can
run `t3 auth pairing create` or `t3 up`. Follow-up: compile these layers out.

### T3-11 Terminal and exec surfaces (Medium, Mitigated, residual)

`terminal.*` RPCs (node-pty) need `terminal:read`/`terminal:operate`, which the
connector token lacks but a local browser session has by default. Agents execute
through the provider under Supervised approvals. Project scripts need
`settings:write`. `shell.openInEditor` needs only `orchestration:operate` (T3-07).
Repository `t3.json` worktree scripts (`runOnWorktreeCreate`) run on worktree
creation: needs verification of when they run without a prompt; until then the
connector launches threads without creating worktrees from untrusted repositories.

### T3-12 Product analytics on by default (Low, Fixed)

`T3CODE_TELEMETRY_ENABLED` now defaults to `false` in the fork
(`telemetry/AnalyticsService.ts`); the policy also sets it explicitly.

### T3-13 Upstream binaries lack the patch (High, Open)

`irm https://t3.codes/install.ps1 | iex` and `t3 update` install upstream's build
from `pingdotgg/t3code`, without these fixes. Install only a `t3.exe` built from this
fork at a reviewed commit; never run `t3 update`. Follow-up: a release workflow in
the fork that builds and checksums `t3.exe`.

### T3-14 IP-based allowlist (Medium, Open)

Windows Firewall cannot match host names. `install-policy.ps1` resolves the allowed
hosts at install time; one lookup of a Bedrock runtime host returned eight addresses,
so `Resolve` mode will drift. Re-run the installer to refresh, pass
provider-published ranges with `-ExtraAllowedAddresses`, or (preferred, follow-up)
run a loopback proxy that allowlists by host name and install with
`-ClaudeEgress LoopbackOnly`.

### T3-15 The Claude binary (Info, Accepted)

The Claude binary that T3 drives is Anthropic's build; its bundled dependencies
(including its own MCP client) are outside this lockfile. The bundled SDK binaries
in `@anthropic-ai/claude-agent-sdk` are already removed by upstream overrides; T3
runs the binary set as the instance's `binaryPath`. Its egress is limited by the
Claude firewall rule and its update and telemetry switches.

### T3-16 Other dependency advisories (High; Fixed for the server path, `seroval` Open)

Once forked, Dependabot listed 328 open alerts on `v0.1.6` (most in the vendored
`.repos/` reference checkouts, the mobile app and build tooling). The high and
critical ones in the root lockfile, triaged by whether the server or the web UI it
serves loads them:

| Package | Advisories | In the server path | Action |
| --- | --- | --- | --- |
| `undici` 8.11.2 | GHSA-qrxm-fqhp-jwvm, GHSA-xjj6-f33q-929c, GHSA-2m5v-pch6-74hx, GHSA-4w7w-5xrc-9h26 | yes (server HTTP client) | Catalog bumped to 8.12.2 |
| `zod` 4.6.5 | GHSA-mrhx-c7xc-m3w5 | yes (agent SDK, MCP SDK) | Override 4.6.6 |
| `dompurify` 3.4.16 | GHSA-cg2g-xh64-v4q7, GHSA-mrv2-3pqr-j5jr | web UI served to the local browser, which holds full scopes | Override 3.4.17 |
| `seroval` 1.5.4 | GHSA-p6vx-979v-rg4c (9.8) and four more | web UI router (client-side serialisation) | **Still open**: the minor bump to 1.6.8 needs the router tested |
| `shell-quote` 1.10.0 | GHSA-pqg4-j6r4-53mv (8.1) | no (React DevTools, development) | Open, not shipped in the server |
| `undici` 7.29.1 | as above | no: only `@electron/get` (desktop build) | Open, build only (confirmed in the lockfile) |
| `undici` 6.29.0 | as above | no: only `node-gyp` (build) and `@ai-sdk/provider-utils` under the mobile app's `@react-native-ai/apple` | Open, build and mobile only (confirmed in the lockfile) |
| `node-forge`, `sharp`, `path-to-regexp` 6.1.0, `body-parser` | various | no (mobile, marketing and build tooling) | Open, not shipped in the server |

Follow-up: a Dependabot or `pnpm audit --prod` step scoped to the server and web
packages in the gate.

### T3-17 Mode cap only inside Claude (High, Fixed)

The first draft capped modes only in the Claude adapter, so T3's own MCP tools still saw a
full-access caller and would run `t3_project_update`, `t3_project_clone` and
`t3_environment_preferences_update` (all `McpToolAccess.writesEnvironment`, which needs a
full-access/default caller). The fork now has a compile-time ceiling,
`TAILOR_MAX_RUNTIME_MODE` (`"auto-accept-edits"` then, `"approval-required"` since T3-42) with `clampRuntimeMode`
(`packages/contracts/src/providerPolicy.ts`), applied at every entry:

- `Orchestrator.dispatch`: every command, from a client or from the server itself
  (`thread.create`, `thread.runtime-mode.set`, `delegated_task.request`);
- `orchestration.launchThread` (`ws.ts`);
- the provider runtime policy (`RuntimePolicy.ts`), so a stored mode above the ceiling never
  reaches a provider;
- every settings read (`serverSettings.ts`, `defaultRuntimeMode`);
- MCP caller limits: thread callers (`mcp/threadAccess.ts`), clients (`clientModeCeiling`)
  and parents (`OrchestratorMcpService.ts`).

`DEFAULT_RUNTIME_MODE` is `approval-required`. Claude pre-approves only
`CLAUDE_READ_ONLY_T3_MCP_ALLOWED_TOOLS`, never `mcp__t3-code__*`, so every other T3 tool
asks. Tests: `apps/server/src/tailor/modeClamp.test.ts`; `McpToolAccess.test.ts` now expects
`capability_denied` for environment writes from a stored full-access thread or client, and
`runtime_mode_escalation_denied` for Auto or Full access starts.

### T3-18 Repository Claude settings and hooks (High, Fixed)

Claude Agent SDK 0.3.276 loads **all** filesystem settings when `settingSources` is omitted
(`sdk.d.ts`: "When omitted, all sources are loaded"). T3 omitted it, so a cloned
repository's `.claude/settings.json` hooks and permissions, and its `.mcp.json` servers,
applied to the agent. Every query now passes through `tailorLockClaudeQueryOptions`
(`ClaudeAdapterV2.ts`):

- `settingSources: []` (no user, project or local file);
- `strictMcpConfig: true` (only T3's own MCP server);
- the permission mode capped at `acceptEdits`, whatever the instance launch arguments say
  (`--permission-mode` and `--dangerously-skip-permissions` are ignored);
- a compiled policy tier (`managedSettings`) that denies `Edit`/`Write` on `**/.claude/**`,
  `**/.mcp.json` and `~/.claude.json`.

The policy's Claude settings file repeats the rules for reference; the binary no longer
loads it. Side effect: repository `CLAUDE.md` files are not loaded either. Test:
`apps/server/src/tailor/claudeLock.test.ts`.

Correction to the first draft: it said the Claude binary skipped the custom home's
`settings.json`. Before this lock it loaded it (all sources); with the lock it does not,
which is why T3 itself enforces the Auto cap from that file (`queryPolicyForTurn`).

Residual: instance `launchArgs` still pass other CLI flags and `--settings` (flag tier).
A user with `providers:manage` can set them; agents cannot (environment writes are refused,
T3-17) and the connector token lacks that scope.

### T3-19 Installer privilege escalation through `%ProgramData%` (High, Fixed)

`%ProgramData%` lets any user create folders, so a user could pre-create the policy folder,
or plant a junction or hard link, and have the elevated installer write through it. The
installer now:

- uses the fixed folder `%ProgramData%\T3CodePolicy` (the server reads the same fixed path);
- creates each folder with its protected security descriptor in the same call
  (`Directory.CreateDirectory(path, DirectorySecurity)`: inheritance off, owner
  Administrators, Administrators and SYSTEM full, Users read, the run-as user Modify only on
  the Claude home);
- refuses an existing folder that is a reparse point or is owned by anyone other than
  Administrators or SYSTEM, and resets the ACL instead of adding to it;
- replaces files by deleting whatever is at the path first (a planted link is removed,
  never written through) and resets each file's ACL;
- no longer writes into any user-writable folder (the T3 settings seed goes to
  `%ProgramData%\T3CodePolicy\t3-settings.seed.json`).

Verified with `-WhatIf` and unit checks of the reparse and owner refusals; the real creation
path needs an elevated run.

### T3-20 Fail closed (High, Fixed)

The server reads `%ProgramData%\T3CodePolicy\t3-policy.json` (fixed path, compiled in). When
it exists, every Claude query refuses to start unless the instance's Claude home and binary
are the ones recorded in its `installed` block. An unreadable or incomplete policy also
refuses (`tailorPolicyGuard` in `ClaudeAdapterV2.ts`). The user-writable T3 settings are not
trusted for this. Without a policy file the build still has the compile-time ceiling (T3-17)
and the query lock (T3-18).

### T3-21 T3 signing key and session store (Medium-High, Mitigated)

The agent runs as the same Windows user as `t3 serve`, so it could read T3's home (`~/.t3`:
server secret, session store, settings). The compiled Claude policy tier denies `Read`,
`Edit` and `Write` on `~/.t3/**`, and on `T3CODE_HOME` when set. Residual: those rules cover
Claude's file tools, not shell commands; Bash still needs an approval per call. The stronger
option, recommended for stage 2, is to run the Claude binary under a separate low-privilege
local account with no access to the T3 home, which the firewall can then also filter by
user.

### T3-22 Firewall swap order (Medium, Fixed)

The installer validates every input (full `.exe` paths that exist, host-name syntax, CIDR
syntax, the run-as account), resolves DNS and builds the complete new rule set first, adds
the new rules under fresh names, and only then removes the previous rules in its group. A
failure part-way leaves the old rules in place.

### T3-23 Installer integrity (Medium, Fixed)

The installer prints its own SHA-256 and the template's. With
`-ExpectedSha256 'script=<hex>,template=<hex>'` (from the reviewed commit) it refuses to run
on a mismatch, before changing anything. It copies itself and the template into
`%ProgramData%\T3CodePolicy\installer` (admin-only); refreshes run that copy, so a later
elevated run never executes a user-writable script.

### T3-24 Standing grants (Medium, Fixed)

"Accept for session" turned an approval into session-wide permission rules, falling back to
the whole tool name when Claude offered no suggestion. The fork maps it to a one-time
approval (`permissionResultFromDecision`); "accept always" is already a denial for Claude.
Test: `claudeLock.test.ts`.

### T3-25 Browser egress and hosted build values (Medium, Fixed)

The web app runs in the user's browser, outside the firewall rules. The fork turns off the
Google favicon service (`TAILOR_DISABLE_FAVICON_SERVICE`) and Open VSX theme search and
import (`TAILOR_DISABLE_OPEN_VSX`) at compile time. It serves the app's HTML with
`Content-Security-Policy: connect-src 'self'; img-src 'self' data: blob:`, so the page can
connect only to this server and rendered agent output cannot send data out through image
URLs. The server and web builds fail if any Clerk, relay or relay-tracing variable is set
(`tailor/build/assertNoRemoteBuildConfig.ts`; test `tailorBuildGuard.test.ts`).

### T3-26 Workflows and actions (Medium, Fixed)

Every upstream workflow is deleted from the branch; only `tailor-gate.yml` remains (CodeQL
and the dependency graph are repository-level dynamic workflows). Third-party actions are
pinned to commit SHAs.

### T3-27 Web tools and proxy variables (Low, Fixed)

`WebSearch` and `WebFetch` are always in `disallowedTools`. `HTTPS_PROXY`, `HTTP_PROXY`,
`ALL_PROXY` (and lower-case forms) and `NODE_OPTIONS` must be unset for `t3 serve`; the
connector starts it with an explicit environment, and the installer warns if they are set.

### T3-28 Build guard file not committed (Blocker, Fixed)

`.gitignore` ignores `build/`, so `tailor/build/assertNoRemoteBuildConfig.ts` never reached
the branch. `.gitignore` now un-ignores `tailor/build/`; `git status --ignored` shows no other
ignored file the fork relies on.

### T3-29 Launch arguments and `--settings` (High, Fixed)

The instance's `launchArgs` (user-writable T3 settings) passed `--settings`, extra CLI flags,
`--add-dir`, append-system-prompt text and permission flags to Claude. In this build
(`TAILOR_IGNORE_LAUNCH_ARGS`) they are ignored everywhere: the driver blanks them, the adapter
sanitises its options again, and `makeClaudeQueryOptions` neither parses them nor uses
`--settings`. Tests run hostile arguments through `makeClaudeQueryOptions` and through a real
turn (`--setting-sources`, `--managed-settings`, `--allowedTools`, `--mcp-config`,
`--plugin-dir`, `--agents`, `--allow-dangerously-skip-permissions`,
`--dangerously-skip-permissions`, `--permission-mode`, `--settings` with `permissions.allow` and
`hooks`, append prompts, `--add-dir /`) and assert the locked options. The Claude adapter also
caps any mode the CLI reports or that would be restored after plan mode
(`tailorCapPermissionMode`), and caps Full access and Auto at query-policy level.

### T3-30 Probe and text generation (High, Fixed)

The capabilities probe now loads no settings files (`settingSources: []`), keeps hooks off and
strict MCP, and carries the compiled deny rules. `claude -p` text generation carries the deny
rules in its flag settings (hooks were already off). Both use the binary and home the driver
takes from the machine policy (T3-31), never from user settings.

**Correction (round 3).** The claim that `claude -p` was locked was wrong: it passed no
`--setting-sources`, so the CLI still loaded user, project and local settings, and it ran in
the project folder. Fixed in T3-47.

### T3-31 Policy configuration (High, Fixed; service accounts UNVERIFIED)

The build contains the Claude driver only (`TAILOR_CLAUDE_ONLY`). When the machine policy is
installed the driver overrides the instance's binary and home with the recorded ones, blanks
launch arguments and keeps only allowlisted instance variables (the compiled list, narrowed by
`installed.instanceEnvironmentAllowlist`; proxy, `NODE_OPTIONS` and `CLAUDE_CONFIG_DIR` are
never allowed).

T3 and the Claude it starts now run as a dedicated local standard account, `t3agent`, created
by the installer (`tailor/policy/ServiceAccounts.psm1`):

- The password is random (40 characters from a CSPRNG), generated in memory, passed to
  `Register-ScheduledTask` (`LogonType Password`, "run whether user is logged on or not",
  `RunLevel Limited`) and discarded. It is never written to disk or a log; a re-install resets
  it to a new random value.
- Local policy, through `secedit /export` and `/configure` of the user-rights area only: "log
  on as a batch job" granted; interactive, Remote Desktop and network logon denied. The INF
  edit is a pure, tested function (`Update-UserRightsInf`).
- The account is removed from Administrators if present. It stays in `BUILTIN\Users` so it
  can execute system binaries; no T3 folder grants anything to `Users`.
- The task `\T3CodePolicy\T3 server` starts at boot, restarts on failure, and runs a
  generated launcher that sets the policy's `T3CODE_*` variables and `T3CODE_HOME`, clears
  the must-be-unset variables, and restarts `t3 serve` if it exits. The launcher needs
  machine-wide PowerShell 7 (the Store package is per user).
- The T3 home (`%ProgramData%\T3CodePolicy\t3-home`) and the Claude home are reachable by
  Administrators, SYSTEM and `t3agent` only. the operator's session and the Claude lanes running as
  the operator cannot read T3's signing key, mint tokens or edit T3 settings.
- Uninstall stops and removes the task, the account, its rights and its profile.

UNVERIFIED: none of this has run elevated. Account creation, the secedit edit, the task
registration and start, the ACLs on a real machine and the profile removal are verified only
as `-WhatIf` previews and by tests of the pure planning functions
(`tailor/policy/tests/ServiceAccounts.Tests.ps1`). The first elevated install is the test.

Residual: Claude and the shell commands it runs are the same `t3agent` account as `t3 serve`,
so ACLs cannot keep the agent away from the T3 home. That boundary is the compiled deny rules
for Claude's file tools plus Supervised approvals for every shell command.

### T3-32 Claude home (Medium, Fixed)

The Claude home starts admin-only (no Users read). Its files (`settings.json`, `.claude.json`)
are written before the run-as account gets any access, created with `CreateNew` after any
existing path is deleted. The account then gets read and create-subfolder on the root (no file
creation, so it cannot plant `remote-settings.json` or replace `settings.json`), modify on
`.claude.json`, and modify only inside subfolders. The compiled deny rules also cover the
resolved Claude home: no `Edit`/`Write` anywhere in it, no `Read` of `.claude.json`,
`.credentials.json`, `remote-settings.json` or `settings.json`.

### T3-33 Machine-wide admin tier (Medium, Fixed)

The installer merges deny entries for the T3 home and the policy folder into
`C:\Program Files\ClaudeCode\managed-settings.json`. That file applies to **every** Claude
Code session on the PC, so the merge only adds those entries to `permissions.deny`
(de-duplicated), keeps every other key and value (unknown keys included), refuses a malformed
file and writes nothing, backs the old file up as `managed-settings.json.t3bak-<UTC>`, writes
through a temp file and an atomic rename after re-parsing, records what it added in
`t3-policy.json`, and on uninstall removes only those entries (deleting the file only if it
created it and it is now empty). `-WhatIf` lists the exact entries. Fixture tests:
`tailor/policy/tests/ManagedSettingsMerge.Tests.ps1` (no file, a file with other permissions,
hooks, env and unknown keys, idempotent re-install, malformed file refused and untouched,
uninstall restoring the original). `-SkipMachineManagedSettings` leaves the file alone.

### T3-34 Policy location and fail closed (Medium, Fixed)

The server finds the policy through the "Common AppData" known folder, read from the registry
by `reg.exe` at its fixed path, never the `ProgramData` environment variable
(`apps/server/src/tailor/machinePolicy.ts`). On a real Windows server (`tailorPolicyRequired`,
set by the CLI config) a missing or unreadable policy means the driver points Claude at a
binary that cannot run and the adapter refuses every query.

### T3-35 Installer integrity and ordering (Medium, Fixed)

The installer reads each file once and hashes and parses the same bytes; requires
`-ExpectedSha256 script=,template=,module=` unless it is the protected copy; copies itself,
the template and the merge module into the admin-only `installer` folder first and continues
from there; validates `serverEnvironment` names against `^T3CODE_[A-Z0-9_]+$`; refuses to run
with any Windows Firewall profile disabled; and requires PowerShell 7.2+.

### T3-36 Binary locations and hashes (Medium, Fixed)

The installer refuses a `t3.exe` or Claude binary whose file or folder is not owned by an
administrator principal or that any other principal can write. It records both SHA-256 values
in `t3-policy.json`; the server checks the Claude binary's hash before the first query. The T3
binary's hash is recorded for the connector to check before it starts `t3 serve` (a process
cannot meaningfully verify itself).

### T3-37 Connector scope (Medium, Fixed; issuance UNVERIFIED)

New scope `tailor:connector`: a token carrying it reaches exactly the five contract RPCs, and
through `dispatchCommand` exactly the five contract command types
(`RpcAuthorization.tailorConnectorAllows`), whatever else the token carries. The contract test
checks the lists against `tailor/contract/connector-rpc-contract.json`.

It is issued by the `t3agent` token issuer task and moved into
`%ProgramData%\T3CodePolicy\connector\token` by the SYSTEM mover (T3-45), readable by
Administrators, SYSTEM and `t3bridge` only (T3-41), and rotated daily with a 7-day lifetime,
keeping the two newest sessions. UNVERIFIED until an elevated run; end-to-end use of the token
against handlers that check scopes internally is not yet tested.

### T3-38 Content-Security-Policy (Medium, Fixed)

The web app's HTML is served with `default-src 'self'; script-src 'self'; style-src 'self'
'unsafe-inline'; font-src 'self' data:; media-src 'self' blob:; connect-src 'self'; img-src
'self' data: blob:; frame-src 'none'; worker-src 'self' blob:; object-src 'none'; base-uri
'self'; form-action 'self'; frame-ancestors 'none'`. Not yet checked against the built UI in a
browser (part of T3-01).

### T3-39 Base dir and attachments (Medium, Fixed)

The deny rules now follow the server's real base dir (`ServerConfig.baseDir`) as well as
`~/.t3` and `T3CODE_HOME`. Reads are denied for the database, secrets, settings and identity
files, logs, browser artifacts, caches and runtime; `userdata/attachments` stays readable.
Nothing under the base dir may be edited or written. Tested in `claudeLock.test.ts`.

### T3-40 Bind default and pnpm (Medium, Fixed)

Web mode binds `127.0.0.1` unless `T3CODE_LAN`/`--lan` is explicitly true; a managed service no
longer defaults to private networks. The gate installs pnpm 12.14.0 only after checking the
tarball against its registry SHA-512.

### T3-41 Who can hold the T3 token (High, Fixed by design)

Threat: the connector and every Claude lane on this PC run as the operator's account. Any file the
connector can read, a lane can read too, and could use to drive T3 directly.

Decision: a second dedicated local standard account, `t3bridge`, set up like `t3agent`
(random password straight to Task Scheduler, never stored; interactive, RDP and network logon
denied; removed on uninstall), is the only non-admin principal that can read
`connector\token` and the bridge's tailor.au key in `bridge\`. the operator's user and `Users` have
no access. The T3 bridge (the connector's T3 source, coming later in tailor-app) runs as
`t3bridge` through its own scheduled task when `-BridgeExe` is given; its executable must sit
in an admin-only folder and its SHA-256 is recorded. It opens no local listener and only dials
out: the firewall blocks all inbound connections to it and all outbound ones except loopback
and the `-TailorApiHosts` (no default host is built in).

Relies on: tailor.au accepting steering commands only from the operator's interactive sign-in (plan
stage 2), never from an agent key. Until stage 2 ships, the bridge executes nothing.

Residual: an administrator on the PC can read everything. UNVERIFIED until an elevated run
(see T3-31).

### T3-42 Ceiling was Auto-accept edits (High, Fixed; raising it is an open design item)

Round 3 review: with Auto-accept edits, Claude edits files without asking, and Claude, its
shell and `t3 serve` are all `t3agent`, so an edit can reach anything `t3agent` can write,
including T3's own state. The compile-time ceiling is now Supervised (`approval-required`) on
every path: `clampRuntimeMode` in the orchestrator, launches, settings, runtime policy and MCP
callers, and `tailorCapPermissionMode` turns Claude's `acceptEdits`, `auto` and
`bypassPermissions` into `default`. Tests: `modeClamp.test.ts`, `claudeModeCap.test.ts`,
`claudeLock.test.ts`, the adapter tests.

**Open design item.** Raising the ceiling again needs a t3server/t3agent split: `t3 serve`
and T3's state under one account, Claude and its tools under another that cannot write T3's
state or the policy. Not in this PR.

### T3-43 SDK dropped managedSettings under a machine tier (High, Fixed)

Claude Agent SDK 0.3.276 ignores an embedding app's `managedSettings` when a machine managed
tier exists unless that tier sets `parentSettingsBehavior: "merge"`. Since the installer
creates that tier, T3's compiled deny rules would have been dropped. Now:

- every chat query (`tailorLockClaudeQueryOptions`), the capabilities probe and `claude -p`
  carry the same deny rules in the flag-tier `settings` as well as `managedSettings`;
- the installer adds `"parentSettingsBehavior": "merge"` to the machine file only if the key
  is absent, records it as its own for uninstall, and refuses (changing nothing) if the key
  has another value.

Tests: `claudeLock.test.ts` (flag tier holds every managed rule), `ManagedSettingsMerge.Tests.ps1`
(added when absent, kept when "merge", refused otherwise, removed on uninstall).

### T3-44 Installer copy and module loading (High, Fixed; UNVERIFIED elevated)

The installer used to copy itself into the protected folder from wherever it was started,
and imported its modules by path. Now the documented first step is an elevated copy of the
five files into `installer\` (created with its ACL at creation), a `Get-FileHash` check there,
and a run from there. The script refuses to run from any other folder, or if the folder, its
parent or any of the files is writable by a non-administrator or is a link
(`Assert-AdminControlled`, `Assert-NoReparseTree`). It hashes each file once, requires
`-ExpectedSha256` for all five, and loads the modules, the template and `verify-install.ps1`
from those bytes (`New-Module -ScriptBlock`). `-Uninstall` runs the same way. Test: the
installer refuses to run from the repository.

### T3-45 Administrator code inside the T3 home (High, Fixed; UNVERIFIED elevated)

The installer used to run `t3.exe auth session ...` elevated against the T3 home (which
`t3agent` controls), seed T3's settings there, and set ACLs by path after creation. Now:

- the token is issued by a `t3agent` scheduled task into `connector-drop\` (create only), and
  moved into `connector\` by a SYSTEM task with fixed code that checks the file is not a link,
  has one hard link, is owned by `t3agent` and holds one printable token, then creates the new
  file with its ACL at creation and renames it into place;
- rotation needs no admin step: the issuer runs daily, keeps the two newest connector
  sessions and revokes the rest; the default lifetime stays 7 days (`-ConnectorTokenDays`);
- T3's settings seed is written to `service\` and copied into the T3 home by the launcher,
  as `t3agent`;
- new folders and files get their ACL at creation; an existing folder or unchanged file has
  its ACL reset through a handle opened without following links (`SetKernelObjectSecurity`),
  never by path;
- wherever admin code works in a folder it first checks that nothing in it is a link; admin
  code never enters the T3 home, the Claude home's subfolders or the workspaces (uninstall
  deletes them only after the accounts and their processes are gone, removing links as links).

### T3-46 Git hooks and config-driven commands (High, Fixed)

Repositories the agent works in could run code through git: hooks, `core.fsmonitor`,
external diff and textconv drivers, `ext::` transports, and bare repositories planted in the
tree. Every git command T3 starts now goes through one helper (`tailor/gitHardening.ts`):

- `GIT_CONFIG_COUNT`/`KEY`/`VALUE` (command-line scope, the same as `-c`):
  `core.hooksPath=%ProgramData%\T3CodePolicy\git-hooks` (empty, admin-owned, `t3agent` read),
  `safe.bareRepository=explicit`, `core.fsmonitor=false`, `protocol.ext.allow=never`;
  `GIT_EXTERNAL_DIFF` is removed;
- `--no-ext-diff --no-textconv` for `diff`, `log`, `show`, `format-patch` and `whatchanged`.

It is applied twice: to the process environment at the CLI entry (`bin.ts`), so Claude and
the commands it runs inherit it, and by a `ChildProcessSpawner` decorator in the server layer
(`tailor/gitSpawner.ts`), which rebuilds every git command's environment and arguments.
`diff.external=` (empty) is not used: git treats an empty value as a program name and fails
with "cannot spawn"; `--no-ext-diff` plus removing `GIT_EXTERNAL_DIFF` is the off switch.
Claude's file tools may not edit `**/.git/hooks/**`, `**/.git/config`,
`**/.git/info/attributes`, `**/.githooks/**` or `**/.husky/**`.

Tests: `gitHardening.test.ts` (keys, idempotence, arguments, the decorator composed as in
`server.ts`, and a source scan that `server.ts` and `bin.ts` are wired and no server code
spawns git through `node:child_process`); `verify-install.ps1` runs a hook test on the machine.

### T3-47 `claude -p` loaded setting sources in the project (High, Fixed)

Correction to T3-30: `claude -p` text generation passed no `--setting-sources`, so the CLI
loaded user, project and local settings, and ran in the project folder. It now passes
`--setting-sources=` (empty) and runs in a new empty temporary folder; only the investigate
run, which reads the repository, keeps the project folder (still with no setting sources and
the deny rules). Test: `ClaudeTextGeneration.test.ts` checks the argv and the working folder.

### T3-48 Agent-made HTML pages (Medium, Fixed)

HTML the agent writes and T3 serves gets `default-src 'none'; script-src 'unsafe-inline';
style-src 'unsafe-inline'; img-src data: blob:; connect-src 'none'; form-action 'none';
sandbox allow-scripts`: scripts run in an opaque origin with no network, no forms and no
same-origin access. Tests: `csp.test.ts`, `http.test.ts`.

### T3-49 Worktree paths (Medium, Fixed)

`thread.create` and `launchThread` (`existing_worktree`) accepted any `worktreePath`. Both now
refuse a path outside the project root and T3's managed worktree folder, and anything in the
policy folder other than the workspace roots. Paths are compared after resolving the real
path (junctions and links followed; for a missing path, its nearest existing ancestor),
case-insensitively on Windows (`tailor/workspacePolicy.ts`, applied in `ws.ts`). Tests:
`workspacePolicy.test.ts`, including a real junction.

### T3-50 Projects anywhere (Medium, Fixed)

With the policy installed, `project.create` refuses a root outside the workspace roots
recorded in `t3-policy.json` (`workspaces\` plus `-WorkspaceRoots`) and T3's own managed
project folders. The installer creates `workspaces\` for Administrators, SYSTEM and
`t3agent` only; an extra root's parent must be admin-only so the folder cannot be swapped.
How code gets in and out is in `policy/README.md`. Tests: `workspacePolicy.test.ts`.

### T3-51 Service account groups (Medium, Fixed; Users kept)

The installer refuses an existing account in any group but `BUILTIN\Users` (it used to remove
it from Administrators silently), and the self-check fails on any other group. The accounts
stay in `Users`: `Program Files` and `System32` grant read and execute through `Users`, so the
accounts could not start PowerShell, `t3` or Claude without it. Nothing under `T3CodePolicy`
grants `Users` anything. Not verified elevated.

### T3-52 Lows from round 3 (Low, Fixed; UNVERIFIED elevated)

- Uninstall now removes `service\`, `installer\`, `state\`, `connector-drop\`, `git-hooks\`,
  the T3 home and the Claude home, stops the accounts' processes first, and removes the
  deleted accounts' ACL entries from the kept workspaces.
- It restores only the `T3CODE_*` machine variables it changed, to their earlier values
  (recorded once, the first time each is changed).
- The undo record is written before the machine managed-settings merge, and "added/created by
  us" is merged across re-runs (`Merge-ManagedSettingsRecord`; tested).
- Passwords reach Task Scheduler through the COM API, never a cmdlet parameter that module
  logging would capture; Task Scheduler keeps them as LSA secrets.
- The Claude binary's hash is checked when the driver builds its settings, so the probe and
  `claude -p` refuse a changed binary as chat queries do.

### T3-53 No self-check of an install (Medium, Fixed; UNVERIFIED elevated)

`verify-install.ps1` is read-only (it writes only the marker and scratch files in temp) and
runs at the end of every install. It checks the protected copy, every folder ACL against
`Get-T3FolderAclPlan`, that the token is readable by `t3bridge` only and that no policy folder
grants the interactive user, `Users`, `Authenticated Users`, `Everyone` or `INTERACTIVE`
anything, the accounts' groups and rights, the tasks' account, logon type, run level and
launcher, the firewall profiles and rules, the machine managed-settings entries against the
install-time baseline, the binary and service-file hashes, and that a repository hook does not
run with T3's git settings. On a full PASS it writes the verified marker, and every launcher
refuses to start without a current one whose hashes match. Checks it cannot script are printed
as a checklist. The reviewer's first-run checks 1 to 7 were not available to this worker; the
seven printed checks are this worker's definition and should be compared with them.

### T3-54 Emergency revoke (High, Fixed; UNVERIFIED elevated)

Revoking a session row does not help if the signing key itself may be exposed, and there was
no single action to stop everything. `install-policy.ps1 -EmergencyRevoke` (protected copy,
same hash rules) removes the verified marker, disables and stops every task, stops the
accounts' processes, and has `t3agent` run T3's own `t3 auth rotate-signing-keys` through an
on-demand task (fork CLI command, `tailor/signingKeys.ts`): new random values for the four
signing keys (session, MCP OAuth, guest share, asset access) and every session revoked. The
token-signing HMAC check then fails for everything issued before. It deletes the connector
token and the drop folder's contents, logs the time in `state\revoke-log.json`, and prints
each step and its outcome. Nothing restarts until a full install and a passing self-check;
the self-check fails unless the signing key's last-write time (read through no-follow handles;
creation time is unreliable because of NTFS file-name tunnelling) is later than the last
revoke. Uninstall rotates the keys before deleting the T3 home.

Tests: `signingKeys.test.ts` (a token verified across a restart stops verifying after the
rotation, with `InvalidSessionTokenSignatureError`; new tokens work), and the revoke plan,
rotation script, on-demand task and freshness check in `ServiceAccounts.Tests.ps1`.

### T3-55 Review-guide investigation (High, Fixed)

The `claude -p` review-guide run uses `--permission-mode dontAsk`, where allowed tools run
without a prompt, and upstream allowed `Bash(git diff/log/show:*)`: shell commands outside
Supervised, with git's config-driven programs. It now gets `--tools Read,Grep,Glob`,
`--allowedTools Read(./**),Grep,Glob` (Read scoped to the repository; Grep and Glob follow
the Read rules and the compiled deny rules) and `--disallowedTools
Bash,Edit,Write,NotebookEdit,WebFetch,WebSearch`, and every `claude -p` gets the git
hardening in its environment. Test: `ClaudeTextGeneration.test.ts` asserts the argv.

### T3-56 Git configuration (High, Fixed)

Every T3 git call now also gets `GIT_CONFIG_GLOBAL` = an empty admin-owned file
(`git-config\gitconfig`), `GIT_CONFIG_NOSYSTEM=1`, `protocol.file.allow=user`,
`credential.helper=` (cleared), `core.sshCommand=ssh` (an empty value would break ssh
remotes), `commit.gpgSign=false` and `tag.gpgSign=false`; `GIT_SSH`, `GIT_SSH_COMMAND` and
`GIT_ASKPASS` are removed; `blame`, `diff-tree` and `stash show` get `--no-ext-diff
--no-textconv` too. Claude may not edit anything under `**/.git/**`, `~/.gitconfig`,
`~/.config/git/**`, `**/.gitattributes` or `**/.gitmodules`.
`filter.<driver>.clean/smudge/process` cannot be switched off for every driver name with `-c`;
the control is that no config can define a driver: global and system config are off, a clone
carries no repository config, Claude cannot edit config or attributes, and the agent's own
shell is Supervised. The self-check requires git 2.50.1 or later (by full path from the
policy). Tests: `gitHardening.test.ts`, `claudeLock.test.ts`.

### T3-57 Machine tier and registry policy (High, Fixed)

The installer refuses, and the self-check fails, while the machine `managed-settings.json`
has `permissions.allow`, `permissions.ask`, `permissions.defaultMode`,
`permissions.additionalDirectories`, `defaultMode`, `env`, `apiKeyHelper` or `hooks`, or
while `HKLM\SOFTWARE\Policies\ClaudeCode` exists. Test: `ManagedSettingsMerge.Tests.ps1`.

### T3-58 Extra workspace roots (Medium, Fixed)

An existing non-empty `-WorkspaceRoots` folder is refused (its children would keep the
operator's or `Users`' entries), and the root is recorded before it is created. The self-check
walks every workspace tree (links not followed) and fails on any allow entry for anyone but
Administrators, SYSTEM, CREATOR OWNER, OWNER RIGHTS and `t3agent`.

### T3-59 Agent HTML as a top-level page (Medium, Fixed)

HTML assets are served inline only when the browser says the request is for a frame
(`Sec-Fetch-Dest: iframe` or `frame`); any other request, a top-level navigation or one
without the header, gets `Content-Disposition: attachment`, `application/octet-stream` and
`default-src 'none'; sandbox`. Test: `http.test.ts`. A browser that sends no
`Sec-Fetch-Dest` gets downloads only (fail closed).

### T3-60 Worktree paths, everywhere (Medium, Fixed)

With the machine policy installed, `Orchestrator.dispatch` checks the worktree of every
`thread.create` and `thread.metadata.update` (client, MCP or server), and the MCP project
toolkit's existing-worktree check applies the same rules (`workspacePolicy.ts`).

### T3-61 Connector token rotation (Medium, Fixed)

`-RotateConnectorToken` runs the issuer through the on-demand task `T3 token rotate now` with
`-RevokeAllPrevious`: every previous connector session is revoked. The daily run keeps one
previous session (the bridge's until the mover runs). `-EmergencyRevoke` disables both tasks
and rotates the signing keys, which invalidates every session whatever the issuer kept.

### T3-62 Group membership (Medium, Fixed)

Groups are read by SID through ADSI (WinNT provider); any error throws, so the installer and
the self-check fail closed.

### T3-63 Mover and issuer (Low, Fixed)

The mover deletes everything else in the drop folder on every run, reads at most 4097 bytes
from the open handle (no size read from the path) and discards anything outside 16 to 4096
printable bytes. The issuer retries once.

### T3-64 Elevated runs (Low, Fixed)

The documented commands are `pwsh -NoProfile -File`. The installer, the self-check and every
generated script pin `PSModulePath` to `$PSHOME` and System32; the installer and self-check
import LocalAccounts, ScheduledTasks, NetSecurity and NetTCPIP by full path.

### T3-65 Uninstall and accounts (Low, Fixed; UNVERIFIED elevated)

The installer records the accounts it creates (intent first, then the SID) and refuses an
existing account of the same name it did not create; uninstall removes only recorded
accounts. Uninstall removes the `\T3CodePolicy` task folder, the `Program Files\ClaudeCode`
folder only if the installer created it and it is empty, and keeps the managed-settings
backups on purpose. A pre-install snapshot (`state\pre-install.json`: managed settings, user
rights, tasks, firewall rules, `T3CODE_*` variables) is taken on the first install and
uninstall prints the diff against it. The managed string copy of each password is
overwritten in place after registration, as the BSTR is zeroed. Tests: the snapshot and
rights comparisons in `ServiceAccounts.Tests.ps1`.

### T3-66 Bridge authenticates the server (High; T3 side Fixed, bridge client Open)

While T3 is down any account can bind the T3 port, and a PID check before connecting leaves a
check-then-connect gap. The bridge now reaches T3 only over the named pipe
`\\.\pipe\t3code-bridge`, created by a shim the T3 launcher runs as `t3agent`
(`service\bridge-pipe.ps1`): `FILE_FLAG_FIRST_PIPE_INSTANCE` (creation fails if the name is
taken, and the shim refuses loudly), owner `t3agent`, a protected DACL with `t3bridge`
read/write, SYSTEM read/write and `t3agent` create-instance only, `PIPE_REJECT_REMOTE_CLIENTS`,
and a listening instance at all times. The shim relays each connection to T3's loopback port
only after checking, on that established connection, that the accepting process is the
`t3 serve` the launcher started. The bridge client opens with `SECURITY_SQOS_PRESENT |
SECURITY_IDENTIFICATION`, checks the owner SID through its own handle and
`GetNamedPipeServerSessionId == 0`, sends nothing otherwise, and never falls back to TCP
(`Connect-T3BridgePipe` is the reference). The firewall gives the bridge the tailor.au API
hosts only. The token is still required over the pipe.

Why a PowerShell/.NET shim: Node cannot set a pipe's DACL or `FILE_FLAG_FIRST_PIPE_INSTANCE`
on its own listener, and adding a native module to T3 would be a new build-time dependency.
The shim calls `CreateNamedPipeW` directly (small P/Invoke, every flag explicit) and runs as
`t3agent`, so the pipe's owner is T3's own account; it is installed, hashed and covered by the
verified marker like the launchers.

Possible extra check (not a replacement): the reviewer notes that `t3bridge` may be able to
see other processes' user SIDs through `WTSEnumerateProcessesEx`; the bridge could also check
that `GetNamedPipeServerProcessId` belongs to `t3agent` that way. The owner SID check is the
real one.

Tests: the descriptor builder and its judgement, the client refusing a pipe owned by another
SID and a server outside session 0, `FILE_FLAG_FIRST_PIPE_INSTANCE` failing for a second first
instance, the shim's instance ordering (`ServiceAccounts.Tests.ps1`). The self-check probe (as
`t3agent`) reads the live pipe's descriptor, tries a second first instance and an instance
claiming another owner. Open: the bridge's own client (tailor-app).

### T3-67 First-run checks (Medium, Fixed; UNVERIFIED elevated)

The self-check now automates the user-rights diff, the agent's privileges, groups and
integrity and live access tests (probe task), each task's actions and security descriptor,
the bridge key ACL, the workspace trees, the machine tier, the git version, and records that
an elevated administrator can read the token. Deny variants, fail-closed tests, hooks and
Bash approvals, and egress are printed as exact manual steps. Built-in read-only Bash
auto-approval in default mode is to be recorded by that manual step.

### T3-68 Revoke recovery (High, Fixed)

The self-check compared the signing key's write time with the revoke log's time, written
after the rotation, so a reinstall after a good revoke could never pass. The revoke now
records its start time before the keys rotate (`RecordRevokeStart`) and the check compares
with that start. Test: the whole revoke, reinstall and verify sequence simulated on the
planner, plus a stale key still failing (`ServiceAccounts.Tests.ps1`).

### T3-69 Connector token rotation (High, Fixed)

With an unmoved token in the drop folder the rotate-now task exited with success before
revoking anything. In `-RevokeAllPrevious` mode it now revokes every connector session first,
and fails with exit code 2 if the drop is occupied; the installer waits for the task and exits
non-zero on any failure.

### T3-70 Planted executables (High, Fixed)

Windows (and libuv) look for a bare program name in the working directory first, so a
`git.exe` at a repository root would run. The spawner decorator now rewrites every bare
command name on Windows to an absolute path from PATH's absolute entries only (a name found
nowhere becomes a path that cannot exist), and with the policy installed `git` is always the
policy's absolute `gitExe` (a policy without one refuses git). `NoDefaultCurrentDirectoryInExePath=1`
is set for the server process and every child (cmd.exe honours it for shell commands). The
Claude binary is already the policy's absolute path. Tests: `gitHardening.test.ts`, including a
real spawn in a folder holding a renamed `whoami.exe` as `git.exe`.

### T3-71 Worktree `.git` files (High, Fixed)

Claude may not edit `**/.git` (the file of a linked worktree or submodule) or `~/.ssh/**`.
Before any git command, the decorator finds the tree's `.git`; if it is a file, its `gitdir:`
must resolve (real path) to `<repository>/.git/worktrees/<name>` or `.git/modules/<name>`, and
with the policy installed that repository must be in a workspace root or the T3 home;
otherwise the command is refused. Test: `gitHardening.test.ts`.

### T3-72 Revoke completeness (Medium, Fixed)

`t3 auth rotate-signing-keys` also revokes every pairing link. The revoke stops the accounts'
processes in rounds until none is left (or fails after ten), empties the probe folder, and
the README says plainly that revoke covers leaked T3 credentials, not a compromised `t3agent`
(uninstall and wipe), and lists the credentials to rotate by hand (the bridge's tailor.au key,
the model credential, any repository credential).

### T3-73 Delta review fixes (Medium, Fixed; UNVERIFIED elevated where noted)

- The review-guide investigation gets `Read(./**)` only: Grep and Glob are dropped, because
  their path scoping could not be proven.
- Git also gets `core.askPass=` and `core.gitProxy=none`, and loses `SSH_ASKPASS` and
  `GIT_PROXY_COMMAND`; `merge.<driver>.driver` and `include.path` are covered by the config
  denial (as filters are).
- The machine managed tier is also refused with `otelHeadersHelper`, `awsAuthRefresh`,
  `awsCredentialExport`, `gcpAuthRefresh`, `enableAllProjectMcpServers` or
  `enabledMcpjsonServers`.
- Agent HTML responses carry `Vary: Sec-Fetch-Dest` and `Cache-Control: no-store`.
- Every task is registered with the descriptor `D:P(A;;FA;;;BA)(A;;FA;;;SY)`: its own account
  can neither read, run nor change it; the self-check fails on any other entry (UNVERIFIED).
- The workspace walk also checks every entry's owner.
- An upgrade without a pre-install snapshot records an "unknown baseline"; the rights diff then
  checks only our four rights.
- The probe also checks that `t3agent` cannot read the bridge key or write the launchers.
- Both scripts refuse to run without `-NoProfile` or when a command they rely on is not the real
  one from its module; every generated script pins `PSModulePath` first.
- `-AdoptExistingAccounts` adopts, once, accounts from an install that predates the ownership
  record, only with exactly this installer's description and no group but `Users`.

### T3-74 Upstream MCP tests (Low, Fixed)

`src/mcp` is in the gate now. Tests that expected full-access or auto callers were rewritten to
assert the Supervised ceiling; the Codex replay integration test was deleted (it replays a
Codex transcript recorded at full access: the build has no Codex driver and no full access).
Tests with the policy installed (a stubbed ProgramData known folder) cover the orchestrator
and MCP worktree checks.

### T3-75 No substitute command (High, Fixed)

An unresolved bare name was rewritten to `C:\T3CodePolicy-refused\command-not-allowed.exe`,
which was then spawned; any user can create that folder, so a planted file would have run as
`t3agent` (for example in place of `gh auth token`, whose output is trusted). Now an unresolved
name is refused with a `NotFound` platform error and nothing is spawned; a `shell: true` launch
runs only if its first token is an existing absolute program path; piped commands are refused
on Windows (none are used). All server spawns through the Effect spawner pass the decorator;
the remaining direct `node:child_process` spawns use absolute paths (Claude from the policy,
`reg.exe`, `process.execPath`) or run only off Windows. Test: an unresolved name spawns nothing
even when every absolute path "exists".

### T3-76 Bridge pipe (High, Fixed; UNVERIFIED elevated)

Adding an instance needs read/write plus create-instance, so the owner (`t3agent`) now gets
exactly `0x12019f`, and the shim's loop can keep an instance listening. The descriptor is read
by a SYSTEM probe task (SYSTEM is in the DACL) instead of by the owner. Test with the
installer's own grants: a further instance by the owner succeeds; with only the bridge's
grant it fails.

### T3-77 Task descriptors (High, Fixed; UNVERIFIED elevated)

`RegisterTaskDefinition` gets flags `0x16` (create or update, `TASK_DONT_ADD_PRINCIPAL_ACE`),
so the explicit Administrators/SYSTEM descriptor is what the task keeps. The self-check also
fails on a task whose last result is a failure.

### T3-78 Delta review 3 (Medium, Fixed; UNVERIFIED elevated where noted)

- Rotation proof: the issuer checks the exit code of every list and revoke, re-lists, and exits
  non-zero if more connector sessions remain than allowed.
- `NoDefaultCurrentDirectoryInExePath` protects libuv because it is in the server's own
  environment (set at the CLI entry); the comment and test now say so.
- A `.git` that is a link or junction is refused; nested submodule gitdirs are allowed.
- Revoke counts a process as stopped only when `Stop-Process` succeeds, and loops until none
  is found.
- `-BridgeExe` requires `-BridgeUsesPipeOnly` until the bridge client is reviewed (loopback is
  not filtered by Windows Firewall).
- T3's PATH is set by the launcher from admin-only folders; the server skips its PATH
  re-read under the policy; Claude may not edit folders that could reach t3agent's PATH or
  profile; the self-check checks the recorded PATH.
- The shim matches its connection's full four-tuple, and the launcher restarts it if it dies.
- The machine managed tier is checked against an allowlist of restrictive keys.
- The orchestrator's under-lock recheck is covered again: a plan-limited caller's write is
  refused when the user raises the interaction mode after the check.

### T3-79 Lows from review 4 (Low, Fixed; UNVERIFIED elevated where noted)

- Every Claude policy source is checked against the allowlist: the machine file, each
  `managed-settings.d\*.json` drop-in, and `SOFTWARE\Policies\ClaudeCode` in HKLM, the
  administrator's HKCU and `t3agent`'s HKCU (a JSON value key by key, other values by name).
  Remote organisation settings: see the policy README (not expected to apply to API-key or
  Bedrock auth; not verified live).
- The SYSTEM pipe probe writes its result into the admin-only `state\` folder with CreateNew
  and a protected Administrators/SYSTEM DACL, owned by SYSTEM; the self-check checks owner and
  DACL. It opens the pipe with `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`, and
  `ERROR_PIPE_BUSY` is a FAIL.
- The shell gate parses the program out of `resolveSpawnCommand`'s caret-escaped command line
  correctly (a real `.cmd` launch passes), requires it to be in one of the policy's
  admin-owned PATH folders when the policy is installed, and gives the shell child the same
  environment hardening. Test with real `resolveSpawnCommand` output.
- `Stop-AccountProcesses` returns a found/stopped pair for a missing account too.
- Claude may not edit `~/bin`, `~/.bashrc`, `~/.bash_profile`, `~/.bash_login`, `~/.profile` or
  `~/.inputrc`; the self-check requires Git Bash's `etc` folder and profile files to be
  admin-only.
- The pipe check also refuses WRITE_DAC or WRITE_OWNER for t3bridge and SYSTEM.
- Once a verified marker exists, the self-check accepts only success or running for the T3
  server task and only success for the probe tasks.

### T3-81 Final review fixes (Medium, Fixed; UNVERIFIED elevated)

- `-UpdatePinned` stops every process of both service accounts until none is left (failing
  after ten rounds) before the swap; Stop-ScheduledTask alone left `t3.exe` and Claude running.
- `-ExpectedSha256` is required for a new Claude, `t3.exe` or node, except for a rollback from
  inside `state\pinned-backup\` (a separator-terminated prefix, so `pinned-backup-x\` does not
  count).
- Before running a new git elevated, the whole Git install (`mingw64\bin` included) must be
  admin-owned with no non-admin write and no links.
- The update's own verification runs with the marker removed and the tasks stopped, so the
  stricter task-result rule applies from the next `verify-install.ps1` run.
- The install and the update check every pinned folder's ancestor chain: no non-admin may
  delete, rename or re-permission entries in them.
- `t3agent`'s `HKCU\Software\Policies` gets an admin-only ACL; the self-check loads the hive
  when it is not loaded instead of skipping it.
- The shell gate allows only `shell: true`, and documents that only the program is validated:
  callers must never put agent or user text into a shell command (batch files re-parse their
  arguments, so escaping cannot make it safe).
- Claude may not edit `~/.bash_logout`.

### T3-80 Updating pinned binaries (Medium, Fixed; UNVERIFIED elevated)

The pinned Claude, `t3.exe`, node and git are used only by T3 and never update themselves.
`-UpdatePinned Claude|T3|Node -From <file> [-ExpectedSha256 <hex>]` stops T3, removes the
marker, checks the source (plain file, expected hash), keeps the current binary as a backup in
`state\pinned-backup\`, writes the new one (CreateNew, protected DACL) and moves it into the
pinned path, records the new hash and the old one, runs the self-check and starts T3 only on a
PASS; on failure T3 stays stopped and the rollback command is printed. Git is upgraded in place
by its own installer and then verified and recorded with `-UpdatePinned Git`. Tests: the
planner's order and refusals.

## What was verified

- Locally on Windows (frozen lockfile), after the delta review: the contracts suite (161/161)
  and the gate's server tests, 771 passed plus 1 upstream skip: `src/mcp` 293/293 (every
  upstream MCP test, including the restored interaction-mode race), `src/tailor`, `http.test.ts`
  and the text-generation tests 91/91, and the other gate files 387 passed plus 1 skip (a real
  `resolveSpawnCommand` `.cmd` launch through the shell gate, git hardening including a real
  planted-`git.exe` spawn, refusal with nothing spawned, `.git` link and nested-submodule
  checks, worktree checks with the policy installed,
  workspace paths, CSP and the frame-only HTML rule with its cache headers, signing-key
  rotation, the investigation argv, `http.test.ts`). Server `src` and contracts typecheck
  clean. `t3 auth rotate-signing-keys` ran from source against a throwaway base dir: four keys
  replaced, sessions and pairing links revoked.
- The PowerShell tests pass: managed settings (including all loosening keys) and the
  service-account module (task XML, ACL plan, launchers with the module-path pin first, the
  bridge pipe descriptor and judgement, the reference client refusing another owner and a
  non-service session, `FILE_FLAG_FIRST_PIPE_INSTANCE`, the shim's instance ordering, issuer
  rotate-now ordering, the revoke plan and the revoke -> reinstall -> verify sequence, rights
  and pre-install diffs, strict task descriptors, the probe, the git version floor, and the
  installer refusing to run outside the protected copy). Both scripts parse.
- Not verified (UNVERIFIED): anything that needs an elevated run on a real machine: accounts,
  adoption and ownership records, secedit, COM task registration with explicit descriptors,
  folder ACLs and the handle reset, the token issuer, mover and rotate-now task, the probe
  task, the bridge pipe as t3agent in session 0, the emergency revoke, the firewall rules, the
  self-check's PASS path and marker, uninstall and its diff, and the policy guard and binary
  hash on a real install. Also not verified: a full build, the full upstream suite outside the
  gate, the CSPs and the frame-only rule in a browser, the connector token end to end, the
  bridge's own pipe client, and the live egress capture (T3-01).
