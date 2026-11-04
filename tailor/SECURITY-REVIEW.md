# Security review: T3 Code v0.1.6 server and the stage 0 patch

Scope: the vendored server (`apps/server`, `packages/contracts`, `packages/shared`,
provider packages) at upstream tag `v0.1.6`, plus this fork's stage 0 patch
(`tailor/`, `pnpm-workspace.yaml` overrides, the Cursor and telemetry changes, the
Claude mode cap). Method: adversarial source review. Nothing here was observed on a
running install.

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
| T3-06 | Default runtime mode is Full access and there is no admin lock | High | Mitigated (fork patch + config) |
| T3-07 | `orchestration:operate` is broader than the connector needs | Medium | Open |
| T3-08 | Listener exposure and bind address | Medium | Mitigated |
| T3-09 | `/ws` upgrade has no Origin check; relies on SameSite=Lax cookies | Medium | Open (verify) |
| T3-10 | Remote layers (Connect relay, pairing, Tailscale, SSH, peer links, guest share) ship in the binary | Medium | Mitigated, residual |
| T3-11 | Terminal and exec surfaces | Medium | Mitigated, residual |
| T3-12 | Product analytics on by default | Low | Fixed |
| T3-13 | Upstream release binaries do not contain this patch | High | Open |
| T3-14 | Firewall allowlist is IP-based; Bedrock addresses rotate | Medium | Open |
| T3-15 | Claude binary's own dependencies are outside our lockfile | Info | Accepted |
| T3-16 | Other high/critical dependency advisories in the lockfile | High | Fixed for the server path; rest Open |

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
| GitHub releases / API: CLI update, pinned runtime | `cli/update.ts`, `cloud/pinnedRuntime.ts`, `shared/cliRelease.ts` | on `t3 update` / service install | Not run; firewall; `server.updateServer` needs `environment:maintain` |
| npm registry (`registry.npmjs.org/t3`) | `cloud/npmRelease.ts` | on client request | Firewall. Note: `server.getNpmRelease` needs only `orchestration:read` |
| Chrome for Testing (`storage.googleapis.com`) | `preview/PreviewBrowser.ts` | when the preview browser is first used | `enableAgentBrowserAccess=false`, firewall |
| ACP registry CDN | `packages/contracts/acpRegistry.ts` | when the ACP registry is browsed | Driver disabled, firewall |
| Provider sign-in hosts (OpenAI, ChatGPT, Google, x.ai, Cursor, OpenCode) | provider packages | when those drivers run | Drivers disabled; Cursor removed (T3-04); firewall |
| Source-control hosts (GitHub, GitLab, Bitbucket, Gitea, Codeberg) | `packages/source-control-*` | on PR and clone features | Separate `git`/`gh` programs (T3-03); those RPCs need `source-control:write` |
| Tailscale | `packages/tailscale` (local `tailscale` CLI) | off | `T3CODE_TAILSCALE_SERVE=false` |
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

### T3-06 Full access by default, no admin lock (High, Mitigated)

Upstream `DEFAULT_RUNTIME_MODE` is `full-access`, and T3 has no admin policy file
(tailor/policy/README.md). Any client with `orchestration:operate` can create a
thread in any runtime mode or switch one (`thread.runtime-mode.set`).

Fixes in this PR:
- The Claude instance's `settings.json` (installed read-only to non-admins) disables
  Bypass and Auto. T3 already downgraded Full access when Bypass is disabled. But T3
  passes `settingSources: ["project", "local"]` for a custom Claude home, so the
  Claude binary never reads that file, and a requested **Auto** ran as Auto. The fork
  now reads the custom home's `settings.json` for a requested Auto and runs it as
  Supervised when Auto is disabled or the file is unreadable (`queryPolicyForTurn` and
  `claudeRuntimeQueryPolicyForRuntimePolicy` in `ClaudeAdapterV2.ts`; test
  `apps/server/src/tailor/claudeModeCap.test.ts`). Project, local and managed
  settings keep upstream behaviour: Claude enforces those itself.
- The settings seed sets `defaultRuntimeMode: approval-required`; the connector always
  sends `approval-required`.

Residual: the cap is Auto-accept edits (Claude has no switch to disable it); a
project-level `.claude/settings.json` in a repository could re-enable modes for the
Claude binary but not T3's downgrade; other drivers would not honour the cap (they
are disabled).

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

### T3-09 No Origin check on the WebSocket upgrade (Medium, Open)

`/ws` authenticates with a short-lived ticket, a bearer token, or the browser session
cookie (`EnvironmentAuth.authenticateWebSocketUpgrade`). No Origin allowlist was
found; outside dev mode the HTTP API sends wildcard CORS without credentials. A
malicious web page opening `ws://127.0.0.1:<port>/ws` is stopped only by the cookie's
`SameSite=Lax`, which current browsers apply to cross-site WebSocket handshakes.
Verify during T3-01 from a cross-origin page; follow-up: reject upgrades whose
Origin is not the server's own.

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

### T3-16 Other dependency advisories (High; Fixed for the server path, rest Open)

Once forked, Dependabot listed 328 open alerts on `v0.1.6` (most in the vendored
`.repos/` reference checkouts, the mobile app and build tooling). The high and
critical ones in the root lockfile, triaged by whether the server or the web UI it
serves loads them:

| Package | Advisories | In the server path | Action |
| --- | --- | --- | --- |
| `undici` 8.11.2 | GHSA-qrxm-fqhp-jwvm, GHSA-xjj6-f33q-929c, GHSA-2m5v-pch6-74hx, GHSA-4w7w-5xrc-9h26 | yes (server HTTP client) | Catalog bumped to 8.12.2 |
| `zod` 4.6.5 | GHSA-mrhx-c7xc-m3w5 | yes (agent SDK, MCP SDK) | Override 4.6.6 |
| `dompurify` 3.4.16 | GHSA-cg2g-xh64-v4q7, GHSA-mrv2-3pqr-j5jr | web UI served to the local browser, which holds full scopes | Override 3.4.17 |
| `seroval` 1.5.4 | GHSA-p6vx-979v-rg4c (9.8) and four more | web UI router (client-side serialisation) | Open: minor bump to 1.6.8 needs the router tested |
| `shell-quote` 1.10.0 | GHSA-pqg4-j6r4-53mv (8.1) | no (React DevTools, development) | Open, not shipped in the server |
| `undici` 7.x | as above | no (Electron download at build time) | Open, build only |
| `node-forge`, `sharp`, `path-to-regexp` 6.1.0, `body-parser` | various | no (mobile, marketing and build tooling) | Open, not shipped in the server |

Follow-up: a Dependabot or `pnpm audit --prod` step scoped to the server and web
packages in the gate.

## What was verified

- Locally on Windows: the full contracts suite with the contract test, the server
  scope and Claude mode cap tests, `RpcAuthorization`, `AnalyticsService` and the
  provider registry tests with the Cursor driver off; the installer with `-WhatIf`
  under PowerShell 7 and Windows PowerShell 5.1, and its address arithmetic.
  `ClaudeAdapterV2.test.ts` has 13 failures on Windows at upstream `v0.1.6` (path and
  attachment tests) and the same 13 with this patch, so the Windows-only gate does not
  run it. The custom-home Auto read in `queryPolicyForTurn` has no integration test yet.
- Not verified: a full build, the full upstream suite, an installed `t3.exe`, the
  firewall rules applied, and the live egress capture (T3-01).
