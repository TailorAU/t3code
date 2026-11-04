# Tailor fork of T3 Code

`TailorAU/t3code` is a public fork of [pingdotgg/t3code](https://github.com/pingdotgg/t3code)
(MIT, see `LICENSE`). `tailor/main` is upstream tag `v0.1.6` plus reviewed patches;
it moves to a new upstream version only through a reviewed bump PR. Never auto-update.

The fork runs T3 Code's server as a local agent harness behind a supervising
connector: loopback only, Supervised as the compile-time ceiling, egress limited to the model endpoint.

| Path | What |
| --- | --- |
| `tailor/SECURITY-REVIEW.md` | Adversarial review of the server at v0.1.6 and this patch; findings and status |
| `tailor/policy/` | Lock-down policy template, the installer (service accounts `t3agent` and `t3bridge`, protected folders, token issuer and mover, firewall, machine-wide deny entries), the self-check `verify-install.ps1` and the provider configuration |
| `tailor/contract/connector-rpc-contract.json` | The RPCs, fields and scopes the connector depends on |
| `packages/contracts/src/tailorConnectorContract.test.ts` | Fails when an upstream bump changes the connector contract |
| `apps/server/src/tailor/` | Machine policy, deny rules, git hardening, workspace paths, and their tests |
| `.github/workflows/tailor-gate.yml` | Required check on `tailor/main` (Windows) |

Patches to upstream code, each marked `Tailor fork` in a comment:

- `pnpm-workspace.yaml`: advisory overrides (`@modelcontextprotocol/sdk` 1.32.2, `proxy-addr` 2.0.8, `zod` 4.6.6, `dompurify` 3.4.17) and `undici` 8.12.2 in the catalog.
- `packages/contracts/src/providerPolicy.ts`: Supervised default and the compile-time Supervised ceiling (`clampRuntimeMode`), applied in `Orchestrator.ts`, `ws.ts`, `RuntimePolicy.ts`, `serverSettings.ts` and the MCP access code.
- `apps/server/src/orchestration-v2/Adapters/ClaudeAdapterV2.ts`: query lock (no settings files, strict MCP, capped mode, compiled deny rules, no web tools), fail-closed policy guard, no standing grants, read-only T3 tools pre-approved only, Auto cap from the Claude home.
- `apps/server/src/provider/builtInDrivers.ts`: Claude driver only.
- `apps/server/src/provider/Drivers/ClaudeDriver.ts`, `apps/server/src/tailor/machinePolicy.ts`: the machine policy sets the Claude binary and home, launch arguments are ignored, instance variables are allowlisted, Windows refuses to run without the policy.
- `packages/contracts/src/auth.ts`, `apps/server/src/auth/RpcAuthorization.ts`: the `tailor:connector` scope.
- `apps/server/src/cli/auth.ts`: `t3 auth rotate-signing-keys` for the emergency revoke (`tailor/signingKeys.ts`).
- `apps/server/src/cli/config.ts`: loopback bind by default.
- `apps/server/src/server.ts`, `apps/server/src/bin.ts`: every git command hardened (`tailor/gitSpawner.ts`, `tailor/gitHardening.ts`).
- `apps/server/src/ws.ts`: worktree and project paths checked (`tailor/workspacePolicy.ts`).
- `apps/server/src/orchestration-v2/Orchestrator.ts`, `apps/server/src/mcp/toolkits/project/handlers.ts`: worktree paths checked for every command and MCP launch.
- `apps/server/src/textGeneration/ClaudeTextGeneration.ts`: `claude -p` with no setting sources, in a temporary folder, git-hardened, and read-only tools for the review-guide run.
- `apps/server/src/telemetry/AnalyticsService.ts`: analytics default off.
- `apps/server/src/http.ts`: web app CSP; agent HTML only inside a frame, otherwise a download. `packages/shared/src/favicon.ts`, `apps/web/src/openVsxThemes.ts`: third-party fetches off.
- `apps/server/vite.config.ts`, `apps/web/vite.config.ts`: build refuses Clerk and relay values (`tailor/build/`).
- `.github/workflows/`: only `tailor-gate.yml`, actions pinned by SHA.

## Bumping upstream

1. Branch from `tailor/main`, merge the new upstream tag.
2. Re-apply the overrides and check the advisories again.
3. Run the gate. A failing contract test means the connector adapter must change in
   the same PR; update `tailor/contract/connector-rpc-contract.json` only then.
4. Redo the security review for the diff, including a new egress capture.
