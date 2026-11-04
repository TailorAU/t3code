# Tailor fork of T3 Code

`TailorAU/t3code` is a public fork of [pingdotgg/t3code](https://github.com/pingdotgg/t3code)
(MIT, see `LICENSE`). `tailor/main` is upstream tag `v0.1.6` plus reviewed patches;
it moves to a new upstream version only through a reviewed bump PR. Never auto-update.

The fork runs T3 Code's server as a local agent harness behind a supervising
connector: loopback only, Supervised by default, egress limited to the model endpoint.

| Path | What |
| --- | --- |
| `tailor/SECURITY-REVIEW.md` | Adversarial review of the server at v0.1.6 and this patch; findings and status |
| `tailor/policy/` | Lock-down policy template, the one-time installer and the provider configuration |
| `tailor/contract/connector-rpc-contract.json` | The RPCs, fields and scopes the connector depends on |
| `packages/contracts/src/tailorConnectorContract.test.ts` | Fails when an upstream bump changes the connector contract |
| `apps/server/src/tailor/` | Scope and mode-cap tests |
| `.github/workflows/tailor-gate.yml` | Required check on `tailor/main` (Windows and Linux) |

Patches to upstream code, each marked `Tailor fork` in a comment:

- `pnpm-workspace.yaml`: `@modelcontextprotocol/sdk` 1.32.2 and `proxy-addr` 2.0.8 overrides.
- `apps/server/src/provider/builtInDrivers.ts`: Cursor driver off at compile time.
- `apps/server/src/telemetry/AnalyticsService.ts`: analytics default off.
- `apps/server/src/orchestration-v2/Adapters/ClaudeAdapterV2.ts`: disabled Auto mode caps a requested Auto.

## Bumping upstream

1. Branch from `tailor/main`, merge the new upstream tag.
2. Re-apply the overrides and check the advisories again.
3. Run the gate. A failing contract test means the connector adapter must change in
   the same PR; update `tailor/contract/connector-rpc-contract.json` only then.
4. Redo the security review for the diff, including a new egress capture.
