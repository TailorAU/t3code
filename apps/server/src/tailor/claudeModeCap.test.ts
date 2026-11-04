/**
 * Tailor fork (TailorAU/t3code): with Bypass and Auto disabled in the Claude
 * instance's managed settings (tailor/policy), no runtime mode reaches a Claude
 * permission mode above acceptEdits, and every capped mode keeps approval prompts.
 */
import * as ProviderAdapter from "@t3tools/provider-core/server/ProviderAdapter";
import { assert, describe, it } from "@effect/vitest";

import * as ClaudeAdapterV2 from "../orchestration-v2/Adapters/ClaudeAdapterV2.ts";

const policyFor = (runtimeMode: "approval-required" | "auto-accept-edits" | "auto" | "full-access") =>
  ProviderAdapter.ProviderAdapterV2RuntimePolicy.make({
    runtimeMode,
    interactionMode: "default",
    cwd: "/workspace",
  });

const locked = { bypassDisabled: true, autoDisabled: true };

describe("Tailor Claude mode cap", () => {
  it("runs Full access and Auto as Supervised when both are disabled", () => {
    for (const mode of ["full-access", "auto"] as const) {
      const queryPolicy = ClaudeAdapterV2.claudeRuntimeQueryPolicyForRuntimePolicy(
        policyFor(mode),
        locked,
      );
      assert.strictEqual(queryPolicy.permissionMode, "default", mode);
      assert.isTrue(queryPolicy.installPermissionCallback, mode);
      assert.isUndefined(queryPolicy.allowDangerouslySkipPermissions, mode);
    }
  });

  it("leaves Supervised and Auto-accept edits as they are", () => {
    assert.strictEqual(
      ClaudeAdapterV2.claudeRuntimeQueryPolicyForRuntimePolicy(policyFor("approval-required"), locked)
        .permissionMode,
      "default",
    );
    assert.strictEqual(
      ClaudeAdapterV2.claudeRuntimeQueryPolicyForRuntimePolicy(policyFor("auto-accept-edits"), locked)
        .permissionMode,
      "acceptEdits",
    );
  });

  it("keeps upstream behaviour when nothing is disabled", () => {
    assert.strictEqual(
      ClaudeAdapterV2.claudeRuntimeQueryPolicyForRuntimePolicy(policyFor("auto")).permissionMode,
      "auto",
    );
  });
});
