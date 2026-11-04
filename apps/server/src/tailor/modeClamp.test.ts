// @effect-diagnostics nodeBuiltinImport:off -- the test reads source files to pin the clamp call sites.
/**
 * Tailor fork (TailorAU/t3code): the compile-time runtime-mode ceiling. No thread, setting,
 * launch or MCP caller is ever above auto-accept-edits, so T3's own environment-writing MCP
 * tools (which need a full-access caller) are always refused.
 */
import * as NodeFS from "node:fs";
import * as NodePath from "node:path";
import { clampRuntimeMode, DEFAULT_RUNTIME_MODE, TAILOR_MAX_RUNTIME_MODE } from "@t3tools/contracts";
import { describe, expect, it } from "@effect/vitest";

import * as McpInvocationContext from "../mcp/McpInvocationContext.ts";

const source = (relative: string) =>
  NodeFS.readFileSync(NodePath.join(import.meta.dirname, "..", relative), "utf8");

describe("Tailor runtime-mode ceiling", () => {
  it("defaults to Supervised and caps at Auto-accept edits", () => {
    expect(DEFAULT_RUNTIME_MODE).toBe("approval-required");
    expect(TAILOR_MAX_RUNTIME_MODE).toBe("auto-accept-edits");
    expect(clampRuntimeMode("full-access")).toBe("auto-accept-edits");
    expect(clampRuntimeMode("auto")).toBe("auto-accept-edits");
    expect(clampRuntimeMode("auto-accept-edits")).toBe("auto-accept-edits");
    expect(clampRuntimeMode("approval-required")).toBe("approval-required");
  });

  it("never approves an MCP client above the ceiling", () => {
    const ceiling = McpInvocationContext.clientModeCeiling({
      access: "full-access",
    } as unknown as Parameters<typeof McpInvocationContext.clientModeCeiling>[0]);
    expect(ceiling.runtimeMode).toBe("auto-accept-edits");
  });

  it("keeps the environment-writing tools behind the full-access check", () => {
    // McpToolAccess.writesEnvironment refuses any caller that is not full-access/default,
    // which the ceiling makes impossible (McpToolAccess.test.ts covers the refusal itself).
    const project = source("mcp/toolkits/project/handlers.ts");
    const environment = source("mcp/toolkits/environment/handlers.ts");
    expect(project).toMatch(/t3_project_update: McpToolAccess\.writesEnvironment\(/);
    expect(project).toMatch(/t3_project_clone: McpToolAccess\.writesEnvironment\(/);
    expect(environment).toMatch(
      /t3_environment_preferences_update: McpToolAccess\.writesEnvironment\(/,
    );
  });

  it("clamps at every entry point", () => {
    expect(source("orchestration-v2/Orchestrator.ts")).toMatch(
      /dispatchWithReceipt\(clampCommandRuntimeMode\(command\)\)/,
    );
    expect(source("ws.ts")).toMatch(/runtimeMode: clampRuntimeMode\(input\.runtimeMode\)/);
    expect(source("orchestration-v2/RuntimePolicy.ts")).toMatch(/clampRuntimeMode\(runtimeMode\)/);
    expect(source("serverSettings.ts")).toMatch(/clampRuntimeMode\(resolved\.defaultRuntimeMode\)/);
    expect(source("mcp/threadAccess.ts")).toMatch(/clampRuntimeMode\(caller\.runtimeMode\)/);
    expect(source("mcp/OrchestratorMcpService.ts")).toMatch(
      /clampRuntimeMode\(parent\.thread\.runtimeMode\)/,
    );
  });
});
