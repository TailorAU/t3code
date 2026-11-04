/**
 * Tailor fork (TailorAU/t3code): every Claude query ignores repository and user settings,
 * hooks and MCP files, cannot raise its permission mode, carries compiled deny rules, and
 * never grants a standing permission.
 */
import { assert, describe, it } from "@effect/vitest";

import * as ClaudeAdapterV2 from "../orchestration-v2/Adapters/ClaudeAdapterV2.ts";

const baseOptions = {
  model: "claude-opus-5-5",
  tools: { type: "preset", preset: "claude_code" },
  permissionMode: "bypassPermissions",
  allowDangerouslySkipPermissions: true,
  disallowedTools: ["Bash(rm:*)"],
} as unknown as ClaudeAdapterV2.ClaudeAgentSdkQueryOptions;

describe("Tailor Claude query lock", () => {
  it("loads no filesystem settings and only T3's MCP servers", () => {
    const locked = ClaudeAdapterV2.tailorLockClaudeQueryOptions(baseOptions, "default");
    assert.deepEqual(locked.settingSources, []);
    assert.strictEqual(locked.strictMcpConfig, true);
  });

  it("cannot be raised to Bypass or Auto", () => {
    for (const mode of ["bypassPermissions", "auto"] as const) {
      const locked = ClaudeAdapterV2.tailorLockClaudeQueryOptions(baseOptions, mode);
      assert.strictEqual(locked.permissionMode, "default");
      assert.isUndefined(locked.allowDangerouslySkipPermissions);
    }
    assert.strictEqual(
      ClaudeAdapterV2.tailorLockClaudeQueryOptions(baseOptions, "acceptEdits").permissionMode,
      "acceptEdits",
    );
  });

  it("disallows web tools and keeps existing denials", () => {
    const locked = ClaudeAdapterV2.tailorLockClaudeQueryOptions(baseOptions, "default");
    for (const tool of ["WebSearch", "WebFetch", "Bash(rm:*)"]) {
      assert.include(locked.disallowedTools ?? [], tool);
    }
  });

  it("denies edits to Claude and MCP config and all access to the T3 home", () => {
    const locked = ClaudeAdapterV2.tailorLockClaudeQueryOptions(baseOptions, "default", {
      T3CODE_HOME: "C:\\Data\\t3-home",
    });
    const deny = (locked.managedSettings as { permissions: { deny: string[] } }).permissions.deny;
    for (const rule of [
      "Edit(**/.claude/**)",
      "Write(**/.claude/**)",
      "Edit(**/.mcp.json)",
      "Write(**/.mcp.json)",
      "Read(~/.t3/**)",
      "Edit(~/.t3/**)",
      "Read(//c/Data/t3-home/**)",
      "Write(//c/Data/t3-home/**)",
    ]) {
      assert.include(deny, rule);
    }
  });

  it("pre-approves only T3's read-only MCP tools", () => {
    const overrides = ClaudeAdapterV2.claudeMcpQueryOverrides({
      mcpSession: {
        endpoint: "http://127.0.0.1:1/mcp",
        authorizationHeader: "Bearer test",
      } as never,
      readOnlySandbox: false,
    });
    assert.notInclude(overrides.allowedTools ?? [], ClaudeAdapterV2.CLAUDE_T3_MCP_TOOL_WILDCARD);
    assert.deepEqual(
      [...(overrides.allowedTools ?? [])].sort(),
      [...ClaudeAdapterV2.CLAUDE_READ_ONLY_T3_MCP_ALLOWED_TOOLS].sort(),
    );
  });

  it("turns 'accept for session' into a one-time approval", () => {
    const result = ClaudeAdapterV2.permissionResultFromDecision({
      toolName: "Bash",
      decision: "acceptForSession",
      toolInput: { command: "git status" },
      toolUseID: "tool-1",
      suggestions: [],
    }) as { behavior: string; updatedPermissions?: unknown; decisionClassification?: string };
    assert.strictEqual(result.behavior, "allow");
    assert.isUndefined(result.updatedPermissions);
    assert.strictEqual(result.decisionClassification, "user_temporary");
    const always = ClaudeAdapterV2.permissionResultFromDecision({
      toolName: "Bash",
      decision: "acceptAlways",
      toolInput: {},
      toolUseID: "tool-2",
    }) as { behavior: string };
    assert.strictEqual(always.behavior, "deny");
  });

  it("reads the installed policy's Claude home and binary, failing closed", () => {
    assert.strictEqual(
      ClaudeAdapterV2.tailorPolicyMarkerPath("win32", { ProgramData: "C:\\ProgramData" }),
      "C:\\ProgramData\\T3CodePolicy\\t3-policy.json",
    );
    assert.deepEqual(
      ClaudeAdapterV2.tailorInstalledClaudePaths(
        JSON.stringify({ installed: { claudeConfigDir: "C:\\p\\home", claudeExe: "C:\\p\\c.exe" } }),
      ),
      { claudeConfigDir: "C:\\p\\home", claudeExe: "C:\\p\\c.exe" },
    );
    assert.isNull(ClaudeAdapterV2.tailorInstalledClaudePaths("{}"));
    assert.isNull(ClaudeAdapterV2.tailorInstalledClaudePaths("not json"));
  });
});
