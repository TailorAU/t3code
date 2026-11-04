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
    // The build ceiling is Supervised: acceptEdits is capped too.
    assert.strictEqual(
      ClaudeAdapterV2.tailorLockClaudeQueryOptions(baseOptions, "acceptEdits").permissionMode,
      "default",
    );
    assert.strictEqual(
      ClaudeAdapterV2.tailorLockClaudeQueryOptions(baseOptions, "plan").permissionMode,
      "plan",
    );
  });

  it("puts the denies in the flag tier as well as managedSettings", () => {
    // SDK 0.3.276 drops managedSettings under a machine tier without parentSettingsBehavior
    // "merge", so the flag tier must carry the same rules.
    const locked = ClaudeAdapterV2.tailorLockClaudeQueryOptions(
      { ...baseOptions, settings: { permissions: { deny: ["Read(./secret)"] } } } as never,
      "default",
    );
    const flag = (locked.settings as { permissions: { deny: string[] } }).permissions.deny;
    const managed = (locked.managedSettings as { permissions: { deny: string[] } }).permissions.deny;
    for (const rule of managed) assert.include(flag, rule);
    assert.include(flag, "Read(./secret)");
    for (const rule of ["Edit(**/.git/hooks/**)", "Write(**/.git/config)", "Edit(**/.githooks/**)"]) {
      assert.include(flag, rule);
    }
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
      "Read(~/.t3/userdata/*.sqlite*)",
      "Read(~/.t3/userdata/secrets/**)",
      "Edit(~/.t3/**)",
      "Write(~/.t3/**)",
      "Read(//c/Data/t3-home/userdata/secrets/**)",
      "Write(//c/Data/t3-home/**)",
    ]) {
      assert.include(deny, rule);
    }
    // Attachments under the base dir stay readable.
    assert.isUndefined(deny.find((rule) => rule.startsWith("Read(") && rule.includes("attachments")));
    assert.isUndefined(deny.find((rule) => rule === "Read(~/.t3/**)"));
  });

  it("follows the server's real base dir and the resolved Claude home", () => {
    const locked = ClaudeAdapterV2.tailorLockClaudeQueryOptions(baseOptions, "default", {}, {
      t3BaseDir: "D:\\T3\\base",
      claudeHome: "C:\\ProgramData\\T3CodePolicy\\claude-home",
    });
    const deny = (locked.managedSettings as { permissions: { deny: string[] } }).permissions.deny;
    for (const rule of [
      "Read(//d/T3/base/userdata/*.sqlite*)",
      "Edit(//d/T3/base/**)",
      "Edit(//c/ProgramData/T3CodePolicy/claude-home/**)",
      "Read(//c/ProgramData/T3CodePolicy/claude-home/.claude.json)",
      "Read(//c/ProgramData/T3CodePolicy/claude-home/remote-settings.json)",
    ]) {
      assert.include(deny, rule);
    }
    assert.strictEqual(locked.strictMcpConfig, true);
    const managed = ClaudeAdapterV2.tailorLockClaudeQueryOptions(baseOptions, "default", {}, {
      managedMcpConfig: true,
    });
    // Next to an administrator's managed-mcp.json Claude rejects the flag; that file governs MCP.
    assert.isUndefined(managed.strictMcpConfig);
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
});
