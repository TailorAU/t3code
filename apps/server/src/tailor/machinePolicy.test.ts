// @effect-diagnostics nodeBuiltinImport:off -- fixtures are plain temp files.
/** Tailor fork (TailorAU/t3code): the machine policy reader fails closed. */
import * as NodeFS from "node:fs";
import * as NodeOS from "node:os";
import * as NodePath from "node:path";
import { describe, expect, it } from "@effect/vitest";

import * as TailorMachinePolicy from "./machinePolicy.ts";

const fixture = (contents: string | null) => {
  const dir = NodeFS.mkdtempSync(NodePath.join(NodeOS.tmpdir(), "t3-policy-"));
  const file = NodePath.join(dir, "t3-policy.json");
  if (contents !== null) NodeFS.writeFileSync(file, contents);
  return file;
};

describe("Tailor machine policy", () => {
  it("is absent only when the file does not exist", () => {
    expect(TailorMachinePolicy.readTailorPolicyAt(fixture(null))._tag).toBe("absent");
  });

  it("is invalid when unreadable, malformed or incomplete", () => {
    expect(TailorMachinePolicy.readTailorPolicyAt(fixture("{ nope"))._tag).toBe("invalid");
    expect(TailorMachinePolicy.readTailorPolicyAt(fixture("{}"))._tag).toBe("invalid");
    expect(TailorMachinePolicy.readTailorPolicyAt(undefined)._tag).toBe("invalid");
    const dir = NodeFS.mkdtempSync(NodePath.join(NodeOS.tmpdir(), "t3-policy-dir-"));
    expect(TailorMachinePolicy.readTailorPolicyAt(dir)._tag).toBe("invalid");
  });

  it("reads the installed block and only ever narrows the environment allowlist", () => {
    const state = TailorMachinePolicy.readTailorPolicyAt(
      fixture(
        JSON.stringify({
          installed: {
            claudeConfigDir: "/policy/claude-home",
            claudeExe: "/opt/claude/claude",
            claudeExeSha256: "ABC",
            instanceEnvironmentAllowlist: ["ANTHROPIC_API_KEY", "NODE_OPTIONS", "PATH"],
          },
        }),
      ),
    );
    expect(state._tag).toBe("installed");
    if (state._tag !== "installed") return;
    expect(state.policy.claudeExeSha256).toBe("abc");
    expect(state.policy.instanceEnvironmentAllowlist).toEqual(["ANTHROPIC_API_KEY"]);
  });

  it("drops instance variables outside the allowlist", () => {
    const filtered = TailorMachinePolicy.filterInstanceEnvironment([
      { name: "ANTHROPIC_API_KEY", value: "x" },
      { name: "NODE_OPTIONS", value: "--require evil" },
      { name: "HTTPS_PROXY", value: "http://evil" },
      { name: "CLAUDE_CONFIG_DIR", value: "/elsewhere" },
    ]);
    expect(filtered?.map((variable) => variable.name)).toEqual(["ANTHROPIC_API_KEY"]);
  });

  it("hashes a file", async () => {
    const file = fixture("abc");
    expect(await TailorMachinePolicy.sha256File(file)).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("compares Windows paths case-insensitively", () => {
    expect(TailorMachinePolicy.samePath("win32", "C:\P\Claude.exe", "c:\p\claude.exe")).toBe(true);
    expect(TailorMachinePolicy.samePath("linux", "/a/B", "/a/b")).toBe(false);
  });
});
