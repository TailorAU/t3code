// @effect-diagnostics nodeBuiltinImport:off -- the junction test uses real temp folders.
/** Tailor fork (TailorAU/t3code): worktree and project paths stay inside their roots. */
import * as NodeFS from "node:fs";
import * as NodeOS from "node:os";
import * as NodePath from "node:path";
import { describe, expect, it } from "@effect/vitest";

import {
  checkProjectRoot,
  checkWorktreePath,
  managedProjectRoots,
  nodePathPolicyHost,
  type PathPolicyHost,
} from "./workspacePolicy.ts";

// A Windows-shaped host without touching the disk: nothing exists, so paths resolve lexically.
const windows: PathPolicyHost = { platform: "win32", realPath: (p) => p, exists: () => false };

const rules = {
  policyDir: "C:\\ProgramData\\T3CodePolicy",
  workspaceRoots: ["C:\\ProgramData\\T3CodePolicy\\workspaces"],
  worktreesRoot: "C:\\ProgramData\\T3CodePolicy\\t3-home\\worktrees",
};

describe("Tailor worktree paths", () => {
  it("allows the project root, its subfolders and the managed worktree root", () => {
    const root = "C:\\ProgramData\\T3CodePolicy\\workspaces\\app";
    expect(checkWorktreePath(root, root, rules, windows)).toBeUndefined();
    expect(checkWorktreePath(`${root}\\wt`, root, rules, windows)).toBeUndefined();
    expect(checkWorktreePath(`${rules.worktreesRoot}\\app-1`, root, rules, windows)).toBeUndefined();
    // Case-insensitive on Windows.
    expect(checkWorktreePath(`${root.toUpperCase()}\\WT`, root, rules, windows)).toBeUndefined();
  });

  it("refuses paths outside both roots, traversal, and the policy folder", () => {
    const root = "C:\\ProgramData\\T3CodePolicy\\workspaces\\app";
    expect(checkWorktreePath("C:\\Users\\someone\\code", root, rules, windows)).toBeDefined();
    expect(checkWorktreePath(`${root}\\..\\..\\connector`, root, rules, windows)).toBeDefined();
    expect(
      checkWorktreePath("C:\\ProgramData\\T3CodePolicy\\connector", "C:\\ProgramData", rules, windows),
    ).toBeDefined();
  });

  it("follows junctions to their real target", () => {
    const base = NodeFS.mkdtempSync(NodePath.join(NodeOS.tmpdir(), "t3-ws-"));
    const project = NodePath.join(base, "project");
    const outside = NodePath.join(base, "outside");
    NodeFS.mkdirSync(project);
    NodeFS.mkdirSync(outside);
    const link = NodePath.join(project, "link");
    NodeFS.symlinkSync(outside, link, "junction");
    const local = { policyDir: undefined, workspaceRoots: undefined, worktreesRoot: NodePath.join(base, "wt") };
    expect(checkWorktreePath(NodePath.join(project, "real"), project, local, nodePathPolicyHost)).toBeUndefined();
    expect(checkWorktreePath(link, project, local, nodePathPolicyHost)).toBeDefined();
    expect(checkWorktreePath(NodePath.join(link, "deeper"), project, local, nodePathPolicyHost)).toBeDefined();
  });
});

describe("Tailor project roots", () => {
  const managed = managedProjectRoots("C:\\ProgramData\\T3CodePolicy\\t3-home", "win32");

  it("allows the workspace roots and T3's managed project folders", () => {
    expect(checkProjectRoot(`${rules.workspaceRoots[0]}\\app`, managed, rules, windows)).toBeUndefined();
    expect(checkProjectRoot(`${managed[0]}\\note`, managed, rules, windows)).toBeUndefined();
  });

  it("refuses anything else when the policy is installed, and the policy folder always", () => {
    expect(checkProjectRoot("D:\\code\\app", managed, rules, windows)).toBeDefined();
    expect(checkProjectRoot("C:\\ProgramData\\T3CodePolicy\\installer", managed, rules, windows)).toBeDefined();
    const noPolicy = { ...rules, workspaceRoots: undefined };
    expect(checkProjectRoot("D:\\code\\app", managed, noPolicy, windows)).toBeUndefined();
    expect(checkProjectRoot("C:\\ProgramData\\T3CodePolicy\\connector", managed, noPolicy, windows)).toBeDefined();
  });
});
