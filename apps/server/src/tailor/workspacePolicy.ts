// @effect-diagnostics nodeBuiltinImport:off -- real-path resolution must follow junctions synchronously.
/**
 * Tailor fork (TailorAU/t3code): where a project or worktree may live.
 *
 * - A thread's worktree must be inside its project root or T3's managed worktree root.
 * - With the machine policy installed, a project must be inside a configured workspace root
 *   (the installer creates %ProgramData%\T3CodePolicy\workspaces for t3agent only) or T3's own
 *   managed project folders under its base dir.
 * - Nothing may sit in the policy folder itself, other than those roots.
 *
 * Paths are compared after resolving the real path (junctions and symbolic links followed;
 * for a path that does not exist yet, its nearest existing ancestor), case-insensitively on
 * Windows.
 */
import * as NodeFS from "node:fs";
import * as NodePath from "node:path";

export interface PathPolicyHost {
  readonly platform: string;
  readonly realPath: (path: string) => string;
  readonly exists: (path: string) => boolean;
}

export const nodePathPolicyHost: PathPolicyHost = {
  platform: process.platform,
  realPath: (path) => NodeFS.realpathSync.native(path),
  exists: (path) => NodeFS.existsSync(path),
};

const pathApi = (platform: string) => (platform === "win32" ? NodePath.win32 : NodePath.posix);

/** The real path; for a missing path, the real path of its nearest existing ancestor plus the rest. */
export function resolveRealPath(path: string, host: PathPolicyHost): string {
  const api = pathApi(host.platform);
  let current = api.resolve(path);
  const rest: string[] = [];
  for (;;) {
    if (host.exists(current)) {
      return api.join(host.realPath(current), ...rest.reverse());
    }
    const parent = api.dirname(current);
    if (parent === current) return api.join(current, ...rest.reverse());
    rest.push(api.basename(current));
    current = parent;
  }
}

export function isInside(child: string, parent: string, host: PathPolicyHost): boolean {
  const api = pathApi(host.platform);
  const fold = (value: string) => (host.platform === "win32" ? value.toLowerCase() : value);
  const relative = api.relative(fold(resolveRealPath(parent, host)), fold(resolveRealPath(child, host)));
  return relative === "" || (!relative.startsWith("..") && !api.isAbsolute(relative));
}

export interface TailorPathRules {
  /** The policy folder (refused unless inside an allowed root). */
  readonly policyDir: string | undefined;
  /** Allowed project roots when the policy is installed; undefined means no restriction. */
  readonly workspaceRoots: ReadonlyArray<string> | undefined;
  /** T3's managed worktree root (ServerConfig.worktreesDir). */
  readonly worktreesRoot: string;
}

/** Refusal reason for a worktree path, or undefined when it is allowed. */
export function checkWorktreePath(
  worktreePath: string,
  projectRoot: string,
  rules: TailorPathRules,
  host: PathPolicyHost = nodePathPolicyHost,
): string | undefined {
  const inProject = isInside(worktreePath, projectRoot, host);
  const inManaged = isInside(worktreePath, rules.worktreesRoot, host);
  if (!inProject && !inManaged) {
    return "The worktree must be inside the project folder or T3's managed worktree folder.";
  }
  if (rules.policyDir !== undefined && isInside(worktreePath, rules.policyDir, host) && !inManaged) {
    const allowedByRoot = (rules.workspaceRoots ?? []).some((root) => isInside(worktreePath, root, host));
    if (!allowedByRoot) return "The worktree may not be inside the T3 policy folder.";
  }
  return undefined;
}

/** Refusal reason for a project root, or undefined when it is allowed. */
export function checkProjectRoot(
  workspaceRoot: string,
  managedProjectRoots: ReadonlyArray<string>,
  rules: TailorPathRules,
  host: PathPolicyHost = nodePathPolicyHost,
): string | undefined {
  const allowed = [...(rules.workspaceRoots ?? []), ...managedProjectRoots];
  const inAllowed = allowed.some((root) => isInside(workspaceRoot, root, host));
  if (rules.workspaceRoots !== undefined && !inAllowed) {
    return "With the machine policy installed, projects must be inside a configured workspace root.";
  }
  if (rules.policyDir !== undefined && isInside(workspaceRoot, rules.policyDir, host) && !inAllowed) {
    return "A project may not be inside the T3 policy folder.";
  }
  return undefined;
}

/** T3's own managed project folders under its base dir (ManagedProjectFolders.ts). */
export function managedProjectRoots(
  baseDir: string,
  platform: string = process.platform,
): ReadonlyArray<string> {
  const api = pathApi(platform);
  return [api.resolve(baseDir, "projects"), api.resolve(baseDir, "scratch")];
}
