// @effect-diagnostics nodeBuiltinImport:off -- executable and .git checks are synchronous file reads.
/**
 * Tailor fork (TailorAU/t3code): a ChildProcessSpawner decorator that every command T3 starts
 * goes through (server.ts layers it over the platform spawner).
 *
 * - On Windows, a bare command name is never resolved in the working directory: Windows
 *   (and libuv) would otherwise run a planted `git.exe` from the repository root. The command
 *   is resolved to an absolute path from PATH's absolute entries only, and
 *   `NoDefaultCurrentDirectoryInExePath=1` is set for the child (cmd.exe honours it when a
 *   command runs through a shell).
 * - With the machine policy installed, `git` is always the policy's absolute `gitExe`; a policy
 *   without one makes every git call fail.
 * - Every git command gets the hardening (gitHardening.ts).
 * - Before a git command runs in a working tree whose `.git` is a file (a linked worktree or a
 *   submodule), the `gitdir:` it names must resolve (real path) to `<repo>/.git/worktrees/<n>`
 *   or `<repo>/.git/modules/<n>`, and with the policy installed that repository must be in a
 *   workspace root or the T3 home. Otherwise the command is refused.
 */
import * as NodeFS from "node:fs";
import * as NodePath from "node:path";

import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import { ChildProcess, ChildProcessSpawner } from "effect/process";

import { isGitExecutable, withTailorGitArgs, withTailorGitConfig } from "./gitHardening.ts";
import * as TailorMachinePolicy from "./machinePolicy.ts";
import { isInside, nodePathPolicyHost } from "./workspacePolicy.ts";

type Command = Parameters<ChildProcessSpawner.ChildProcessSpawner["Service"]["spawn"]>[0];

/** A path no file can have: spawning it fails instead of searching anywhere. */
export const TAILOR_UNRESOLVED_COMMAND = "C:\\T3CodePolicy-refused\\command-not-allowed.exe";

export interface SpawnPolicy {
  readonly platform: string;
  /** The policy's git.exe; null when the policy is installed without one; undefined without a policy. */
  readonly gitExe: string | null | undefined;
  /** Workspace roots when the policy is installed. */
  readonly workspaceRoots: ReadonlyArray<string> | undefined;
  readonly isFile: (path: string) => boolean;
  readonly readText: (path: string) => string | undefined;
  readonly realPath: (path: string) => string | undefined;
}

export function currentSpawnPolicy(): SpawnPolicy {
  const state =
    process.platform === "win32"
      ? TailorMachinePolicy.readTailorPolicy(process.platform)
      : { _tag: "absent" as const };
  return {
    platform: process.platform,
    gitExe: state._tag === "installed" ? (state.policy.gitExe ?? null) : undefined,
    workspaceRoots: state._tag === "installed" ? state.policy.workspaceRoots : undefined,
    isFile: (path) => {
      try {
        return NodeFS.statSync(path).isFile();
      } catch {
        return false;
      }
    },
    readText: (path) => {
      try {
        return NodeFS.readFileSync(path, "utf8");
      } catch {
        return undefined;
      }
    },
    realPath: (path) => {
      try {
        return NodeFS.realpathSync.native(path);
      } catch {
        return undefined;
      }
    },
  };
}

function envOf(command: Extract<Command, { _tag: "StandardCommand" }>) {
  const options = command.options;
  return options.env === undefined
    ? process.env
    : options.extendEnv === true
      ? { ...process.env, ...options.env }
      : options.env;
}

/** Resolves a bare command name from PATH's absolute entries only (never the working directory). */
export function resolveFromPath(
  name: string,
  env: Readonly<Record<string, string | undefined>>,
  policy: Pick<SpawnPolicy, "isFile">,
): string | undefined {
  const pathValue = env.PATH ?? env.Path ?? env.path ?? "";
  const extensions = (env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD")
    .split(";")
    .map((ext) => ext.trim().toLowerCase())
    .filter((ext) => ext.length > 0);
  const hasExtension = NodePath.win32.extname(name).length > 0;
  for (const rawDir of pathValue.split(";")) {
    const dir = rawDir.trim().replace(/^"(.*)"$/, "$1");
    // A relative PATH entry (".", "bin") is relative to the working directory: skip it.
    if (dir.length === 0 || !NodePath.win32.isAbsolute(dir)) continue;
    const candidates = hasExtension
      ? [NodePath.win32.join(dir, name)]
      : extensions.map((ext) => NodePath.win32.join(dir, `${name}${ext}`));
    for (const candidate of candidates) if (policy.isFile(candidate)) return candidate;
  }
  return undefined;
}

/**
 * Checks the `.git` of the tree a git command runs in. Returns a refusal reason, or undefined.
 */
export function checkGitDirFile(directory: string, policy: SpawnPolicy): string | undefined {
  const api = policy.platform === "win32" ? NodePath.win32 : NodePath.posix;
  let current = api.resolve(directory);
  for (;;) {
    const dotGit = api.join(current, ".git");
    if (policy.isFile(dotGit)) {
      const text = policy.readText(dotGit) ?? "";
      const match = /^gitdir:\s*(.+?)\s*$/m.exec(text);
      if (!match) return `${dotGit} is a file without a gitdir line.`;
      const target = policy.realPath(api.resolve(current, match[1]!));
      if (target === undefined) return `${dotGit} names a gitdir that does not exist.`;
      const kind = api.basename(api.dirname(target)).toLowerCase();
      const gitFolder = api.dirname(api.dirname(target));
      if ((kind !== "worktrees" && kind !== "modules") || api.basename(gitFolder).toLowerCase() !== ".git") {
        return `${dotGit} points outside a repository's .git/worktrees or .git/modules.`;
      }
      if (policy.workspaceRoots !== undefined) {
        const repository = api.dirname(gitFolder);
        const home = process.env.T3CODE_HOME;
        const roots = [...policy.workspaceRoots, ...(home ? [home] : [])];
        if (!roots.some((root) => isInside(repository, root, { ...nodePathPolicyHost, platform: policy.platform }))) {
          return `${dotGit} points into a repository outside the workspace roots.`;
        }
      }
      return undefined;
    }
    const parent = api.dirname(current);
    if (parent === current) return undefined;
    // A .git folder ends the walk: an ordinary repository.
    if (policy.realPath(dotGit) !== undefined) return undefined;
    current = parent;
  }
}

function gitWorkingDirectory(command: Extract<Command, { _tag: "StandardCommand" }>): string {
  const base = command.options.cwd ?? process.cwd();
  const args = command.args;
  let directory = base;
  for (let index = 0; index < args.length; index++) {
    const arg = args[index]!;
    if (!arg.startsWith("-")) break;
    if (arg === "-C" && args[index + 1] !== undefined) {
      directory = NodePath.resolve(directory, args[index + 1]!);
      index++;
    } else if (arg === "-c" || arg === "--git-dir" || arg === "--work-tree") {
      index++;
    }
  }
  return directory;
}

/** The command as T3 runs it, or a refusal reason. */
export function tailorCommand(
  command: Command,
  policy: SpawnPolicy = currentSpawnPolicy(),
): { readonly command: Command } | { readonly refused: string } {
  if (command._tag !== "StandardCommand") return { command };
  const isGit = isGitExecutable(command.command);
  const env = envOf(command);
  let executable = command.command;
  if (isGit && policy.gitExe !== undefined) {
    if (policy.gitExe === null) return { refused: "The machine policy names no git.exe." };
    executable = policy.gitExe;
  } else if (policy.platform === "win32" && !NodePath.win32.isAbsolute(executable)) {
    executable = resolveFromPath(executable, env, policy) ?? TAILOR_UNRESOLVED_COMMAND;
  }
  if (isGit) {
    const refusal = checkGitDirFile(gitWorkingDirectory(command), policy);
    if (refusal !== undefined) return { refused: refusal };
  }
  if (!isGit && executable === command.command && command.options.env === undefined) {
    return { command };
  }
  const baseEnv: Record<string, string | undefined> = isGit ? withTailorGitConfig(env) : { ...env };
  if (policy.platform === "win32") baseEnv.NoDefaultCurrentDirectoryInExePath = "1";
  return {
    command: ChildProcess.make(executable, [...(isGit ? withTailorGitArgs(command.args) : command.args)], {
      ...command.options,
      env: baseEnv,
      extendEnv: false,
    }) as Command,
  };
}

/** Back-compatible name: git hardening for one command (refusals become an unrunnable path). */
export function tailorGitCommand(command: Command, policy: SpawnPolicy = currentSpawnPolicy()): Command {
  const result = tailorCommand(command, policy);
  return "command" in result
    ? result.command
    : (ChildProcess.make(TAILOR_UNRESOLVED_COMMAND, [], {}) as Command);
}

export const layer: Layer.Layer<
  ChildProcessSpawner.ChildProcessSpawner,
  never,
  ChildProcessSpawner.ChildProcessSpawner
> = Layer.effect(
  ChildProcessSpawner.ChildProcessSpawner,
  Effect.gen(function* () {
    const inner = yield* ChildProcessSpawner.ChildProcessSpawner;
    return ChildProcessSpawner.make((command) => {
      const result = tailorCommand(command);
      return "command" in result
        ? inner.spawn(result.command)
        : Effect.die(new Error(`Tailor policy refused a command: ${result.refused}`));
    });
  }),
);
