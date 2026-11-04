// @effect-diagnostics nodeBuiltinImport:off -- executable and .git checks are synchronous file reads.
/**
 * Tailor fork (TailorAU/t3code): a ChildProcessSpawner decorator that every command T3 starts
 * goes through (server.ts layers it over the platform spawner).
 *
 * - On Windows a bare command name is resolved to an absolute path from PATH's absolute
 *   entries only, so a planted `git.exe` in a repository is never the one found. A name found
 *   nowhere is REFUSED: nothing is spawned and no substitute path is used.
 * - A `shell: true` command (Windows `.cmd`/`.bat` launches, already resolved and quoted by
 *   `resolveSpawnCommand`) runs only if its first token is an absolute path to an existing
 *   file; anything else is refused.
 * - With the machine policy installed, `git` is always the policy's absolute `gitExe`; a policy
 *   without one refuses every git call.
 * - Every git command gets the hardening (gitHardening.ts).
 * - Before a git command, the tree's `.git` must not be a link; if it is a file (linked
 *   worktree or submodule), its `gitdir:` must resolve (real path) inside
 *   `<repository>/.git/worktrees/` or `<repository>/.git/modules/` (nested submodules
 *   included), and with the policy installed that repository must be in a workspace root or
 *   the T3 home. Otherwise the command is refused.
 *
 * `NoDefaultCurrentDirectoryInExePath=1` is set in the SERVER's own environment at the CLI
 * entry (gitHardening.applyTailorGitHardening): libuv and CreateProcess read it from the
 * process that spawns. It is also passed to children so a child that itself resolves names
 * (cmd.exe running a `.cmd`) skips its working directory too; that does not protect libuv.
 */
import * as NodeFS from "node:fs";
import * as NodePath from "node:path";

import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as PlatformError from "effect/PlatformError";
import { ChildProcess, ChildProcessSpawner } from "effect/process";

import { isGitExecutable, withTailorGitArgs, withTailorGitConfig } from "./gitHardening.ts";
import * as TailorMachinePolicy from "./machinePolicy.ts";
import { isInside, nodePathPolicyHost } from "./workspacePolicy.ts";

type Command = Parameters<ChildProcessSpawner.ChildProcessSpawner["Service"]["spawn"]>[0];
type StandardCommand = Extract<Command, { _tag: "StandardCommand" }>;

export interface SpawnPolicy {
  readonly platform: string;
  /** The policy's git.exe; null when the policy is installed without one; undefined without a policy. */
  readonly gitExe: string | null | undefined;
  /** Workspace roots when the policy is installed. */
  readonly workspaceRoots: ReadonlyArray<string> | undefined;
  readonly isFile: (path: string) => boolean;
  /** True for a symbolic link, junction or other reparse point (not followed). */
  readonly isLink: (path: string) => boolean;
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
    isLink: (path) => {
      try {
        return NodeFS.lstatSync(path).isSymbolicLink();
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

function envOf(command: StandardCommand) {
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

/** The first token of a cmd.exe command line as resolveSpawnCommand quotes it (carets undone). */
export function firstShellToken(commandLine: string): string {
  const trimmed = commandLine.trimStart();
  if (trimmed.startsWith('"')) {
    let token = "";
    for (let index = 1; index < trimmed.length; index++) {
      const char = trimmed[index]!;
      if (char === "^" && index + 1 < trimmed.length) {
        token += trimmed[++index];
        continue;
      }
      if (char === '"') return token;
      token += char;
    }
    return token;
  }
  return trimmed.split(/\s+/, 1)[0] ?? "";
}

/** Checks the `.git` of the tree a git command runs in. Returns a refusal reason, or undefined. */
export function checkGitDirFile(directory: string, policy: SpawnPolicy): string | undefined {
  const api = policy.platform === "win32" ? NodePath.win32 : NodePath.posix;
  let current = api.resolve(directory);
  for (;;) {
    const dotGit = api.join(current, ".git");
    if (policy.isLink(dotGit)) return `${dotGit} is a link or junction.`;
    if (policy.isFile(dotGit)) {
      const text = policy.readText(dotGit) ?? "";
      const match = /^gitdir:\s*(.+?)\s*$/m.exec(text);
      if (!match) return `${dotGit} is a file without a gitdir line.`;
      const target = policy.realPath(api.resolve(current, match[1]!));
      if (target === undefined) return `${dotGit} names a gitdir that does not exist.`;
      const parts = target.split(/[\\/]+/);
      let gitIndex = -1;
      for (let index = parts.length - 3; index >= 0; index--) {
        const kind = parts[index + 1]!.toLowerCase();
        if (parts[index]!.toLowerCase() === ".git" && (kind === "worktrees" || kind === "modules")) {
          gitIndex = index;
          break;
        }
      }
      if (gitIndex <= 0) {
        return `${dotGit} points outside a repository's .git/worktrees or .git/modules.`;
      }
      const gitFolder = parts.slice(0, gitIndex + 1).join(api.sep);
      if (policy.isLink(gitFolder) || policy.realPath(gitFolder) === undefined) {
        return `${dotGit} points into a .git folder that is missing or a link.`;
      }
      if (policy.workspaceRoots !== undefined) {
        const repository = api.dirname(gitFolder);
        const home = process.env.T3CODE_HOME;
        const roots = [...policy.workspaceRoots, ...(home ? [home] : [])];
        const host = { ...nodePathPolicyHost, platform: policy.platform };
        if (!roots.some((root) => isInside(repository, root, host))) {
          return `${dotGit} points into a repository outside the workspace roots.`;
        }
      }
      return undefined;
    }
    // A .git folder ends the walk: an ordinary repository.
    if (policy.realPath(dotGit) !== undefined) return undefined;
    const parent = api.dirname(current);
    if (parent === current) return undefined;
    current = parent;
  }
}

function gitWorkingDirectory(command: StandardCommand): string {
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

/** The command as T3 runs it, or a refusal reason. Nothing is ever substituted. */
export function tailorCommand(
  command: Command,
  policy: SpawnPolicy = currentSpawnPolicy(),
): { readonly command: Command } | { readonly refused: string } {
  if (command._tag !== "StandardCommand") {
    // No server code pipes commands; a pipe would hide its programs from these checks.
    return policy.platform === "win32" ? { refused: "Piped commands are not allowed." } : { command };
  }
  const env = envOf(command);
  const windows = policy.platform === "win32";
  if (windows && command.options.shell) {
    // resolveSpawnCommand resolves and quotes the program before a shell launch.
    const program = firstShellToken(command.command);
    if (!NodePath.win32.isAbsolute(program) || !policy.isFile(program)) {
      return { refused: `A shell command must start with an existing absolute program path (${program}).` };
    }
    return { command };
  }
  const isGit = isGitExecutable(command.command);
  let executable = command.command;
  if (isGit && policy.gitExe !== undefined) {
    if (policy.gitExe === null) return { refused: "The machine policy names no git.exe." };
    executable = policy.gitExe;
  } else if (windows && !NodePath.win32.isAbsolute(executable)) {
    const found = resolveFromPath(executable, env, policy);
    if (found === undefined) return { refused: `${executable} was not found on PATH.` };
    executable = found;
  }
  if (isGit) {
    const refusal = checkGitDirFile(gitWorkingDirectory(command), policy);
    if (refusal !== undefined) return { refused: refusal };
  }
  if (!isGit && executable === command.command && command.options.env === undefined) {
    return { command };
  }
  const baseEnv: Record<string, string | undefined> = isGit ? withTailorGitConfig(env) : { ...env };
  if (windows) baseEnv.NoDefaultCurrentDirectoryInExePath = "1";
  return {
    command: ChildProcess.make(
      executable,
      [...(isGit ? withTailorGitArgs(command.args) : command.args)],
      { ...command.options, env: baseEnv, extendEnv: false },
    ) as Command,
  };
}

/** A refused command fails like a program that is not there; nothing is spawned. */
export function refusedError(command: Command, reason: string) {
  return PlatformError.systemError({
    _tag: "NotFound",
    module: "ChildProcess",
    method: "spawn",
    description: `Tailor policy refused the command: ${reason}`,
    pathOrDescriptor: command._tag === "StandardCommand" ? command.command : "piped command",
  });
}

export const makeLayer = (
  policy: () => SpawnPolicy = currentSpawnPolicy,
): Layer.Layer<ChildProcessSpawner.ChildProcessSpawner, never, ChildProcessSpawner.ChildProcessSpawner> =>
  Layer.effect(
    ChildProcessSpawner.ChildProcessSpawner,
    Effect.gen(function* () {
      const inner = yield* ChildProcessSpawner.ChildProcessSpawner;
      return ChildProcessSpawner.make((command) => {
        const result = tailorCommand(command, policy());
        return "command" in result
          ? inner.spawn(result.command)
          : Effect.fail(refusedError(command, result.refused));
      });
    }),
  );

export const layer = makeLayer();
