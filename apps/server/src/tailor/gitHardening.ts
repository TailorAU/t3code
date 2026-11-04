// @effect-diagnostics nodeBuiltinImport:off -- runs at the CLI entry, before any Effect layer exists.
/**
 * Tailor fork (TailorAU/t3code): every git process T3 starts, and every process those start
 * (Claude and the agent's shells inherit the server's environment), runs with:
 *
 * - `core.hooksPath` = an empty, admin-owned folder, so no repository hook ever runs;
 * - `safe.bareRepository=explicit`, so a planted bare repository is never opened implicitly;
 * - `core.fsmonitor=false`, so no repository-configured monitor command runs;
 * - `protocol.ext.allow=never`, so no `ext::` transport runs a command;
 * - and for diff-producing commands, `--no-ext-diff --no-textconv`, so no configured external
 *   diff or textconv command runs.
 *
 * `-c diff.external=` is NOT used: with an empty value git tries to spawn "" and every diff
 * fails ("cannot spawn"), so it is not an off switch. `--no-ext-diff` is.
 *
 * Two layers apply it: `applyTailorGitHardening(process.env)` at server start (inherited by
 * every child), and `tailorGitCommand` in a ChildProcessSpawner decorator (server.ts) for
 * any git command whose call site replaced the environment.
 */
import * as NodePath from "node:path";

import * as TailorMachinePolicy from "./machinePolicy.ts";

const DIFF_PRODUCING_SUBCOMMANDS = new Set(["diff", "log", "show", "format-patch", "whatchanged"]);

/** The empty hooks folder the installer creates; a path that cannot exist if it is unknown. */
export function tailorGitHooksDirectory(platform: string = process.platform): string {
  if (platform === "win32") {
    const programData = TailorMachinePolicy.windowsProgramDataFolder();
    return programData === undefined
      ? "NUL"
      : NodePath.win32.join(programData, TailorMachinePolicy.TAILOR_POLICY_FOLDER_NAME, "git-hooks");
  }
  return "/etc/t3code-policy/git-hooks";
}

export function tailorGitConfig(hooksDirectory: string): ReadonlyArray<readonly [string, string]> {
  return [
    ["core.hooksPath", hooksDirectory],
    ["safe.bareRepository", "explicit"],
    ["core.fsmonitor", "false"],
    ["protocol.ext.allow", "never"],
  ];
}

/**
 * Returns `env` with the hardening keys appended as GIT_CONFIG_KEY_n/VALUE_n (they win over
 * repository and user config). Idempotent: keys already applied with the same value are kept.
 */
export function withTailorGitConfig(
  env: Readonly<Record<string, string | undefined>>,
  hooksDirectory: string = tailorGitHooksDirectory(),
): Record<string, string | undefined> {
  const next: Record<string, string | undefined> = { ...env };
  const countRaw = next.GIT_CONFIG_COUNT;
  let count = countRaw !== undefined && /^\d+$/.test(countRaw) ? Number.parseInt(countRaw, 10) : 0;
  const present = new Map<string, string | undefined>();
  for (let index = 0; index < count; index++) {
    const key = next[`GIT_CONFIG_KEY_${index}`];
    if (key !== undefined) present.set(key.toLowerCase(), next[`GIT_CONFIG_VALUE_${index}`]);
  }
  for (const [key, value] of tailorGitConfig(hooksDirectory)) {
    if (present.get(key.toLowerCase()) === value) continue;
    next[`GIT_CONFIG_KEY_${count}`] = key;
    next[`GIT_CONFIG_VALUE_${count}`] = value;
    count++;
  }
  next.GIT_CONFIG_COUNT = String(count);
  // An external diff from the environment would bypass --no-ext-diff's config check.
  delete next.GIT_EXTERNAL_DIFF;
  return next;
}

/** Applies the hardening to this process's environment, so every child inherits it. */
export function applyTailorGitHardening(env: NodeJS.ProcessEnv = process.env): void {
  const hardened = withTailorGitConfig(env);
  for (const [key, value] of Object.entries(hardened)) {
    if (value === undefined) delete env[key];
    else env[key] = value;
  }
  delete env.GIT_EXTERNAL_DIFF;
}

export function isGitExecutable(command: string): boolean {
  const base = command.replace(/\\/g, "/").split("/").at(-1)?.toLowerCase() ?? "";
  return base === "git" || base === "git.exe";
}

/** Adds --no-ext-diff --no-textconv after a diff-producing subcommand. */
export function withTailorGitArgs(args: ReadonlyArray<string>): ReadonlyArray<string> {
  let index = 0;
  while (index < args.length) {
    const arg = args[index]!;
    if (!arg.startsWith("-")) break;
    index += arg === "-c" || arg === "-C" || arg === "--git-dir" || arg === "--work-tree" ? 2 : 1;
  }
  const subcommand = args[index];
  if (subcommand === undefined || !DIFF_PRODUCING_SUBCOMMANDS.has(subcommand)) return args;
  const rest = args.slice(index + 1);
  const extra = ["--no-ext-diff", "--no-textconv"].filter((flag) => !rest.includes(flag));
  return [...args.slice(0, index + 1), ...extra, ...rest];
}
