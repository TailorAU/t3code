// @effect-diagnostics nodeBuiltinImport:off -- runs at the CLI entry, before any Effect layer exists.
/**
 * Tailor fork (TailorAU/t3code): every git process T3 starts, and every process those start
 * (Claude and the agent's shells inherit the server's environment), runs with:
 *
 * - `core.hooksPath` = an empty, admin-owned folder, so no repository hook ever runs;
 * - `safe.bareRepository=explicit`, so a planted bare repository is never opened implicitly;
 * - `core.fsmonitor=false`, so no repository-configured monitor command runs;
 * - `protocol.ext.allow=never` and `protocol.file.allow=user`, so no `ext::` transport runs a
 *   command and `file://` is not used implicitly (submodules);
 * - `credential.helper=` (empty: the helper list is cleared), so no configured helper runs;
 * - `core.sshCommand=ssh`, so a repository cannot name another ssh program;
 * - `commit.gpgSign=false` and `tag.gpgSign=false`, so no signing program runs;
 * - `GIT_CONFIG_GLOBAL` = an empty admin-owned file and `GIT_CONFIG_NOSYSTEM=1`, so no global
 *   or system config (includes, filters, aliases, helpers) is read;
 * - `core.askPass=` (empty) and `core.gitProxy=none`, so no prompt or proxy program runs;
 * - `GIT_EXTERNAL_DIFF`, `GIT_SSH`, `GIT_SSH_COMMAND`, `GIT_ASKPASS`, `SSH_ASKPASS` and
 *   `GIT_PROXY_COMMAND` removed;
 * - and for diff-producing commands (diff, log, show, format-patch, whatchanged, blame,
 *   diff-tree, stash show), `--no-ext-diff --no-textconv`.
 *
 * `-c diff.external=` is NOT used: with an empty value git tries to spawn "" and every diff
 * fails ("cannot spawn"), so it is not an off switch. `--no-ext-diff` is. Likewise
 * `core.sshCommand=` (empty) would break every ssh remote, so it is set to plain `ssh`.
 *
 * `filter.<driver>.clean/smudge/process`, `merge.<driver>.driver` and `include.path` cannot be
 * switched off for every name with `-c`. The control is that no config can define one: global and system config are off, a
 * clone never carries repository config, and Claude may not edit anything under `.git/`,
 * `~/.gitconfig`, `~/.config/git/`, `.gitattributes` or `.gitmodules` (claudeDenyRules.ts);
 * the agent's own shell commands are Supervised.
 *
 * Two layers apply it: `applyTailorGitHardening(process.env)` at server start (inherited by
 * every child), and `tailorGitCommand` in a ChildProcessSpawner decorator (server.ts) for
 * any git command whose call site replaced the environment.
 */
import * as NodePath from "node:path";

import * as TailorMachinePolicy from "./machinePolicy.ts";

const DIFF_PRODUCING_SUBCOMMANDS = new Set([
  "diff",
  "log",
  "show",
  "format-patch",
  "whatchanged",
  "blame",
  "diff-tree",
]);
/** Subcommands whose second word produces a diff (`git stash show`). */
const DIFF_PRODUCING_SUB_SUBCOMMANDS: Readonly<Record<string, ReadonlySet<string>>> = {
  stash: new Set(["show"]),
};

const REMOVED_GIT_ENVIRONMENT = [
  "GIT_EXTERNAL_DIFF",
  "GIT_SSH",
  "GIT_SSH_COMMAND",
  "GIT_ASKPASS",
  "SSH_ASKPASS",
  "GIT_PROXY_COMMAND",
];

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

/** The empty admin-owned global config file the installer creates (NUL when unknown). */
export function tailorGitGlobalConfigFile(platform: string = process.platform): string {
  if (platform === "win32") {
    const programData = TailorMachinePolicy.windowsProgramDataFolder();
    return programData === undefined
      ? "NUL"
      : NodePath.win32.join(
          programData,
          TailorMachinePolicy.TAILOR_POLICY_FOLDER_NAME,
          "git-config",
          "gitconfig",
        );
  }
  return "/dev/null";
}

export function tailorGitConfig(hooksDirectory: string): ReadonlyArray<readonly [string, string]> {
  return [
    ["core.hooksPath", hooksDirectory],
    ["safe.bareRepository", "explicit"],
    ["core.fsmonitor", "false"],
    ["protocol.ext.allow", "never"],
    ["protocol.file.allow", "user"],
    ["credential.helper", ""],
    ["core.askPass", ""],
    ["core.gitProxy", "none"],
    ["core.sshCommand", "ssh"],
    ["commit.gpgSign", "false"],
    ["tag.gpgSign", "false"],
  ];
}

/**
 * Returns `env` with the hardening keys appended as GIT_CONFIG_KEY_n/VALUE_n (they win over
 * repository and user config). Idempotent: keys already applied with the same value are kept.
 */
export function withTailorGitConfig(
  env: Readonly<Record<string, string | undefined>>,
  hooksDirectory: string = tailorGitHooksDirectory(),
  globalConfigFile: string = tailorGitGlobalConfigFile(),
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
  next.GIT_CONFIG_GLOBAL = globalConfigFile;
  next.GIT_CONFIG_NOSYSTEM = "1";
  // Programs named by the environment would bypass the config above.
  for (const name of REMOVED_GIT_ENVIRONMENT) delete next[name];
  return next;
}

/** Applies the hardening to this process's environment, so every child inherits it. */
export function applyTailorGitHardening(env: NodeJS.ProcessEnv = process.env): void {
  const hardened = withTailorGitConfig(env);
  for (const [key, value] of Object.entries(hardened)) {
    if (value === undefined) delete env[key];
    else env[key] = value;
  }
  for (const name of REMOVED_GIT_ENVIRONMENT) delete env[name];
  // Windows: never resolve a bare command name in the working directory (cmd.exe, CreateProcess
  // search and libuv honour this), so a planted git.exe in a repository is not run.
  if (process.platform === "win32") env.NoDefaultCurrentDirectoryInExePath = "1";
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
  if (subcommand === undefined) return args;
  let at = index;
  if (!DIFF_PRODUCING_SUBCOMMANDS.has(subcommand)) {
    const second = DIFF_PRODUCING_SUB_SUBCOMMANDS[subcommand];
    const next = args[index + 1];
    if (second === undefined || next === undefined || !second.has(next)) return args;
    at = index + 1;
  }
  const rest = args.slice(at + 1);
  const extra = ["--no-ext-diff", "--no-textconv"].filter((flag) => !rest.includes(flag));
  return [...args.slice(0, at + 1), ...extra, ...rest];
}
