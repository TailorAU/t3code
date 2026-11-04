// @effect-diagnostics nodeBuiltinImport:off -- the known-folder lookup and binary hash run before an Effect platform layer is guaranteed.
/**
 * Tailor fork (TailorAU/t3code): the machine policy that tailor/policy/install-policy.ps1
 * writes to %ProgramData%\T3CodePolicy\t3-policy.json, writable only by Administrators and
 * SYSTEM. The server reads it at a fixed location (the known folder, never an environment
 * variable a user can change) and the policy always wins over user settings:
 *
 * - the Claude instance runs only from the recorded Claude binary and Claude home;
 * - the recorded binary must hash to the recorded SHA-256;
 * - the instance environment is cut down to an allowlist;
 * - on Windows a missing or unreadable policy means Claude does not run at all.
 */
import * as NodeChildProcess from "node:child_process";
import * as NodeCrypto from "node:crypto";
import * as NodeFS from "node:fs";
import * as NodePath from "node:path";

export const TAILOR_POLICY_FOLDER_NAME = "T3CodePolicy";
export const TAILOR_POLICY_FILE_NAME = "t3-policy.json";

/** Variables a user may set on the Claude instance; the policy can only narrow this. */
export const TAILOR_INSTANCE_ENVIRONMENT_ALLOWLIST: ReadonlyArray<string> = [
  "ANTHROPIC_API_KEY",
  "ANTHROPIC_BASE_URL",
  "ANTHROPIC_MODEL",
  "ANTHROPIC_DEFAULT_OPUS_MODEL",
  "ANTHROPIC_DEFAULT_SONNET_MODEL",
  "ANTHROPIC_DEFAULT_HAIKU_MODEL",
  "ANTHROPIC_SMALL_FAST_MODEL",
  "CLAUDE_CODE_USE_BEDROCK",
  "AWS_REGION",
  "AWS_PROFILE",
  "DISABLE_AUTOUPDATER",
  "DISABLE_TELEMETRY",
  "DISABLE_ERROR_REPORTING",
  "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
];

export interface TailorInstalledPolicy {
  readonly claudeConfigDir: string;
  readonly claudeExe: string;
  readonly claudeExeSha256: string | undefined;
  readonly instanceEnvironmentAllowlist: ReadonlyArray<string>;
  /** Project roots the installer created for t3agent; projects must be inside one. */
  readonly workspaceRoots: ReadonlyArray<string>;
}

export type TailorPolicyState =
  | { readonly _tag: "installed"; readonly path: string; readonly policy: TailorInstalledPolicy }
  | { readonly _tag: "absent"; readonly path: string | undefined }
  | { readonly _tag: "invalid"; readonly path: string | undefined; readonly reason: string };

/** Parses the `installed` block; null when it is missing or incomplete. */
export function parseTailorInstalledPolicy(raw: string): TailorInstalledPolicy | null {
  try {
    const parsed = JSON.parse(raw) as {
      readonly installed?: {
        readonly claudeConfigDir?: unknown;
        readonly claudeExe?: unknown;
        readonly claudeExeSha256?: unknown;
        readonly instanceEnvironmentAllowlist?: unknown;
        readonly workspaceRoots?: unknown;
      };
    };
    const installed = parsed.installed;
    if (
      typeof installed?.claudeConfigDir !== "string" ||
      installed.claudeConfigDir.length === 0 ||
      typeof installed.claudeExe !== "string" ||
      installed.claudeExe.length === 0
    ) {
      return null;
    }
    const listed = Array.isArray(installed.instanceEnvironmentAllowlist)
      ? installed.instanceEnvironmentAllowlist.filter(
          (name): name is string => typeof name === "string",
        )
      : undefined;
    return {
      claudeConfigDir: installed.claudeConfigDir,
      claudeExe: installed.claudeExe,
      claudeExeSha256:
        typeof installed.claudeExeSha256 === "string"
          ? installed.claudeExeSha256.toLowerCase()
          : undefined,
      // The policy can narrow the compiled allowlist, never widen it.
      instanceEnvironmentAllowlist:
        listed === undefined
          ? TAILOR_INSTANCE_ENVIRONMENT_ALLOWLIST
          : TAILOR_INSTANCE_ENVIRONMENT_ALLOWLIST.filter((name) => listed.includes(name)),
      workspaceRoots: Array.isArray(installed.workspaceRoots)
        ? installed.workspaceRoots.filter(
            (root): root is string => typeof root === "string" && root.length > 0,
          )
        : [],
    };
  } catch {
    return null;
  }
}

let cachedProgramData: string | null | undefined;

/**
 * The Windows "Common AppData" known folder, read from the registry by reg.exe at its
 * fixed system path. Environment variables (ProgramData, SystemRoot) are not used: a user
 * can change those for their own processes. Undefined when it cannot be read.
 */
export function windowsProgramDataFolder(): string | undefined {
  if (cachedProgramData !== undefined) return cachedProgramData ?? undefined;
  try {
    const output = NodeChildProcess.execFileSync(
      "C:\\Windows\\System32\\reg.exe",
      [
        "query",
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
        "/v",
        "Common AppData",
      ],
      { encoding: "utf8", windowsHide: true, timeout: 10_000, env: {} },
    );
    const match = /Common AppData\s+REG_SZ\s+(.+)\r?$/m.exec(output);
    cachedProgramData = match?.[1]?.trim() || null;
  } catch {
    cachedProgramData = null;
  }
  return cachedProgramData ?? undefined;
}

export function tailorPolicyFilePath(
  platform: string,
  programData: string | undefined = platform === "win32" ? windowsProgramDataFolder() : undefined,
): string | undefined {
  if (platform === "win32") {
    return programData === undefined
      ? undefined
      : NodePath.win32.join(programData, TAILOR_POLICY_FOLDER_NAME, TAILOR_POLICY_FILE_NAME);
  }
  return "/etc/t3code-policy/t3-policy.json";
}

/** Reads the machine policy. Errors other than "file not found" are invalid, not absent. */
export function readTailorPolicy(platform: string): TailorPolicyState {
  return readTailorPolicyAt(tailorPolicyFilePath(platform));
}

/** As readTailorPolicy, for an explicit path; undefined means the location is unknown. */
export function readTailorPolicyAt(filePath: string | undefined): TailorPolicyState {
  if (filePath === undefined) {
    return { _tag: "invalid", path: undefined, reason: "The ProgramData known folder could not be read." };
  }
  let raw: string;
  try {
    raw = NodeFS.readFileSync(filePath, "utf8");
  } catch (cause) {
    return (cause as { code?: string }).code === "ENOENT"
      ? { _tag: "absent", path: filePath }
      : { _tag: "invalid", path: filePath, reason: "The machine policy could not be read." };
  }
  const policy = parseTailorInstalledPolicy(raw);
  return policy === null
    ? { _tag: "invalid", path: filePath, reason: "The machine policy has no complete installed block." }
    : { _tag: "installed", path: filePath, policy };
}

/** SHA-256 of a file, streamed. */
export function sha256File(filePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = NodeCrypto.createHash("sha256");
    NodeFS.createReadStream(filePath)
      .on("error", reject)
      .on("data", (chunk) => hash.update(chunk))
      .on("end", () => resolve(hash.digest("hex")));
  });
}

export function samePath(platform: string, left: string, right: string): boolean {
  const resolve = platform === "win32" ? NodePath.win32.resolve : NodePath.posix.resolve;
  return platform === "win32"
    ? resolve(left).toLowerCase() === resolve(right).toLowerCase()
    : resolve(left) === resolve(right);
}

/** Keeps only allowlisted names in a provider-instance environment list. */
export function filterInstanceEnvironment<E extends { readonly name: string }>(
  environment: ReadonlyArray<E>,
  allowlist: ReadonlyArray<string> = TAILOR_INSTANCE_ENVIRONMENT_ALLOWLIST,
): ReadonlyArray<E> {
  return environment.filter((variable) => allowlist.includes(variable.name));
}

/**
 * The path rules for projects and worktrees. With the policy installed, projects are limited
 * to its workspace roots (plus T3's managed folders); otherwise only the policy folder itself
 * is off limits.
 */
export function tailorPathRules(
  platform: string,
  worktreesRoot: string,
): { readonly policyDir: string | undefined; readonly workspaceRoots: ReadonlyArray<string> | undefined; readonly worktreesRoot: string } {
  const policyFile = tailorPolicyFilePath(platform);
  const policyDir =
    policyFile === undefined
      ? undefined
      : (platform === "win32" ? NodePath.win32 : NodePath.posix).dirname(policyFile);
  const state = readTailorPolicyAt(policyFile);
  return {
    policyDir,
    workspaceRoots: state._tag === "installed" ? state.policy.workspaceRoots : undefined,
    worktreesRoot,
  };
}
