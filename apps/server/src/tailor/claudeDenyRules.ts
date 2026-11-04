/**
 * Tailor fork (TailorAU/t3code): the Claude permission deny rules compiled into the server.
 * The chat adapter sends them as `managedSettings` (policy tier); text generation sends them
 * as flag settings. tailor/policy/install-policy.ps1 writes the machine-safe subset to the
 * real admin tier as well.
 */
export interface ClaudeDenySettings {
  readonly permissions: { readonly deny: ReadonlyArray<string> };
}

/** Claude permission-rule form of an absolute path: `//c/Users/x` on Windows, `//home/x` elsewhere. */
export function claudeAbsoluteRulePath(filePath: string): string {
  const posix = filePath.replace(/\\/g, "/").replace(/\/+$/, "");
  const drive = /^([A-Za-z]):\/(.*)$/.exec(posix);
  return drive ? `//${drive[1]!.toLowerCase()}/${drive[2]}` : `/${posix}`;
}

/**
 * Tailor fork: policy-tier Claude settings compiled into the server. They reach the Claude
 * binary as `managedSettings`, which no user, project or local file can loosen. Agents may
 * not edit Claude or MCP configuration, and may not read or change T3's own state (its
 * signing key, session store and settings).
 */
/** Tailor fork: where the compiled deny rules point; all optional, defaults are safe. */
export interface TailorProtectedPaths {
  /** The server's real base dir (`--base-dir`, `T3CODE_HOME`, or `~/.t3`). */
  readonly t3BaseDir?: string | undefined;
  /** The resolved Claude home of this instance. */
  readonly claudeHome?: string | undefined;
  /** An administrator's managed-mcp.json exists; Claude then refuses --strict-mcp-config. */
  readonly managedMcpConfig?: boolean | undefined;
}

/** State the T3 server keeps under a base dir; `userdata/attachments` stays readable. */
function t3BaseDirDenyRules(base: string): ReadonlyArray<string> {
  const readDenied = [
    `${base}/userdata/*.sqlite*`,
    `${base}/userdata/secrets/**`,
    `${base}/userdata/*.json`,
    `${base}/userdata/anonymous-id`,
    `${base}/userdata/environment-id`,
    `${base}/userdata/logs/**`,
    `${base}/userdata/browser-artifacts/**`,
    `${base}/dev/**`,
    `${base}/caches/**`,
    `${base}/runtime/**`,
    `${base}/*.json`,
    `${base}/*.env`,
  ];
  return [
    ...readDenied.map((pattern) => `Read(${pattern})`),
    // Nothing under the base dir may be changed by the agent, attachments included.
    `Edit(${base}/**)`,
    `Write(${base}/**)`,
  ];
}

/**
 * Tailor fork: policy-tier Claude settings compiled into the server. They reach the Claude
 * binary as `managedSettings`, which no user, project or local file can loosen. Agents may
 * not edit Claude or MCP configuration, may not change the Claude home, and may not read or
 * change T3's own state (its signing key, session store and settings); attachments stay
 * readable.
 */
export function tailorClaudeManagedSettings(
  environment?: NodeJS.ProcessEnv,
  paths: TailorProtectedPaths = {},
): ClaudeDenySettings {
  const bases = new Set<string>(["~/.t3"]);
  const configured = environment?.T3CODE_HOME ?? process.env.T3CODE_HOME;
  if (configured !== undefined && configured.trim().length > 0) {
    bases.add(claudeAbsoluteRulePath(configured.trim()));
  }
  if (paths.t3BaseDir !== undefined && paths.t3BaseDir.trim().length > 0) {
    bases.add(claudeAbsoluteRulePath(paths.t3BaseDir.trim()));
  }
  // Claude and MCP config, and git hooks and config (hooks, core.hooksPath, fsmonitor,
  // external diff and textconv drivers all live there).
  const protectedConfig = [
    "**/.claude/**",
    "**/.mcp.json",
    "~/.claude.json",
    "**/.git/hooks/**",
    "**/.git/config",
    "**/.git/info/attributes",
    "**/.githooks/**",
    "**/.husky/**",
  ];
  const claudeHomeRules =
    paths.claudeHome === undefined || paths.claudeHome.trim().length === 0
      ? []
      : (() => {
          const home = claudeAbsoluteRulePath(paths.claudeHome.trim());
          return [
            `Edit(${home}/**)`,
            `Write(${home}/**)`,
            ...[".claude.json", ".credentials.json", "remote-settings.json", "settings.json"].map(
              (file) => `Read(${home}/${file})`,
            ),
          ];
        })();
  return {
    permissions: {
      deny: [
        ...protectedConfig.flatMap((pattern) => [`Edit(${pattern})`, `Write(${pattern})`]),
        ...[...bases].flatMap(t3BaseDirDenyRules),
        ...claudeHomeRules,
      ],
    },
  };
}

