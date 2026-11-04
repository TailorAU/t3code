// @effect-diagnostics nodeBuiltinImport:off -- the scan test reads source files.
/** Tailor fork (TailorAU/t3code): git hooks and config-driven commands are off for every git call. */
import * as NodeFS from "node:fs";
import * as NodePath from "node:path";
import { assert, describe, it } from "@effect/vitest";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import { ChildProcess, ChildProcessSpawner } from "effect/process";

import {
  applyTailorGitHardening,
  withTailorGitArgs,
  withTailorGitConfig,
} from "./gitHardening.ts";
import * as NodeChildProcess from "node:child_process";
import * as NodeOS from "node:os";
import * as TailorGitSpawner from "./gitSpawner.ts";

const configOf = (env: Record<string, string | undefined>) => {
  const count = Number.parseInt(env.GIT_CONFIG_COUNT ?? "0", 10);
  const entries: Record<string, string | undefined> = {};
  for (let index = 0; index < count; index++) {
    entries[env[`GIT_CONFIG_KEY_${index}`]!] = env[`GIT_CONFIG_VALUE_${index}`];
  }
  return entries;
};

describe("Tailor git hardening", () => {
  it("sets every hardening key, an empty global config and no system config", () => {
    const env = withTailorGitConfig(
      {
        PATH: "/bin",
        GIT_EXTERNAL_DIFF: "evil",
        GIT_SSH_COMMAND: "evil",
        GIT_SSH: "evil",
        GIT_ASKPASS: "evil",
        SSH_ASKPASS: "evil",
        GIT_CONFIG_GLOBAL: "/home/x/.gitconfig",
      },
      "/empty-hooks",
      "/empty-config",
    );
    assert.deepEqual(configOf(env), {
      "core.hooksPath": "/empty-hooks",
      "safe.bareRepository": "explicit",
      "core.fsmonitor": "false",
      "protocol.ext.allow": "never",
      "protocol.file.allow": "user",
      "credential.helper": "",
      "core.askPass": "",
      "core.gitProxy": "none",
      "core.sshCommand": "ssh",
      "commit.gpgSign": "false",
      "tag.gpgSign": "false",
    });
    assert.strictEqual(env.GIT_CONFIG_GLOBAL, "/empty-config");
    assert.strictEqual(env.GIT_CONFIG_NOSYSTEM, "1");
    for (const name of ["GIT_EXTERNAL_DIFF", "GIT_SSH_COMMAND", "GIT_SSH", "GIT_ASKPASS", "SSH_ASKPASS"]) {
      assert.isUndefined(env[name], name);
    }
    assert.strictEqual(env.PATH, "/bin");
  });

  it("appends after existing GIT_CONFIG entries and is idempotent", () => {
    const first = withTailorGitConfig(
      { GIT_CONFIG_COUNT: "1", GIT_CONFIG_KEY_0: "user.name", GIT_CONFIG_VALUE_0: "x" },
      "/h",
    );
    assert.strictEqual(first.GIT_CONFIG_KEY_0, "user.name");
    assert.strictEqual(first.GIT_CONFIG_COUNT, "12");
    const second = withTailorGitConfig(first, "/h");
    assert.strictEqual(second.GIT_CONFIG_COUNT, "12");
  });

  it("applies to the process environment so every child inherits it", () => {
    const env: NodeJS.ProcessEnv = { PATH: "/bin" };
    applyTailorGitHardening(env);
    // The server's own environment: libuv and CreateProcess read it from the spawning process.
    if (process.platform === "win32") assert.strictEqual(env.NoDefaultCurrentDirectoryInExePath, "1");
    assert.strictEqual(configOf(env as Record<string, string>)["core.fsmonitor"], "false");
    assert.isDefined(configOf(env as Record<string, string>)["core.hooksPath"]);
  });

  it("turns off external diff and textconv for diff-producing commands only", () => {
    assert.deepEqual(withTailorGitArgs(["-c", "a=b", "diff", "HEAD"]), [
      "-c",
      "a=b",
      "diff",
      "--no-ext-diff",
      "--no-textconv",
      "HEAD",
    ]);
    assert.deepEqual(withTailorGitArgs(["log", "--no-ext-diff", "-p"]), [
      "log",
      "--no-textconv",
      "--no-ext-diff",
      "-p",
    ]);
    assert.deepEqual(withTailorGitArgs(["status", "--porcelain"]), ["status", "--porcelain"]);
    assert.deepEqual(withTailorGitArgs(["blame", "-L1,2", "f"]), [
      "blame",
      "--no-ext-diff",
      "--no-textconv",
      "-L1,2",
      "f",
    ]);
    assert.deepEqual(withTailorGitArgs(["diff-tree", "-p", "HEAD"]).slice(0, 3), [
      "diff-tree",
      "--no-ext-diff",
      "--no-textconv",
    ]);
    assert.deepEqual(withTailorGitArgs(["stash", "show", "-p"]), [
      "stash",
      "show",
      "--no-ext-diff",
      "--no-textconv",
      "-p",
    ]);
    assert.deepEqual(withTailorGitArgs(["stash", "list"]), ["stash", "list"]);
    assert.deepEqual(withTailorGitArgs(["-C", "/repo", "show", "HEAD"]).slice(0, 5), [
      "-C",
      "/repo",
      "show",
      "--no-ext-diff",
      "--no-textconv",
    ]);
  });

  it.effect("the spawner decorator hardens git commands and leaves others alone", () =>
    Effect.gen(function* () {
      const seen: Array<{ command: string; args: ReadonlyArray<string>; env: unknown }> = [];
      const fake = Layer.succeed(ChildProcessSpawner.ChildProcessSpawner)(
        ChildProcessSpawner.make((command) => {
          if (command._tag === "StandardCommand") {
            seen.push({ command: command.command, args: command.args, env: command.options.env });
          }
          return Effect.die("not spawned in this test");
        }),
      );
      // The same composition server.ts uses: the decorator over the platform spawner.
      const composed = TailorGitSpawner.layer.pipe(Layer.provideMerge(fake));
      yield* Effect.gen(function* () {
        const spawner = yield* ChildProcessSpawner.ChildProcessSpawner;
        yield* Effect.exit(
          Effect.scoped(
            spawner.spawn(ChildProcess.make("git", ["diff"], { env: { PATH: process.env.PATH ?? "/bin" } })),
          ),
        );
        yield* Effect.exit(Effect.scoped(spawner.spawn(ChildProcess.make("node", ["-v"]))));
      }).pipe(Effect.provide(composed));
      assert.lengthOf(seen, 2);
      assert.deepEqual(seen[0]!.args, ["diff", "--no-ext-diff", "--no-textconv"]);
      assert.strictEqual(
        configOf(seen[0]!.env as Record<string, string>)["safe.bareRepository"],
        "explicit",
      );
      // A bare name is resolved from PATH's absolute entries (Windows) or left alone.
      if (process.platform === "win32") {
        assert.isTrue(NodePath.win32.isAbsolute(seen[1]!.command), seen[1]!.command);
        assert.match(seen[1]!.command.toLowerCase(), /node\.exe$/);
      } else {
        assert.strictEqual(seen[1]!.command, "node");
      }
    }),
  );

  it("is wired into the server and the CLI entry, and nothing spawns git around it", () => {
    const root = NodePath.join(import.meta.dirname, "..");
    const server = NodeFS.readFileSync(NodePath.join(root, "server.ts"), "utf8");
    assert.match(server, /TailorGitSpawner\.layer\.pipe\(\s*Layer\.provideMerge\(DocumentText\.layer/);
    const bin = NodeFS.readFileSync(NodePath.join(root, "bin.ts"), "utf8");
    assert.match(bin, /applyTailorGitHardening\(\)/);
    // No server source starts git through node:child_process (which the decorator cannot see).
    const offenders: string[] = [];
    const walk = (directory: string) => {
      for (const entry of NodeFS.readdirSync(directory, { withFileTypes: true })) {
        const full = NodePath.join(directory, entry.name);
        if (entry.isDirectory()) walk(full);
        else if (entry.name.endsWith(".ts") && !entry.name.includes(".test.")) {
          const text = NodeFS.readFileSync(full, "utf8");
          if (
            /node:child_process/.test(text) &&
            /(exec|execFile|spawn|execSync|execFileSync|spawnSync)\(\s*["'`]git(\.exe)?["'`]/.test(text)
          ) {
            offenders.push(NodePath.relative(root, full));
          }
        }
      }
    };
    walk(root);
    assert.deepEqual(offenders, []);
  });

  it("never resolves a bare command in the working directory, and runs the policy's git", () => {
    const fakeRepo = NodeFS.mkdtempSync(NodePath.join(NodeOS.tmpdir(), "t3-planted-git-"));
    const files = new Set([NodePath.win32.join(fakeRepo, "git.exe"), "C:\\Tools\\git.exe"]);
    const policy: TailorGitSpawner.SpawnPolicy = {
      platform: "win32",
      gitExe: undefined,
      workspaceRoots: undefined,
      isFile: (path) => files.has(path),
      isLink: () => false,
      readText: () => undefined,
      realPath: () => undefined,
    };
    // PATH with a relative entry and the repository itself as "." : both are skipped.
    const env = { PATH: `.;bin;C:\\Tools`, PATHEXT: ".EXE" };
    assert.strictEqual(TailorGitSpawner.resolveFromPath("git", env, policy), "C:\\Tools\\git.exe");
    assert.isUndefined(TailorGitSpawner.resolveFromPath("git", { PATH: ".;bin", PATHEXT: ".EXE" }, policy));
    const bare = ChildProcess.make("git", ["status"], { cwd: fakeRepo, env });
    const resolved = TailorGitSpawner.tailorCommand(bare, policy);
    assert.isTrue("command" in resolved);
    if ("command" in resolved && resolved.command._tag === "StandardCommand") {
      assert.strictEqual(resolved.command.command, "C:\\Tools\\git.exe");
      assert.strictEqual(resolved.command.options.env?.NoDefaultCurrentDirectoryInExePath, "1");
    }
    // With the policy installed, git is always the policy's git.exe.
    const withPolicy = TailorGitSpawner.tailorCommand(bare, { ...policy, gitExe: "D:\\Git\\cmd\\git.exe" });
    assert.isTrue("command" in withPolicy && withPolicy.command._tag === "StandardCommand" && withPolicy.command.command === "D:\\Git\\cmd\\git.exe");
    const noGit = TailorGitSpawner.tailorCommand(bare, { ...policy, gitExe: null });
    assert.isTrue("refused" in noGit);
    // A name found nowhere is refused: no substitute path, no working-directory lookup.
    const unknown = TailorGitSpawner.tailorCommand(ChildProcess.make("whereami", [], { env }), policy);
    assert.isTrue("refused" in unknown);
  });

  it.skipIf(process.platform !== "win32")("a planted git.exe at a repository root is not run (real spawn)", () => {
    const fakeRepo = NodeFS.mkdtempSync(NodePath.join(NodeOS.tmpdir(), "t3-planted-git-real-"));
    // whoami.exe renamed to git.exe: if it ran, the output would be a user name.
    NodeFS.copyFileSync(NodePath.join(process.env.SystemRoot ?? "C:\\Windows", "System32", "whoami.exe"), NodePath.join(fakeRepo, "git.exe"));
    const resolved = TailorGitSpawner.tailorCommand(
      ChildProcess.make("git", ["--version"], { cwd: fakeRepo }),
      { ...TailorGitSpawner.currentSpawnPolicy(), gitExe: undefined, workspaceRoots: undefined },
    );
    assert.isTrue("command" in resolved);
    if (!("command" in resolved) || resolved.command._tag !== "StandardCommand") return;
    const executable = resolved.command.command;
    assert.isFalse(executable.toLowerCase().startsWith(fakeRepo.toLowerCase()), executable);
    const output = NodeChildProcess.execFileSync(executable, ["--version"], { cwd: fakeRepo, encoding: "utf8" });
    assert.match(output, /^git version/);
  });

  it("refuses git in a tree whose .git file points outside .git/worktrees or .git/modules", () => {
    const base = NodeFS.mkdtempSync(NodePath.join(NodeOS.tmpdir(), "t3-gitdir-"));
    const repo = NodePath.join(base, "repo");
    const linked = NodePath.join(repo, ".git", "worktrees", "wt");
    NodeFS.mkdirSync(linked, { recursive: true });
    const worktree = NodePath.join(base, "wt");
    NodeFS.mkdirSync(worktree);
    NodeFS.writeFileSync(NodePath.join(worktree, ".git"), `gitdir: ${linked}\n`);
    const evil = NodePath.join(base, "evil-gitdir");
    NodeFS.mkdirSync(evil);
    const hijacked = NodePath.join(base, "hijacked");
    NodeFS.mkdirSync(hijacked);
    NodeFS.writeFileSync(NodePath.join(hijacked, ".git"), `gitdir: ${evil}\n`);
    const policy = { ...TailorGitSpawner.currentSpawnPolicy(), gitExe: undefined, workspaceRoots: undefined };
    assert.isUndefined(TailorGitSpawner.checkGitDirFile(worktree, policy));
    assert.isUndefined(TailorGitSpawner.checkGitDirFile(NodePath.join(repo), policy));
    assert.isDefined(TailorGitSpawner.checkGitDirFile(hijacked, policy));
    const sub = NodePath.join(hijacked, "src");
    NodeFS.mkdirSync(sub);
    assert.isDefined(TailorGitSpawner.checkGitDirFile(sub, policy), "a subfolder of a hijacked tree");
    // With the policy installed, the repository must be in a workspace root.
    assert.isDefined(
      TailorGitSpawner.checkGitDirFile(worktree, { ...policy, workspaceRoots: [NodePath.join(base, "elsewhere")] }),
    );
    assert.isUndefined(TailorGitSpawner.checkGitDirFile(worktree, { ...policy, workspaceRoots: [base] }));
    const refused = TailorGitSpawner.tailorCommand(ChildProcess.make("git", ["status"], { cwd: hijacked }), policy);
    assert.isTrue("refused" in refused);
  });

  it.effect("an unresolved name spawns nothing, whatever exists on disk", () =>
    Effect.gen(function* () {
      const seen: Array<string> = [];
      const fake = Layer.succeed(ChildProcessSpawner.ChildProcessSpawner)(
        ChildProcessSpawner.make((command) => {
          if (command._tag === "StandardCommand") seen.push(command.command);
          return Effect.die("must not be reached");
        }),
      );
      // Every absolute path "exists" except on PATH: even a planted fallback could not be used.
      const policy: TailorGitSpawner.SpawnPolicy = {
        platform: "win32",
        gitExe: undefined,
        workspaceRoots: undefined,
        isFile: (path) => !path.toLowerCase().startsWith("c:\\tools"),
        isLink: () => false,
        readText: () => undefined,
        realPath: () => undefined,
      };
      const composed = TailorGitSpawner.makeLayer(() => policy).pipe(Layer.provideMerge(fake));
      const exit = yield* Effect.gen(function* () {
        const spawner = yield* ChildProcessSpawner.ChildProcessSpawner;
        return yield* Effect.exit(
          Effect.scoped(spawner.spawn(ChildProcess.make("gh", ["auth", "token"], { env: { PATH: "C:\\Tools", PATHEXT: ".EXE" } }))),
        );
      }).pipe(Effect.provide(composed));
      assert.isTrue(exit._tag === "Failure");
      assert.deepEqual(seen, []);
      // A shell launch must start with an existing absolute program path.
      const shellRefused = TailorGitSpawner.tailorCommand(
        ChildProcess.make('code.cmd "file.txt"', [], { shell: true }),
        { ...policy, isFile: () => true },
      );
      assert.isTrue("refused" in shellRefused);
      const shellAllowed = TailorGitSpawner.tailorCommand(
        ChildProcess.make('"C:\\Program Files\\Code\\bin\\code.cmd" "file.txt"', [], { shell: true }),
        { ...policy, isFile: (path) => path === "C:\\Program Files\\Code\\bin\\code.cmd" },
      );
      assert.isTrue("command" in shellAllowed);
      assert.strictEqual(TailorGitSpawner.firstShellToken('"C:\\a ^& b\\x.cmd" "y"'), "C:\\a & b\\x.cmd");
    }),
  );

  it("refuses a .git link or junction, and allows nested submodule gitdirs", () => {
    const base = NodeFS.mkdtempSync(NodePath.join(NodeOS.tmpdir(), "t3-gitdir-nested-"));
    const repo = NodePath.join(base, "repo");
    const nested = NodePath.join(repo, ".git", "modules", "a", "modules", "b");
    NodeFS.mkdirSync(nested, { recursive: true });
    const sub = NodePath.join(repo, "a", "b");
    NodeFS.mkdirSync(sub, { recursive: true });
    NodeFS.writeFileSync(NodePath.join(sub, ".git"), `gitdir: ${nested}\n`);
    const policy = { ...TailorGitSpawner.currentSpawnPolicy(), gitExe: undefined, workspaceRoots: undefined };
    assert.isUndefined(TailorGitSpawner.checkGitDirFile(sub, policy), "nested submodule");
    const linked = NodePath.join(base, "linked");
    NodeFS.mkdirSync(linked);
    NodeFS.symlinkSync(NodePath.join(repo, ".git"), NodePath.join(linked, ".git"), "junction");
    assert.isDefined(TailorGitSpawner.checkGitDirFile(linked, policy), "a .git junction");
  });
});
