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
  it("sets the hooks path, bare-repository, fsmonitor and ext-transport keys", () => {
    const env = withTailorGitConfig({ PATH: "/bin", GIT_EXTERNAL_DIFF: "evil" }, "/empty-hooks");
    assert.deepEqual(configOf(env), {
      "core.hooksPath": "/empty-hooks",
      "safe.bareRepository": "explicit",
      "core.fsmonitor": "false",
      "protocol.ext.allow": "never",
    });
    assert.isUndefined(env.GIT_EXTERNAL_DIFF);
    assert.strictEqual(env.PATH, "/bin");
  });

  it("appends after existing GIT_CONFIG entries and is idempotent", () => {
    const first = withTailorGitConfig(
      { GIT_CONFIG_COUNT: "1", GIT_CONFIG_KEY_0: "user.name", GIT_CONFIG_VALUE_0: "x" },
      "/h",
    );
    assert.strictEqual(first.GIT_CONFIG_KEY_0, "user.name");
    assert.strictEqual(first.GIT_CONFIG_COUNT, "5");
    const second = withTailorGitConfig(first, "/h");
    assert.strictEqual(second.GIT_CONFIG_COUNT, "5");
  });

  it("applies to the process environment so every child inherits it", () => {
    const env: NodeJS.ProcessEnv = { PATH: "/bin" };
    applyTailorGitHardening(env);
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
            spawner.spawn(ChildProcess.make("git", ["diff"], { env: { PATH: "/bin" } })),
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
      assert.strictEqual(seen[1]!.command, "node");
      assert.isUndefined(seen[1]!.env);
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
});
