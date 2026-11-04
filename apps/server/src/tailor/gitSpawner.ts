/**
 * Tailor fork (TailorAU/t3code): a ChildProcessSpawner decorator that applies the git
 * hardening (gitHardening.ts) to every git command, whatever environment its call site built.
 * server.ts layers it over the platform spawner, so every T3 git call goes through it.
 */
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import { ChildProcess, ChildProcessSpawner } from "effect/process";

import { isGitExecutable, withTailorGitArgs, withTailorGitConfig } from "./gitHardening.ts";

type Command = Parameters<ChildProcessSpawner.ChildProcessSpawner["Service"]["spawn"]>[0];

/** The command with the git hardening applied; any other command is returned unchanged. */
export function tailorGitCommand(command: Command): Command {
  if (command._tag !== "StandardCommand" || !isGitExecutable(command.command)) return command;
  const options = command.options;
  const base =
    options.env === undefined
      ? process.env
      : options.extendEnv === true
        ? { ...process.env, ...options.env }
        : options.env;
  return ChildProcess.make(command.command, [...withTailorGitArgs(command.args)], {
    ...options,
    env: withTailorGitConfig(base),
    extendEnv: false,
  }) as Command;
}

export const layer: Layer.Layer<
  ChildProcessSpawner.ChildProcessSpawner,
  never,
  ChildProcessSpawner.ChildProcessSpawner
> = Layer.effect(
  ChildProcessSpawner.ChildProcessSpawner,
  Effect.gen(function* () {
    const inner = yield* ChildProcessSpawner.ChildProcessSpawner;
    return ChildProcessSpawner.make((command) => inner.spawn(tailorGitCommand(command)));
  }),
);
