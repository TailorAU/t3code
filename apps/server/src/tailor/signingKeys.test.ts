/** Tailor fork (TailorAU/t3code): emergency revoke invalidates every token issued before it. */
import * as NodeServices from "@effect/platform-node/NodeServices";
import { EnvironmentId } from "@t3tools/contracts";
import { expect, it } from "@effect/vitest";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Option from "effect/Option";

import * as ServerSecretStore from "../auth/ServerSecretStore.ts";
import * as SessionStore from "../auth/SessionStore.ts";
import * as ServerConfig from "../config.ts";
import * as ServerEnvironment from "../environment/ServerEnvironment.ts";
import * as SqlitePersistence from "../persistence/Sqlite.ts";
import { rotateSigningKeys, TAILOR_SIGNING_SECRET_NAMES } from "./signingKeys.ts";

// One secret store (on disk, in a temp base dir) and one database shared by every
// SessionStore instance below, as across a T3 restart.
const layerShared = Layer.mergeAll(ServerSecretStore.layer, SqlitePersistence.layerMemory).pipe(
  Layer.provideMerge(
    Layer.succeed(ServerEnvironment.ServerEnvironmentIdentity, {
      getEnvironmentId: Effect.succeed(EnvironmentId.make("test-environment")),
    }),
  ),
  Layer.provideMerge(ServerConfig.layerTest(process.cwd(), { prefix: "t3-tailor-revoke-test-" })),
  Layer.provideMerge(NodeServices.layer),
);

// A fresh SessionStore reads the signing key when it starts, like a restarted server.
const withFreshStore = <A, E, R>(
  body: (sessions: SessionStore.SessionStore["Service"]) => Effect.Effect<A, E, R>,
) =>
  Effect.gen(function* () {
    const sessions = yield* SessionStore.SessionStore;
    return yield* body(sessions);
  }).pipe(Effect.provide(SessionStore.layer));

it.effect("rotating the signing keys invalidates tokens issued before it", () =>
  Effect.gen(function* () {
    const secrets = yield* ServerSecretStore.ServerSecretStore;
    const issued = yield* withFreshStore((sessions) =>
      sessions.issue({ method: "bearer-access-token", scopes: ["tailor:connector"] }),
    );
    // Control: a restart without rotation still accepts the token.
    const before = yield* withFreshStore((sessions) => sessions.verify(issued.token));
    expect(before.sessionId).toBe(issued.sessionId);

    const oldKey = Option.getOrThrow(yield* secrets.get("server-signing-key"));
    const rotated = yield* rotateSigningKeys;
    expect(rotated).toEqual([...TAILOR_SIGNING_SECRET_NAMES]);
    const newKey = Option.getOrThrow(yield* secrets.get("server-signing-key"));
    expect(Buffer.from(newKey).equals(Buffer.from(oldKey))).toBe(false);
    expect(newKey.length).toBe(32);
    for (const name of TAILOR_SIGNING_SECRET_NAMES) {
      expect(Option.isSome(yield* secrets.get(name))).toBe(true);
    }

    const after = yield* withFreshStore((sessions) => Effect.flip(sessions.verify(issued.token)));
    expect(after._tag).toBe("InvalidSessionTokenSignatureError");

    // New tokens issued after the rotation work.
    const fresh = yield* withFreshStore((sessions) => sessions.issue({ method: "bearer-access-token" }));
    const verified = yield* withFreshStore((sessions) => sessions.verify(fresh.token));
    expect(verified.sessionId).toBe(fresh.sessionId);
  }).pipe(Effect.provide(layerShared)),
);
