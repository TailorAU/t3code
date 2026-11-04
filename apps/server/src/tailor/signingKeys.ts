/**
 * Tailor fork (TailorAU/t3code): emergency revoke.
 *
 * Every bearer token, browser session cookie, websocket ticket, MCP OAuth token, guest share
 * link and asset link T3 issues is an HMAC over its claims with one of these server secrets.
 * Replacing them makes every credential issued before invalid at its signature check, whatever
 * the session table says. `t3 auth rotate-signing-keys` (cli/auth.ts) runs this as the account
 * that owns the T3 home (t3agent), so no administrator code touches that folder
 * (tailor/policy/install-policy.ps1 -EmergencyRevoke).
 *
 * Other files in the secrets folder (for example stored provider credentials and the
 * secret-request salt) are left alone: they are not token-signing keys.
 */
import * as Crypto from "effect/Crypto";
import * as Effect from "effect/Effect";

import * as ServerSecretStore from "../auth/ServerSecretStore.ts";

export const TAILOR_SIGNING_SECRET_NAMES = [
  "server-signing-key",
  "mcp-oauth-signing-key",
  "guest-share-signing-key",
  "asset-access-signing-key",
] as const;

const SIGNING_SECRET_BYTES = 32;

/** Writes a new random value for every signing secret (temp file + rename). Returns the names. */
export const rotateSigningKeys = Effect.gen(function* () {
  const crypto = yield* Crypto.Crypto;
  const secrets = yield* ServerSecretStore.ServerSecretStore;
  for (const name of TAILOR_SIGNING_SECRET_NAMES) {
    const value = yield* crypto.randomBytes(SIGNING_SECRET_BYTES);
    yield* secrets.set(name, value);
  }
  return [...TAILOR_SIGNING_SECRET_NAMES];
}).pipe(Effect.withSpan("tailor.rotateSigningKeys"));
