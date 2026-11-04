/**
 * Tailor fork (TailorAU/t3code): the build fails if any hosted-service value would be
 * compiled in. A local-only build has no Clerk sign-in, no T3 Connect relay and no relay
 * tracing, so none of these may be set when the server or web app is built.
 */
const FORBIDDEN_BUILD_VARIABLE = /^(VITE_)?(T3CODE_)?(CLERK_|RELAY_|T3CODE_RELAY_)/;
const FORBIDDEN_EXACT = new Set(["T3CODE_RELAY_URL", "VITE_T3CODE_RELAY_URL"]);

export function forbiddenRemoteBuildVariables(
  env: Readonly<Record<string, string | undefined>>,
): ReadonlyArray<string> {
  return Object.entries(env)
    .filter(
      ([name, value]) =>
        (FORBIDDEN_EXACT.has(name) || FORBIDDEN_BUILD_VARIABLE.test(name)) &&
        value !== undefined &&
        value.trim().length > 0,
    )
    .map(([name]) => name)
    .sort();
}

export function assertNoRemoteBuildConfig(
  env: Readonly<Record<string, string | undefined>>,
): void {
  const found = forbiddenRemoteBuildVariables(env);
  if (found.length > 0) {
    throw new Error(
      `Tailor fork build refuses hosted-service configuration: ${found.join(", ")}. Unset them and rebuild.`,
    );
  }
}
