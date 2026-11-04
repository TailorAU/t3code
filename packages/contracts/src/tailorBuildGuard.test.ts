/** Tailor fork (TailorAU/t3code): the build refuses hosted-service configuration. */
import { describe, expect, it } from "vite-plus/test";

import {
  assertNoRemoteBuildConfig,
  forbiddenRemoteBuildVariables,
} from "../../../tailor/build/assertNoRemoteBuildConfig.ts";

describe("Tailor build guard", () => {
  it("flags Clerk, relay and relay-tracing variables", () => {
    expect(
      forbiddenRemoteBuildVariables({
        VITE_CLERK_PUBLISHABLE_KEY: "x",
        VITE_T3CODE_RELAY_URL: "x",
        VITE_RELAY_OTLP_TRACES_URL: "x",
        T3CODE_RELAY_URL: "x",
        T3CODE_CLERK_CLI_OAUTH_CLIENT_ID: "x",
        T3CODE_RELAY_CLIENT_OTLP_TRACES_TOKEN: "x",
        PATH: "x",
        VITE_WS_URL: "x",
        T3CODE_CLERK_EMPTY: " ",
      }),
    ).toEqual([
      "T3CODE_CLERK_CLI_OAUTH_CLIENT_ID",
      "T3CODE_RELAY_CLIENT_OTLP_TRACES_TOKEN",
      "T3CODE_RELAY_URL",
      "VITE_CLERK_PUBLISHABLE_KEY",
      "VITE_RELAY_OTLP_TRACES_URL",
      "VITE_T3CODE_RELAY_URL",
    ]);
  });

  it("throws when any is set and passes when none is", () => {
    expect(() => assertNoRemoteBuildConfig({ VITE_CLERK_JWT_TEMPLATE: "x" })).toThrow(
      /VITE_CLERK_JWT_TEMPLATE/,
    );
    expect(() => assertNoRemoteBuildConfig({ PATH: "x" })).not.toThrow();
  });
});
