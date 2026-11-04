/** Tailor fork (TailorAU/t3code): the web app and agent-HTML Content-Security-Policies. */
import { describe, expect, it } from "@effect/vitest";

import { HTML_CONTENT_SECURITY_POLICY, TAILOR_WEB_APP_CONTENT_SECURITY_POLICY } from "../http.ts";

const directives = (policy: string) =>
  new Map(
    policy.split(";").map((part) => {
      const [name, ...values] = part.trim().split(/\s+/);
      return [name!, values.join(" ")] as const;
    }),
  );

describe("Tailor CSP", () => {
  it("sandboxes agent HTML with no network, no forms and no same-origin", () => {
    const csp = directives(HTML_CONTENT_SECURITY_POLICY);
    expect(csp.get("default-src")).toBe("'none'");
    expect(csp.get("script-src")).toBe("'unsafe-inline'");
    expect(csp.get("style-src")).toBe("'unsafe-inline'");
    expect(csp.get("img-src")).toBe("data: blob:");
    expect(csp.get("connect-src")).toBe("'none'");
    expect(csp.get("form-action")).toBe("'none'");
    expect(csp.get("sandbox")).toBe("allow-scripts");
  });

  it("keeps the web app on its own origin", () => {
    const csp = directives(TAILOR_WEB_APP_CONTENT_SECURITY_POLICY);
    for (const [name, value] of [
      ["default-src", "'self'"],
      ["script-src", "'self'"],
      ["connect-src", "'self'"],
      ["frame-ancestors", "'none'"],
      ["frame-src", "'none'"],
      ["object-src", "'none'"],
    ] as const) {
      expect(csp.get(name), name).toBe(value);
    }
  });
});
