import { describe, expect, it } from "@effect/vitest";

import { faviconUrlForOrigin, toolActivityFaviconUrl } from "./favicon.ts";

describe("faviconUrlForOrigin", () => {
  // Tailor fork: the Google favicon service is off at compile time.
  it("never builds a third-party favicon service URL", () => {
    expect(faviconUrlForOrigin("https://github.com:8443/pingdotgg/t3code?private=query", 64)).toBeNull();
  });

  // regression: #5838 no favicon request for missing or non-http origins
  it.each([null, "invalid URL", "file:///tmp/private"])(
    "rejects an invalid or unsupported origin %s",
    (origin) => {
      expect(faviconUrlForOrigin(origin)).toBeNull();
    },
  );
});

describe("toolActivityFaviconUrl", () => {
  it("uses the page origin instead of a third-party favicon service", () => {
    expect(toolActivityFaviconUrl({ pageUrl: "https://example.com/docs/page?q=1" }, "light")).toBe(
      "https://example.com/favicon.ico",
    );
    expect(toolActivityFaviconUrl({ pageUrl: "http://localhost:5173/app" }, "light")).toBe(
      "http://localhost:5173/favicon.ico",
    );
  });

  it("accepts provider-supplied image URLs but rejects extension URLs", () => {
    expect(
      toolActivityFaviconUrl(
        { pageUrl: "https://example.com/docs", faviconUrl: "https://example.com/icon.png" },
        "light",
      ),
    ).toBe("https://example.com/icon.png");
    expect(
      toolActivityFaviconUrl(
        { pageUrl: "https://example.com/docs", faviconUrl: "chrome-extension://example/_favicon/" },
        "light",
      ),
    ).toBe("https://example.com/favicon.ico");
  });
});
