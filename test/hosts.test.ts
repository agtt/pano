import { describe, expect, test } from "bun:test";
import { hostAllowed } from "../src/web/hosts.ts";

describe("panel host allowlist", () => {
  const e = { webHost: "100.64.0.5", webVpnHost: "10.77.0.1", webHosts: "panel.example.com, box.tail1234.ts.net" };
  test("accepts the configured addresses and names, with or without port", () => {
    for (const h of ["100.64.0.5:7800", "10.77.0.1:7800", "localhost:7800", "127.0.0.1", "[::1]:7800", "Panel.Example.com", "box.tail1234.ts.net:7800"]) {
      expect(hostAllowed(h, e)).toBe(true);
    }
  });
  test("refuses other names (rebinding) and a missing host", () => {
    for (const h of ["evil.example", "evil.example:7800", "100.64.0.5.evil.example", "localhost.evil.example", "10.77.0.2", ""]) {
      expect(hostAllowed(h, e)).toBe(false);
    }
    expect(hostAllowed(undefined, e)).toBe(false);
  });
  test("listening on every address allows bare IPs but still no names", () => {
    const any = { webHost: "0.0.0.0", webVpnHost: "" };
    expect(hostAllowed("203.0.113.9:7800", any)).toBe(true);
    expect(hostAllowed("evil.example", any)).toBe(false);
  });
  test("default config is localhost only", () => {
    const d = { webHost: "127.0.0.1", webVpnHost: "" };
    expect(hostAllowed("localhost:7800", d)).toBe(true);
    expect(hostAllowed("203.0.113.9", d)).toBe(false);
  });
});
