import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { decryptStream, encryptStream } from "../src/agent/crypto-stream.ts";
import { renderCaddyfile } from "../src/agent/edge.ts";
import { moveListenersToLocalhost } from "../src/agent/cutover.ts";
import { parseOls, readServerConfig, readVhost, serializeOls } from "../src/agent/ols.ts";
import type { App, Site } from "../src/agent/state.ts";
import { formatEnv, parseEnv, v } from "../src/shared/validate.ts";
import { code, verify } from "../src/web/totp.ts";

const fixture = (p: string) => readFileSync(join(import.meta.dir, "fixtures/lsws/conf", p), "utf8");

describe("ols", () => {
  test("round-trips files byte for byte", () => {
    for (const f of ["httpd_config.conf", "vhosts/api.example.net/vhost.conf", "vhosts/blog.example.org/vhost.conf"]) {
      expect(serializeOls(parseOls(fixture(f)))).toBe(fixture(f));
    }
  });

  test("reads listeners, maps and vhosts", () => {
    const s = readServerConfig(fixture("httpd_config.conf"));
    expect(s.vhosts.map((x) => x.name)).toEqual(["shop.example", "api.example.net", "blog.example.org", "Example"]);
    expect(s.listeners[0]!.maps[0]!.domains).toEqual(["shop.example", "www.shop.example", "*.shop.example", "*"]);
  });

  test("reads proxy contexts, heredoc rules and ssl", () => {
    const vh = readVhost(fixture("vhosts/api.example.net/vhost.conf"), { VH_NAME: "api.example.net", VH_ROOT: "/home/api.example.net" });
    expect(vh.docRoot).toBe("/home/api.example.net/html");
    expect(vh.contexts.find((c) => c.uri === "/__deploy/github")?.handler).toBe("api-hook");
    expect(vh.processors.find((p) => p.name === "api")?.address).toBe("127.0.0.1:3100");
    expect(vh.ssl?.certFile).toBe("/opt/api/tls/origin.pem");
  });

  test("cutover moves every listener to a unique localhost port", () => {
    const out = moveListenersToLocalhost(fixture("httpd_config.conf"), 8088);
    const s = readServerConfig(out);
    expect(s.listeners.map((l) => l.address)).toEqual(["127.0.0.1:8088", "127.0.0.1:8089", "127.0.0.1:8090"]);
    // everything else untouched
    expect(out.split("\n").length).toBe(fixture("httpd_config.conf").split("\n").length);
  });
});

describe("edge", () => {
  const app = {
    name: "web", kind: "managed", domains: ["example.com", "www.example.com"], active_slot: "b", port_a: 4100, port_b: 4101,
  } as App;
  const proxy = {
    name: "shop", kind: "proxy", domains: ["shop.example", "*"], routes: [{ path: "/", upstream: "127.0.0.1:3000" }, { path: "/online", upstream: "127.0.0.1:3001" }],
    enabled: 1, on_demand_tls: 1, tls_cert: "", tls_key: "", root: "", ask_url: "", php_version: "", source: "cyberpanel", created_at: 0,
  } as Site;
  const php = { ...proxy, name: "blog", kind: "legacy", domains: ["blog.example.org"], routes: [], on_demand_tls: 0 } as Site;
  const out = renderCaddyfile({ apps: [app], sites: [proxy, php], settings: { email: "a@b.co", behindCloudflare: true, hooksDomain: "hooks.example.com" }, certs: new Set(["site-blog"]) });

  test("routes apps to their active slot", () => {
    expect(out).toContain("example.com, www.example.com {");
    expect(out).toContain("reverse_proxy 127.0.0.1:4101");
  });
  test("catch-all uses on-demand TLS and longest-prefix routes", () => {
    expect(out).toContain("shop.example, https:// {");
    expect(out).toContain("\t\ton_demand");
    expect(out.indexOf("@route0 path /online /online/*")).toBeLessThan(out.indexOf("handle {"));
  });
  test("php sites go to the localhost OpenLiteSpeed with imported certs", () => {
    expect(out).toContain("tls /etc/pano/certs/site-blog/cert.pem /etc/pano/certs/site-blog/key.pem");
    expect(out).toContain("reverse_proxy 127.0.0.1:8088");
  });
  test("only /hooks/* is public on the hooks domain", () => {
    expect(out).toContain("hooks.example.com {");
    expect(out).toContain("handle /hooks/* {");
  });
});

describe("backup encryption", () => {
  const key = Buffer.alloc(32, 7);
  const roundtrip = async (data: Uint8Array, k = key, mutate?: (b: Buffer) => Buffer) => {
    let enc: Buffer = Buffer.from(await new Response(new Blob([data as Uint8Array<ArrayBuffer>]).stream().pipeThrough(encryptStream(key))).arrayBuffer());
    if (mutate) enc = mutate(enc);
    return Buffer.from(await new Response(new Blob([enc]).stream().pipeThrough(decryptStream(k))).arrayBuffer());
  };

  test("round-trips small and multi-chunk data", async () => {
    expect((await roundtrip(new Uint8Array(0))).length).toBe(0);
    const data = Buffer.concat([Buffer.alloc(9 * 1024 * 1024, 1), Buffer.from(crypto.getRandomValues(new Uint8Array(65536)))]);
    expect((await roundtrip(data)).equals(data)).toBe(true);
  });
  test("rejects a wrong key, tampering and truncation", async () => {
    const data = Buffer.alloc(5 * 1024 * 1024, 3);
    await expect(roundtrip(data, Buffer.alloc(32, 8))).rejects.toThrow();
    await expect(roundtrip(data, key, (b) => ((b[100] = b[100]! ^ 1), b))).rejects.toThrow();
    // drop the final chunk: 16-byte header + first chunk (4 + 4 MiB + 16)
    await expect(roundtrip(data, key, (b) => b.subarray(0, 16 + 4 + 4 * 1024 * 1024 + 16))).rejects.toThrow("truncated");
  });
});

describe("totp", () => {
  test("RFC 6238 vector", () => {
    expect(code("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 1)).toBe("287082");
  });
  test("blocks replay of a used step", () => {
    const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    const now = 59_000;
    const step = verify(secret, code(secret, 1), 0, now);
    expect(step).toBe(1);
    expect(verify(secret, code(secret, 1), step!, now)).toBeNull();
  });
});

describe("validation", () => {
  test("domains, names and git urls", () => {
    expect(v.domains("Example.com, www.example.com")).toEqual(["example.com", "www.example.com"]);
    expect(() => v.domain("exa mple.com")).toThrow();
    expect(() => v.appName("App")).toThrow();
    expect(() => v.gitUrl("--upload-pack=x")).toThrow();
    expect(v.gitUrl("git@github.com:me/app.git")).toBe("git@github.com:me/app.git");
    expect(() => v.pathUnder("/home/../etc/shadow", ["/home"])).toThrow();
  });
  test("env files survive quotes and dollars", () => {
    const vars = { A: 'he said "hi"', B: "$HOME/x", C: "a\\b" };
    expect(formatEnv(vars)).toContain('A="he said \\"hi\\""');
    expect(parseEnv("X=1\n# c\nY='two'\n")).toEqual({ X: "1", Y: "two" });
  });
});
