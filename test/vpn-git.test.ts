import { describe, expect, test } from "bun:test";
import { parseRepo } from "../src/agent/github.ts";
import { renderGuard } from "../src/agent/guard.ts";
import { formatCrons, parseCrons } from "../src/agent/apps.ts";
import { clientConfig, renderConf, renderRules, renderUnit } from "../src/agent/vpn.ts";

describe("vpn", () => {
  test("server config lists each device with its preshared key and a /32", () => {
    const conf = renderConf("SERVERKEY", 51820, [{ public_key: "A", psk: "P", ip: "10.77.0.2" }]);
    expect(conf).toContain("ListenPort = 51820");
    expect(conf).toContain("PresharedKey = P");
    expect(conf).toContain("AllowedIPs = 10.77.0.2/32");
  });
  test("locks drop only what is locked, tunnel and open sessions stay", () => {
    const none = renderRules({ panel: false, ssh: false, services: false, databases: false }, 22);
    expect(none).not.toContain("dport");
    expect(none).toContain("ip daddr 10.77.0.0/24 drop");
    const all = renderRules({ panel: true, ssh: true, services: true, databases: true }, 2222);
    expect(all).toContain("tcp dport 2222 drop");
    expect(all).toContain("3306");
    expect(all.indexOf('iifname "pano0" accept')).toBeLessThan(all.indexOf("drop"));
    expect(all.indexOf("ct state established,related accept")).toBeLessThan(all.indexOf("dport 2222 drop"));
    expect(all.startsWith("table inet pano_vpn\ndelete table inet pano_vpn\n")).toBe(true);
  });
  test("client config routes only the server through the tunnel", () => {
    const c = clientConfig({ privateKey: "K", ip: "10.77.0.2", psk: "P" }, { publicKey: "S", endpoint: "2001:db8::1", port: 51820 });
    expect(c).toContain("AllowedIPs = 10.77.0.1/32");
    expect(c).toContain("Endpoint = [2001:db8::1]:51820");
    expect(renderUnit()).toContain("wg setconf pano0");
  });
});

describe("github", () => {
  test("parses every repository URL form", () => {
    expect(parseRepo("https://github.com/me/app.git")).toEqual({ owner: "me", repo: "app" });
    expect(parseRepo("git@github.com:me/my.app.git")).toEqual({ owner: "me", repo: "my.app" });
    expect(parseRepo("ssh://git@github.com/org/x")).toEqual({ owner: "org", repo: "x" });
    expect(parseRepo("https://gitlab.com/me/app.git")).toBeNull();
  });
});

describe("guard and crons", () => {
  test("guard rules: tunnel first, http limit off behind Cloudflare", () => {
    const g = renderGuard({ ssh: true, http: true }, 22, false);
    expect(g.indexOf('iifname { "lo", "pano0" } accept')).toBeLessThan(g.indexOf("ssh_ban4 tcp dport 22 drop"));
    expect(g).toContain("http_rate4");
    expect(renderGuard({ ssh: true, http: true }, 22, true)).not.toContain("http_rate");
    expect(renderGuard({ ssh: false, http: false }, 22, false)).not.toContain("drop");
  });
  test("crons parse and round-trip", () => {
    const c = parseCrons("*:0/15 | bun run sync.ts\n# note\ndaily | node x.js");
    expect(c).toEqual([{ schedule: "*:0/15", command: "bun run sync.ts" }, { schedule: "daily", command: "node x.js" }]);
    expect(parseCrons(formatCrons(c))).toEqual(c);
    expect(() => parseCrons("daily node x.js")).toThrow();
    expect(() => parseCrons("$(reboot) | x")).toThrow();
  });
});
