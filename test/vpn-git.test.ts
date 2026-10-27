import { describe, expect, test } from "bun:test";
import { parseRepo } from "../src/agent/github.ts";
import { clientConfig, renderConf, renderRules, renderUnit } from "../src/agent/vpn.ts";

describe("vpn", () => {
  test("server config lists each device with its preshared key and a /32", () => {
    const conf = renderConf("SERVERKEY", 51820, [{ public_key: "A", psk: "P", ip: "10.77.0.2" }]);
    expect(conf).toContain("ListenPort = 51820");
    expect(conf).toContain("PresharedKey = P");
    expect(conf).toContain("AllowedIPs = 10.77.0.2/32");
  });
  test("locks drop only what is locked, tunnel and open sessions stay", () => {
    const none = renderRules({ panel: false, ssh: false, services: false }, 22);
    expect(none).not.toContain("drop");
    const all = renderRules({ panel: true, ssh: true, services: true }, 2222);
    expect(all).toContain("tcp dport 2222 drop");
    expect(all).toContain("3306");
    expect(all.indexOf('iifname "pano0" accept')).toBeLessThan(all.indexOf("drop"));
    expect(all.indexOf("ct state established,related accept")).toBeLessThan(all.indexOf("drop"));
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
