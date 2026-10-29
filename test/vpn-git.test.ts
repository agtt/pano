import { describe, expect, test } from "bun:test";
import { parseRepo } from "../src/agent/github.ts";
import { renderGuard } from "../src/agent/guard.ts";
import { countLogins, matchRules, parseLists, renderBans, renderReputation } from "../src/agent/shield.ts";
import { renderCaddyfile } from "../src/agent/edge.ts";
import { formatCrons, parseCrons } from "../src/agent/apps.ts";
import { clientConfig, renderConf, renderRules, renderUnit, zoneCommands, zonePorts } from "../src/agent/vpn.ts";

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

describe("vpn firewall zone", () => {
  const L = { panel: false, ssh: false, services: false, databases: false };
  test("peers get SSH and the panel, services and database ports only as the locks say", () => {
    expect(zonePorts(L, 2222, 7800)).toEqual(["2222/tcp", "7800/tcp"]);
    expect(zonePorts({ ...L, databases: true }, 22, 7800)).toEqual(["22/tcp", "3306/tcp", "5432/tcp", "6379/tcp", "7800/tcp"]);
    expect(zonePorts({ ...L, services: true }, 22, 7800)).toContain("7080/tcp");
    expect(zonePorts({ ...L, services: true }, 22, 7800)).not.toContain("80/tcp");
  });
  test("moves pano0 out of trusted into its own zone, then is idempotent", () => {
    const want = ["22/tcp", "7800/tcp"];
    const first = zoneCommands({ zones: ["public", "trusted"], inTrusted: true, inZone: false, ports: [] }, want);
    expect(first).toEqual([
      ["--new-zone=pano-vpn"],
      ["--zone=trusted", "--remove-interface=pano0"],
      ["--zone=pano-vpn", "--add-interface=pano0"],
      ["--zone=pano-vpn", "--add-port=22/tcp"],
      ["--zone=pano-vpn", "--add-port=7800/tcp"],
    ]);
    expect(zoneCommands({ zones: ["pano-vpn"], inTrusted: false, inZone: true, ports: ["7800/tcp", "22/tcp"] }, want)).toEqual([]);
    expect(zoneCommands({ zones: ["pano-vpn"], inTrusted: false, inZone: true, ports: ["22/tcp", "3306/tcp"] }, want)).toEqual([
      ["--zone=pano-vpn", "--remove-port=3306/tcp"],
      ["--zone=pano-vpn", "--add-port=7800/tcp"],
    ]);
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

describe("shield", () => {
  const ids = (path: string, text: string) => matchRules(path, text).map((h) => h.rule.id);
  test("catches web shells, droppers, spam redirects; leaves normal code alone", () => {
    expect(ids("/s/x.php", "<?php eval(base64_decode($x));")).toContain("php.eval.decode");
    expect(ids("/s/x.php", "<?php @system($_GET['c']);")).toContain("php.exec.input");
    expect(ids("/s/x.php", "<?php $_POST['f']($_POST['a']);")).toContain("php.callable.input");
    expect(ids("/s/x.php", "<?php $default_action = 'FilesMan';")).toContain("php.shell.known");
    expect(ids("/s/x.php", `<?php preg_replace("/.*/e", $_REQUEST['x'], "");`)).toContain("php.preg.e");
    expect(ids("/s/logo.png", "GIF89a<?php eval($_POST[1]); ?>")).toContain("php.in.media");
    expect(ids("/s/wp-content/uploads/2024/x.php", "<?php echo 1;")).toContain("php.in.uploads");
    expect(ids("/s/.htaccess", "RewriteCond %{HTTP_REFERER} google\nRewriteRule .* https://spam.example/ [R,L]")).toContain("htaccess.spam.redirect");
    expect(ids("/s/x.php", `<?php $a = "${"QUJD".repeat(1000)}";`)).toContain("php.obfuscated.blob");
    // ordinary WordPress-style code
    expect(ids("/s/wp-includes/x.php", "<?php function get_option($n) { return apply_filters('x', base64_encode($n)); } exec('ls'); preg_replace('/a/i', 'b', $c);")).toEqual([]);
    expect(ids("/s/app.js", "const x = document.createElement('div');")).toEqual([]);
  });
  test("reputation lists never block private or reserved networks", () => {
    const d4 = ['{"cidr":"1.10.16.0/20","sblid":"SBL1"}', '{"cidr":"10.0.0.0/8"}', '{"cidr":"192.168.0.0/16"}', '{"type":"metadata"}'].join("\n");
    const l = parseLists(d4, '{"cidr":"2001:db8:1::/48"}\n{"cidr":"fd00::/8"}', "# c2\n203.0.113.9\n127.0.0.1\n");
    expect(l).toEqual({ v4: ["1.10.16.0/20"], v6: ["2001:db8:1::/48"], c2: ["203.0.113.9"] });
    const nft = renderReputation(l);
    expect(nft).toContain("ip saddr @drop4 drop");
    expect(nft).toContain("ip daddr @c2 reject");
    expect(nft.indexOf('iifname { "lo", "pano0" } accept')).toBeLessThan(nft.indexOf("@drop4 drop"));
  });
  test("login brute force: only POSTs to wp-login/xmlrpc, per address, over the limit", () => {
    const line = (ip: string, uri: string, method = "POST") => JSON.stringify({ request: { client_ip: ip, method, uri } });
    const now = Date.now();
    const lines = [...Array(21)].map(() => line("198.51.100.4", "/wp-login.php"));
    lines.push(...[...Array(30)].map(() => line("198.51.100.5", "/wp-login.php", "GET")), ...[...Array(30)].map(() => line("127.0.0.5", "/xmlrpc.php")));
    expect(countLogins(lines, now)).toEqual(["198.51.100.4"]);
    expect(renderBans(["198.51.100.4"], [])).toContain("elements = { 198.51.100.4 }");
    const caddy = renderCaddyfile({ apps: [], sites: [], settings: { email: "", behindCloudflare: true, hooksDomain: "" }, certs: new Set(), banned: ["198.51.100.4"] });
    expect(caddy).toContain("@pano_banned client_ip 198.51.100.4");
  });
});
