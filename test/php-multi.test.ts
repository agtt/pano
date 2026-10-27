import { describe, expect, test } from "bun:test";
import { cleanDumpLine, grantMatches, parseGrants } from "../src/agent/cpanel.ts";
import { renderCaddyfile } from "../src/agent/edge.ts";
import { analyzeHtaccess } from "../src/agent/htaccess.ts";
import { renderFpmConf, renderPhpIni, renderPhpUnit } from "../src/agent/php.ts";
import type { App, Site } from "../src/agent/state.ts";
import { formatProcesses, parseProcesses, v } from "../src/shared/validate.ts";

describe("processes", () => {
  const text = `# fastpos
pos    | apps/pos    | example.com, www.example.com | 1024 |
online | apps/online | *.example.com, *             | 768  |
api    | apps/api    | example.com/api               | 256  | bun run start:prod
worker | .           | -                            | 256  | bun packages/api/cron/worker.ts`;

  test("parses and round-trips", () => {
    const list = parseProcesses(text);
    expect(list.map((p) => p.name)).toEqual(["pos", "online", "api", "worker"]);
    expect(list[1]!.routes).toEqual(["*.example.com", "*"]);
    expect(list[2]!.routes).toEqual(["example.com/api"]);
    expect(list[3]).toEqual({ name: "worker", dir: "", routes: [], memory_mb: 256, start: "bun packages/api/cron/worker.ts" });
    expect(parseProcesses(formatProcesses(list))).toEqual(list);
  });

  test("rejects bad input", () => {
    expect(() => parseProcesses("Bad_Name | . | - | 256 |")).toThrow();
    expect(() => parseProcesses("a | ../x | - | 256 |")).toThrow();
    expect(() => parseProcesses("a | . | - | 256 |\na | . | - | 256 |")).toThrow();
    expect(() => v.route("example.com/a b")).toThrow();
    expect(v.route("Example.com/Admin/")).toBe("example.com/Admin");
  });
});

describe("edge: multi-process apps and php sites", () => {
  const app = {
    name: "fastpos", kind: "managed", domains: [], active_slot: "a", port_a: 4100, port_b: 4101,
    processes: [
      { name: "pos", dir: "apps/pos", routes: ["example.com", "www.example.com"], memory_mb: 512, start: "", port_a: 4102, port_b: 4103 },
      { name: "api", dir: "apps/api", routes: ["example.com/api"], memory_mb: 512, start: "", port_a: 4104, port_b: 4105 },
      { name: "online", dir: "apps/online", routes: ["*.example.com"], memory_mb: 512, start: "", port_a: 4106, port_b: 4107 },
      { name: "worker", dir: "", routes: [], memory_mb: 256, start: "bun w.ts", port_a: 0, port_b: 0 },
    ],
  } as unknown as App;
  const php = {
    name: "blog.example.org", kind: "php", domains: ["blog.example.org"], routes: [], enabled: 1, on_demand_tls: 0, tls_cert: "", tls_key: "",
    root: "/srv/pano/sites/blog.example.org/public", ask_url: "", php_version: "8.5", source: "pano", deny_paths: ["/private", "/wp-content/uploads/wc-logs"],
    converted_from: null, created_at: 0,
  } as Site;
  const out = renderCaddyfile({ apps: [app], sites: [php], settings: { email: "", behindCloudflare: false, hooksDomain: "" }, certs: new Set() });

  test("hosts with different routes get their own blocks", () => {
    expect(out).toContain("www.example.com {\n\timport pano_common\n\treverse_proxy 127.0.0.1:4102");
    const block = out.slice(out.indexOf("example.com {"));
    expect(block).toContain("@route0 path /api /api/*");
    expect(block).toContain("reverse_proxy 127.0.0.1:4104");
    expect(block.indexOf("reverse_proxy 127.0.0.1:4102")).toBeGreaterThan(block.indexOf("127.0.0.1:4104"));
  });
  test("wildcard hosts get on-demand certificates; workers get no route", () => {
    expect(out).toContain("*.example.com {\n\timport pano_common\n\ttls {\n\t\ton_demand");
    expect(out).not.toContain(":0");
  });
  test("php sites go to their own pool, with deny rules first", () => {
    expect(out).toContain("root * /srv/pano/sites/blog.example.org/public");
    expect(out).toContain("php_fastcgi unix//run/pano-php/blog.example.org/fpm.sock");
    expect(out).toContain("@pano_deny_dirs path /private /private/* /wp-content/uploads/wc-logs /wp-content/uploads/wc-logs/*");
    expect(out.indexOf("respond @pano_deny 404")).toBeLessThan(out.indexOf("php_fastcgi"));
    expect(out).toContain("not path /.well-known/*");
  });
});

describe("php config", () => {
  test("pool, ini and unit are locked down", () => {
    const ini = renderPhpIni("shop");
    expect(ini).toContain("open_basedir = /srv/pano/sites/shop/");
    expect(ini).toContain("expose_php = Off");
    expect(ini).toContain("session.cookie_secure = 1");
    expect(ini).toMatch(/disable_functions = .*shell_exec/);
    const fpm = renderFpmConf("shop");
    expect(fpm).toContain("listen.acl_users = pano-edge");
    expect(fpm).toContain("pm = ondemand");
    const unit = renderPhpUnit("shop", "8.5");
    expect(unit).toContain("User=site-shop");
    expect(unit).toContain("ExecStart=/opt/remi/php85/root/usr/sbin/php-fpm");
    expect(unit).toContain("MemoryDenyWriteExecute=true");
    expect(unit).toContain("ReadWritePaths=/srv/pano/sites/shop");
  });
});

describe("htaccess", () => {
  test("the WordPress block needs nothing", () => {
    const wp = `# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
RewriteBase /
RewriteRule ^index\\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>
# END WordPress`;
    expect(analyzeHtaccess(wp)).toEqual({ deny: false, notes: [] });
  });
  test("deny from all closes the directory, scoped rules are only reported", () => {
    expect(analyzeHtaccess("Order deny,allow\nDeny from all").deny).toBe(true);
    expect(analyzeHtaccess("<IfModule mod_authz_core.c>\n  Require all denied\n</IfModule>").deny).toBe(true);
    const files = analyzeHtaccess("<Files *.php>\ndeny from all\n</Files>");
    expect(files.deny).toBe(false);
    expect(files.notes.length).toBe(1);
    expect(analyzeHtaccess("AuthType Basic\nAuthUserFile /home/x/.htpasswd\nRequire valid-user").deny).toBe(true);
    expect(analyzeHtaccess("RewriteRule ^old$ /new [R=301,L]").notes[0]).toContain("rewrite");
  });
});

describe("cpanel", () => {
  const grants = `GRANT USAGE ON *.* TO 'shop'@'localhost' IDENTIFIED BY PASSWORD '*0123456789ABCDEF0123456789ABCDEF01234567';
GRANT ALL PRIVILEGES ON \`shop\\_wp\`.* TO 'shop'@'localhost';
GRANT USAGE ON *.* TO 'shop_ro'@'localhost' IDENTIFIED BY PASSWORD '*AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
GRANT SELECT, SUPER, FILE ON \`shop\\_%\`.* TO 'shop_ro'@'localhost';
GRANT ALL PRIVILEGES ON \`shop\\_wp\`.* TO 'shop'@'%';
CREATE USER \`shop_new\`@\`localhost\` IDENTIFIED WITH 'caching_sha2_password' AS '$A$005$abc';`;

  test("keeps localhost accounts, hashes and whitelisted privileges", () => {
    const g = parseGrants(grants);
    expect(g.users.get("shop")?.hash).toBe("*0123456789ABCDEF0123456789ABCDEF01234567");
    expect(g.users.get("shop_new")?.hash).toBe("$A$005$abc");
    expect(g.grants).toEqual([
      { user: "shop", db: "shop\\_wp", privs: ["ALL PRIVILEGES"] },
      { user: "shop_ro", db: "shop\\_%", privs: ["SELECT"] },
    ]);
    expect(grantMatches("shop\\_wp", "shop_wp")).toBe(true);
    expect(grantMatches("shop\\_wp", "shopxwp")).toBe(false);
    expect(grantMatches("shop\\_%", "shop_anything")).toBe(true);
  });

  test("dump lines are made loadable without touching data", () => {
    expect(cleanDumpLine("/*!50013 DEFINER=`cpuser`@`localhost` SQL SECURITY DEFINER */")).toBe("/*!50013 SQL SECURITY DEFINER */");
    expect(cleanDumpLine(") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;")).toBe(") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;");
    expect(cleanDumpLine("SET @@GLOBAL.GTID_PURGED=/*!80000 '+'*/ 'abc:1-5';")).toBeNull();
    expect(cleanDumpLine("CREATE TABLE t (a int) /*!80016 DEFAULT ENCRYPTION='N' */;")).toBe("CREATE TABLE t (a int) ;");
    const row = "INSERT INTO `t` VALUES ('DEFINER=`x`@`y` utf8mb4_0900_ai_ci');";
    expect(cleanDumpLine(row)).toBe(row);
  });
});
