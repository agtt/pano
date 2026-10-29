import { expect, test } from "bun:test";
import { needsOtp } from "../src/agent/rpc.ts";
import {
  WP_PHAR,
  dbNameFor,
  parseAdmins,
  parseCoreUpdates,
  parseExtensions,
  parseMaintenance,
  parseSha512,
  parseWpJson,
  pickWpCliAssets,
  secretsYaml,
  updateArgs,
  validateInstall,
  wpCommand,
  wpEnv,
} from "../src/agent/wordpress.ts";
import { WordPressCard, WordPressPage } from "../src/web/views/wordpress.tsx";

test("wp-cli argv: site PHP, phar, arguments, then globals; no secrets on it", () => {
  const argv = wpCommand("8.3", "/srv/pano/sites/a.com", ["plugin", "update", "--all"]);
  expect(argv[0]).toContain("php83");
  expect(argv[argv.indexOf(WP_PHAR) + 1]).toBe("plugin");
  expect(argv).toContain("--path=/srv/pano/sites/a.com/public");
  expect(argv).toContain("--skip-plugins");
  expect(argv).toContain("sys_temp_dir=/srv/pano/sites/a.com/tmp");
  expect(wpEnv("8.3", "/srv/pano/sites/a.com").HOME).toBe("/srv/pano/sites/a.com/tmp");
});

test("passwords go in a wp-cli config file, quoted", () => {
  expect(secretsYaml({ "core install": { admin_password: 'p"w' }, "user update": { user_pass: "x" } })).toBe(
    'core install:\n  admin_password: "p\\"w"\nuser update:\n  user_pass: "x"\n',
  );
});

test("release assets and sha512 parsing", () => {
  const base = "https://github.com/wp-cli/wp-cli/releases/download/v2.11.0/";
  const release = {
    assets: [
      { name: "wp-cli-2.11.0.phar.md5", browser_download_url: base + "wp-cli-2.11.0.phar.md5" },
      { name: "wp-cli-2.11.0.phar", browser_download_url: base + "wp-cli-2.11.0.phar" },
      { name: "wp-cli-2.11.0.phar.sha512", browser_download_url: base + "wp-cli-2.11.0.phar.sha512" },
    ],
  };
  expect(pickWpCliAssets(release)).toEqual({ phar: base + "wp-cli-2.11.0.phar", sha512: base + "wp-cli-2.11.0.phar.sha512" });
  expect(() => pickWpCliAssets({ assets: [release.assets[1]] })).toThrow();
  expect(() => pickWpCliAssets({ assets: [{ name: "wp-cli-2.11.0.phar", browser_download_url: "https://evil.example/x" }, { name: "wp-cli-2.11.0.phar.sha512", browser_download_url: "https://evil.example/y" }] })).toThrow();
  const h = "AB".repeat(64);
  expect(parseSha512(`${h}  wp-cli-2.11.0.phar\n`)).toBe(h.toLowerCase());
  expect(() => parseSha512("nothing")).toThrow();
});

test("parses wp-cli JSON around noise", () => {
  const plugins = `Notice: something\n[{"name":"akismet","title":"Akismet","status":"active","version":"5.0","update_version":"5.3"},{"name":"hello","title":"","status":"inactive","version":"1.7","update_version":""}]`;
  expect(parseExtensions(plugins)).toEqual([
    { name: "akismet", title: "Akismet", status: "active", version: "5.0", update: "5.3" },
    { name: "hello", title: "hello", status: "inactive", version: "1.7", update: "" },
  ]);
  expect(parseExtensions("Success: nothing")).toEqual([]);
  expect(parseCoreUpdates('[{"version":"6.5.3","update_type":"minor","package_url":"x"}]')).toEqual([{ version: "6.5.3", type: "minor" }]);
  expect(parseCoreUpdates("Success: WordPress is at the latest version.")).toEqual([]);
  expect(parseAdmins('[{"ID":"3","user_login":"boss","user_email":"b@x.com"}]')).toEqual([{ id: 3, login: "boss", email: "b@x.com" }]);
  expect(parseWpJson("garbage", null)).toBeNull();
  expect(parseMaintenance("Maintenance mode is active.")).toBe(true);
  expect(parseMaintenance("Maintenance mode is not active.")).toBe(false);
});

test("update arguments are validated", () => {
  expect(updateArgs("plugin", "all")).toEqual(["plugin", "update", "--all"]);
  expect(updateArgs("theme", ["twentytwentyfour"])).toEqual(["theme", "update", "twentytwentyfour"]);
  expect(() => updateArgs("plugin", ["--exec=evil"])).toThrow();
  expect(() => updateArgs("plugin", [])).toThrow();
  expect(() => updateArgs("plugin", "x" as any)).toThrow();
});

test("install input and database naming", () => {
  expect(validateInstall({ title: " My Blog ", adminUser: "boss", adminEmail: "a@b.co" })).toEqual({ title: "My Blog", adminUser: "boss", adminEmail: "a@b.co" });
  expect(() => validateInstall({ title: "x", adminUser: "a b", adminEmail: "a@b.co" })).toThrow();
  expect(() => validateInstall({ title: "x", adminUser: "boss", adminEmail: "no" })).toThrow();
  expect(dbNameFor("My-Site.com", new Set())).toBe("wp_my_site_com");
  expect(dbNameFor("a.com", new Set(["wp_a_com"]))).toBe("wp_a_com_2");
});

test("install and password reset need an authenticator code", () => {
  expect(needsOtp("wp.install", {})).toBe(true);
  expect(needsOtp("wp.resetPassword", {})).toBe(true);
  expect(needsOtp("wp.status", {})).toBe(false);
});

test("views: install form on an empty site, tools on a WordPress site", () => {
  const empty = String(<WordPressCard site="a.com" d={{ installed: false, version: "", empty: true, auto: false }} csrf="t" />);
  expect(empty).toContain("/sites/a.com/wordpress/install");
  expect(empty).toContain('name="otp"');
  const page = String(
    <WordPressPage
      site="a.com"
      csrf="t"
      st={{
        version: "6.5.2",
        coreUpdates: [{ version: "6.5.3", type: "minor" }],
        plugins: [{ name: "akismet", title: "Akismet", status: "active", version: "5.0", update: "5.3" }],
        themes: [],
        maintenance: false,
        admins: [{ id: 1, login: "boss", email: "b@x.com" }],
        auto: true,
      }}
    />,
  );
  expect(page).toContain('value="akismet"');
  expect(page).toContain("/wordpress/password");
  expect(page).toContain("6.5.3");
});
