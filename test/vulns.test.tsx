import { expect, test } from "bun:test";
import { cvss3, fixedIn, nodeSecurity, parseComposerLock, parseNpmLock, parseUpdateinfo, renderDnfAutomatic, severityOf } from "../src/agent/vulns.ts";
import { VulnsCard } from "../src/web/views/vulns.tsx";

test("CVSS 3 scores and severities", () => {
  expect(cvss3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toBe(9.8);
  expect(cvss3("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")).toBe(6.1);
  expect(cvss3("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N")).toBe(0);
  expect(severityOf({ database_specific: { severity: "MODERATE" } })).toBe("medium");
  expect(severityOf({ severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }] })).toBe("critical");
  expect(severityOf({})).toBe("unknown");
  const adv = { affected: [{ package: { name: "next" }, ranges: [{ events: [{ introduced: "0" }, { fixed: "14.2.25" }, { introduced: "15.0.0" }, { fixed: "15.2.3" }] }] }] };
  expect(fixedIn(adv, "next")).toBe("14.2.25, 15.2.3");
});

test("lockfiles", () => {
  const bunLock = `{
  "lockfileVersion": 1,
  "workspaces": { "": { "name": "shop", "dependencies": { "next": "15.0.0" } } },
  "packages": {
    "next": ["next@15.0.0", "", { "dependencies": { "@next/env": "15.0.0" } }, "sha512-x"],
    "@next/env": ["@next/env@15.0.0", "", {}, "sha512-y"],
    "shop/react": ["react@18.2.0", "", {}, "sha512-z"],
    "ui": ["ui@workspace:packages/ui"],
  }
}`;
  expect(parseNpmLock("bun.lock", bunLock)).toEqual([
    { name: "next", version: "15.0.0" },
    { name: "@next/env", version: "15.0.0" },
    { name: "react", version: "18.2.0" },
  ]);
  const npmLock = JSON.stringify({ packages: { "": { name: "x" }, "node_modules/a": { version: "1.0.0" }, "node_modules/a/node_modules/@s/b": { version: "2.0.0" }, "packages/ui": { version: "0.0.1", link: true } } });
  expect(parseNpmLock("package-lock.json", npmLock)).toEqual([
    { name: "a", version: "1.0.0" },
    { name: "@s/b", version: "2.0.0" },
  ]);
  expect(parseComposerLock(JSON.stringify({ packages: [{ name: "guzzlehttp/guzzle", version: "v7.8.0" }], "packages-dev": [{ name: "phpunit/phpunit", version: "10.0.0" }] }))).toEqual([
    { name: "guzzlehttp/guzzle", version: "7.8.0" },
    { name: "phpunit/phpunit", version: "10.0.0" },
  ]);
});

test("OS advisories and Node.js security releases", () => {
  const f = parseUpdateinfo("ALSA-2026:1234 Important/Sec.  openssl-1:3.0.7-28.el9_5.x86_64\nALSA-2026:99 Low/Sec. tzdata-2026a-1.el9.noarch\nnoise\n");
  expect(f.map((x) => [x.id, x.severity, x.name, x.fixed])).toEqual([
    ["ALSA-2026:1234", "high", "openssl", "1:3.0.7-28.el9_5"],
    ["ALSA-2026:99", "low", "tzdata", "2026a-1.el9"],
  ]);
  const index = [
    { version: "v22.12.0", security: false },
    { version: "v22.11.1", security: true },
    { version: "v22.10.0", security: true },
    { version: "v20.18.1", security: true },
  ];
  const n = nodeSecurity(["22.10.0", "24.1.0"], index);
  expect(n).toHaveLength(1);
  expect(n[0]).toMatchObject({ version: "22.10.0", fixed: "22.11.1" });
  expect(renderDnfAutomatic()).toContain("upgrade_type = security");
  expect(renderDnfAutomatic()).toContain("reboot = never");
});

test("vulnerabilities card renders", () => {
  const html = String(
    <VulnsCard
      csrf="c"
      v={{
        patch: { os: true, php: true, edge: false },
        osAutomatic: true,
        rebootNeeded: true,
        scanning: false,
        last: {
          at: 1,
          packages: 900,
          errors: [],
          findings: [{ where: "app:shop", ecosystem: "npm", name: "next", version: "15.0.0", id: "GHSA-f82v-jwr5-mffw", aliases: ["CVE-2025-29927"], severity: "critical", summary: "Authorization bypass in middleware", fixed: "15.2.3", autofix: false }],
        },
      }}
    />,
  );
  expect(html).toContain("CVE-2025-29927");
  expect(html).toContain("needs a reboot");
  expect(html).toContain("update it in the app");
});
