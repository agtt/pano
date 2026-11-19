import { expect, test } from "bun:test";
import { isFirstInstall, tailscaleName, webPortsFree, withWebHost } from "../src/firstrun.ts";

test("edge starts on its own only when nothing holds :80/:443", () => {
  expect(webPortsFree("")).toBe(true);
  expect(webPortsFree("LISTEN 0 511 *:80 *:*\n")).toBe(false);
});

test("tailscale: the MagicDNS name when up and serve is unused", () => {
  const up = JSON.stringify({ BackendState: "Running", Self: { DNSName: "web-1.tail1234.ts.net." } });
  expect(tailscaleName(up, "No serve config")).toBe("web-1.tail1234.ts.net");
  expect(tailscaleName(up, "")).toBe("web-1.tail1234.ts.net");
  // Someone already serves something there: left alone.
  expect(tailscaleName(up, "https://web-1.tail1234.ts.net (tailnet only)\n|-- / proxy http://127.0.0.1:3000")).toBe("");
  expect(tailscaleName(JSON.stringify({ BackendState: "NeedsLogin" }), "")).toBe("");
  expect(tailscaleName("not json", "")).toBe("");
  expect(tailscaleName(JSON.stringify({ BackendState: "Running", Self: { DNSName: "evil.example." } }), "")).toBe("");
});

test("pano.env gets one PANO_WEB_HOSTS line", () => {
  const out = withWebHost("PANO_WEB_HOST=127.0.0.1\nPANO_WEB_HOSTS=old.ts.net\n\n", "new.ts.net");
  expect(out.match(/^PANO_WEB_HOSTS=/gm)).toHaveLength(1);
  expect(out).toContain("PANO_WEB_HOST=127.0.0.1\n");
  expect(out.endsWith("PANO_WEB_HOSTS=new.ts.net\n")).toBe(true);
});

test("first install only when neither the web nor the agent has an admin (N4)", () => {
  expect(isFirstInstall(0, 0)).toBe(true);
  // the web database emptied (it belongs to the web user): the agent's admins still count
  expect(isFirstInstall(0, 1)).toBe(false);
  expect(isFirstInstall(2, 0)).toBe(false);
});
