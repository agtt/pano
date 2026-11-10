import { expect, test } from "bun:test";
import { lang, pickLang, t, withLang } from "../src/web/i18n.ts";
import { Layout } from "../src/web/views/layout.tsx";
import { createWebApp } from "../src/web/server.tsx";

test("language: cookie, then browser preference in q order, then English", () => {
  expect(pickLang(undefined, undefined)).toBe("en");
  expect(pickLang(undefined, "tr-TR,tr;q=0.9,en;q=0.8")).toBe("tr");
  expect(pickLang(undefined, "de-DE,de;q=0.9,en;q=0.5,tr;q=0.4")).toBe("en");
  expect(pickLang(undefined, "en;q=0.2,tr;q=0.8")).toBe("tr");
  expect(pickLang(undefined, "fr")).toBe("en");
  expect(pickLang("en", "tr")).toBe("en");
  expect(pickLang("xx", "tr")).toBe("tr");
});

test("strings follow the request's language", () => {
  expect(t("Apps")).toBe("Apps");
  expect(withLang("tr", () => t("Apps"))).toBe("Uygulamalar");
  expect(withLang("tr", () => lang())).toBe("tr");
  const html = withLang("tr", () => String(<Layout title="X" path="/projects" user="a" csrf="c" />));
  expect(html).toContain('<html lang="tr">');
  expect(html).toContain("Projeler");
  expect(html).toContain('aria-current="page"');
});

test("/lang only redirects within the panel", async () => {
  const app = createWebApp();
  const go = (next: string) => app.request(`http://127.0.0.1:7800/lang/tr?next=${encodeURIComponent(next)}`, { headers: { host: "127.0.0.1:7800" } });
  const ok = await go("/apps");
  expect(ok.headers.get("location")).toBe("/apps");
  expect(ok.headers.get("set-cookie")).toContain("pano_lang=tr");
  for (const bad of ["//evil.example", "/\\evil.example", "https://evil.example", "javascript:alert(1)"]) expect((await go(bad)).headers.get("location")).toBe("/");
  const login = await app.request("http://127.0.0.1:7800/login", { headers: { host: "127.0.0.1:7800", "accept-language": "tr-TR,tr;q=0.9" } });
  expect(await login.text()).toContain("Giriş");
});
