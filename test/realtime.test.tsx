import { expect, test } from "bun:test";
import { createHmac } from "node:crypto";
import { envFor, newer, parseOrigins, parseWebhookUrl, renderConfig, renderUnit, signQuery, type RealtimeApp } from "../src/agent/realtime.ts";
import { RealtimeCard } from "../src/web/views/realtime.tsx";

const app: RealtimeApp = { id: "123456", name: "shop", key: "k1", secret: "s1", origins: ["https://pos.example.com"], webhook_url: "", max_connections: 0, created_at: 1 };

test("config is valid TOML with our apps, localhost only, no client events", () => {
  const cfg = Bun.TOML.parse(renderConfig([app, { ...app, id: "2", name: "b", key: "k2", origins: [] }])) as any;
  expect(cfg.host).toBe("127.0.0.1");
  expect(cfg.metrics.enabled).toBe(false);
  expect(cfg.app_manager.array.apps).toHaveLength(2);
  expect(cfg.app_manager.array.apps[0]).toMatchObject({ id: "123456", key: "k1", secret: "s1", enabled: true });
  expect(cfg.app_manager.array.apps[0].policy.features.enable_client_messages).toBe(false);
  expect(cfg.app_manager.array.apps[0].policy.channels.allowed_origins).toEqual(["https://pos.example.com"]);
  expect(cfg.app_manager.array.apps[1].policy.channels).toBeUndefined();
});

test("unit: dynamic user, config as a credential, localhost forced by env", () => {
  const u = renderUnit("5.2.0");
  expect(u).toContain("DynamicUser=yes");
  expect(u).toContain("install -m 0400 -o pano-realtime /etc/pano/realtime.toml /run/pano-realtime/config.toml");
  expect(u).toContain("--config /run/pano-realtime/config.toml");
  expect(u).toContain("HOST=127.0.0.1");
});

test("Pusher API signature", () => {
  const q = signQuery("GET", "/apps/1/channels", { auth_version: "1.0", auth_key: "k", auth_timestamp: "100" }, "secret");
  const expected = createHmac("sha256", "secret").update("GET\n/apps/1/channels\nauth_key=k&auth_timestamp=100&auth_version=1.0").digest("hex");
  expect(q).toBe(`auth_key=k&auth_timestamp=100&auth_version=1.0&auth_signature=${expected}`);
});

test("versions, origins, app env", () => {
  expect(newer("5.10.0", "5.9.3")).toBe(true);
  expect(newer("5.2.0", "5.2.0")).toBe(false);
  expect(parseOrigins("https://a.com, http://localhost:3000\nhttps://*.b.com/")).toEqual(["https://a.com", "http://localhost:3000", "https://*.b.com"]);
  expect(() => parseOrigins("javascript:alert(1)")).toThrow();
  const env = envFor(app, "ws.example.com");
  expect(env).toMatchObject({ PUSHER_HOST: "127.0.0.1", PUSHER_PORT: "6001", NEXT_PUBLIC_PUSHER_HOST: "ws.example.com", NEXT_PUBLIC_PUSHER_PORT: "443" });
});

test("realtime card renders", () => {
  const off = String(<RealtimeCard csrf="c" appNames={[]} r={{ installed: false } as any} />);
  expect(off).toContain("/services/realtime/install");
  const on = String(
    <RealtimeCard
      csrf="c"
      appNames={["shop"]}
      r={{ installed: true, version: "5.2.0", latest: "6.0.0", autoUpdate: true, updatedAt: null, active: "active", memory: 9e6, domain: "ws.example.com", port: 6001, apps: [{ id: "1", name: "shop", key: "k1", origins: [], created_at: 1 }] }}
    />,
  );
  expect(on).toContain("Update to 6.0.0");
  expect(on).toContain("Add to app environment");
  expect(on).not.toContain("s1");
});

test("webhooks and a connection limit go into the app's policy", async () => {
  const cfg = Bun.TOML.parse(renderConfig([{ ...app, webhook_url: "http://127.0.0.1:3000/api/webhooks/pusher", max_connections: 500 }, { ...app, id: "2", name: "b", key: "k2" }])) as any;
  const [a, b] = cfg.app_manager.array.apps;
  expect(a.policy.limits).toEqual({ max_connections: 500 });
  expect(a.policy.webhooks[0].url).toBe("http://127.0.0.1:3000/api/webhooks/pusher");
  expect(a.policy.webhooks[0].event_types).toContain("channel_vacated");
  expect(b.policy.limits).toBeUndefined();
  expect(b.policy.webhooks).toBeUndefined();
  expect(await parseWebhookUrl("")).toBe("");
  for (const bad of ["http://example.com/x", "https://127.0.0.1/x", "https://a.com/x?y=1", "ftp://a.com/"]) await expect(parseWebhookUrl(bad)).rejects.toThrow();
  expect(envFor(app, "").PUSHER_KEY).toBe("k1");
});
