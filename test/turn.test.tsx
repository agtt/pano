import { expect, test } from "bun:test";
import { createHmac } from "node:crypto";
import { credentials, renderConf, renderDropin, urlsFor } from "../src/agent/turn.ts";
import { renderSysctl, sizes } from "../src/agent/tune.ts";
import { TurnCard } from "../src/web/views/turn.tsx";

test("TURN config refuses private peers and needs the shared secret", () => {
  const c = renderConf({ ip: "203.0.113.5", realm: "example.com", secret: "s3cret" });
  expect(c.startsWith("# Written by pano")).toBe(true);
  for (const line of ["use-auth-secret", "static-auth-secret=s3cret", "no-cli", "no-multicast-peers", "denied-peer-ip=127.0.0.0-127.255.255.255", "denied-peer-ip=100.64.0.0-100.127.255.255", "external-ip=203.0.113.5"]) {
    expect(c).toContain(line);
  }
  expect(renderDropin()).toContain("ProtectSystem=strict");
  expect(urlsFor("turn.example.com")[0]).toBe("turn:turn.example.com:3478?transport=udp");
});

test("short-lived TURN credentials", () => {
  const { username, credential } = credentials("s3cret", "alice", 3600, 1_700_000_000_000);
  expect(username).toBe("1700003600:alice");
  expect(credential).toBe(createHmac("sha1", "s3cret").update(username).digest("base64"));
});

test("memory for data services grows with the server", () => {
  const GB = 1024 ** 3;
  expect(sizes(1 * GB)).toMatchObject({ innodbPoolMb: 128, pgSharedMb: 128, valkeyMaxMb: 256, mariadbConnections: 100 });
  const big = sizes(16 * GB);
  expect(big.innodbPoolMb).toBe(2432);
  expect(big.pgSharedMb).toBe(1600);
  expect(big.valkeyMaxMb).toBe(768);
  expect(sizes(256 * GB).innodbPoolMb).toBe(4096);
  expect(renderSysctl(true)).toContain("net.ipv4.tcp_congestion_control = bbr");
  expect(renderSysctl(false)).not.toContain("bbr");
});

test("TURN card", () => {
  const base = { installed: true, managed: true, active: "active", memory: 11e6, domain: "", urls: urlsFor("203.0.113.5"), allocations: 2, port: 3478, relay: { min: 49160, max: 49200 } };
  expect(String(<TurnCard v={base} csrf="c" appNames={["shop"]} />)).toContain("turn:203.0.113.5:3478?transport=tcp");
  expect(String(<TurnCard v={{ ...base, managed: false }} csrf="c" appNames={[]} />)).toContain("Take over");
});
