import { expect, test } from "bun:test";
import { authorizedKeys, parseKey, renderRunnerNet, runnerArgv } from "../src/agent/runner.ts";
import { cacheName, sandboxArgv } from "../src/agent/throwaway.ts";
import { EXIT, OUT, frame, readFrames } from "../src/shared/runner.ts";
import { RunnerPage } from "../src/web/views/runner.tsx";

const ED = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ8n0V1x2k5Q9eS0h3yQp8m3rB1oWm1v6c7Z1q2w3e4r me@laptop";

test("frames survive arbitrary chunking", async () => {
  const bytes = new Uint8Array([...frame(OUT, "hello\n"), ...frame(OUT, new Uint8Array([0, 1, 2])), ...frame(EXIT, "3")]);
  const stream = new ReadableStream<Uint8Array>({
    start(c) {
      for (let i = 0; i < bytes.length; i += 4) c.enqueue(bytes.slice(i, i + 4));
      c.close();
    },
  });
  const got = [];
  for await (const f of readFrames(stream)) got.push([f.kind, [...f.data]]);
  expect(got).toEqual([
    [OUT, [...new TextEncoder().encode("hello\n")]],
    [OUT, [0, 1, 2]],
    [EXIT, [51]],
  ]);
});

test("runner keys: one public key, held to the forced command, none while off", () => {
  const k = parseKey(`  ${ED}  `);
  expect(k).toMatchObject({ type: "ssh-ed25519", comment: "me@laptop" });
  expect(k.fingerprint).toStartWith("SHA256:");
  expect(() => parseKey("ssh-ed25519 AAAA\nssh-ed25519 BBBB")).toThrow();
  expect(() => parseKey('command="sh" ssh-ed25519 AAAA')).toThrow();
  expect(() => parseKey("-----BEGIN OPENSSH PRIVATE KEY-----")).toThrow();
  const list = [{ ...k, added: 0 }];
  expect(authorizedKeys(list, true)).toBe(`restrict,command="/opt/pano/bin/pano run-shell" ${ED}\n`);
  expect(authorizedKeys(list, false)).toBe("");
});

test("a run sees only its workspace and the cache, capped and low priority", () => {
  const argv = runnerArgv("pano-run-shop-abc123", "shop-1a2b3c", "./gradlew assembleDebug", { memory_mb: 8192, timeout_min: 60, parallel: 1 }, { HOME: "/var/lib/pano-run/home" });
  const props = argv.filter((_, i) => argv[i - 1] === "-p");
  expect(props).toContain("User=pano-run");
  expect(props).toContain("MemoryMax=8192M");
  expect(props).toContain("RuntimeMaxSec=3600");
  expect(props).toContain("TemporaryFileSystem=/var/lib/pano-run:ro");
  expect(props).toContain("BindPaths=/var/lib/pano-run/ws /var/lib/pano-run/home");
  expect(props).toContain("WorkingDirectory=/var/lib/pano-run/ws/shop-1a2b3c");
  expect(props).toContain("InaccessiblePaths=-/run/pano-run");
  expect(props).toContain("ProtectSystem=strict");
  expect(props.some((p) => p.startsWith("InaccessiblePaths=") && p.includes("/etc/pano"))).toBe(true);
  expect(argv.slice(-4)).toEqual(["--", "/bin/bash", "-c", "./gradlew assembleDebug"]);
});

test("runs cannot reach services on this host, only their own ephemeral ports and DNS", () => {
  const r = renderRunnerNet(998, 32768);
  expect(r).toContain("meta skuid != 998 accept");
  expect(r).toContain("th dport 53 accept");
  expect(r).toContain("fib daddr type local meta l4proto { tcp, udp } th dport < 32768 reject");
  expect(r.indexOf("dport 53 accept")).toBeLessThan(r.indexOf("reject"));
});

test("Android builds keep a per-project cache under a stable dynamic user", () => {
  const c = cacheName("shop-app");
  expect(c).toMatch(/^pano-c-[a-f0-9]{12}$/);
  expect(c).toBe(cacheName("shop-app"));
  expect(c).not.toBe(cacheName("other"));
  const argv = sandboxArgv("pano-android-build-1", { memoryMb: 4096, timeoutMin: 30, network: true, cache: c }, "true");
  expect(argv).toContain(`User=${c}`);
  expect(argv).toContain(`CacheDirectory=${c}`);
  expect(argv).toContain("DynamicUser=yes");
  expect(() => sandboxArgv("pano-android-build-1", { memoryMb: 4096, timeoutMin: 30, network: true, cache: "root" }, "true")).toThrow();
});

test("Runner page renders off and on", () => {
  const base = {
    config: { memory_mb: 8192, timeout_min: 60, parallel: 1 },
    keys: [],
    workspaces: [],
    cacheBytes: 0,
    recent: [],
    running: [],
    host: "build.example.com",
    androidToolchain: false,
  };
  expect(String(<RunnerPage v={{ ...base, enabled: false }} csrf="x" />)).toContain("/runner/enable");
  const on = String(
    <RunnerPage
      v={{ ...base, enabled: true, workspaces: [{ name: "shop-1a2b3c", bytes: 1024, modified: 0, running: false }], recent: [{ ws: "shop-1a2b3c", cmd: "bun test", started: 0, seconds: 4, code: 0 }] }}
      csrf="x"
    />,
  );
  expect(on).toContain("pano-remote init pano-run@build.example.com");
  expect(on).toContain("shop-1a2b3c");
});
