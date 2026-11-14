import { expect, test } from "bun:test";
import { parseJlist, parsePm2Ref, pm2LogPath, pm2Ref, portOf } from "../src/agent/pm2.ts";

test("pm2 log files are read only from the user's own .pm2/logs", () => {
  expect(pm2LogPath("/home/shop", "/home/shop/.pm2/logs/pos-out.log")).toBe(true);
  for (const bad of ["/etc/shadow", "/home/shop/.pm2/logs/", "/home/shop/.pm2/logs/../../.ssh/id_rsa", "/home/shop/.pm2/other/x.log", "/home/shop2/.pm2/logs/x.log", "/dev/zero", ""]) expect(pm2LogPath("/home/shop", bad)).toBe(false);
});

test("pm2 refs round-trip and refuse anything else", () => {
  expect(parsePm2Ref(pm2Ref({ user: "shop", name: "deploy-hook" }))).toEqual({ user: "shop", name: "deploy-hook" });
  for (const bad of ["pm2:root/a b", "pm2:../x", "nginx.service", "pm2:shop/$(id)", ""]) expect(parsePm2Ref(bad)).toBeNull();
});

test("ports from start args or env", () => {
  expect(portOf(["start", "-p", "3000"], undefined)).toBe(3000);
  expect(portOf("start --port=3001", undefined)).toBe(3001);
  expect(portOf(["start", "--port", "3004"], undefined)).toBe(3004);
  expect(portOf(undefined, "9000")).toBe(9000);
  expect(portOf([], undefined)).toBe(0);
});

test("jlist: instances grouped, modules skipped, env never kept", () => {
  const inst = (pid: number, name: string, status: string, extra: Record<string, unknown> = {}) => ({
    pid,
    name,
    monit: { memory: 100 },
    pm2_env: { status, pm_uptime: 1000 + pid, restart_time: 1, exec_mode: "cluster_mode", args: ["start", "-p", "3000"], env: { STRIPE_SECRET_KEY: "sk_live_x" }, ...extra },
  });
  const list = parseJlist(JSON.stringify([inst(1, "pm2-logrotate", "online", { pmx_module: true }), inst(2, "pos", "online"), inst(3, "pos", "stopped"), inst(4, "pos", "online")]));
  expect(list).toHaveLength(1);
  const pos = list[0]!;
  expect([pos.online, pos.total, pos.memory, pos.restarts, pos.port, pos.since]).toEqual([2, 3, 300, 3, 3000, 1002]);
  expect(pos.pids).toEqual([2, 4]);
  expect(JSON.stringify(list)).not.toContain("sk_live");
});
