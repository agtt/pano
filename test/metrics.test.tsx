import { Database } from "bun:sqlite";
import { expect, test } from "bun:test";
import { collect, downsample, history, parseMeminfo, parseNetDev, rollup, store } from "../src/agent/metrics.ts";
import { METRICS_DDL } from "../src/agent/state.ts";
import { AppCharts, Chart, areaPath, linePath, niceMax, segments, type History } from "../src/web/views/charts.tsx";

const mem = () => {
  const db = new Database(":memory:", { strict: true });
  db.exec(METRICS_DDL);
  return db;
};
const count = (db: Database, res: number) => (db.query("SELECT COUNT(*) AS n FROM metrics WHERE res = ?").get(res) as { n: number }).n;

test("parsers read /proc text", () => {
  expect(parseMeminfo("MemTotal: 1000 kB\nMemAvailable: 400 kB\nSwapTotal: 200 kB\nSwapFree: 150 kB\n")).toEqual({ total: 1024000, available: 409600, swapTotal: 204800, swapFree: 153600 });
  const dev = "h1\nh2\n  lo: 999 1 0 0 0 0 0 0 999 1 0 0 0 0 0 0\neth0: 100 1 0 0 0 0 0 0 40 1 0 0 0 0 0 0\nveth1: 5 1 0 0 0 0 0 0 5 1 0 0 0 0 0 0\n";
  expect(parseNetDev(dev)).toEqual({ rx: 100, tx: 40 });
});

test("rates come from two samples and skip counters that went backwards", () => {
  const unit = "/sys/fs/cgroup/system.slice/pano-app-x@a.service";
  const files: Record<string, string> = {
    "/proc/stat": "cpu  100 0 100 800 0 0 0 0 0 0\n",
    "/proc/meminfo": "MemTotal: 1000 kB\nMemAvailable: 500 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n",
    "/proc/net/dev": "h\nh\neth0: 1000 0 0 0 0 0 0 0 500 0 0 0 0 0 0 0\n",
    [`${unit}/memory.current`]: "2048\n",
    [`${unit}/cpu.stat`]: "usage_usec 1000000\nuser_usec 1\n",
  };
  const input = { read: (p: string) => files[p] ?? null, disks: [{ mount: "/", used: 10, total: 100 }], apps: [{ name: "x", units: ["pano-app-x@a.service", "gone.service"] }], load1: 0.5 };
  const a = collect(input, null, 0);
  expect(a.values.cpu).toBeUndefined();
  expect(a.values).toMatchObject({ mem: 512000, memtotal: 1024000, "disk:/": 10, "disktotal:/": 100, "app:x:mem": 2048, load1: 0.5 });
  files["/proc/stat"] = "cpu  150 0 150 900 0 0 0 0 0 0\n"; // +100 busy, +100 idle
  files["/proc/net/dev"] = "h\nh\neth0: 3000 0 0 0 0 0 0 0 1500 0 0 0 0 0 0 0\n";
  files[`${unit}/cpu.stat`] = "usage_usec 4000000\n"; // 3 s of cpu in 60 s
  const b = collect(input, a.next, 60_000);
  expect(b.values.cpu).toBeCloseTo(50);
  expect(b.values.rx).toBeCloseTo(2000 / 60);
  expect(b.values.tx).toBeCloseTo(1000 / 60);
  expect(b.values["app:x:cpu"]).toBeCloseTo(5);
  files["/proc/net/dev"] = "h\nh\neth0: 10 0 0 0 0 0 0 0 10 0 0 0 0 0 0 0\n"; // reboot
  expect(collect(input, b.next, 120_000).values.rx).toBeUndefined();
});

test("rollup averages finished 15-minute buckets once and applies retention", () => {
  const db = mem();
  const t0 = 1_700_000_100; // a multiple of 900
  expect(t0 % 900).toBe(0);
  for (let i = 0; i < 40; i++) store(db, t0 + i * 60, { cpu: i < 15 ? 10 : 30, "app:x:mem": 100 + i });
  const now = t0 + 40 * 60; // buckets 0 and 1 are finished, bucket 2 is still open
  rollup(db, now);
  rollup(db, now);
  const rows = db.query("SELECT key, ts, value FROM metrics WHERE res = 900 ORDER BY key, ts").all() as { key: string; ts: number; value: number }[];
  expect(rows.length).toBe(4);
  expect(rows.filter((r) => r.key === "cpu").map((r) => [r.ts, r.value])).toEqual([[t0, 10], [t0 + 900, 30]]);
  expect(rows.find((r) => r.key === "app:x:mem" && r.ts === t0)!.value).toBe(107);

  // minute rows older than 48 h go, coarse rows older than 30 days go
  rollup(db, now + 48 * 3600);
  expect(count(db, 60)).toBe(0);
  expect(count(db, 900)).toBe(6); // the open bucket was rolled up before its minutes were pruned
  rollup(db, now + 31 * 86_400);
  expect(count(db, 900)).toBe(0);
});

test("size stays bounded", () => {
  const db = mem();
  const t0 = 1_700_000_100;
  for (let m = 0; m < 5 * 1440; m++) {
    const ts = t0 + m * 60;
    store(db, ts, { cpu: 1, mem: 2, load1: 3 });
    if (m % 15 === 0) rollup(db, ts);
  }
  expect(count(db, 60)).toBeLessThanOrEqual(3 * (48 * 60 + 15));
  expect(count(db, 900)).toBeGreaterThan(3 * 4 * 24 * 4);
});

test("downsample averages into steps", () => {
  expect(downsample([[0, 1], [60, 3], [300, 10], [330, 20]], 300)).toEqual([[0, 2], [300, 15]]);
  expect(downsample([], 300)).toEqual([]);
});

test("history reads minutes for short ranges, coarse plus open minutes for long ones", () => {
  const db = mem();
  const t0 = 1_700_000_100;
  for (let i = 0; i < 3 * 60; i++) store(db, t0 + i * 60, { cpu: i < 120 ? 10 : 50, "app:x:cpu": 1 });
  const now = t0 + 3 * 3600;
  rollup(db, now);
  const day = history(db, "24h", undefined, now);
  expect(Object.keys(day.series)).toEqual(["cpu"]); // app keys only with app
  expect(day.series.cpu![0]![0] % 300).toBe(0);
  const week = history(db, "7d", undefined, now - 600);
  expect(week.step).toBe(1800);
  expect(week.series.cpu!.length).toBeGreaterThan(0);
  expect(Object.keys(history(db, "1h", "x", now).series)).toEqual(["app:x:cpu"]);
});

test("svg paths: gaps break the line, area closes to the baseline", () => {
  const x = (ts: number) => ts;
  const y = (v: number) => 100 - v;
  const segs = segments([[0, 10], [60, 20], [600, 30], [660, 40]], 150);
  expect(segs.length).toBe(2);
  expect(linePath(segs, x, y)).toBe("M0 90L60 80M600 70L660 60");
  expect(areaPath(segs, x, y, 100)).toBe("M0 90L60 80L60 100L0 100ZM600 70L660 60L660 100L600 100Z");
  expect(linePath([], x, y)).toBe("");
  expect(niceMax(0)).toBe(1);
  expect(niceMax(3.2)).toBe(5);
  expect(niceMax(130)).toBe(200);
  expect(niceMax(1)).toBe(1);
});

test("chart renders accessible svg with CSS-variable colors and a tooltip", () => {
  const h: History = { range: "1h", from: 1000, to: 4600, step: 60, series: {} };
  const pts: [number, number][] = Array.from({ length: 60 }, (_, i) => [1000 + i * 60, i]);
  const html = String(<Chart id="c1" title="CPU" h={h} series={[{ label: "CPU", points: pts }]} max={100} fmt={(v) => `${v}%`} />);
  expect(html).toContain('role="img"');
  expect(html).toContain('<title id="c1-t">CPU</title>');
  expect(html).toContain("59%, ");
  expect(html).toContain('class="area s1"');
  expect(html).not.toContain("style=");
  expect(html).not.toContain("<script");
  const empty = String(<Chart id="c2" title="CPU" h={h} series={[{ label: "CPU", points: [] }]} fmt={String} />);
  expect(empty).not.toContain("<svg");
  const app = String(<AppCharts h={{ ...h, series: { "app:web:mem": pts, "app:web:cpu": pts } }} app="web" limitMb={512} />);
  expect(app).toContain("/apps/web?range=7d");
});
