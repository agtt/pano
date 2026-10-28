import { expect, test } from "bun:test";
import { validateJob } from "../src/agent/backup.ts";
import { KIT_PREFIX, parseKit } from "../src/agent/recovery.ts";
import { renderSysctl } from "../src/agent/tune.ts";
import { TuneCard } from "../src/web/views/tune.tsx";

const kit = {
  key: Buffer.alloc(32, 7).toString("base64"),
  host: "web1",
  dests: [{ endpoint: "https://x.r2.cloudflarestorage.com", bucket: "b", prefix: "pano", accessKeyId: "AK", secret: "S" }],
};
const encode = (k: unknown) => KIT_PREFIX + Buffer.from(JSON.stringify(k)).toString("base64url");

test("recovery kit round-trips and rejects damaged or foreign text", () => {
  expect(parseKit(`  ${encode(kit)}\n`)).toEqual(kit);
  expect(() => parseKit("hello")).toThrow("not a recovery kit");
  expect(() => parseKit(encode({ ...kit, key: "c2hvcnQ=" }))).toThrow("damaged");
  expect(() => parseKit(encode({ ...kit, dests: [] }))).toThrow("damaged");
  expect(() => parseKit(encode({ ...kit, dests: [{ ...kit.dests[0], secret: "" }] }))).toThrow("damaged");
});

test("the panel backup job has a fixed name and target", () => {
  const j = validateJob({ kind: "panel", target: "/etc", name: "x", schedule: "daily 04:30", keep: 30 });
  expect(j).toEqual({ name: "panel", kind: "panel", target: "panel", schedule: "daily 04:30", keep: 30 });
});

test("kernel settings: BBR only when the kernel has it", () => {
  expect(renderSysctl(true)).toContain("tcp_congestion_control = bbr");
  expect(renderSysctl(false)).not.toContain("bbr");
  expect(renderSysctl(false)).toContain("net.core.somaxconn = 4096");
});

test("tuning card offers the opposite of the current state", () => {
  const html = String(<TuneCard csrf="t" v={{ on: true, values: [{ key: "net.core.somaxconn", now: "4096", pano: "4096" }] }} />);
  expect(html).toContain('name="on" value="0"');
  expect(html).toContain("Turn off");
  expect(html).toContain("net.core.somaxconn");
});
