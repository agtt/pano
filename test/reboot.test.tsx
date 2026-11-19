import { expect, test } from "bun:test";
import { AUTO_MIN_UPTIME_MS, fstabErrors, grubbyField, kernelOf, nextAutoNight, tailscaleTakesWebPorts, unitNames } from "../src/agent/reboot.ts";
import { FRESH_ONLY, needsOtp } from "../src/agent/rpc.ts";
import { VulnsCard } from "../src/web/views/vulns.tsx";

test("rebooting needs a code (or the trusted window), N5", () => {
  expect(needsOtp("vulns.reboot", {})).toBe(true);
  expect(FRESH_ONLY.has("vulns.reboot")).toBe(false);
});

test("grubby info and kernel paths", () => {
  const info = `index=0
kernel="/boot/vmlinuz-5.14.0-741.22.1.el9_9.x86_64"
args="ro crashkernel=1G-2G:192M panic=10"
id="1eff64ec-5.14.0-741.22.1.el9_9.x86_64"`;
  expect(grubbyField(info, "id")).toBe("1eff64ec-5.14.0-741.22.1.el9_9.x86_64");
  expect(grubbyField(info, "args")).toContain("panic=10");
  expect(grubbyField(info, "title")).toBe("");
  expect(kernelOf("/boot/vmlinuz-5.14.0-741.22.1.el9_9.x86_64\n")).toBe("5.14.0-741.22.1.el9_9.x86_64");
});

test("fstab: warnings pass, errors stop the reboot", () => {
  expect(fstabErrors("swap\n   [W] non-bind mount source /swap is a file\n\n0 parse errors, 0 errors, 1 warning")).toBe(0);
  expect(fstabErrors("/data\n   [E] unreachable source\n\n0 parse errors, 1 error, 0 warnings")).toBe(1);
  expect(fstabErrors("2 parse errors, 0 errors, 0 warnings")).toBe(2);
});

test("tailscale serve on the edge's ports", () => {
  expect(tailscaleTakesWebPorts(`{"TCP":{"443":{"HTTPS":true}},"Web":{}}`)).toBe(true);
  expect(tailscaleTakesWebPorts(`{"TCP":{"8443":{"HTTPS":true}}}`)).toBe(false);
  expect(tailscaleTakesWebPorts(`{}`)).toBe(false);
  expect(tailscaleTakesWebPorts("not json")).toBe(false);
});

test("automatic reboot: the chosen weekday, 4 weeks after the boot at the earliest", () => {
  const at = (d: number, h = 0) => new Date(2026, 10, d, h).getTime(); // November 2026; the 22nd is a Sunday
  const ymd = (x: Date) => `${x.getMonth() + 1}/${x.getDate()} ${x.getHours()}h`;
  // Booted 18 Nov 00:24: 4 weeks are up on 16 Dec, the first Sunday after is 20 Dec.
  expect(ymd(nextAutoNight(at(18, 0) + 24 * 60_000, 0, at(18, 1)))).toBe("12/20 4h");
  // Up for 5 weeks: this Sunday's window, also while it runs.
  expect(ymd(nextAutoNight(at(1) - 7 * 86_400_000, 0, at(22, 4) + 10 * 60_000))).toBe("11/22 4h");
  // After the window: the next Sunday.
  expect(ymd(nextAutoNight(at(1) - 7 * 86_400_000, 0, at(22, 6)))).toBe("11/29 4h");
  // 4 weeks are up at 04:30 on a Sunday: too late for that night's run (04:00).
  expect(ymd(nextAutoNight(at(22, 4) + 30 * 60_000 - AUTO_MIN_UPTIME_MS, 0, at(22, 4) + 10 * 60_000))).toBe("11/29 4h");
});

test("unit names from systemctl list-units", () => {
  expect(unitNames("crond.service loaded active running Command Scheduler\npano-edge.service loaded active running pano edge\n")).toEqual(["crond.service", "pano-edge.service"]);
});

test("card: reboot now, automatic window, reboot under way", () => {
  const base = { patch: { os: true, php: true, edge: true }, osAutomatic: true, scanning: false, last: null };
  const needed = String(<VulnsCard csrf="c" v={{ ...base, rebootNeeded: true, reboot: { auto: true, day: 3, pending: false, badKernel: "" } }} />);
  expect(needed).toContain("/security/vulns/reboot");
  expect(needed).toContain("night of Wednesday");
  expect(needed).toContain("at most once a month");
  const pending = String(<VulnsCard csrf="c" v={{ ...base, rebootNeeded: true, reboot: { auto: false, day: 0, pending: true, badKernel: "6.1" } }} />);
  expect(pending).toContain("under way");
  expect(pending).not.toContain("/security/vulns/reboot");
  expect(pending).toContain("Kernel 6.1 did not boot");
});
