import { expect, test } from "bun:test";
import { fstabErrors, grubbyField, kernelOf, tailscaleTakesWebPorts, unitNames } from "../src/agent/reboot.ts";
import { VulnsCard } from "../src/web/views/vulns.tsx";

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

test("unit names from systemctl list-units", () => {
  expect(unitNames("crond.service loaded active running Command Scheduler\npano-edge.service loaded active running pano edge\n")).toEqual(["crond.service", "pano-edge.service"]);
});

test("card: reboot now, automatic window, reboot under way", () => {
  const base = { patch: { os: true, php: true, edge: true }, osAutomatic: true, scanning: false, last: null };
  const needed = String(<VulnsCard csrf="c" v={{ ...base, rebootNeeded: true, reboot: { auto: true, day: 3, pending: false, badKernel: "" } }} />);
  expect(needed).toContain("/security/vulns/reboot");
  expect(needed).toContain("Wednesday night");
  const pending = String(<VulnsCard csrf="c" v={{ ...base, rebootNeeded: true, reboot: { auto: false, day: 0, pending: true, badKernel: "6.1" } }} />);
  expect(pending).toContain("under way");
  expect(pending).not.toContain("/security/vulns/reboot");
  expect(pending).toContain("Kernel 6.1 did not boot");
});
