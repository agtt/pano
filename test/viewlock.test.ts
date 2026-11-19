import { expect, test } from "bun:test";
import {
  MS_BIND,
  MS_NOATIME,
  MS_NODEV,
  MS_NOEXEC,
  MS_NOSUID,
  MS_NOSYMFOLLOW,
  MS_RDONLY,
  MS_RELATIME,
  MS_REMOUNT,
  kernelHasNoSymFollow,
  lockView,
  mountOptions,
  remountFlags,
  viewLocked,
  type LockDeps,
} from "../src/agent/viewlock.ts";

const VIEW = "/srv/pano/edgeview";
const line = (opts: string) => `812 29 253:0 /srv/pano/sites ${VIEW} ${opts} shared:1 - xfs /dev/mapper/root rw,attr2`;
const INFO = "29 1 253:0 / / rw,relatime shared:1 - xfs /dev/mapper/root rw\n";

test("flags of the visible mount at a path, from mountinfo", () => {
  expect(mountOptions(INFO, VIEW)).toBeNull();
  expect(mountOptions(INFO + line("ro,relatime"), VIEW)).toEqual(["ro", "relatime"]);
  // the last mount on a point is the one in use
  expect(mountOptions(INFO + line("ro,relatime") + "\n" + line("ro,nosymfollow,relatime"), VIEW)).toEqual(["ro", "nosymfollow", "relatime"]);
  expect(viewLocked(["ro", "nosymfollow"])).toBe(true);
  expect(viewLocked(["rw", "nosymfollow"])).toBe(false);
  expect(viewLocked(["ro", "relatime"])).toBe(false);
  expect(viewLocked(null)).toBe(false);
});

test("the remount: read-only, nosymfollow, nothing executable, the same atime mode", () => {
  const base = MS_REMOUNT | MS_BIND | MS_RDONLY | MS_NOSYMFOLLOW | MS_NOSUID | MS_NODEV | MS_NOEXEC;
  expect(MS_NOSYMFOLLOW).toBe(256);
  expect(remountFlags(["ro", "relatime"])).toBe(base | MS_RELATIME);
  expect(remountFlags(["ro", "noatime"])).toBe(base | MS_NOATIME);
  expect(remountFlags(["ro"])).toBe(base);
});

test("kernel versions with nosymfollow", () => {
  for (const k of ["5.10.0-35-amd64", "5.14.0-503.el9.x86_64", "5.15.0-140-generic", "6.1.0-37-amd64", "7.2.12-orbstack"]) expect(kernelHasNoSymFollow(k)).toBe(true);
  for (const k of ["5.4.0-216-generic", "4.18.0-553.el8.x86_64", "garbage"]) expect(kernelHasNoSymFollow(k)).toBe(false);
});

/** A fake kernel: mountinfo follows what remount() did, unless it lies (returns 0 but changes nothing). */
function fake(opts: string | null, o: { lies?: boolean; errno?: number; probe?: boolean; kernel?: string } = {}) {
  let cur = opts;
  const calls: number[] = [];
  const deps: LockDeps = {
    mountinfo: async () => INFO + (cur === null ? "" : line(cur)),
    remount: (target, flags) => {
      expect(target).toBe(VIEW);
      calls.push(flags);
      if (o.errno) return o.errno;
      if (!o.lies) cur = "ro,nosuid,nodev,noexec,nosymfollow,relatime";
      return 0;
    },
    probe: async () => o.probe ?? true,
    kernel: o.kernel ?? "5.14.0-503.el9.x86_64",
  };
  return { deps, calls };
}

test("util-linux 2.38+ already set it: no mount(2) call", async () => {
  const f = fake("ro,nosymfollow,relatime");
  expect(await lockView(VIEW, f.deps)).toMatchObject({ ok: true, via: "already" });
  expect(f.calls).toEqual([]);
});

test("util-linux 2.37 dropped it: mount(2) remount, then checked", async () => {
  const f = fake("ro,relatime");
  expect(await lockView(VIEW, f.deps)).toMatchObject({ ok: true, via: "mount(2)" });
  expect(f.calls).toEqual([remountFlags(["ro", "relatime"])]);
});

test("the result of the call is never trusted: mountinfo and a real link decide", async () => {
  // returns success, changes nothing
  expect(await lockView(VIEW, fake("ro,relatime", { lies: true }).deps)).toMatchObject({ ok: false, via: "mount(2)" });
  // an error is reported, the probe still runs on what the kernel shows
  const failed = await lockView(VIEW, fake("ro,relatime", { errno: 1 }).deps);
  expect(failed.ok).toBe(false);
  expect(failed.detail).toContain("errno 1");
  // flags shown but a link is still followed
  expect(await lockView(VIEW, fake("ro,relatime", { probe: false }).deps)).toMatchObject({ ok: false });
  expect(await lockView(VIEW, fake("ro,nosymfollow", { probe: false }).deps)).toMatchObject({ ok: false, via: "already" });
});

test("nothing mounted or a kernel without nosymfollow: no call, fail closed", async () => {
  const none = fake(null);
  expect(await lockView(VIEW, none.deps)).toMatchObject({ ok: false, via: "none" });
  const old = fake("ro,relatime", { kernel: "5.4.0-216-generic" });
  expect(await lockView(VIEW, old.deps)).toMatchObject({ ok: false, via: "none" });
  expect([...none.calls, ...old.calls]).toEqual([]);
});
