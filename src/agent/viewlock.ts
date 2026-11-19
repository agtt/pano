// nosymfollow on the edge's view of the site files (edge.ts EDGE_VIEW) where mount(8) cannot set it.
//
// The kernel has MS_NOSYMFOLLOW since Linux 5.10, but util-linux before 2.38 may drop the option on a bind
// mount (its MNT_BIND_SETTABLE mask lacked it until commit 36a3923; AlmaLinux 9's 2.37.4 did apply it in
// the test VM), and 2.36 (Debian 11) does not know the option at all. Where the systemd mount unit leaves
// a read-only bind that still follows links, `pano edge-view-lock`
// (pano-edgeview-lock.service, root, in the host's mount namespace, ordered before the edge) remounts it
// with mount(2) itself. Whatever a call returns, only the probe decides: the flags in mountinfo and a real
// link opened through the view must fail with ELOOP. When it does not, the edge (which requires this unit)
// stays down until the agent renders it without the view, and PHP sites are held offline (edge.ts).

import { FFIType, dlopen, ptr, read } from "bun:ffi";
import { lstat, readFile, symlink, unlink } from "node:fs/promises";
import { release } from "node:os";
import { fsPath, paths } from "../shared/config.ts";

export const MS_RDONLY = 1;
export const MS_NOSUID = 2;
export const MS_NODEV = 4;
export const MS_NOEXEC = 8;
export const MS_REMOUNT = 32;
export const MS_NOSYMFOLLOW = 256;
export const MS_NOATIME = 1024;
export const MS_NODIRATIME = 2048;
export const MS_BIND = 4096;
export const MS_RELATIME = 1 << 21;

/** Per-mount options of the visible (last) mount at `path` in a mountinfo text; null when nothing is mounted there. */
export function mountOptions(mountinfo: string, path: string): string[] | null {
  // Fields: id parent major:minor root mount-point options ...; the last mount on a point is the visible one.
  const line = mountinfo
    .split("\n")
    .map((l) => l.split(" "))
    .filter((f) => f[4] === path)
    .at(-1);
  return line ? (line[5] ?? "").split(",") : null;
}

/** The view is safe for the edge: read-only and no symlink followed. */
export const viewLocked = (opts: string[] | null) => !!opts && opts.includes("ro") && opts.includes("nosymfollow");

/**
 * Flags for the bind remount: read-only, no symlinks, no devices, setuid or exec (the edge only reads), and
 * the atime mode the mount has (a remount replaces every per-mount flag).
 */
export function remountFlags(opts: string[]): number {
  let f = MS_REMOUNT | MS_BIND | MS_RDONLY | MS_NOSYMFOLLOW | MS_NOSUID | MS_NODEV | MS_NOEXEC;
  if (opts.includes("noatime")) f |= MS_NOATIME;
  else if (opts.includes("relatime")) f |= MS_RELATIME;
  if (opts.includes("nodiratime")) f |= MS_NODIRATIME;
  return f;
}

/** Linux 5.10 or newer (MS_NOSYMFOLLOW); "5.14.0-503.el9.x86_64" and the like. */
export function kernelHasNoSymFollow(rel: string): boolean {
  const [maj = 0, min = 0] = (rel.match(/^(\d+)\.(\d+)/) ?? []).slice(1).map(Number);
  return maj > 5 || (maj === 5 && min >= 10);
}

export type LockDeps = {
  mountinfo: () => Promise<string>;
  /** mount(2) with no source, type or data; returns 0 or an errno. */
  remount: (target: string, flags: number) => number;
  /** A link opened through the view fails with ELOOP. */
  probe: () => Promise<boolean>;
  kernel: string;
};
export type LockResult = { ok: boolean; via: "already" | "mount(2)" | "none"; detail: string };

/** Makes sure the view at `path` is ro + nosymfollow, by mount(2) when mount(8) left the flag off. */
export async function lockView(path: string, d: LockDeps): Promise<LockResult> {
  const before = mountOptions(await d.mountinfo(), path);
  if (!before) return { ok: false, via: "none", detail: `nothing is mounted at ${path}` };
  let via: LockResult["via"] = "already";
  let detail = "";
  if (!viewLocked(before)) {
    if (!kernelHasNoSymFollow(d.kernel)) return { ok: false, via: "none", detail: `Linux ${d.kernel} has no nosymfollow (5.10+ needed)` };
    via = "mount(2)";
    const err = d.remount(path, remountFlags(before));
    if (err) detail = `mount(2) failed with errno ${err}; `;
  }
  // The call's result is never trusted: the flags as the kernel shows them, then a real link.
  if (!viewLocked(mountOptions(await d.mountinfo(), path))) return { ok: false, via, detail: `${detail}${path} is still not ro,nosymfollow` };
  if (!(await d.probe())) return { ok: false, via, detail: `${detail}a link through ${path} was still followed` };
  return { ok: true, via, detail: `${path} is ro,nosymfollow` };
}

/** libc's mount(2) through bun:ffi; errno from __errno_location. */
function ffiRemount(target: string, flags: number): number {
  const lib = dlopen("libc.so.6", {
    mount: { args: [FFIType.ptr, FFIType.ptr, FFIType.ptr, FFIType.u64, FFIType.ptr], returns: FFIType.i32 },
    __errno_location: { args: [], returns: FFIType.ptr },
  });
  try {
    const t = Buffer.from(`${target}\0`);
    const rc = lib.symbols.mount(null, ptr(t), null, BigInt(flags), null);
    return rc === 0 ? 0 : read.i32(lib.symbols.__errno_location()!, 0) || -1;
  } finally {
    lib.close();
  }
}

/** A link in the sites directory to a file that surely exists; opened through the view it must fail with ELOOP. */
async function probeView(view: string): Promise<boolean> {
  const name = `.pano-view-probe-${process.pid}`;
  const link = fsPath(`${paths.sites}/${name}`);
  await unlink(link).catch(() => {});
  await symlink("/proc/version", link);
  try {
    if (!(await lstat(fsPath(`${view}/${name}`)).catch(() => null))?.isSymbolicLink()) return false;
    return await readFile(fsPath(`${view}/${name}`)).then(
      () => false,
      (e: NodeJS.ErrnoException) => e.code === "ELOOP",
    );
  } finally {
    await unlink(link).catch(() => {});
  }
}

/** `pano edge-view-lock` (pano-edgeview-lock.service): exit code 0 only when the probe passed. */
export async function lockEdgeView(view: string): Promise<LockResult> {
  return lockView(view, {
    mountinfo: () => readFile("/proc/self/mountinfo", "utf8"),
    remount: ffiRemount,
    probe: () => probeView(view),
    kernel: release(),
  });
}
