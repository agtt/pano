// Throwaway sandboxes for heavy, untrusted work (Android builds today): a
// transient systemd unit whose user exists only while it runs (DynamicUser),
// with an empty private directory as its home, read-only everything else and
// nothing of other users. Input comes in on stdin, results are picked up from
// its directory after it stopped, then the directory goes too: nothing of it
// is left on the server except, when asked for, a download cache (Gradle,
// npm, bun) that the next sandbox of the same project starts from.

import { createHash } from "node:crypto";
import { constants, lstat, open } from "node:fs/promises";
import { fsPath, paths } from "../shared/config.ts";
import { LOW } from "./apps.ts";
import { remove, run, type RunOptions } from "./sys.ts";

export type SandboxOptions = {
  memoryMb: number;
  timeoutMin: number;
  /** false: no network at all (signing) */
  network: boolean;
  env?: Record<string, string>;
  /** extra unit properties, e.g. LoadCredential= for a key it may read */
  props?: string[];
  /** a cache that outlives the sandbox (cacheName): /var/cache/<cache>, owned by a user of that name that still exists only while a sandbox runs */
  cache?: string;
};

const UNIT = /^pano-[a-z0-9-]{1,80}$/;
const CACHE = /^pano-c-[a-f0-9]{12}$/;

/** Where systemd keeps the directory of a DynamicUser unit; root reads results there once the unit stopped. */
export const sandboxDir = (unit: string) => `/var/lib/private/${unit}`;

/** A cache per owner (an Android project): a valid user name too (32 chars at most), so the dynamic uid stays the same between runs and nothing is chowned again. */
export const cacheName = (owner: string) => `pano-c-${createHash("sha256").update(owner).digest("hex").slice(0, 12)}`;
/** The cache as the sandbox sees it. */
export const cachePath = (cache: string) => `/var/cache/${cache}`;

/** What every sandbox gets: nothing of pano or other users, no privileges, no kernel knobs, a narrow syscall set. */
export function hardening(network: boolean): string[] {
  return [
    "NoNewPrivileges=yes",
    "ProtectSystem=strict",
    "ProtectHome=yes",
    "PrivateTmp=yes",
    "PrivateDevices=yes",
    "ProtectKernelTunables=yes",
    "ProtectKernelModules=yes",
    "ProtectKernelLogs=yes",
    "ProtectControlGroups=yes",
    "ProtectClock=yes",
    "ProtectHostname=yes",
    "ProtectProc=invisible",
    "RestrictSUIDSGID=yes",
    "RestrictRealtime=yes",
    "RestrictNamespaces=yes",
    "LockPersonality=yes",
    "CapabilityBoundingSet=",
    "UMask=0077",
    // pano's state, secrets, socket, apps and sites (DynamicUser already hides other sandboxes' directories).
    `InaccessiblePaths=-${paths.etc} -${paths.data} -${paths.run} -/srv/pano`,
    "SystemCallArchitectures=native",
    "SystemCallFilter=@system-service",
    "SystemCallErrorNumber=ENOSYS",
    ...(network
      ? ["RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX", "IPAddressDeny=169.254.169.254/32"]
      : ["PrivateNetwork=yes", "RestrictAddressFamilies=AF_UNIX", "IPAddressDeny=any"]),
  ];
}

export function sandboxArgv(unit: string, o: SandboxOptions, script: string): string[] {
  if (!UNIT.test(unit)) throw new Error(`bad sandbox name ${unit}`);
  if (o.cache && !CACHE.test(o.cache)) throw new Error(`bad cache name ${o.cache}`);
  const home = `/var/lib/${unit}`;
  const props = [
    "DynamicUser=yes",
    ...(o.cache ? [`User=${o.cache}`, `CacheDirectory=${o.cache}`] : []),
    `StateDirectory=${unit}`,
    `WorkingDirectory=${home}`,
    `MemoryMax=${o.memoryMb}M`,
    "MemorySwapMax=0",
    `RuntimeMaxSec=${o.timeoutMin * 60}`,
    "TasksMax=4096",
    ...LOW.trim().split("\n"),
    ...hardening(o.network),
    ...(o.props ?? []),
  ];
  const env = { HOME: home, CI: "1", XDG_CACHE_HOME: `${home}/.cache`, ...o.env };
  return [
    "systemd-run", "--quiet", "--wait", "--pipe", "--collect", "--service-type=exec", `--unit=${unit}`,
    ...props.flatMap((p) => ["-p", p]),
    ...Object.entries(env).map(([k, val]) => `--setenv=${k}=${val}`),
    "--", "/bin/bash", "-c", script,
  ];
}

/** Runs a script in a new sandbox; stdin is `inputFile` (opened here, so the sandbox needs no access to it). */
export function runSandbox(unit: string, o: SandboxOptions, script: string, ro: Pick<RunOptions, "inputFile" | "onLine" | "check">) {
  return run(sandboxArgv(unit, o, script), { ...ro, timeoutMs: (o.timeoutMin + 5) * 60_000 });
}

/** Stops the unit if it still runs and removes its directory: after this nothing of the sandbox exists. */
export async function removeSandbox(unit: string) {
  if (!UNIT.test(unit)) return;
  await run(["systemctl", "stop", `${unit}.service`], { check: false, quiet: true });
  await remove(sandboxDir(unit));
  await remove(`/var/lib/${unit}`);
}

/** Drops a cache (the next sandbox downloads everything again). */
export async function removeCache(cache: string) {
  if (!CACHE.test(cache)) return;
  await remove(`/var/cache/private/${cache}`);
  await remove(cachePath(cache));
}

/**
 * Reads a file a stopped sandbox left behind: a regular file only, opened without following
 * links, so nothing the sandbox wrote can point this root process at another file.
 */
export async function readResult(path: string, maxBytes: number): Promise<Uint8Array | null> {
  const real = fsPath(path);
  const st = await lstat(real).catch(() => null);
  if (!st?.isFile() || st.size > maxBytes) return null;
  const fh = await open(real, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    return new Uint8Array(await fh.readFile());
  } finally {
    await fh.close();
  }
}
