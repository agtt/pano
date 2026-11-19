// Process and filesystem helpers for the agent. Commands are always argv arrays
// (never a shell string); the only shell ever used is `sh -c` for an app's own
// build/start commands, and that runs as the app's unprivileged user.

import { constants } from "node:fs";
import { lstat, mkdir, open, readFile, realpath, rename, rm, stat, statfs } from "node:fs/promises";
import { dirname } from "node:path";
import { DRY_RUN, fsPath } from "../shared/config.ts";

export type RunResult = { code: number; stdout: string; stderr: string };

export type RunOptions = {
  /** Run as this system user via runuser. */
  user?: string;
  cwd?: string;
  env?: Record<string, string>;
  input?: string;
  /** Real path of a file fed to stdin (opened by the agent, so the command needs no access to it). */
  inputFile?: string;
  timeoutMs?: number;
  /** Streams combined output line by line (deploy logs). */
  onLine?: (line: string) => void;
  /** Throw when the exit code is not 0 (default true). */
  check?: boolean;
  /** Discard output instead of capturing it (for commands that leave a daemon holding stdout). */
  quiet?: boolean;
};

export class CommandError extends Error {
  constructor(public cmd: string[], public result: RunResult) {
    super(`${cmd[0]} exited with ${result.code}: ${(result.stderr || result.stdout).trim().split("\n").slice(-3).join(" | ")}`);
  }
}

const BASE_ENV = { PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", LANG: "C.UTF-8", HOME: "/root" };

export async function run(cmd: string[], o: RunOptions = {}): Promise<RunResult> {
  const argv = o.user ? ["runuser", "-u", o.user, "--", ...cmd] : cmd;
  if (DRY_RUN) {
    const line = `[dry-run] ${o.user ? `(${o.user}) ` : ""}${cmd.join(" ")}`;
    console.log(line);
    o.onLine?.(line);
    return { code: 0, stdout: "", stderr: "" };
  }
  let proc: Bun.Subprocess;
  try {
    proc = Bun.spawn(argv, {
      cwd: o.cwd,
      env: { ...BASE_ENV, ...o.env },
      stdin: o.inputFile ? Bun.file(o.inputFile) : o.input !== undefined ? new TextEncoder().encode(o.input) : "ignore",
      stdout: o.quiet ? "ignore" : "pipe",
      stderr: o.quiet ? "ignore" : "pipe",
    });
  } catch (e) {
    // Missing binary (e.g. no `nft` on this distro) behaves like exit 127.
    const result = { code: 127, stdout: "", stderr: e instanceof Error ? e.message : String(e) };
    if (o.check !== false) throw new CommandError(cmd, result);
    return result;
  }
  const timer = o.timeoutMs ? setTimeout(() => proc.kill("SIGKILL"), o.timeoutMs) : undefined;
  const [stdout, stderr] = o.quiet
    ? ["", ""]
    : await Promise.all([
        collect(proc.stdout as ReadableStream<Uint8Array>, o.onLine),
        collect(proc.stderr as ReadableStream<Uint8Array>, o.onLine),
      ]);
  const code = await proc.exited;
  if (timer) clearTimeout(timer);
  const result = { code, stdout, stderr };
  if (code !== 0 && o.check !== false) throw new CommandError(cmd, result);
  return result;
}

async function collect(stream: ReadableStream<Uint8Array>, onLine?: (l: string) => void): Promise<string> {
  const dec = new TextDecoder();
  let all = "";
  let pending = "";
  for await (const chunk of stream) {
    const text = dec.decode(chunk, { stream: true });
    all += text;
    if (onLine) {
      pending += text;
      const lines = pending.split("\n");
      pending = lines.pop() ?? "";
      for (const l of lines) onLine(l);
    }
    // Keep memory bounded for chatty builds.
    if (all.length > 2_000_000) all = all.slice(-1_000_000);
  }
  if (onLine && pending) onLine(pending);
  return all;
}

export async function exists(abs: string): Promise<boolean> {
  try {
    await stat(fsPath(abs));
    return true;
  } catch {
    return false;
  }
}

export async function readText(abs: string): Promise<string | null> {
  try {
    return await readFile(fsPath(abs), "utf8");
  } catch {
    return null;
  }
}

/**
 * Root-owned directories only: inside a tree a tenant can write, create directories as that user
 * (run(["mkdir", ...], { user })), since the parents on the way can be swapped for links.
 */
export async function ensureDir(abs: string, mode = 0o755, owner?: string) {
  const real = fsPath(abs);
  // mkdir's mode is filtered by the umask (0027 for the agent); fix every directory it created.
  const first = await mkdir(real, { recursive: true, mode });
  if (first) for (let d = dirname(real); d.length >= first.length; d = dirname(d)) await setDir(d, mode);
  await setDir(real, mode, owner);
}

/**
 * chmod/chown through a descriptor opened without following a link: a user who owns the parent
 * could otherwise swap the directory for a symlink to /etc between a check and the change.
 */
async function setDir(real: string, mode: number, owner?: string) {
  let fh;
  try {
    fh = await open(real, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === "ELOOP" || code === "ENOTDIR") throw new Error(`${real} is a symlink or not a directory, refusing`);
    throw e;
  }
  try {
    await fh.chmod(mode);
    if (owner && !DRY_RUN && process.getuid?.() === 0) {
      const ids = await lookupUser(owner);
      if (!ids) throw new Error(`unknown user ${owner}`);
      await fh.chown(ids.uid, ids.gid);
    }
  } finally {
    await fh.close();
  }
}

async function notSymlink(real: string) {
  if ((await lstat(real)).isSymbolicLink()) throw new Error(`${real} is a symlink, refusing`);
}

/**
 * Atomic write: temp file in the same directory, fsync'd by rename semantics. The temp name is
 * random and opened O_EXCL|O_NOFOLLOW, so nothing planted in the directory can redirect the write.
 */
export async function writeAtomic(abs: string, content: string | Uint8Array, mode = 0o644, owner?: string) {
  const real = fsPath(abs);
  await mkdir(dirname(real), { recursive: true });
  await notSymlink(dirname(real));
  const tmp = `${real}.pano-tmp-${randomToken(9)}`;
  const fh = await open(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, mode);
  try {
    await fh.writeFile(content);
    await fh.chmod(mode);
    if (owner && !DRY_RUN && process.getuid?.() === 0) {
      const ids = await lookupUser(owner);
      if (!ids) throw new Error(`unknown user ${owner}`);
      await fh.chown(ids.uid, ids.gid);
    }
  } catch (e) {
    await fh.close();
    await rm(tmp, { force: true });
    throw e;
  }
  await fh.close();
  await rename(tmp, real);
}

/** Root-owned paths only; a tree its user can write goes through removeAs. */
export async function remove(abs: string) {
  await rm(fsPath(abs), { recursive: true, force: true });
}

/**
 * Deletes a tree a system user can write, as that user: whatever they swap in there meanwhile
 * (a directory for a link to /etc), the delete only reaches what that user may remove anyway.
 * Best effort, like remove: what the user cannot delete stays.
 */
export async function removeAs(abs: string, user: string) {
  await run(["rm", "-rf", "--", fsPath(abs)], { user, check: false, timeoutMs: 600_000 });
}

/**
 * A tenant's whole tree: first as its user (removeAs), then root removes the root-owned rest with
 * coreutils rm, which never follows a symlink and descends by descriptor (not a path walk that a swapped
 * directory could redirect), and stays on one filesystem. Never Node's recursive rm on a tenant's tree.
 */
export async function removeTree(abs: string, user: string) {
  await removeAs(abs, user);
  await run(["rm", "-rf", "--one-file-system", "--", fsPath(abs)], { check: false, timeoutMs: 600_000 });
  // Dry runs (tests, dev) run no commands: the sandbox copy goes the plain way.
  if (DRY_RUN) await remove(abs);
}

/**
 * The bytes of a file in a tenant's tree, read by that user ("" = root), so root never opens a path the
 * tenant can redirect. `real` is a real filesystem path (already through fsPath).
 */
export async function readAs(real: string, user: string, maxBytes = 50_000_000): Promise<Uint8Array> {
  if (DRY_RUN) return new Uint8Array(await readFile(real));
  // Bounded: the path may have been swapped for a link to /dev/zero.
  const cmd = ["head", "-c", String(maxBytes + 1), "--", real];
  const argv = user ? ["runuser", "-u", user, "--", ...cmd] : cmd;
  const proc = Bun.spawn(argv, { env: BASE_ENV, stdin: "ignore", stdout: "pipe", stderr: "pipe" });
  const [out, err, code] = await Promise.all([new Response(proc.stdout).arrayBuffer(), new Response(proc.stderr).text(), proc.exited]);
  if (code !== 0) throw new Error(`cannot read ${real}: ${err.trim().slice(0, 200)}`);
  if (out.byteLength > maxBytes) throw new Error(`${real} is larger than ${maxBytes} bytes`);
  return new Uint8Array(out);
}

/** Not cached: users are deleted and recreated (app/site removal) and may come back with another uid. */
export async function lookupUser(user: string): Promise<{ uid: number; gid: number } | null> {
  const passwd = await readText("/etc/passwd");
  const line = passwd?.split("\n").find((l) => l.startsWith(user + ":"));
  if (!line) return null;
  const [, , uid, gid] = line.split(":");
  return { uid: Number(uid), gid: Number(gid) };
}

/** The user name of a uid (null when /etc/passwd has none). */
export async function userName(uid: number): Promise<string | null> {
  const passwd = await readText("/etc/passwd");
  return passwd?.split("\n").map((l) => l.split(":")).find((f) => f.length > 2 && f[2] === String(uid))?.[0] ?? null;
}

/**
 * A file only root can have put in place, or null. The file, every directory on the way to it and
 * every symlink on the way are root's, and no directory is writable by anyone but root, both on the
 * path as given and on the path it resolves to; so nobody else can have pointed it at another file.
 * Read through a descriptor (no final symlink followed) that must be a regular, root-owned file.
 */
export async function readRootOwned(abs: string, maxBytes = 1_000_000): Promise<string | null> {
  const asRoot = !DRY_RUN && process.getuid?.() === 0;
  try {
    const real = await realpath(fsPath(abs));
    if (asRoot) for (const p of [fsPath(abs), real]) if (!(await rootOnlyPath(p))) return null;
    const fh = await open(real, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    try {
      const st = await fh.stat();
      if (!st.isFile() || st.size > maxBytes || (asRoot && st.uid !== 0)) return null;
      return await fh.readFile("utf8");
    } finally {
      await fh.close();
    }
  } catch {
    return null;
  }
}

async function rootOnlyPath(p: string): Promise<boolean> {
  const parts = p.split("/").filter(Boolean);
  for (let i = 0; i <= parts.length; i++) {
    const st = await lstat(`/${parts.slice(0, i).join("/")}`);
    if (st.uid !== 0) return false;
    // Group write only for root's group.
    if (st.isDirectory() && (st.mode & 0o002 || (st.mode & 0o020 && st.gid !== 0))) return false;
  }
  return true;
}

export async function chownR(abs: string, owner: string) {
  await run(["chown", "-R", `${owner}:${owner}`, fsPath(abs)]);
}

export function randomToken(bytes = 32): string {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64url");
}

/** Alphanumeric password, safe in any config file or SQL literal. */
export function randomPassword(len = 28): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
  // Rejection sampling keeps every character equally likely.
  const limit = 256 - (256 % alphabet.length);
  let out = "";
  while (out.length < len) {
    for (const b of crypto.getRandomValues(new Uint8Array(len * 2))) {
      if (b >= limit) continue;
      out += alphabet[b % alphabet.length];
      if (out.length === len) break;
    }
  }
  return out;
}

/**
 * Properties of many systemd units in one `systemctl show` (one process instead of one per unit).
 * Keyed by the unit name as asked; a unit systemd does not know comes back with its defaults.
 */
export async function showUnits(units: string[], props: string[], extra: string[] = []): Promise<Map<string, Record<string, string>>> {
  const out = new Map<string, Record<string, string>>();
  if (!units.length) return out;
  const r = await run(["systemctl", "show", ...extra, ...units, `--property=${props.join(",")}`], { check: false });
  return parseShow(r.stdout, units);
}

/** `systemctl show` output for several units: one block per unit, in the order asked, separated by a blank line. */
export function parseShow(stdout: string, units: string[]): Map<string, Record<string, string>> {
  const blocks = stdout.replace(/\n+$/, "").split("\n\n");
  return new Map(units.map((u, i) => [u, Object.fromEntries((blocks[i] ?? "").split("\n").filter(Boolean).map((l) => l.split(/=(.*)/s).slice(0, 2) as [string, string]))]));
}

/** Size, used and available bytes of the file system holding a path (no `df` process). */
export async function diskUsage(abs = "/"): Promise<{ size: number; used: number; avail: number }> {
  const s = await statfs(fsPath(abs));
  const size = s.blocks * s.bsize;
  return { size, used: (s.blocks - s.bfree) * s.bsize, avail: s.bavail * s.bsize };
}

/** Bytes a directory takes on disk (0 when it does not exist). */
export async function dirBytes(abs: string): Promise<number> {
  if (!(await exists(abs))) return 0;
  const r = await run(["du", "-sb", fsPath(abs)], { check: false, timeoutMs: 60_000 });
  return Number(r.stdout.split("\t")[0]) || 0;
}
