// Process and filesystem helpers for the agent. Commands are always argv arrays
// (never a shell string); the only shell ever used is `sh -c` for an app's own
// build/start commands, and that runs as the app's unprivileged user.

import { constants } from "node:fs";
import { chmod, lchown, lstat, mkdir, open, readFile, rename, rm, stat, statfs } from "node:fs/promises";
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

export async function ensureDir(abs: string, mode = 0o755, owner?: string) {
  const real = fsPath(abs);
  // mkdir's mode is filtered by the umask (0027 for the agent); fix every directory it created.
  const first = await mkdir(real, { recursive: true, mode });
  // chmod/chown follow symlinks: a user who owns the parent could point this at /etc.
  await notSymlink(real);
  if (first) for (let d = real; d.length >= first.length; d = dirname(d)) await chmod(d, mode);
  await chmod(real, mode);
  if (owner) await chownTo(abs, owner);
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

export async function remove(abs: string) {
  await rm(fsPath(abs), { recursive: true, force: true });
}

/** Not cached: users are deleted and recreated (app/site removal) and may come back with another uid. */
export async function lookupUser(user: string): Promise<{ uid: number; gid: number } | null> {
  const passwd = await readText("/etc/passwd");
  const line = passwd?.split("\n").find((l) => l.startsWith(user + ":"));
  if (!line) return null;
  const [, , uid, gid] = line.split(":");
  return { uid: Number(uid), gid: Number(gid) };
}

async function chownTo(abs: string, owner: string) {
  if (DRY_RUN || process.getuid?.() !== 0) return;
  const ids = await lookupUser(owner);
  if (!ids) throw new Error(`unknown user ${owner}`);
  await lchown(fsPath(abs), ids.uid, ids.gid);
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
