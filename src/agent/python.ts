// Python on demand. Nothing here runs, installs or is even loaded (runtimes.ts imports this file
// lazily) until an admin installs a Python version or the first Python app deploys: a server
// without Python apps has no Python, no uv, no build packages and no extra process.
//
// Source: python-build-standalone (astral-sh/python-build-standalone), relocatable CPython builds
// per exact version, side by side under /opt/pano/runtimes/python/<x.y.z> like Node.js and Bun. Each
// release publishes a SHA256SUMS file; the tarball is checked against it before anything is
// extracted. Packages come from uv (also from astral-sh, downloaded with its published .sha256),
// into one virtualenv per release; the distribution's Python and pip are never used. Distro
// packages are only for native wheels' headers (mysqlclient, psycopg2, ...), installed when a
// deploy needs them (see nativePackages).

import { constants } from "node:fs";
import { lstat, open, readdir, readlink, realpath, rename, rm, type FileHandle } from "node:fs/promises";
import { dirname } from "node:path";
import { DRY_RUN, fsPath, paths } from "../shared/config.ts";
import {
  PY_APP_FILES, PY_TEXT_FILES, listPython, nativePackages, pbsAsset, pickPython, trustedDownload, uvAsset, afterUninstall, type GhAsset, type PyRepo,
} from "../shared/python.ts";
import { v } from "../shared/validate.ts";
import { arch, cmpVer, dir, download, expectedSum, installedAll, sha256 } from "./runtimes.ts";
import { currentOs } from "./php-os.ts";
import { settings } from "./state.ts";
import { ensureDir, exists, randomToken, remove, run } from "./sys.ts";

const PBS = "https://api.github.com/repos/astral-sh/python-build-standalone/releases?per_page=8";
const UV_LATEST = "https://api.github.com/repos/astral-sh/uv/releases/latest";
const FULL = /^\d+\.\d+\.\d+$/;

type Release = { tag_name: string; assets: GhAsset[] };

let pbsCache: { at: number; value: Release[] } | null = null;
async function pbsReleases(): Promise<Release[]> {
  if (pbsCache && Date.now() - pbsCache.at < 600_000) return pbsCache.value;
  const res = await fetch(PBS, { headers: { "user-agent": "pano" }, signal: AbortSignal.timeout(15_000) });
  if (!res.ok) throw new Error(`cannot list Python releases (${res.status} from github.com)`);
  const value = (await res.json()) as Release[];
  pbsCache = { at: Date.now(), value };
  return value;
}

/** Python versions that can be installed (newest patch of each minor), empty when github.com is unreachable. Only asked for when the admin looks. */
export async function availablePython(): Promise<string[]> {
  const rel = await pbsReleases().catch(() => [] as Release[]);
  const all = new Set<string>();
  for (const r of rel.slice(0, 3)) for (const x of listPython(r.assets.map((a) => a.name), arch())) all.add(x);
  return [...all].sort((a, b) => cmpVer(b, a));
}

/** "3.14" -> the newest installed or published 3.14.x; "3.14.2" stays. Installed versions win (no network). */
export async function resolvePython(wanted: string): Promise<string> {
  const want = v.pythonVersion(wanted);
  if (FULL.test(want)) return want;
  const have = (await installedAll()).filter((r) => r.runtime === "python" && r.version.startsWith(`${want}.`)).map((r) => r.version);
  if (have.length) return have.sort(cmpVer).pop()!;
  for (const r of await pbsReleases()) {
    const hit = pickPython(r.assets.map((a) => a.name), want, arch());
    if (hit) return hit.version;
  }
  throw new Error(`Python ${want} is not offered for this CPU by python-build-standalone`);
}

/** Installs the version (and uv) if missing; returns the exact version the app is pinned to. */
export async function ensurePython(wanted: string, log: (l: string) => void = () => {}): Promise<string> {
  const ver = await resolvePython(wanted);
  await installPython(ver, log);
  await ensureUv(log);
  return ver;
}

async function extract(url: string, sumsUrl: string, file: string, stage: string, tmp: string) {
  if (!trustedDownload(url) || !trustedDownload(sumsUrl)) throw new Error("download URL is not on github.com/astral-sh");
  const [bytes, sums] = await Promise.all([download(url), download(sumsUrl)]);
  if (sha256(bytes) !== expectedSum(new TextDecoder().decode(sums), file)) throw new Error(`checksum mismatch for ${file}`);
  await ensureDir(tmp, 0o700);
  await Bun.write(fsPath(`${tmp}/${file}`), bytes);
  await ensureDir(stage, 0o755);
  await run(["tar", "-xzf", fsPath(`${tmp}/${file}`), "-C", fsPath(stage), "--strip-components=1", "--no-same-owner"]);
}

/** One install of a thing at a time (a deploy and the Runtimes page may ask together). */
const installing = new Map<string, Promise<unknown>>();
async function once<T>(key: string, fn: () => Promise<T>): Promise<T> {
  const prev = installing.get(key) ?? Promise.resolve();
  const next = prev.catch(() => {}).then(fn);
  installing.set(key, next);
  try {
    return await next;
  } finally {
    if (installing.get(key) === next) installing.delete(key);
  }
}

/**
 * Extracts into a staging directory (ignored by every listing), checks it, then renames it into place:
 * a crash half way leaves no directory that looks installed, and a failure never touches a directory
 * another install finished meanwhile.
 */
async function stageInstall(final: string, probe: string, fetchInto: (stage: string, tmp: string) => Promise<void>) {
  const stage = `${dirname(final)}/.stage-${randomToken(6)}`;
  const tmp = `${paths.data}/tmp/${randomToken(6)}`;
  try {
    await fetchInto(stage, tmp);
    if (!DRY_RUN && !(await exists(`${stage}/${probe}`))) throw new Error(`the archive has no ${probe}`);
    if (await exists(final)) return;
    await rename(fsPath(stage), fsPath(final));
  } finally {
    await remove(stage);
    await remove(tmp);
  }
}

export const installPython = (version: string, log: (l: string) => void = () => {}): Promise<void> =>
  resolvePython(version).then((ver) =>
    once(`python-${ver}`, async () => {
      const target = dir("python", ver);
      if (await exists(`${target}/bin/python3`)) return;
      let found: { asset: string; release: Release } | null = null;
      for (const r of await pbsReleases()) {
        const hit = pickPython(r.assets.map((a) => a.name), ver, arch());
        if (hit && hit.version === ver) {
          found = { asset: hit.asset, release: r };
          break;
        }
      }
      if (!found) throw new Error(`Python ${ver} is not in the newest python-build-standalone releases`);
      const url = (name: string) => found!.release.assets.find((a) => a.name === name)?.browser_download_url ?? "";
      log(`downloading ${found.asset} (python-build-standalone ${found.release.tag_name})`);
      await stageInstall(target, "bin/python3", (stage, tmp) => extract(url(found!.asset), url("SHA256SUMS"), found!.asset, stage, tmp));
      log(`installed python ${ver}`);
    }),
  );

/** Removes one version; with the last one, uv goes too: nothing of Python is left except distro packages. */
export async function uninstallPython(version: string): Promise<void> {
  await remove(dir("python", v.version(version)));
  if (afterUninstall((await installedAll()).filter((r) => r.runtime === "python")).removeUv) {
    await remove(`${paths.runtimes}/uv`);
    await remove(`${paths.runtimes}/python`);
  }
}

// ---- uv -----------------------------------------------------------------------------

/** Directory with the newest installed uv, or "" (Python never installed). */
export async function uvDir(): Promise<string> {
  try {
    const vers = (await readdir(fsPath(`${paths.runtimes}/uv`))).filter((x) => FULL.test(x)).sort(cmpVer);
    const last = vers.pop();
    return last && (await exists(`${dir("uv", last)}/uv`)) ? dir("uv", last) : "";
  } catch {
    return "";
  }
}

export const ensureUv = (log: (l: string) => void = () => {}): Promise<string> =>
  once("uv", async () => {
    const have = await uvDir();
    if (have) return have;
    const res = await fetch(UV_LATEST, { headers: { "user-agent": "pano" }, signal: AbortSignal.timeout(15_000) });
    if (!res.ok) throw new Error(`cannot look up uv (${res.status} from github.com)`);
    const ver = String(((await res.json()) as { tag_name?: string }).tag_name ?? "").replace(/^v/, "");
    if (!FULL.test(ver)) throw new Error("unexpected uv version from github.com");
    const file = uvAsset(arch());
    const base = `https://github.com/astral-sh/uv/releases/download/${ver}`;
    const target = dir("uv", ver);
    log(`downloading ${file} (uv ${ver})`);
    await stageInstall(target, "uv", (stage, tmp) => extract(`${base}/${file}`, `${base}/${file}.sha256`, file, stage, tmp));
    log(`installed uv ${ver}`);
    return target;
  });

// ---- reading a repository ----------------------------------------------------------------------

const SKIP = new Set([".git", "node_modules", ".venv", "venv", "__pycache__", ".pano-build", ".tox", ".mypy_cache"]);
const MAX_TEXT = 512 * 1024;

/**
 * Canonical path of what an open descriptor refers to: /proc/self/fd/N names the inode itself, so it
 * cannot be swapped under us. (Where there is no /proc, in development, a realpath of the path.)
 */
async function fdPath(fh: FileHandle, path: string): Promise<string> {
  try {
    return await readlink(`/proc/self/fd/${fh.fd}`);
  } catch {
    return realpath(path);
  }
}
const under = (path: string, root: string) => path.startsWith(root + "/");

/**
 * A regular file's text, read by root from a tenant's tree: opened without following a link, and only
 * used if the opened file really lives under `root` (a link in a directory on the way would lead out of
 * it; the descriptor's own path shows that). Undefined otherwise or when larger than MAX_TEXT.
 */
async function readSafe(path: string, root: string): Promise<string | undefined> {
  let fh;
  try {
    fh = await open(fsPath(path), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const st = await fh.stat();
    if (!st.isFile() || st.size > MAX_TEXT) return undefined;
    if (!under(await fdPath(fh, fsPath(path)), root)) return undefined;
    return await fh.readFile("utf8");
  } catch {
    return undefined;
  } finally {
    await fh?.close().catch(() => {});
  }
}

/**
 * Files up to two levels deep (names only, links skipped) and the contents of the few that detection
 * reads. `allowedRoot` is the app's releases directory: nothing outside it is read.
 */
export async function readRepo(workdir: string, configuredRequirements = "", allowedRoot = ""): Promise<PyRepo> {
  const files = new Set<string>();
  const root = await realpath(fsPath(allowedRoot || workdir)).catch(() => "");
  if (!root) return { files, texts: {} };
  const list = async (rel: string, depth: number) => {
    const entries = await readdir(fsPath(rel ? `${workdir}/${rel}` : workdir), { withFileTypes: true }).catch(() => []);
    for (const e of entries.slice(0, 2000)) {
      if (SKIP.has(e.name) || e.isSymbolicLink()) continue;
      const path = rel ? `${rel}/${e.name}` : e.name;
      if (e.isFile()) files.add(path);
      else if (e.isDirectory() && depth < 2) await list(path, depth + 1);
    }
  };
  await list("", 1);
  if (configuredRequirements && !files.has(configuredRequirements) && (await lstat(fsPath(`${workdir}/${configuredRequirements}`)).catch(() => null))?.isFile()) files.add(configuredRequirements);
  const texts: Record<string, string> = {};
  const want = [...PY_TEXT_FILES, ...PY_APP_FILES, ...[...files].filter((f) => /^requirements\/[^/]+\.txt$/.test(f)).slice(0, 20), configuredRequirements].filter(Boolean);
  for (const f of new Set(want)) {
    if (!files.has(f)) continue;
    const text = await readSafe(`${workdir}/${f}`, root);
    if (text !== undefined) texts[f] = text;
  }
  return { files, texts };
}

// ---- distro packages for native wheels ---------------------------------------------------------------

const APT_ENV = { DEBIAN_FRONTEND: "noninteractive", NEEDRESTART_MODE: "a" };

/** What a source build needs from the OS, installed the first time an app needs it (idempotent, nothing when already there). */
export async function ensureBuildPackages(deps: Iterable<string>, log: (l: string) => void = () => {}): Promise<string[]> {
  const os = currentOs();
  const pkgs = nativePackages(deps, os.family);
  const missing: string[] = [];
  for (const p of pkgs) {
    const ok =
      os.family === "el"
        ? (await run(["rpm", "-q", p], { check: false })).code === 0
        : (await run(["dpkg-query", "-W", "-f=${Status}", p], { check: false })).stdout.includes("install ok installed");
    if (!ok) missing.push(p);
  }
  if (!missing.length) return [];
  if (!os.known) throw new Error(`these packages are needed to build your dependencies and pano cannot install them on this system: ${missing.join(" ")}`);
  log(`installing build packages: ${missing.join(" ")}`);
  if (os.family === "el") await run(["dnf", "-y", "install", ...missing], { timeoutMs: 900_000 });
  else {
    await run(["apt-get", "update", "-qq"], { env: APT_ENV, check: false, timeoutMs: 600_000 });
    await run(["apt-get", "install", "-y", "--no-install-recommends", ...missing], { env: APT_ENV, timeoutMs: 900_000 });
  }
  // Left installed when the last Python app goes (other software may use them); the list is kept for whoever wants them gone.
  const known = JSON.parse(settings.get("python.os_packages") ?? "[]") as string[];
  settings.set("python.os_packages", JSON.stringify([...new Set([...known, ...missing])].sort()));
  return missing;
}

// ---- static files for the edge ----------------------------------------------------------------------

const MAX_FILE = 256 * 1024 * 1024;
const MAX_FILES = 100_000;
const MAX_BYTES = 4 * 1024 ** 3;

export type SnapshotOptions = {
  /** only files owned by this uid (the app's user) are copied */
  uid?: number;
  /** called before each file is opened; tests swap directories for links here */
  beforeOpen?: (path: string) => void | Promise<void>;
};

/**
 * Copies one file out of a tenant's tree into a root-owned destination. The tree is writable by the app
 * (its live release runs as the same user), so nothing about the path is trusted: the file is opened
 * without following a link, and only what the opened descriptor really is counts: a regular file, owned
 * by the app, small enough, and located (by /proc/self/fd, not by name) under `root`. A directory swapped
 * for a link anywhere on the way ends up outside `root` and the file is skipped. Returns the size, or null.
 */
async function copyChecked(from: string, to: string, root: string, o: SnapshotOptions): Promise<number | null> {
  let src: FileHandle | undefined;
  let out: FileHandle | undefined;
  const target = fsPath(to);
  const tmp = `${target}.pano-tmp-${randomToken(9)}`;
  try {
    await o.beforeOpen?.(from);
    src = await open(fsPath(from), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const st = await src.stat();
    if (!st.isFile() || st.size > MAX_FILE || (o.uid !== undefined && st.uid !== o.uid)) return null;
    if (!under(await fdPath(src, fsPath(from)), root)) return null;
    out = await open(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o644);
    const buf = Buffer.allocUnsafe(1024 * 1024);
    let size = 0;
    for (;;) {
      const { bytesRead } = await src.read(buf, 0, buf.length, null);
      if (!bytesRead) break;
      size += bytesRead;
      if (size > MAX_FILE) throw new Error("file grew while it was copied");
      await out.write(buf, 0, bytesRead);
    }
    await out.chmod(0o644);
    await out.close();
    out = undefined;
    await rename(tmp, target);
    return size;
  } catch {
    await out?.close().catch(() => {});
    await rm(tmp, { force: true }).catch(() => {});
    return null;
  } finally {
    await src?.close().catch(() => {});
  }
}

/**
 * Copies collected static files into root-owned directories the edge reads: regular files only,
 * dot files skipped, limits on size and count. `allowedRoot` is the app's releases directory: `src`
 * and every file copied must really be inside it (see copyChecked; checked also in development).
 * Returns what was copied.
 */
export async function snapshotStatic(src: string, allowedRoot: string, dest: string, opts: SnapshotOptions = {}): Promise<{ files: number; bytes: number; skipped: number }> {
  const root = await realpath(fsPath(allowedRoot));
  const top = await open(fsPath(src), constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try {
    if (!under(await fdPath(top, fsPath(src)), root)) throw new Error("static files directory is outside the release");
  } finally {
    await top.close();
  }
  await remove(dest);
  await ensureDir(dest, 0o755);
  const out = { files: 0, bytes: 0, skipped: 0 };
  const walk = async (from: string, to: string, depth: number) => {
    const names = await readdir(fsPath(from)).catch(() => [] as string[]);
    for (const name of names) {
      if (name.startsWith(".") || /[\0\n\r]/.test(name)) {
        out.skipped++;
        continue;
      }
      const st = await lstat(fsPath(`${from}/${name}`)).catch(() => null);
      if (st?.isDirectory() && depth < 24) {
        await ensureDir(`${to}/${name}`, 0o755);
        await walk(`${from}/${name}`, `${to}/${name}`, depth + 1);
      } else if (st?.isFile() && st.size <= MAX_FILE && out.files < MAX_FILES && out.bytes + st.size <= MAX_BYTES) {
        const size = await copyChecked(`${from}/${name}`, `${to}/${name}`, root, opts);
        if (size !== null) {
          out.files++;
          out.bytes += size;
        } else out.skipped++;
      } else out.skipped++;
    }
  };
  await walk(src, dest, 0);
  return out;
}

/** An app's served static files (all slots); with the app gone nothing of them is left. */
export const removeStatic = (app: string) => remove(`${paths.static}/${app}`);
