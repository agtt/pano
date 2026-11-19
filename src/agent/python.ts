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
import { lstat, open, readdir, realpath } from "node:fs/promises";
import { DRY_RUN, fsPath, paths } from "../shared/config.ts";
import {
  PY_APP_FILES, PY_TEXT_FILES, listPython, nativePackages, pbsAsset, pickPython, trustedDownload, uvAsset, afterUninstall, type GhAsset, type PyRepo,
} from "../shared/python.ts";
import { v } from "../shared/validate.ts";
import { arch, cmpVer, dir, download, expectedSum, installedAll, sha256 } from "./runtimes.ts";
import { currentOs } from "./php-os.ts";
import { settings } from "./state.ts";
import { copyResult } from "./throwaway.ts";
import { ensureDir, exists, remove, run } from "./sys.ts";

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

async function extract(url: string, sumsUrl: string, file: string, target: string, tmp: string) {
  if (!trustedDownload(url) || !trustedDownload(sumsUrl)) throw new Error("download URL is not on github.com/astral-sh");
  const [bytes, sums] = await Promise.all([download(url), download(sumsUrl)]);
  if (sha256(bytes) !== expectedSum(new TextDecoder().decode(sums), file)) throw new Error(`checksum mismatch for ${file}`);
  await ensureDir(tmp, 0o700);
  await Bun.write(fsPath(`${tmp}/${file}`), bytes);
  await ensureDir(target, 0o755);
  await run(["tar", "-xzf", fsPath(`${tmp}/${file}`), "-C", fsPath(target), "--strip-components=1", "--no-same-owner"]);
}

export async function installPython(version: string, log: (l: string) => void = () => {}): Promise<void> {
  const ver = await resolvePython(version);
  const target = dir("python", ver);
  if (await exists(`${target}/bin/python3`)) return;
  const tmp = `${paths.data}/tmp/python-${ver}`;
  try {
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
    await extract(url(found.asset), url("SHA256SUMS"), found.asset, target, tmp);
    if (!DRY_RUN && !(await exists(`${target}/bin/python3`))) throw new Error("the archive has no bin/python3");
    log(`installed python ${ver}`);
  } catch (e) {
    await remove(target);
    throw e;
  } finally {
    await remove(tmp);
  }
}

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

export async function ensureUv(log: (l: string) => void = () => {}): Promise<string> {
  const have = await uvDir();
  if (have) return have;
  const res = await fetch(UV_LATEST, { headers: { "user-agent": "pano" }, signal: AbortSignal.timeout(15_000) });
  if (!res.ok) throw new Error(`cannot look up uv (${res.status} from github.com)`);
  const ver = String(((await res.json()) as { tag_name?: string }).tag_name ?? "").replace(/^v/, "");
  if (!FULL.test(ver)) throw new Error("unexpected uv version from github.com");
  const file = uvAsset(arch());
  const base = `https://github.com/astral-sh/uv/releases/download/${ver}`;
  const target = dir("uv", ver);
  const tmp = `${paths.data}/tmp/uv-${ver}`;
  log(`downloading ${file} (uv ${ver})`);
  try {
    await extract(`${base}/${file}`, `${base}/${file}.sha256`, file, target, tmp);
    if (!DRY_RUN && !(await exists(`${target}/uv`))) throw new Error("the archive has no uv binary");
  } catch (e) {
    await remove(target);
    throw e;
  } finally {
    await remove(tmp);
  }
  log(`installed uv ${ver}`);
  return target;
}

// ---- reading a repository ----------------------------------------------------------------------

const SKIP = new Set([".git", "node_modules", ".venv", "venv", "__pycache__", ".pano-build", ".tox", ".mypy_cache"]);
const MAX_TEXT = 512 * 1024;

/** A regular file's text, never through a link and never more than MAX_TEXT; "" otherwise. Root reads what the repository holds. */
async function readSafe(path: string): Promise<string | undefined> {
  let fh;
  try {
    fh = await open(fsPath(path), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const st = await fh.stat();
    if (!st.isFile() || st.size > MAX_TEXT) return undefined;
    return await fh.readFile("utf8");
  } catch {
    return undefined;
  } finally {
    await fh?.close().catch(() => {});
  }
}

/** Files up to two levels deep (names only, links skipped) and the contents of the few that detection reads. */
export async function readRepo(workdir: string, configuredRequirements = ""): Promise<PyRepo> {
  const files = new Set<string>();
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
    const text = await readSafe(`${workdir}/${f}`);
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

/**
 * Copies collected static files into root-owned directories the edge reads: regular files and
 * directories only, no link followed (the build is finished, nothing writes while this runs), dot
 * files skipped, limits on size and count. `src` must resolve inside `release`. Returns what was copied.
 */
export async function snapshotStatic(src: string, release: string, dest: string): Promise<{ files: number; bytes: number; skipped: number }> {
  if (!DRY_RUN) {
    const [real, root] = await Promise.all([realpath(fsPath(src)), realpath(fsPath(release))]);
    if (!real.startsWith(root + "/")) throw new Error("static files directory is outside the release");
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
        const r = await copyResult(`${from}/${name}`, `${to}/${name}`, MAX_FILE, 0o644);
        if (r) {
          out.files++;
          out.bytes += r.size;
        } else out.skipped++;
      } else out.skipped++;
    }
  };
  await walk(src, dest, 0);
  return out;
}

/** An app's served static files (all slots); with the app gone nothing of them is left. */
export const removeStatic = (app: string) => remove(`${paths.static}/${app}`);
