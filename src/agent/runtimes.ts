// Node.js and Bun runtimes, installed side by side under /opt/pano/runtimes so
// each app pins its own version and system packages never change them.
// Every download is checked against the publisher's SHA-256 list.

import { readdir } from "node:fs/promises";
import { fsPath, paths } from "../shared/config.ts";
import { v } from "../shared/validate.ts";
import { ensureDir, exists, remove, run } from "./sys.ts";

export type Runtime = "node" | "bun";

const arch = () => (process.arch === "arm64" ? "arm64" : "x64");
const dir = (rt: Runtime, ver: string) => `${paths.runtimes}/${rt}/${ver}`;

/** Directory that goes first on PATH for an app using this runtime. */
export function runtimeBin(rt: Runtime, ver: string): string {
  return rt === "node" ? `${dir(rt, ver)}/bin` : dir(rt, ver);
}

export async function installed(): Promise<{ runtime: Runtime; version: string }[]> {
  const out: { runtime: Runtime; version: string }[] = [];
  for (const rt of ["node", "bun"] as const) {
    try {
      for (const ver of await readdir(fsPath(`${paths.runtimes}/${rt}`))) {
        if (/^\d+\.\d+\.\d+$/.test(ver)) out.push({ runtime: rt, version: ver });
      }
    } catch {}
  }
  return out.sort((a, b) => a.runtime.localeCompare(b.runtime) || cmpVer(b.version, a.version));
}

export function cmpVer(a: string, b: string): number {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) if (pa[i] !== pb[i]) return (pa[i] ?? 0) - (pb[i] ?? 0);
  return 0;
}

export async function available(): Promise<{ node: { version: string; lts: string | false }[]; bun: string[] }> {
  const [nodeRes, bunRes] = await Promise.all([
    fetch("https://nodejs.org/dist/index.json"),
    fetch("https://api.github.com/repos/oven-sh/bun/releases?per_page=10", { headers: { "user-agent": "pano" } }),
  ]);
  const nodeAll = nodeRes.ok ? ((await nodeRes.json()) as { version: string; lts: string | false }[]) : [];
  // Latest release of each of the newest majors.
  const seen = new Set<string>();
  const node = nodeAll
    .map((r) => ({ version: r.version.replace(/^v/, ""), lts: r.lts }))
    .filter((r) => {
      const major = r.version.split(".")[0]!;
      if (seen.has(major) || Number(major) < 20) return false;
      seen.add(major);
      return true;
    });
  const bun = bunRes.ok
    ? ((await bunRes.json()) as { tag_name: string; prerelease: boolean }[])
        .filter((r) => !r.prerelease && r.tag_name.startsWith("bun-v"))
        .map((r) => r.tag_name.replace("bun-v", ""))
    : [];
  return { node, bun };
}

async function download(url: string): Promise<Uint8Array> {
  const res = await fetch(url, { headers: { "user-agent": "pano" } });
  if (!res.ok) throw new Error(`download failed (${res.status}): ${url}`);
  return new Uint8Array(await res.arrayBuffer());
}

function sha256(bytes: Uint8Array) {
  return new Bun.CryptoHasher("sha256").update(bytes).digest("hex");
}

function expectedSum(list: string, file: string): string {
  const line = list.split("\n").find((l) => l.trim().split(/\s+/)[1]?.replace(/^\*/, "") === file);
  if (!line) throw new Error(`no checksum published for ${file}`);
  return line.trim().split(/\s+/)[0]!;
}

export async function install(rt: Runtime, version: string, log: (l: string) => void = () => {}): Promise<void> {
  const ver = v.version(version);
  const target = dir(rt, ver);
  if (await exists(target)) return;
  const tmp = `${paths.data}/tmp/${rt}-${ver}`;
  await ensureDir(tmp, 0o700);
  try {
    if (rt === "node") {
      const file = `node-v${ver}-linux-${arch()}.tar.xz`;
      log(`downloading ${file}`);
      const [bytes, sums] = await Promise.all([
        download(`https://nodejs.org/dist/v${ver}/${file}`),
        download(`https://nodejs.org/dist/v${ver}/SHASUMS256.txt`),
      ]);
      if (sha256(bytes) !== expectedSum(new TextDecoder().decode(sums), file)) throw new Error("checksum mismatch");
      await Bun.write(fsPath(`${tmp}/${file}`), bytes);
      await ensureDir(target, 0o755);
      await run(["tar", "-xJf", fsPath(`${tmp}/${file}`), "-C", fsPath(target), "--strip-components=1", "--no-same-owner"]);
    } else {
      const file = `bun-linux-${arch() === "arm64" ? "aarch64" : "x64"}.zip`;
      log(`downloading ${file}`);
      const base = `https://github.com/oven-sh/bun/releases/download/bun-v${ver}`;
      const [bytes, sums] = await Promise.all([download(`${base}/${file}`), download(`${base}/SHASUMS256.txt`)]);
      if (sha256(bytes) !== expectedSum(new TextDecoder().decode(sums), file)) throw new Error("checksum mismatch");
      await Bun.write(fsPath(`${tmp}/${file}`), bytes);
      await run(["unzip", "-q", "-o", fsPath(`${tmp}/${file}`), "-d", fsPath(tmp)]);
      await ensureDir(target, 0o755);
      await run(["install", "-m", "0755", fsPath(`${tmp}/${file.replace(".zip", "")}/bun`), fsPath(`${target}/bun`)]);
      await run(["ln", "-sf", "bun", fsPath(`${target}/bunx`)]);
    }
    log(`installed ${rt} ${ver}`);
  } catch (e) {
    await remove(target);
    throw e;
  } finally {
    await remove(tmp);
  }
}

export async function uninstall(rt: Runtime, version: string, inUse: boolean) {
  if (inUse) throw new Error(`${rt} ${version} is used by an app`);
  await remove(dir(rt, v.version(version)));
}
