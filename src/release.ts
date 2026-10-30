// Fetching a pano release from GitHub for `pano update --latest`: the binary for
// this CPU plus the release's SHA256SUMS and its signature. SHA256SUMS must be
// signed by the release key (so a hijacked release or repository cannot ship a
// binary), and the hash comes from it, so the binary is checked before update()
// ever sees it (update() checks it again).

import { createPublicKey, verify } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { RELEASE_PUBKEY } from "./shared/release-key.ts";

/** Whether `sig` (raw Ed25519, as `openssl pkeyutl -sign -rawin` writes it) signs `data`. */
export function signedBy(data: Uint8Array, sig: Uint8Array, pubkeyPem: string = process.env.PANO_RELEASE_PUBKEY || RELEASE_PUBKEY): boolean {
  try {
    return verify(null, data, createPublicKey(pubkeyPem), sig);
  } catch {
    return false;
  }
}

/** `<sha256>  <file>` lines as written by sha256sum (text or binary mode marker). */
export function parseSums(text: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const line of text.split("\n")) {
    const m = line.trim().match(/^([a-f0-9]{64}) [ *]?(.+)$/i);
    if (m) out.set(m[2]!, m[1]!.toLowerCase());
  }
  return out;
}

export function assetName(arch: string = process.arch): string {
  if (arch === "x64") return "pano-linux-x64";
  if (arch === "arm64") return "pano-linux-arm64";
  throw new Error(`no release binary for ${arch}`);
}

type Asset = { name: string; url: string };

async function gh(url: string, accept: string): Promise<Response> {
  const token = process.env.GITHUB_TOKEN;
  const res = await fetch(url, {
    headers: { "user-agent": "pano", accept, ...(token ? { authorization: `Bearer ${token}` } : {}) },
    signal: AbortSignal.timeout(120_000),
  });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}${res.status === 404 && !token ? " (a private repository needs GITHUB_TOKEN)" : ""}`);
  return res;
}

/** Downloads the latest release's binary for this arch into a fresh temp dir, verified against SHA256SUMS. */
export async function fetchLatest(): Promise<{ file: string; sha: string; tag: string; cleanup: () => Promise<void> }> {
  const repo = process.env.PANO_REPO ?? "agtt/pano";
  if (!/^[\w.-]+\/[\w.-]+$/.test(repo)) throw new Error("PANO_REPO must look like owner/name");
  const rel = (await (await gh(`https://api.github.com/repos/${repo}/releases/latest`, "application/vnd.github+json")).json()) as { tag_name: string; assets: Asset[] };
  const bin = assetName();
  const asset = (name: string) => {
    const a = rel.assets.find((x) => x.name === name);
    if (!a) throw new Error(`release ${rel.tag_name} has no ${name}`);
    return gh(a.url, "application/octet-stream");
  };
  const sums = new Uint8Array(await (await asset("SHA256SUMS")).arrayBuffer());
  const sig = new Uint8Array(await (await asset("SHA256SUMS.sig")).arrayBuffer());
  if (!signedBy(sums, sig)) throw new Error(`SHA256SUMS of ${rel.tag_name} is not signed by the pano release key`);
  const sha = parseSums(new TextDecoder().decode(sums)).get(bin);
  if (!sha) throw new Error(`${bin} is not listed in SHA256SUMS of ${rel.tag_name}`);
  const dir = await mkdtemp(`${tmpdir()}/pano-update-`);
  const cleanup = () => rm(dir, { recursive: true, force: true });
  try {
    const bytes = new Uint8Array(await (await asset(bin)).arrayBuffer());
    if (new Bun.CryptoHasher("sha256").update(bytes).digest("hex") !== sha) throw new Error(`${bin} does not match SHA256SUMS`);
    const file = `${dir}/${bin}`;
    await Bun.write(file, bytes);
    return { file, sha, tag: rel.tag_name, cleanup };
  } catch (e) {
    await cleanup();
    throw e;
  }
}
