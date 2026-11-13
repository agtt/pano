// What PostgreSQL and MariaDB remote access (pgremote.ts, mysqlremote.ts) share: the name and its
// certificate from the edge, the address to listen on, the allowed networks and the firewalls.

import { applyEdge, edgeCert, edgeInstalled } from "./edge.ts";
import { followSettings as followFirewall } from "./firewall.ts";
import { cidr, REMOTE_PORT, remoteConfig, type RemoteEngine } from "./remotedb-config.ts";
import { settings } from "./state.ts";
import { ensureDir, readText, run, writeAtomic } from "./sys.ts";
import { followRemoteDb as followVpn } from "./vpn.ts";

/** Connections one remote user may hold: serverless functions open many; local apps keep the rest. */
export const REMOTE_CONN_LIMIT = 20;
const DOMAIN = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

export function remoteDomain(input: unknown): string {
  const d = String(input ?? "").trim().toLowerCase();
  if (!DOMAIN.test(d)) throw new Error("domain: a name of its own for the database, e.g. db.example.com");
  return d;
}

/** Parses the allowed networks (spaces, commas or new lines between them); throws on the first that is not one. */
export function parseAllow(input: unknown): string[] {
  const out = new Set<string>();
  for (const part of String(input ?? "").split(/[\s,]+/).filter(Boolean)) {
    const c = cidr(part);
    if (!c) throw new Error(`not an IP address or network: ${part} (e.g. 203.0.113.7 or 203.0.113.0/24)`);
    out.add(c);
  }
  if (out.size > 64) throw new Error("at most 64 networks");
  return [...out];
}

/** The address the database listens on for remote clients: the one the default route leaves from (behind 1:1 NAT, the private one). */
export async function localIp(): Promise<string> {
  const r = await run(["ip", "-4", "route", "get", "1.1.1.1"], { check: false });
  return r.stdout.match(/\bsrc (\S+)/)?.[1] ?? "";
}

/** Copies the edge's certificate to dir, readable only by owner. null: none yet; else whether it changed. */
export async function copyCert(domain: string, dir: string, owner: string): Promise<boolean | null> {
  const c = await edgeCert(domain);
  if (!c) return null;
  if ((await readText(`${dir}/server.crt`)) === c.cert && (await readText(`${dir}/server.key`)) === c.key) return false;
  await ensureDir(dir, 0o700, owner);
  await writeAtomic(`${dir}/server.crt`, c.cert, 0o600, owner);
  await writeAtomic(`${dir}/server.key`, c.key, 0o600, owner);
  return true;
}

/** Has the edge get a certificate for the (already saved) name and copies it; up to 90 s for a new name. */
export async function obtainCert(domain: string, dir: string, owner: string) {
  if (!(await edgeInstalled())) throw new Error("remote access uses the edge's certificate: install the edge first");
  await applyEdge();
  for (let i = 0; i < 45; i++) {
    if ((await copyCert(domain, dir, owner)) !== null) return;
    await Bun.sleep(2000);
  }
  throw new Error(`no certificate for ${domain} yet: its DNS record must point to this server (DNS only, no proxy) and ports 80/443 must reach the edge`);
}

const firewalld = async () => (await run(["firewall-cmd", "--state"], { check: false })).stdout.trim() === "running";

/** firewalld (EL): the port for everyone, or one rich rule per allowed network; what was added is remembered and taken back exactly. */
async function syncFirewalld(e: RemoteEngine) {
  const c = remoteConfig(e);
  const port = REMOTE_PORT[e];
  const key = `remote.${e}.firewalld`;
  const want = !c.on
    ? []
    : !c.allow.length
      ? [`--add-port=${port}/tcp`]
      : c.allow.map((n) => `--add-rich-rule=rule family="${n.includes(":") ? "ipv6" : "ipv4"}" source address="${n}" port port="${port}" protocol="tcp" accept`);
  const had: string[] = JSON.parse(settings.get(key) || "[]");
  if (!(await firewalld())) {
    settings.set(key, "[]");
    return;
  }
  if (JSON.stringify(had) === JSON.stringify(want)) return;
  for (const a of had) if (!want.includes(a)) await run(["firewall-cmd", "--permanent", a.replace(/^--add-/, "--remove-")], { check: false });
  for (const a of want) if (!had.includes(a)) await run(["firewall-cmd", "--permanent", a]);
  await run(["firewall-cmd", "--reload"], { check: false });
  settings.set(key, JSON.stringify(want));
}

/** Every firewall pano knows about follows the saved state of this engine. */
export async function syncNetwork(e: RemoteEngine) {
  await syncFirewalld(e);
  await followFirewall();
  await followVpn();
}

export async function listening(port: number, ip: string): Promise<boolean> {
  if (!ip) return false;
  const out = (await run(["ss", "-Htln", `sport = :${port}`], { check: false })).stdout;
  return [`${ip}:`, "0.0.0.0:", "*:", "[::]:"].some((a) => out.includes(` ${a}${port}`) || out.includes(`\t${a}${port}`));
}
