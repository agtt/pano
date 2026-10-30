// Boat (boat.dev) client: throwaway cloud machines for Android builds. Only the
// calls pano needs, over the REST API with the key kept root-only on the server.

import type { Machine } from "../shared/android.ts";
import { paths } from "../shared/config.ts";
import { readText } from "./sys.ts";

export const KEY_FILE = `${paths.secrets}/boat.token`;
const API = "https://boat.dev/api/v1";

export const SANDBOX_ID = /^bx_[23456789abcdefghjkmnpqrstuvwxyz]{8}$/;

export async function boatKey(): Promise<string> {
  return ((await readText(KEY_FILE)) ?? "").trim();
}

export class BoatError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message);
  }
}

async function boat<T = any>(method: string, path: string, body?: unknown, o: { key?: string; headers?: Record<string, string>; timeoutMs?: number } = {}): Promise<T> {
  const key = o.key ?? (await boatKey());
  if (!key) throw new Error("Boat is not connected (Android page)");
  const r = await fetch(`${API}${path}`, {
    method,
    headers: { authorization: `Bearer ${key}`, "user-agent": "pano", ...(body ? { "content-type": "application/json" } : {}), ...o.headers },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(o.timeoutMs ?? 30_000),
  });
  const data = (await r.json().catch(() => ({}))) as any;
  if (!r.ok || data.ok === false) {
    const code = String(data.code ?? data.error?.code ?? r.status);
    throw new BoatError(r.status, code, `Boat ${r.status} ${code}: ${data.message ?? data.error?.message ?? r.statusText}${data.requestId ? ` (${data.requestId})` : ""}`);
  }
  return data as T;
}

/** Checks a key and returns what the account may start now. */
export async function limits(key?: string): Promise<{ machineTypes?: string[] }> {
  return boat("GET", "/limits", undefined, { key });
}

export type Sandbox = { id: string; state: string; setupStatus?: string; error?: unknown };

/**
 * A machine nobody else can use: no account secrets inside (noEnv) and no snapshots, so a stop,
 * an auto-stop or a crash erases its disk instead of keeping it for 14 days. ttl is the backstop
 * if pano never comes back to delete it.
 */
export async function createSandbox(o: { machine: Machine; from?: string; ttlSeconds: number; name: string; snapshots?: boolean }): Promise<Sandbox> {
  const r = await boat<{ sandbox: Sandbox }>("POST", "/sandboxes", {
    type: o.machine,
    ...(o.from ? { from: o.from } : {}),
    ttlSeconds: o.ttlSeconds,
    name: o.name,
    labels: { pano: "android" },
    noEnv: true,
    snapshots: o.snapshots ?? false,
  });
  if (!SANDBOX_ID.test(r.sandbox?.id ?? "")) throw new Error("Boat returned no sandbox id");
  return r.sandbox;
}

export async function getSandbox(id: string): Promise<Sandbox> {
  return (await boat<{ sandbox: Sandbox }>("GET", `/sandboxes/${id}`)).sandbox;
}

/** Until the machine takes commands (a few seconds from a saved snapshot, about a minute fresh). */
export async function waitReady(id: string, timeoutMs = 10 * 60_000) {
  const until = Date.now() + timeoutMs;
  for (;;) {
    const s = await getSandbox(id);
    if (["ready", "idle", "running"].includes(s.state) && s.setupStatus !== "pending" && s.setupStatus !== "running") return;
    if (["error", "archived", "archiving", "cancelled"].includes(s.state)) throw new Error(`Boat machine ${id} is ${s.state}`);
    if (Date.now() > until) throw new Error(`Boat machine ${id} not ready after ${Math.round(timeoutMs / 60_000)} min`);
    await Bun.sleep(3000);
  }
}

/** Deletes the machine and everything on it. Never throws: it runs in cleanups. */
export async function deleteSandbox(id: string): Promise<boolean> {
  if (!SANDBOX_ID.test(id)) return false;
  try {
    await boat("DELETE", `/sandboxes/${id}`, undefined, { headers: { "x-ascii-confirm-delete": id } });
    return true;
  } catch (e) {
    return e instanceof BoatError && e.status === 404;
  }
}

/** Small files (scripts, a keystore) straight into the machine; at most 5 MiB. */
export async function writeFile(id: string, path: string, content: string | Uint8Array) {
  const bytes = typeof content === "string" ? Buffer.from(content) : Buffer.from(content);
  await boat("PUT", `/sandboxes/${id}/files`, { path, content: bytes.toString("base64"), encoding: "base64" });
}

/** Large files go over a signed URL served by the machine itself (no size limit). */
export async function upload(id: string, path: string, file: Blob) {
  const u = await boat<{ url: string }>("POST", `/sandboxes/${id}/files/upload-url`, { path, ttlSeconds: 900 });
  const r = await fetch(u.url, { method: "PUT", body: file, signal: AbortSignal.timeout(30 * 60_000) });
  if (!r.ok) throw new Error(`upload to the Boat machine failed: ${r.status}`);
}

export async function download(id: string, path: string): Promise<Response> {
  const u = await boat<{ url: string }>("POST", `/sandboxes/${id}/files/download-url`, { path, ttlSeconds: 900 });
  const r = await fetch(u.url, { signal: AbortSignal.timeout(30 * 60_000) });
  if (!r.ok || !r.body) throw new Error(`download from the Boat machine failed: ${r.status}`);
  return r;
}

/** A short command; its output comes back with it. */
export async function exec(id: string, command: string, timeoutSeconds = 60): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  const r = await boat<{ exitCode: number | null; stdout?: string; stderr?: string }>("POST", `/sandboxes/${id}/commands`, { command, timeoutSeconds }, { timeoutMs: (timeoutSeconds + 30) * 1000 });
  return { exitCode: r.exitCode ?? -1, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

/**
 * Runs a long command in the background and streams its output to onText until it ends.
 * Returns the exit code; throws when it runs past the deadline (the caller deletes the machine).
 */
export async function runDetached(id: string, command: string, onText: (s: string) => void, deadline: number): Promise<number> {
  const start = await boat<{ processId: number }>("POST", `/sandboxes/${id}/commands`, { command, detached: true });
  let out = 0;
  let err = 0;
  for (;;) {
    const s = await boat<{ status: string; exitCode: number | null; stdout?: string; stderr?: string; stdoutNextOffset?: number; stderrNextOffset?: number; more?: boolean }>(
      "GET",
      `/sandboxes/${id}/commands/${start.processId}?stdoutOffset=${out}&stderrOffset=${err}`,
    );
    if (s.stdout) onText(s.stdout);
    if (s.stderr) onText(s.stderr);
    out = s.stdoutNextOffset ?? out;
    err = s.stderrNextOffset ?? err;
    if (s.more) continue;
    if (s.status !== "running") return s.exitCode ?? -1;
    if (Date.now() > deadline) throw new Error("build timed out");
    await Bun.sleep(2000);
  }
}

/** Saves the machine's disk under a name (replacing what it held); new machines start from it. */
export async function saveSnapshot(id: string, name: string, timeoutMs = 30 * 60_000) {
  await boat("POST", "/saved-snapshots", { sandboxId: id, name });
  const until = Date.now() + timeoutMs;
  for (;;) {
    const s = (await boat<{ snapshot: { status: string } }>("GET", `/saved-snapshots/${name}`)).snapshot;
    if (s.status === "ready") return;
    if (s.status === "failed") throw new Error(`saving ${name} failed on Boat`);
    if (Date.now() > until) throw new Error(`saving ${name} still not done after ${Math.round(timeoutMs / 60_000)} min`);
    await Bun.sleep(5000);
  }
}

export async function deleteSnapshot(name: string) {
  await boat("DELETE", `/saved-snapshots/${name}`).catch(() => {});
}
