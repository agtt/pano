// Client for the agent's unix socket. The web process has no other way to
// change the system.

import { AsyncLocalStorage } from "node:async_hooks";
import { readFileSync } from "node:fs";
import { fsPath, paths } from "../shared/config.ts";

/**
 * Per request: the authenticator code typed into the form. It goes to the agent
 * with the first call, which answers with a short grant used by the rest.
 */
export const stepUp = new AsyncLocalStorage<{ otp?: string; grant?: string }>();

/** Only root can read it: lets `pano rpc` on the server skip the code. */
const cliToken = (() => {
  try {
    return readFileSync(fsPath(`${paths.secrets}/cli.token`), "utf8").trim();
  } catch {
    return "";
  }
})();

export class AgentError extends Error {}

export async function call<T = any>(method: string, params: Record<string, unknown> = {}, actor = "web"): Promise<T> {
  const s = stepUp.getStore();
  const res = await fetch(`http://agent/rpc/${method}`, {
    method: "POST",
    unix: fsPath(paths.agentSocket),
    headers: { "content-type": "application/json", ...(cliToken ? { "x-pano-cli": cliToken } : {}) },
    body: JSON.stringify({ params, actor, ...(s?.grant ? { grant: s.grant } : s?.otp ? { otp: s.otp } : {}) }),
  } as RequestInit);
  const body = (await res.json().catch(() => ({ ok: false, error: `agent returned ${res.status}` }))) as { ok: boolean; result?: T; error?: string; grant?: string };
  if (s) {
    if (body.grant) s.grant = body.grant;
    s.otp = undefined;
  }
  if (!body.ok) throw new AgentError(body.error ?? "agent error");
  return body.result as T;
}
