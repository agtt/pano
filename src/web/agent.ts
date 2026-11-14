// Client for the agent's unix socket. The web process has no other way to
// change the system.

import { AsyncLocalStorage } from "node:async_hooks";
import { readFileSync } from "node:fs";
import { fsPath, paths } from "../shared/config.ts";

/**
 * Per request: the authenticator code typed into the form. It goes to the agent with the first
 * call that needs it. The agent may answer with a short grant, good only for repeating that same
 * call (method and params), and never for the actions that always ask for a code.
 */
export const stepUp = new AsyncLocalStorage<{ otp?: string; grant?: string; grantFor?: string; trust?: string; trustNew?: string }>();

/**
 * Only root can read it: lets `pano rpc` on the server skip the code. Never sent by the web process.
 * Read when first needed and kept once found: a first `pano install` calls the agent right after
 * starting it, before it has written the file.
 */
let cliTokenValue = "";
function cliTokenNow(): string {
  if (cliTokenValue || process.getuid?.() !== 0) return cliTokenValue;
  try {
    cliTokenValue = readFileSync(fsPath(`${paths.secrets}/cli.token`), "utf8").trim();
  } catch {
    // not there yet
  }
  return cliTokenValue;
}

export class AgentError extends Error {}

export async function call<T = any>(method: string, params: Record<string, unknown> = {}, actor = "web"): Promise<T> {
  const s = stepUp.getStore();
  const grant = s?.grant && s.grantFor === method ? s.grant : undefined;
  const res = await fetch(`http://agent/rpc/${method}`, {
    method: "POST",
    unix: fsPath(paths.agentSocket),
    headers: { "content-type": "application/json", ...(cliTokenNow() ? { "x-pano-cli": cliTokenNow() } : {}) },
    body: JSON.stringify({ params, actor, ...(s?.trust ? { trust: s.trust } : {}), ...(grant ? { grant } : s?.otp ? { otp: s.otp } : {}) }),
  } as RequestInit);
  const body = (await res.json().catch(() => ({ ok: false, error: `agent returned ${res.status}` }))) as { ok: boolean; result?: T; error?: string; grant?: string; trust?: string };
  // A verified code trusts the session for a while; the web keeps it next to the session.
  if (s && body.trust) s.trust = s.trustNew = body.trust;
  // The agent only takes the code on a call that needs it (it answers with a trust token then; an
  // always-ask action gets no grant); until then it stays for the next one. A code is used once.
  if (s && (body.grant || body.trust || res.status === 403)) {
    if (body.grant) {
      s.grant = body.grant;
      s.grantFor = method;
    }
    s.otp = undefined;
  }
  if (!body.ok) throw new AgentError(body.error ?? "agent error");
  return body.result as T;
}
