// Client for the agent's unix socket. The web process has no other way to
// change the system.

import { fsPath, paths } from "../shared/config.ts";

export class AgentError extends Error {}

export async function call<T = any>(method: string, params: Record<string, unknown> = {}, actor = "web"): Promise<T> {
  const res = await fetch(`http://agent/rpc/${method}`, {
    method: "POST",
    unix: fsPath(paths.agentSocket),
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ params, actor }),
  } as RequestInit);
  const body = (await res.json().catch(() => ({ ok: false, error: `agent returned ${res.status}` }))) as { ok: boolean; result?: T; error?: string };
  if (!body.ok) throw new AgentError(body.error ?? "agent error");
  return body.result as T;
}
