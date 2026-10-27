// GitHub connection: one fine-grained token, kept root-only on the server. With
// it an app is linked in one click (read-only deploy key + push webhook) and
// every deploy reports back to the commit as a status check, Vercel-style.
// Without it everything still works by hand (deploy key + webhook URL).

import { paths } from "../shared/config.ts";
import { edgeSettings } from "./edge.ts";
import { audit, settings, type App } from "./state.ts";
import { ensureDir, readText, writeAtomic } from "./sys.ts";

const TOKEN_FILE = `${paths.secrets}/github.token`;
const API = "https://api.github.com";

/** owner/repo of a GitHub URL in any of the forms an app accepts, or null. */
export function parseRepo(url: string): { owner: string; repo: string } | null {
  const m = url.trim().match(/^(?:https:\/\/github\.com\/|git@github\.com:|ssh:\/\/git@github\.com\/)([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?\/?$/);
  return m ? { owner: m[1]!, repo: m[2]! } : null;
}

async function token(): Promise<string> {
  return ((await readText(TOKEN_FILE)) ?? "").trim();
}

async function gh<T = any>(path: string, init: { method?: string; body?: unknown } = {}, tok?: string): Promise<{ status: number; data: T }> {
  const t = tok ?? (await token());
  if (!t) throw new Error("GitHub is not connected");
  const r = await fetch(`${API}${path}`, {
    method: init.method ?? "GET",
    headers: {
      authorization: `Bearer ${t}`,
      accept: "application/vnd.github+json",
      "x-github-api-version": "2022-11-28",
      "user-agent": "pano",
      ...(init.body ? { "content-type": "application/json" } : {}),
    },
    body: init.body ? JSON.stringify(init.body) : undefined,
    signal: AbortSignal.timeout(15_000),
  });
  const data = (await r.json().catch(() => ({}))) as T;
  return { status: r.status, data };
}

const fail = (what: string, r: { status: number; data: any }) =>
  new Error(`${what}: GitHub ${r.status} ${r.data?.message ?? ""}${r.status === 403 || r.status === 404 ? " (check the token's repository access and permissions)" : ""}`);

export async function status() {
  const login = settings.get("github.login") ?? "";
  return { connected: !!login && !!(await token()), login };
}

export async function connect(input: { token?: unknown }, actor: string) {
  const tok = String(input.token ?? "").trim();
  if (!/^(github_pat_[A-Za-z0-9_]{20,255}|gh[pousr]_[A-Za-z0-9]{30,255})$/.test(tok)) throw new Error("paste a GitHub token (github_pat_… or ghp_…)");
  const r = await gh<{ login: string }>("/user", {}, tok);
  if (r.status !== 200) throw fail("token check", r);
  await ensureDir(paths.secrets, 0o700);
  await writeAtomic(TOKEN_FILE, tok + "\n", 0o600);
  settings.set("github.login", r.data.login);
  audit(actor, "github.connect", { login: r.data.login });
  return { login: r.data.login };
}

export async function disconnect(actor: string) {
  await writeAtomic(TOKEN_FILE, "", 0o600);
  settings.set("github.login", "");
  audit(actor, "github.disconnect", {});
}

/** Repositories the token can see, newest push first (for the new-app form). */
export async function repos(): Promise<{ full_name: string; ssh_url: string; default_branch: string; private: boolean }[]> {
  if (!(await status()).connected) return [];
  const r = await gh<any[]>("/user/repos?per_page=100&sort=pushed&affiliation=owner,collaborator,organization_member");
  if (r.status !== 200) return [];
  return r.data.map((x) => ({ full_name: x.full_name, ssh_url: x.ssh_url, default_branch: x.default_branch, private: x.private }));
}

/**
 * Links an app to its repository: adds the app's own key as a read-only deploy
 * key and a push webhook signed with the app's secret. Safe to run again.
 */
export async function link(app: App, deployKey: string, actor: string) {
  const r = parseRepo(app.repo);
  if (!r) throw new Error("the app's repository is not on github.com");
  const hooks = edgeSettings().hooksDomain;
  if (!hooks) throw new Error("set a webhook domain on the Edge page first (GitHub has to reach the server)");
  const base = `/repos/${r.owner}/${r.repo}`;

  const keys = await gh<{ key: string }[]>(`${base}/keys`);
  if (keys.status !== 200) throw fail("deploy keys", keys);
  const keyBody = deployKey.split(" ").slice(0, 2).join(" ");
  if (!keys.data.some((k) => k.key.trim() === keyBody)) {
    const add = await gh(`${base}/keys`, { method: "POST", body: { title: `pano ${app.name}`, key: deployKey, read_only: true } });
    if (add.status !== 201) throw fail("add deploy key", add);
  }

  const url = `https://${hooks}/hooks/github/${app.name}`;
  const list = await gh<{ id: number; config: { url?: string } }[]>(`${base}/hooks`);
  if (list.status !== 200) throw fail("webhooks", list);
  const config = { url, content_type: "json", secret: app.webhook_secret, insecure_ssl: "0" };
  const existing = list.data.find((h) => h.config.url === url);
  const hook = existing
    ? await gh(`${base}/hooks/${existing.id}`, { method: "PATCH", body: { config, events: ["push"], active: true } })
    : await gh(`${base}/hooks`, { method: "POST", body: { name: "web", config, events: ["push"], active: true } });
  if (hook.status !== 200 && hook.status !== 201) throw fail("webhook", hook);

  audit(actor, "github.link", { app: app.name, repo: `${r.owner}/${r.repo}` });
  // Private repositories are cloned over SSH with the deploy key.
  return { repo: `${r.owner}/${r.repo}`, sshUrl: `git@github.com:${r.owner}/${r.repo}.git`, webhook: url };
}

/** Commit status shown next to the commit and in pull requests. Never fails a deploy. */
export async function reportStatus(app: App, sha: string, state: "pending" | "success" | "failure", description: string) {
  const r = parseRepo(app.repo);
  if (!r || !/^[0-9a-f]{40}$/.test(sha) || !(await status()).connected) return;
  const target = (app.domains ?? [])[0];
  await gh(`/repos/${r.owner}/${r.repo}/statuses/${sha}`, {
    method: "POST",
    body: { state, context: "pano/deploy", description: description.slice(0, 140), ...(target && state === "success" ? { target_url: `https://${target}` } : {}) },
  }).catch(() => {});
}
