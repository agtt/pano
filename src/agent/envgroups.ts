// Shared variables: a group (a Stripe key, a Sentry DSN, SMTP settings) kept once and given to
// several apps. Root-only files under /etc/pano/env-groups (part of the panel's own backup);
// systemd reads them before the app's own .env, so a value the app sets itself wins.

import { readdir } from "node:fs/promises";
import { fsPath, paths } from "../shared/config.ts";
import { groupList, groupName } from "../shared/env.ts";
import { formatEnv, parseEnv } from "../shared/validate.ts";
import { apps, audit } from "./state.ts";
import { ensureDir, exists, readText, remove, writeAtomic } from "./sys.ts";

const DIR = `${paths.etc}/env-groups`;
export const groupFile = (name: string) => `${DIR}/${name}.env`;

export async function groupNames(): Promise<string[]> {
  const files = await readdir(fsPath(DIR)).catch(() => [] as string[]);
  return files.filter((f) => f.endsWith(".env")).map((f) => f.slice(0, -4)).sort();
}

export async function readGroup(name: string): Promise<Record<string, string>> {
  return parseEnv((await readText(groupFile(groupName(name)))) ?? "");
}

export const appsUsing = (name: string) => apps.list().filter((a) => groupList(a.env_groups).includes(name)).map((a) => a.name);

/** Names, variable names and the apps that use each group; never values. */
export async function listGroups() {
  return Promise.all((await groupNames()).map(async (name) => ({ name, keys: Object.keys(await readGroup(name)), apps: appsUsing(name) })));
}

export async function saveGroup(nameInput: unknown, vars: Record<string, string>, actor: string) {
  const name = groupName(nameInput);
  await ensureDir(DIR, 0o700);
  await writeAtomic(groupFile(name), formatEnv(vars), 0o600);
  audit(actor, "envgroup.save", { name, keys: Object.keys(vars) });
  return { name, apps: appsUsing(name) };
}

export async function removeGroup(nameInput: unknown, actor: string) {
  const name = groupName(nameInput);
  const users = appsUsing(name);
  if (users.length) throw new Error(`${name} is used by ${users.join(", ")}; remove it from those apps first`);
  await remove(groupFile(name));
  audit(actor, "envgroup.remove", { name });
}

export async function assertGroupsExist(groups: string) {
  for (const g of groupList(groups)) if (!(await exists(groupFile(g)))) throw new Error(`no shared variable group ${g}`);
}
