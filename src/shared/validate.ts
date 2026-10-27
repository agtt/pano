// Every value that reaches a command line, a config file or SQL goes through one
// of these first. The agent re-validates everything it receives from the web UI.

export class ValidationError extends Error {
  status = 400;
}

function check(ok: boolean, msg: string): asserts ok {
  if (!ok) throw new ValidationError(msg);
}

// Max 24 chars: the app's system user is "app-<name>" and must fit in 32.
const APP_NAME = /^[a-z][a-z0-9-]{1,22}[a-z0-9]$/;
const DOMAIN = /^(\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/;
const DB_IDENT = /^[A-Za-z0-9_]{1,64}$/;
const DB_USER = /^[A-Za-z0-9_]{1,32}$/;
// file:// is limited to bare repos under /srv/pano/git ("git push to the server" deploys).
const GIT_URL = /^(?:https:\/\/[A-Za-z0-9.-]+(?::\d+)?\/[A-Za-z0-9._~\/-]+|git@[A-Za-z0-9.-]+:[A-Za-z0-9._~\/-]+|ssh:\/\/git@[A-Za-z0-9.-]+(?::\d+)?\/[A-Za-z0-9._~\/-]+|file:\/\/\/srv\/pano\/git\/[A-Za-z0-9._-]+\.git)$/;
const BRANCH = /^[A-Za-z0-9][A-Za-z0-9._\/-]{0,99}$/;
const VERSION = /^\d{1,3}\.\d{1,3}\.\d{1,3}$/;
const ENV_KEY = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const SUBDIR = /^(?:[A-Za-z0-9._-]+\/)*[A-Za-z0-9._-]+$/;
const HTTP_PATH = /^\/[A-Za-z0-9._~\/?=&%-]{0,200}$/;

export const v = {
  appName(s: unknown): string {
    check(typeof s === "string" && APP_NAME.test(s), "name: 3-24 chars, lowercase letters, digits and dashes");
    return s;
  },
  domain(s: unknown): string {
    check(typeof s === "string", "domain required");
    const d = s.trim().toLowerCase().replace(/\.$/, "");
    check(d.length <= 253 && DOMAIN.test(d), `invalid domain: ${d}`);
    return d;
  },
  domains(s: unknown): string[] {
    const list = (Array.isArray(s) ? s : String(s ?? "").split(/[\s,]+/)).filter(Boolean);
    check(list.length > 0 && list.length <= 50, "1-50 domains required");
    return [...new Set(list.map(v.domain))];
  },
  dbName(s: unknown): string {
    check(typeof s === "string" && DB_IDENT.test(s), "database name: letters, digits, underscore (max 64)");
    return s;
  },
  dbUser(s: unknown): string {
    check(typeof s === "string" && DB_USER.test(s), "database user: letters, digits, underscore (max 32)");
    return s;
  },
  password(s: unknown, min = 12): string {
    check(typeof s === "string" && s.length >= min && s.length <= 256, `password: at least ${min} characters`);
    check(!/[\0\n\r]/.test(s), "password contains invalid characters");
    return s;
  },
  gitUrl(s: unknown): string {
    check(typeof s === "string" && GIT_URL.test(s.trim()) && !s.includes(".."), "repository: https://host/path, git@host:path, ssh://git@host/path or file:///srv/pano/git/name.git");
    return s.trim();
  },
  branch(s: unknown): string {
    check(typeof s === "string" && BRANCH.test(s) && !s.includes(".."), "invalid branch name");
    return s;
  },
  version(s: unknown): string {
    const x = String(s ?? "").replace(/^v/, "");
    check(VERSION.test(x), "version must look like 24.1.0");
    return x;
  },
  runtime(s: unknown): "node" | "bun" {
    check(s === "node" || s === "bun", "runtime must be node or bun");
    return s;
  },
  port(n: unknown): number {
    const x = Number(n);
    check(Number.isInteger(x) && x >= 1024 && x <= 65535, "port must be 1024-65535");
    return x;
  },
  int(n: unknown, min: number, max: number, field: string): number {
    const x = Number(n);
    check(Number.isInteger(x) && x >= min && x <= max, `${field} must be ${min}-${max}`);
    return x;
  },
  /** Shell commands an admin types (install/build/start). They run as the app's own user. */
  command(s: unknown, field: string, optional = true): string {
    const x = String(s ?? "").trim();
    if (optional && !x) return "";
    check(x.length > 0 && x.length <= 500 && !/[\0\n\r]/.test(x), `${field}: single line, max 500 chars`);
    return x;
  },
  subdir(s: unknown): string {
    const x = String(s ?? "").trim().replace(/^\.?\/+|\/+$/g, "");
    if (!x) return "";
    check(SUBDIR.test(x) && !x.split("/").includes(".."), "invalid sub-directory");
    return x;
  },
  httpPath(s: unknown): string {
    const x = String(s ?? "/").trim() || "/";
    check(HTTP_PATH.test(x), "invalid health check path");
    return x;
  },
  envKey(s: unknown): string {
    check(typeof s === "string" && ENV_KEY.test(s), `invalid env key: ${String(s)}`);
    return s;
  },
  envValue(s: unknown): string {
    const x = String(s ?? "");
    check(x.length <= 8192 && !/[\0\n\r]/.test(x), "env values must be single-line");
    return x;
  },
  /** Absolute path that must stay inside one of the allowed roots. */
  pathUnder(s: unknown, roots: string[]): string {
    check(typeof s === "string" && s.startsWith("/"), "absolute path required");
    const norm = normalize(s);
    check(roots.some((r) => norm === r || norm.startsWith(r.endsWith("/") ? r : r + "/")), `path must be under ${roots.join(", ")}`);
    return norm;
  },
  bucket(s: unknown): string {
    check(typeof s === "string" && /^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/.test(s), "invalid bucket name");
    return s;
  },
  hhmm(s: unknown): string {
    check(typeof s === "string" && /^([01]\d|2[0-3]):[0-5]\d$/.test(s), "time must be HH:MM");
    return s;
  },
  /** Where a process is reachable: "example.com", "*.example.com", "*" (any host) or any of those plus a path prefix. */
  route(s: unknown): string {
    const x = String(s ?? "").trim();
    const i = x.indexOf("/");
    const host = (i < 0 ? x : x.slice(0, i)).toLowerCase();
    const h = host === "*" ? "*" : v.domain(host);
    if (i < 0) return h;
    const path = x.slice(i).replace(/\/+$/, "");
    check(path === "" || /^\/[A-Za-z0-9._~\/-]{1,100}$/.test(path), `invalid path in ${x}`);
    return h + path;
  },
  siteName(s: unknown): string {
    const x = String(s ?? "").trim().toLowerCase();
    check(/^[a-z0-9][a-z0-9.-]{0,62}$/.test(x) && !x.includes(".."), "site name: letters, digits, dots and dashes (max 63)");
    return x;
  },
  phpVersion(s: unknown): string {
    check(typeof s === "string" && PHP_VERSIONS.includes(s), `PHP version must be one of ${PHP_VERSIONS.join(", ")}`);
    return s;
  },
};

/** Versions offered for PHP sites (Remi SCL packages), newest first. */
export const PHP_VERSIONS = ["8.5", "8.4", "8.3", "8.2", "8.1", "8.0", "7.4"];
/** End of security support; older versions still run imported sites but are flagged. */
export const PHP_EOL: Record<string, string> = {
  "8.5": "2029-12-31", "8.4": "2028-12-31", "8.3": "2027-12-31", "8.2": "2026-12-31",
  "8.1": "2025-12-31", "8.0": "2023-11-26", "7.4": "2022-11-28",
};
export const DEFAULT_PHP = "8.5";

export type ProcessSpec = { name: string; dir: string; routes: string[]; memory_mb: number; start: string };

const PROC_NAME = /^[a-z][a-z0-9-]{0,15}$/;

/**
 * One process per line: `name | dir | routes | memory MB | start command`.
 * Routes are comma separated (see v.route); "-" or empty means a worker with no port.
 * An empty start command is detected from the package.json in `dir`.
 */
export function parseProcesses(text: string): ProcessSpec[] {
  const out: ProcessSpec[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const [name = "", dir = "", routes = "", mem = "", ...start] = line.split("|").map((x) => x.trim());
    check(PROC_NAME.test(name), `process "${name}": 1-16 chars, a-z 0-9 -`);
    check(!out.some((p) => p.name === name), `process ${name} is listed twice`);
    out.push({
      name,
      dir: dir === "." ? "" : v.subdir(dir),
      routes: routes && routes !== "-" ? [...new Set(routes.split(/[\s,]+/).filter(Boolean).map(v.route))] : [],
      memory_mb: v.int(mem || 512, 64, 65536, `${name}: memory`),
      start: v.command(start.join("|"), `${name}: start command`),
    });
  }
  check(out.length <= 16, "at most 16 processes");
  return out;
}

export function formatProcesses(list: ProcessSpec[]): string {
  return list.map((p) => [p.name, p.dir || ".", p.routes.join(", ") || "-", String(p.memory_mb), p.start].join(" | ")).join("\n");
}

export function normalize(p: string): string {
  const out: string[] = [];
  for (const part of p.split("/")) {
    if (!part || part === ".") continue;
    if (part === "..") out.pop();
    else out.push(part);
  }
  return "/" + out.join("/");
}

/** Parse a .env style file (KEY=value per line). */
export function parseEnv(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split("\n")) {
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$/);
    if (!m) continue;
    let val = m[2]!.trim();
    if (/^(['"]).*\1$/.test(val)) val = val.slice(1, -1);
    out[m[1]!] = val;
  }
  return out;
}

/** systemd EnvironmentFile compatible output; values are double-quoted with escapes. */
export function formatEnv(vars: Record<string, string>): string {
  return Object.entries(vars)
    .map(([k, val]) => `${v.envKey(k)}="${v.envValue(val).replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\$/g, "\\$")}"`)
    .join("\n") + "\n";
}
