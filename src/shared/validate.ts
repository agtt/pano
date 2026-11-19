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
  runtime(s: unknown): "node" | "bun" | "python" {
    check(s === "node" || s === "bun" || s === "python", "runtime must be node, bun or python");
    return s;
  },
  /** Python: 3.13 (newest patch, pinned at the first deploy) or 3.13.5. */
  pythonVersion(s: unknown): string {
    const x = String(s ?? "").trim().replace(/^v/, "");
    check(/^3\.\d{1,2}(\.\d{1,2})?$/.test(x), "Python version must look like 3.13 or 3.13.5");
    return x;
  },
  /** The version of a runtime: Python also takes a minor ("3.13"), the others exactly x.y.z. */
  runtimeVersion(rt: "node" | "bun" | "python", s: unknown): string {
    return rt === "python" ? v.pythonVersion(s) : v.version(s);
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
    check(/^[A-Za-z0-9._\/-]+$/.test(s as string), "path: letters, digits and . _ - / only");
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

/** `static`: files of this directory are served by the edge itself (collected static files of a Python app), `upstream` is then empty. */
export type SiteRoute = { path: string; upstream: string; redirect?: string; code?: number; static?: string };

// A redirect target: an absolute https/http URL or a path on the same host, optionally ending in Caddy's
// {uri} (the request's path and query). No spaces, quotes or other braces: it is written into the Caddyfile.
const REDIRECT_TARGET = /^(?:https?:\/\/[A-Za-z0-9.-]+(?::\d{1,5})?(?:\/[A-Za-z0-9._~%&=+,:@\/?-]*)?|\/[A-Za-z0-9._~%&=+,:@\/?-]*)(?:\{uri\})?$/;
const REDIRECT_CODES = [301, 302, 307, 308];

/**
 * A proxy site's routes, one per line: `/path 127.0.0.1:PORT`, or `/path redirect TARGET [301|302|307|308]`
 * (TARGET may end in {uri}: `/old redirect https://example.com{uri}`).
 */
export function parseSiteRoutes(text: unknown): SiteRoute[] {
  return String(text ?? "")
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => {
      const [path = "", up = "", to = "", code = "", ...rest] = l.split(/\s+/);
      check(path.startsWith("/") && HTTP_PATH.test(path), `route "${l}": the path must start with /`);
      if (up === "redirect") {
        const n = code ? Number(code) : 301;
        check(REDIRECT_TARGET.test(to) && REDIRECT_CODES.includes(n) && !rest.length, `route "${l}": use "/path redirect https://host/path [301|302|307|308]"`);
        return { path, upstream: "", redirect: to, code: n };
      }
      check(/^127\.0\.0\.1:\d{2,5}$/.test(up) && !to, `route "${l}": use "/path 127.0.0.1:PORT"`);
      return { path, upstream: up };
    });
}

/** One route as the routes textarea shows it (parseSiteRoutes reads it back). */
export const routeText = (r: SiteRoute) => (r.redirect ? `${r.path} redirect ${r.redirect} ${r.code ?? 301}` : `${r.path} ${r.upstream}`);
/** Short form for lists: "/api → 127.0.0.1:3001", "/old → 301 https://…". */
export const routeLabel = (r: SiteRoute) => `${r.path} → ${r.redirect ? `${r.code ?? 301} ${r.redirect}` : r.upstream}`;

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

export type FwPort = { from: number; to: number; proto: "tcp" | "udp" };

/**
 * Extra firewall ports, one per line or comma separated: `8080`, `8080/tcp`, `51820/udp`,
 * `3000-3010/tcp`. A bare number means tcp. Sorted and de-duplicated; at most 50.
 */
export function parsePorts(text: unknown): FwPort[] {
  const seen = new Map<string, FwPort>();
  for (const raw of String(text ?? "").split(/[\s,]+/)) {
    if (!raw) continue;
    const m = raw.toLowerCase().match(/^(\d{1,5})(?:-(\d{1,5}))?(?:\/(tcp|udp))?$/);
    check(!!m, `port "${raw.slice(0, 40)}": use 8080, 8080/udp or 3000-3010/tcp`);
    const from = Number(m[1]);
    const to = Number(m[2] ?? m[1]);
    check(from >= 1 && to <= 65535 && from <= to, `port "${raw}": 1-65535, range from low to high`);
    const proto = (m[3] ?? "tcp") as "tcp" | "udp";
    seen.set(`${proto}/${from}-${to}`, { from, to, proto });
  }
  check(seen.size <= 50, "at most 50 extra ports");
  return [...seen.values()].sort((a, b) => (a.proto === b.proto ? a.from - b.from || a.to - b.to : a.proto < b.proto ? -1 : 1));
}

export function formatPorts(list: FwPort[]): string {
  return list.map((p) => `${p.from === p.to ? p.from : `${p.from}-${p.to}`}/${p.proto}`).join("\n");
}
