// The edge does not read .htaccess files. When a PHP site moves off Apache or
// OpenLiteSpeed, directories that were closed with "deny from all" (or basic
// auth) become 404 paths, failing closed; every other rule that no longer
// applies is reported so it can be recreated by hand.

import { fsPath } from "../shared/config.ts";
import { run } from "./sys.ts";

export type HtaccessFinding = { deny: boolean; notes: string[] };

// WordPress' own block works as is: php_fastcgi already falls back to index.php.
const HARMLESS_REWRITE = [
  /^RewriteRule\s+\^index\\?\.php\$\s+-\s+\[L\]$/i,
  /^RewriteRule\s+\.\s+\/index\.php\s+\[L\]$/i,
  /^RewriteRule\s+\.\*\s+-\s+\[E=HTTP_AUTHORIZATION:%\{HTTP:Authorization\}\]$/i,
  /^RewriteRule\s+\^\s+index\.php\s+\[L\]$/i,
];

export function analyzeHtaccess(text: string): HtaccessFinding {
  const notes = new Set<string>();
  let deny = false;
  // Only <Files>/<FilesMatch>/<Limit> narrow a rule; <IfModule> and friends are transparent.
  const scopes: boolean[] = [];
  const narrowed = () => scopes.some(Boolean);
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim().replace(/\s+/g, " ");
    if (!line || line.startsWith("#")) continue;
    const open = line.match(/^<(\w+)/);
    if (open && !line.startsWith("</")) {
      scopes.push(/^(Files|FilesMatch|Limit|LimitExcept)$/i.test(open[1]!));
      continue;
    }
    if (line.startsWith("</")) {
      scopes.pop();
      continue;
    }
    if (/^(deny from all|require all denied)$/i.test(line)) {
      if (narrowed()) notes.add("access rule inside <Files>/<Limit> is not enforced; review it");
      else deny = true;
    } else if (/^(allow from|require (ip|host))\b/i.test(line)) {
      notes.add("IP allow-list is not enforced; the directory is blocked for everyone");
    } else if (/^(AuthType|AuthUserFile|Require valid-user)\b/i.test(line)) {
      if (!narrowed()) deny = true;
      notes.add("password protection is not enforced; the directory is blocked until you protect it another way");
    } else if (/^RewriteRule\b/i.test(line)) {
      if (!HARMLESS_REWRITE.some((r) => r.test(line))) notes.add("custom rewrite rules are not applied");
    } else if (/^(Redirect|RedirectMatch|RedirectPermanent)\b/i.test(line)) {
      notes.add("redirects are not applied");
    } else if (/^php_(value|flag|admin_value|admin_flag)\b/i.test(line)) {
      notes.add("php_value settings are ignored (use .user.ini)");
    } else if (/^(SetHandler|AddHandler|AddType)\b.*php/i.test(line)) {
      notes.add("custom PHP handler mapping is ignored (only .php runs)");
    }
  }
  return { deny, notes: [...notes] };
}

const SAFE_PATH = /^\/[A-Za-z0-9._~\/-]*$/;

/** Reads every .htaccess under a document root and turns it into deny paths plus warnings. */
export async function scanHtaccess(docroot: string): Promise<{ denyPaths: string[]; warnings: string[] }> {
  const real = fsPath(docroot);
  const r = await run(["find", real, "-name", ".htaccess", "-type", "f", "-size", "-256k"], { check: false, timeoutMs: 120_000 });
  const files = r.stdout.split("\n").filter(Boolean).sort().slice(0, 5000);
  const deny: string[] = [];
  const warnings: string[] = [];
  for (const file of files) {
    const text = await Bun.file(file).text().catch(() => null);
    if (text === null) continue;
    const rel = file.slice(real.length).replace(/\/\.htaccess$/, "") || "/";
    const found = analyzeHtaccess(text);
    if (found.deny) {
      if (SAFE_PATH.test(rel)) deny.push(rel);
      else warnings.push(`${rel}: closed with .htaccess but the path has characters the edge cannot match; move or protect it`);
    }
    for (const n of found.notes) warnings.push(`${rel}/.htaccess: ${n}`);
  }
  // A denied directory already covers everything below it.
  const sorted = deny.sort((a, b) => a.length - b.length);
  const minimal = sorted.filter((p, i) => !sorted.slice(0, i).some((q) => q === "/" || p.startsWith(q + "/")));
  return { denyPaths: minimal, warnings };
}
