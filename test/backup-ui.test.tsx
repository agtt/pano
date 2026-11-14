import { expect, test } from "bun:test";
import { PROVIDER_IDS, PROVIDERS } from "../src/shared/backup-providers.ts";
import { t, withLang } from "../src/web/i18n.ts";
import { trBackups } from "../src/web/i18n-backups.ts";
import { BackupBanner, ConnectPage, ConnectResultPage, DestCards, type BackupHealth, type ConnectResult, type Dest } from "../src/web/views/backups.tsx";
import { DatabaseDetail, DatabasesPage, rowsOf } from "../src/web/views/databases.tsx";
import { BackupsPage, type BackupSettings } from "../src/web/views/pages.tsx";

const providers = PROVIDER_IDS.map((id) => PROVIDERS[id]);
const empty: Dest = { accountId: "", bucket: "", prefix: "pano", accessKeyId: "", hasSecret: false, endpoint: "", protect: false };
const r2: Dest = { ...empty, accountId: "a".repeat(32), bucket: "my-backups", accessKeyId: "AKIA1234567890ABCD", hasSecret: true, protect: true, provider: "r2" };
const health = (over: Partial<BackupHealth> = {}): BackupHealth => ({
  configured: 1, protected: true, allProtected: true, jobs: 3, lastSuccessAt: 1_700_000_000, lastFailure: null, neverRan: [], keyExported: true, keyExportedAt: 1_700_000_000, ...over,
});
const html = (n: unknown) => String(n);

test("banner: nothing when all is well, one line per thing that needs a person", () => {
  expect(html(<BackupBanner health={health()} />)).toBe("");
  expect(html(<BackupBanner health={null} />)).toBe("");
  const none = html(<BackupBanner health={health({ configured: 0 })} />);
  expect(none).toContain("/backups/connect?dest=a");
  expect(none).not.toContain("saved the backup key");
  const bad = html(<BackupBanner health={health({ lastFailure: { job: "panel", at: 1_700_000_000, error: "bucket gone" }, neverRan: ["shop"], keyExported: false })} />);
  expect(bad).toContain("panel");
  expect(bad).toContain("bucket gone");
  expect(bad).toContain("shop");
  expect(bad).toContain("/backups#tab-recovery");
});

test("banner: the daily-jobs action is a button on the backups page and a link on the overview", () => {
  const idle = health({ jobs: 0 });
  expect(html(<BackupBanner health={idle} csrf="tok" />)).toContain('action="/backups/defaults"');
  const link = html(<BackupBanner health={idle} />);
  expect(link).not.toContain("<form");
  expect(link).toContain('href="/backups"');
});

test("destination cards: empty ones offer to connect, filled ones show provider, bucket and protection", () => {
  const out = html(<DestCards dests={{ a: r2, b: empty }} csrf="tok" providers={providers} />);
  expect(out).toContain("Cloudflare R2");
  expect(out).toContain("my-backups");
  expect(out).toContain("Protected");
  expect(out).toContain("/backups/connect?dest=a");
  expect(out).toContain("/backups/connect?dest=b");
  // Only the second destination can be disconnected.
  expect(out).not.toContain("Disconnect");
  const both = html(<DestCards dests={{ a: r2, b: { ...r2, provider: "b2", endpoint: "https://s3.eu-central-003.backblazeb2.com" } }} csrf="tok" providers={providers} />);
  expect(both).toContain("Backblaze B2");
  expect(both).toContain("Disconnect");
});

test("connect step 1: every provider is a plain link", () => {
  const out = html(<ConnectPage csrf="tok" dest="b" providers={providers} current={empty} />);
  for (const id of PROVIDER_IDS) expect(out).toContain(`href="/backups/connect?dest=b&amp;provider=${id}"`);
  expect(out).not.toContain("<form");
});

test("connect step 2: form from the spec, key links, protect box and an always-asked code", () => {
  const out = html(<ConnectPage csrf="tok" dest="a" providers={providers} provider={PROVIDERS.r2} current={empty} />);
  expect(out).toContain('action="/backups/connect"');
  expect(out).toContain('name="provider" value="r2"');
  for (const f of PROVIDERS.r2.fields) expect(out).toContain(`name="${f.name}"`);
  // Advanced fields sit in a <details>.
  const more = out.slice(out.indexOf('<details class="more">'), out.indexOf("</details>"));
  expect(more).toContain('name="jurisdiction"');
  expect(more).toContain('name="prefix"');
  expect(more).not.toContain('name="accountId"');
  expect(out).toContain('type="password"');
  expect(out).toContain('target="_blank" rel="noopener noreferrer"');
  expect(out).toContain(PROVIDERS.r2.keyUrl);
  expect(out).toContain(PROVIDERS.r2.docsUrl);
  expect(out).toContain("Open Cloudflare R2 key page");
  expect(out).toContain('name="protect" value="1"');
  expect(out).toMatch(/name="otp"[^>]*data-always/);
  // The other-provider form has no key page link.
  const other = html(<ConnectPage csrf="tok" dest="a" providers={providers} provider={PROVIDERS.other} current={empty} />);
  expect(other).not.toContain("key page");
});

test("connect step 2 when changing: stored values come back, the secret is optional", () => {
  const out = html(<ConnectPage csrf="tok" dest="a" providers={providers} provider={PROVIDERS.r2} current={r2} />);
  expect(out).toContain('value="my-backups"');
  expect(out).toContain('value="AKIA1234567890ABCD"');
  expect(out).toContain("stored; leave empty");
  expect(out).toMatch(/name="protect" value="1" checked/);
  // Another provider than the stored one starts blank.
  const b2 = html(<ConnectPage csrf="tok" dest="a" providers={providers} provider={PROVIDERS.b2} current={r2} />);
  expect(b2).not.toContain("AKIA1234567890ABCD");
});

test("connect result: steps with marks and hints, next actions only on success", () => {
  const base: ConnectResult = { ok: true, provider: "r2", bucket: "pano-abc", endpoint: "https://x.r2.cloudflarestorage.com", region: "auto", prefix: "pano", created: true, protect: true, lifecycle: { retentionDays: 60 }, notes: ["Remember to save the key."], steps: [{ name: "Sign in", ok: true, hint: "" }, { name: "Create bucket", ok: true, hint: "made it" }] };
  const ok = html(<ConnectResultPage csrf="tok" dest="a" result={base} providers={providers} />);
  expect(ok).toContain("flash ok");
  expect(ok).toContain("pano-abc");
  expect(ok).toContain("pano created it");
  expect(ok).toContain("60 days");
  expect(ok).toContain("Remember to save the key.");
  expect(ok).toContain("✓");
  expect(ok).toContain('action="/backups/defaults"');
  expect(ok).toContain('action="/backups/key"');
  const bad: ConnectResult = { ...base, ok: false, created: false, steps: [{ name: "Sign in", ok: true, hint: "" }, { name: "Write test", ok: false, hint: "The key may not write to this bucket." }] };
  const no = html(<ConnectResultPage csrf="tok" dest="a" result={bad} providers={providers} />);
  expect(no).toContain("flash err");
  expect(no).toContain("✗");
  expect(no).toContain("The key may not write to this bucket.");
  expect(no).not.toContain('action="/backups/defaults"');
  expect(no).toContain("/backups/connect?dest=a&amp;provider=r2");
});

const settings: BackupSettings = { dests: { a: r2, b: empty }, engine: "archive", restic: "", kit: "none" };
const job = { id: 1, name: "panel", kind: "panel", target: "panel", schedule: "daily 03:30", keep: 30, last_run_at: 1_700_000_000, last_status: "success", runs: [{ id: 9, status: "success", bytes: 10, object_key: "k", error: "", started_at: 1_700_000_000, dest: "a", engine: "archive" }] };

test("backups page: banner, summary, tabs, jobs in one table, old form kept under Advanced", () => {
  const out = html(<BackupsPage csrf="tok" s={settings} jobs={[job]} dbs={[]} apps={[]} health={health({ keyExported: false })} providers={providers} />);
  for (const key of ["storage", "jobs", "recovery"]) expect(out).toContain(`id="tab-${key}"`);
  expect(out).toContain("summary-card");
  expect(out).toContain("/backups#tab-recovery");
  expect(out).toContain('class="jobs-table"');
  expect(out).toContain("Advanced: custom settings");
  // Every route and field of the old forms is still there.
  for (const a of ["/backups/dest", "/backups/engine", "/backups/key", "/backups/jobs", "/backups/jobs/1/run", "/backups/jobs/1/remove", "/backups/runs/9/restore"]) expect(out).toContain(`action="${a}"`);
  for (const n of ["accountId", "secretAccessKey", "endpoint", "protect"]) expect(out).toContain(`name="${n}"`);
  // The manual form's code field stays an always-asked one.
  expect(out).toMatch(/name="otp"[^>]*data-always/);
  const first = html(<BackupsPage csrf="tok" s={{ ...settings, dests: { a: empty, b: empty } }} jobs={[]} dbs={[]} apps={[]} health={health({ configured: 0, jobs: 0 })} providers={providers} />);
  expect(first).toContain("Connect storage");
  expect(first).toContain("No backup jobs yet");
});

test("backups page: the recovery kit opens on its own tab", () => {
  const out = html(<BackupsPage csrf="tok" s={settings} jobs={[]} dbs={[]} apps={[]} kitText="KIT-123" />);
  expect(out).toContain("KIT-123");
  expect(out).toMatch(/<section class="pane default" data-tab="recovery"/);
});

test("databases: one table for both engines, creation behind a button, remote on its own tab", () => {
  const data = { databases: [{ name: "shop", sizeMb: 3, tables: 12, users: ["shop@localhost"], system: false }, { name: "mysql", sizeMb: 1, tables: 1, users: [], system: true }], users: [{ user: "shop", host: "localhost" }] };
  const pg = [{ name: "blog", sizeMb: 7, owner: "blog", system: false }];
  const remote = { engine: "postgres" as const, available: true, on: true, domain: "db.example.com", allow: [], port: 5432, ip: "", listening: true, connLimit: 5, users: [{ user: "blog_r", database: "blog", created_at: 1 }] };
  const services = [
    { key: "mariadb" as const, label: "MariaDB", port: 3306, note: "", installed: true, version: "11", managed: true, active: "active", memory: 0, enabled: true },
    { key: "postgres" as const, label: "PostgreSQL", port: 5432, note: "", installed: true, version: "16", managed: true, active: "active", memory: 0, enabled: true },
  ];
  const out = html(<DatabasesPage csrf="tok" data={data} pg={pg} services={services} pgRemote={remote} />);
  expect(out).toContain("/databases/mariadb/shop");
  expect(out).toContain("/databases/postgres/blog");
  expect(out).not.toContain("/databases/mariadb/mysql");
  expect(out).toContain("1 system databases are hidden.");
  expect(out).toContain('action="/databases/create"');
  expect(out).toContain('action="/services/postgres/create"');
  expect(out).toContain('id="tab-remote"');
  expect(out).toContain("svc-strip");
  expect(rowsOf(data, pg)).toHaveLength(3);
  const none = html(<DatabasesPage csrf="tok" data={{ databases: [], users: [] }} />);
  expect(none).toContain("No databases yet");
});

test("database page: users, password reset, backup and delete keep their routes and fields", () => {
  const row = { engine: "mariadb" as const, name: "shop", sizeMb: 3, users: ["shop@localhost"], tables: 12, system: false };
  const out = html(<DatabaseDetail csrf="tok" engine="mariadb" name="shop" row={row} mariaUsers={[{ user: "shop", host: "localhost" }]} />);
  expect(out).toContain('action="/databases/password"');
  expect(out).toContain('name="userhost"');
  expect(out).toContain('action="/databases/drop"');
  expect(out).toContain('name="confirm"');
  expect(out).toContain('name="name" value="shop"');
  expect(out).toMatch(/name="otp"[^>]*data-always/);
  // No job yet: a daily one is offered with the old form's fields.
  expect(out).toContain('action="/backups/jobs"');
  expect(out).toContain('name="kind" value="mysql"');
  const withJob = html(<DatabaseDetail csrf="tok" engine="mariadb" name="shop" row={row} mariaUsers={[]} job={{ ...job, id: 4, kind: "mysql", target: "shop" }} />);
  expect(withJob).toContain('action="/backups/jobs/4/run"');
  const pg = html(<DatabaseDetail csrf="tok" engine="postgres" name="blog" row={{ ...row, engine: "postgres", name: "blog", tables: undefined }} mariaUsers={[]} />);
  expect(pg).toContain('action="/services/postgres/drop"');
  expect(pg).toContain('name="kind" value="postgres"');
});

test("Turkish: every text of the providers is translated", () => {
  const missing: string[] = [];
  const need = (s: string | undefined) => {
    if (s && !(s in trBackups)) missing.push(s);
  };
  for (const p of Object.values(PROVIDERS)) {
    need(p.tagline);
    need(p.keyHelp);
    need(p.permission);
    for (const f of p.fields) {
      need(f.label);
      need(f.placeholder);
      need(f.help);
    }
  }
  need(PROVIDERS.r2.fields.find((f) => f.name === "jurisdiction")!.options!.map((o) => o.label)[0]);
  // Brand names and key formats that are the same in both languages are fine untranslated.
  const same = new Set(["Bucket", "pano", "https://s3.example.com", "Cloudflare R2", "Backblaze B2", "Amazon S3", "Wasabi", "Hetzner Object Storage", "keyID", "applicationKey", "60"]);
  expect(missing.filter((s) => !same.has(s))).toEqual([]);
  expect(withLang("tr", () => t("Connect storage"))).toBe("Depolama bağla");
  const tr = withLang("tr", () => html(<ConnectPage csrf="tok" dest="a" providers={providers} provider={PROVIDERS.hetzner} current={empty} />));
  expect(tr).toContain("Anahtarı Hetzner Object Storage üzerinden al");
  expect(tr).toContain("Bağla ve dene");
});
