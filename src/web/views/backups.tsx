// Backup storage the easy way: where the backups go (cards), the connect flow (pick a provider,
// paste the key, see every step of the test), and the banners that say what still needs a person.
// No inline script or style: the picker is plain links, the form is plain HTML.

import type { Child } from "hono/jsx";
import type { ProviderId, ProviderSpec } from "../../shared/backup-providers.ts";
import { fmtTime, t } from "../i18n.ts";
import { alwaysAttr, Card, Csrf } from "./layout.tsx";

export type Dest = {
  accountId: string;
  bucket: string;
  prefix: string;
  accessKeyId: string;
  hasSecret: boolean;
  endpoint: string;
  protect: boolean;
  provider?: ProviderId;
  jurisdiction?: "" | "eu";
};
export type DestId = "a" | "b";
export type BackupHealth = {
  configured: number;
  protected: boolean;
  allProtected: boolean;
  jobs: number;
  lastSuccessAt: number | null;
  lastFailure: { job: string; at: number; error: string } | null;
  neverRan: string[];
  keyExported: boolean;
  keyExportedAt: number | null;
};
export type ConnectResult = {
  ok: boolean;
  provider: ProviderId;
  bucket: string;
  endpoint: string;
  region: string;
  prefix: string;
  created: boolean;
  protect: boolean;
  lifecycle: { retentionDays: number } | null;
  notes: string[];
  steps: { name: string; ok: boolean; hint: string }[];
};

const Otp = (p: { always?: boolean }) => (
  <input name="otp" inputmode="numeric" pattern="[0-9]{6}" placeholder={t("Authenticator code")} required class="short" autocomplete="one-time-code" {...alwaysAttr(p.always)} />
);

export const providerName = (providers: ProviderSpec[] | undefined, id: string | undefined) => providers?.find((x) => x.id === id)?.name ?? id ?? "";
const destTitle = (d: DestId) => (d === "a" ? t("Main destination") : t("Second destination (optional)"));
const fill = (s: string, vars: Record<string, string | number>) => Object.entries(vars).reduce((acc, [k, v]) => acc.replaceAll(`{${k}}`, String(v)), t(s));

// ---- banners -----------------------------------------------------------------------------------

/**
 * What still needs a person, from backup.health: no storage, a failed run, jobs that never ran, the
 * key never saved. Nothing at all when all is well. With `csrf` (the Backups page) the daily-jobs
 * action is a button; without (the overview) it is a link to that page.
 */
export function BackupBanner({ health, csrf }: { health?: BackupHealth | null; csrf?: string }) {
  if (!health) return null;
  if (health.configured === 0) {
    return (
      <div class="flash warn" id="backup-banner">
        <span>{t("Your backups have nowhere to go yet. Connect a storage and pano sends encrypted backups there.")}</span>
        <a class="btn primary small" href="/backups/connect?dest=a">
          {t("Connect storage")}
        </a>
      </div>
    );
  }
  const items: Child[] = [];
  if (health.lastFailure) {
    const f = health.lastFailure;
    items.push(
      <div class="flash err">
        <span>{fill("Backup {job} failed ({time}): {error}", { job: f.job, time: fmtTime(f.at), error: f.error.slice(0, 200) })}</span>{" "}
        <a href="/backups#tab-jobs">{t("See the runs")}</a>
      </div>,
    );
  }
  if (health.jobs === 0) {
    items.push(
      <div class="flash warn">
        <span>{t("Storage is ready, but nothing is backed up yet.")}</span>
        {csrf ? (
          <form method="post" action="/backups/defaults" class="row">
            <Csrf token={csrf} />
            <Otp />
            <button class="btn primary small">{t("Back up everything daily")}</button>
          </form>
        ) : (
          <a class="btn primary small" href="/backups">
            {t("Back up everything daily")}
          </a>
        )}
      </div>,
    );
  } else if (health.neverRan.length) {
    const names = health.neverRan.slice(0, 4).join(", ") + (health.neverRan.length > 4 ? ", …" : "");
    items.push(
      <div class="flash warn">
        <span>{fill(health.neverRan.length === 1 ? "Backup job {names} has not run yet." : "{n} backup jobs have not run yet: {names}", { names, n: health.neverRan.length })}</span>
        <a class="btn small" href="/backups#tab-jobs">
          {t("Open jobs")}
        </a>
      </div>,
    );
  }
  if (!health.keyExported) {
    items.push(
      <div class="flash warn">
        <span>{t("You have not saved the backup key. Without it, backups cannot be read on a new server.")}</span>
        <a class="btn small" href="/backups#tab-recovery">
          {t("Export backup key")}
        </a>
      </div>,
    );
  }
  return items.length ? <div class="backup-banner">{items}</div> : null;
}

/** Four numbers above the Backups page. */
export function BackupSummary({ health, dests }: { health?: BackupHealth | null; dests: { a: Dest; b: Dest } }) {
  if (!health) return null;
  const set = (dests.a.bucket ? 1 : 0) + (dests.b.bucket ? 1 : 0);
  const cards: { label: string; value: string; sub: string; tone?: string }[] = [
    { label: t("Storage"), value: `${set} / 2`, sub: set ? (health.allProtected ? t("all protected") : health.protected ? t("one protected") : t("not protected")) : t("not connected"), tone: set ? "" : "warn" },
    { label: t("Last backup"), value: health.lastSuccessAt ? fmtTime(health.lastSuccessAt) : t("Never"), sub: health.lastFailure ? t("a run failed") : `${health.jobs} ${t("jobs")}`, tone: health.lastFailure ? "down" : "" },
    { label: t("Backup key"), value: health.keyExported ? t("Saved") : t("Not saved"), sub: health.keyExportedAt ? fmtTime(health.keyExportedAt) : t("export it once"), tone: health.keyExported ? "" : "warn" },
  ];
  return (
    <section class="summary" aria-label={t("Summary")}>
      {cards.map((c) => (
        <div class={`summary-card ${c.tone ?? ""}`}>
          <span class="summary-label">{c.label}</span>
          <strong class="summary-value">{c.value}</strong>
          <small class="muted">{c.sub}</small>
        </div>
      ))}
    </section>
  );
}

// ---- the two destinations ------------------------------------------------------------------------

export function DestCards({ dests, csrf, providers }: { dests: { a: Dest; b: Dest }; csrf: string; providers?: ProviderSpec[] }) {
  return (
    <div class="cols dests">
      {(["a", "b"] as const).map((d) => {
        const x = dests[d];
        if (!x.bucket) {
          return (
            <Card title={destTitle(d)}>
              <div class="empty">
                <p>{d === "a" ? t("Nowhere to send backups yet. Pick a provider, paste a key, and pano does the rest.") : t("A second place on another provider: one account or region going away cannot take the backups with it.")}</p>
                <a class="btn primary" href={`/backups/connect?dest=${d}`}>
                  {t("Connect storage")}
                </a>
              </div>
            </Card>
          );
        }
        const endpoint = x.endpoint || (x.accountId ? `https://${x.accountId}.r2.cloudflarestorage.com` : "");
        return (
          <Card title={destTitle(d)} actions={<span class={`badge ${x.protect ? "good" : "neutral"}`}>{x.protect ? t("Protected") : t("Not protected")}</span>}>
            <p>
              <span class="provider-badge">{providerName(providers, x.provider)}</span>
            </p>
            <dl class="kv">
              <dt>{t("Bucket")}</dt>
              <dd>
                <code>{x.bucket}</code>
              </dd>
              <dt>{t("Endpoint")}</dt>
              <dd>{endpoint || "—"}</dd>
              <dt>{t("Folder")}</dt>
              <dd>{x.prefix || "pano"}</dd>
            </dl>
            <div class="row dest-actions">
              <a class="btn" href={`/backups/connect?dest=${d}`}>
                {t("Change")}
              </a>
              <form method="post" action="/backups/dest/test">
                <Csrf token={csrf} />
                <input type="hidden" name="dest" value={d} />
                <button class="btn">{t("Test connection")}</button>
              </form>
              {d === "b" ? (
                <form method="post" action="/backups/dest/clear" class="row">
                  <Csrf token={csrf} />
                  <input type="hidden" name="dest" value="b" />
                  <Otp />
                  <button class="btn danger">{t("Disconnect")}</button>
                </form>
              ) : null}
            </div>
          </Card>
        );
      })}
    </div>
  );
}

// ---- connect: step 1 (provider) and step 2 (the key) -----------------------------------------------

function SpecField({ f, cur, same }: { f: ProviderSpec["fields"][number]; cur: Dest; same: boolean }) {
  const stored: Record<string, string> = { accessKeyId: cur.accessKeyId, bucket: cur.bucket, prefix: cur.prefix, accountId: cur.accountId, endpoint: cur.endpoint, jurisdiction: cur.jurisdiction ?? "" };
  const value = same && f.name in stored ? stored[f.name]! : (f.default ?? "");
  const keepSecret = f.name === "secretAccessKey" && same && cur.hasSecret;
  return (
    <label class="field">
      <span>{t(f.label)}</span>
      {f.kind === "select" ? (
        <select name={f.name} required={f.required}>
          {(f.options ?? []).map((o) => (
            <option value={o.value} selected={o.value === value}>
              {t(o.label)}
            </option>
          ))}
        </select>
      ) : (
        <input
          name={f.name}
          type={f.kind === "password" ? "password" : "text"}
          value={f.kind === "password" ? "" : value}
          placeholder={keepSecret ? t("•••••• (stored; leave empty to keep it)") : t(f.placeholder)}
          required={f.required && !keepSecret}
          autocomplete={f.kind === "password" ? "new-password" : "off"}
          spellcheck={false}
        />
      )}
      {f.help ? <small class="muted">{t(f.help)}</small> : null}
    </label>
  );
}

export function ConnectPage(p: { csrf: string; dest: DestId; providers: ProviderSpec[]; provider?: ProviderSpec; current: Dest }) {
  const spec = p.provider;
  return (
    <div class="stack connect">
      <p class="muted">
        <strong>{destTitle(p.dest)}</strong> · {spec ? t("Step 2 of 2: your key") : t("Step 1 of 2: where should backups go?")}
      </p>
      {!spec ? (
        <section class="picker" aria-label={t("Providers")}>
          {p.providers.map((x) => (
            <a class="pick" href={`/backups/connect?dest=${p.dest}&provider=${x.id}`}>
              <strong>{x.name}</strong>
              <small class="muted">{t(x.tagline)}</small>
            </a>
          ))}
        </section>
      ) : (
        <ConnectForm csrf={p.csrf} dest={p.dest} spec={spec} current={p.current} />
      )}
      {!spec ? <p class="muted small">{t("Your data is encrypted on this server before it is sent; the provider only sees scrambled bytes.")}</p> : null}
    </div>
  );
}

function ConnectForm({ csrf, dest, spec, current }: { csrf: string; dest: DestId; spec: ProviderSpec; current: Dest }) {
  const same = !!current.bucket && current.provider === spec.id;
  const main = spec.fields.filter((f) => !f.advanced);
  const more = spec.fields.filter((f) => f.advanced);
  return (
    <>
      <Card
        title={fill("Get the key from {provider}", { provider: spec.name })}
        actions={
          <a href={`/backups/connect?dest=${dest}`} class="small">
            {t("Choose another provider")}
          </a>
        }
      >
        <p>{t(spec.keyHelp)}</p>
        <p class="muted small">
          {t("The key needs")}: {t(spec.permission)}
        </p>
        <div class="row">
          {spec.keyUrl ? (
            <a class="btn" href={spec.keyUrl} target="_blank" rel="noopener noreferrer">
              {fill("Open {provider} key page", { provider: spec.name })}
            </a>
          ) : null}
          {spec.docsUrl ? (
            <a href={spec.docsUrl} target="_blank" rel="noopener noreferrer">
              {fill("Read the {provider} guide", { provider: spec.name })}
            </a>
          ) : null}
        </div>
      </Card>
      <Card title={t("Paste the key")}>
        <form method="post" action="/backups/connect" class="grid-form">
          <Csrf token={csrf} />
          <input type="hidden" name="dest" value={dest} />
          <input type="hidden" name="provider" value={spec.id} />
          {main.map((f) => (
            <SpecField f={f} cur={current} same={same} />
          ))}
          {more.length ? (
            <details class="more">
              <summary>{t("More options")}</summary>
              <div class="grid-form">
                {more.map((f) => (
                  <SpecField f={f} cur={current} same={same} />
                ))}
              </div>
            </details>
          ) : null}
          <label class="check protect">
            <input type="checkbox" name="protect" value="1" checked={same ? current.protect : false} />
            <span>
              <strong>{t("Protected store (recommended)")}</strong>
              <br />
              {t("pano never deletes anything there. Old backups are removed by the provider's own lifecycle rule, so someone who takes over this server cannot erase them. Backups to a protected store are always full archives.")}
            </span>
          </label>
          <label class="field">
            <span>{t("Authenticator code")}</span>
            <Otp always />
          </label>
          <div class="actions">
            <button class="btn primary">{t("Connect and test")}</button>
            <a class="btn" href="/backups">
              {t("Cancel")}
            </a>
          </div>
        </form>
      </Card>
    </>
  );
}

// ---- result ----------------------------------------------------------------------------------------

export function ConnectResultPage(p: { csrf: string; dest: DestId; result: ConnectResult; providers: ProviderSpec[] }) {
  const r = p.result;
  const name = providerName(p.providers, r.provider);
  return (
    <div class="stack connect">
      {r.ok ? (
        <div class="flash ok">
          <p>
            <strong>{fill("{provider} is connected", { provider: name })}</strong>
          </p>
          <p>
            {t("Bucket")}: <code>{r.bucket}</code>
            {r.created ? ` (${t("pano created it")})` : ""} · {t("Folder")}: <code>{r.prefix}</code>
            {r.endpoint ? (
              <>
                {" "}
                · {t("Endpoint")}: {r.endpoint}
              </>
            ) : null}
          </p>
          {r.protect ? <p>{r.lifecycle ? fill("Protected: the provider removes backups older than {n} days.", { n: r.lifecycle.retentionDays }) : t("Protected: pano never deletes there.")}</p> : null}
          {r.notes.length ? (
            <ul>
              {r.notes.map((n) => (
                <li>{n}</li>
              ))}
            </ul>
          ) : null}
        </div>
      ) : (
        <div class="flash err">
          <strong>{t("Not connected. Nothing was saved.")}</strong> {t("Read the hint under the step that failed, then try again.")}
        </div>
      )}
      <Card title={t("What pano checked")}>
        <ol class="steps result">
          {r.steps.map((s) => (
            <li class={s.ok ? "done" : "fail"}>
              <span class="step-mark" aria-hidden="true">
                {s.ok ? "✓" : "✗"}
              </span>
              <div>
                <strong>{s.name}</strong> <span class="sr-only">{s.ok ? t("passed") : t("failed")}</span>
                {s.hint ? <div class="muted small">{s.hint}</div> : null}
              </div>
            </li>
          ))}
        </ol>
      </Card>
      {r.ok ? (
        <Card title={t("What next")}>
          <p class="muted small">{t("Two things make this useful: backups that run by themselves, and a copy of the key kept somewhere other than this server.")}</p>
          <div class="cols">
            <form method="post" action="/backups/defaults" class="stack-sm">
              <Csrf token={p.csrf} />
              <p class="small">{t("Adds a daily backup, kept 30 days, for the panel, every app, PHP site and database that has none yet.")}</p>
              <div class="row">
                <Otp />
                <button class="btn primary">{t("Back up everything daily")}</button>
              </div>
            </form>
            <form method="post" action="/backups/key" class="stack-sm">
              <Csrf token={p.csrf} />
              <p class="small">{t("Shows the recovery kit once. Keep it in a password manager, never on this server.")}</p>
              <div class="row">
                <Otp always />
                <button class="btn">{t("Export backup key")}</button>
              </div>
            </form>
          </div>
          <p>
            <a href="/backups">{t("Back to backups")}</a>
          </p>
        </Card>
      ) : (
        <p class="row">
          <a class="btn primary" href={`/backups/connect?dest=${p.dest}&provider=${r.provider}`}>
            {t("Try again")}
          </a>
          <a href="/backups">{t("Back to backups")}</a>
        </p>
      )}
    </div>
  );
}
