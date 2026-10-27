import { fmtTime, t } from "../i18n.ts";
import { Badge, Card, Csrf, Field } from "./layout.tsx";

export type ShieldView = {
  settings: { scan: boolean; autoQuarantine: boolean; reputation: boolean; bruteforce: boolean };
  scan: { running: boolean; last: { at: number; full: boolean; files: number; found: number; ms: number } | null };
  deepScan: { at: number; found: number } | null;
  clamav: boolean;
  reputation: { at: number; v4: number; v6: number; c2: number } | null;
  bans: { ip: string; until: number; reason: string }[];
  findings: { id: number; path: string; rule: string; severity: string; snippet: string; status: string; found_at: number }[];
  roots: string[];
};

const ago = (ms: number) => fmtTime(Math.floor(ms / 1000));

export function ShieldPage({ csrf, s }: { csrf: string; s: ShieldView }) {
  const open = s.findings.filter((f) => f.status === "open");
  return (
    <div class="stack">
      <Card title={t("Shield")} actions={<Badge state={open.some((f) => f.severity === "malware") ? "fail" : open.length ? "warn" : "ok"} />}>
        <form method="post" action="/shield/settings">
          <Csrf token={csrf} />
          <label class="check">
            <input type="checkbox" name="scan" value="1" checked={s.settings.scan} /> Malware scan of sites and app uploads: changed files every hour, everything weekly
          </label>
          <label class="check">
            <input type="checkbox" name="autoQuarantine" value="1" checked={s.settings.autoQuarantine} /> Quarantine files marked malware automatically (reversible)
          </label>
          <label class="check">
            <input type="checkbox" name="reputation" value="1" checked={s.settings.reputation} /> Block known hostile networks (Spamhaus DROP) both ways and botnet
            controllers (abuse.ch Feodo) outbound, refreshed daily
          </label>
          <label class="check">
            <input type="checkbox" name="bruteforce" value="1" checked={s.settings.bruteforce} /> WordPress login brute force: over 20 login/xmlrpc posts in 10
            minutes blocks the address for an hour (also behind Cloudflare)
          </label>
          <Field label="Authenticator code" name="otp" autocomplete="one-time-code" required />
          <button class="btn primary">{t("Save")}</button>
        </form>
        <p class="muted small">
          Scanned: {s.roots.length ? s.roots.join(", ") : "no sites yet"}.
          {s.scan.last ? ` Last ${s.scan.last.full ? "full" : "quick"} scan ${ago(s.scan.last.at)}: ${s.scan.last.files} files, ${s.scan.last.found} found, ${Math.round(s.scan.last.ms / 100) / 10}s.` : ""}
          {s.scan.running ? " A scan is running…" : ""}
          {s.reputation ? ` Lists: ${s.reputation.v4 + s.reputation.v6} networks, ${s.reputation.c2} botnet controllers (${ago(s.reputation.at)}).` : ""}
        </p>
        <div class="row">
          {(["quick", "full"] as const).map((k) => (
            <form method="post" action="/shield/scan">
              <Csrf token={csrf} />
              <input type="hidden" name="full" value={k === "full" ? "1" : "0"} />
              <button class="btn" disabled={s.scan.running}>
                {k === "full" ? "Full scan now" : "Scan changed files"}
              </button>
            </form>
          ))}
          <form method="post" action="/shield/deep">
            <Csrf token={csrf} />
            <button class="btn" disabled={s.scan.running} title="ClamAV, installed on first use; no daemon, about 1 GB of memory while it runs">
              Deep scan (ClamAV{s.clamav ? "" : ", installs"})
            </button>
          </form>
        </div>
        {s.deepScan ? <p class="muted small">Last ClamAV scan {ago(s.deepScan.at)}: {s.deepScan.found} infected.</p> : null}
      </Card>

      <Card title={`Findings (${open.length} open)`}>
        {s.findings.length ? (
          <table>
            <thead>
              <tr>
                <th>File</th>
                <th>Rule</th>
                <th>{t("Status")}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {s.findings.map((f) => (
                <tr class={f.status === "open" ? "" : "muted"}>
                  <td class="small">
                    <code>{f.path}</code>
                    {f.snippet ? <div class="muted mono small">{f.snippet.slice(0, 160)}</div> : null}
                  </td>
                  <td class="small">
                    <Badge state={f.severity === "malware" ? "fail" : "warn"} /> {f.rule}
                  </td>
                  <td class="small">{f.status}</td>
                  <td>
                    <form method="post" action="/shield/finding" class="row">
                      <Csrf token={csrf} />
                      <input type="hidden" name="id" value={String(f.id)} />
                      {f.status === "open" ? (
                        <button class="btn small danger" name="action" value="quarantine">
                          Quarantine
                        </button>
                      ) : null}
                      {f.status === "open" || f.status === "quarantined" ? (
                        <>
                          <input name="otp" inputmode="numeric" pattern="[0-9]{6}" placeholder="2FA" size={6} class="short" />
                          {f.status === "quarantined" ? (
                            <button class="btn small" name="action" value="restore">
                              Restore
                            </button>
                          ) : (
                            <button class="btn small" name="action" value="ignore">
                              Ignore
                            </button>
                          )}
                        </>
                      ) : null}
                    </form>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p class="muted">Nothing found.</p>
        )}
      </Card>

      {s.bans.length ? (
        <Card title="Blocked addresses">
          <table>
            <tbody>
              {s.bans.map((b) => (
                <tr>
                  <td>
                    <code>{b.ip}</code>
                  </td>
                  <td class="small muted">
                    {b.reason}, until {fmtTime(b.until)}
                  </td>
                  <td>
                    <form method="post" action="/shield/unban" class="row">
                      <Csrf token={csrf} />
                      <input type="hidden" name="ip" value={b.ip} />
                      <input name="otp" inputmode="numeric" pattern="[0-9]{6}" placeholder="2FA" size={6} class="short" required />
                      <button class="btn small">Unblock</button>
                    </form>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      ) : null}
    </div>
  );
}
