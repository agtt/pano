import { fmtTime, t } from "../i18n.ts";
import { Badge, Card, Csrf, Field } from "./layout.tsx";

type Finding = {
  where: string;
  ecosystem: string;
  name: string;
  version: string;
  id: string;
  aliases: string[];
  severity: string;
  summary: string;
  fixed: string;
  autofix: boolean;
  exploited?: boolean;
  epss?: number;
};
export type VulnView = {
  patch: { os: boolean; php: boolean; edge: boolean };
  osAutomatic: boolean;
  rebootNeeded: boolean;
  scanning: boolean;
  last: { at: number; findings: Finding[]; errors: string[]; packages: number } | null;
};

const link = (f: Finding) => {
  const id = f.aliases[0] ?? f.id;
  if (id.startsWith("CVE-")) return `https://nvd.nist.gov/vuln/detail/${id}`;
  if (/^(GHSA|GO|RUSTSEC|PYSEC)-/.test(id)) return `https://osv.dev/vulnerability/${id}`;
  return "";
};

export function VulnsCard({ v, csrf }: { v: VulnView; csrf: string }) {
  const findings = v.last?.findings ?? [];
  const counts = (["critical", "high", "medium", "low"] as const).map((s) => [s, findings.filter((f) => f.severity === s).length] as const);
  return (
    <Card
      title={t("Vulnerabilities and updates")}
      actions={<Badge state={findings.some((f) => f.severity === "critical" || f.severity === "high") ? "fail" : findings.length ? "warn" : "ok"} />}
    >
      <p class="muted small">
        Checked every night (and on request) against the distribution's security advisories, OSV.dev (npm, Composer, Go, Rust), nodejs.org, php.net and
        wordpress.org. New high and critical findings go to Telegram. {v.last ? `Last check ${fmtTime(v.last.at)}, ${v.last.packages} packages.` : "Not checked yet."}
        {v.scanning ? " Checking…" : ""}
      </p>
      {v.rebootNeeded ? <p class="flash err">An installed security update needs a reboot (kernel or a core library). Restart the server when traffic is low.</p> : null}
      <form method="post" action="/security/vulns/patch">
        <Csrf token={csrf} />
        <label class="check">
          <input type="checkbox" name="os" value="1" checked={v.patch.os} /> Install OS security updates daily (dnf-automatic
          {v.osAutomatic ? ", running" : ""}); a needed reboot is reported, never done on its own
        </label>
        <label class="check">
          <input type="checkbox" name="php" value="1" checked={v.patch.php} /> Install PHP patch releases nightly (same minor, sites move to them without
          downtime)
        </label>
        <label class="check">
          <input type="checkbox" name="edge" value="1" checked={v.patch.edge} /> Update the edge (Caddy) at night: patch releases, or the newest 2.x when the
          running one has a known vulnerability; rolled back if it does not start
        </label>
        <Field label="Authenticator code" name="otp" autocomplete="one-time-code" required />
        <button class="btn">{t("Save")}</button>
      </form>
      <div class="row">
        <form method="post" action="/security/vulns/scan">
          <Csrf token={csrf} />
          <button class="btn" disabled={v.scanning}>
            Check now
          </button>
        </form>
        <form method="post" action="/security/vulns/now">
          <Csrf token={csrf} />
          <button class="btn" disabled={v.scanning}>
            Patch and check now
          </button>
        </form>
      </div>
      {v.last?.errors.length ? <p class="small muted">Could not check: {v.last.errors.join(" · ")}</p> : null}
      {findings.length ? (
        <>
          <p class="small">{counts.filter(([, n]) => n).map(([s, n]) => `${n} ${s}`).join(" · ")}</p>
          <table>
            <thead>
              <tr>
                <th>{t("Severity")}</th>
                <th>Where</th>
                <th>Package</th>
                <th>Fixed in</th>
                <th>Advisory</th>
              </tr>
            </thead>
            <tbody>
              {findings.slice(0, 200).map((f) => (
                <tr>
                  <td>
                    <Badge state={f.severity === "critical" || f.severity === "high" ? "fail" : f.severity} />
                    <div class="muted small">{f.severity}</div>
                    {f.exploited ? <div class="small"><strong>exploited in the wild</strong></div> : (f.epss ?? 0) >= 0.1 ? <div class="small"><strong>EPSS {Math.round((f.epss ?? 0) * 100)}%</strong></div> : null}
                  </td>
                  <td class="small">{f.where}</td>
                  <td class="small">
                    <code>{f.name}</code> {f.version}
                  </td>
                  <td class="small">
                    {f.fixed || "—"}
                    <div class="muted small">{f.autofix ? "pano updates this" : "update it in the app / site"}</div>
                  </td>
                  <td class="small">
                    {link(f) ? <a href={link(f)} rel="noreferrer" target="_blank">{f.aliases[0] ?? f.id}</a> : f.id}
                    <div class="muted small">{f.summary}</div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {findings.length > 200 ? <p class="muted small">…and {findings.length - 200} more.</p> : null}
        </>
      ) : v.last ? (
        <p class="flash ok">No known vulnerabilities.</p>
      ) : null}
    </Card>
  );
}
