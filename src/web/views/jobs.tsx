import { fmtBytes, fmtTime, t } from "../i18n.ts";
import { Badge, Card, Csrf } from "./layout.tsx";

export type JobRow = {
  owner: "app" | "site";
  name: string;
  index: number;
  schedule: string;
  command: string;
  armed: boolean;
  running: boolean;
  next: number | null;
  last: number | null;
  result: string;
  seconds: number | null;
};
export type JobsView = { jobs: JobRow[]; crontabs: { user: string; lines: string[] }[] };
export type QueueRow = {
  kind: "bullmq" | "laravel";
  key: string;
  name: string;
  waiting: number;
  active: number;
  delayed: number;
  failed: number | null;
  completed: number | null;
  paused: boolean;
};
export type QueuesView = {
  enabled: boolean;
  store: { installed: boolean; managed: boolean; version: string; active: string };
  workers: { app: string; process: string; unit: string; active: string; memory: number }[];
  queues: QueueRow[];
  error: string;
};

const refKey = (j: Pick<JobRow, "owner" | "name" | "index">) => `${j.owner}:${j.name}:${j.index}`;

export function JobResult({ j }: { j: Pick<JobRow, "running" | "last" | "result" | "seconds"> }) {
  if (j.running) return <Badge state="running" />;
  if (!j.last) return <span class="muted">—</span>;
  return (
    <>
      {fmtTime(j.last)} <Badge state={j.result === "success" ? "ok" : "failed"} />
      {j.result && j.result !== "success" ? <span class="muted small"> {j.result}</span> : null}
      {j.seconds !== null ? <span class="muted small"> {j.seconds}s</span> : null}
    </>
  );
}

function RunNow({ j, csrf }: { j: JobRow; csrf: string }) {
  return (
    <form method="post" action="/jobs/run" class="inline">
      <Csrf token={csrf} />
      <input type="hidden" name="owner" value={j.owner} />
      <input type="hidden" name="name" value={j.name} />
      <input type="hidden" name="index" value={String(j.index)} />
      <button class="btn small" disabled={j.running || !j.armed}>
        {t("Run now")}
      </button>
    </form>
  );
}

export function JobsPage(p: { csrf: string; jobs: JobsView; queues: QueuesView; log?: { ref: string; text: string } }) {
  const q = p.queues;
  return (
    <div class="stack">
      <Card title={t("Scheduled jobs")}>
        <p class="muted small">
          Set on each app (settings) or PHP site page as <code>schedule | command</code>. They run as systemd timers: nothing waits in memory between runs, a job
          never runs twice at once, a run missed while the server was off happens at boot, and jobs get a fifth of the CPU and disk the sites get when the server
          is busy.
        </p>
        {p.jobs.jobs.length ? (
          <table>
            <thead>
              <tr>
                <th>{t("Owner")}</th>
                <th>{t("Schedule")}</th>
                <th>{t("Command")}</th>
                <th>{t("Last run")}</th>
                <th>{t("Next run")}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {p.jobs.jobs.map((j) => (
                <tr>
                  <td>
                    <a href={j.owner === "app" ? `/apps/${j.name}` : `/sites/${j.name}`}>{j.name}</a>
                    <div class="muted small">
                      {j.owner} #{j.index}
                    </div>
                  </td>
                  <td>
                    <code>{j.schedule}</code>
                  </td>
                  <td class="small">
                    <code>{j.command}</code>
                  </td>
                  <td class="small">
                    <JobResult j={j} />
                  </td>
                  <td class="small muted">{j.armed ? fmtTime(j.next) : t("not armed (deploy the app / enable the site)")}</td>
                  <td class="row">
                    <RunNow j={j} csrf={p.csrf} />
                    <a class="btn small" href={`/jobs?log=${encodeURIComponent(refKey(j))}`}>
                      {t("Logs")}
                    </a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p class="muted">{t("No scheduled jobs yet.")}</p>
        )}
        {p.log ? (
          <>
            <h3 class="small">{p.log.ref}</h3>
            <pre class="log small">{p.log.text || "—"}</pre>
          </>
        ) : null}
      </Card>

      {p.jobs.crontabs.length ? (
        <Card title={t("Crontabs from before pano")}>
          <p class="muted small">
            Still run by the system cron, read-only here (values that look like passwords are hidden). Move each one to its app or site, then remove it from the
            crontab.
          </p>
          {p.jobs.crontabs.map((c) => (
            <>
              <h3 class="small">{c.user}</h3>
              <pre class="log small">{c.lines.join("\n")}</pre>
            </>
          ))}
        </Card>
      ) : null}

      <Card title={t("Queues")} actions={q.enabled ? <Badge state={q.error ? "error" : "ok"} /> : undefined}>
        {q.enabled ? (
          <>
            <p class="muted small">
              {q.store.managed ? "Valkey installed by pano" : "Redis/Valkey that was already on the server"} {q.store.version} · read once a minute; new failures and
              queues that stop moving are sent to Telegram.
            </p>
            {q.error ? <p class="flash err">{q.error}</p> : null}
            {q.queues.length ? (
              <table>
                <thead>
                  <tr>
                    <th>{t("Queue")}</th>
                    <th class="num">{t("Waiting")}</th>
                    <th class="num">{t("Active")}</th>
                    <th class="num">{t("Delayed")}</th>
                    <th class="num">{t("Failed")}</th>
                    <th class="num">{t("Completed")}</th>
                  </tr>
                </thead>
                <tbody>
                  {q.queues.map((x) => (
                    <tr>
                      <td>
                        <b>{x.name}</b> {x.paused ? <Badge state="paused" /> : null}
                        <div class="muted small">
                          {x.kind === "bullmq" ? "BullMQ" : "Laravel"} · <code>{x.key}</code>
                        </div>
                      </td>
                      <td class="num">{x.waiting}</td>
                      <td class="num">{x.active}</td>
                      <td class="num">{x.delayed}</td>
                      <td class="num">{x.failed ?? "—"}</td>
                      <td class="num">{x.completed ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : q.error ? null : (
              <p class="muted small">No BullMQ or Laravel queues in the store yet. They show up after an app adds its first job.</p>
            )}
          </>
        ) : (
          <p class="muted small">
            Off: nothing is installed or checked. Turning it on uses the Redis/Valkey already on the server, or installs Valkey (about 10 MB of memory when idle). Apps
            then use <code>REDIS_URL</code> (app page → + Database → Valkey) with BullMQ, Laravel queues or any Redis queue library.
          </p>
        )}
        <form method="post" action="/jobs/queues" class="inline">
          <Csrf token={p.csrf} />
          <input type="hidden" name="on" value={q.enabled ? "0" : "1"} />
          <button class={`btn${q.enabled ? "" : " primary"}`}>{q.enabled ? t("Turn off") : q.store.installed ? t("Turn on") : t("Install and turn on")}</button>
        </form>
      </Card>

      <Card title={t("Workers")}>
        <p class="muted small">
          App processes without a domain (the <code>-</code> routes column in an app's processes), for example <code>worker | . | - | 256 | bun worker.ts</code>.
          They restart when they crash, stop before a new release starts, and get half the CPU and disk share of web processes when the server is busy.
        </p>
        {q.workers.length ? (
          <table>
            <thead>
              <tr>
                <th>{t("App")}</th>
                <th>{t("Process")}</th>
                <th>{t("Status")}</th>
                <th class="num">{t("Memory")}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {q.workers.map((w) => (
                <tr>
                  <td>
                    <a href={`/apps/${w.app}`}>{w.app}</a>
                  </td>
                  <td>
                    <code>{w.process}</code>
                  </td>
                  <td>
                    <Badge state={w.active} />
                  </td>
                  <td class="num">{fmtBytes(w.memory)}</td>
                  <td>
                    <form method="post" action="/jobs/workers/restart" class="inline">
                      <Csrf token={p.csrf} />
                      <input type="hidden" name="app" value={w.app} />
                      <input type="hidden" name="process" value={w.process} />
                      <button class="btn small">{t("Restart")}</button>
                    </form>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p class="muted small">No workers yet.</p>
        )}
      </Card>
    </div>
  );
}
