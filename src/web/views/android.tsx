import { MACHINES, buildCost } from "../../shared/android.ts";
import { fmtBytes, fmtDuration, fmtTime, t } from "../i18n.ts";
import { Badge, Card, Csrf, DangerForm, Field } from "./layout.tsx";

export type AndroidBuildRow = {
  id: number;
  project: string;
  status: string;
  trigger: string;
  commit_sha: string;
  machine: string;
  signed: number;
  artifacts: { name: string; size: number; sha256: string }[];
  error: string;
  started_at: number;
  finished_at: number | null;
};

export type AndroidProjectRow = {
  name: string;
  repo: string;
  branch: string;
  root_dir: string;
  gradle_dir: string;
  prepare_cmd: string;
  tasks: string;
  machine: string;
  jdk: number;
  timeout_min: number;
};

export type AndroidStatusView = {
  connected: boolean;
  image: { name: string; status: string; current: boolean; error: string; at: number };
  projects: (AndroidProjectRow & { signing: string; last: AndroidBuildRow | null })[];
};

export type AndroidDetailView = { project: AndroidProjectRow; signing: string; deployKey: string; builds: AndroidBuildRow[] };

const Otp = () => <input name="otp" inputmode="numeric" pattern="[0-9]{6}" placeholder="2FA" size={6} class="short" required />;

const cost = (b: AndroidBuildRow) => (b.finished_at ? `$${buildCost(b.machine, b.finished_at - b.started_at).toFixed(3)}` : "");

export function AndroidPage({ v, csrf, imageLog }: { v: AndroidStatusView; csrf: string; imageLog: boolean }) {
  return (
    <div class="stack">
      <Card title={t("Android builds")} actions={v.connected ? <Badge state="active" /> : <Badge state="off" />}>
        <p class="muted small">
          Optional. Gradle never runs on this server: each build gets a fresh{" "}
          <a href="https://boat.dev" target="_blank" rel="noreferrer">
            Boat
          </a>{" "}
          cloud machine (billed by the second to your Boat account), made without your account's secrets or snapshots and deleted when the build ends. The
          server fetches the commit as an unprivileged user without checking it out, so nothing from the repository runs here. The signing key stays root-only
          here and goes to the build machine only for that build.
        </p>
        {v.connected ? (
          <div class="cols">
            <div>
              <p class="small">
                <b>Saved image</b>:{" "}
                {v.image.status === "ready" ? (
                  <>
                    <code>{v.image.name}</code> <span class="muted">({fmtTime(v.image.at)}{v.image.current ? "" : ", outdated: prepare again"})</span>
                  </>
                ) : v.image.status === "building" ? (
                  "being prepared…"
                ) : (
                  <span class="muted">none: each build installs the JDK and Android SDK first (a few minutes longer)</span>
                )}
              </p>
              {v.image.status === "failed" ? <p class="small bad">Last attempt failed: {v.image.error}</p> : null}
              <form method="post" action="/android-image" class="row">
                <Csrf token={csrf} />
                <button class="btn" disabled={v.image.status === "building"}>
                  {v.image.status === "ready" ? "Prepare again" : "Prepare saved image"}
                </button>
                <small class="muted">About 10 minutes, once. Builds then start in seconds. Needs a paid Boat plan (the trial cannot save images).</small>
              </form>
            </div>
            <form method="post" action="/android/disconnect" class="row">
              <Csrf token={csrf} />
              <Otp />
              <button class="btn danger">Disconnect Boat</button>
              <small class="muted">Deletes the saved image on Boat and the key here.</small>
            </form>
          </div>
        ) : (
          <form method="post" action="/android/connect" class="grid-form">
            <Csrf token={csrf} />
            <label class="field wide">
              <span>Boat API key</span>
              <input name="key" type="password" autocomplete="off" placeholder="boat_…" required />
              <small class="muted">
                Create one at boat.dev with the scopes sandbox.create, sandbox.read, sandbox.delete-own, exec, file.read, file.write, snapshot.read and
                snapshot.write (the "ci" preset plus snapshot.write). Kept root-only on this server, never shown again.
              </small>
            </label>
            <div class="actions row">
              <Otp />
              <button class="btn primary">Connect</button>
            </div>
          </form>
        )}
        {imageLog ? <pre class="log small" data-deploy-log="/android-image/log"></pre> : null}
      </Card>

      {v.connected ? (
        <>
          <Card title={t("Projects")}>
            {v.projects.length ? (
              <table class="compact">
                <thead>
                  <tr>
                    <th>{t("Name")}</th>
                    <th>Repository</th>
                    <th>Gradle</th>
                    <th>Last build</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {v.projects.map((p) => (
                    <tr>
                      <td>
                        <a href={`/android/${p.name}`}>{p.name}</a>
                        {p.signing ? <span class="muted small"> · signed</span> : null}
                      </td>
                      <td class="small mono">
                        {p.repo} ({p.branch})
                      </td>
                      <td class="small mono">{p.tasks}</td>
                      <td>{p.last ? <Badge state={p.last.status} /> : <span class="muted">—</span>}</td>
                      <td>
                        <form method="post" action={`/android/${p.name}/build`} class="inline">
                          <Csrf token={csrf} />
                          <button class="btn small">{t("Build")}</button>
                        </form>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <p class="muted small">No projects yet.</p>
            )}
          </Card>
          <Card title="New project">
            <ProjectForm csrf={csrf} />
          </Card>
        </>
      ) : null}
    </div>
  );
}

export function ProjectForm({ csrf, p }: { csrf: string; p?: AndroidProjectRow }) {
  return (
    <form method="post" action="/android/projects" class="grid-form">
      <Csrf token={csrf} />
      {p ? <input type="hidden" name="name" value={p.name} /> : <Field label="Name" name="name" required placeholder="my-app" hint="3-24: a-z 0-9 -" />}
      <Field label="Repository" name="repo" value={p?.repo} required placeholder="git@github.com:you/app.git" hint="Private: add the project's deploy key to the repository." />
      <Field label="Branch" name="branch" value={p?.branch ?? "main"} />
      <Field label="Directory" name="root_dir" value={p?.root_dir} placeholder="(repository root)" hint="Where the prepare command runs, e.g. apps/mobile." />
      <Field label="Prepare command" name="prepare_cmd" value={p?.prepare_cmd} placeholder="bun install" hint="Optional, e.g. bun install for React Native; bun install && bunx expo prebuild -p android for Expo." />
      <Field label="Gradle directory" name="gradle_dir" value={p?.gradle_dir} placeholder="(auto: . or android)" hint="Where gradlew is, under the directory above." />
      <Field label="Gradle tasks" name="tasks" value={p?.tasks ?? "bundleRelease"} hint="bundleRelease (AAB for Google Play), assembleRelease (APK), assembleDebug…" />
      <label class="field">
        <span>Machine</span>
        <select name="machine">
          {Object.entries(MACHINES).map(([k, m]) => (
            <option value={k} selected={(p?.machine ?? "default") === k}>
              {m.label} · ${m.perHour}/h
            </option>
          ))}
        </select>
      </label>
      <label class="field">
        <span>JDK</span>
        <select name="jdk">
          {[17, 21].map((j) => (
            <option value={String(j)} selected={(p?.jdk ?? 17) === j}>
              {j}
            </option>
          ))}
        </select>
      </label>
      <Field label="Timeout (minutes)" name="timeout_min" type="number" value={p?.timeout_min ?? 60} />
      <div class="actions row">
        <Otp />
        <button class="btn primary">{t("Save")}</button>
      </div>
    </form>
  );
}

export function AndroidDetail({ d, csrf, buildId }: { d: AndroidDetailView; csrf: string; buildId?: number }) {
  const p = d.project;
  return (
    <div class="stack">
      <Card
        title={`Android · ${p.name}`}
        actions={
          <form method="post" action={`/android/${p.name}/build`} class="inline">
            <Csrf token={csrf} />
            <button class="btn primary">{t("Build")}</button>
          </form>
        }
      >
        <p class="small mono">
          {p.repo} ({p.branch}) · ./gradlew {p.tasks} · {p.machine} · JDK {p.jdk}
        </p>
        <p class="muted small">Deploy key (read-only, for a private repository):</p>
        <pre class="log small" data-copy>
          {d.deployKey}
        </pre>
      </Card>

      {buildId ? (
        <Card title={`Build #${buildId}`}>
          <pre class="log" data-deploy-log={`/android/${p.name}/builds/${buildId}/log`}></pre>
        </Card>
      ) : null}

      <Card title={t("Builds")}>
        {d.builds.length ? (
          <table class="compact">
            {d.builds.map((b) => (
              <tr>
                <td>
                  <a href={`/android/${p.name}?build=${b.id}`}>#{b.id}</a>
                </td>
                <td>
                  <Badge state={b.status} />
                </td>
                <td>
                  <code>{b.commit_sha.slice(0, 7)}</code>
                </td>
                <td class="muted small">
                  {fmtTime(b.started_at)}
                  {b.finished_at ? ` · ${fmtDuration(b.finished_at - b.started_at)} · ${cost(b)}` : ""}
                  {b.signed ? " · signed" : ""}
                </td>
                <td class="small">
                  {b.artifacts.map((a) => (
                    <div>
                      <a href={`/android/${p.name}/builds/${b.id}/${a.name}`} title={`sha256 ${a.sha256}`}>
                        {a.name}
                      </a>{" "}
                      <span class="muted">{fmtBytes(a.size)}</span>
                    </div>
                  ))}
                  {b.error ? <span class="muted">{b.error}</span> : null}
                </td>
              </tr>
            ))}
          </table>
        ) : (
          <p class="muted small">No builds yet.</p>
        )}
        <p class="muted small">The newest 3 builds keep their files. From the server: <code>pano rpc android.build '{`{"name":"${p.name}","trigger":"cli"}`}'</code></p>
      </Card>

      <Card title="Signing">
        <p class="muted small">
          {d.signing
            ? `Release builds are signed with the key "${d.signing}" (Android Gradle Plugin injected signing: build.gradle needs no signing config).`
            : "Not set: release builds come out unsigned unless build.gradle signs them itself. For Google Play, use the upload key."}{" "}
          The keystore and its passwords are kept root-only here and can never be shown again; on the build machine they are removed when the build ends and
          the machine itself is deleted.
        </p>
        <form method="post" action={`/android/${p.name}/signing`} enctype="multipart/form-data" class="grid-form">
          <Csrf token={csrf} />
          <label class="field">
            <span>Keystore (.jks, .keystore, .p12)</span>
            <input name="keystore" type="file" required />
          </label>
          <Field label="Key alias" name="alias" required placeholder="upload" />
          <label class="field">
            <span>Keystore password</span>
            <input name="storePassword" type="password" autocomplete="off" required />
          </label>
          <label class="field">
            <span>Key password</span>
            <input name="keyPassword" type="password" autocomplete="off" placeholder="(same as the keystore)" />
          </label>
          <div class="actions row">
            <Otp />
            <button class="btn primary">{d.signing ? "Replace key" : "Save key"}</button>
          </div>
        </form>
        {d.signing ? (
          <form method="post" action={`/android/${p.name}/signing/clear`} class="row">
            <Csrf token={csrf} />
            <Otp />
            <button class="btn danger small">Remove key</button>
          </form>
        ) : null}
      </Card>

      <Card title={t("Settings")}>
        <ProjectForm csrf={csrf} p={p} />
      </Card>

      <details>
        <summary class="muted small">{t("Delete")}</summary>
        <DangerForm action={`/android/${p.name}/delete`} csrf={csrf} name={p.name} label="Delete the project, its builds and its signing key" />
      </details>
    </div>
  );
}
