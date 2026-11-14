import { fmtBytes, fmtDuration, fmtTime, t } from "../i18n.ts";
import { Badge, Card, Csrf, DangerForm, Field, alwaysAttr } from "./layout.tsx";

export type AndroidBuildRow = {
  id: number;
  project: string;
  status: string;
  trigger: string;
  commit_sha: string;
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
  sdk_packages: string;
  jdk: number;
  memory_mb: number;
  timeout_min: number;
};

export type ToolchainView = { supported: boolean; installed: boolean; state: string; error: string; jdks: number[]; buildTools: string[] };

export type AndroidStatusView = {
  toolchain: ToolchainView;
  projects: (AndroidProjectRow & { signing: string; last: AndroidBuildRow | null })[];
};

export type AndroidDetailView = { project: AndroidProjectRow; signing: string; deployKey: string; builds: AndroidBuildRow[]; cacheBytes: number };

const Otp = (p: { always?: boolean }) => <input name="otp" inputmode="numeric" pattern="[0-9]{6}" placeholder="2FA" size={6} class="short" required {...alwaysAttr(p.always)} />;

export function AndroidPage({ v, csrf, toolchainLog }: { v: AndroidStatusView; csrf: string; toolchainLog: boolean }) {
  const tc = v.toolchain;
  return (
    <div class="stack">
      <Card title={t("Android builds")} actions={<Badge state={tc.installed ? "active" : tc.state || "off"} />}>
        <p class="muted small">
          Optional. Every build runs in a sandbox made for it on this server and removed when it ends: a user that exists only while it runs, an empty
          directory of its own, nothing of pano, the apps or other builds in sight, a memory cap and low CPU priority. Afterwards the source and the user are
          gone; the APK/AAB is kept, and so is the project's download cache (only its own next builds see it, so they do not download everything again).
          Signing happens in a second throwaway sandbox without network, so the project's code never sees the key.
        </p>
        {!tc.supported ? (
          <p class="small">Android's build tools only run on x86-64 servers; this one is not.</p>
        ) : tc.installed ? (
          <div class="row">
            <span class="small">
              JDK {tc.jdks.join(", ")} · build-tools {tc.buildTools.join(", ") || "—"} · <code>/opt/pano/android</code>
            </span>
            <form method="post" action="/android-toolchain/remove" class="inline">
              <Csrf token={csrf} />
              <button class="btn small" title="Frees the disk; installing again takes a few minutes">
                Remove toolchain
              </button>
            </form>
          </div>
        ) : (
          <form method="post" action="/android-toolchain" class="row">
            <Csrf token={csrf} />
            <button class="btn primary" disabled={tc.state === "installing"}>
              {tc.state === "installing" ? "Installing…" : "Install Android toolchain"}
            </button>
            <small class="muted">
              Eclipse Temurin JDK 17 and the Android SDK (checksums verified), about 2 GB under /opt/pano/android, a few minutes. Installing accepts the
              Android SDK licence. Builds need a few GB of memory: 8 GB or more on the server is best.
            </small>
          </form>
        )}
        {tc.state === "failed" ? <p class="small">Last install failed: {tc.error}</p> : null}
        {toolchainLog || tc.state === "installing" ? <pre class="log small" data-deploy-log="/android-toolchain/log"></pre> : null}
      </Card>

      {tc.installed ? (
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
      <Field label="Prepare command" name="prepare_cmd" value={p?.prepare_cmd} placeholder="bun install" hint="Optional, e.g. bun install for React Native; bun install && bunx expo prebuild -p android for Expo. Runs in the sandbox." />
      <Field label="Gradle directory" name="gradle_dir" value={p?.gradle_dir} placeholder="(auto: . or android)" hint="Where gradlew is, under the directory above." />
      <Field label="Gradle tasks" name="tasks" value={p?.tasks ?? "bundleRelease"} hint="bundleRelease (AAB for Google Play), assembleRelease (APK), assembleDebug…" />
      <Field label="SDK packages" name="sdk_packages" value={p?.sdk_packages} placeholder="ndk;27.1.12297006" hint="Beyond platforms 35/36: the SDK is read-only in the sandbox. A build that misses one names it." />
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
      <Field label="Memory (MB)" name="memory_mb" type="number" value={p?.memory_mb ?? 6144} hint="Cap for the build sandbox." />
      <Field label="Timeout (minutes)" name="timeout_min" type="number" value={p?.timeout_min ?? 60} />
      <div class="actions row">
        <Otp always />
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
          {p.repo} ({p.branch}) · ./gradlew {p.tasks} · JDK {p.jdk} · {p.memory_mb} MB
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
                  {b.finished_at ? ` · ${fmtDuration(b.finished_at - b.started_at)}` : ""}
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
        <p class="muted small">
          One build at a time; the newest 3 keep their files. From the server: <code>pano rpc android.build '{`{"name":"${p.name}","trigger":"cli"}`}'</code>
        </p>
        <form method="post" action={`/android/${p.name}/cache/clear`} class="row">
          <Csrf token={csrf} />
          <span class="muted small">
            Download cache (Gradle, npm, bun) kept for this project's next builds: {fmtBytes(d.cacheBytes)}. Only its own builds see it.
          </span>
          <button class="btn small" disabled={!d.cacheBytes} title="The next build downloads everything again">
            Clear cache
          </button>
        </form>
      </Card>

      <Card title="Signing">
        <p class="muted small">
          {d.signing
            ? `APK/AAB are signed with the key "${d.signing}" after the build (apksigner / jarsigner), replacing whatever key the build used.`
            : "Not set: the files come out as the build made them (unsigned, or with the key build.gradle uses). For Google Play, use the upload key."}{" "}
          The keystore and its passwords are kept root-only and can never be shown again. Only the signing sandbox (no network, removed afterwards) gets
          them, as systemd credentials.
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
