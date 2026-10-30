import { fmtBytes, fmtTime, t } from "../i18n.ts";
import { Badge, Card, Csrf, Field } from "./layout.tsx";

export type RunnerView = {
  enabled: boolean;
  config: { memory_mb: number; timeout_min: number; parallel: number };
  keys: { type: string; comment: string; fingerprint: string; added: number }[];
  workspaces: { name: string; bytes: number; modified: number; running: boolean }[];
  cacheBytes: number;
  recent: { ws: string; cmd: string; started: number; seconds: number; code: number }[];
  running: string[];
  host: string;
  androidToolchain: boolean;
};

const Otp = () => <input name="otp" inputmode="numeric" pattern="[0-9]{6}" placeholder="2FA" size={6} class="short" required />;

export function RunnerPage({ v, csrf }: { v: RunnerView; csrf: string }) {
  return (
    <div class="stack">
      <Card title={t("Runner")} actions={<Badge state={v.enabled ? "active" : "off"} />}>
        <p class="muted small">
          Optional. Heavy commands from your own machine (or a coding agent on it) run here instead: <code>pano-remote</code> syncs the project over SSH
          (rsync, only what changed), runs the command and streams the output back. Build outputs, node_modules and the download cache stay here, so the next
          run is incremental. Each run is a sandbox as the <code>pano-run</code> user: memory cap, time limit, low CPU priority, nothing of pano, the apps or
          other users in sight, of the runner only its workspace and the cache. A key added here can run any command in that sandbox: add only your own.
        </p>
        <div class="row">
          {v.enabled ? (
            <form method="post" action="/runner/disable" class="inline">
              <Csrf token={csrf} />
              <button class="btn small" title="Removes SSH access and stops what runs; workspaces stay until cleaned">
                Turn off
              </button>
            </form>
          ) : (
            <form method="post" action="/runner/enable" class="row">
              <Csrf token={csrf} />
              <Otp />
              <button class="btn primary">Turn on</button>
              <small class="muted">Creates the pano-run user (SSH only with the keys below, only into the runner), installs rsync if missing.</small>
            </form>
          )}
        </div>
        {v.enabled && !v.androidToolchain ? (
          <p class="small">
            For Gradle builds install the Android toolchain on the <a href="/android">Android</a> page (JDK and SDK; runs find them by themselves).
          </p>
        ) : null}
      </Card>

      {v.enabled ? (
        <>
          <Card title="Use">
            <pre class="log small" data-copy>
              {`# once, on your machine (needs rsync and ssh)
curl -fsSL https://raw.githubusercontent.com/agtt/pano/main/tools/pano-remote -o ~/.local/bin/pano-remote && chmod +x ~/.local/bin/pano-remote
pano-remote init pano-run@${v.host}

# in a project: sync, run, bring the APKs back
pano-remote -p android/app/build/outputs -- 'bun install && cd android && ./gradlew assembleDebug'
pano-remote -- bun test
pano-remote ls`}
            </pre>
          </Card>

          <Card title="SSH keys">
            {v.keys.length ? (
              <table class="compact">
                {v.keys.map((k) => (
                  <tr>
                    <td class="small mono">{k.fingerprint}</td>
                    <td class="small">{k.comment || k.type}</td>
                    <td class="muted small">{fmtTime(k.added)}</td>
                    <td>
                      <form method="post" action="/runner/keys/remove" class="inline">
                        <Csrf token={csrf} />
                        <input type="hidden" name="fingerprint" value={k.fingerprint} />
                        <button class="btn danger small">{t("Remove")}</button>
                      </form>
                    </td>
                  </tr>
                ))}
              </table>
            ) : (
              <p class="muted small">No key yet: nobody can use the runner.</p>
            )}
            <form method="post" action="/runner/keys" class="grid-form">
              <Csrf token={csrf} />
              <label class="field">
                <span>Public key (cat ~/.ssh/id_ed25519.pub)</span>
                <input name="key" required placeholder="ssh-ed25519 AAAA… me@laptop" />
              </label>
              <div class="actions row">
                <Otp />
                <button class="btn primary">Add key</button>
              </div>
            </form>
          </Card>

          <Card title="Workspaces">
            {v.workspaces.length ? (
              <table class="compact">
                {v.workspaces.map((w) => (
                  <tr>
                    <td class="mono small">
                      {w.name}
                      {w.running ? <span class="muted"> · running</span> : null}
                    </td>
                    <td class="small">{fmtBytes(w.bytes)}</td>
                    <td class="muted small">{fmtTime(w.modified)}</td>
                    <td>
                      <form method="post" action="/runner/workspaces/clean" class="inline">
                        <Csrf token={csrf} />
                        <input type="hidden" name="ws" value={w.name} />
                        <button class="btn small" disabled={w.running} title="Deletes the synced copy and its build outputs; the next run syncs everything again">
                          Clean
                        </button>
                      </form>
                    </td>
                  </tr>
                ))}
              </table>
            ) : (
              <p class="muted small">None yet: the first pano-remote run creates one per project.</p>
            )}
            <form method="post" action="/runner/cache/clear" class="row">
              <Csrf token={csrf} />
              <span class="muted small">Shared download cache (Gradle, npm, bun): {fmtBytes(v.cacheBytes)}</span>
              <button class="btn small" disabled={!v.cacheBytes || v.running.length > 0} title="The next runs download everything again">
                Clear cache
              </button>
            </form>
          </Card>

          <Card title="Recent runs">
            {v.recent.length ? (
              <table class="compact">
                {v.recent.map((r) => (
                  <tr>
                    <td>
                      <Badge state={r.code === 0 ? "success" : "failed"} />
                    </td>
                    <td class="mono small">{r.ws}</td>
                    <td class="mono small">{r.cmd}</td>
                    <td class="muted small">
                      {fmtTime(r.started)} · {r.seconds} s
                    </td>
                  </tr>
                ))}
              </table>
            ) : (
              <p class="muted small">No runs yet.</p>
            )}
          </Card>

          <Card title={t("Settings")}>
            <form method="post" action="/runner/config" class="grid-form">
              <Csrf token={csrf} />
              <Field label="Memory per run (MB)" name="memory_mb" type="number" value={v.config.memory_mb} hint="Gradle wants 4-8 GB." />
              <Field label="Time limit (minutes)" name="timeout_min" type="number" value={v.config.timeout_min} />
              <Field label="Runs at the same time" name="parallel" type="number" value={v.config.parallel} hint="Others wait for a slot." />
              <div class="actions">
                <button class="btn primary">{t("Save")}</button>
              </div>
            </form>
          </Card>
        </>
      ) : null}
    </div>
  );
}
