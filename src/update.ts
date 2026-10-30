// Updating pano itself without risking what runs on it. The new binary has to
// run before it is installed, the old one and a consistent copy of the state
// database are kept, and the panel restarts; if the agent or the UI does not
// answer within a minute, the old binary and state come back by themselves.
// Apps, PHP sites and the edge are their own services and keep serving
// throughout. The state only ever gains columns, so an older binary still runs
// on a newer database (a manual rollback keeps today's state).

import { Database } from "bun:sqlite";
import { chmod, copyFile, rename, rm } from "node:fs/promises";
import { VERSION, fsPath, paths } from "./shared/config.ts";

const BIN = fsPath(`${paths.bin}/pano`);
const PREV = `${BIN}.prev`;
const STAGED = `${BIN}.new`;
const STATE_PREV = fsPath(`${paths.data}/state.db.prev`);

const sh = (argv: string[]) => Bun.spawnSync(argv, { stdout: "pipe", stderr: "pipe" });
const exists = (p: string) => Bun.file(p).exists();

/** -1, 0 or 1 comparing the leading x.y.z of two versions. */
function cmpVersion(a: string, b: string): number {
  const pa = a.split(/[.-]/).slice(0, 3).map(Number);
  const pb = b.split(/[.-]/).slice(0, 3).map(Number);
  for (let i = 0; i < 3; i++) if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) < (pb[i] ?? 0) ? -1 : 1;
  return 0;
}

export async function update(src: string, sha: string, allowDowngrade = false) {
  if (process.getuid?.() !== 0) throw new Error("run as root");
  if (!/^[a-f0-9]{64}$/i.test(sha)) throw new Error("the sha256 of the new binary is required (from the release page)");
  const bytes = await Bun.file(src).bytes();
  if (new Bun.CryptoHasher("sha256").update(bytes).digest("hex") !== sha.toLowerCase()) throw new Error("checksum does not match");
  await Bun.write(STAGED, bytes);
  await chmod(STAGED, 0o755);
  let next = "";
  let why = "";
  try {
    // Not as root: nothing of the new binary runs privileged before it is installed.
    const probe = sh(["runuser", "-u", "nobody", "--", STAGED, "version"]);
    next = probe.exitCode === 0 ? probe.stdout.toString().trim() : "";
    why = probe.stderr.toString().trim().split("\n").at(-1) ?? "";
  } catch (e) {
    why = (e as Error).message;
  }
  if (!/^\d+\.\d+\.\d+/.test(next)) {
    await rm(STAGED, { force: true });
    throw new Error(`the new binary does not run here${why ? `: ${why}` : ""}`);
  }
  if (!allowDowngrade && cmpVersion(next, VERSION) < 0) {
    await rm(STAGED, { force: true });
    throw new Error(`${next} is older than the running ${VERSION} (older releases may carry fixed holes); --allow-downgrade to go ahead`);
  }
  console.log(`pano ${VERSION} → ${next}`);

  await copyFile(BIN, `${PREV}.tmp`);
  await chmod(`${PREV}.tmp`, 0o755);
  await rename(`${PREV}.tmp`, PREV);
  await rm(STATE_PREV, { force: true });
  const db = new Database(fsPath(paths.stateDb), { readonly: true });
  // The copy holds 2FA and webhook secrets: created root-only, not readable for a moment before a chmod.
  const umask = process.umask(0o077);
  try {
    db.exec(`VACUUM INTO '${STATE_PREV}'`);
  } finally {
    process.umask(umask);
    db.close();
  }
  await chmod(STATE_PREV, 0o600);
  // rename, not copy: the running binary stays valid until the restart
  await rename(STAGED, BIN);
  sh(["systemctl", "reset-failed", "pano-agent", "pano-web"]);
  sh(["systemctl", "restart", "pano-agent", "pano-web"]);
  if (await healthy()) {
    console.log(`updated to ${next}; the previous version is kept (pano update-rollback)`);
    return;
  }
  console.error("the new version did not come up; going back");
  await rollbackUpdate(true);
  throw new Error("update rolled back");
}

/** Back to the binary before the last update. Automatic rollbacks also put back the state from just before it. */
export async function rollbackUpdate(withState = false) {
  if (process.getuid?.() !== 0) throw new Error("run as root");
  if (!(await exists(PREV))) throw new Error("no previous version is kept");
  sh(["systemctl", "stop", "pano-web", "pano-agent"]);
  await copyFile(PREV, `${BIN}.tmp`);
  await chmod(`${BIN}.tmp`, 0o755);
  await rename(`${BIN}.tmp`, BIN);
  if (withState && (await exists(STATE_PREV))) {
    const stamp = Date.now();
    for (const f of ["", "-wal", "-shm"]) {
      const cur = fsPath(paths.stateDb) + f;
      if (!(await exists(cur))) continue;
      await rename(cur, `${fsPath(paths.stateDb)}.failed-${stamp}${f}`);
      await chmod(`${fsPath(paths.stateDb)}.failed-${stamp}${f}`, 0o600);
    }
    await copyFile(STATE_PREV, fsPath(paths.stateDb));
    await chmod(fsPath(paths.stateDb), 0o640);
  }
  // a release that crashed on start leaves systemd's start limit hit
  sh(["systemctl", "reset-failed", "pano-agent", "pano-web"]);
  sh(["systemctl", "start", "pano-agent", "pano-web"]);
  console.log((await healthy()) ? "previous version running" : "previous version started but does not answer (journalctl -u pano-agent -n 50)");
}

/** The agent answers on its socket and the UI on its port, within a minute. */
async function healthy(): Promise<boolean> {
  const { call } = await import("./web/agent.ts");
  const conf = (await Bun.file(fsPath(`${paths.etc}/pano.env`)).text().catch(() => "")) as string;
  const host = conf.match(/^PANO_WEB_HOST=(\S+)/m)?.[1] ?? "127.0.0.1";
  const port = conf.match(/^PANO_WEB_PORT=(\d+)/m)?.[1] ?? "7800";
  for (let i = 0; i < 60; i++) {
    await Bun.sleep(1000);
    const agent = await call("system.info", {}, "cli").then(() => true, () => false);
    const web = agent && (await fetch(`http://${host}:${port}/login`, { signal: AbortSignal.timeout(2000) }).then((r) => r.status < 500, () => false));
    if (agent && web) return true;
  }
  return false;
}
