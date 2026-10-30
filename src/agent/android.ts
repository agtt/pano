// Android builds (optional): off until a Boat (boat.dev) API key is added on the
// Android page. This server never runs Gradle or the project's own scripts. It
// fetches the commit as an unprivileged user (bare fetch + git archive: no
// checkout, no hooks, no submodules), sends the source to a fresh Boat machine,
// builds there and brings the APK/AAB back. Each machine is made without the
// account's secrets and without snapshots, and is deleted after its build, so
// neither the source nor the signing key outlives the build on Boat.

import { appendFile, chmod, chown, stat } from "node:fs/promises";
import { ARTIFACT_NAME, MACHINES, artifactFile, type Machine } from "../shared/android.ts";
import { DRY_RUN, fsPath, paths } from "../shared/config.ts";
import { ValidationError, v } from "../shared/validate.ts";
import { notify } from "./alerts.ts";
import * as boat from "./boat.ts";
import { ensureUser } from "./edge.ts";
import { androidBuilds, androidProjects, audit, settings, type AndroidArtifact, type AndroidProject } from "./state.ts";
import { ensureDir, exists, lookupUser, randomToken, readText, remove, run, writeAtomic } from "./sys.ts";

export const BUILD_USER = "pano-android";
const ROOT = `${paths.data}/android`;
const WORK = `${ROOT}/work`;
const logFile = (id: number | "image") => `${ROOT}/logs/${id}.log`;
const keyDir = (name: string) => `${ROOT}/keys/${name}`;
const signingFile = (name: string) => `${paths.secrets}/android/${name}.json`;

/** Build history kept per project; only the newest few keep their files (an AAB is 50-150 MB). */
const KEEP_BUILDS = 20;
const KEEP_FILES = 3;
const MAX_PARALLEL = 2;
const MAX_SOURCE = 1024 ** 3;
const MAX_ARTIFACT = 2 * 1024 ** 3;
const MAX_LOG = 20 * 1024 ** 2;

// On the Boat machine (Ubuntu, user "user" with sudo).
const HOME = "/home/user";
const SDK = `${HOME}/android-sdk`;
/** Bump when the toolchain below changes: machines and saved images without its marker install it again. */
export const TOOLCHAIN = "pano-toolchain-1";
const CMDLINE_TOOLS = {
  url: "https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip",
  sha256: "2d2d50857e4eb553af5a6dc3ad507a17adf43d115264b1afc116f95c92e5e258",
};

// ---- projects ------------------------------------------------------------------

export type ProjectInput = Omit<AndroidProject, "created_at">;

const TASK = /^:?[A-Za-z][A-Za-z0-9:_.-]{0,99}$/;

export function validateProject(x: Record<string, unknown>): ProjectInput {
  const repo = v.gitUrl(x.repo);
  if (repo.startsWith("file:")) throw new ValidationError("repository: a remote git URL (https://… or git@…)");
  const tasks = String(x.tasks ?? "").trim().split(/\s+/).filter(Boolean);
  if (!tasks.length) tasks.push("assembleRelease");
  if (tasks.length > 8 || !tasks.every((t) => TASK.test(t))) throw new ValidationError("Gradle tasks: up to 8 task names such as bundleRelease or :app:assembleRelease");
  const machine = String(x.machine ?? "default");
  if (!Object.hasOwn(MACHINES, machine)) throw new ValidationError("machine: small, default, large or xlarge");
  const jdk = Number(x.jdk ?? 17);
  if (jdk !== 17 && jdk !== 21) throw new ValidationError("JDK: 17 or 21");
  return {
    name: v.appName(x.name),
    repo,
    branch: v.branch(String(x.branch ?? "").trim() || "main"),
    root_dir: v.subdir(x.root_dir),
    gradle_dir: v.subdir(x.gradle_dir),
    prepare_cmd: v.command(x.prepare_cmd, "prepare command"),
    tasks: tasks.join(" "),
    machine,
    jdk,
    timeout_min: v.int(x.timeout_min ?? 60, 5, 180, "timeout (minutes)"),
  };
}

function mustGet(name: string): AndroidProject {
  const p = androidProjects.get(name);
  if (!p) throw new Error("no such Android project");
  return p;
}

export async function saveProject(x: Record<string, unknown>, actor: string) {
  const p = validateProject(x);
  androidProjects.upsert(p);
  await deployKey(p.name);
  audit(actor, "android.project.save", p);
  return p;
}

export async function removeProject(name: string, actor: string) {
  mustGet(name);
  if (androidBuilds.running().some((b) => b.project === name)) throw new Error("a build is running for this project");
  for (const id of androidBuilds.older(name, 0)) await dropBuild(id);
  await remove(keyDir(name));
  await remove(signingFile(name));
  androidProjects.remove(name);
  audit(actor, "android.project.remove", { name });
}

/** Read-only deploy key for a private repository (add it to the repository, not to an account). */
export async function deployKey(name: string): Promise<string> {
  mustGet(name);
  await ensureLayout();
  const dir = keyDir(name);
  await ensureDir(dir, 0o700, BUILD_USER);
  if (!(await exists(`${dir}/id_ed25519`))) {
    await run(["ssh-keygen", "-t", "ed25519", "-N", "", "-C", `pano-android-${name}`, "-f", fsPath(`${dir}/id_ed25519`)], { user: BUILD_USER });
  }
  return ((await readText(`${dir}/id_ed25519.pub`)) ?? "").trim();
}

// ---- signing ---------------------------------------------------------------------

type Signing = { keystore: string; alias: string; storePassword: string; keyPassword: string };

async function readSigning(name: string): Promise<Signing | null> {
  const text = await readText(signingFile(name));
  if (!text) return null;
  try {
    return JSON.parse(text) as Signing;
  } catch {
    return null;
  }
}

const secretText = (s: unknown, field: string) => {
  const x = String(s ?? "");
  if (x.length < 6 || x.length > 128 || /[\0-\x1f\x7f]/.test(x)) throw new ValidationError(`${field}: 6-128 characters, one line`);
  return x;
};

/** The upload/release keystore, root-only here; it goes to a build machine only for that build. Write-only from the UI. */
export async function setSigning(name: string, x: Record<string, unknown>, actor: string) {
  mustGet(name);
  const ks = Buffer.from(String(x.keystore ?? ""), "base64");
  if (ks.length < 32 || ks.length > 64 * 1024) throw new ValidationError("keystore: a .jks, .keystore or .p12 file (up to 64 KB)");
  // JKS starts with FEEDFEED; PKCS12 (the keytool default) is a DER sequence.
  if (ks.readUInt32BE(0) !== 0xfeedfeed && ks[0] !== 0x30) throw new ValidationError("keystore: not a Java keystore or PKCS12 file");
  const alias = String(x.alias ?? "").trim();
  if (!/^[A-Za-z0-9._ -]{1,64}$/.test(alias)) throw new ValidationError("key alias: letters, digits, space, . _ - (max 64)");
  const storePassword = secretText(x.storePassword, "keystore password");
  const keyPassword = x.keyPassword ? secretText(x.keyPassword, "key password") : storePassword;
  await ensureDir(`${paths.secrets}/android`, 0o700);
  await writeAtomic(signingFile(name), JSON.stringify({ keystore: ks.toString("base64"), alias, storePassword, keyPassword } satisfies Signing), 0o600);
  audit(actor, "android.signing.set", { name, alias });
}

export async function clearSigning(name: string, actor: string) {
  mustGet(name);
  await remove(signingFile(name));
  audit(actor, "android.signing.clear", { name });
}

/** A value in a Java .properties file: backslashes, a leading space and anything outside ASCII escaped. */
export function propValue(s: string): string {
  return s
    .replace(/\\/g, "\\\\")
    .replace(/^\s/, (m) => `\\${m}`)
    .replace(/[^\x20-\x7e]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
}

/** Android Gradle Plugin's injected signing (what Android Studio uses): no change to build.gradle needed. */
export function signingProperties(s: Signing, storeFile: string): string {
  return [
    `android.injected.signing.store.file=${propValue(storeFile)}`,
    `android.injected.signing.store.password=${propValue(s.storePassword)}`,
    `android.injected.signing.key.alias=${propValue(s.alias)}`,
    `android.injected.signing.key.password=${propValue(s.keyPassword)}`,
    "",
  ].join("\n");
}

// ---- scripts run on the Boat machine -----------------------------------------------

const q = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;

/** JDK 17 and 21 and the Android SDK; skipped when the machine (or the saved image it came from) has them. */
export function toolchainScript(): string {
  return `if [ ! -f "$SDK/.${TOOLCHAIN}" ]; then
  echo "==> install JDK 17/21 and the Android SDK (saved image: Android page)"
  sudo apt-get update -q >/dev/null
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q openjdk-17-jdk-headless openjdk-21-jdk-headless unzip >/dev/null
  curl -fsSL -o /tmp/clt.zip ${CMDLINE_TOOLS.url}
  echo "${CMDLINE_TOOLS.sha256}  /tmp/clt.zip" | sha256sum -c -
  rm -rf "$SDK/cmdline-tools" /tmp/clt && mkdir -p "$SDK/cmdline-tools" && unzip -q /tmp/clt.zip -d /tmp/clt
  mv /tmp/clt/cmdline-tools "$SDK/cmdline-tools/latest" && rm -rf /tmp/clt /tmp/clt.zip
  set +o pipefail
  yes | "$SDK/cmdline-tools/latest/bin/sdkmanager" --sdk_root="$SDK" --licenses >/dev/null
  set -o pipefail
  "$SDK/cmdline-tools/latest/bin/sdkmanager" --sdk_root="$SDK" "platform-tools" "platforms;android-35" "build-tools;35.0.0" >/dev/null
  touch "$SDK/.${TOOLCHAIN}"
fi`;
}

export function buildScript(p: AndroidProject, id: number): string {
  const gradle = p.gradle_dir
    ? `cd ${q(p.gradle_dir)}`
    : `if [ ! -f gradlew ] && [ -f android/gradlew ]; then cd android; fi`;
  return `#!/bin/bash
# Written by pano for Android build ${id} (${p.name}).
set -euo pipefail
SDK=${SDK}
# The signing key never stays behind, whatever happens to the build.
trap 'rm -f ${HOME}/pano/release.keystore ${HOME}/.gradle/gradle.properties' EXIT
${toolchainScript()}
export ANDROID_HOME="$SDK" ANDROID_SDK_ROOT="$SDK" CI=1
export JAVA_HOME="/usr/lib/jvm/java-${p.jdk}-openjdk-$(dpkg --print-architecture)"
export PATH="$JAVA_HOME/bin:$SDK/platform-tools:$PATH"
echo "==> unpack the source"
mkdir -p ${HOME}/src
tar -xzf ${HOME}/pano/source.tar.gz -C ${HOME}/src
rm -f ${HOME}/pano/source.tar.gz
cd ${HOME}/src/${q(p.root_dir || ".")}
${p.prepare_cmd ? `echo ${q(`==> ${p.prepare_cmd}`)}\n${p.prepare_cmd}\n` : ""}${gradle}
[ -f gradlew ] || { echo "FAILED: no gradlew in $(pwd) (set the Gradle directory)"; exit 1; }
chmod +x gradlew
echo ${q(`==> ./gradlew ${p.tasks}`)}
./gradlew --no-daemon --console=plain ${p.tasks}
find ${HOME}/src -path '*/build/outputs/*' -type f \\( -name '*.apk' -o -name '*.aab' \\) -printf '%s\\t%p\\n' > ${HOME}/pano/artifacts.txt
`;
}

// ---- builds ----------------------------------------------------------------------

let active = 0;
const waiting: (() => void)[] = [];

/** At most MAX_PARALLEL machines at once (the Boat trial allows two). */
async function slot<T>(fn: () => Promise<T>): Promise<T> {
  while (active >= MAX_PARALLEL) await new Promise<void>((r) => waiting.push(r));
  active++;
  try {
    return await fn();
  } finally {
    active--;
    waiting.shift()?.();
  }
}

/** Starts a build in the background and returns its id. */
export async function startBuild(name: string, trigger: string, actor: string): Promise<number> {
  const p = mustGet(name);
  if (!(await boat.boatKey())) throw new Error("connect Boat first (Android page)");
  if (androidBuilds.running().some((b) => b.project === name)) throw new Error("a build is already running for this project");
  const id = androidBuilds.start(name, trigger, p.machine, !!(await readSigning(name)));
  audit(actor, "android.build", { project: name, id, trigger });
  void slot(() => runBuild(id, p)).catch((e) => console.error(`[agent] android build ${id}: ${e}`));
  return id;
}

/** Appends to a log in order, with the given secrets blanked and a size cap. */
function logWriter(file: string, hide: string[] = []) {
  let size = 0;
  let chain = Promise.resolve();
  return (text: string) => {
    if (size > MAX_LOG) return;
    let t = text;
    for (const s of hide) if (s) t = t.split(s).join("••••••••");
    size += t.length;
    if (size > MAX_LOG) t += "\n[log cut at 20 MB]\n";
    chain = chain.then(() => appendFile(fsPath(file), t)).catch(() => {});
  };
}

async function runBuild(id: number, p: AndroidProject) {
  const signing = await readSigning(p.name);
  const log = logWriter(logFile(id), signing ? [signing.storePassword, signing.keyPassword] : []);
  const step = (s: string) => log(`\n==> ${s}\n`);
  const started = Date.now();
  let sandbox = "";
  try {
    await ensureLayout();
    step(`fetch ${p.repo} (${p.branch})`);
    const { sha, tar } = await fetchSource(p, id, (line) => log(`${line}\n`));
    androidBuilds.setCommit(id, sha);
    log(`commit ${sha}\n`);

    const image = imageReady();
    step(`start a ${p.machine} Boat machine${image ? ` from the saved image ${image}` : " (no saved image: the SDK is installed first)"}`);
    // Its own deadline as a backstop: Boat stops it (and, without snapshots, erases it) even if pano never comes back.
    const sb = await boat.createSandbox({ machine: p.machine as Machine, from: image ?? undefined, ttlSeconds: (p.timeout_min + 30) * 60, name: `pano-android-${id}` });
    sandbox = sb.id;
    androidBuilds.setSandbox(id, sandbox);
    log(`machine ${sandbox}\n`);
    await boat.waitReady(sandbox);
    await boat.exec(sandbox, `mkdir -p ${HOME}/pano ${HOME}/.gradle`);

    step("upload the source");
    await boat.upload(sandbox, `${HOME}/pano/source.tar.gz`, Bun.file(fsPath(tar)));
    await remove(tar);
    if (signing) {
      step(`signing with key "${signing.alias}"`);
      await boat.writeFile(sandbox, `${HOME}/pano/release.keystore`, Buffer.from(signing.keystore, "base64"));
      await boat.writeFile(sandbox, `${HOME}/.gradle/gradle.properties`, signingProperties(signing, `${HOME}/pano/release.keystore`));
    }
    await boat.writeFile(sandbox, `${HOME}/pano/build.sh`, buildScript(p, id));
    const code = await boat.runDetached(sandbox, `bash ${HOME}/pano/build.sh 2>&1`, log, started + p.timeout_min * 60_000);
    if (code !== 0) throw new Error(`the build exited with ${code}`);

    step("download the APK/AAB");
    const artifacts = await collect(id, sandbox, log);
    if (!artifacts.length) throw new Error("the build made no APK or AAB (check the Gradle tasks)");
    androidBuilds.finish(id, { status: "success", artifacts });
    log(`\nbuild ${id} done in ${Math.round((Date.now() - started) / 1000)} s\n`);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    log(`\nFAILED: ${msg}\n`);
    androidBuilds.finish(id, { status: "failed", error: msg.slice(0, 500) });
    await notify(`🔴 Android build ${p.name} #${id} failed: ${msg}`);
  } finally {
    if (sandbox && (await boat.deleteSandbox(sandbox))) androidBuilds.setSandbox(id, "");
    await remove(`${WORK}/${id}.git`);
    await remove(`${WORK}/${id}.tar.gz`);
    await prune(p.name);
  }
}

/** The branch's newest commit as a tar.gz, fetched as the unprivileged build user (nothing from the repository runs here). */
async function fetchSource(p: AndroidProject, id: number, onLine: (l: string) => void): Promise<{ sha: string; tar: string }> {
  await deployKey(p.name);
  const keys = fsPath(keyDir(p.name));
  const bare = fsPath(`${WORK}/${id}.git`);
  const tar = `${WORK}/${id}.tar.gz`;
  const env = {
    HOME: keys,
    GIT_SSH_COMMAND: `ssh -i ${keys}/id_ed25519 -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=${keys}/known_hosts`,
    GIT_TERMINAL_PROMPT: "0",
    GIT_CONFIG_NOSYSTEM: "1",
  };
  const git = (args: string[]) => run(["git", ...args], { user: BUILD_USER, env, onLine, timeoutMs: 10 * 60_000 });
  await git(["init", "--bare", "-q", bare]);
  await git(["-C", bare, "fetch", "--depth", "1", "--no-tags", "--", p.repo, `refs/heads/${p.branch}`]);
  const sha = (await run(["git", "-C", bare, "rev-parse", "FETCH_HEAD"], { user: BUILD_USER, env, check: false })).stdout.trim();
  await git(["-C", bare, "archive", "--format=tar.gz", "-o", fsPath(tar), "FETCH_HEAD"]);
  await remove(`${WORK}/${id}.git`);
  if (!DRY_RUN && (await stat(fsPath(tar))).size > MAX_SOURCE) throw new Error("the source is over 1 GB");
  return { sha, tar };
}

/** Lines "<size>\t<path>" written by the build script. */
export function parseArtifacts(text: string): { path: string; name: string; size: number }[] {
  const out: { path: string; name: string; size: number }[] = [];
  const used = new Set<string>();
  for (const line of text.split("\n")) {
    const [size, path] = line.split("\t");
    if (!path || !path.startsWith(`${HOME}/src/`) || path.includes("..")) continue;
    let name = path.split("/").pop()!;
    if (!ARTIFACT_NAME.test(name) || Number(size) > MAX_ARTIFACT) continue;
    // app-release.apk from two modules: the second becomes 2-app-release.apk
    for (let n = 2; used.has(name); n++) name = `${n}-${path.split("/").pop()}`;
    used.add(name);
    out.push({ path, name, size: Number(size) });
    if (out.length === 20) break;
  }
  return out;
}

async function collect(id: number, sandbox: string, log: (s: string) => void): Promise<AndroidArtifact[]> {
  const list = parseArtifacts((await boat.exec(sandbox, `cat ${HOME}/pano/artifacts.txt`)).stdout);
  const dir = `${ROOT}/artifacts/${id}`;
  await ensureDir(dir, 0o750);
  await panoGroup(dir);
  const out: AndroidArtifact[] = [];
  for (const a of list) {
    const dest = fsPath(artifactFile(id, a.name));
    const res = await boat.download(sandbox, a.path);
    if (Number(res.headers.get("content-length") ?? 0) > MAX_ARTIFACT) throw new Error(`${a.name} is over 2 GB`);
    await Bun.write(dest, res);
    await chmod(dest, 0o640);
    await panoGroup(artifactFile(id, a.name));
    const hash = new Bun.CryptoHasher("sha256");
    for await (const chunk of Bun.file(dest).stream()) hash.update(chunk);
    const item = { name: a.name, size: Bun.file(dest).size, sha256: hash.digest("hex") };
    log(`${item.name}  ${item.size} bytes  sha256 ${item.sha256}\n`);
    out.push(item);
  }
  return out;
}

async function dropBuild(id: number) {
  await remove(`${ROOT}/artifacts/${id}`);
  await remove(logFile(id));
  androidBuilds.remove([id]);
}

async function prune(project: string) {
  for (const id of androidBuilds.older(project, KEEP_BUILDS)) await dropBuild(id);
  for (const id of androidBuilds.older(project, KEEP_FILES)) {
    if (!androidBuilds.get(id)?.artifacts.length) continue;
    await remove(`${ROOT}/artifacts/${id}`);
    androidBuilds.dropArtifacts(id);
  }
}

export async function readLog(id: number | "image", offset = 0): Promise<{ text: string; offset: number }> {
  const file = Bun.file(fsPath(logFile(id)));
  if (!(await file.exists())) return { text: "", offset };
  const size = file.size;
  if (offset >= size) return { text: "", offset: size };
  return { text: await file.slice(offset, size).text(), offset: size };
}

// ---- layout ------------------------------------------------------------------------

/** root 0711 (traverse only); artifacts root:pano for the web; work and keys only for the build user; logs root-only. */
async function ensureLayout() {
  await ensureUser(BUILD_USER, WORK);
  await ensureDir(ROOT, 0o711);
  await ensureDir(`${ROOT}/logs`, 0o700);
  await ensureDir(`${ROOT}/artifacts`, 0o750);
  await panoGroup(`${ROOT}/artifacts`);
  await ensureDir(WORK, 0o700, BUILD_USER);
  await ensureDir(`${ROOT}/keys`, 0o700, BUILD_USER);
}

async function panoGroup(abs: string) {
  if (DRY_RUN || process.getuid?.() !== 0) return;
  const pano = await lookupUser("pano");
  if (pano) await chown(fsPath(abs), 0, pano.gid);
}

// ---- Boat connection and the saved image ----------------------------------------

export async function connect(key: unknown, actor: string) {
  const k = String(key ?? "").trim();
  if (!/^(boat|box)_[A-Za-z0-9_-]{16,256}$/.test(k)) throw new ValidationError("paste a Boat API key (boat_…)");
  await boat.limits(k);
  await ensureDir(paths.secrets, 0o700);
  await writeAtomic(boat.KEY_FILE, `${k}\n`, 0o600);
  audit(actor, "android.connect", {});
}

/** Removes the key; the saved image goes first (it is billed while it exists). */
export async function disconnect(actor: string) {
  if (androidBuilds.running().length || settings.get("android.image.status") === "building") throw new Error("wait for the running builds to finish");
  const image = settings.get("android.image");
  if (image) await boat.deleteSnapshot(image);
  for (const k of ["android.image", "android.image.status", "android.image.error", "android.image.at", "android.image.toolchain"]) settings.set(k, "");
  await writeAtomic(boat.KEY_FILE, "", 0o600);
  audit(actor, "android.disconnect", {});
}

/** The saved image builds start from, when it has the current toolchain. */
function imageReady(): string | null {
  const name = settings.get("android.image");
  return name && settings.get("android.image.status") === "ready" && settings.get("android.image.toolchain") === TOOLCHAIN ? name : null;
}

/**
 * One machine installs the toolchain and is saved under a name of this server's own; builds then
 * start from it in seconds instead of installing the SDK each time. Needs a paid Boat plan
 * (the trial cannot save images) and a key that may save snapshots.
 */
export async function prepareImage(actor: string) {
  if (!(await boat.boatKey())) throw new Error("connect Boat first");
  if (settings.get("android.image.status") === "building") throw new Error("the image is being prepared");
  await ensureLayout();
  await remove(logFile("image"));
  settings.set("android.image.status", "building");
  settings.set("android.image.error", "");
  audit(actor, "android.image.prepare", {});
  const log = logWriter(logFile("image"));
  void (async () => {
    let sandbox = "";
    try {
      log("==> start a Boat machine\n");
      sandbox = (await boat.createSandbox({ machine: "default", ttlSeconds: 2 * 3600, name: "pano-android-image", snapshots: true })).id;
      settings.set("android.image.sandbox", sandbox);
      await boat.waitReady(sandbox);
      await boat.writeFile(sandbox, `${HOME}/pano-toolchain.sh`, `#!/bin/bash\nset -euo pipefail\nSDK=${SDK}\n${toolchainScript()}\nrm -f ${HOME}/pano-toolchain.sh\n`);
      const code = await boat.runDetached(sandbox, `bash ${HOME}/pano-toolchain.sh 2>&1`, log, Date.now() + 40 * 60_000);
      if (code !== 0) throw new Error(`the toolchain install exited with ${code}`);
      const name = settings.get("android.image") || `pano-android-${randomToken(6).toLowerCase().replace(/[^a-z0-9]/g, "x")}`;
      log(`==> save as ${name} (a few minutes)\n`);
      await boat.saveSnapshot(sandbox, name);
      settings.set("android.image", name);
      settings.set("android.image.toolchain", TOOLCHAIN);
      settings.set("android.image.at", String(Math.floor(Date.now() / 1000)));
      settings.set("android.image.status", "ready");
      log("\nimage ready\n");
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      settings.set("android.image.status", "failed");
      settings.set("android.image.error", msg.slice(0, 300));
      log(`\nFAILED: ${msg}\n`);
    } finally {
      if (sandbox && (await boat.deleteSandbox(sandbox))) settings.set("android.image.sandbox", "");
    }
  })();
}

/** At agent start: builds cut off by a restart fail, and every machine pano still holds is deleted. */
export async function cleanupAndroid() {
  androidBuilds.failStale();
  if (settings.get("android.image.status") === "building") {
    settings.set("android.image.status", "failed");
    settings.set("android.image.error", "agent restarted");
  }
  if (!(await boat.boatKey())) return;
  for (const b of androidBuilds.withSandbox()) if (await boat.deleteSandbox(b.sandbox)) androidBuilds.setSandbox(b.id, "");
  const img = settings.get("android.image.sandbox");
  if (img && (await boat.deleteSandbox(img))) settings.set("android.image.sandbox", "");
}

// ---- views ----------------------------------------------------------------------------

export async function androidStatus() {
  const projects = await Promise.all(
    androidProjects.list().map(async (p) => ({ ...p, signing: (await readSigning(p.name))?.alias ?? "", last: androidBuilds.list(p.name, 1)[0] ?? null })),
  );
  return {
    connected: !!(await boat.boatKey()),
    image: {
      name: settings.get("android.image") ?? "",
      status: settings.get("android.image.status") ?? "",
      current: settings.get("android.image.toolchain") === TOOLCHAIN,
      error: settings.get("android.image.error") ?? "",
      at: Number(settings.get("android.image.at") ?? 0),
    },
    projects,
  };
}

export async function projectDetail(name: string) {
  const p = mustGet(name);
  return { project: p, signing: (await readSigning(name))?.alias ?? "", deployKey: await deployKey(name), builds: androidBuilds.list(name, KEEP_BUILDS) };
}
