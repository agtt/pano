// Android builds (optional): nothing is installed until the toolchain is asked
// for on the Android page. Every build runs in a sandbox made for it and
// removed after it: a transient systemd unit with a user that exists only
// while it runs (DynamicUser), its own empty directory, no access to other
// users' files, a memory cap and low CPU priority. When it ends the user, the
// directory and the source are gone; the APK/AAB is kept, and so is the
// project's download cache (Gradle, npm, bun), which only that project's next
// build sees (without it every build downloads hundreds of MB again). Signing
// happens afterwards in a second throwaway sandbox without network, so the
// project's code (and its dependencies) never see the key.

import { appendFile, chown, readdir } from "node:fs/promises";
import { ARTIFACT_NAME, artifactFile, toolchainDir } from "../shared/android.ts";
import { DRY_RUN, fsPath, paths } from "../shared/config.ts";
import { ValidationError, v } from "../shared/validate.ts";
import { notify } from "./alerts.ts";
import { ensureUser } from "./edge.ts";
import { installed as installedRuntimes, runtimeBin } from "./runtimes.ts";
import { androidBuilds, androidProjects, audit, settings, type AndroidArtifact, type AndroidProject } from "./state.ts";
import { dirBytes, ensureDir, exists, lookupUser, readText, remove, run, writeAtomic } from "./sys.ts";
import { cacheName, cachePath, copyResult, plainDirectory, removeCache, removeSandbox, runSandbox, sandboxDir } from "./throwaway.ts";

/** Fetches sources with the projects' deploy keys; never runs anything from a repository. */
export const FETCH_USER = "pano-android";
const ROOT = `${paths.data}/android`;
const WORK = `${ROOT}/work`;
const logFile = (id: number | "toolchain") => `${ROOT}/logs/${id}.log`;
const keyDir = (name: string) => `${ROOT}/keys/${name}`;
/** keystore, alias, storepass, keypass: root-only files, handed to the signing sandbox as systemd credentials. */
const signingDir = (name: string) => `${paths.secrets}/android/${name}`;

export const SDK = `${toolchainDir}/sdk`;
export const jdkDir = (n: number) => `${toolchainDir}/jdk-${n}`;
const sdkmanager = `${SDK}/cmdline-tools/latest/bin/sdkmanager`;
const CMDLINE_TOOLS = {
  url: "https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip",
  sha256: "2d2d50857e4eb553af5a6dc3ad507a17adf43d115264b1afc116f95c92e5e258",
};
const DEFAULT_PACKAGES = ["platform-tools", "platforms;android-36", "build-tools;36.0.0", "platforms;android-35", "build-tools;35.0.0"];

/** Build history kept per project; only the newest few keep their files (an AAB is 50-150 MB). */
const KEEP_BUILDS = 20;
const KEEP_FILES = 3;
const MAX_SOURCE = 1024 ** 3;
const MAX_ARTIFACT = 1024 ** 3;
const MAX_LOG = 20 * 1024 ** 2;

/** The two throwaway sandboxes of a build (throwaway.ts). */
const unit = (kind: "build" | "sign", id: number) => `pano-android-${kind}-${id}`;

// ---- projects ------------------------------------------------------------------

export type ProjectInput = Omit<AndroidProject, "created_at">;

const TASK = /^:?[A-Za-z][A-Za-z0-9:_.-]{0,99}$/;
const SDK_PACKAGE = /^[a-z][a-z0-9-]*(;[A-Za-z0-9._-]+){0,2}$/;

export function validateProject(x: Record<string, unknown>): ProjectInput {
  const repo = v.gitUrl(x.repo);
  if (repo.startsWith("file:")) throw new ValidationError("repository: a remote git URL (https://… or git@…)");
  const tasks = String(x.tasks ?? "").trim().split(/\s+/).filter(Boolean);
  if (!tasks.length) tasks.push("assembleRelease");
  if (tasks.length > 8 || !tasks.every((t) => TASK.test(t))) throw new ValidationError("Gradle tasks: up to 8 task names such as bundleRelease or :app:assembleRelease");
  const pkgs = String(x.sdk_packages ?? "").trim().split(/\s+/).filter(Boolean);
  if (pkgs.length > 12 || !pkgs.every((p) => SDK_PACKAGE.test(p) && p.length <= 80)) throw new ValidationError("SDK packages: ids such as ndk;27.1.12297006 or platforms;android-36");
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
    sdk_packages: [...new Set(pkgs)].join(" "),
    jdk,
    memory_mb: v.int(x.memory_mb ?? 6144, 2048, 32768, "memory (MB)"),
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
  const prev = androidProjects.get(p.name);
  // A build of another repository or branch must not inherit what an earlier one left in the cache
  // (a Gradle init script, a wrapper distribution): that would run in a later build and be signed.
  const moved = !!prev && (prev.repo !== p.repo || prev.branch !== p.branch);
  if (moved && androidBuilds.running().some((b) => b.project === p.name)) throw new Error("a build is running for this project: change the repository or branch when it has finished");
  androidProjects.upsert(p);
  if (moved) await removeCache(cacheName(p.name));
  await deployKey(p.name);
  audit(actor, "android.project.save", p);
  return p;
}

export async function removeProject(name: string, actor: string) {
  mustGet(name);
  if (androidBuilds.running().some((b) => b.project === name)) throw new Error("a build is running for this project");
  for (const id of androidBuilds.older(name, 0)) await dropBuild(id);
  await remove(keyDir(name));
  await remove(signingDir(name));
  await removeCache(cacheName(name));
  androidProjects.remove(name);
  audit(actor, "android.project.remove", { name });
}

/** The next build downloads Gradle, its plugins and the dependencies again (a broken or poisoned cache). */
export async function clearCache(name: string, actor: string) {
  mustGet(name);
  if (androidBuilds.running().some((b) => b.project === name)) throw new Error("a build is running for this project");
  await removeCache(cacheName(name));
  audit(actor, "android.cache.clear", { name });
}

/** Read-only deploy key for a private repository (add it to the repository, not to an account). */
export async function deployKey(name: string): Promise<string> {
  mustGet(name);
  await ensureLayout();
  const dir = keyDir(name);
  await ensureDir(dir, 0o700, FETCH_USER);
  if (!(await exists(`${dir}/id_ed25519`))) {
    await run(["ssh-keygen", "-t", "ed25519", "-N", "", "-C", `pano-android-${name}`, "-f", fsPath(`${dir}/id_ed25519`)], { user: FETCH_USER });
  }
  return ((await readText(`${dir}/id_ed25519.pub`)) ?? "").trim();
}

// ---- signing ---------------------------------------------------------------------

const secretText = (s: unknown, field: string) => {
  const x = String(s ?? "");
  if (x.length < 6 || x.length > 128 || /[\0-\x1f\x7f]/.test(x)) throw new ValidationError(`${field}: 6-128 characters, one line`);
  return x;
};

/** The key alias when a signing key is set (never the key or its passwords). */
export async function signingAlias(name: string): Promise<string> {
  return (await exists(`${signingDir(name)}/keystore`)) ? ((await readText(`${signingDir(name)}/alias`)) ?? "").trim() : "";
}

/** The upload/release keystore: root-only here, write-only from the UI, seen only by the signing sandbox. */
export async function setSigning(name: string, x: Record<string, unknown>, actor: string) {
  mustGet(name);
  const ks = Buffer.from(String(x.keystore ?? ""), "base64");
  if (ks.length < 32 || ks.length > 64 * 1024) throw new ValidationError("keystore: a .jks, .keystore or .p12 file (up to 64 KB)");
  // JKS starts with FEEDFEED; PKCS12 (the keytool default) is a DER sequence.
  if (ks.readUInt32BE(0) !== 0xfeedfeed && ks[0] !== 0x30) throw new ValidationError("keystore: not a Java keystore or PKCS12 file");
  const alias = String(x.alias ?? "").trim();
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(alias)) throw new ValidationError("key alias: letters, digits, . _ - (max 64)");
  const storePassword = secretText(x.storePassword, "keystore password");
  const keyPassword = x.keyPassword ? secretText(x.keyPassword, "key password") : storePassword;
  const dir = signingDir(name);
  await ensureDir(`${paths.secrets}/android`, 0o700);
  await ensureDir(dir, 0o700);
  await writeAtomic(`${dir}/keystore`, ks, 0o600);
  await writeAtomic(`${dir}/alias`, alias, 0o600);
  await writeAtomic(`${dir}/storepass`, storePassword, 0o600);
  await writeAtomic(`${dir}/keypass`, keyPassword, 0o600);
  audit(actor, "android.signing.set", { name, alias });
}

export async function clearSigning(name: string, actor: string) {
  mustGet(name);
  await remove(signingDir(name));
  audit(actor, "android.signing.clear", { name });
}

// ---- toolchain (JDK + Android SDK, root-owned, read-only for builds) ---------------

export async function toolchainStatus() {
  const jdks = [];
  for (const n of [17, 21]) if (await exists(`${jdkDir(n)}/bin/java`)) jdks.push(n);
  let buildTools: string[] = [];
  try {
    buildTools = (await readdir(fsPath(`${SDK}/build-tools`))).sort();
  } catch {}
  return {
    supported: process.arch === "x64",
    installed: !!jdks.length && (await exists(sdkmanager)),
    state: settings.get("android.toolchain") ?? "",
    error: settings.get("android.toolchain.error") ?? "",
    jdks,
    buildTools,
  };
}

/** JDK 17, the SDK command-line tools, licences and the usual platforms; in the background (a few minutes). */
export async function installToolchain(actor: string) {
  if (process.arch !== "x64") throw new Error("Android's build tools (aapt2) only run on x86-64 servers");
  if (settings.get("android.toolchain") === "installing") throw new Error("already installing");
  await ensureLayout();
  await remove(logFile("toolchain"));
  settings.set("android.toolchain", "installing");
  settings.set("android.toolchain.error", "");
  audit(actor, "android.toolchain.install", {});
  const log = logWriter(logFile("toolchain"));
  void (async () => {
    try {
      await ensureZip(log);
      await ensureJdk(17, log);
      if (!(await exists(sdkmanager))) {
        log("==> Android SDK command-line tools\n");
        const tmp = `${paths.data}/tmp/android-clt`;
        await remove(tmp);
        await ensureDir(tmp, 0o700);
        try {
          const zip = await downloadVerified(CMDLINE_TOOLS.url, CMDLINE_TOOLS.sha256, `${tmp}/clt.zip`);
          await run(["unzip", "-q", fsPath(zip), "-d", fsPath(tmp)]);
          await ensureDir(`${SDK}/cmdline-tools`, 0o755);
          await run(["mv", fsPath(`${tmp}/cmdline-tools`), fsPath(`${SDK}/cmdline-tools/latest`)]);
        } finally {
          await remove(tmp);
        }
      }
      log("==> accept the Android SDK licences\n");
      await run([fsPath(sdkmanager), `--sdk_root=${fsPath(SDK)}`, "--licenses"], { env: sdkEnv(), input: "y\n".repeat(40), timeoutMs: 300_000, check: false });
      await ensurePackages(DEFAULT_PACKAGES, log);
      await run(["chmod", "-R", "a+rX,go-w", fsPath(toolchainDir)]);
      settings.set("android.toolchain", "ready");
      log("\ntoolchain ready\n");
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      settings.set("android.toolchain", "failed");
      settings.set("android.toolchain.error", msg.slice(0, 300));
      log(`\nFAILED: ${msg}\n`);
    }
  })();
}

export async function removeToolchain(actor: string) {
  if (androidBuilds.running().length || settings.get("android.toolchain") === "installing") throw new Error("wait for the running builds to finish");
  await remove(toolchainDir);
  settings.set("android.toolchain", "");
  audit(actor, "android.toolchain.remove", {});
}

const sdkEnv = () => ({ JAVA_HOME: fsPath(jdkDir(17)), PATH: `${fsPath(jdkDir(17))}/bin:/usr/bin:/bin` });

/** AAB signatures left by the build (React Native signs release with the debug key) are removed with zip. */
async function ensureZip(log: (s: string) => void) {
  if ((await run(["sh", "-c", "command -v zip"], { check: false })).code === 0) return;
  log("==> zip (distribution package)\n");
  const deb = /^(ID|ID_LIKE)=.*\b(debian|ubuntu)\b/m.test((await readText("/etc/os-release")) ?? "");
  await run(deb ? ["apt-get", "install", "-y", "zip"] : ["dnf", "-y", "install", "zip"], { timeoutMs: 600_000, env: { DEBIAN_FRONTEND: "noninteractive" } });
}

/** Eclipse Temurin, checked against the SHA-256 Adoptium publishes for it. */
async function ensureJdk(n: 17 | 21 | number, log: (s: string) => void) {
  if (await exists(`${jdkDir(n)}/bin/java`)) return;
  log(`==> JDK ${n} (Eclipse Temurin)\n`);
  const r = await fetch(`https://api.adoptium.net/v3/assets/latest/${n}/hotspot?architecture=x64&image_type=jdk&os=linux&vendor=eclipse`, {
    headers: { "user-agent": "pano" },
    signal: AbortSignal.timeout(30_000),
  });
  const pkg = ((await r.json().catch(() => [])) as { binary?: { package?: { link?: string; checksum?: string } } }[])[0]?.binary?.package;
  if (!r.ok || !pkg?.link?.startsWith("https://github.com/adoptium/") || !/^[0-9a-f]{64}$/.test(pkg.checksum ?? "")) throw new Error(`JDK ${n}: no release found at Adoptium`);
  const tmp = `${paths.data}/tmp/android-jdk-${n}`;
  await remove(tmp);
  await ensureDir(tmp, 0o700);
  try {
    const tar = await downloadVerified(pkg.link, pkg.checksum!, `${tmp}/jdk.tar.gz`);
    await ensureDir(`${tmp}/jdk`, 0o755);
    await run(["tar", "-xzf", fsPath(tar), "-C", fsPath(`${tmp}/jdk`), "--strip-components=1", "--no-same-owner"]);
    await ensureDir(toolchainDir, 0o755);
    await run(["mv", fsPath(`${tmp}/jdk`), fsPath(jdkDir(n))]);
    log(`JDK ${n} installed\n`);
  } finally {
    await remove(tmp);
  }
}

async function downloadVerified(url: string, sum: string, dest: string): Promise<string> {
  const res = await fetch(url, { headers: { "user-agent": "pano" }, signal: AbortSignal.timeout(30 * 60_000) });
  if (!res.ok) throw new Error(`download failed (${res.status}): ${url}`);
  await Bun.write(fsPath(dest), res);
  const hash = new Bun.CryptoHasher("sha256");
  for await (const chunk of Bun.file(fsPath(dest)).stream()) hash.update(chunk);
  if (!DRY_RUN && hash.digest("hex") !== sum) throw new Error(`checksum mismatch: ${url}`);
  return dest;
}

/** Installs SDK packages that are missing (as root: builds cannot change the SDK). sdkmanager checks each download. */
async function ensurePackages(pkgs: string[], log: (s: string) => void) {
  const missing = [];
  for (const p of pkgs) if (!(await exists(`${SDK}/${p.replace(/;/g, "/")}`))) missing.push(p);
  if (!missing.length) return;
  log(`==> SDK packages: ${missing.join(" ")}\n`);
  await run([fsPath(sdkmanager), `--sdk_root=${fsPath(SDK)}`, ...missing], { env: sdkEnv(), timeoutMs: 1_800_000, onLine: (l) => /^\s*$|\[=*/.test(l) || log(`${l}\n`) });
  await run(["chmod", "-R", "a+rX,go-w", fsPath(SDK)]);
}

/** "Failed to install the following SDK components: ndk;27.1.12297006 …": what to add to the project. */
export function missingPackages(log: string): string[] {
  const i = log.indexOf("Failed to install the following");
  if (i < 0) return [];
  return [...new Set([...log.slice(i, i + 2000).matchAll(/^\s+([a-z][a-z0-9-]*(?:;[A-Za-z0-9._-]+){1,2})\s/gm)].map((m) => m[1]!))];
}

// ---- builds ----------------------------------------------------------------------

/** Builds run one at a time: Gradle takes several GB and all cores it gets. */
let queue: Promise<unknown> = Promise.resolve();

export async function startBuild(name: string, trigger: string, actor: string): Promise<number> {
  const p = mustGet(name);
  if (!(await toolchainStatus()).installed) throw new Error("install the Android toolchain first (Android page)");
  if (androidBuilds.running().some((b) => b.project === name)) throw new Error("a build is already running for this project");
  const id = androidBuilds.start(name, trigger, !!(await signingAlias(name)));
  audit(actor, "android.build", { project: name, id, trigger });
  queue = queue.then(() => runBuild(id, p)).catch((e) => console.error(`[agent] android build ${id}: ${e}`));
  return id;
}

/** Appends to a log in order, with a size cap. */
function logWriter(file: string) {
  let size = 0;
  let chain = Promise.resolve();
  return (text: string) => {
    if (size > MAX_LOG) return;
    let t = text;
    size += t.length;
    if (size > MAX_LOG) t += "\n[log cut at 20 MB]\n";
    chain = chain.then(() => appendFile(fsPath(file), t)).catch(() => {});
  };
}

const q = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;

/** What runs inside the build sandbox; the source tarball arrives on stdin. */
export function buildScript(p: AndroidProject): string {
  const gradle = p.gradle_dir ? `cd ${q(p.gradle_dir)}` : `if [ ! -f gradlew ] && [ -f android/gradlew ]; then cd android; fi`;
  return `set -euo pipefail
cd "$HOME"
mkdir -p src out
echo "==> unpack the source"
tar -xzf - -C src --no-same-owner
cd src/${q(p.root_dir || ".")}
${p.prepare_cmd ? `echo ${q(`==> ${p.prepare_cmd}`)}\n${p.prepare_cmd}\n` : ""}${gradle}
[ -f gradlew ] || { echo "FAILED: no gradlew in $(pwd) (set the Gradle directory)"; exit 1; }
chmod +x gradlew
echo ${q(`==> ./gradlew ${p.tasks}`)}
./gradlew --no-daemon --console=plain ${p.tasks}
echo "==> collect APK/AAB"
find "$HOME/src" -path '*/build/outputs/*' -type f \\( -name '*.apk' -o -name '*.aab' \\) -print0 | while IFS= read -r -d '' f; do
  n=$(basename "$f"); d="$n"; i=1
  while [ -e "$HOME/out/$d" ]; do i=$((i+1)); d="$i-$n"; done
  cp "$f" "$HOME/out/$d"
done
`;
}

/** What runs inside the signing sandbox (no network); the APK/AAB arrive as a tar on stdin, the key as credentials. */
export function signScript(): string {
  return `set -euo pipefail
cd "$HOME"
mkdir -p in
tar -xf - -C in --no-same-owner
C="$CREDENTIALS_DIRECTORY"
ALIAS=$(cat "$C/alias")
export PANO_SP=$(cat "$C/storepass") PANO_KP=$(cat "$C/keypass")
for f in in/*; do
  case "$f" in
    *.apk)
      "$APKSIGNER" sign --ks "$C/keystore" --ks-key-alias "$ALIAS" --ks-pass env:PANO_SP --key-pass env:PANO_KP --out "$f.signed" "$f"
      mv "$f.signed" "$f"
      echo "signed $(basename "$f") (apksigner)" ;;
    *.aab)
      zip -q -d "$f" 'META-INF/*.SF' 'META-INF/*.RSA' 'META-INF/*.EC' 'META-INF/*.DSA' >/dev/null 2>&1 || true
      jarsigner -keystore "$C/keystore" -storepass:env PANO_SP -keypass:env PANO_KP "$f" "$ALIAS" >/dev/null
      echo "signed $(basename "$f") (jarsigner)" ;;
  esac
done
`;
}

async function runBuild(id: number, p: AndroidProject) {
  const log = logWriter(logFile(id));
  const step = (s: string) => log(`\n==> ${s}\n`);
  const started = Date.now();
  let text = "";
  const tee = (line: string) => {
    if (text.length < 1_000_000) text += `${line}\n`;
    log(`${line}\n`);
  };
  try {
    await ensureLayout();
    await ensureJdk(p.jdk, log);
    const pkgs = p.sdk_packages.split(" ").filter(Boolean);
    if (pkgs.length) await ensurePackages(pkgs, log);

    step(`fetch ${p.repo} (${p.branch})`);
    const { sha, tar } = await fetchSource(p, id, (l) => log(`${l}\n`));
    androidBuilds.setCommit(id, sha);
    log(`commit ${sha}\n`);

    step(`build in a throwaway sandbox (${p.memory_mb} MB, ${p.timeout_min} min, the project's download cache kept)`);
    const runtimes = await installedRuntimes();
    const node = runtimes.find((r) => r.runtime === "node");
    const bun = runtimes.find((r) => r.runtime === "bun");
    const extra = [node && runtimeBin("node", node.version), bun && runtimeBin("bun", bun.version)].filter(Boolean).join(":");
    const home = `/var/lib/${unit("build", id)}`;
    const cache = cacheName(p.name);
    const c = cachePath(cache);
    const env = {
      GRADLE_USER_HOME: `${c}/gradle`,
      XDG_CACHE_HOME: `${c}/xdg`,
      npm_config_cache: `${c}/npm`,
      BUN_INSTALL_CACHE_DIR: `${c}/bun`,
      ANDROID_USER_HOME: `${home}/.android`,
      JAVA_HOME: jdkDir(p.jdk),
      ANDROID_HOME: SDK,
      ANDROID_SDK_ROOT: SDK,
      PATH: `${jdkDir(p.jdk)}/bin:${SDK}/platform-tools${extra ? `:${extra}` : ""}:/usr/local/bin:/usr/bin:/bin`,
    };
    const r = await runSandbox(unit("build", id), { memoryMb: p.memory_mb, timeoutMin: p.timeout_min, network: true, env, cache }, buildScript(p), {
      inputFile: fsPath(tar),
      onLine: tee,
      check: false,
    });
    await remove(tar);
    if (r.code !== 0) {
      const missing = missingPackages(text);
      throw new Error(missing.length ? `missing SDK packages: add "${missing.join(" ")}" to the project's SDK packages` : `the build exited with ${r.code}`);
    }

    step("collect APK/AAB");
    let artifacts = await collect(id, `${sandboxDir(unit("build", id))}/out`, log);
    if (!artifacts.length) throw new Error("the build made no APK or AAB (check the Gradle tasks)");
    await removeSandbox(unit("build", id));

    const alias = await signingAlias(p.name);
    if (alias) {
      step(`sign with "${alias}" in a separate sandbox without network`);
      artifacts = await sign(id, p.name, artifacts, log);
    }
    androidBuilds.finish(id, { status: "success", artifacts });
    log(`\nbuild ${id} done in ${Math.round((Date.now() - started) / 1000)} s\n`);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    log(`\nFAILED: ${msg}\n`);
    androidBuilds.finish(id, { status: "failed", error: msg.slice(0, 500) });
    await notify(`🔴 Android build ${p.name} #${id} failed: ${msg}`);
  } finally {
    await removeSandbox(unit("build", id));
    await removeSandbox(unit("sign", id));
    await remove(`${WORK}/${id}.git`);
    await remove(`${WORK}/${id}.tar.gz`);
    await prune(p.name);
  }
}

/** The branch's newest commit as a tar.gz, fetched as the fetch user: no checkout, no hooks, nothing from the repository runs. */
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
  const git = (args: string[]) => run(["git", ...args], { user: FETCH_USER, env, onLine, timeoutMs: 10 * 60_000 });
  await git(["init", "--bare", "-q", bare]);
  await git(["-C", bare, "fetch", "--depth", "1", "--no-tags", "--", p.repo, `refs/heads/${p.branch}`]);
  const sha = (await run(["git", "-C", bare, "rev-parse", "FETCH_HEAD"], { user: FETCH_USER, env, check: false })).stdout.trim();
  await git(["-C", bare, "archive", "--format=tar.gz", "-o", fsPath(tar), "FETCH_HEAD"]);
  await remove(`${WORK}/${id}.git`);
  if (!DRY_RUN && Bun.file(fsPath(tar)).size > MAX_SOURCE) throw new Error("the source is over 1 GB");
  return { sha, tar };
}

/** Copies the APK/AAB a stopped sandbox left in `from` (throwaway.ts readResult: regular files, no links followed). */
async function collect(id: number, from: string, log: (s: string) => void): Promise<AndroidArtifact[]> {
  const dir = `${ROOT}/artifacts/${id}`;
  await ensureDir(dir, 0o750);
  await panoGroup(dir);
  // The sandbox could have swapped its output directory for a link to somewhere else: not followed.
  if (!(await plainDirectory(from))) return [];
  let names: string[] = [];
  try {
    names = (await readdir(fsPath(from))).filter((n) => ARTIFACT_NAME.test(n)).sort().slice(0, 20);
  } catch {
    return [];
  }
  const out: AndroidArtifact[] = [];
  for (const name of names) {
    // Streamed to its place (no 1 GiB file in memory); links, FIFOs and oversize files are skipped.
    const copied = await copyResult(`${from}/${name}`, artifactFile(id, name), MAX_ARTIFACT, 0o640);
    if (!copied) continue;
    await panoGroup(artifactFile(id, name));
    const item = { name, size: copied.size, sha256: copied.sha256 };
    log(`${item.name}  ${item.size} bytes  sha256 ${item.sha256}\n`);
    out.push(item);
  }
  return out;
}

/** Signs the collected files in a second sandbox: no network, the key only as systemd credentials (gone when it stops). */
async function sign(id: number, name: string, artifacts: AndroidArtifact[], log: (s: string) => void): Promise<AndroidArtifact[]> {
  const buildTools = (await toolchainStatus()).buildTools.at(-1);
  if (!buildTools) throw new Error("no Android build-tools installed (apksigner)");
  const dir = `${ROOT}/artifacts/${id}`;
  const tar = `${ROOT}/tmp/${id}-unsigned.tar`;
  await run(["tar", "-cf", fsPath(tar), "-C", fsPath(dir), "--", ...artifacts.map((a) => a.name)]);
  const keys = signingDir(name);
  const env = {
    JAVA_HOME: jdkDir(17),
    PATH: `${jdkDir(17)}/bin:/usr/bin:/bin`,
    APKSIGNER: `${SDK}/build-tools/${buildTools}/apksigner`,
  };
  const props = ["keystore", "alias", "storepass", "keypass"].map((c) => `LoadCredential=${c}:${keys}/${c}`);
  try {
    await runSandbox(unit("sign", id), { memoryMb: 1024, timeoutMin: 10, network: false, env, props }, signScript(), {
      inputFile: fsPath(tar),
      onLine: (l) => log(`${l}\n`),
    });
  } finally {
    await remove(tar);
  }
  const signed = await collect(id, `${sandboxDir(unit("sign", id))}/in`, log);
  if (signed.length !== artifacts.length) throw new Error("signing did not return every file");
  return signed;
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

export async function readLog(id: number | "toolchain", offset = 0): Promise<{ text: string; offset: number }> {
  const file = Bun.file(fsPath(logFile(id)));
  if (!(await file.exists())) return { text: "", offset };
  const size = file.size;
  if (offset >= size) return { text: "", offset: size };
  return { text: await file.slice(offset, size).text(), offset: size };
}

// ---- layout ------------------------------------------------------------------------

/** root 0711 (traverse only); artifacts root:pano for the web; work and keys only for the fetch user; logs root-only. */
async function ensureLayout() {
  await ensureUser(FETCH_USER, WORK);
  await ensureDir(ROOT, 0o711);
  await ensureDir(`${ROOT}/logs`, 0o700);
  await ensureDir(`${ROOT}/tmp`, 0o700);
  await ensureDir(`${ROOT}/artifacts`, 0o750);
  await panoGroup(`${ROOT}/artifacts`);
  await ensureDir(WORK, 0o700, FETCH_USER);
  await ensureDir(`${ROOT}/keys`, 0o700, FETCH_USER);
}

async function panoGroup(abs: string) {
  if (DRY_RUN || process.getuid?.() !== 0) return;
  const pano = await lookupUser("pano");
  if (pano) await chown(fsPath(abs), 0, pano.gid);
}

/** At agent start: builds cut off by a restart fail and their sandboxes are removed. */
export async function cleanupAndroid() {
  const stale = androidBuilds.running();
  androidBuilds.failStale();
  for (const b of stale) {
    await removeSandbox(unit("build", b.id));
    await removeSandbox(unit("sign", b.id));
  }
  if (settings.get("android.toolchain") === "installing") {
    settings.set("android.toolchain", "failed");
    settings.set("android.toolchain.error", "agent restarted");
  }
}

// ---- views ----------------------------------------------------------------------------

export async function androidStatus() {
  const projects = await Promise.all(
    androidProjects.list().map(async (p) => ({ ...p, signing: await signingAlias(p.name), last: androidBuilds.list(p.name, 1)[0] ?? null })),
  );
  return { toolchain: await toolchainStatus(), projects };
}

export async function projectDetail(name: string) {
  const p = mustGet(name);
  return {
    project: p,
    signing: await signingAlias(name),
    deployKey: await deployKey(name),
    builds: androidBuilds.list(name, KEEP_BUILDS),
    cacheBytes: await dirBytes(`/var/cache/private/${cacheName(name)}`),
  };
}
