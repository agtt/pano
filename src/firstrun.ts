// The end of a first install: everything a new server needs, without questions. Creates the
// admin (generated password, 2FA shown as a QR code in the terminal), starts the edge when the
// server has no web server yet, and puts the panel on Tailscale when the machine is on a tailnet.
// Re-running `pano install` (an update) changes none of this.

import { readFile, writeFile } from "node:fs/promises";
import { DRY_RUN, fsPath, paths } from "./shared/config.ts";

type Call = <T = unknown>(method: string, params?: Record<string, unknown>, actor?: string) => Promise<T>;
type Step = (argv: string[]) => { code: number; out: string };

const run: Step = (argv) => {
  if (DRY_RUN) return { code: 0, out: "" };
  try {
    const r = Bun.spawnSync(argv, { stdout: "pipe", stderr: "pipe" });
    return { code: r.exitCode ?? 1, out: r.stdout.toString().trim() };
  } catch {
    // the program is not installed
    return { code: 127, out: "" };
  }
};

export async function waitForAgent(call: Call, seconds = 60) {
  for (let i = 0; i < seconds; i++) {
    if (await call("system.info", {}, "cli").then(() => true, () => false)) return;
    await Bun.sleep(1000);
  }
  throw new Error("the agent did not come up (journalctl -u pano-agent -n 50)");
}

/** Nothing listens on :80 or :443 (no nginx/Apache/OpenLiteSpeed to move out of the way). */
export function webPortsFree(ssOutput: string): boolean {
  return ssOutput.trim() === "";
}

/** The machine's MagicDNS name when Tailscale is up and `tailscale serve` is not used for anything yet. */
export function tailscaleName(statusJson: string, serveStatus: string): string {
  try {
    const s = JSON.parse(statusJson) as { BackendState?: string; Self?: { DNSName?: string } };
    if (s.BackendState !== "Running") return "";
    const name = (s.Self?.DNSName ?? "").replace(/\.$/, "").toLowerCase();
    if (!/^[a-z0-9.-]+\.ts\.net$/.test(name)) return "";
    return serveStatus.trim() && !/no serve config/i.test(serveStatus) ? "" : name;
  } catch {
    return "";
  }
}

/** pano.env with PANO_WEB_HOSTS set to `host` (other lines kept). */
export function withWebHost(envText: string, host: string): string {
  const lines = envText.split("\n").filter((l) => !/^PANO_WEB_HOSTS=/.test(l));
  while (lines.length && lines.at(-1) === "") lines.pop();
  return `${lines.join("\n")}\n# The panel's name on the tailnet (tailscale serve), set by pano install.\nPANO_WEB_HOSTS=${host}\n`;
}

/** The server's main IPv4 address, for the SSH tunnel line. */
function mainIp(): string {
  const m = run(["ip", "-4", "route", "get", "1.1.1.1"]).out.match(/\bsrc (\d+\.\d+\.\d+\.\d+)/);
  return m?.[1] ?? "<server>";
}

/** A QR code drawn with text, when qrencode is there (or can be installed); "" otherwise. */
function terminalQr(text: string): string {
  const have = () => run(["sh", "-c", "command -v qrencode"]).code === 0;
  if (!have()) {
    if (run(["sh", "-c", "command -v apt-get"]).code === 0) run(["sh", "-c", "DEBIAN_FRONTEND=noninteractive apt-get install -y -q qrencode"]);
    // RHEL family: qrencode is in EPEL (pano adds EPEL for coturn as well).
    else if (run(["dnf", "-y", "-q", "install", "qrencode"]).code !== 0) run(["sh", "-c", "dnf -y -q install epel-release && dnf -y -q install qrencode"]);
  }
  if (!have()) return "";
  const r = run(["qrencode", "-t", "ANSIUTF8", "-m", "2", text]);
  return r.code === 0 ? r.out : "";
}

/**
 * A new server has no admin on either side. The web database belongs to the web user (a compromised
 * pano-web could empty it), so the agent's root-owned admins decide as well: then the installer only
 * updates, and a lost web login is `pano admin`'s job.
 */
export const isFirstInstall = (webUsers: number, agentAdmins: number) => webUsers === 0 && agentAdmins === 0;

export async function firstRun(call: Call, ownWebDb: () => Promise<void>) {
  const { createUser, userCount, webDb } = await import("./web/auth.ts");
  const { adminNames } = await import("./agent/otp.ts");
  if (!isFirstInstall(userCount(), adminNames().length)) {
    // Opening it as root may have made its -wal/-shm files: they stay the web user's.
    webDb().close();
    await ownWebDb();
    return false;
  }
  const { otpauthUri } = await import("./web/totp.ts");
  const { setAdminSecret } = await import("./agent/otp.ts");
  const { randomPassword } = await import("./agent/sys.ts");

  const username = "admin";
  const password = randomPassword(20);
  const { secret } = await createUser(username, password);
  webDb().close();
  setAdminSecret(username, secret);
  await ownWebDb();

  console.log("Admin created. Starting the web server…");
  await waitForAgent(call);
  // The edge: on a server with no web server yet it simply starts; with one, the panel's Edge page moves it.
  let edge = "An existing web server holds :80/:443: open Server > Edge in the panel to move it behind pano.";
  if (process.env.PANO_NO_EDGE === "1") edge = "Skipped (PANO_NO_EDGE=1).";
  else if (webPortsFree(run(["ss", "-Htln", "( sport = :80 or sport = :443 )"]).out)) {
    try {
      await call("edge.install", {}, "cli");
      const r = await call<{ ok: boolean }>("edge.cutover", {}, "cli");
      edge = r.ok ? "Caddy serves :80 and :443 (HTTPS certificates come automatically)." : "Could not start Caddy: see Server > Edge in the panel.";
    } catch (e) {
      edge = `Could not start Caddy (${e instanceof Error ? e.message : String(e)}): see Server > Edge in the panel.`;
    }
  }

  // Tailscale: the panel gets an HTTPS name on the tailnet, reachable by every device and user of that tailnet.
  let url = "";
  const ts = process.env.PANO_NO_TAILSCALE !== "1" && run(["sh", "-c", "command -v tailscale"]).code === 0 ? tailscaleName(run(["tailscale", "status", "--json"]).out, run(["tailscale", "serve", "status"]).out) : "";
  if (ts && run(["tailscale", "serve", "--bg", "7800"]).code === 0) {
    const file = fsPath(`${paths.etc}/pano.env`);
    await writeFile(file, withWebHost(await readFile(file, "utf8"), ts), { mode: 0o600 });
    run(["systemctl", "restart", "pano-web"]);
    url = `https://${ts}`;
  }

  console.log("Preparing the two-factor QR code…");
  const uri = otpauthUri(secret, username);
  const qr = terminalQr(uri);
  const ip = mainIp();
  console.log(`
pano is ready.

  Panel      ${url ? `${url}   (Tailscale: every device and user of your tailnet reaches the login)\n             or ` : ""}ssh -L 7800:127.0.0.1:7800 root@${ip}   then open http://127.0.0.1:7800
  Username   ${username}
  Password   ${password}
             Shown only now: put it in your password manager.

  Two-factor code: scan this with an authenticator app (Google Authenticator, 1Password, Authy…)
${qr ? qr.replace(/^/gm, "  ") : ""}
  Or type this key into the app: ${secret}

  Web server ${edge}

  Next: open the panel, add a site or an app, and connect backup storage (Backups).`);
  return true;
}
