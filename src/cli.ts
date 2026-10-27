#!/usr/bin/env bun
// Single binary, several roles:
//   pano install            set up users, directories and systemd units (root)
//   pano agent              privileged agent (systemd: pano-agent)
//   pano web                web UI as the unprivileged `pano` user (systemd: pano-web)
//   pano admin <username>   create an admin or reset its password + 2FA (root)
//   pano rpc <method> [json]  call the agent directly (root)

import { chmod, copyFile, mkdir, rename, writeFile } from "node:fs/promises";
import { DRY_RUN, env, fsPath, paths } from "./shared/config.ts";

const [cmd, ...args] = process.argv.slice(2);

async function main() {
  switch (cmd) {
    case "agent": {
      const { startAgent } = await import("./agent/main.ts");
      await startAgent();
      break;
    }
    case "web": {
      const { createWebApp, createHookApp } = await import("./web/server.tsx");
      const web = createWebApp();
      // No idle timeout: installs and imports keep a request open for minutes (the panel is never public).
      Bun.serve({ hostname: env.webHost, port: env.webPort, fetch: web.fetch, maxRequestBodySize: 2_000_000, idleTimeout: 0 });
      if (env.webVpnHost) {
        // Also on the WireGuard address; the interface may come up after us, so keep trying.
        const listenVpn = () => {
          try {
            Bun.serve({ hostname: env.webVpnHost, port: env.webPort, fetch: web.fetch, maxRequestBodySize: 2_000_000, idleTimeout: 0 });
            console.log(`[web] also on http://${env.webVpnHost}:${env.webPort} (WireGuard)`);
          } catch {
            setTimeout(listenVpn, 10_000);
          }
        };
        listenVpn();
      }
      const hooks = createHookApp();
      Bun.serve({ hostname: "127.0.0.1", port: env.hookPort, fetch: hooks.fetch, maxRequestBodySize: 1_100_000 });
      console.log(`[web] http://${env.webHost}:${env.webPort} (hooks on 127.0.0.1:${env.hookPort})`);
      break;
    }
    case "admin": {
      const username = args[0];
      if (!username) return fail("usage: pano admin <username>");
      const password = args[1] ?? (await promptHidden("New password (min 12 chars): "));
      const { createUser, webDb } = await import("./web/auth.ts");
      const { otpauthUri } = await import("./web/totp.ts");
      const { secret } = await createUser(username, password);
      webDb().close();
      await ownWebDb();
      console.log(`\nAdmin "${username}" saved. Add this to your authenticator app:\n`);
      console.log(`  secret: ${secret}`);
      console.log(`  uri:    ${otpauthUri(secret, username)}\n`);
      console.log("Existing sessions of this user were signed out.");
      break;
    }
    case "rpc": {
      const { call } = await import("./web/agent.ts");
      const result = await call(args[0] ?? "system.info", args[1] ? JSON.parse(args[1]) : {}, "cli");
      console.log(typeof result === "string" ? result : JSON.stringify(result, null, 2));
      break;
    }
    case "install":
      await install();
      break;
    default:
      fail("usage: pano install | agent | web | admin <username> | rpc <method> [json]");
  }
}

function fail(msg: string): never {
  console.error(msg);
  process.exit(1);
}

async function promptHidden(question: string): Promise<string> {
  process.stdout.write(question);
  const tty = process.stdin.isTTY;
  if (tty) Bun.spawnSync(["stty", "-echo"], { stdin: "inherit" });
  try {
    for await (const line of console) return line.trim();
    return "";
  } finally {
    if (tty) Bun.spawnSync(["stty", "echo"], { stdin: "inherit" });
    process.stdout.write("\n");
  }
}

async function sh(argv: string[], check = true) {
  if (DRY_RUN) return console.log(`[dry-run] ${argv.join(" ")}`);
  const r = Bun.spawnSync(argv, { stdout: "inherit", stderr: "inherit" });
  if (check && r.exitCode !== 0) fail(`${argv.join(" ")} failed`);
}

async function ownWebDb() {
  if (DRY_RUN || process.getuid?.() !== 0) return;
  await sh(["chown", "-R", "pano:pano", fsPath(`${paths.data}/web`)]);
}

const AGENT_UNIT = `[Unit]
Description=pano agent (privileged operations)
After=network-online.target mariadb.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=${paths.bin}/pano agent
EnvironmentFile=-${paths.etc}/pano.env
Restart=always
RestartSec=2
UMask=0027
NoNewPrivileges=true
ProtectHome=read-only
PrivateTmp=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectClock=true
LockPersonality=true
RestrictRealtime=true

[Install]
WantedBy=multi-user.target
`;

const WEB_UNIT = `[Unit]
Description=pano web UI (unprivileged)
After=pano-agent.service
Requires=pano-agent.service

[Service]
Type=simple
User=pano
Group=pano
ExecStart=${paths.bin}/pano web
EnvironmentFile=-${paths.etc}/pano.env
Restart=always
RestartSec=2
UMask=0077
MemoryMax=256M
NoNewPrivileges=true
CapabilityBoundingSet=
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${paths.data}/web
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
RestrictSUIDSGID=true
RestrictRealtime=true
RestrictNamespaces=true
LockPersonality=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources

[Install]
WantedBy=multi-user.target
`;

const ENV_TEMPLATE = `# pano settings. Restart pano-web / pano-agent after changes.
# Keep the panel off the public internet: localhost (SSH tunnel) or your Tailscale IP.
PANO_WEB_HOST=127.0.0.1
PANO_WEB_PORT=7800
# Set to 1 only when the panel is reached over plain HTTP (SSH tunnel / Tailscale).
PANO_INSECURE_COOKIES=1
PANO_LANG=tr
`;

async function install() {
  if (!DRY_RUN && process.getuid?.() !== 0) fail("run as root");
  console.log("Installing pano…");
  if (!DRY_RUN && Bun.spawnSync(["id", "-u", "pano"]).exitCode !== 0) {
    await sh(["useradd", "--system", "--home-dir", `${paths.data}/web`, "--no-create-home", "--shell", "/usr/sbin/nologin", "pano"]);
  }
  for (const [dir, mode] of [
    // traverse-only: the edge user reaches its Caddyfile and certs, nobody can list
    [paths.etc, 0o711],
    [paths.secrets, 0o700],
    [paths.data, 0o711],
    [paths.deployLogs, 0o700],
    [paths.logs, 0o711],
    [paths.apps, 0o755],
    [paths.bin, 0o755],
    [paths.runtimes, 0o755],
  ] as const) {
    await mkdir(fsPath(dir), { recursive: true });
    await chmod(fsPath(dir), mode);
  }
  await mkdir(fsPath(`${paths.data}/web`), { recursive: true, mode: 0o700 });
  await ownWebDb();

  const self = process.execPath.endsWith("/bun") ? null : process.execPath;
  if (self && self !== fsPath(`${paths.bin}/pano`)) {
    // copy + rename: replacing a running binary in place fails with ETXTBSY
    await copyFile(self, fsPath(`${paths.bin}/pano.new`));
    await chmod(fsPath(`${paths.bin}/pano.new`), 0o755);
    await rename(fsPath(`${paths.bin}/pano.new`), fsPath(`${paths.bin}/pano`));
  } else if (!self) {
    console.log(`(running from source: build with "bun run build" and copy dist/pano to ${paths.bin}/pano)`);
  }

  if (!(await Bun.file(fsPath(`${paths.etc}/pano.env`)).exists())) {
    // Read by systemd (root) when starting the units; the services never open it.
    await writeFile(fsPath(`${paths.etc}/pano.env`), ENV_TEMPLATE, { mode: 0o600 });
  }
  await writeFile(fsPath(`${paths.systemd}/pano-agent.service`), AGENT_UNIT, { mode: 0o644 });
  await writeFile(fsPath(`${paths.systemd}/pano-web.service`), WEB_UNIT, { mode: 0o644 });
  await sh(["systemctl", "daemon-reload"]);
  await sh(["systemctl", "enable", "pano-agent", "pano-web"]);
  // restart (not just start) so re-running install upgrades a running panel
  await sh(["systemctl", "restart", "pano-agent", "pano-web"]);
  console.log(`
Done.
  1. Create the admin:   ${paths.bin}/pano admin <username>
  2. Open the panel:     ssh -L 7800:127.0.0.1:7800 root@<server>  →  http://127.0.0.1:7800
     (or set PANO_WEB_HOST to your Tailscale IP in ${paths.etc}/pano.env)
  3. Nothing public changed yet. The edge (Caddy) only takes :80/:443 at cutover.`);
}

main().catch((e) => fail(e instanceof Error ? e.message : String(e)));
