# pano

A lightweight, security-first server panel for **Next.js, Node.js and Bun** apps (monorepos included) and
**PHP sites**, with MariaDB management, encrypted **Cloudflare R2** backups, and migration off **CyberPanel/OpenLiteSpeed**
and **cPanel**.

One self-contained binary, no Docker, no Python; PHP is installed only when a PHP site needs it. Measured in the test VM
(AlmaLinux 9): web ≈ 7 MB, agent ≈ 25–70 MB, Caddy edge ≈ 55 MB RAM; a deployed Next.js app ≈ 45 MB, a Bun app ≈ 4–13 MB,
an idle PHP site (its own pool, PHP 8.5) ≈ 11–20 MB.

## What it does

| Area | |
|---|---|
| Apps | git → sandboxed install/build → blue/green systemd slots → health check → traffic switch. Zero-downtime deploys, one-click rollback to the previous release (kept on disk: no build, seconds), per-app env, logs, memory limits, cron jobs (systemd timers in the live release, same user/env/sandbox, never overlapping, missed runs catch up). bun is the package manager for every app (installed automatically; reads package-lock/yarn/pnpm lockfiles with their exact versions); Node.js apps still run on node. `DATA_DIR` is a per-app directory kept across deploys (SQLite, uploads) and included in app backups (SQLite databases as a consistent copy, even while the app writes). |
| Git | Push-to-deploy from GitHub, GitLab, Gitea, Forgejo (webhook per app, HMAC or token checked in constant time; can be switched off per app). Optional GitHub connection (one fine-grained token, root-only): repository picker, one-click link (read-only deploy key + webhook) and a `pano/deploy` commit status on every deploy, Vercel-style. Preview deploys per branch, with the preview link commented (and kept up to date) on the branch's open pull requests. |
| Environment | Per-app variables (masked, 2FA to show or change), preview-only values (a test payment key for branch previews), shared variable groups used by several apps (root-only, the app's own value wins), and a hint on the app page when a restart, or for variables built into the code (`NEXT_PUBLIC_*`, `VITE_*`, …) a redeploy, would apply changed values. |
| Runtimes | Any Node.js / Bun version side by side under `/opt/pano/runtimes`, checksum-verified. Apps pin their own version; OS updates never change them. |
| Edge | Caddy (pinned, checksum-verified) on :80/:443: automatic HTTPS, HTTP/3, on-demand TLS for customer domains, Cloudflare real-IP. Config is rendered from state and validated before every reload. |
| Monorepos | One build, several processes: `name \| dir \| routes \| memory \| start` per line. Routes are hosts, `host/path`, `*.host` or `*` (any host, on-demand TLS with an ask URL). Web processes get blue/green slots and health checks; workers have no port and never run twice (old one stops before the new one starts). |
| PHP sites | PHP 7.4–8.5 (Remi on AlmaLinux/Rocky, Ondřej Surý's on Debian/Ubuntu; signed) installed on first use; WordPress tools (one-click install, updates, maintenance mode, password reset) with a verified wp-cli run as the site user. Each site: its own system user, its own PHP-FPM pool running as that user (never root, `pm=ondemand`, hardened unit with `MemoryDenyWriteExecute`), socket only the edge can open (ACL), `open_basedir`, dangerous functions off, secure session cookies. The edge never serves dotfiles, dumps/backups, composer files or PHP inside uploads. Patch releases arrive with OS updates; pools reload onto the new binary. |
| Sites | Proxy (path → port routes), static, PHP, and legacy sites still served by the old OpenLiteSpeed on localhost. |
| Containers (optional) | Off until enabled; then Podman comes from the distribution (no daemon, nothing runs without a container). Each container is a Quadlet systemd unit in its own user namespace (root inside = unprivileged uid outside), memory/pids capped, published on 127.0.0.1 only, HTTPS through the edge when given a domain. Templates: Redis, PostgreSQL, Meilisearch, Uptime Kuma, n8n; empty passwords/keys are generated. |
| Databases | MariaDB/MySQL: list with sizes and grants, create db + user, reset passwords, drop (with 2FA). Any existing MariaDB or PostgreSQL database (imported, or another app's) can be connected to an app: it gets a user of its own for that database only, written into its env. |
| Services | MariaDB, PostgreSQL (latest major from postgresql.org, signed) and Valkey (Redis-compatible) installed on demand, natively, on 127.0.0.1 only, with small memory settings and passwords (scram-sha-256 / requirepass). PostgreSQL databases with their own role, `DATABASE_URL` shown once; every database pano creates (and every app) gets a daily encrypted backup job automatically (runs once R2 is set up). An existing MariaDB (CyberPanel) is used as is, never reconfigured. |
| Shield | Imunify-style, no daemon or license. Malware scanner for sites and app uploads with built-in signatures (PHP web shells, eval/decode droppers, request-driven exec, PHP hidden in images, SEO-spam `.htaccess` redirects, obfuscation, injected JS): changed files hourly, everything weekly, quarantine (reversible, root-only), ignore until the file changes, Telegram alert; optional ClamAV deep scan installed on demand. IP reputation: Spamhaus DROP blocked both ways and abuse.ch Feodo botnet controllers outbound, daily, in nftables. WordPress login/xmlrpc brute force read from the edge logs: the address is dropped in the kernel and answered 429 by the edge (works behind Cloudflare). Turning any of it off, restoring or ignoring a file needs a 2FA code. |
| Realtime | Pusher-compatible WebSockets on demand (Sockudo, MIT, one static binary): pusher-js, Laravel Echo and Pusher server SDKs work unchanged. Apps with id/key/secret, allowed origins, public wss domain through the edge, one click to put PUSHER_* / NEXT_PUBLIC_PUSHER_* into an app. Updates itself daily within its major version (checksum-verified, health-checked with a signed API call, rolled back on failure); nothing on disk until installed. |
| TURN | Relay for WebRTC calls and peer-to-peer game data on demand (coturn): apps get TURN_URLS and TURN_SECRET and hand each user credentials that expire in an hour; relaying to this host, private, CGNAT/Tailscale and multicast addresses is refused; per-user and total quotas; the process locked down (no new privileges, read-only system, syscall filter, 512 MB cap). New secret in one click (apps get it and restart). An existing coturn is taken over with its secret and gets its own config back on uninstall. |
| Android builds (optional) | Nothing installed until asked (x86-64): JDK 17/21 (Temurin) and the Android SDK under `/opt/pano/android`, checksums verified. Each build runs in a throwaway sandbox made for it and removed after it (transient unit, DynamicUser, empty own directory, pano/apps/secrets out of sight, memory cap, low priority); only the APK/AAB (sha256) is kept. Signing with the upload/release keystore happens afterwards in a second throwaway sandbox without network, the key as systemd credentials: the project's code never sees it. Project settings and keystore need a fresh 2FA code. |
| Throwaway app builds (optional) | Per app: install and build see only the new release (no deploy key, data, env file or shared caches) and their caches are deleted afterwards. |
| Jobs | Cron jobs for apps and PHP sites (`schedule \| command`), all on one page with last/next run, result, duration, run now and logs. systemd timers, no cron daemon: nothing waits in memory, a job never overlaps itself, a missed run happens at boot, and a failed run is a Telegram alert. Crontabs left by the previous panel are listed read-only (passwords hidden) until moved. Under load, builds and cron jobs get a fifth and queue workers half of the CPU/disk share of web processes, so they never slow the sites. Queue monitor on demand: uses the Redis already on the server or installs Valkey, shows BullMQ and Laravel queues (waiting, active, delayed, failed, completed) and worker processes with restart, and alerts on new failures (at most every 15 min) and queues that stop moving for 10 min. |
| Alerts | Telegram: failed deploys, crons and backups at once; app or service down, disk over 85 %, memory almost full within a minute; once when it starts, once when it clears. |
| Guard | nftables, no daemon: SSH brute force (over 20 new connections a minute → banned 15 min) and per-address HTTP flood limit (off behind Cloudflare). WireGuard and localhost never limited. |
| Private access | Optional WireGuard network of your own (no coordination server, no account): devices by public key, or phone config + QR shown once; preshared key per device. Locks close SSH and admin/database ports to everything but the tunnel and serve the panel on the tunnel address; a new lock is undone automatically unless confirmed from inside the tunnel, so a mistake cannot lock you out. Optionally MariaDB/PostgreSQL/Valkey answer on the tunnel address for desktop clients (socket-activated forwarder, databases keep listening on 127.0.0.1 only). |
| Disk | Two releases per app (live + instant rollback); a release that never went live is removed at once. bun hard-links packages from a per-app store, Next.js keeps one build cache outside the releases (faster rebuilds). Journal capped at 300 MB. PostgreSQL WAL capped at 256 MB. |
| Backups | To one or two stores at once (for example R2 + Backblaze B2). Full archives: mysqldump / tar → gzip → **AES-256-GCM on the server** → streamed multipart upload, or incremental (restic, installed on demand): only changes uploaded, deduplicated and compressed, repository password derived from the same backup key, weekly prune. Stores: Cloudflare R2, Backblaze B2, Hetzner Object Storage, Wasabi, AWS S3 or MinIO (region taken from the endpoint). Hourly, daily or weekly, retention, restore. The store only ever sees ciphertext. A store can be marked protected: pano never deletes from it (retention by the store's lifecycle rule), so a stolen server cannot wipe its backups. |
| Disaster recovery | The panel backs itself up daily (state, settings, edge certs). The recovery kit (one line: backup key + stores, shown with 2FA) and `pano install && pano recover` on a new server bring back admins, services, runtimes, apps (env, data, deploy keys), databases with their users, PHP sites and their files, realtime/TURN, then redeploy every app. |
| Updates | `pano update <binary> <sha256>` checks the sha256, runs the new binary first (unprivileged), refuses downgrades, keeps the old one and a copy of the state, rolls back by itself if the panel does not come up within a minute; `pano update-rollback`. |
| Import | Reads a CyberPanel/OLS server (vhosts, proxies, PHP versions, certificates, suspended sites, databases, the systemd/PM2 services behind each port) into pano. Read-only until cutover. Legacy sites can then be moved one by one onto pano PHP (files copied, `deny from all` directories stay closed, one-click revert). |
| cPanel | Imports `cpmove-USER.tar.gz` full backups: one PHP site per domain (main, addon, subdomain, parked as aliases), databases loaded by their own user (never root), users recreated with their original password hashes, `.htaccess` deny rules kept, escaping symlinks removed. Mail, cron, DNS and FTP are listed for manual follow-up. |
| Vulnerabilities | Nightly (and on request): distribution security advisories (dnf updateinfo), OSV.dev for every app and site lockfile (bun.lock, package-lock.json, composer.lock) and the edge/realtime binaries, nodejs.org security releases for installed Node.js, php.net for installed PHP, wordpress.org for WordPress cores. New high/critical findings go to Telegram. Automatic: OS security updates daily (dnf-automatic, never reboots by itself, a needed reboot is shown), PHP patch releases nightly, the edge (Caddy) to a newer patch, or the newest 2.x when the running one is vulnerable, rolled back if it does not come up. App dependencies and WordPress plugins are reported, not changed. |
| Performance | Sized to the machine: BBR and fq, larger accept queues and UDP buffers for HTTP/3, swappiness 10, a journal capped at 500 MB; MariaDB buffer pool, PostgreSQL shared buffers and Valkey memory as a share of RAM; PHP opcache 128 MB / 20 000 files and a realpath cache; a week of browser caching for static files of PHP and static sites unless the site sets its own; HTTP/3 and zstd/gzip at the edge. The kernel settings are one switch (Security page). |
| Security | Read-only audit (public ports, firewall, SSH, MariaDB bind, CyberPanel leftovers, OLS admin, auto-updates, SELinux, backups) with the exact fix command for each finding. |

## Security model

- **Privilege separation.** `pano-web` (UI) runs as the unprivileged `pano` user in a hardened systemd sandbox and can only talk to
  `pano-agent` over a unix socket (`root:pano 0660`). The agent exposes a fixed list of typed operations, validates every argument and never
  runs a caller-supplied shell command as root.
- **Apps are isolated.** Each app has its own system user and directory; units use `ProtectSystem=strict`, `NoNewPrivileges`, an empty
  capability set, a syscall filter and a memory cap, no access to cloud metadata (169.254.169.254) or other users' processes. Builds run in a
  transient `systemd-run` sandbox as the app user.
- **Panel is never public.** It listens on `127.0.0.1` (SSH tunnel) or a Tailscale address. Only `/hooks/*` can be exposed through the edge for GitHub.
- **Login:** argon2id + mandatory TOTP, lockout after 5 failures, hashed session ids, 30 min idle / 12 h absolute expiry, `SameSite=Strict`
  cookies, CSRF tokens + origin checks, strict CSP.
- **2FA is enforced by the agent, not the UI.** TOTP secrets live root-only with the agent; the web process can ask whether a code is right
  but cannot make one (5 wrong codes lock the user for 15 minutes, each code works once). Revealing a secret (env values, webhook secret,
  Valkey password, backup key), changing env or what an app runs (repository, branch, commands), dropping/restoring data, adding a VPN device
  and cutover all need a fresh code checked by the agent. So even a fully compromised `pano-web` cannot read secrets, plant code into an app
  or open the network. Root's `pano rpc` uses a root-only token instead.
- **Env values are masked.** The UI shows keys and `••••••••`; a masked line is kept as is when saving. "+ Database" creates the database and
  its own user and writes `DATABASE_URL`/`REDIS_URL` straight into the app's env: the password never passes through the browser.
- **Secrets:** R2 secret and backup key are root-only files and write-only from the UI. Every action is in the audit log.
- **Independent of CyberPanel.** pano keeps its own binary, runtimes, Caddy, users and units; CyberPanel/OS updates do not change them.

## Install (AlmaLinux/Rocky 9, Debian/Ubuntu)

```sh
bun install && bun run build          # → dist/pano (linux-x64); build:arm for arm64
scp dist/pano root@server:/tmp/pano
ssh root@server '/tmp/pano install && /opt/pano/bin/pano admin you'
ssh -L 7800:127.0.0.1:7800 root@server   # then open http://127.0.0.1:7800
```

From a release (tagged builds for x64/arm64, checked against `SHA256SUMS` before anything runs; while the repo is private set `GITHUB_TOKEN`):

```sh
curl -fsSL https://raw.githubusercontent.com/agtt/pano/main/install.sh | sudo sh   # PANO_VERSION=x.y.z pins one
sudo pano update --latest                                                          # later: download, verify, update with rollback
```

`install` creates the `pano` user, directories and the `pano-agent` / `pano-web` units. Nothing public changes.

## Migrating from CyberPanel

1. **Import** → *Scan server* → review → *Import selected*. CyberPanel keeps serving.
2. Fix the warnings (WordPress `X-Forwarded-Proto` snippet, ask URL for catch-all sites).
3. **Edge** → *Install Caddy* → check the Caddyfile preview.
4. **Edge** → *Cutover*: OpenLiteSpeed moves to `127.0.0.1:8088` (PHP sites keep running behind the edge), Caddy takes :80/:443,
   every domain is probed. If Caddy fails to start the old config is restored automatically; *Rollback* undoes it any time.
5. **Sites** → a legacy site → *Move to pano PHP*, one site at a time (revert any time). When no legacy site is left,
   OpenLiteSpeed can be stopped.
6. After a few quiet days: `systemctl disable --now lscpd fastapi_ssh_server` (see Security).

Running Node apps (PM2, systemd) are imported as *external* apps first (status, logs, restart). To let pano build and
deploy them, create a managed app from the same repository; a monorepo such as several Next.js apps plus a worker
becomes one app with several processes.

## Migrating from cPanel

1. On the cPanel server: `/scripts/pkgacct USER` (or cPanel → Backup → Download a Full Account Backup).
2. `scp cpmove-USER.tar.gz root@new-server:/var/lib/pano/imports/`
3. **Import** → cPanel → *Scan* → review → *Import selected*. Test with a hosts-file entry, then switch DNS.

## Development

```sh
bun install
bun run dev          # agent + web in one process, paths under dev/root, commands only logged
bun run dev/otp.ts   # current 2FA code for admin / pano-dev-password
bun test
bun run typecheck
dev/vm.sh            # full test in an OrbStack AlmaLinux 9 VM (real systemd, MariaDB, OpenLiteSpeed)
dev/vm-e2e.sh        # then: import, deploy Next.js/Bun, cutover, zero-downtime redeploy, rollback
dev/vm-e2e-php.sh    # then: monorepo app, PHP site, OLS → PHP move/revert, cPanel import
dev/vm-e2e-containers.sh  # then: enable Podman, nginx behind the edge, Redis template
dev/vm-e2e-backup.sh      # then: two destinations, full + incremental (restic) backups and restores against dev/s3-mock.ts
dev/vm-e2e-jobs.sh        # then: PHP site cron, run now, old crontab, queue monitor, worker CPU share
dev/vm-e2e-vulns.sh       # then: dnf-automatic on, a scan (distro advisories, OSV, Node, PHP)
dev/vm-e2e-turn.sh        # then: TURN install, STUN, allocation, private peer refused, rotate, uninstall (+ -adopt.sh)
dev/vm-e2e-realtime.sh    # then: realtime install from the release, app, signed API call, uninstall
dev/vm-e2e-tune.sh        # then: kernel/journal defaults, opcache, static file caching
dev/vm-e2e-recovery.sh    # then: protected store, recovery kit, a brand-new VM recovered with `pano recover`
dev/vm-e2e-update.sh      # then: pano update, refused binaries, automatic and manual rollback
dev/vm-e2e-shield.sh      # then: planted web shells, quarantine/restore, reputation lists, login brute force
dev/vm-e2e-ops.sh         # then: bun installs, cron, rollback, MariaDB into env, databases over WireGuard, SSH guard
dev/vm-e2e-secrets.sh     # then: + Database into an app env, masked env, agent-side 2FA, a compromised pano-web
dev/vm-e2e-env.sh         # then: shared variable groups, restart/redeploy hints, preview-only values, connecting existing databases
dev/vm-e2e-sqlite.sh      # then: SQLite in DATA_DIR backed up consistently under constant writes (archive and restic), restored
dev/vm-e2e-vpn-services.sh  # then: WireGuard from a netns "laptop", locks + auto-undo, PostgreSQL/Valkey on demand
```

Layout: `src/agent` (root: state, apps, php, edge, backups, importer, cpanel, cutover, audit), `src/web` (UI, auth), `src/shared` (paths, validation).

## Roadmap

CyberPanel backup files from another server · Android builds on push · staging copies of PHP sites ·
DNS-01 / Cloudflare Origin CA certificates · admin roles · mail (deliberately out of scope).

## License

MIT
