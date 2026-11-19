# pano

A lightweight, security-first server panel for **Next.js, Node.js, Bun and Python (Django, FastAPI, Flask)** apps (monorepos included) and
**PHP sites**, with MariaDB management, encrypted **Cloudflare R2** backups, and migration off **CyberPanel/OpenLiteSpeed**
and **cPanel**.

One self-contained binary, no Docker, no Python needed to run it; PHP and Python are installed only when a PHP site or a Python app needs them. Measured in the test VM
(AlmaLinux 9): web ≈ 7 MB, agent ≈ 25–70 MB, Caddy edge ≈ 55 MB RAM; a deployed Next.js app ≈ 45 MB, a Bun app ≈ 4–13 MB,
an idle PHP site (its own pool, PHP 8.5) ≈ 11–20 MB.

## What it does

| Area | |
|---|---|
| Apps | git → sandboxed install/build → blue/green systemd slots → health check → traffic switch. Zero-downtime deploys, one-click rollback to the previous release (kept on disk: no build, seconds), per-app env, logs, memory limits, cron jobs (systemd timers in the live release, same user/env/sandbox, never overlapping, missed runs catch up). bun is the package manager for every app (installed automatically; reads package-lock/yarn/pnpm lockfiles with their exact versions); Node.js apps still run on node. `DATA_DIR` is a per-app directory kept across deploys (SQLite, uploads) and included in app backups (SQLite databases as a consistent copy, even while the app writes). |
| Git | Push-to-deploy from GitHub, GitLab, Gitea, Forgejo (webhook per app, HMAC or token checked in constant time; can be switched off per app). Optional GitHub connection (one fine-grained token, root-only): repository picker, one-click link (read-only deploy key + webhook) and a `pano/deploy` commit status on every deploy, Vercel-style. Preview deploys per branch, with the preview link commented (and kept up to date) on the branch's open pull requests; previews live under a zone of their own (`*.preview.example.com`) and, unless you choose otherwise, get no secret-looking or shared-group variables from production. |
| Environment | Per-app variables (masked, 2FA to show or change), preview-only values (a test payment key for branch previews), shared variable groups used by several apps (root-only, the app's own value wins), and a hint on the app page when a restart, or for variables built into the code (`NEXT_PUBLIC_*`, `VITE_*`, …) a redeploy, would apply changed values. |
| Python apps (optional) | Django, FastAPI, Flask or any WSGI/ASGI app through the same pipeline as Node.js apps (git → sandboxed build → blue/green slots → health check → traffic switch → rollback; env, logs, memory limits, cron jobs, `DATA_DIR`, previews and webhooks work unchanged). Nothing of Python (interpreter, uv, build packages, units) exists on a server until the first Python app deploys or you install a version on the Runtimes page; delete the last version and uv goes with it. Interpreters are [python-build-standalone](https://github.com/astral-sh/python-build-standalone) builds, side by side under `/opt/pano/runtimes/python/<x.y.z>`, checked against the release's SHA-256 list (an app pins `3.14` to the exact patch at its first deploy); packages come from [uv](https://github.com/astral-sh/uv) (checksum-verified too) into one virtualenv per release, never the system's Python or pip. Dependencies from `uv.lock` (`uv sync --locked`), `poetry.lock`, `requirements.txt` / `requirements/production.txt` (or a configured file; `--require-hashes` when it has hashes) or `pyproject.toml`. gunicorn (WSGI) or uvicorn (ASGI) on `127.0.0.1:$PORT`, detected from `manage.py`, `wsgi.py`/`asgi.py`, `app.py`/`main.py` or set as `module:attr` / a start command (missing servers are installed into the venv with a note). Django: `collectstatic --noinput` in the build, `migrate --noinput` once per release before the traffic switch (a failure switches nothing; keep migrations compatible with the running release, a rollback does not undo them), collected static files copied as root-owned regular files (every source file verified by its descriptor, never by path) and served by the edge itself; previews get no edge-served copy and never migrate by default (with migrate set to Always the guard against a shared database is a name/value heuristic). Native wheels (mysqlclient, psycopg2, python-ldap) pull their `-devel` packages and gcc from the distribution (AlmaLinux/Rocky 9, Debian 11–13, Ubuntu 22.04/24.04) on first need. |
| Runtimes | Any Node.js / Bun version (and, on demand, Python) side by side under `/opt/pano/runtimes`, checksum-verified. Apps pin their own version; OS updates never change them. |
| Edge | Caddy (pinned, checksum-verified) on :80/:443: automatic HTTPS, HTTP/3, on-demand TLS for customer domains, Cloudflare real-IP. Optional Cloudflare lock (80/443 only from Cloudflare's ranges; those are shared by all Cloudflare customers, so add Authenticated Origin Pulls for a lock bound to your zone). Config is rendered from state and validated before every reload. |
| Monorepos | One build, several processes: `name \| dir \| routes \| memory \| start` per line. Routes are hosts, `host/path`, `*.host` or `*` (any host, on-demand TLS with an ask URL). Web processes get blue/green slots and health checks; workers have no port and never run twice (old one stops before the new one starts). |
| PHP sites | PHP 7.4–8.5 (Remi on AlmaLinux/Rocky, Ondřej Surý's on Debian/Ubuntu; signed) installed on first use; WordPress tools (one-click install, updates, maintenance mode, password reset) with a verified wp-cli run as the site user. Each site: its own system user, its own PHP-FPM pool running as that user (never root, `pm=ondemand`, hardened unit with `MemoryDenyWriteExecute`), socket only the edge can open (ACL), `open_basedir`, dangerous functions off, secure session cookies. The edge never serves dotfiles, dumps/backups, composer files or PHP inside uploads. Patch releases arrive with OS updates; pools reload onto the new binary. |
| Sites | Proxy (path → port routes), static, PHP, and legacy sites still served by the old OpenLiteSpeed on localhost. Suspend a site, an app or a whole project (with a reason): the edge keeps the domains and certificates and answers with a plain "This site is suspended" page (503), while PHP pools, app processes, cron jobs and previews stop until resumed. Per site/app "Redirect HTTP to HTTPS" (off for imported OpenLiteSpeed sites, or for Cloudflare "Flexible" SSL). |
| Containers (optional) | Off until enabled; then Podman comes from the distribution (no daemon, nothing runs without a container). Each container is a Quadlet systemd unit in its own user namespace (root inside = unprivileged uid outside), memory/pids capped, published on 127.0.0.1 only, HTTPS through the edge when given a domain. Templates: Redis, PostgreSQL, Meilisearch, Uptime Kuma, n8n; empty passwords/keys are generated. |
| Databases | MariaDB/MySQL: list with sizes and grants, create db + user, reset passwords, drop (with 2FA). Any existing MariaDB or PostgreSQL database (imported, or another app's) can be connected to an app: it gets a user of its own for that database only, written into its env. |
| Services | MariaDB, PostgreSQL (latest major from postgresql.org, signed) and Valkey (Redis-compatible) installed on demand, natively, on 127.0.0.1 only, with small memory settings and passwords (scram-sha-256 / requirepass). PostgreSQL databases with their own role, `DATABASE_URL` shown once; every database pano creates (and every app) gets a daily encrypted backup job automatically (runs once R2 is set up). An existing MariaDB (CyberPanel) is used as is, never reconfigured. |
| Shield | Imunify-style, no daemon or license. Malware scanner for sites and app uploads with built-in signatures (PHP web shells, eval/decode droppers, request-driven exec, PHP hidden in images, SEO-spam `.htaccess` redirects, obfuscation, injected JS): changed files hourly, everything weekly, quarantine (reversible, root-only), ignore until the file changes, Telegram alert; optional ClamAV deep scan installed on demand. IP reputation: Spamhaus DROP blocked both ways and abuse.ch Feodo botnet controllers outbound, daily, in nftables. WordPress login/xmlrpc brute force read from the edge logs: the address is dropped in the kernel and answered 429 by the edge (works behind Cloudflare). Turning any of it off, restoring or ignoring a file needs a 2FA code. |
| Realtime | Pusher-compatible WebSockets on demand (Sockudo, MIT, one static binary): pusher-js, Laravel Echo and Pusher server SDKs work unchanged. Apps with id/key/secret, allowed origins, public wss domain through the edge, one click to put PUSHER_* / NEXT_PUBLIC_PUSHER_* into an app. Updates itself daily within its major version (checksum-verified, health-checked with a signed API call, rolled back on failure); nothing on disk until installed. |
| TURN | Relay for WebRTC calls and peer-to-peer game data on demand (coturn): apps get TURN_URLS and TURN_SECRET and hand each user credentials that expire in an hour; relaying to this host, private, CGNAT/Tailscale and multicast addresses is refused; per-user and total quotas; the process locked down (no new privileges, read-only system, syscall filter, 512 MB cap). New secret in one click (apps get it and restart). An existing coturn is taken over with its secret and gets its own config back on uninstall. |
| Android builds (optional) | Nothing installed until asked (x86-64): JDK 17/21 (Temurin) and the Android SDK under `/opt/pano/android`, checksums verified. Each build runs in a throwaway sandbox made for it and removed after it (transient unit, DynamicUser, empty own directory, pano/apps/secrets out of sight, memory cap, low priority); the APK/AAB (sha256) and a per-project download cache are kept. Signing with the upload/release keystore happens afterwards in a second throwaway sandbox without network, the key as systemd credentials: the project's code never sees it. Project settings and keystore need a fresh 2FA code. |
| Runner (optional) | Heavy commands from your laptop (or a coding agent on it) run on the server: `tools/pano-remote -p android/app/build/outputs -- ./gradlew assembleDebug` syncs the project with rsync, runs it in a sandbox (memory cap, time limit, low priority, pano/apps out of sight) with warm Gradle/npm/bun caches and incremental build outputs, streams the output and copies the results back. SSH only with keys added on the Runner page (2FA), each held to a forced command. |
| Throwaway app builds (optional) | Per app: install and build see only the new release (no deploy key, data, env file or shared caches) and their caches are deleted afterwards. |
| Jobs | Cron jobs for apps and PHP sites (`schedule \| command`), all on one page with last/next run, result, duration, run now and logs. systemd timers, no cron daemon: nothing waits in memory, a job never overlaps itself, a missed run happens at boot, and a failed run is a Telegram alert. Crontabs left by the previous panel are listed read-only (passwords hidden) until moved. Under load, builds and cron jobs get a fifth and queue workers half of the CPU/disk share of web processes, so they never slow the sites. Queue monitor on demand: uses the Redis already on the server or installs Valkey, shows BullMQ and Laravel queues (waiting, active, delayed, failed, completed) and worker processes with restart, and alerts on new failures (at most every 15 min) and queues that stop moving for 10 min. |
| Alerts | Telegram: failed deploys, crons and backups at once; app or service down, disk over 85 %, memory almost full within a minute; once when it starts, once when it clears. |
| Guard | nftables, no daemon: SSH brute force (over 20 completed connections a minute → banned 15 min; spoofed SYNs never count) and per-address HTTP flood limit (off behind Cloudflare). WireGuard and localhost never limited. |
| Private access | Optional WireGuard network of your own (no coordination server, no account): devices by public key, or phone config + QR shown once; preshared key per device. Locks close SSH and admin/database ports to everything but the tunnel and serve the panel on the tunnel address; a new lock is undone automatically unless confirmed from inside the tunnel, so a mistake cannot lock you out. Optionally MariaDB/PostgreSQL/Valkey answer on the tunnel address for desktop clients (socket-activated forwarder, databases keep listening on 127.0.0.1 only). |
| Disk | Two releases per app (live + instant rollback); a release that never went live is removed at once. bun hard-links packages from a per-app store, Next.js keeps one build cache outside the releases (faster rebuilds). Journal capped at 300 MB. PostgreSQL WAL capped at 256 MB. |
| Backups | To one or two stores at once (for example R2 + Backblaze B2). Full archives: mysqldump / tar → gzip → **AES-256-GCM on the server** → streamed multipart upload, or incremental (restic, installed on demand): only changes uploaded, deduplicated and compressed, repository password derived from the same backup key, weekly prune. Stores: Cloudflare R2, Backblaze B2, Hetzner Object Storage, Wasabi, AWS S3 or MinIO (region taken from the endpoint). Hourly, daily or weekly, retention, restore. The store only ever sees ciphertext. A store can be marked protected: pano never deletes from it (retention by the store's lifecycle rule), so a stolen server cannot wipe its backups. |
| Disaster recovery | The panel backs itself up daily (state, settings, edge certs). The recovery kit (one line: backup key + stores, shown with 2FA) and `pano install && pano recover` on a new server bring back admins, services, runtimes, apps (env, data, deploy keys), databases with their users, PHP sites and their files, realtime/TURN, then redeploy every app. |
| Updates | `pano update <binary> <sha256>` checks the sha256, runs the new binary first (unprivileged), refuses downgrades, keeps the old one and a copy of the state, rolls back by itself if the panel does not come up within a minute; `pano update-rollback`. |
| Import | Reads a CyberPanel/OLS server (vhosts, proxies, PHP versions, certificates, suspended sites, databases, the systemd/PM2 services behind each port) into pano. Read-only until cutover. Legacy sites can then be moved one by one onto pano PHP (files copied, `deny from all` directories stay closed, one-click revert). |
| cPanel | Imports `cpmove-USER.tar.gz` full backups: one PHP site per domain (main, addon, subdomain, parked as aliases), databases loaded by their own user (never root), users recreated with their original password hashes, `.htaccess` deny rules kept, escaping symlinks removed. Mail, cron, DNS and FTP are listed for manual follow-up. |
| Vulnerabilities | Nightly (and on request): distribution security advisories (dnf updateinfo), OSV.dev for every app and site lockfile (bun.lock, package-lock.json, composer.lock) and the edge/realtime binaries, nodejs.org security releases for installed Node.js, php.net for installed PHP, wordpress.org for WordPress cores. New high/critical findings go to Telegram. Automatic: OS security updates daily (dnf-automatic; a needed reboot is shown, done with one click or, opt-in, in the night window of a chosen weekday, at most once a month (4 weeks after the last boot): checked before (nothing deploying, fstab, ports 80/443 free for the edge), a new kernel tried once with the old one as the way back, every service that ran before checked and restarted after), PHP patch releases nightly, the edge (Caddy) to a newer patch, or the newest 2.x when the running one is vulnerable, rolled back if it does not come up. App dependencies and WordPress plugins are reported, not changed. |
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
  but cannot make one (5 wrong codes lock the user for 15 minutes, each code works once). Root's `pano rpc` uses a root-only token instead.
  - *Trusted window.* Signing in or any verified code trusts that admin's session for 15 minutes (or until "Lock"): routine guarded actions
    (saving env values, an app's domains, a site's redirect/www/TLS options or removing one of its domains, databases for an app, backup
    jobs, shield settings, suspending, a safe reboot, …) skip the code.
  - *Always ask.* These take only a code sent with that very call, never the window or a grant: revealing a secret (env and shared values,
    container env, webhook/realtime/TURN secrets, Valkey URL, backup key, recovery kit, WordPress or database password resets); changing
    what runs (creating an app; repository, branch, directory, runtime, commands, processes, crons, shared groups or build isolation of an app;
    a variable such as `NODE_OPTIONS`, `LD_PRELOAD`, `PATH` or a proxy; site crons, containers, Android projects, restoring a quarantined
    file); what a site is (creating one, its kind, static root, proxy routes and redirects, adding or moving a domain, using another site's
    certificate); the network and its locks (VPN devices and locks, firewall off or ports, Cloudflare lock, guard, remote database access);
    lasting access (runner on and keys, GitHub token, backup destination, cPanel import, alert channel, admins, granting a database user
    access to a database); and deleting, restoring or cutover.
  - *Grants.* A verified code also returns a 60 s grant, good only for repeating that same call (method and params), never for an always-ask one.
  - *What this guarantees.* A compromised `pano-web` cannot read secrets, plant code into an app, publish a directory, send a domain's
    visitors to a port or address of its choosing, give a database user it knows access to an existing database or open the network on
    its own, not even right after an admin signs in. Inside a trusted window it can make the routine changes above, which apps act on (an
    ordinary variable such as a mail host is one; a domain removed from a site and added to an app reaches that app's own code). Static
    roots are never inside pano's own directories (`/srv/pano`: other sites, apps, containers) and no route points at pano's own ports.
    The code still travels through it, so it can spend a code the admin types on one always-ask action of its own choosing instead of the
    admin's. Adding an admin, a runner key, a VPN device, a remote database user, a GitHub token or a backup destination, turning the
    runner on, exporting the backup key or recovery kit, resetting an admin's 2FA and changing the alert channel are therefore also
    reported on Telegram (when alerts are set up), before the action runs.
- **Env values are masked.** The UI shows keys and `••••••••`; a masked line is kept as is when saving. "+ Database" creates the database and
  its own user and writes `DATABASE_URL`/`REDIS_URL` straight into the app's env: the password never passes through the browser.
- **Secrets:** R2 secret and backup key are root-only files and write-only from the UI. Every action is in the audit log.
- **Independent of CyberPanel.** pano keeps its own binary, runtimes, Caddy, users and units; CyberPanel/OS updates do not change them.
- **Signed releases.** The installer and `pano update` run only artifacts listed in a `SHA256SUMS` signed by the release key. The
  release workflow signs whatever a `v*` tag points at, so keep that key in a GitHub environment with a required reviewer and limit who
  can push tags ([SECURITY.md](SECURITY.md#releases)).
- **Reporting a vulnerability:** privately through GitHub's "Report a vulnerability" (Security tab); see [SECURITY.md](SECURITY.md).

## Install (AlmaLinux/Rocky 9, Debian/Ubuntu)

On a new server, as root:

```sh
curl -fsSL https://raw.githubusercontent.com/agtt/pano/main/install.sh | sh
```

No questions. When it finishes it prints:

- how to open the panel: an SSH tunnel line, or an HTTPS address on your tailnet when the server runs Tailscale;
- the `admin` password (shown once) and a QR code for your authenticator app. They go to standard output: when the installer runs from
  cloud-init or another logged session they also stay in that log (`/var/log/cloud-init-output.log`), so reset them there with
  `pano admin admin` afterwards;
- whether the web server started: on a server with nothing on ports 80/443, Caddy starts right away and sites get HTTPS automatically. A server that already runs a web server (CyberPanel, nginx, Apache) keeps it until you move it from the panel (Server > Edge).

Then add sites and apps in the panel and connect backup storage (Backups).

Later updates: `pano update --latest` (download, verify the signature, update, keep the previous version for `pano update-rollback`). Running the installer again also updates; it never touches the admin, the edge or the panel address a second time.

Options: `PANO_VERSION=x.y.z` installs a given release, `PANO_NO_EDGE=1` leaves ports 80/443 alone, `PANO_NO_TAILSCALE=1` does not publish
the panel with `tailscale serve` (otherwise every device and user of the tailnet, shared nodes included, reaches the login page). Releases are checked against the signed `SHA256SUMS` before anything runs.

From source: `bun install && bun run build`, copy `dist/pano` to the server and run `./pano install` as root.

### Supported systems

AlmaLinux/Rocky 9, Debian 11–13, Ubuntu 22.04/24.04 (systemd, root access).

PHP sites additionally need the edge's **no-symlink view**: the site files are bind-mounted read-only with `nosymfollow`, so a link a
site plants (to a TLS key, to another site's `wp-config.php`) is never followed by the edge. That takes Linux 5.10+ (the
`nosymfollow` flag) **and util-linux 2.38+**: mount 2.37 knows the option but drops it on a bind mount (fixed upstream in util-linux
commit `36a3923`, "mount: Allow bind-mounting with nosymfollow"). pano checks the mount in `/proc/*/mountinfo`, not the version, so a
distribution that backports the fix works too.

| System | Kernel | util-linux | PHP sites |
|---|---|---|---|
| Debian 12 / 13 | 6.1 / 6.12 | 2.38.1 / 2.41 | served |
| Ubuntu 24.04 | 6.8 | 2.39.3 | served |
| Ubuntu 22.04 | 5.15 | 2.37.2 | held offline |
| AlmaLinux/Rocky 9 | 5.14 | 2.37.4 | held offline |
| Debian 11 | 5.10 | 2.36.1 | held offline |

Where the view cannot be mounted pano fails closed: every PHP site answers `503`, the Security page shows it as a failure and each agent
start (and every day) sends an alert. Apps, proxy and static sites, and sites kept on OpenLiteSpeed are not affected. To serve PHP sites
there anyway, accepting that a site can read other sites' files and TLS keys through a symlink until the daily sweep removes it, root sets
`PANO_EDGE_FOLLOW_LINKS=1` in `/etc/pano/pano.env` and restarts `pano-agent`.

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
dev/vm-e2e-python.sh      # then: no Python before the first app, Django (collectstatic, migrate before the switch, static from the edge, failing migration, rollback, cron), FastAPI, runtime removed with the last app
dev/vm-e2e-sqlite.sh      # then: SQLite in DATA_DIR backed up consistently under constant writes (archive and restic), restored
dev/vm-e2e-vpn-services.sh  # then: WireGuard from a netns "laptop", locks + auto-undo, PostgreSQL/Valkey on demand
```

Layout: `src/agent` (root: state, apps, php, edge, backups, importer, cpanel, cutover, audit), `src/web` (UI, auth), `src/shared` (paths, validation).

## Roadmap

CyberPanel backup files from another server · Android builds on push · staging copies of PHP sites ·
DNS-01 / Cloudflare Origin CA certificates · admin roles · mail (deliberately out of scope).

## License

MIT
