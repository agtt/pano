# pano (working name) — feature overview

Open-source (MIT), self-hosted server panel for one or a few Linux servers (AlmaLinux/Rocky 9, Debian/Ubuntu).
Built for modern apps (Next.js, Node.js, Bun, Python/Django, monorepos) and simple PHP/WordPress sites, with security first and a small
footprint. One self-contained binary written in TypeScript on Bun; no Docker, no Python needed to run it, no license server. Everything
optional is installed only when asked for, so nothing unused sits on disk or in memory.

Footprint (measured): panel UI ≈ 7 MB RAM, root agent ≈ 25–70 MB, Caddy edge ≈ 55 MB; a Next.js app ≈ 45 MB, a Bun app
≈ 4–13 MB, an idle PHP site with its own PHP-FPM pool ≈ 11–20 MB.

## What it replaces

| Today | pano instead |
|---|---|
| cPanel/WHM, CyberPanel, CloudPanel, Plesk (single-server hosting) | Sites, PHP, databases, TLS, backups, cron, security in one panel; imports cPanel `cpmove` backups and live CyberPanel servers |
| Vercel / Netlify / Coolify / Dokploy (app hosting, push-to-deploy) | Git push-to-deploy with zero-downtime blue/green releases and instant rollback, on your own server |
| PM2 + nginx by hand | systemd units per app + Caddy edge, rendered and validated by the panel |
| ImunifyAV / Maldet (basic), fail2ban | Shield: malware scanner, quarantine, login brute-force protection, reputation blocklists (not a WAF, EDR or DDoS protection) |
| JetBackup / Acronis / custom backup scripts | Encrypted full or incremental (restic) backups to one or two S3 stores at once |
| Pusher / Ably (paid realtime) | Pusher-compatible WebSockets (Sockudo) on demand |
| Twilio TURN / Xirsys | TURN relay (coturn) for WebRTC calls and P2P games on demand |
| Tailscale (for admin access) | Built-in WireGuard private network with SSH/panel locks |
| Cronitor / Bull Board / Horizon (basic) | Jobs page: crons of apps and sites, queue monitor (BullMQ, Laravel) with alerts |
| Snyk / Dependabot alerts (basic), unattended-upgrades | Nightly CVE scan + automatic OS/PHP/edge security patching; actively exploited holes (CISA KEV, EPSS) patched within hours |
| Docker for a few services | Optional Podman containers (daemonless), off by default |

## Features

**Apps (Next.js, Node.js, Bun)**
- Git → sandboxed build → blue/green systemd slots → health check → traffic switch; zero-downtime deploys (the old process gets up to 20 s to finish requests; database migrations must stay backward compatible, a code rollback does not roll back the database), one-click rollback (previous release kept, no rebuild).
- bun as package manager for every app (reads npm/yarn/pnpm lockfiles); any Node.js/Bun version side by side, pinned per app, checksum-verified.
- Monorepos: one build, several processes (web + workers), per-process routes, memory limits.
- Per-app env (masked in the UI), logs, cron jobs, persistent `DATA_DIR` (SQLite, uploads) included in backups.
- Env like Vercel's: production values, preview-only values (never seen by the live app), shared variable groups for several apps (root-only files, the app's own value wins); the app page names the variables a restart would apply, and those built into the code (`NEXT_PUBLIC_*`, `VITE_*`, `PUBLIC_*`, …) that need a redeploy.
- Push-to-deploy from GitHub, GitLab, Gitea, Forgejo; optional GitHub connection with repo picker, deploy keys and commit status.
- Preview deploys: pushes to other branches build `<branch>.<preview domain>` as an isolated app (own user, ports, `DATA_DIR`, env minus prod-only vars plus preview-only values), TLS only for existing previews; removed on branch delete, after a TTL (7 days) or past the limit (3). With GitHub connected, the link is commented on the branch's open pull requests and updated on every build.

**Python apps (Django, FastAPI, Flask, any WSGI/ASGI app) — optional**
- Same pipeline as Node.js apps: git → sandboxed build → blue/green systemd slots → health check → traffic switch → instant rollback; per-app env, logs, memory limits, cron jobs (the release's venv first on PATH), `DATA_DIR`, previews and push-to-deploy.
- On demand, zero footprint otherwise: no interpreter, uv, build packages, unit or directory exists until the first Python app deploys or an admin installs a version (Runtimes page). Deleting the last version removes uv and `/opt/pano/runtimes/python`; distribution packages installed for native wheels (gcc, `-devel`) stay and are listed in the setting `python.os_packages`. Node.js apps never see Python on their PATH and Python apps never trigger the bun install.
- Runtime source: python-build-standalone (astral-sh) CPython builds, one directory per exact version beside Node/Bun, tarball checked against the release's `SHA256SUMS` (download URLs must stay on github.com/astral-sh); uv from astral-sh, checked against its published `.sha256`. Chosen over distro Python (versions differ per OS, no side by side) and over uv-managed Pythons (uv would download unverified). An app pins `3.14` to the exact patch it resolved to at the first deploy.
- Packages: one virtualenv per release (`<release>/.venv`, created by uv from the pinned interpreter, never the system's Python or pip); `uv.lock` → `uv sync --locked`, `poetry.lock` → poetry (run through uv) into the venv, `requirements.txt` / `requirements/production.txt|prod|deploy|main|base` or a configured file → `uv pip install -r` (`--require-hashes` when it has hashes), `pyproject.toml` → its dependencies. Install steps are argv (no shell) in the same transient sandbox as Node builds (`build_isolated` applies); an own install command replaces them and gets the empty venv.
- Start: gunicorn for WSGI, uvicorn for ASGI, bound to `127.0.0.1:$PORT` (edge-proxied), forwarded headers trusted from 127.0.0.1 only; detected from Django's `manage.py` / `wsgi.py` / `asgi.py` (channels or daphne → ASGI), `app.py`, `main.py`, `app/main.py`, or set (`module:attr`, server, workers, or a start command). A server missing from the dependencies is installed into the venv with a note in the log.
- Django (auto from `manage.py`, each overridable to always/never): `collectstatic --noinput` in the build, with the app's variables (skipped with an own build command; "auto" does not fail the deploy without `STATIC_ROOT`), and `migrate --noinput` as an explicit release step after the build and before anything of the new release starts: if it fails the deploy fails and the live release keeps serving. It runs against the live database, so migrations must work with the running release (add before you remove); a rollback does not undo them (and is refused when the older release's Python was uninstalled).
- Previews: built like the app, but the edge serves no static files for them (collectstatic still runs when configured, for apps that serve their own) and they never run `migrate` unless Django migrate is set to Always and the preview's environment shares no database or store with production. That check compares variable values and names with production's, so a database reached under other names or hard-coded in settings is not recognised: leave migrate on Auto/Never for apps whose previews could reach a shared database.
- Static files: STATIC_URL/STATIC_ROOT are read from Django (or listed as `/static | staticfiles`), copied at each deploy into `/srv/pano/static/<app>/<slot>/<n>` as root-owned regular files (copied as root from the app's tree without trusting any path: every file is opened without following links and must, by its descriptor's own path, lie under the app's releases directory and belong to the app's user; links, dot files and anything else skipped, size limits) and served by the Caddy edge itself; the switch flips with the slot. Uploaded media is not served this way (keep it in `DATA_DIR`).
- Native wheels: only packages without a Linux wheel need the OS: mysqlclient, psycopg2, python-ldap pull gcc and the `-devel` packages (AlmaLinux/Rocky 9: `mariadb-connector-c-devel`, `libpq-devel`, `openldap-devel`; Debian 12–13 / Ubuntu 22.04–24.04: `libmariadb-dev`, `libpq-dev`, `libldap2-dev`) the first time a deploy needs them. Pillow, lxml, cryptography, numpy and psycopg2-binary come as wheels and need nothing.
- Security: runs as the app's own unprivileged user with the same unit hardening as other apps, nothing listens beyond 127.0.0.1, repository files are read without following links, `PYTHON*` count as runtime variables for every app, `PIP_*`, `UV_*`, `POETRY_*` and `VIRTUAL_ENV` for Python apps only (2FA to change), the Python settings are guarded fields like the commands.

**Edge**
- Caddy: automatic HTTPS (Let's Encrypt), HTTP/3, zstd/gzip, on-demand TLS for customer domains, Cloudflare real IP, security headers.

**PHP sites and WordPress**
- PHP 7.4–8.5 installed on first use; versions past end of life are flagged in the UI and the security audit (meant only for migrated legacy sites); each site its own system user, own PHP-FPM pool and an OS-level sandbox (read-only system, no new privileges, syscall filter); `open_basedir` and disabled functions are an extra layer, not the boundary.
- Per-site PHP version switch with revert, site cron jobs, blocked paths, legacy sites can stay on OpenLiteSpeed during migration.
- Existing PHP apps (POS, small CMS, Laravel) and WordPress supported.
- AlmaLinux/Rocky/RHEL (Remi) and Debian 12–13 / Ubuntu 22.04–24.04 (Ondřej Surý's packages, signed keyring); the distro's own php-fpm service is masked, one pool per site.
- WordPress tools: one-click install on an empty site, core/plugin/theme updates (all or selected), maintenance mode, admin password reset (shown once), optional nightly minor-core + plugin updates. wp-cli is verified against its published sha512 and always runs as the site's own user.

**Databases and services (on demand)**
- MariaDB: databases, users, grants, sizes, password reset; PostgreSQL (latest major); Valkey (Redis-compatible); SQLite per app.
- "+ Database" creates DB + user and writes `DATABASE_URL`/`REDIS_URL` into the app env; the password never reaches the browser.
- PostgreSQL remote access for apps hosted elsewhere (Vercel, Netlify, …), off by default: TLS 1.2+ only with the edge's certificate for a name of its own (`sslmode=verify-full`), remote-only users (one database each, SCRAM, 40-character password, 20 connections) in a managed `pg_hba.conf` block, every other role refused from outside, optional source networks (e.g. Vercel Static IPs) enforced by pg_hba and every firewall pano runs (firewalld, its own, the VPN services lock). Certificate renewals are picked up automatically.
- MariaDB remote access, the same way: one drop-in file (works with CyberPanel's MariaDB too, removed when off), TLS 1.2+ with the edge's certificate, remote-only accounts (`REQUIRE SSL`, one database, 20 connections, locked while off) whose hosts follow the allowed networks, refused to turn on while any other account accepts non-local hosts. URLs for Prisma (`sslaccept=strict`) and mysql2/Drizzle (`ssl={"rejectUnauthorized":true}`); renewals via `FLUSH SSL`, no restart. Needs MariaDB 10.11+ (10.4+ if it already listens on every address).
- "Connect existing" gives an app its own user on a database that already exists (imported from cPanel/CyberPanel, or another app's), under any variable name; PostgreSQL roles join the database's owner so migrations work. Recovery brings these users back.
- Memory of each service sized to the server's RAM.

**Realtime and games (optional extensions, nothing on disk until installed)**
- Pusher-compatible WebSocket server (Sockudo): pusher-js, Laravel Echo and Pusher SDKs work unchanged; apps, keys, allowed origins, public wss domain, auto-update with rollback.
- Realtime apps: Pusher-style signed webhooks (occupancy, presence), optional per-app connection limit, env written under both Laravel and Pusher SDK names.
- TURN relay for WebRTC: short-lived per-user credentials, private networks refused, quotas, secret rotation; takes over an existing coturn.
- TURN over TLS (optional): `turns:` on 5349 with the edge's certificate for the TURN domain.
- WebSocket game servers (Colyseus, Socket.IO, uWS) run as normal apps.

**Jobs and queues**
- One page for all cron jobs (apps + PHP sites): last/next run, result, run now, logs; systemd timers, no overlap, missed runs catch up, failures alert.
- Queue monitor on demand: BullMQ and Laravel queues, workers with restart, alerts on failures and stuck queues.
- Builds, crons and workers get a lower CPU/disk share than websites so they never slow sites down.

**Backups**
- Full archives (AES-256-GCM, encrypted on the server) or incremental (restic: deduplicated, encrypted with restic's own AES-256-CTR + Poly1305-AES).
- SQLite databases in an app's `DATA_DIR` are backed up consistently while the app writes: each gets a `VACUUM INTO` copy (made as the app's user) that the backup holds instead of the live file and its `-wal`; restores put the copy in place.
- Each backup carries an authenticated header (kind, job, location, time): a restore refuses an object swapped in from another job or run.
- One or two destinations at once: Cloudflare R2, Backblaze B2, Hetzner Object Storage, Wasabi, AWS S3, MinIO.
- Hourly/daily/weekly schedules, retention, restore; the storage provider only sees ciphertext.
- Protected stores: pano never deletes from them (retention is left to the store's own lifecycle rule / object lock), so a stolen server key cannot wipe the backups; the store test shows whether the key could still delete.

**Disaster recovery**
- The panel backs itself up daily (state, settings, edge certificates) next to the app, database and site backups; every PHP site gets a file backup job.
- Recovery kit: one line (backup key + stores) shown with 2FA, kept in a password manager; the security audit warns when it is missing or out of date.
- `pano install` + `pano recover` on a new server: panel, admins, services (MariaDB/PostgreSQL/Valkey as the data needs), runtimes, app env/data/deploy keys, databases with the same users and passwords, PHP sites with their files, realtime/TURN, then every app deploys from git.

**Updating pano itself**
- `pano update <binary> <sha256>`: checksum required, the new binary must run first (as nobody), no silent downgrade; the old one and a copy of the state are kept; if the agent or UI does not answer within a minute it rolls back by itself; `pano update-rollback` by hand. Apps and sites keep serving throughout.
- Releases: tagged builds for x64/arm64 with `SHA256SUMS`; `install.sh` verifies before installing; `pano update --latest` downloads, verifies and updates with the same rollback.

**Security**
- Privilege separation: unprivileged web UI talks to a root agent over a unix socket with a fixed list of typed operations.
- Several admins (all equal, no roles): add, remove, reset password or 2FA from the panel, each change with your own code; a new admin's password and authenticator QR are shown once; you cannot remove yourself or the last admin.
- Panel never public (localhost via SSH tunnel, Tailscale or built-in WireGuard). Login: argon2id + mandatory TOTP, lockout, strict CSP/CSRF.
- 2FA enforced by the agent for every sensitive action. After sign-in or a verified code, routine ones skip the code for 15 minutes (a "Lock" button ends it early); revealing secrets, changing what runs (repository, commands, crons, runtime variables like `NODE_OPTIONS`), opening the network or a lock, lasting access (runner keys, VPN devices, GitHub token, backup destination, admins) and deleting/restoring always need a code sent with that action. A compromised UI process cannot read secrets or plant code on its own; it could only redirect a code the admin types, and codes used for lasting access are reported on Telegram.
- Apps and sites sandboxed (own user, read-only system, no new privileges, syscall filter, memory cap, no cloud metadata access).
- Shield: malware scanner with quarantine/restore, login brute-force bans, reputation blocklists. Guard: nftables SSH/HTTP flood protection.
- Optional default-deny inbound firewall (own nftables table, off by default since providers like Hetzner have one): SSH, 80/443, panel only if public, WireGuard, TURN and your extra ports; rolls itself back after 2 minutes unless confirmed from the panel.
- The panel answers only to its own address, localhost, the VPN address and names in `PANO_WEB_HOSTS` (DNS-rebinding guard).
- Containers run their image by digest (resolved on save, re-resolved only by "Update image"); optional read-only root filesystem.
- Vulnerabilities: nightly scan of OS advisories, app/site lockfiles (OSV.dev), Node.js, PHP, WordPress core; Telegram alerts; automatic OS security updates (reboots only on request or in an opt-in night window at most once a month, with a fallback kernel and a post-boot service check), PHP patch releases, edge updates with rollback (only releases out for a few days); findings in CISA KEV or with EPSS ≥ 10% are marked urgent and patched within 6 hours.
- Security audit page (public ports, firewall, SSH, DB bind, leftovers) with exact fix commands; full audit log.

**Private access**
- Built-in WireGuard (no account, no coordination server): devices by key, QR codes, locks that close SSH/panel to everything but the VPN, with automatic undo if you lock yourself out.
- VPN devices get their own firewalld zone: SSH, the panel and the ports you unlock, not the whole server.

**Monitoring and alerts**
- Telegram alerts: failed deploys/crons/backups, app or service down, disk/memory pressure, new high/critical vulnerabilities.
- Metrics history: every minute CPU, memory, swap, load, network, disks and per-app memory/CPU (read from /proc and cgroups); minute points kept 48 h, 15-minute averages 30 days; inline SVG charts (1h/24h/7d/30d) on Home and each app page.

**Performance defaults**
- BBR, larger network queues and UDP buffers for HTTP/3 (one switch on the Security page, current vs pano values shown), journal size cap, opcache/realpath cache for PHP, browser caching of static files.

**Android builds (optional, nothing installed until asked; x86-64 servers)**
- Toolchain on demand: Eclipse Temurin JDK 17/21 and the Android SDK under `/opt/pano/android`, checksums verified, read-only for builds; SDK packages a project needs (NDK, CMake, newer platforms) installed by the agent.
- Every build runs in a throwaway sandbox: a transient systemd unit with a user that exists only while it runs (DynamicUser), an empty directory of its own, pano's state, secrets, apps and sites out of sight, memory cap, low CPU priority, time limit. When it ends the user and the source are gone; the APK/AAB (size, sha256) is kept, the newest three builds keep their files. One build at a time.
- Per-project download cache (Gradle, npm, bun) kept between builds so they do not download hundreds of MB each time; only that project's builds see it (stable dynamic user + CacheDirectory), size shown, one-click clear, removed with the project.
- The commit is fetched by an unprivileged user (bare fetch + `git archive`: no checkout, hooks or submodules) and handed to the sandbox on stdin; read-only deploy key per project.
- Signing with the project's upload/release keystore after the build (apksigner for APK, jarsigner for AAB) in a second throwaway sandbox without network, the key passed as systemd credentials: the project's code and dependencies never see it. Keystore root-only, write-only from the UI.

**Runner: heavy commands from your own machine (optional, off by default)**
- `tools/pano-remote` (bash, needs ssh + rsync) syncs the project (only what changed; node_modules, build outputs and caches are not sent), runs the command on the server, streams the output, exits with its code and copies paths back (`-p android/app/build/outputs`). Ctrl-C stops the run on the server. Made for coding agents too: one command, no state on the laptop.
- Server side: `pano-run` user, SSH only with keys added on the Runner page (2FA), each held to `pano run-shell` (`restrict`, forced command): rsync goes through rrsync, confined to the workspaces; runs are asked of the agent on a socket only that user can open.
- Each run is a transient systemd unit: memory cap, time limit, low CPU priority, ProtectSystem=strict, pano/apps/secrets out of sight, of the runner's home only the workspaces and the shared cache (Gradle, npm, bun). Services listening on the server itself (databases, Valkey, panel, apps, edge) are unreachable from runs (nftables by uid; their own ephemeral ports and DNS stay open), and Yama ptrace scope 1 keeps a run from tracing the SSH side. Build outputs and node_modules stay in the workspace, so the next run is incremental. Android SDK/JDK and pano's Node.js/Bun on PATH. Parallel runs configurable (default one, others wait).

**Throwaway build sandbox for apps (per app, off by default)**
- Install and build see only the new release: not the deploy key, data, env file (systemd hands the env to the build) or the shared caches; their own caches are deleted afterwards. Slower builds, same output path.

**Migration**
- From CyberPanel/OpenLiteSpeed: scans the server (vhosts, proxies, PHP versions, certificates, databases, crontabs), imports while the old panel keeps serving, moves sites one by one, cutover of ports 80/443 with one-click rollback, CyberPanel removed last.
- From cPanel: imports `cpmove-USER.tar.gz` full backups (main, addon, sub and parked domains, files, databases).
- Runs independently of CyberPanel/OS updates (own binary, runtimes, Caddy, users, units).

## Not there yet (honest gaps)
- Python: no vulnerability scan of the installed interpreter or of Python lockfiles yet (patch releases arrive by installing the newer patch and redeploying); previews get no edge-served static files and their migrate guard is a name/value heuristic; one static-file copy per slot (no media); poetry installs resolve through PyPI (not hash-pinned); gunicorn+uvicorn workers and `--factory` apps need a start command.
- Email hosting (mail server, webmail) and DNS server — intended to stay external (Cloudflare, a mail provider).
- Multiple servers from one panel, resellers, client accounts and admin roles (all admins are equal), billing (WHMCS-style).
- File manager and per-site SFTP users; full-page cache (Varnish-style).
- iOS build runner (needs macOS hardware); Android builds on push; staging copies of PHP sites.
- Long field history: young project, tested end to end in VMs; the first real server migration is next.
