# pano (working name) — feature overview

Open-source (planned: AGPL-3.0), self-hosted server panel for one or a few Linux servers (AlmaLinux/Rocky 9, Debian/Ubuntu).
Built for modern apps (Next.js, Node.js, Bun, monorepos) and simple PHP/WordPress sites, with security first and a small
footprint. One self-contained binary written in TypeScript on Bun; no Docker, no Python, no license server. Everything
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
| Snyk / Dependabot alerts (basic), unattended-upgrades | Nightly CVE scan + automatic OS/PHP/edge security patching |
| Docker for a few services | Optional Podman containers (daemonless), off by default |

## Features

**Apps (Next.js, Node.js, Bun)**
- Git → sandboxed build → blue/green systemd slots → health check → traffic switch; zero-downtime deploys (the old process gets up to 20 s to finish requests; database migrations must stay backward compatible, a code rollback does not roll back the database), one-click rollback (previous release kept, no rebuild).
- bun as package manager for every app (reads npm/yarn/pnpm lockfiles); any Node.js/Bun version side by side, pinned per app, checksum-verified.
- Monorepos: one build, several processes (web + workers), per-process routes, memory limits.
- Per-app env (masked in the UI), logs, cron jobs, persistent `DATA_DIR` (SQLite, uploads) included in backups.
- Push-to-deploy from GitHub, GitLab, Gitea, Forgejo; optional GitHub connection with repo picker, deploy keys and commit status.

**Edge**
- Caddy: automatic HTTPS (Let's Encrypt), HTTP/3, zstd/gzip, on-demand TLS for customer domains, Cloudflare real IP, security headers.

**PHP sites and WordPress**
- PHP 7.4–8.5 installed on first use; versions past end of life are flagged in the UI and the security audit (meant only for migrated legacy sites); each site its own system user, own PHP-FPM pool and an OS-level sandbox (read-only system, no new privileges, syscall filter); `open_basedir` and disabled functions are an extra layer, not the boundary.
- Per-site PHP version switch with revert, site cron jobs, blocked paths, legacy sites can stay on OpenLiteSpeed during migration.
- Existing PHP apps (POS, small CMS, Laravel) and WordPress supported.

**Databases and services (on demand)**
- MariaDB: databases, users, grants, sizes, password reset; PostgreSQL (latest major); Valkey (Redis-compatible); SQLite per app.
- "+ Database" creates DB + user and writes `DATABASE_URL`/`REDIS_URL` into the app env; the password never reaches the browser.
- Memory of each service sized to the server's RAM.

**Realtime and games (on demand)**
- Pusher-compatible WebSocket server (Sockudo): pusher-js, Laravel Echo and Pusher SDKs work unchanged; apps, keys, allowed origins, public wss domain, auto-update with rollback.
- TURN relay for WebRTC: short-lived per-user credentials, private networks refused, quotas, secret rotation; takes over an existing coturn.
- WebSocket game servers (Colyseus, Socket.IO, uWS) run as normal apps.

**Jobs and queues**
- One page for all cron jobs (apps + PHP sites): last/next run, result, run now, logs; systemd timers, no overlap, missed runs catch up, failures alert.
- Queue monitor on demand: BullMQ and Laravel queues, workers with restart, alerts on failures and stuck queues.
- Builds, crons and workers get a lower CPU/disk share than websites so they never slow sites down.

**Backups**
- Full archives (AES-256-GCM, encrypted on the server) or incremental (restic: deduplicated, encrypted with restic's own AES-256-CTR + Poly1305-AES).
- One or two destinations at once: Cloudflare R2, Backblaze B2, Hetzner Object Storage, Wasabi, AWS S3, MinIO.
- Hourly/daily/weekly schedules, retention, restore; the storage provider only sees ciphertext.

**Security**
- Privilege separation: unprivileged web UI talks to a root agent over a unix socket with a fixed list of typed operations.
- Panel never public (localhost via SSH tunnel, Tailscale or built-in WireGuard). Login: argon2id + mandatory TOTP, lockout, strict CSP/CSRF.
- 2FA enforced by the agent for every sensitive action (reveal secrets, change env/code source, drop/restore data, VPN, cutover): a compromised UI process still cannot read secrets or plant code.
- Apps and sites sandboxed (own user, read-only system, no new privileges, syscall filter, memory cap, no cloud metadata access).
- Shield: malware scanner with quarantine/restore, login brute-force bans, reputation blocklists. Guard: nftables SSH/HTTP flood protection.
- Vulnerabilities: nightly scan of OS advisories, app/site lockfiles (OSV.dev), Node.js, PHP, WordPress core; Telegram alerts; automatic OS security updates (no surprise reboots), PHP patch releases, edge updates with rollback.
- Security audit page (public ports, firewall, SSH, DB bind, leftovers) with exact fix commands; full audit log.

**Private access**
- Built-in WireGuard (no account, no coordination server): devices by key, QR codes, locks that close SSH/panel to everything but the VPN, with automatic undo if you lock yourself out.

**Monitoring and alerts**
- Telegram alerts: failed deploys/crons/backups, app or service down, disk/memory pressure, new high/critical vulnerabilities.

**Performance defaults**
- BBR, larger network queues and UDP buffers for HTTP/3, journal size cap, opcache/realpath cache for PHP, browser caching of static files.

**Migration**
- From CyberPanel/OpenLiteSpeed: scans the server (vhosts, proxies, PHP versions, certificates, databases, crontabs), imports while the old panel keeps serving, moves sites one by one, cutover of ports 80/443 with one-click rollback, CyberPanel removed last.
- From cPanel: imports `cpmove-USER.tar.gz` full backups (main, addon, sub and parked domains, files, databases).
- Runs independently of CyberPanel/OS updates (own binary, runtimes, Caddy, users, units).

## Not there yet (honest gaps)
- Email hosting (mail server, webmail) and DNS server — intended to stay external (Cloudflare, a mail provider).
- Multiple servers from one panel, resellers, client accounts/roles, billing (WHMCS-style).
- File manager and per-site SFTP users; WordPress toolkit (one-click install, staging, plugin updates); full-page cache (Varnish-style).
- Preview/staging environments for apps; iOS/Android build runners.
- Long field history: young project, tested end to end in VMs; the first real server migration is next.
