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
| Apps | git → sandboxed install/build → blue/green systemd slots → health check → traffic switch. Zero-downtime deploys, rollback by redeploying, GitHub push webhooks, deploy keys, per-app env, logs, memory limits. Lockfile-aware (bun, npm, pnpm, yarn). |
| Runtimes | Any Node.js / Bun version side by side under `/opt/pano/runtimes`, checksum-verified. Apps pin their own version; OS updates never change them. |
| Edge | Caddy (pinned, checksum-verified) on :80/:443: automatic HTTPS, HTTP/3, on-demand TLS for customer domains, Cloudflare real-IP. Config is rendered from state and validated before every reload. |
| Monorepos | One build, several processes: `name \| dir \| routes \| memory \| start` per line. Routes are hosts, `host/path`, `*.host` or `*` (any host, on-demand TLS with an ask URL). Web processes get blue/green slots and health checks; workers have no port and never run twice (old one stops before the new one starts). |
| PHP sites | PHP 7.4–8.5 (Remi packages, signed) installed on first use. Each site: its own system user, its own PHP-FPM pool running as that user (never root, `pm=ondemand`, hardened unit with `MemoryDenyWriteExecute`), socket only the edge can open (ACL), `open_basedir`, dangerous functions off, secure session cookies. The edge never serves dotfiles, dumps/backups, composer files or PHP inside uploads. Patch releases arrive with OS updates; pools reload onto the new binary. |
| Sites | Proxy (path → port routes), static, PHP, and legacy sites still served by the old OpenLiteSpeed on localhost. |
| Databases | MariaDB/MySQL: list with sizes and grants, create db + user, reset passwords, drop (with 2FA). |
| Backups | mysqldump / tar → gzip → **AES-256-GCM on the server** → streamed multipart upload to R2. Schedules, retention, restore. R2 only ever sees ciphertext. |
| Import | Reads a CyberPanel/OLS server (vhosts, proxies, PHP versions, certificates, suspended sites, databases, the systemd/PM2 services behind each port) into pano. Read-only until cutover. Legacy sites can then be moved one by one onto pano PHP (files copied, `deny from all` directories stay closed, one-click revert). |
| cPanel | Imports `cpmove-USER.tar.gz` full backups: one PHP site per domain (main, addon, subdomain, parked as aliases), databases loaded by their own user (never root), users recreated with their original password hashes, `.htaccess` deny rules kept, escaping symlinks removed. Mail, cron, DNS and FTP are listed for manual follow-up. |
| Security | Read-only audit (public ports, firewall, SSH, MariaDB bind, CyberPanel leftovers, OLS admin, auto-updates, SELinux, backups) with the exact fix command for each finding. |

## Security model

- **Privilege separation.** `pano-web` (UI) runs as the unprivileged `pano` user in a hardened systemd sandbox and can only talk to
  `pano-agent` over a unix socket (`root:pano 0660`). The agent exposes a fixed list of typed operations, validates every argument and never
  runs a caller-supplied shell command as root.
- **Apps are isolated.** Each app has its own system user and directory; units use `ProtectSystem=strict`, `NoNewPrivileges`, an empty
  capability set, a syscall filter and a memory cap. Builds run in a transient `systemd-run` sandbox as the app user.
- **Panel is never public.** It listens on `127.0.0.1` (SSH tunnel) or a Tailscale address. Only `/hooks/*` can be exposed through the edge for GitHub.
- **Login:** argon2id + mandatory TOTP, lockout after 5 failures, hashed session ids, 30 min idle / 12 h absolute expiry, `SameSite=Strict`
  cookies, CSRF tokens + origin checks, strict CSP. Destructive actions (delete, drop, restore, cutover, key export) require a fresh TOTP code.
- **Secrets:** R2 secret and backup key are root-only files and write-only from the UI. Every action is in the audit log.
- **Independent of CyberPanel.** pano keeps its own binary, runtimes, Caddy, users and units; CyberPanel/OS updates do not change them.

## Install (AlmaLinux/Rocky 9, Debian/Ubuntu)

```sh
bun install && bun run build          # → dist/pano (linux-x64); build:arm for arm64
scp dist/pano root@server:/tmp/pano
ssh root@server '/tmp/pano install && /opt/pano/bin/pano admin you'
ssh -L 7800:127.0.0.1:7800 root@server   # then open http://127.0.0.1:7800
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
```

Layout: `src/agent` (root: state, apps, php, edge, backups, importer, cpanel, cutover, audit), `src/web` (UI, auth), `src/shared` (paths, validation).

## Roadmap

WordPress one-click install · CyberPanel backup files from another server · Debian/Ubuntu PHP (sury) · Postgres ·
DNS-01 / Cloudflare Origin CA certificates · metrics history · multiple admins with roles · mail (deliberately out of scope).

## License

MIT
