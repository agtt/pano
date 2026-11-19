# Security policy

## Supported versions

Only the latest release gets security fixes. Update with `pano update --latest` (or run the installer again); older releases are not
patched.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub Security Advisories: open the repository's **Security** tab and choose
**Report a vulnerability**. Do not open a public issue, pull request or discussion for a security problem.

A useful report says which version you ran, on which distribution, what an attacker needs (network access only, a tenant's code, the
web process, an admin session) and the steps or a proof of concept.

## Scope

In scope: everything in this repository that runs on a server, in particular

- the privilege boundary between `pano-web` (unprivileged UI) and `pano-agent` (root): any RPC that lets the web process do more than
  the security model in the [README](README.md#security-model) says, including skipping a 2FA code;
- isolation between tenants: an app, PHP site or container reaching another tenant's files, secrets, databases or traffic, or root;
- the edge (Caddy configuration pano generates): serving files it should not, certificate or domain takeover;
- login, sessions, CSRF and the 2FA flow;
- the installer, `pano update` and release verification (signature and checksum checks);
- backups and the recovery kit (encryption, key handling).

Out of scope: vulnerabilities in third-party software pano installs (Caddy, PHP, MariaDB, PostgreSQL, Valkey, WordPress and its plugins)
unless pano configures it insecurely; attacks that already need root on the server; denial of service through sheer traffic volume;
findings from automated scanners without a demonstrated impact; the development helpers in `dev/`.

## What to expect

- An acknowledgement within 3 working days.
- An assessment (confirmed or not, severity) within 10 working days.
- A fix in a new release as soon as it is ready, normally within 30 days for high and critical issues, followed by a published advisory.
  Reporters are credited in the advisory unless they prefer otherwise.

Please give us the chance to release a fix before you disclose details publicly.

## Releases

Releases are built by `.github/workflows/release.yml` from a `vX.Y.Z` tag and signed with a key held as the `PANO_RELEASE_KEY` secret;
the installer and `pano update` accept only artifacts whose `SHA256SUMS` carries a valid signature from the public key built into them.
Because anyone who can push a tag can trigger a signed build, the recommended maintainer setup is:

- `PANO_RELEASE_KEY` lives in a GitHub **environment** (for example `release`) with a **required reviewer** and deployments limited
  to `v*` tags, instead of being a repository secret; the release job then declares `environment: release`, so no signature is made
  without a person approving that run;
- a tag ruleset allows only maintainers to create `v*` tags;
- 2FA on every account with write access, and a protected `main` branch (the installer is fetched from `main`).
