// Server overview and the security audit. The audit only reads; every finding
// carries the exact command that fixes it so nothing risky (firewall, SSH) is
// ever changed behind the admin's back.

import { cpus, hostname, loadavg, totalmem, uptime } from "node:os";
import { env } from "../shared/config.ts";
import { destIds } from "./backup.ts";
import { EDGE_VIEW, EDGE_VIEW_UNIT, edgeActive, edgeInstalled, edgeViewMounted } from "./edge.ts";
import { kitState } from "./recovery.ts";
import { bindAddress } from "./mysql.ts";
import { PHP_EOL } from "../shared/validate.ts";
import { backups, settings, sites } from "./state.ts";
import { diskUsage, exists, readText, run, showUnits } from "./sys.ts";
import { paths } from "../shared/config.ts";

export async function info() {
  const meminfo = (await readText("/proc/meminfo")) ?? "";
  const kb = (k: string) => Number(meminfo.match(new RegExp(`^${k}:\\s+(\\d+)`, "m"))?.[1] ?? 0) * 1024;
  const { size, used, avail } = await diskUsage("/").catch(() => ({ size: 0, used: 0, avail: 0 }));
  const os = (await readText("/etc/os-release"))?.match(/^PRETTY_NAME="?([^"\n]+)/m)?.[1] ?? process.platform;
  const services: { unit: string; state: string; memory: number }[] = [];
  const units = ["pano-agent", "pano-web", "pano-edge", "lshttpd", "mariadb", "redis", "lscpd", "fastapi_ssh_server", "docker"];
  const r = await run(["systemctl", "show", ...units.map((u) => `${u}.service`), "--property=Id,ActiveState,MemoryCurrent"], { check: false });
  for (const block of r.stdout.trim().split("\n\n")) {
    const p = Object.fromEntries(block.split("\n").map((l) => l.split(/=(.*)/s).slice(0, 2)));
    if (!p.Id || p.ActiveState === "inactive") continue;
    const mem = Number(p.MemoryCurrent);
    services.push({ unit: p.Id.replace(/\.service$/, ""), state: p.ActiveState ?? "", memory: Number.isFinite(mem) ? mem : 0 });
  }
  return {
    hostname: hostname(),
    os,
    cpus: cpus().length,
    load: loadavg(),
    uptime: uptime(),
    memory: { total: totalmem(), available: kb("MemAvailable") },
    disk: { size: size ?? 0, used: used ?? 0, avail: avail ?? 0 },
    services,
    edge: { active: await edgeActive(), cutover: settings.get("edge.cutover") === "1" },
  };
}

export type Finding = { id: string; level: "ok" | "warn" | "fail"; title: string; detail: string; fix?: string };

const EXPECTED_PUBLIC = new Set([22, 80, 443]);

export async function audit(): Promise<Finding[]> {
  const f: Finding[] = [];
  // Every probe at once; the checks below only read the answers.
  const UNITS = ["firewalld.service", "lscpd.service", "fastapi_ssh_server.service", "dnf-automatic.timer", "unattended-upgrades.service"];
  const [ss, units, nft, sshd, bind, se, edgeUp, kit] = await Promise.all([
    run(["ss", "-Htlnp"], { check: false }),
    showUnits(UNITS, ["ActiveState", "UnitFileState"]),
    // Chains only: the ruleset would also list every banned address in the shield's sets.
    run(["nft", "list", "chains"], { check: false }),
    run(["sshd", "-T"], { check: false }),
    bindAddress(),
    run(["getenforce"], { check: false }),
    settings.get("edge.cutover") === "1" ? edgeActive() : Promise.resolve(true),
    destIds().length ? kitState() : Promise.resolve(null),
  ]);
  const unit = (u: string) => units.get(u) ?? {};

  // Public listeners
  const exposed: string[] = [];
  for (const line of ss.stdout.split("\n").filter(Boolean)) {
    const local = line.split(/\s+/)[3] ?? "";
    const port = Number(local.split(":").pop());
    const host = local.slice(0, local.lastIndexOf(":"));
    const isPublic = host === "0.0.0.0" || host === "*" || host === "[::]";
    if (!isPublic || EXPECTED_PUBLIC.has(port)) continue;
    const proc = line.match(/users:\(\("([^"]+)"/)?.[1] ?? "?";
    exposed.push(`${port} (${proc})`);
  }
  const uniq = [...new Set(exposed)];
  f.push(
    uniq.length
      ? {
          id: "ports",
          level: "fail",
          title: "Services listening on all interfaces",
          detail: uniq.join(", "),
          fix: "Bind them to 127.0.0.1 or block them: firewall-cmd --permanent --remove-port=<port>/tcp; firewall-cmd --reload (or use a Hetzner Cloud Firewall allowing only 22, 80, 443).",
        }
      : { id: "ports", level: "ok", title: "Only SSH, HTTP and HTTPS are public", detail: "" },
  );

  // Firewall
  const hasFirewall = unit("firewalld.service").ActiveState === "active" || /hook input.*policy drop/.test(nft.stdout);
  f.push(
    hasFirewall
      ? { id: "firewall", level: "ok", title: "Host firewall active", detail: "" }
      : {
          id: "firewall",
          level: "warn",
          title: "No host firewall",
          detail: "Without a firewall every port a service opens is reachable from the internet (unless a Hetzner Cloud Firewall is attached).",
          fix: "dnf install -y firewalld && systemctl enable --now firewalld && firewall-cmd --permanent --add-service={ssh,http,https} && firewall-cmd --permanent --add-port=443/udp && firewall-cmd --permanent --zone=trusted --add-interface=tailscale0 && firewall-cmd --reload",
        },
  );

  // SSH
  const conf = Object.fromEntries(sshd.stdout.split("\n").map((l) => l.split(" ")).map(([k, ...val]) => [k, val.join(" ")]));
  if (conf.passwordauthentication === "yes")
    f.push({ id: "ssh-password", level: "fail", title: "SSH accepts passwords", detail: "Brute-force target; use keys only.", fix: "echo 'PasswordAuthentication no' > /etc/ssh/sshd_config.d/10-pano.conf && systemctl reload sshd" });
  if (conf.permitrootlogin === "yes")
    f.push({ id: "ssh-root", level: "warn", title: "Root can log in with a password", detail: "", fix: "echo 'PermitRootLogin prohibit-password' >> /etc/ssh/sshd_config.d/10-pano.conf && systemctl reload sshd" });
  if (sshd.code === 0 && conf.passwordauthentication !== "yes" && conf.permitrootlogin !== "yes")
    f.push({ id: "ssh", level: "ok", title: "SSH: keys only", detail: "" });

  // Database
  f.push(
    // NULL (unset) means every interface
    !bind || bind === "NULL" || bind === "0.0.0.0" || bind === "*" || bind === "::"
      ? { id: "mysql-bind", level: "warn", title: "MariaDB accepts network connections", detail: `bind-address=${bind || "(all)"}`, fix: "printf '[mysqld]\\nbind-address=127.0.0.1\\n' > /etc/my.cnf.d/zz-pano.cnf && systemctl restart mariadb   # only if no other server connects to it" }
      : { id: "mysql-bind", level: "ok", title: "MariaDB listens on localhost only", detail: bind },
  );

  // CyberPanel leftovers
  for (const [name, why] of [
    ["lscpd", "CyberPanel's own web server (panel on :8090)"],
    ["fastapi_ssh_server", "CyberPanel web terminal, runs as root on :8888"],
  ] as const) {
    if (unit(`${name}.service`).ActiveState === "active")
      f.push({ id: `cp-${name}`, level: "warn", title: `${name} is still running`, detail: `${why}. Not needed once pano manages the server.`, fix: `systemctl disable --now ${name}` });
  }

  // OpenLiteSpeed admin console
  const admin = await readText(`${paths.ols}/admin/conf/admin_config.conf`);
  const adminAddr = admin?.match(/^\s*address\s+(\S+)/m)?.[1];
  if (adminAddr && !adminAddr.startsWith("127.0.0.1"))
    f.push({ id: "ols-admin", level: "warn", title: "OpenLiteSpeed admin console is public", detail: `address ${adminAddr}`, fix: `sed -i 's/^\\(\\s*address\\s*\\).*:7080/\\1127.0.0.1:7080/' ${paths.ols}/admin/conf/admin_config.conf && ${paths.ols}/bin/lswsctrl restart` });

  // Automatic security updates
  f.push(
    unit("dnf-automatic.timer").UnitFileState === "enabled" || unit("unattended-upgrades.service").UnitFileState === "enabled"
      ? { id: "updates", level: "ok", title: "Automatic security updates on", detail: "" }
      : { id: "updates", level: "warn", title: "No automatic security updates", detail: "", fix: "dnf install -y dnf-automatic && sed -i 's/^upgrade_type.*/upgrade_type = security/; s/^apply_updates.*/apply_updates = yes/' /etc/dnf/automatic.conf && systemctl enable --now dnf-automatic.timer" },
  );

  // SELinux
  if (se.code === 0 && se.stdout.trim() !== "Enforcing")
    f.push({ id: "selinux", level: "warn", title: `SELinux is ${se.stdout.trim()}`, detail: "Enforcing mode contains a compromised service. Test before switching on a live server." });

  // Panel exposure
  const host = env.webHost;
  const privateHost = host === "127.0.0.1" || host === "::1" || host.startsWith("100.") || host.startsWith("10.") || host.startsWith("192.168.");
  f.push(
    privateHost
      ? { id: "panel", level: "ok", title: "Panel is not on the public internet", detail: `listening on ${host}:${env.webPort}` }
      : { id: "panel", level: "fail", title: "Panel listens on a public address", detail: host, fix: "Set PANO_WEB_HOST to 127.0.0.1 or your Tailscale IP in /etc/pano/pano.env" },
  );

  // Backups
  const jobs = backups.jobs().filter((j) => j.enabled && j.schedule !== "manual");
  const stale = jobs.filter((j) => !j.last_run_at || j.last_status !== "success" || Date.now() / 1000 - j.last_run_at > 26 * 3600);
  f.push(
    !jobs.length
      ? { id: "backups", level: "warn", title: "No scheduled backups", detail: "Add daily jobs for databases and app data on the Backups page." }
      : stale.length
        ? { id: "backups", level: "warn", title: "Some backups are failing or late", detail: stale.map((j) => j.name).join(", ") }
        : { id: "backups", level: "ok", title: "Backups are current", detail: `${jobs.length} scheduled jobs` },
  );

  // Edge
  if (!edgeUp) f.push({ id: "edge", level: "fail", title: "Edge is down", detail: "Sites are unreachable.", fix: "systemctl restart pano-edge; journalctl -u pano-edge -n 50" });
  // Edge and symlinks in PHP sites (edge.ts EDGE_VIEW)
  if (sites.list().some((s) => s.kind === "php") && (await edgeInstalled())) {
    // As the host sees it and, when the edge runs, inside the edge's own mount namespace.
    const pid = (await showUnits(["pano-edge.service"], ["MainPID"])).get("pano-edge.service")?.MainPID ?? "0";
    f.push(
      (await edgeViewMounted()) && (!/^[1-9]\d*$/.test(pid) || (await edgeViewMounted(pid)))
        ? { id: "edge-links", level: "ok", title: "The edge never follows symlinks in site files", detail: `Sites are served from a read-only, nosymfollow view (${EDGE_VIEW}).` }
        : {
            id: "edge-links",
            level: "warn",
            title: "The edge can follow symlinks that sites create",
            detail: `The server could not mount the sites read-only with nosymfollow (needs Linux 5.10+ and a mount/util-linux that knows the option). A site could link to another site's files or a TLS key and fetch them over HTTP; links that lead out of a site are removed once a day, which only narrows that window.`,
            fix: `Upgrade to a distribution with Linux 5.10+ (Debian 12, Ubuntu 22.04, AlmaLinux/Rocky 9) and reboot; pano switches over by itself (check: systemctl status ${EDGE_VIEW_UNIT}).`,
          },
    );
  }

  if (kit) {
    f.push(
      kit === "ok"
        ? { id: "recovery-kit", level: "ok", title: "Recovery kit saved off the server", detail: "With it this server can be rebuilt elsewhere (pano recover)." }
        : {
            id: "recovery-kit",
            level: "warn",
            title: kit === "none" ? "No recovery kit saved off the server" : "Recovery kit is out of date (a backup store changed)",
            detail: "Without the backup key and store credentials no backup can be read if this server is lost.",
            fix: "Backups → Recovery kit: keep it in a password manager, not on this server.",
          },
    );
  }

  // PHP: versions past their security support
  const today = new Date().toISOString().slice(0, 10);
  const phpSites = sites.list().filter((s) => s.kind === "php" || (s.kind === "legacy" && s.php_version));
  const old = phpSites.filter((s) => PHP_EOL[s.php_version] && PHP_EOL[s.php_version]! < today);
  if (old.length)
    f.push({ id: "php-eol", level: "warn", title: "Sites on PHP without security updates", detail: old.map((s) => `${s.name} (${s.php_version})`).join(", "), fix: "Sites → site → PHP version (test the site after switching)" });
  else if (phpSites.length) f.push({ id: "php-eol", level: "ok", title: "PHP versions are supported", detail: `${phpSites.length} PHP sites` });

  const order = { fail: 0, warn: 1, ok: 2 } as const;
  return f.sort((a, b) => order[a.level] - order[b.level]);
}
