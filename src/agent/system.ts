// Server overview and the security audit. The audit only reads; every finding
// carries the exact command that fixes it so nothing risky (firewall, SSH) is
// ever changed behind the admin's back.

import { cpus, hostname, loadavg, totalmem, uptime } from "node:os";
import { env } from "../shared/config.ts";
import { edgeActive } from "./edge.ts";
import { bindAddress } from "./mysql.ts";
import { PHP_EOL } from "../shared/validate.ts";
import { backups, settings, sites } from "./state.ts";
import { exists, readText, run } from "./sys.ts";
import { paths } from "../shared/config.ts";

export async function info() {
  const meminfo = (await readText("/proc/meminfo")) ?? "";
  const kb = (k: string) => Number(meminfo.match(new RegExp(`^${k}:\\s+(\\d+)`, "m"))?.[1] ?? 0) * 1024;
  const df = await run(["df", "-B1", "--output=size,used,avail", "/"], { check: false });
  const [size, used, avail] = (df.stdout.trim().split("\n")[1] ?? "").trim().split(/\s+/).map(Number);
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

  // Public listeners
  const ss = await run(["ss", "-Htlnp"], { check: false });
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
  const fw = await run(["systemctl", "is-active", "firewalld"], { check: false });
  const nft = await run(["nft", "list", "ruleset"], { check: false });
  const hasFirewall = fw.stdout.trim() === "active" || /hook input.*policy drop/s.test(nft.stdout);
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
  const sshd = await run(["sshd", "-T"], { check: false });
  const conf = Object.fromEntries(sshd.stdout.split("\n").map((l) => l.split(" ")).map(([k, ...val]) => [k, val.join(" ")]));
  if (conf.passwordauthentication === "yes")
    f.push({ id: "ssh-password", level: "fail", title: "SSH accepts passwords", detail: "Brute-force target; use keys only.", fix: "echo 'PasswordAuthentication no' > /etc/ssh/sshd_config.d/10-pano.conf && systemctl reload sshd" });
  if (conf.permitrootlogin === "yes")
    f.push({ id: "ssh-root", level: "warn", title: "Root can log in with a password", detail: "", fix: "echo 'PermitRootLogin prohibit-password' >> /etc/ssh/sshd_config.d/10-pano.conf && systemctl reload sshd" });
  if (sshd.code === 0 && conf.passwordauthentication !== "yes" && conf.permitrootlogin !== "yes")
    f.push({ id: "ssh", level: "ok", title: "SSH: keys only", detail: "" });

  // Database
  const bind = await bindAddress();
  f.push(
    // NULL (unset) means every interface
    !bind || bind === "NULL" || bind === "0.0.0.0" || bind === "*" || bind === "::"
      ? { id: "mysql-bind", level: "warn", title: "MariaDB accepts network connections", detail: `bind-address=${bind || "(all)"}`, fix: "printf '[mysqld]\\nbind-address=127.0.0.1\\n' > /etc/my.cnf.d/zz-pano.cnf && systemctl restart mariadb   # only if no other server connects to it" }
      : { id: "mysql-bind", level: "ok", title: "MariaDB listens on localhost only", detail: bind },
  );

  // CyberPanel leftovers
  for (const [unit, why] of [
    ["lscpd", "CyberPanel's own web server (panel on :8090)"],
    ["fastapi_ssh_server", "CyberPanel web terminal, runs as root on :8888"],
  ] as const) {
    const s = await run(["systemctl", "is-active", unit], { check: false });
    if (s.stdout.trim() === "active")
      f.push({ id: `cp-${unit}`, level: "warn", title: `${unit} is still running`, detail: `${why}. Not needed once pano manages the server.`, fix: `systemctl disable --now ${unit}` });
  }

  // OpenLiteSpeed admin console
  const admin = await readText(`${paths.ols}/admin/conf/admin_config.conf`);
  const adminAddr = admin?.match(/^\s*address\s+(\S+)/m)?.[1];
  if (adminAddr && !adminAddr.startsWith("127.0.0.1"))
    f.push({ id: "ols-admin", level: "warn", title: "OpenLiteSpeed admin console is public", detail: `address ${adminAddr}`, fix: `sed -i 's/^\\(\\s*address\\s*\\).*:7080/\\1127.0.0.1:7080/' ${paths.ols}/admin/conf/admin_config.conf && ${paths.ols}/bin/lswsctrl restart` });

  // Automatic security updates
  const auto = await run(["systemctl", "is-enabled", "dnf-automatic.timer"], { check: false });
  const unattended = await run(["systemctl", "is-enabled", "unattended-upgrades"], { check: false });
  f.push(
    auto.stdout.trim() === "enabled" || unattended.stdout.trim() === "enabled"
      ? { id: "updates", level: "ok", title: "Automatic security updates on", detail: "" }
      : { id: "updates", level: "warn", title: "No automatic security updates", detail: "", fix: "dnf install -y dnf-automatic && sed -i 's/^upgrade_type.*/upgrade_type = security/; s/^apply_updates.*/apply_updates = yes/' /etc/dnf/automatic.conf && systemctl enable --now dnf-automatic.timer" },
  );

  // SELinux
  const se = await run(["getenforce"], { check: false });
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
  if (settings.get("edge.cutover") === "1" && !(await edgeActive()))
    f.push({ id: "edge", level: "fail", title: "Edge is down", detail: "Sites are unreachable.", fix: "systemctl restart pano-edge; journalctl -u pano-edge -n 50" });

  if (await exists(`${paths.secrets}/backup.key`))
    f.push({ id: "backup-key", level: "ok", title: "Backup encryption key exists", detail: "Keep an offline copy (Backups page → export key)." });

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
