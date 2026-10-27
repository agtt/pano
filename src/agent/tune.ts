// Performance defaults sized to this machine. Kernel network settings for many
// short HTTP connections and HTTP/3 (BBR, larger queues and UDP buffers), a
// journal that cannot fill the disk, and database/cache memory that grows with
// the server instead of a fixed small number. Only files pano wrote are
// rewritten; a changed setting takes effect without restarting anything that
// serves traffic (sysctl and journald reload in place).

import { totalmem } from "node:os";
import { readText, run, writeAtomic } from "./sys.ts";

const SYSCTL = "/etc/sysctl.d/90-pano.conf";
const MODULES = "/etc/modules-load.d/pano.conf";
const JOURNALD = "/etc/systemd/journald.conf.d/pano.conf";

const MB = 1024 * 1024;
const clamp = (n: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, n));
/** Megabytes, rounded down to a multiple of 64. */
const mb = (bytes: number) => Math.floor(bytes / MB / 64) * 64;

/** Memory for each data service as a share of RAM; all together stay near a third of it. */
export function sizes(ram = totalmem()) {
  return {
    innodbPoolMb: mb(clamp(ram * 0.15, 128 * MB, 4096 * MB)),
    pgSharedMb: mb(clamp(ram * 0.1, 128 * MB, 2048 * MB)),
    pgEffectiveCacheMb: mb(clamp(ram * 0.4, 256 * MB, 32768 * MB)),
    valkeyMaxMb: mb(clamp(ram * 0.05, 256 * MB, 1024 * MB)),
    mariadbConnections: ram >= 8192 * MB ? 200 : 100,
  };
}

export function renderSysctl(bbr: boolean): string {
  return `# Written by pano: web serving defaults.
${bbr ? "net.core.default_qdisc = fq\nnet.ipv4.tcp_congestion_control = bbr\n" : ""}net.core.somaxconn = 4096
net.core.netdev_max_backlog = 16384
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 131072
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
# HTTP/3 (QUIC) and the TURN relay move a lot of UDP.
net.core.rmem_max = 7500000
net.core.wmem_max = 7500000
vm.swappiness = 10
vm.vfs_cache_pressure = 50
fs.file-max = 2097152
fs.inotify.max_user_watches = 524288
`;
}

export const JOURNALD_CONF = `# Written by pano: logs stay useful without filling the disk.
[Journal]
SystemMaxUse=500M
SystemMaxFileSize=50M
MaxRetentionSec=1month
Compress=yes
`;

async function bbrAvailable(): Promise<boolean> {
  await run(["modprobe", "tcp_bbr"], { check: false });
  const r = await run(["sysctl", "-n", "net.ipv4.tcp_available_congestion_control"], { check: false });
  return r.stdout.split(/\s+/).includes("bbr");
}

async function writeIfChanged(file: string, content: string): Promise<boolean> {
  if ((await readText(file)) === content) return false;
  await writeAtomic(file, content, 0o644);
  return true;
}

export async function applyTuning() {
  const bbr = await bbrAvailable();
  if (bbr) await writeIfChanged(MODULES, "# Written by pano\ntcp_bbr\n");
  // Values a container or an old kernel refuses are skipped one by one (-e).
  if (await writeIfChanged(SYSCTL, renderSysctl(bbr))) await run(["sysctl", "-e", "-q", "-p", SYSCTL], { check: false });
  if (await writeIfChanged(JOURNALD, JOURNALD_CONF)) await run(["systemctl", "restart", "systemd-journald"], { check: false });
}
