// The panel, the on-demand TLS question and the webhook listener answer on
// localhost. Apps, sites, sandboxes and the services pano runs are system
// users on the same machine: without this they could reach those ports too
// (try passwords until the admin is locked out, ask for certificates, post to
// hooks). Only root, pano's own users and people (SSH tunnels run as the
// signed-in user) may connect; in the kernel, by uid, always on.

import { env, paths } from "../shared/config.ts";
import { EDGE_USER } from "./edge.ts";
import { lookupUser, run, writeAtomic } from "./sys.ts";
import { RELAY } from "./turn.ts";

const UNIT = "pano-local.service";
const RULES = `${paths.etc}/local.nft`;
/** Human accounts (useradd's UID_MIN..) up to where systemd's dynamic users start. */
const PEOPLE = "1000-61183";

/**
 * `turn`: the TURN relay sends where its users ask; to this host only to its own relay ports (two
 * callers on the same relay), never to another service here (memcached, WireGuard, DNS).
 */
export function renderLocalPorts(allowed: number[], ports: number[], turn?: { uid: number; min: number; max: number }): string {
  return [
    "table inet pano_local",
    "delete table inet pano_local",
    "table inet pano_local {",
    "\tchain output {",
    "\t\ttype filter hook output priority 0; policy accept;",
    ...(turn ? [`\t\tmeta skuid ${turn.uid} fib daddr type local udp dport != ${turn.min}-${turn.max} reject`] : []),
    `\t\tmeta skuid { ${[...new Set(allowed)].join(", ")}, ${PEOPLE} } accept`,
    `\t\tfib daddr type local tcp dport { ${ports.join(", ")} } reject with tcp reset`,
    "\t}",
    "}",
    "",
  ].join("\n");
}

export async function applyLocalPorts() {
  const uids = [0];
  for (const u of ["pano", EDGE_USER]) {
    const id = await lookupUser(u);
    if (id) uids.push(id.uid);
  }
  // coturn's user: "coturn" in EPEL/Fedora, "turnserver" on Debian/Ubuntu.
  const turnUser = (await lookupUser("coturn")) ?? (await lookupUser("turnserver"));
  const turn = turnUser ? { uid: turnUser.uid, ...RELAY } : undefined;
  await writeAtomic(`${RULES}.new`, renderLocalPorts(uids, [env.webPort, env.askPort, env.hookPort], turn), 0o600);
  await run(["nft", "-c", "-f", `${RULES}.new`]);
  await run(["mv", "-f", `${RULES}.new`, RULES]);
  await writeAtomic(
    `${paths.systemd}/${UNIT}`,
    `[Unit]\nDescription=pano: panel ports only for root, pano and people\nAfter=network-pre.target\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=nft -f ${RULES}\nExecReload=nft -f ${RULES}\nExecStop=-nft delete table inet pano_local\n\n[Install]\nWantedBy=multi-user.target\n`,
    0o644,
  );
  await run(["systemctl", "daemon-reload"]);
  await run(["systemctl", "enable", UNIT]);
  await run(["systemctl", "restart", UNIT]);
}
