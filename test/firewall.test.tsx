import { expect, test } from "bun:test";
import { panelIsPublic, renderRules, renderUnit, sshPorts } from "../src/agent/firewall.ts";
import { formatPorts, parsePorts } from "../src/shared/validate.ts";
import { FirewallCard } from "../src/web/views/firewall.tsx";

const base = { ssh: [22], turn: false, extra: [] };

test("rules: default drop, essentials, replaced atomically", () => {
  const r = renderRules(base);
  expect(r).toContain("delete table inet pano_fw");
  expect(r).toContain("policy drop;");
  expect(r).toContain("ct state established,related accept");
  expect(r).toContain('iifname "lo" accept');
  expect(r).toContain("tcp dport { 22, 80, 443 } accept");
  expect(r).toContain("udp dport { 443 } accept");
  expect(r).toContain("icmpv6 type");
  // Never touches the private-access table.
  expect(r).not.toContain("pano_vpn");
});

test("rules: panel, WireGuard, TURN and extra ports; overlaps are merged", () => {
  const r = renderRules({ ssh: [2222, 22], panel: 7800, wg: 51820, turn: true, extra: parsePorts("8080 3000-3010/tcp 3005/tcp 5000/udp 49170/udp") });
  expect(r).toContain("tcp dport { 22, 80, 443, 2222, 3000-3010, 3478, 7800, 8080 } accept");
  expect(r).toContain("udp dport { 443, 3478, 5000, 49160-49200, 51820 } accept");
});

test("ports: parsing and limits", () => {
  expect(formatPorts(parsePorts("8080, 51820/UDP\n3000-3010/tcp 8080/tcp"))).toBe("3000-3010/tcp\n8080/tcp\n51820/udp");
  expect(parsePorts("")).toEqual([]);
  for (const bad of ["0", "65536", "80/icmp", "10-5", "80;drop", "a", "1-2-3"]) expect(() => parsePorts(bad)).toThrow();
  expect(() => parsePorts(Array.from({ length: 51 }, (_, i) => 1000 + i).join(" "))).toThrow("at most 50");
  expect(parsePorts(Array.from({ length: 50 }, (_, i) => 1000 + i).join(" "))).toHaveLength(50);
});

test("panel exposure and ssh detection", () => {
  expect(panelIsPublic("127.0.0.1")).toBe(false);
  expect(panelIsPublic("100.64.0.5")).toBe(false);
  expect(panelIsPublic("172.20.1.1")).toBe(false);
  expect(panelIsPublic("0.0.0.0")).toBe(true);
  expect(panelIsPublic("203.0.113.9")).toBe(true);
  const ss = 'LISTEN 0 128 0.0.0.0:2200 0.0.0.0:* users:(("sshd",pid=1,fd=3))\nLISTEN 0 128 [::]:2201 [::]:* users:(("sshd",pid=1,fd=4))\nLISTEN 0 1 0.0.0.0:80 0.0.0.0:* users:(("caddy",pid=2,fd=5))';
  expect(sshPorts("port 22\nport 2200\n", ss)).toEqual([22, 2200, 2201]);
  expect(sshPorts("", "")).toEqual([]);
});

test("unit loads the saved rules and removes the table on stop", () => {
  const u = renderUnit();
  expect(u).toContain("ExecStart=nft -f /etc/pano/firewall.nft");
  expect(u).toContain("ExecStop=-nft delete table inet pano_fw");
});

test("card: off, waiting for confirmation", () => {
  const v = { installed: true, on: false, loaded: false, confirmIn: 0, ports: "", detected: { ssh: [22], panel: null, wg: null, turn: false } };
  const off = String(<FirewallCard csrf="t" v={v} />);
  expect(off).toContain("/security/firewall/enable");
  expect(off).not.toContain("/security/firewall/confirm");
  const waiting = String(<FirewallCard csrf="t" v={{ ...v, on: true, loaded: true, confirmIn: 90 }} />);
  expect(waiting).toContain("/security/firewall/confirm");
  expect(waiting).toContain("/security/firewall/disable");
});
