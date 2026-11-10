// Minimal OpenLiteSpeed config parser. Keeps every original line so a file can
// be edited in place (listener addresses at cutover) without reformatting it.

export type OlsNode = OlsLine | OlsBlock;
export type OlsLine = { type: "line"; key: string; value: string; raw: string[] };
export type OlsBlock = { type: "block"; key: string; value: string; open: string; close: string; children: OlsNode[] };

export function parseOls(text: string): OlsBlock {
  const root: OlsBlock = { type: "block", key: "", value: "", open: "", close: "", children: [] };
  const stack: OlsBlock[] = [root];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i]!;
    const t = raw.trim();
    const top = stack[stack.length - 1]!;
    if (t.endsWith("{") && !t.startsWith("#")) {
      const head = t.slice(0, -1).trim();
      const [key, ...rest] = head.split(/\s+/);
      const block: OlsBlock = { type: "block", key: key ?? "", value: rest.join(" "), open: raw, close: "", children: [] };
      top.children.push(block);
      stack.push(block);
      continue;
    }
    if (t === "}" && stack.length > 1) {
      top.close = raw;
      stack.pop();
      continue;
    }
    const m = t.match(/^(\S+)\s*(.*)$/);
    const node: OlsLine = { type: "line", key: m && !t.startsWith("#") ? m[1]! : "", value: m ? m[2]!.trim() : "", raw: [raw] };
    // Heredoc values: `rules <<<END_rules` ... `END_rules`
    const here = node.value.match(/^<<<(\S+)$/);
    if (here) {
      const end = here[1]!;
      const body: string[] = [];
      while (++i < lines.length && lines[i]!.trim() !== end) body.push(lines[i]!);
      node.raw.push(...body, lines[i] ?? end);
      node.value = body.join("\n");
    }
    top.children.push(node);
  }
  return root;
}

export function serializeOls(node: OlsBlock): string {
  const out: string[] = [];
  const walk = (b: OlsBlock) => {
    for (const c of b.children) {
      if (c.type === "line") out.push(...c.raw);
      else {
        out.push(c.open);
        walk(c);
        out.push(c.close);
      }
    }
  };
  walk(node);
  return out.join("\n");
}

// OpenLiteSpeed keys are case-insensitive: CyberPanel writes `virtualHost`, the docs `virtualhost`.
const same = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();

export const blocks = (b: OlsBlock, key?: string) =>
  b.children.filter((c): c is OlsBlock => c.type === "block" && (key === undefined || same(c.key, key)));

export const lines = (b: OlsBlock, key: string) => b.children.filter((c): c is OlsLine => c.type === "line" && same(c.key, key));

export const value = (b: OlsBlock, key: string) => lines(b, key)[0]?.value;

/** Replace a single-line directive's value, keeping indentation. */
export function setValue(line: OlsLine, val: string) {
  const indent = line.raw[0]!.match(/^\s*/)![0];
  const pad = Math.max(1, 26 - line.key.length);
  line.raw = [`${indent}${line.key}${" ".repeat(pad)}${val}`];
  line.value = val;
}

// ---- higher level views used by the importer -------------------------------

export type OlsVhostRef = { name: string; vhRoot: string; configFile: string };
export type OlsListener = { name: string; address: string; secure: boolean; maps: { vhost: string; domains: string[] }[] };

export function readServerConfig(text: string) {
  const root = parseOls(text);
  const vhosts: OlsVhostRef[] = blocks(root, "virtualhost").map((b) => ({
    name: b.value,
    vhRoot: value(b, "vhRoot") ?? "",
    configFile: value(b, "configFile") ?? "",
  }));
  const listeners: OlsListener[] = blocks(root, "listener").map((b) => ({
    name: b.value,
    address: value(b, "address") ?? "",
    secure: value(b, "secure") === "1",
    maps: lines(b, "map").map((l) => {
      const [vhost, ...rest] = l.value.split(/\s+/);
      return { vhost: vhost ?? "", domains: rest.join(" ").split(/\s*,\s*/).filter(Boolean) };
    }),
  }));
  return { root, vhosts, listeners };
}

export type OlsVhost = {
  docRoot: string;
  domain: string;
  aliases: string[];
  processors: { name: string; type: string; address: string; path: string }[];
  contexts: { uri: string; type: string; handler: string; location: string }[];
  ssl: { keyFile: string; certFile: string } | null;
  phpHandler: string;
  rewriteRules: string;
};

export function readVhost(text: string, vars: Record<string, string>): OlsVhost {
  const sub = (s: string) => s.replace(/\$(VH_NAME|VH_ROOT|SERVER_ROOT|DOC_ROOT)/g, (_, k) => vars[k] ?? `$${k}`);
  const root = parseOls(text);
  const ssl = blocks(root, "vhssl")[0];
  const script = blocks(root, "scripthandler")[0];
  return {
    docRoot: sub(value(root, "docRoot") ?? ""),
    domain: sub(value(root, "vhDomain") ?? vars.VH_NAME ?? ""),
    aliases: sub(value(root, "vhAliases") ?? "")
      .split(/\s*,\s*/)
      .filter(Boolean),
    processors: blocks(root, "extprocessor").map((b) => ({
      name: b.value,
      type: value(b, "type") ?? "",
      address: value(b, "address") ?? "",
      path: value(b, "path") ?? "",
    })),
    contexts: blocks(root, "context").map((b) => ({
      uri: b.value,
      type: value(b, "type") ?? "",
      handler: value(b, "handler") ?? "",
      location: value(b, "location") ?? "",
    })),
    ssl: ssl ? { keyFile: sub(value(ssl, "keyFile") ?? ""), certFile: sub(value(ssl, "certFile") ?? "") } : null,
    phpHandler: script ? (value(script, "add") ?? "") : "",
    rewriteRules: blocks(root, "rewrite").map((b) => value(b, "rules") ?? "").join("\n"),
  };
}
