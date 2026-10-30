// `pano run-shell`: the forced command of every Runner key (agent/runner.ts),
// running as pano-run. It never starts a shell: rsync goes to rrsync, held to
// the workspaces; the rest are a few fixed requests to the agent's runner
// socket, whose answers are streamed back over SSH.

import { existsSync } from "node:fs";
import { EXIT, OUT, RRSYNC, readFrames, runWorkspaces, runnerSocket } from "./shared/runner.ts";

const USAGE = `pano runner: use tools/pano-remote on your machine.
  run <workspace> <jdk> <base64 command> | stop <workspace> | clean <workspace> | ls
`;

const ask = (path: string, body: unknown) =>
  fetch(`http://runner${path}`, { method: "POST", unix: runnerSocket, body: JSON.stringify(body), headers: { "content-type": "application/json" } } as RequestInit);

async function json(path: string, body: unknown): Promise<number> {
  const res = await ask(path, body);
  const r = (await res.json().catch(() => ({ error: `agent returned ${res.status}` }))) as { error?: string };
  if (r.error) {
    process.stderr.write(`pano: ${r.error}\n`);
    return 1;
  }
  if (path === "/ls") process.stdout.write(`${JSON.stringify(r, null, 2)}\n`);
  return 0;
}

export async function runShell(line: string): Promise<number> {
  const [cmd, ...a] = line.trim().split(/\s+/);
  switch (cmd) {
    case "rsync": {
      if (a[0] !== "--server") break;
      const rrsync = RRSYNC.find((p) => existsSync(p));
      if (!rrsync) {
        process.stderr.write("pano: rrsync is missing on the server\n");
        return 1;
      }
      // rrsync reads SSH_ORIGINAL_COMMAND itself and refuses paths outside the workspaces.
      const p = Bun.spawn([rrsync, runWorkspaces], { stdin: "inherit", stdout: "inherit", stderr: "inherit" });
      return await p.exited;
    }
    case "run": {
      if (a.length !== 3) break;
      const [ws, jdk, b64] = a as [string, string, string];
      const res = await ask("/run", { ws, jdk: Number(jdk), cmd: Buffer.from(b64, "base64").toString("utf8") });
      if (!res.ok || !res.body) {
        const r = (await res.json().catch(() => ({}))) as { error?: string };
        process.stderr.write(`pano: ${r.error ?? `agent returned ${res.status}`}\n`);
        return 1;
      }
      for await (const f of readFrames(res.body)) {
        if (f.kind === OUT) {
          if (f.data.length) await Bun.write(Bun.stdout, f.data);
        }
        else if (f.kind === EXIT) return Number(new TextDecoder().decode(f.data)) || 0;
      }
      process.stderr.write("pano: the run ended without an exit code (agent restarted?)\n");
      return 1;
    }
    case "stop":
    case "clean":
      if (a.length === 1) return json(`/${cmd}`, { ws: a[0] });
      break;
    case "ls":
      return json("/ls", {});
  }
  process.stderr.write(USAGE);
  return 2;
}
