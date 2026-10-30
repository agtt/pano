// Runner: heavy commands (Gradle, tests, web builds) sent from a developer's
// machine over SSH, run here in a sandbox with warm caches. What both ends
// on this server need: the agent (runner.ts) and the SSH forced command
// (run-shell.ts, as the runner user).

/** Owns the synced workspaces and the shared cache; logs in only with keys from the Runner page, only into run-shell. */
export const RUN_USER = "pano-run";
export const runHome = "/var/lib/pano-run";
/** One directory per project, filled by rsync from the developer's machine. */
export const runWorkspaces = `${runHome}/ws`;
/** HOME of every run: ~/.gradle, ~/.bun, ~/.npm, ~/.cache, shared by all workspaces and kept between runs. */
export const runCache = `${runHome}/home`;
/** root:pano-run 0660; the agent listens, run-shell asks. Hidden from runs. */
export const runnerSocket = "/run/pano-run/runner.sock";

/** rrsync ships with rsync 3.2.4+ (Debian 12, Ubuntu 22.04 and later). */
export const RRSYNC = ["/usr/bin/rrsync", "/usr/share/rsync/scripts/rrsync", "/usr/share/doc/rsync/support/rrsync"];

export const WORKSPACE =/^[a-z0-9][a-z0-9._-]{0,63}$/;

/** Frames on the socket: 1 byte kind, 4 bytes length (big endian), payload. Output is bytes as they come; the last frame is the exit code. */
export const OUT = 1;
export const EXIT = 2;

export function frame(kind: number, data: Uint8Array | string): Uint8Array {
  const body = typeof data === "string" ? new TextEncoder().encode(data) : data;
  const f = new Uint8Array(5 + body.length);
  f[0] = kind;
  new DataView(f.buffer).setUint32(1, body.length);
  f.set(body, 5);
  return f;
}

export async function* readFrames(stream: ReadableStream<Uint8Array>): AsyncGenerator<{ kind: number; data: Uint8Array }> {
  let buf = new Uint8Array(0);
  for await (const chunk of stream) {
    const next = new Uint8Array(buf.length + chunk.length);
    next.set(buf);
    next.set(chunk, buf.length);
    buf = next;
    while (buf.length >= 5) {
      const len = new DataView(buf.buffer, buf.byteOffset).getUint32(1);
      if (buf.length < 5 + len) break;
      yield { kind: buf[0]!, data: buf.slice(5, 5 + len) };
      buf = buf.slice(5 + len);
    }
  }
}
