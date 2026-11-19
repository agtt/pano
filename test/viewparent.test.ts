import { describe, expect, test } from "bun:test";
import { chmodSync, mkdirSync, rmSync, statSync, symlinkSync } from "node:fs";
import { fsPath } from "../src/shared/config.ts";
import { ensureViewParent, WWW_ROOT } from "../src/agent/edge.ts";

const www = fsPath(WWW_ROOT);
const reset = () => rmSync(www, { recursive: true, force: true });

describe("ensureViewParent", () => {
  test("creates /var/www when it is missing", async () => {
    reset();
    expect(await ensureViewParent(WWW_ROOT)).toBe(true);
    expect(statSync(www).isDirectory()).toBe(true);
  });

  test("leaves the mode of an existing /var/www alone", async () => {
    reset();
    mkdirSync(www, { recursive: true });
    chmodSync(www, 0o2775);
    expect(await ensureViewParent(WWW_ROOT)).toBe(true);
    expect(statSync(www).mode & 0o7777).toBe(0o2775);
  });

  test("a symlinked /var/www gets no view instead of throwing", async () => {
    reset();
    const target = fsPath("/elsewhere");
    mkdirSync(target, { recursive: true });
    mkdirSync(fsPath("/var"), { recursive: true });
    symlinkSync(target, www);
    expect(await ensureViewParent(WWW_ROOT)).toBe(false);
    reset();
  });

  test("pano's own sites directory is still ensured", async () => {
    expect(await ensureViewParent("/srv/pano/sites")).toBe(true);
    expect(statSync(fsPath("/srv/pano/sites")).isDirectory()).toBe(true);
  });
});
