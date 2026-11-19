import { describe, expect, test } from "bun:test";
import { AppForm, type AppRow } from "../src/web/views/apps.tsx";
import { RuntimesPage } from "../src/web/views/pages.tsx";
import { appType } from "../src/web/views/projects.tsx";

const html = (x: unknown) => String(x);

describe("Python in the UI", () => {
  test("new app form offers Python without any installed runtime and keeps the fields collapsed", () => {
    const out = html(<AppForm csrf="c" runtimes={[{ runtime: "node", version: "24.1.0" }]} action="/apps" submit="Create" />);
    expect(out).toContain('<option value="node@24.1.0"');
    expect(out).toContain('<option value="python@"');
    expect(out).toContain("Python (new version, installed on first deploy)");
    expect(out).toContain('name="python_version"');
    for (const n of ["py_app", "py_server", "py_requirements", "py_workers", "py_collectstatic", "py_migrate", "py_static"]) expect(out).toContain(`name="${n}"`);
    expect(out).toMatch(/<details class="wide">/);
  });

  test("editing a Python app shows its values and opens the section", () => {
    const app = { name: "hub", runtime: "python", runtime_version: "3.14.2", repo: "x", py_app: "config.wsgi:application", py_migrate: "off", py_server: "gunicorn", py_static: "/static | staticfiles", py_workers: 3 } as Partial<AppRow>;
    const out = html(<AppForm csrf="c" app={app} runtimes={[]} action="/apps/hub/settings" submit="Save" />);
    expect(out).toContain('<option value="python@3.14.2" selected');
    expect(out).toContain('value="3.14"');
    expect(out).toContain('value="config.wsgi:application"');
    expect(out).toContain('<option value="off" selected');
    expect(out).toContain("/static | staticfiles");
    expect(out).toMatch(/<details class="wide" open/);
  });

  test("runtimes page: optional Python card, versions only on request", () => {
    const base = { csrf: "c", installed: [{ runtime: "python", version: "3.14.2", inUse: false }], available: null, php: [] };
    const off = html(<RuntimesPage {...base} />);
    expect(off).toContain("Optional: nothing of Python");
    expect(off).toContain('href="/runtimes?python=1"');
    expect(off).toContain('name="runtime" value="python"');
    const on = html(<RuntimesPage {...base} pythonAvailable={["3.14.2", "3.13.9"]} />);
    expect(on).toContain("Python 3.13.9");
    expect(on).toContain("Installed");
  });

  test("project tag", () => {
    expect(appType({ kind: "managed", runtime: "python", build_cmd: "", start_cmd: "" } as never).label).toBe("Python");
    expect(appType({ kind: "managed", runtime: "node", build_cmd: "", start_cmd: "" } as never).label).toBe("Node");
  });
});
