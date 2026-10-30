import { expect, test } from "bun:test";
import { buildScript, parseArtifacts, propValue, signingProperties, validateProject } from "../src/agent/android.ts";
import { buildCost } from "../src/shared/android.ts";
import { AndroidPage } from "../src/web/views/android.tsx";

const base = { name: "shop-app", repo: "git@github.com:acme/shop.git", branch: "main" };

test("Android projects: defaults, and nothing reaches the script unchecked", () => {
  const p = validateProject(base);
  expect(p).toMatchObject({ tasks: "assembleRelease", machine: "default", jdk: 17, timeout_min: 60, root_dir: "", gradle_dir: "" });
  expect(validateProject({ ...base, tasks: " :app:bundleRelease  assembleDebug " }).tasks).toBe(":app:bundleRelease assembleDebug");
  expect(() => validateProject({ ...base, tasks: "bundleRelease --init-script=/tmp/x" })).toThrow();
  expect(() => validateProject({ ...base, tasks: "bundleRelease;id" })).toThrow();
  expect(() => validateProject({ ...base, repo: "file:///srv/pano/git/shop.git" })).toThrow();
  expect(() => validateProject({ ...base, root_dir: "../etc" })).toThrow();
  expect(() => validateProject({ ...base, machine: "huge" })).toThrow();
  expect(() => validateProject({ ...base, jdk: 11 })).toThrow();
  expect(() => validateProject({ ...base, prepare_cmd: "bun install\nrm -rf /" })).toThrow();
});

test("build script: quoted directories, the key removed on exit, outputs listed", () => {
  const p = { ...validateProject({ ...base, root_dir: "apps/mobile", prepare_cmd: "bun install", tasks: "bundleRelease" }), created_at: 0 };
  const s = buildScript(p, 7);
  expect(s).toContain("set -euo pipefail");
  expect(s).toContain("trap 'rm -f /home/user/pano/release.keystore /home/user/.gradle/gradle.properties' EXIT");
  expect(s).toContain("cd /home/user/src/'apps/mobile'");
  expect(s).toContain("bun install\n");
  expect(s).toContain("if [ ! -f gradlew ] && [ -f android/gradlew ]; then cd android; fi");
  expect(s).toContain("./gradlew --no-daemon --console=plain bundleRelease");
  expect(s).toContain("sha256sum -c -");
  expect(s).toContain("java-17-openjdk");
});

test("signing goes in as Gradle properties, escaped", () => {
  expect(propValue("a\\b")).toBe("a\\\\b");
  expect(propValue(" x")).toBe("\\ x");
  expect(propValue("şifre")).toBe("\\u015fifre");
  const props = signingProperties({ keystore: "", alias: "upload", storePassword: "p=ss:word", keyPassword: "k" }, "/home/user/pano/release.keystore");
  expect(props).toContain("android.injected.signing.store.file=/home/user/pano/release.keystore\n");
  expect(props).toContain("android.injected.signing.store.password=p=ss:word\n");
  expect(props).toContain("android.injected.signing.key.alias=upload\n");
});

test("only APK/AAB files from the build tree come back, with unique names", () => {
  const list = parseArtifacts(
    [
      "1000\t/home/user/src/android/app/build/outputs/apk/release/app-release.apk",
      "2000\t/home/user/src/android/wear/build/outputs/apk/release/app-release.apk",
      "3000\t/home/user/src/android/app/build/outputs/bundle/release/app-release.aab",
      "10\t/etc/passwd",
      "10\t/home/user/src/../pano/release.keystore",
      "10\t/home/user/src/x/build/outputs/evil name.apk",
      "",
    ].join("\n"),
  );
  expect(list.map((a) => a.name)).toEqual(["app-release.apk", "2-app-release.apk", "app-release.aab"]);
  expect(list[2]!.size).toBe(3000);
});

test("cost per build and the off state of the page", () => {
  expect(buildCost("large", 600)).toBeCloseTo(0.012);
  expect(buildCost("nope", 600)).toBe(0);
  const html = String(<AndroidPage v={{ connected: false, image: { name: "", status: "", current: false, error: "", at: 0 }, projects: [] }} csrf="c" imageLog={false} />);
  expect(html).toContain('action="/android/connect"');
  expect(html).not.toContain("New project");
});
