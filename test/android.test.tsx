import { expect, test } from "bun:test";
import { buildScript, missingPackages, signScript, validateProject } from "../src/agent/android.ts";
import { validateAppInput } from "../src/agent/apps.ts";
import { sandboxArgv } from "../src/agent/throwaway.ts";
import { AndroidPage } from "../src/web/views/android.tsx";

const base = { name: "shop-app", repo: "git@github.com:acme/shop.git", branch: "main" };

test("Android projects: defaults, and nothing reaches the script unchecked", () => {
  const p = validateProject(base);
  expect(p).toMatchObject({ tasks: "assembleRelease", jdk: 17, memory_mb: 6144, timeout_min: 60, root_dir: "", gradle_dir: "", sdk_packages: "" });
  expect(validateProject({ ...base, tasks: " :app:bundleRelease  assembleDebug " }).tasks).toBe(":app:bundleRelease assembleDebug");
  expect(validateProject({ ...base, sdk_packages: "ndk;27.1.12297006 platforms;android-36" }).sdk_packages).toBe("ndk;27.1.12297006 platforms;android-36");
  expect(() => validateProject({ ...base, tasks: "bundleRelease --init-script=/tmp/x" })).toThrow();
  expect(() => validateProject({ ...base, tasks: "bundleRelease;id" })).toThrow();
  expect(() => validateProject({ ...base, sdk_packages: "ndk;1 $(id)" })).toThrow();
  expect(() => validateProject({ ...base, repo: "file:///srv/pano/git/shop.git" })).toThrow();
  expect(() => validateProject({ ...base, root_dir: "../etc" })).toThrow();
  expect(() => validateProject({ ...base, memory_mb: 512 })).toThrow();
  expect(() => validateProject({ ...base, jdk: 11 })).toThrow();
  expect(() => validateProject({ ...base, prepare_cmd: "bun install\nrm -rf /" })).toThrow();
});

test("build script: source on stdin, quoted directories, outputs copied out", () => {
  const p = { ...validateProject({ ...base, root_dir: "apps/mobile", prepare_cmd: "bun install", tasks: "bundleRelease" }), created_at: 0 };
  const s = buildScript(p);
  expect(s).toContain("set -euo pipefail");
  expect(s).toContain("tar -xzf - -C src --no-same-owner");
  expect(s).toContain("cd src/'apps/mobile'");
  expect(s).toContain("bun install\n");
  expect(s).toContain("if [ ! -f gradlew ] && [ -f android/gradlew ]; then cd android; fi");
  expect(s).toContain("./gradlew --no-daemon --console=plain bundleRelease");
  expect(s).toContain('cp "$f" "$HOME/out/$d"');
});

test("signing reads the key only from systemd credentials", () => {
  const s = signScript();
  expect(s).toContain('C="$CREDENTIALS_DIRECTORY"');
  expect(s).toContain("--ks-pass env:PANO_SP");
  expect(s).toContain("-storepass:env PANO_SP");
  expect(s).not.toContain("/etc/pano");
});

test("throwaway sandbox: own user and directory, pano out of sight, no network when asked", () => {
  const net = sandboxArgv("pano-android-build-7", { memoryMb: 6144, timeoutMin: 60, network: true }, "true").join("\n");
  for (const p of ["DynamicUser=yes", "StateDirectory=pano-android-build-7", "MemoryMax=6144M", "RuntimeMaxSec=3600", "NoNewPrivileges=yes", "InaccessiblePaths=-/etc/pano -/var/lib/pano -/run/pano -/srv/pano", "IPAddressDeny=169.254.169.254/32"]) {
    expect(net).toContain(p);
  }
  const off = sandboxArgv("pano-android-sign-7", { memoryMb: 1024, timeoutMin: 10, network: false, props: ["LoadCredential=alias:/etc/pano/secrets/android/x/alias"] }, "true").join("\n");
  expect(off).toContain("PrivateNetwork=yes");
  expect(off).toContain("LoadCredential=alias:");
  expect(() => sandboxArgv("../etc", { memoryMb: 1, timeoutMin: 1, network: false }, "true")).toThrow();
});

test("a missing SDK package is named from the Gradle output", () => {
  const log = "FAILURE: Build failed\n> Failed to install the following SDK components:\n      ndk;27.1.12297006 NDK (Side by side) 27.1.12297006\n  The SDK directory is not writable";
  expect(missingPackages(log)).toEqual(["ndk;27.1.12297006"]);
  expect(missingPackages("BUILD SUCCESSFUL")).toEqual([]);
});

test("apps: the throwaway build sandbox is off unless asked for", () => {
  const app = { name: "web", runtime: "bun", runtime_version: "1.3.0", repo: "https://github.com/acme/web", domains: "web.example.com" };
  expect(validateAppInput(app).build_isolated).toBe(0);
  expect(validateAppInput({ ...app, build_isolated: "1" }).build_isolated).toBe(1);
});

test("the Android page offers the toolchain before anything else", () => {
  const tc = { supported: true, installed: false, state: "", error: "", jdks: [], buildTools: [] };
  const html = String(<AndroidPage v={{ toolchain: tc, projects: [] }} csrf="c" toolchainLog={false} />);
  expect(html).toContain('action="/android-toolchain"');
  expect(html).not.toContain("New project");
});
