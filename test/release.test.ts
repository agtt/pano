import { expect, test } from "bun:test";
import { assetName, cmpVersion, parseSums } from "../src/release.ts";

const A = "a".repeat(64);
const B = "B".repeat(64);

test("SHA256SUMS lines parse in text and binary mode, junk is skipped", () => {
  const sums = parseSums(`${A}  pano-linux-x64\n${B} *pano-linux-arm64\n\nnot a line\n${"c".repeat(63)}  short\n`);
  expect(sums.get("pano-linux-x64")).toBe(A);
  expect(sums.get("pano-linux-arm64")).toBe("b".repeat(64));
  expect(sums.size).toBe(2);
});

test("release asset names follow the CPU", () => {
  expect(assetName("x64")).toBe("pano-linux-x64");
  expect(assetName("arm64")).toBe("pano-linux-arm64");
  expect(() => assetName("ia32")).toThrow();
});

test("versions compare on x.y.z, a leading v and any suffix ignored", () => {
  expect(cmpVersion("v0.1.0", "0.1.0")).toBe(0);
  expect(cmpVersion("v0.1.0", "0.1.0-dev")).toBe(0);
  expect(cmpVersion("v0.2.0", "0.1.9")).toBe(1);
  expect(cmpVersion("0.1.9", "v0.10.0")).toBe(-1);
});

test("install.sh has a minimum version the release workflow raises", async () => {
  const installer = await Bun.file(new URL("../install.sh", import.meta.url)).text();
  const workflow = await Bun.file(new URL("../.github/workflows/release.yml", import.meta.url)).text();
  expect(installer).toMatch(/^MIN_VERSION="[0-9]+\.[0-9]+\.[0-9]+"$/m);
  expect(installer).toContain('version_lt "$SIGNED_TAG" "$MIN_VERSION"');
  expect(workflow).toContain("s/^MIN_VERSION=.*/MIN_VERSION=");
});
