import { expect, test } from "bun:test";
import { assetName, parseSums } from "../src/release.ts";

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
