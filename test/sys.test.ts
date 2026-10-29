import { expect, test } from "bun:test";
import { parseShow } from "../src/agent/sys.ts";

test("one systemctl show for many units: blocks map back to the units asked", () => {
  const out = "ActiveState=active\nMemoryCurrent=1234\nActiveEnterTimestamp=Wed 2026-10-28 10:00:00 UTC\n\nActiveState=inactive\nMemoryCurrent=[not set]\nActiveEnterTimestamp=\n";
  const m = parseShow(out, ["a@a.service", "b@b.service", "c.service"]);
  expect(m.get("a@a.service")).toEqual({ ActiveState: "active", MemoryCurrent: "1234", ActiveEnterTimestamp: "Wed 2026-10-28 10:00:00 UTC" });
  expect(m.get("b@b.service")?.ActiveState).toBe("inactive");
  expect(m.get("b@b.service")?.ActiveEnterTimestamp).toBe("");
  expect(m.get("c.service")).toEqual({}); // missing block: nothing known
});
