import { expect, test } from "bun:test";
import { checkOtp, grantValid, issueGrant, setAdminSecret } from "../src/agent/otp.ts";
import { ENV_MASK, needsOtp } from "../src/agent/rpc.ts";
import { code, newSecret } from "../src/web/totp.ts";

const step = () => Math.floor(Date.now() / 30_000);

test("codes are checked by the agent: once each, five misses lock", () => {
  const secret = newSecret();
  setAdminSecret("alice", secret);
  const now = code(secret, step());
  expect(checkOtp("alice", now)).toBe(true);
  expect(checkOtp("alice", now)).toBe(false); // replay
  expect(checkOtp("bob", now)).toBe(false); // unknown user

  setAdminSecret("carol", secret);
  for (let i = 0; i < 5; i++) checkOtp("carol", "000000");
  expect(checkOtp("carol", code(secret, step() + 1))).toBe(false); // locked even with a right code
});

test("grants are bound to the admin and expire", () => {
  const g = issueGrant("alice");
  expect(grantValid(g, "alice")).toBe(true);
  expect(grantValid(g, "mallory")).toBe(false);
  expect(grantValid("made-up", "alice")).toBe(false);
});

test("secrets, destruction and network access need a code", () => {
  for (const m of ["apps.env.reveal", "apps.env.set", "db.drop", "pg.drop", "vpn.peer.add", "backup.key.export", "services.valkeyUrl"]) expect(needsOtp(m, {})).toBe(true);
  for (const m of ["apps.list", "apps.env.get", "apps.deploy", "apps.addDatabase", "pg.create"]) expect(needsOtp(m, {})).toBe(false);
  expect(ENV_MASK).toBe("••••••••");
});
