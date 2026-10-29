import { expect, test } from "bun:test";
import { addAdmin, adminNames, checkOtp, issueGrant, grantValid, removeAdmin, resetAdmin, setAdminSecret } from "../src/agent/otp.ts";
import { needsOtp } from "../src/agent/rpc.ts";
import { checkRemove } from "../src/shared/admins.ts";
import { addUser, killSessions, listUsers, login, prepareHash, removeUser, session, setPassword, webDb } from "../src/web/auth.ts";
import { code } from "../src/web/totp.ts";
import { AdminsPage } from "../src/web/views/admins.tsx";

const step = () => Math.floor(Date.now() / 30_000);

test("guard: not yourself, not the last admin, only existing admins", () => {
  expect(() => checkRemove("a", "a", ["a", "b"])).toThrow("yourself");
  expect(() => checkRemove("cli", "a", ["a"])).toThrow("last admin");
  expect(() => checkRemove("a", "zed", ["a", "b"])).toThrow("no such admin");
  expect(() => checkRemove("a", "b", ["a", "b"])).not.toThrow();
});

test("agent: add makes a one-time secret, remove obeys the guard", async () => {
  setAdminSecret("root1", "JBSWY3DPEHPK3PXP");
  const n = await addAdmin("root1", "bob.b");
  expect(n.secret).toMatch(/^[A-Z2-7]{32}$/);
  expect(n.uri).toContain(n.secret);
  expect(adminNames()).toContain("bob.b");
  await expect(addAdmin("root1", "bob.b")).rejects.toThrow("already exists");
  await expect(addAdmin("root1", "Bad Name")).rejects.toThrow("username");
  // the new secret works for that admin
  expect(checkOtp("bob.b", code(n.secret, step()))).toBe(true);

  expect(() => removeAdmin("bob.b", "bob.b")).toThrow("yourself");
  removeAdmin("root1", "bob.b");
  expect(adminNames()).not.toContain("bob.b");
  expect(checkOtp("bob.b", code(n.secret, step() + 1))).toBe(false);
});

test("agent: the last admin cannot be removed; removal drops the user's grants", () => {
  for (const n of adminNames()) if (n !== "root1") removeAdmin("root1", n);
  expect(adminNames()).toEqual(["root1"]);
  expect(() => removeAdmin("cli", "root1")).toThrow("last admin");
  setAdminSecret("temp1", "JBSWY3DPEHPK3PXP");
  const g = issueGrant("temp1");
  removeAdmin("root1", "temp1");
  expect(grantValid(g, "temp1")).toBe(false);
});

test("agent: reset 2FA changes the secret; reset password only audits", async () => {
  setAdminSecret("carl1", "JBSWY3DPEHPK3PXP");
  expect(await resetAdmin("root1", "carl1", false)).toBeNull();
  const r = await resetAdmin("root1", "carl1", true);
  expect(r!.secret).not.toBe("JBSWY3DPEHPK3PXP");
  expect(checkOtp("carl1", code("JBSWY3DPEHPK3PXP", step()))).toBe(false);
  await expect(resetAdmin("root1", "nobody", true)).rejects.toThrow("no such admin");
});

test("management methods need a code; listing does not", () => {
  for (const m of ["admins.add", "admins.remove", "admins.reset"]) expect(needsOtp(m, {})).toBe(true);
  expect(needsOtp("admins.list", {})).toBe(false);
});

test("web: removing or resetting a user signs them out; listing carries created and last login", async () => {
  const hash = await prepareHash("correct horse battery");
  addUser("dave.d", hash);
  expect(() => addUser("dave.d", hash)).toThrow("already exists");
  const id = (webDb().query("SELECT id FROM users WHERE username = 'dave.d'").get() as { id: number }).id;
  const addSession = (sid: string) => webDb().query("INSERT INTO sessions (id_hash, user_id, csrf, created_at, seen_at) VALUES (?, ?, 'c', ?, ?)").run(sid, id, Math.floor(Date.now() / 1000), Math.floor(Date.now() / 1000));
  const count = () => (webDb().query("SELECT COUNT(*) AS n FROM sessions WHERE user_id = ?").get(id) as { n: number }).n;

  addSession("s1");
  killSessions("dave.d");
  expect(count()).toBe(0);

  addSession("s2");
  setPassword("dave.d", await prepareHash("another long password"));
  expect(count()).toBe(0);
  expect(await login("dave.d", "correct horse battery", "000000", "1.1.1.1")).toHaveProperty("error"); // old password is gone

  addSession("s3");
  removeUser("dave.d");
  expect(count()).toBe(0);
  expect(session("s3")).toBeNull();

  const u = listUsers()[0];
  if (u) expect(Object.keys(u).sort()).toEqual(["created_at", "last_login", "username"]);
  await expect(prepareHash("short")).rejects.toThrow("12 characters");
});

test("page says all admins are equal and hides self-removal", () => {
  const html = String(AdminsPage({ csrf: "c", me: "a", admins: [{ username: "a", created_at: 1, last_login: 0, twofa: true }, { username: "b", created_at: 1, last_login: 0, twofa: false }] }));
  expect(html).toContain("no roles");
  expect(html.match(/value="remove"/g)?.length).toBe(1);
});
