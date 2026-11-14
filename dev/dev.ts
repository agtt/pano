// Local development on any OS: agent + web in one process, every path under
// dev/root, every system command logged instead of executed.
//   bun run dev          → http://127.0.0.1:7800  (admin / pano-dev-password)
//   bun run dev/otp.ts   → current authenticator code for the dev admin

import { cp, mkdir } from "node:fs/promises";
import { join } from "node:path";

const root = join(import.meta.dir, "root");
process.env.PANO_ROOT = root;
process.env.PANO_DRY_RUN = "1";
process.env.PANO_INSECURE_COOKIES = "1";
process.env.PANO_ASK_PORT ??= "17801";
process.env.PANO_HOOK_PORT ??= "17802";

await mkdir(join(root, "usr/local"), { recursive: true });
await cp(join(import.meta.dir, "../test/fixtures/lsws"), join(root, "usr/local/lsws"), { recursive: true });

const { startAgent } = await import("../src/agent/main.ts");
await startAgent();

const { createUser, userCount } = await import("../src/web/auth.ts");
if (userCount() === 0) {
  const { secret } = await createUser("admin", "pano-dev-password");
  // as `pano admin` does: the agent keeps the 2FA secret, the web never stores it
  const { setAdminSecret } = await import("../src/agent/otp.ts");
  setAdminSecret("admin", secret);
  console.log(`[dev] admin / pano-dev-password, TOTP secret ${secret}`);
}

const { env } = await import("../src/shared/config.ts");
const { createWebApp, createHookApp } = await import("../src/web/server.tsx");
Bun.serve({ hostname: env.webHost, port: env.webPort, fetch: createWebApp().fetch });
Bun.serve({ hostname: "127.0.0.1", port: env.hookPort, fetch: createHookApp().fetch });
console.log(`[dev] http://${env.webHost}:${env.webPort}  (code: bun run dev/otp.ts)`);
