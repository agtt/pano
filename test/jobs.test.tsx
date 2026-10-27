import { expect, test } from "bun:test";
import { maskSecrets, renderSiteCron } from "../src/agent/jobs.ts";
import { judge, type Queue } from "../src/agent/queues.ts";
import type { Site } from "../src/agent/state.ts";
import { JobsPage } from "../src/web/views/jobs.tsx";

const site = {
  name: "shop.example.com",
  kind: "php",
  php_version: "8.4",
  enabled: 1,
  crons: [{ schedule: "*:0/5", command: "php public/wp-cron.php && echo done" }],
} as Site;

test("site cron runs as the site user with its PHP, at low priority", () => {
  const r = renderSiteCron(site, 0);
  expect(r.service).toContain("User=site-shop-example-com");
  expect(r.service).toContain("PATH=/opt/remi/php84/root/usr/bin:");
  expect(r.service).toContain("PHPRC=");
  expect(r.service).toContain("CPUWeight=20");
  expect(r.service).toContain("ProtectSystem=strict");
  expect(r.timer).toContain("OnCalendar=*:0/5");
  expect(r.script).toContain("php public/wp-cron.php && echo done");
  expect(r.script).not.toContain("exec ");
});

test("old crontab lines hide passwords", () => {
  expect(maskSecrets("0 3 * * * mysqldump -uroot -pS3cret db > x.sql")).toBe("0 3 * * * mysqldump -uroot -p•••• db > x.sql");
  expect(maskSecrets("* * * * * curl https://u:pw@x.io/?token=abc")).toBe("* * * * * curl https://u:••••@x.io/?token=••••");
  expect(maskSecrets("*/5 * * * * php /home/a/public_html/wp-cron.php")).toBe("*/5 * * * * php /home/a/public_html/wp-cron.php");
});

const q = (x: Partial<Queue>): Queue => ({ kind: "bullmq", key: "bull:mail", name: "mail", waiting: 0, active: 0, delayed: 0, failed: 0, completed: 0, paused: false, ...x });

test("queue monitor: failures summed and throttled, stuck queue raised and cleared", async () => {
  const sent: string[] = [];
  const problems = new Map<string, boolean>();
  const problem = async (k: string, bad: boolean) => void problems.set(k, bad);
  const notify = async (s: string) => void sent.push(s);
  const min = 60_000;
  await judge([q({ key: "bull:t1", failed: 2 })], problem, notify, 0);
  await judge([q({ key: "bull:t1", failed: 5 })], problem, notify, min);
  await judge([q({ key: "bull:t1", failed: 6 })], problem, notify, 2 * min);
  expect(sent).toEqual(["🟠 queue mail: 3 jobs failed (5 in the failed list)"]);
  await judge([q({ key: "bull:t1", failed: 6 })], problem, notify, 17 * min);
  expect(sent[1]).toBe("🟠 queue mail: 1 job failed (6 in the failed list)");

  for (let i = 0; i <= 10; i++) await judge([q({ key: "bull:t2", waiting: 40 })], problem, notify, i * min);
  expect(problems.get("queue:bull:t2")).toBe(true);
  await judge([q({ key: "bull:t2", waiting: 39, active: 1 })], problem, notify, 11 * min);
  expect(problems.get("queue:bull:t2")).toBe(false);
});

test("jobs page renders", () => {
  const html = String(
    <JobsPage
      csrf="c"
      jobs={{
        jobs: [{ owner: "site", name: "shop.example.com", index: 0, schedule: "*:0/5", command: "php x.php", armed: true, running: false, next: 2e9, last: 1.9e9, result: "exit-code", seconds: 3 }],
        crontabs: [{ user: "root", lines: ["0 3 * * * /root/backup.sh"] }],
      }}
      queues={{ enabled: true, store: { installed: true, managed: false, version: "7.2.4", active: "active" }, workers: [], queues: [q({ waiting: 4 })], error: "" }}
    />,
  );
  expect(html).toContain("exit-code");
  expect(html).toContain("/root/backup.sh");
  expect(html).toContain("bull:mail");
});
