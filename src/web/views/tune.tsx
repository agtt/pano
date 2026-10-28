import { t } from "../i18n.ts";
import { Card, Csrf } from "./layout.tsx";

export type TuneView = { on: boolean; values: { key: string; now: string; pano: string }[] };

export function TuneCard({ v, csrf }: { v: TuneView; csrf: string }) {
  return (
    <Card title="Kernel network settings">
      <p class="muted small">
        For many short HTTP connections and HTTP/3: BBR congestion control, larger connection queues and UDP buffers, less swapping. Common on web servers;
        turn it off to keep the distribution's values (they return at the next reboot).
      </p>
      <form method="post" action="/security/tune" class="row">
        <Csrf token={csrf} />
        <input type="hidden" name="on" value={v.on ? "0" : "1"} />
        <button class="btn">{v.on ? "Turn off" : "Turn on"}</button>
      </form>
      <details>
        <summary class="muted small">Values now</summary>
        <table class="compact">
          <thead>
            <tr>
              <th>{t("Name")}</th>
              <th>Now</th>
              <th>pano</th>
            </tr>
          </thead>
          <tbody>
            {v.values.map((x) => (
              <tr>
                <td class="small">
                  <code>{x.key}</code>
                </td>
                <td class="small">{x.now || "—"}</td>
                <td class="small muted">{x.pano || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    </Card>
  );
}
