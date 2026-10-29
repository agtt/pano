// Server-rendered SVG charts for the metrics history: no script, no library, no
// inline styles (the CSP forbids them). Colors come from CSS variables, so the
// charts follow light and dark; each chart has a title and a description with the
// numbers, and a native tooltip on every column.

import { fmtBytes, t } from "../i18n.ts";

export type Point = [ts: number, value: number];
export type History = { range: string; from: number; to: number; step: number; series: Record<string, Point[]> };

// ---- geometry (pure) -----------------------------------------------------------

/** A round axis maximum at or above v: 1, 2, 5 times a power of ten. */
export function niceMax(v: number): number {
  if (!(v > 0)) return 1;
  const exp = 10 ** Math.floor(Math.log10(v));
  const f = v / exp;
  return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * exp;
}

/** Runs of points with no hole longer than maxGap seconds: a gap in the data stays a gap in the line. */
export function segments(points: Point[], maxGap: number): Point[][] {
  const out: Point[][] = [];
  let cur: Point[] = [];
  for (const p of points) {
    const last = cur[cur.length - 1];
    if (last && p[0] - last[0] > maxGap) {
      out.push(cur);
      cur = [];
    }
    cur.push(p);
  }
  if (cur.length) out.push(cur);
  return out;
}

const n1 = (n: number) => String(Math.round(n * 10) / 10);

export function linePath(segs: Point[][], x: (ts: number) => number, y: (v: number) => number): string {
  return segs.map((s) => s.map((p, i) => `${i ? "L" : "M"}${n1(x(p[0]))} ${n1(y(p[1]))}`).join("")).join("");
}

/** Filled area under each run down to `base`. */
export function areaPath(segs: Point[][], x: (ts: number) => number, y: (v: number) => number, base: number): string {
  return segs
    .map((s) => {
      const top = s.map((p, i) => `${i ? "L" : "M"}${n1(x(p[0]))} ${n1(y(p[1]))}`).join("");
      const first = x(s[0]![0]);
      const last = x(s[s.length - 1]![0]);
      return `${top}L${n1(last)} ${n1(base)}L${n1(first)} ${n1(base)}Z`;
    })
    .join("");
}

// ---- formatting ------------------------------------------------------------------

const pad = (n: number) => String(n).padStart(2, "0");
/** "14:05" for short ranges, "10-29" for long ones. */
export function fmtTick(ts: number, long: boolean): string {
  const d = new Date(ts * 1000);
  return long ? `${pad(d.getMonth() + 1)}-${pad(d.getDate())}` : `${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
const fmtFull = (ts: number) => {
  const d = new Date(ts * 1000);
  return `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
};

export const fmtPct = (v: number) => `${v >= 10 ? Math.round(v) : v.toFixed(1)}%`;
export const fmtRate = (v: number) => `${fmtBytes(v) || "0 B"}/s`;
export const fmtLoad = (v: number) => v.toFixed(2);
const bytes = (v: number) => fmtBytes(v) || "0 B";

// ---- chart -------------------------------------------------------------------------

const W = 600;
const H = 150;
const M = { l: 48, r: 10, t: 8, b: 20 };
const COLUMNS = 48;

export type ChartSeries = { label: string; points: Point[] };

export function Chart(p: {
  id: string;
  title: string;
  series: ChartSeries[];
  h: History;
  fmt: (v: number) => string;
  /** fixed axis maximum (100 for percent, total memory); otherwise rounded up from the data */
  max?: number;
  /** minimum for the automatic maximum, so a quiet load does not fill the whole chart */
  floor?: number;
}) {
  const all = p.series.flatMap((s) => s.points.map((q) => q[1]));
  if (!all.length) {
    return (
      <figure class="chart">
        <figcaption>{p.title}</figcaption>
        <p class="muted small">{t("Collecting data: the first points appear within a minute or two.")}</p>
      </figure>
    );
  }
  const long = p.h.to - p.h.from > 86_400;
  const top = p.max && p.max > 0 ? p.max : Math.max(p.floor ?? 0, niceMax(Math.max(...all)));
  const x = (ts: number) => M.l + ((ts - p.h.from) / (p.h.to - p.h.from || 1)) * (W - M.l - M.r);
  const y = (v: number) => H - M.b - (Math.min(Math.max(v, 0), top) / top) * (H - M.t - M.b);
  const base = H - M.b;
  const gap = p.h.step * 2.5;
  const segs = p.series.map((s) => segments(s.points, gap));
  const area = p.series.length === 1;

  const stats = p.series
    .map((s) => {
      const vs = s.points.map((q) => q[1]);
      const now = vs[vs.length - 1]!;
      return `${s.label}: ${t("now")} ${p.fmt(now)}, ${t("average")} ${p.fmt(vs.reduce((a, b) => a + b, 0) / vs.length)}, ${t("peak")} ${p.fmt(Math.max(...vs))}`;
    })
    .join("; ");

  // One transparent column per slice of time; its tooltip lists the nearest value of each series.
  const cw = (W - M.l - M.r) / COLUMNS;
  const nearest = (pts: Point[], ts: number) => {
    let best: Point | undefined;
    for (const q of pts) if (Math.abs(q[0] - ts) <= p.h.step && (!best || Math.abs(q[0] - ts) < Math.abs(best[0] - ts))) best = q;
    return best;
  };
  const columns = Array.from({ length: COLUMNS }, (_, i) => {
    const ts = p.h.from + ((i + 0.5) / COLUMNS) * (p.h.to - p.h.from);
    const vals = p.series.flatMap((s) => {
      const q = nearest(s.points, ts);
      return q ? [`${s.label} ${p.fmt(q[1])}`] : [];
    });
    return { i, tip: vals.length ? `${fmtFull(ts)} · ${vals.join(" · ")}` : "" };
  });

  const ticks = [0, 0.5, 1];
  return (
    <figure class="chart">
      <figcaption>
        {p.title}
        {p.series.length > 1 ? (
          <span class="legend">
            {p.series.map((s, i) => (
              <span>
                <i class={`sw s${i + 1}`} /> {s.label}
              </span>
            ))}
          </span>
        ) : null}
      </figcaption>
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-labelledby={`${p.id}-t ${p.id}-d`}>
        <title id={`${p.id}-t`}>{p.title}</title>
        <desc id={`${p.id}-d`}>{stats}</desc>
        {ticks.map((f) => (
          <g>
            <line class="grid" x1={M.l} x2={W - M.r} y1={n1(y(top * f))} y2={n1(y(top * f))} />
            <text class="tick" x={M.l - 6} y={n1(y(top * f) + 3)} text-anchor="end">
              {p.fmt(top * f)}
            </text>
          </g>
        ))}
        <text class="tick" x={M.l} y={H - 5}>
          {fmtTick(p.h.from, long)}
        </text>
        <text class="tick" x={(M.l + W - M.r) / 2} y={H - 5} text-anchor="middle">
          {fmtTick((p.h.from + p.h.to) / 2, long)}
        </text>
        <text class="tick" x={W - M.r} y={H - 5} text-anchor="end">
          {fmtTick(p.h.to, long)}
        </text>
        {p.series.map((_, i) => (
          <g>
            {area ? <path class={`area s${i + 1}`} d={areaPath(segs[i]!, x, y, base)} /> : null}
            <path class={`line s${i + 1}`} d={linePath(segs[i]!, x, y)} />
          </g>
        ))}
        {columns.map((c) =>
          c.tip ? (
            <rect class="hit" x={n1(M.l + c.i * cw)} y={M.t} width={n1(cw)} height={H - M.t - M.b}>
              <title>{c.tip}</title>
            </rect>
          ) : null,
        )}
      </svg>
    </figure>
  );
}

// ---- pages ---------------------------------------------------------------------------

export const RANGE_LIST = ["1h", "24h", "7d", "30d"] as const;
export const parseRange = (s: string | undefined): (typeof RANGE_LIST)[number] => (RANGE_LIST as readonly string[]).includes(s ?? "") ? (s as (typeof RANGE_LIST)[number]) : "24h";

export function RangeNav({ base, range }: { base: string; range: string }) {
  return (
    <nav class="row" aria-label={t("Time range")}>
      {RANGE_LIST.map((r) => (
        <a class={`btn small${r === range ? " primary" : ""}`} href={`${base}?range=${r}`} aria-current={r === range ? "true" : undefined}>
          {r}
        </a>
      ))}
    </nav>
  );
}

const last = (pts: Point[] | undefined) => pts?.[pts.length - 1]?.[1];

/** CPU, memory, load, network and one chart per disk. */
export function ServerCharts({ h, base }: { h: History; base: string }) {
  const s = h.series;
  const disks = Object.keys(s)
    .filter((k) => k.startsWith("disk:"))
    .map((k) => k.slice(5));
  return (
    <section class="card">
      <div class="card-head">
        <h2>{t("History")}</h2>
        <RangeNav base={base} range={h.range} />
      </div>
      <div class="charts">
        <Chart id="c-cpu" title="CPU" h={h} series={[{ label: "CPU", points: s.cpu ?? [] }]} max={100} fmt={fmtPct} />
        <Chart
          id="c-mem"
          title={t("Memory")}
          h={h}
          series={[{ label: t("Memory"), points: s.mem ?? [] }, ...(last(s.swaptotal) ? [{ label: "Swap", points: s.swap ?? [] }] : [])]}
          max={last(s.memtotal)}
          fmt={bytes}
        />
        <Chart id="c-load" title={t("Load")} h={h} series={[{ label: "load1", points: s.load1 ?? [] }]} floor={1} fmt={fmtLoad} />
        <Chart id="c-net" title={t("Network")} h={h} series={[{ label: "rx", points: s.rx ?? [] }, { label: "tx", points: s.tx ?? [] }]} fmt={fmtRate} />
        {disks.map((d, i) => (
          <Chart id={`c-disk${i}`} title={`${t("Disk")} ${d}`} h={h} series={[{ label: d, points: s[`disk:${d}`] ?? [] }]} max={last(s[`disktotal:${d}`])} fmt={bytes} />
        ))}
      </div>
    </section>
  );
}

/** One app: memory (against its limit when it has one) and CPU in percent of one core. */
export function AppCharts({ h, app, limitMb }: { h: History; app: string; limitMb?: number }) {
  const s = h.series;
  const mem = s[`app:${app}:mem`] ?? [];
  const limit = limitMb ? limitMb * 1024 * 1024 : 0;
  const peak = Math.max(0, ...mem.map((q) => q[1]));
  return (
    <section class="card">
      <div class="card-head">
        <h2>{t("History")}</h2>
        <RangeNav base={`/apps/${app}`} range={h.range} />
      </div>
      <div class="charts">
        <Chart id="c-app-mem" title={t("Memory")} h={h} series={[{ label: t("Memory"), points: mem }]} max={limit && peak <= limit ? limit : undefined} fmt={bytes} />
        <Chart id="c-app-cpu" title={t("CPU (% of one core)")} h={h} series={[{ label: "CPU", points: s[`app:${app}:cpu`] ?? [] }]} floor={100} fmt={fmtPct} />
      </div>
    </section>
  );
}
