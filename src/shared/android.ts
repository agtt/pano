// Android builds: what both processes need (the web serves the finished files
// itself, straight from disk; everything else goes through the agent).

import { paths } from "./config.ts";

/** Sizes Boat rents, with their price per hour (USD) for the cost shown next to a build. */
export const MACHINES = {
  small: { label: "small (2 vCPU, 4 GB)", perHour: 0.018 },
  default: { label: "default (4 vCPU, 8 GB)", perHour: 0.036 },
  large: { label: "large (8 vCPU, 16 GB)", perHour: 0.072 },
  xlarge: { label: "xlarge (16 vCPU, 32 GB)", perHour: 0.2 },
} as const;
export type Machine = keyof typeof MACHINES;

/** File names an APK/AAB may have here (also what the download URL accepts). */
export const ARTIFACT_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,150}\.(apk|aab)$/;

/** root:pano 0750, files 0640: the web process reads them, nothing else. */
export const artifactFile = (build: number, name: string) => `${paths.data}/android/artifacts/${build}/${name}`;

/** What the machine cost for a build, in USD (Boat bills by the second). */
export function buildCost(machine: string, seconds: number): number {
  const rate = (MACHINES as Record<string, { perHour: number }>)[machine]?.perHour ?? 0;
  return (rate * Math.max(0, seconds)) / 3600;
}
