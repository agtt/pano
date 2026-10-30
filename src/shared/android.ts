// Android builds: what both processes need (the web serves the finished files
// itself, straight from disk; everything else goes through the agent).

import { paths } from "./config.ts";

/** File names an APK/AAB may have here (also what the download URL accepts). */
export const ARTIFACT_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,150}\.(apk|aab)$/;

/** root:pano 0750, files 0640: the web process reads them, nothing else. */
export const artifactFile = (build: number, name: string) => `${paths.data}/android/artifacts/${build}/${name}`;

/** JDKs and the Android SDK, root-owned and read-only for builds. */
export const toolchainDir = `${paths.opt}/android`;
