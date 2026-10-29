// The panel's CSS and JS, built into the binary. URLs carry a hash of the content, so browsers
// keep them for a year and still fetch the new ones right after an update.

import { createHash } from "node:crypto";
import css from "./static/app.css" with { type: "text" };
import js from "./static/app.js" with { type: "text" };

const tag = (s: string) => createHash("sha256").update(s).digest("hex").slice(0, 10);

export const assets = {
  css: { body: css, url: `/static/app.css?v=${tag(css)}`, type: "text/css; charset=utf-8" },
  js: { body: js, url: `/static/app.js?v=${tag(js)}`, type: "text/javascript; charset=utf-8" },
};
