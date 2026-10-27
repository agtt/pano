// Preloaded before every test file: all paths go to a throwaway root and no
// system command is executed.
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

process.env.PANO_ROOT = mkdtempSync(join(tmpdir(), "pano-test-"));
process.env.PANO_DRY_RUN = "1";
