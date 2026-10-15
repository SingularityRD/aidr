#!/usr/bin/env node
// Regenerate assets/icons/ (app icon PNGs, icon.ico, tray icons) from the
// product mark, branding/singularity-mark.svg, by rendering it with Electron
// itself in an offscreen window. No image library is needed.
//
//   pnpm --filter @singularityrd/aidr-desktop icons

import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { electronBinary } from "./electron-path.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const mark = resolve(root, "..", "..", "branding", "singularity-mark.svg");
const out = join(root, "assets", "icons");

const result = spawnSync(electronBinary(), [join(root, "scripts", "render-icons.cjs"), mark, out], {
	stdio: "inherit",
	env: { ...process.env, ELECTRON_ENABLE_LOGGING: "0" },
});
process.exit(result.status ?? 1);
