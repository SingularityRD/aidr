/**
 * Cross-platform rm -rf with a verification + fallback.
 *
 * Why: On some Windows setups `fs.rmSync(..., { recursive: true })` can appear
 * to succeed but leave directories intact. This script ensures we actually
 * remove the targets before continuing.
 *
 * Usage:
 *   node scripts/rmrf.mjs dist tsconfig.tsbuildinfo
 */

import fs from "node:fs";
import path from "node:path";

const targets = process.argv.slice(2);
for (const raw of targets) {
	if (!raw) continue;
	const p = path.resolve(process.cwd(), raw);
	rmrf(p);
}

function rmrf(p) {
	if (!fs.existsSync(p)) return;

	try {
		fs.rmSync(p, { recursive: true, force: true });
	} catch {
		// Continue to fallback.
	}

	if (!fs.existsSync(p)) return;

	// Fallback: manual recursion.
	try {
		const st = fs.lstatSync(p);
		if (st.isSymbolicLink()) {
			try {
				fs.unlinkSync(p);
			} catch {}
			return;
		}

		if (st.isDirectory()) {
			const entries = fs.readdirSync(p, { withFileTypes: true });
			for (const e of entries) {
				rmrf(path.join(p, e.name));
			}
			try {
				fs.rmdirSync(p);
			} catch {}
			return;
		}

		// File
		try {
			fs.unlinkSync(p);
		} catch {}
	} catch {
		// Ignore and verify below.
	}

	if (fs.existsSync(p)) {
		throw new Error(`rmrf: failed to remove ${p}`);
	}
}

