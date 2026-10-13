import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SCRIPT = path.join(root, "scripts", "demo-preflight.mjs");
const INPUTS = [
	"packages/dashboard/src/main.tsx",
	"packages/dashboard/src/ui/PublicLayout.tsx",
	"packages/dashboard/src/i18n/en.ts",
	"packages/dashboard/src/ui/pages/public/LandingPage.tsx",
	"scripts/dashboard-route-smoke.mjs",
	"packages/dashboard/tests/browser-smoke.manifest.json",
	"docs/sales/demo-script.md",
];

function runStatic(mutateDemoScript) {
	const workspace = mkdtempSync(path.join(tmpdir(), "aidr-demo-preflight-"));
	try {
		for (const relative of INPUTS) {
			mkdirSync(path.dirname(path.join(workspace, relative)), { recursive: true });
			cpSync(path.join(root, relative), path.join(workspace, relative));
		}
		const demo = path.join(workspace, "docs/sales/demo-script.md");
		if (mutateDemoScript) writeFileSync(demo, mutateDemoScript(readFileSync(demo, "utf8")));
		const env = { ...process.env, VITE_AIDR_COMMERCIAL_MODE: "", VITE_SALES_URL: "", VITE_SALES_EMAIL: "" };
		return spawnSync(process.execPath, [SCRIPT, "--static"], { cwd: workspace, env, encoding: "utf8" });
	} finally {
		rmSync(workspace, { recursive: true, force: true });
	}
}

test("the shipped demo script passes the static pre-flight", () => {
	const result = runStatic();
	assert.equal(result.status, 0, result.stderr);
});

test("a pre-flight that runs verify-enforcement after a plain `pnpm build` is NO-GO (OPS-7)", () => {
	const result = runStatic((text) => text.replace(/^pnpm build:release\b([^\n]*)\n(node scripts\/verify-enforcement\.mjs)/mu, "pnpm build$1\n$2"));
	assert.equal(result.status, 1);
	assert.match(result.stderr, /Demo preflight: NO-GO/u);
	assert.match(result.stderr, /a development build before verify-enforcement/u);
	assert.match(result.stderr, /missing a release build immediately before verify-enforcement/u);
});
