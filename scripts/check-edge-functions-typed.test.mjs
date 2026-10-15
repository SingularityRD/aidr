import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { denoCheckArgs, edgeFunctionEntryPoints } from "./check-edge-functions-typed.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

test("the Deno type-check gate covers every deployed Edge Function", () => {
	const deployed = readdirSync(path.join(root, "supabase", "functions"), { withFileTypes: true })
		.filter((d) => d.isDirectory() && !d.name.startsWith("_") && !d.name.startsWith("."))
		.map((d) => `supabase/functions/${d.name}/index.ts`)
		.sort();
	const checked = edgeFunctionEntryPoints(root);
	assert.deepEqual(checked, deployed);
	// CP-5: the previously hand-maintained slice missed these auth-critical handlers.
	for (const name of ["device-start", "device-poll", "api-keys", "operator-admin", "notification-dispatch", "version-check"]) {
		assert.ok(checked.includes(`supabase/functions/${name}/index.ts`), `${name} must be type-checked`);
	}
	const args = denoCheckArgs(checked);
	assert.deepEqual(args.slice(0, 6), ["dlx", "deno@2.5.2", "check", "--node-modules-dir=none", "--lock=supabase/functions/deno.lock", "--frozen"]);
	assert.deepEqual(args.slice(6), checked);
});

test("a function directory without index.ts fails the gate instead of being skipped", () => {
	const dir = mkdtempSync(path.join(tmpdir(), "edge-typed-"));
	try {
		mkdirSync(path.join(dir, "supabase", "functions", "_shared"), { recursive: true });
		mkdirSync(path.join(dir, "supabase", "functions", "good"));
		writeFileSync(path.join(dir, "supabase", "functions", "good", "index.ts"), "export {};\n");
		mkdirSync(path.join(dir, "supabase", "functions", "broken"));
		assert.throws(() => edgeFunctionEntryPoints(dir), /broken/);
		rmSync(path.join(dir, "supabase", "functions", "broken"), { recursive: true });
		assert.deepEqual(edgeFunctionEntryPoints(dir), ["supabase/functions/good/index.ts"]);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});
