import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const serverFile = join(dirname(fileURLToPath(import.meta.url)), "server.mjs");
const anonKey = "sb_publishable_test_key";

test("dashboard exposes configured Azure auth while rejecting unknown methods", async () => {
	const directory = mkdtempSync(join(tmpdir(), "aidr-dashboard-auth-"));
	writeFileSync(join(directory, "index.html"), "<!doctype html><title>AIDR test</title>");
	const env = {
		...process.env,
		AIDR_STATIC_DIR: directory,
		VITE_SUPABASE_URL: "https://api.customer.example",
		VITE_SUPABASE_ANON_KEY: anonKey,
		AIDR_AUTH_METHODS: "password,azure,azure",
		PORT: "0",
	};
	let child;
	try {
		const invalid = spawnSync(process.execPath, [serverFile], { env: { ...env, AIDR_AUTH_METHODS: "password,unapproved" }, encoding: "utf8", timeout: 10_000 });
		assert.notEqual(invalid.status, 0);
		assert.match(invalid.stderr, /Invalid AIDR_AUTH_METHODS/);

		child = spawn(process.execPath, [serverFile], { env, stdio: ["ignore", "pipe", "pipe"] });
		const port = await new Promise((resolvePort, rejectPort) => {
			let output = "";
			const timeout = setTimeout(() => rejectPort(new Error("Dashboard did not start")), 10_000);
			child.stdout.on("data", (chunk) => {
				output += chunk.toString();
				const match = output.match(/AIDR dashboard listening on (\d+)/);
				if (match) { clearTimeout(timeout); resolvePort(Number(match[1])); }
			});
			child.once("error", (error) => { clearTimeout(timeout); rejectPort(error); });
			child.once("exit", (code) => { clearTimeout(timeout); rejectPort(new Error(`Dashboard exited before readiness: ${code}`)); });
		});
		const response = await fetch(`http://127.0.0.1:${port}/runtime-config.js`, { signal: AbortSignal.timeout(5_000) });
		assert.equal(response.status, 200);
		const body = await response.text();
		const config = JSON.parse(body.replace(/^window\.__AIDR_CONFIG__=/, "").replace(/;$/, ""));
		assert.deepEqual(config.authMethods, ["password", "azure"]);
		assert.equal(config.supabaseUrl, "https://api.customer.example");
	} finally {
		child?.kill();
		assert.equal(dirname(realpathSync(directory)), realpathSync(tmpdir()));
		rmSync(directory, { recursive: true, force: true });
	}
});
