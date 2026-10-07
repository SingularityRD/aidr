import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { build } from "esbuild";
import { coreSourcePlugin, gatewayBundleOptions, readRuleSets } from "./bundle-options.mjs";

const root = resolve(import.meta.dirname, "..");
const entries = process.argv.slice(2).length ? process.argv.slice(2).map((path) => resolve(path)) :
	["gateway.test.mjs", "stdio.test.mjs", "interactions.test.mjs", "context.test.mjs"].map((name) => join(root, "src", "__tests__", name));
const directory = await mkdtemp(join(tmpdir(), "aidr-mcp-source-tests-"));
try {
	const outputs = [];
	const bundleOptions = gatewayBundleOptions({ ruleSets: await readRuleSets() });
	for (const [index, entry] of entries.entries()) {
		const output = join(directory, `${index}.test.mjs`);
		await build({ ...bundleOptions, entryPoints: [entry], outfile: output, external: [...bundleOptions.external, "esbuild"],
			plugins: [...bundleOptions.plugins, coreSourcePlugin()], logLevel: "silent" });
		outputs.push(output);
	}
	const pattern = process.env.AIDR_MCP_TEST_PATTERN;
	const result = spawnSync(process.execPath, ["--test", ...(pattern ? ["--test-name-pattern", pattern] : []), ...outputs], { stdio: "inherit", timeout: 60_000 });
	if (result.error) throw result.error;
	process.exitCode = result.status ?? 1;
} finally { await rm(directory, { recursive: true, force: true }); }
