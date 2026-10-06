import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { build } from "esbuild";

const root = resolve(import.meta.dirname, "..");
const entries = process.argv.slice(2).length ? process.argv.slice(2).map((path) => resolve(path)) :
	["gateway.test.mjs", "stdio.test.mjs", "interactions.test.mjs"].map((name) => join(root, "src", "__tests__", name));
const directory = await mkdtemp(join(tmpdir(), "aidr-mcp-source-tests-"));
try {
	const outputs = [];
	for (const [index, entry] of entries.entries()) {
		const output = join(directory, `${index}.test.mjs`);
		await build({ entryPoints: [entry], outfile: output, bundle: true, platform: "node", format: "esm", target: "node22.12",
			plugins: [{ name: "core-source", setup(builder) {
				builder.onResolve({ filter: /core\/dist\/.*\.js$/ }, ({ path, resolveDir }) => ({ path: resolve(resolveDir, path.replace("/dist/", "/src/").replace(/\.js$/, ".ts")) }));
			} }], logLevel: "silent" });
		outputs.push(output);
	}
	const pattern = process.env.AIDR_MCP_TEST_PATTERN;
	const result = spawnSync(process.execPath, ["--test", ...(pattern ? ["--test-name-pattern", pattern] : []), ...outputs], { stdio: "inherit", timeout: 60_000 });
	if (result.error) throw result.error;
	process.exitCode = result.status ?? 1;
} finally { await rm(directory, { recursive: true, force: true }); }
