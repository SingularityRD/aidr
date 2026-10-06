import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { copyFile, mkdir, mkdtemp, readFile, readdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { copyPackageLicense } from "../../../scripts/copy-package-license.mjs";

const packageRoot = resolve(import.meta.dirname, "..");
const entries = [
	["cli.mjs", "aidr-mcp-gateway.mjs"],
	["approve.mjs", "aidr-mcp-approve.mjs"],
	["stdio-cli.mjs", "aidr-mcp-stdio.mjs"],
	["library.mjs", "aidr-mcp-library.mjs"],
];

/** Isolated installed-package fixture; never modifies shared dist or release signing material. */
export async function buildGatewayPackageFixture(root) {
	const installed = join(root, "node_modules", "@singularityrd", "aidr-mcp-gateway");
	const dist = join(installed, "dist");
	const packageManifest = JSON.parse(await readFile(join(packageRoot, "package.json"), "utf8"));
	await mkdir(dist, { recursive: true });
	await copyFile(join(packageRoot, "package.json"), join(installed, "package.json"));
	await copyFile(join(packageRoot, "README.md"), join(installed, "README.md"));
	await Promise.all(entries.map(([entry, output]) => build({
		entryPoints: [join(packageRoot, "src", entry)], outfile: join(dist, output),
		bundle: true, platform: "node", format: "esm", target: "node22.12", logLevel: "silent",
		plugins: [{ name: "core-source", setup(builder) {
			builder.onResolve({ filter: /core\/dist\/.*\.js$/ }, ({ path, resolveDir }) => ({
				path: resolve(resolveDir, path.replace("/dist/", "/src/").replace(/\.js$/, ".ts")),
			}));
		} }],
	})));
	await copyPackageLicense({ packageRoot: installed });
	const keys = generateKeyPairSync("ed25519");
	const manifestRaw = `${JSON.stringify({
		schema_version: 1, artifact_id: "mcp-gateway/dist", artifact_version: packageManifest.version,
		created_at: new Date().toISOString(),
		files: await Promise.all((await readdir(dist)).sort().map(async (path) => ({
			path, sha256: createHash("sha256").update(await readFile(join(dist, path))).digest("hex"),
		}))),
	})}\n`;
	await writeFile(join(dist, "aidr-artifact.manifest.json"), manifestRaw);
	await writeFile(join(dist, "aidr-artifact.manifest.sig"), sign(null, Buffer.from(manifestRaw), keys.privateKey).toString("base64"));
	const home = join(root, "home");
	await mkdir(join(home, ".singularity-aidr"), { recursive: true });
	await writeFile(join(home, ".singularity-aidr", "config.json"), JSON.stringify({
		integrity: { enabled: true, verify_on_start: true, public_keys_pem: [keys.publicKey.export({ type: "spki", format: "pem" }).toString()] },
		logging: { enabled: false },
	}));
	return { root, installed, dist, home, environment: { ...process.env, HOME: home, AIDR_COMMERCIAL: "1" } };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	const fixture = await buildGatewayPackageFixture(await mkdtemp(join(tmpdir(), "aidr-mcp-library-fixture-")));
	// Deliberately retain this named temporary fixture for coordinated integration consumers.
	process.stdout.write(`${JSON.stringify({ root: fixture.root, installed: fixture.installed, dist: fixture.dist, home: fixture.home })}\n`);
}
