import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { copyFile, mkdir, mkdtemp, readFile, readdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { copyPackageLicense } from "../../../scripts/copy-package-license.mjs";
import { coreSourcePlugin, GATEWAY_ENTRIES, gatewayBundleOptions, readRuleSets } from "./bundle-options.mjs";

const packageRoot = resolve(import.meta.dirname, "..");

/** Isolated installed-package fixture; never modifies shared dist or release signing material. */
export async function buildGatewayPackageFixture(root) {
	const installed = join(root, "node_modules", "@singularityrd", "aidr-mcp-gateway");
	const dist = join(installed, "dist");
	const packageManifest = JSON.parse(await readFile(join(packageRoot, "package.json"), "utf8"));
	await mkdir(dist, { recursive: true });
	await copyFile(join(packageRoot, "package.json"), join(installed, "package.json"));
	await copyFile(join(packageRoot, "README.md"), join(installed, "README.md"));
	const bundleOptions = gatewayBundleOptions({ ruleSets: await readRuleSets() });
	await Promise.all(GATEWAY_ENTRIES.map(([entry, output]) => build({
		...bundleOptions,
		entryPoints: [join(packageRoot, "src", entry)], outfile: join(dist, output), logLevel: "silent",
		plugins: [...bundleOptions.plugins, coreSourcePlugin()],
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
