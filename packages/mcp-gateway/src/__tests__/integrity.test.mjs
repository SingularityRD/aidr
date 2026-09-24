import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { build } from "esbuild";
import { signMcpToolManifest } from "../../../core/dist/mcp-attestation.js";

const packageRoot = resolve(import.meta.dirname, "../..");
const binaries = [
	["cli.mjs", "aidr-mcp-gateway.mjs"],
	["approve.mjs", "aidr-mcp-approve.mjs"],
	["stdio-cli.mjs", "aidr-mcp-stdio.mjs"],
];

test("commercial gateway binaries start only with a complete signed artifact and verifier key", async () => {
	const root = await mkdtemp(join(tmpdir(), "aidr-mcp-integrity-"));
	try {
		const dist = join(root, "dist");
		await mkdir(dist);
		await Promise.all(
			binaries.map(([entry, output]) =>
				build({
					entryPoints: [join(packageRoot, "src", entry)],
					outfile: join(dist, output),
					bundle: true,
					platform: "node",
					target: "node20",
					format: "esm",
					logLevel: "silent",
				}),
			),
		);

		const artifactKeys = generateKeyPairSync("ed25519");
		const manifestRaw = `${JSON.stringify({
			schema_version: 1,
			artifact_id: "mcp-gateway/dist",
			artifact_version: "0.6.0",
			created_at: new Date().toISOString(),
			files: await Promise.all(
				binaries.map(async ([, path]) => ({
					path,
					sha256: createHash("sha256").update(await readFile(join(dist, path))).digest("hex"),
				})),
			),
		})}\n`;
		await writeFile(join(dist, "aidr-artifact.manifest.json"), manifestRaw);

		const home = join(root, "home");
		const aidrHome = join(home, ".singularity-aidr");
		await mkdir(aidrHome, { recursive: true });
		const writeIntegrityConfig = (keys) =>
			writeFile(
				join(aidrHome, "config.json"),
				JSON.stringify({
					integrity: { enabled: true, verify_on_start: true, public_keys_pem: keys },
					logging: { enabled: false },
				}),
			);
		await writeIntegrityConfig([
			artifactKeys.publicKey.export({ type: "spki", format: "pem" }).toString(),
		]);

		const toolKeys = generateKeyPairSync("ed25519");
		const toolPublicKey = toolKeys.publicKey.export({ type: "spki", format: "pem" }).toString();
		const now = Date.now();
		const signedManifest = signMcpToolManifest({
			keyId: "publisher-key",
			privateKey: toolKeys.privateKey,
			manifest: {
				schema_version: 1,
				server_id: "server-a",
				sequence: 1,
				issued_at: new Date(now - 60_000).toISOString(),
				expires_at: new Date(now + 60_000).toISOString(),
				tools: [
					{
						name: "search",
						description: "Search",
						input_schema: { type: "object" },
					},
				],
			},
		});
		const token = "a".repeat(40);
		const gatewayConfig = join(root, "gateway.json");
		await writeFile(
			gatewayConfig,
			JSON.stringify({
				stateDir: join(root, "state"),
				port: 0,
				clients: [
					{
						id: "client-a",
						tenantId: "tenant-a",
						tokenSha256: createHash("sha256").update(token).digest("hex"),
						allowedTools: { "server-a": ["search"] },
					},
				],
				servers: [
					{
						tenantId: "tenant-a",
						id: "server-a",
						url: "https://mcp.example.test/mcp",
						transport: "json",
						sessionMode: "stateless",
						signedManifest,
						trustedSigners: { "publisher-key": toolPublicKey },
					},
				],
			}),
		);

		const executable = join(dist, "aidr-mcp-gateway.mjs");
		const env = { ...process.env, HOME: home, AIDR_COMMERCIAL: "1" };
		const incomplete = spawnSync(process.execPath, [executable, gatewayConfig], {
			env,
			encoding: "utf8",
			timeout: 10_000,
		});
		assert.equal(incomplete.status, 1);

		await writeFile(
			join(dist, "aidr-artifact.manifest.sig"),
			sign(null, Buffer.from(manifestRaw), artifactKeys.privateKey).toString("base64"),
		);
		await writeIntegrityConfig([]);
		const withoutKey = spawnSync(process.execPath, [executable, gatewayConfig], {
			env,
			encoding: "utf8",
			timeout: 10_000,
		});
		assert.equal(withoutKey.status, 1);

		await writeIntegrityConfig([
			artifactKeys.publicKey.export({ type: "spki", format: "pem" }).toString(),
		]);
		const child = spawn(process.execPath, [executable, gatewayConfig], { env });
		let stderr = "";
		child.stderr.on("data", (chunk) => {
			stderr += chunk;
		});
		try {
			await new Promise((resolveStarted, rejectStarted) => {
				const timeout = setTimeout(
					() => rejectStarted(new Error(`gateway did not start: ${stderr}`)),
					10_000,
				);
				child.stdout.on("data", (chunk) => {
					if (!chunk.toString().includes("AIDR MCP gateway listening")) return;
					clearTimeout(timeout);
					resolveStarted();
				});
				child.once("exit", (code) => {
					clearTimeout(timeout);
					rejectStarted(new Error(`gateway exited with ${code}: ${stderr}`));
				});
			});
		} finally {
			await new Promise((resolveExit) => {
				if (child.exitCode !== null) return resolveExit();
				child.once("exit", resolveExit);
				child.kill();
			});
		}
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});
