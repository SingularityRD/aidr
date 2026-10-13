/**
 * `aidr setup` provisions the release key of a standalone install into the
 * real config file (`integrity.public_keys_pem` of ~/.singularity-aidr/
 * config.json), before the connector canaries run, merging it into the
 * existing configuration.
 *
 * The defect this pins: a release-flavour desktop install blocked every tool
 * call because nothing put the release key the installer ships where the
 * hooks look for it.
 *
 * `config-manager` captures the home directory at import time, so HOME is
 * redirected before the modules are imported (as setup-honesty.test.ts does).
 */

import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { PassThrough } from "node:stream";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";

const testHome = mkdtempSync(join(tmpdir(), "aidr-setup-release-key-"));
const originalHome = process.env.HOME;
process.env.HOME = testHome;
vi.mock("node:os", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:os")>();
	return { ...actual, homedir: () => testHome };
});

const { default: setupCommand } = await import("../commands/setup.js");

const posix = process.platform !== "win32";
const scratch: string[] = [];
afterEach(() => {
	for (const dir of scratch.splice(0)) rmSync(dir, { recursive: true, force: true });
	process.exitCode = 0;
});
afterAll(() => {
	if (originalHome === undefined) delete process.env.HOME;
	else process.env.HOME = originalHome;
	rmSync(testHome, { recursive: true, force: true });
});

const MULTI_CALL = `#!/bin/sh
[ "$1" = "hook" ] || exit 0
input=$(cat)
case "$input" in
*"| bash"*) printf '%s\\n' '{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"blocked"}}' ;;
*) printf '{}\\n' ;;
esac
`;

function files(root: string, dir = root): string[] {
	return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
		const full = join(dir, entry.name);
		return entry.isDirectory() ? files(root, full) : [relative(root, full).split("\\").join("/")];
	});
}
const digest = (path: string) => createHash("sha256").update(readFileSync(path)).digest("hex");

/** A signed stand-in release bundle with the installer's key at <prefix>/config. */
function signedBundle() {
	const { publicKey, privateKey } = generateKeyPairSync("ed25519");
	const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
	const prefix = mkdtempSync(join(tmpdir(), "aidr-setup-release-prefix-"));
	scratch.push(prefix);
	const root = join(prefix, "bundle");
	mkdirSync(join(root, "bin"), { recursive: true });
	mkdirSync(join(root, "dist", "resources", "threats"), { recursive: true });
	mkdirSync(join(prefix, "config"));
	writeFileSync(join(prefix, "config", "release-public.pem"), pem);
	writeFileSync(join(root, "dist", "resources", "threats", "rules.yaml"), "- id: T\n");
	writeFileSync(join(root, "bin", "aidr"), MULTI_CALL, { mode: 0o755 });
	const runtime = {
		schema_version: 1,
		artifact_id: "sea/dist",
		artifact_version: "0.6.0",
		files: [
			{
				path: "resources/threats/rules.yaml",
				sha256: digest(join(root, "dist", "resources", "threats", "rules.yaml")),
			},
		],
	};
	writeFileSync(join(root, "dist", "aidr-artifact.manifest.json"), JSON.stringify(runtime));
	const sig = (file: string) =>
		`${sign(null, readFileSync(file), privateKey).toString("base64")}\n`;
	writeFileSync(
		join(root, "dist", "aidr-artifact.manifest.sig"),
		sig(join(root, "dist", "aidr-artifact.manifest.json")),
	);
	const outer = {
		schema_version: 1,
		artifact_id: "claude-code/sea",
		artifact_version: "0.6.0",
		files: files(root)
			.sort()
			.map((path) => ({ path, sha256: digest(join(root, path)) })),
	};
	writeFileSync(join(root, "aidr-artifact.manifest.json"), JSON.stringify(outer));
	writeFileSync(
		join(root, "aidr-artifact.manifest.sig"),
		sig(join(root, "aidr-artifact.manifest.json")),
	);
	return { root, pem };
}

async function quietly(run: () => Promise<void>): Promise<string> {
	const lines: string[] = [];
	const spies = [
		vi.spyOn(console, "log").mockImplementation((...args) => void lines.push(args.join(" "))),
		vi.spyOn(console, "error").mockImplementation((...args) => void lines.push(args.join(" "))),
		vi.spyOn(console, "warn").mockImplementation((...args) => void lines.push(args.join(" "))),
	];
	try {
		await run();
	} finally {
		for (const spy of spies) spy.mockRestore();
	}
	return lines.join("\n");
}

const configKeys = () =>
	JSON.parse(readFileSync(join(testHome, ".singularity-aidr", "config.json"), "utf8")).integrity
		?.public_keys_pem;

describe.skipIf(!posix)("aidr setup and the release key", () => {
	it("provisions the installer's key into the config before the canary, so a release bundle registers", async () => {
		const { root, pem } = signedBundle();
		const userHome = mkdtempSync(join(tmpdir(), "aidr-setup-release-user-"));
		scratch.push(userHome);
		mkdirSync(join(userHome, ".claude"));
		const output = await quietly(() =>
			setupCommand(
				{ host: "claude-code" },
				{ home: userHome, standaloneRoot: root, commercial: true, env: process.env },
			),
		);
		expect(output).toMatch(/Release key sha256:[0-9a-f]{64} set up \(from .*release-public\.pem\)/);
		expect(configKeys()).toEqual([pem]);
		const config = JSON.parse(
			readFileSync(join(testHome, ".singularity-aidr", "config.json"), "utf8"),
		);
		expect(config.version).toBeTruthy(); // merged into the config setup created, not a new document
		const settings = JSON.parse(readFileSync(join(userHome, ".claude", "settings.json"), "utf8"));
		expect(settings.hooks.PreToolUse.at(-1).hooks[0].command).toBe(
			`"${join(root, "bin", "aidr")}" hook pre-tool-use`,
		);

		// A rerun leaves the key alone; a different installer key is not trusted without --force.
		const other = signedBundle();
		const rerun = await quietly(() =>
			setupCommand(
				{ host: "claude-code", dryRun: false },
				{ home: userHome, standaloneRoot: other.root, commercial: true, env: process.env },
			),
		);
		expect(rerun).toMatch(
			/A different release key is already set up \(sha256:[0-9a-f]{64}\); it was kept/,
		);
		expect(rerun).toMatch(/signature does not verify against the release key/);
		expect(configKeys()).toEqual([pem]);
	}, 60_000);

	it("--release-key sets up a manual install's key after operator confirmation, and prints its fingerprint", async () => {
		const { root, pem } = signedBundle();
		rmSync(join(root, "..", "config"), { recursive: true });
		const keyFile = join(mkdtempSync(join(tmpdir(), "aidr-setup-release-keyfile-")), "release.pem");
		scratch.push(join(keyFile, ".."));
		writeFileSync(keyFile, pem);
		const userHome = mkdtempSync(join(tmpdir(), "aidr-setup-release-user-"));
		scratch.push(userHome);
		mkdirSync(join(userHome, ".claude"));
		const fingerprint = createHash("sha256").update(generateKeyFromPem(pem)).digest("hex");

		// Without a terminal or the operator variable nothing changes.
		const refused = await quietly(() =>
			setupCommand(
				{ host: "claude-code", releaseKey: keyFile, force: true },
				{ home: userHome, standaloneRoot: root, commercial: true, env: {} },
			),
		);
		expect(refused).toMatch(/interactive terminal/);

		const prompt = new PassThrough();
		const promptText: string[] = [];
		prompt.on("data", (chunk) => promptText.push(String(chunk)));
		const output = await quietly(() =>
			setupCommand(
				{ host: "claude-code", releaseKey: keyFile, yes: true, force: true },
				{
					home: userHome,
					standaloneRoot: root,
					commercial: true,
					env: { ...process.env, AIDR_OPERATOR_NONINTERACTIVE: "1" },
					streams: { input: process.stdin, output: prompt },
				},
			),
		);
		expect(promptText.join("")).toContain(`Release key: ${keyFile} (sha256:${fingerprint})`);
		expect(output).toMatch(new RegExp(`Release key sha256:${fingerprint} set up`));
		expect(configKeys()).toEqual([pem]);
	}, 60_000);
});

function generateKeyFromPem(pem: string): Buffer {
	const body = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
	return Buffer.from(body, "base64");
}
