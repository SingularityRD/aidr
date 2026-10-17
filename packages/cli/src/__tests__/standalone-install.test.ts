/**
 * Standalone (desktop installer) installs: `aidr setup` running from the SEA
 * bundle registers that bundle's multi-call binary (`"<bundle>/bin/aidr" hook
 * <name>`) for Claude Code and Codex, installs the editor VSIXs the bundle
 * ships, provisions the release key the installer embeds, `aidr uninstall`
 * removes them on the strength of the receipt, `aidr status` ends with a
 * measured verdict and `aidr verify` exercises each registered hook with a
 * canary passed as data.
 *
 * The defect these pin: a customer who installed the standalone bundle had no
 * way to get Claude Code protected (setup only offered a plugin directory),
 * `aidr status` ended without saying what to do next, and nothing exercised
 * the real hook entry point after install. A release bundle blocked every call
 * because nothing provisioned its release key.
 *
 * The bundle is a stand-in whose `bin/aidr` is a shell script: `aidr hook
 * pre-tool-use` / `aidr hook aidr-codex-hook` deny only a pipe-to-shell
 * command, so the canary and its benign twin are both observable. Every home
 * is a temporary directory.
 */

import { createHash, generateKeyPairSync, sign } from "node:crypto";
import {
	existsSync,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import setupCommand from "../commands/setup.js";
import { statusVerdictFor } from "../commands/status.js";
import { uninstallAidr } from "../commands/uninstall.js";
import { verifyHosts } from "../commands/verify.js";
import { type ConnectorDeps, installConnectors } from "../utils/connector-install.js";
import { detectConnectorStatuses } from "../utils/connector-status.js";
import { MANAGED_HOOK_MARKER } from "../utils/install-hooks.js";
import {
	parseReleaseKey,
	planReleaseKey,
	provisionReleaseKey,
	type ReleaseKeyStore,
	readReleaseKeyFile,
} from "../utils/release-key.js";
import { writeSetupLedger } from "../utils/setup-ledger.js";
import { decisionOf, failClosedHookCommand, verifyStandaloneBundle } from "../utils/standalone.js";
import { buildStatusVerdict } from "../utils/status-verdict.js";

const posix = process.platform !== "win32";
const dirs: string[] = [];
afterEach(() => {
	for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
	process.exitCode = 0;
});
function temp(label: string): string {
	const dir = mkdtempSync(join(tmpdir(), `aidr-standalone-${label}-`));
	dirs.push(dir);
	return dir;
}

/** `aidr hook <name>`: the two PreToolUse hooks deny only a pipe-to-shell command. */
const MULTI_CALL = `#!/bin/sh
[ "$1" = "hook" ] || { echo "aidr cli $*"; exit 0; }
input=$(cat)
case "$2" in
pre-tool-use|aidr-codex-hook)
	case "$input" in
	*"| bash"*) printf '%s\\n' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"blocked"}}' ;;
	*) printf '{}\\n' ;;
	esac ;;
*) printf '{}\\n' ;;
esac
`;
const ALLOW_ALL = "#!/bin/sh\ncat >/dev/null\nprintf '{}\\n'\n";
const DENY_ALL = `#!/bin/sh
cat >/dev/null
printf '%s\\n' '{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"release key not set up"}}'
`;

function files(root: string, dir = root): string[] {
	return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
		const full = join(dir, entry.name);
		return entry.isDirectory() ? files(root, full) : [relative(root, full).split("\\").join("/")];
	});
}

const digest = (path: string) => createHash("sha256").update(readFileSync(path)).digest("hex");

function writeManifests(root: string): void {
	const dist = join(root, "dist");
	const runtime = files(dist)
		.filter((path) => !path.startsWith("aidr-artifact.manifest."))
		.sort()
		.map((path) => ({ path, sha256: digest(join(dist, path)) }));
	writeFileSync(
		join(dist, "aidr-artifact.manifest.json"),
		`${JSON.stringify({ schema_version: 1, artifact_id: "sea/dist", artifact_version: "0.6.0", files: runtime }, null, 2)}\n`,
	);
	const listed = files(root)
		.filter(
			(path) => path !== "aidr-artifact.manifest.json" && path !== "aidr-artifact.manifest.sig",
		)
		.sort()
		.map((path) => ({ path, sha256: digest(join(root, path)) }));
	writeFileSync(
		join(root, "aidr-artifact.manifest.json"),
		`${JSON.stringify({ schema_version: 1, artifact_id: "claude-code/sea", artifact_version: "0.6.0", files: listed }, null, 2)}\n`,
	);
}

function releaseKeyPair() {
	const { publicKey, privateKey } = generateKeyPairSync("ed25519");
	return { pem: publicKey.export({ type: "spki", format: "pem" }).toString(), privateKey };
}

/** Sign the runtime manifest, re-manifest the bundle over it, sign the bundle manifest. */
function signBundle(root: string, privateKey: ReturnType<typeof releaseKeyPair>["privateKey"]) {
	const sigOf = (file: string) =>
		`${sign(null, readFileSync(file), privateKey).toString("base64")}\n`;
	rmSync(join(root, "aidr-artifact.manifest.sig"), { force: true });
	writeFileSync(
		join(root, "dist", "aidr-artifact.manifest.sig"),
		sigOf(join(root, "dist", "aidr-artifact.manifest.json")),
	);
	const manifest = JSON.parse(readFileSync(join(root, "aidr-artifact.manifest.json"), "utf8"));
	manifest.files = files(root)
		.filter(
			(path) => path !== "aidr-artifact.manifest.json" && path !== "aidr-artifact.manifest.sig",
		)
		.sort()
		.map((path) => ({ path, sha256: digest(join(root, path)) }));
	writeFileSync(
		join(root, "aidr-artifact.manifest.json"),
		`${JSON.stringify(manifest, null, 2)}\n`,
	);
	writeFileSync(
		join(root, "aidr-artifact.manifest.sig"),
		sigOf(join(root, "aidr-artifact.manifest.json")),
	);
}

function bundle(
	binary = MULTI_CALL,
	{
		extensions = [] as string[],
		installerKey,
	}: { extensions?: string[]; installerKey?: string } = {},
): string {
	const root = join(temp("prefix"), "bundle");
	mkdirSync(join(root, "bin"), { recursive: true });
	mkdirSync(join(root, "dist", "resources", "threats"), { recursive: true });
	writeFileSync(join(root, "dist", "resources", "threats", "rules.yaml"), "- id: T\n");
	writeFileSync(join(root, "bin", "aidr"), binary, { mode: 0o755 });
	for (const name of extensions) {
		mkdirSync(join(root, "extensions"), { recursive: true });
		writeFileSync(join(root, "extensions", name), `PK ${name}`);
	}
	if (installerKey) {
		mkdirSync(join(root, "..", "config"), { recursive: true });
		writeFileSync(join(root, "..", "config", "release-public.pem"), installerKey);
	}
	writeManifests(root);
	return root;
}

const CUSTOMER_HOOK = { type: "command", command: "customer-audit", timeout: 3 };

function home(settings: Record<string, unknown> = {}): string {
	const dir = temp("home");
	mkdirSync(join(dir, ".claude"), { recursive: true });
	writeFileSync(join(dir, ".claude", "settings.json"), `${JSON.stringify(settings, null, 2)}\n`);
	return dir;
}

const settingsOf = (dir: string) =>
	JSON.parse(readFileSync(join(dir, ".claude", "settings.json"), "utf8"));
const install = (dir: string, root: string, extra: Partial<ConnectorDeps> = {}) =>
	installConnectors(
		{
			home: dir,
			env: { PATH: process.env.PATH },
			version: "0.6.0",
			standaloneRoot: root,
			...extra,
		},
		{ hosts: ["claude-code"] },
	).find((entry) => entry.host === "claude-code");

// AIDR-SKIP: AIDR-063 qa-owner - the fake standalone bundle's multi-call hook is a /bin/sh script, which Windows cannot execute; the MSI path is covered by deploy/installers tests
describe.skipIf(!posix)("aidr setup from the standalone bundle (Claude Code)", () => {
	it("registers the bundle's multi-call hooks after a passing canary and writes a receipt", () => {
		const root = bundle();
		const dir = home({ hooks: { PreToolUse: [{ matcher: "Bash", hooks: [CUSTOMER_HOOK] }] } });
		const first = install(dir, root);
		expect(first?.action, first?.detail).toBe("installed");
		const settings = settingsOf(dir);
		expect(settings.hooks.PreToolUse[0].hooks).toEqual([CUSTOMER_HOOK]);
		const managed = ["PreToolUse", "PostToolUse", "SessionStart"].map(
			(event) => settings.hooks[event].at(-1).hooks[0],
		);
		expect(managed.map((hook) => hook.statusMessage)).toEqual(Array(3).fill(MANAGED_HOOK_MARKER));
		expect(managed.map((hook) => hook.command)).toEqual(
			["pre-tool-use", "post-tool-use", "session-start"].map((name) =>
				failClosedHookCommand(`"${join(root, "bin", "aidr")}" hook ${name}`),
			),
		);
		const receipt = JSON.parse(
			readFileSync(join(dir, ".singularity-aidr", "installation.json"), "utf8"),
		);
		expect(receipt).toMatchObject({
			connector: "claude-code",
			install_kind: "sea_bundle",
			path: root,
			local_canary: "deny",
			package_integrity: "digests_verified_unsigned",
		});

		// Idempotent: a rerun writes nothing and adds no backup.
		const before = readdirSync(join(dir, ".claude"));
		expect(install(dir, root)?.action).toBe("already_installed");
		expect(readdirSync(join(dir, ".claude"))).toEqual(before);
	});

	it("refuses a tampered bundle, a hook that allows the canary and one that denies everything", () => {
		const tampered = bundle();
		writeFileSync(join(tampered, "dist", "resources", "threats", "rules.yaml"), "- id: X\n");
		const dir = home();
		const refused = install(dir, tampered);
		expect(refused?.action).toBe("failed");
		expect(refused?.detail).toMatch(/does not match its manifest digest/);
		expect(settingsOf(dir)).toEqual({});

		const permissive = install(dir, bundle(ALLOW_ALL));
		expect(permissive?.action).toBe("failed");
		expect(permissive?.detail).toMatch(/returned allow for the deny canary/);

		const blocksAll = install(dir, bundle(DENY_ALL));
		expect(blocksAll?.action).toBe("failed");
		expect(blocksAll?.detail).toMatch(/denied the harmless 'ls' as well/);
		expect(settingsOf(dir)).toEqual({});
		expect(existsSync(join(dir, ".singularity-aidr", "installation.json"))).toBe(false);
	});

	it("leaves an enabled AIDR plugin alone instead of inspecting every call twice", () => {
		const dir = home({ enabledPlugins: { "aidr@aidr": true } });
		const outcome = install(dir, bundle());
		expect(outcome?.action).toBe("already_installed");
		expect(settingsOf(dir)).toEqual({ enabledPlugins: { "aidr@aidr": true } });
	});

	it("a release bundle registers only when its signatures verify against the trusted release key", () => {
		const signer = releaseKeyPair();
		const root = bundle();
		signBundle(root, signer.privateKey);
		const release = { releaseKeys: [signer.pem], requireSignedBundle: true };

		const ok = verifyStandaloneBundle(root, { trustKeys: [signer.pem], requireSignature: true });
		expect(ok.problems).toEqual([]);
		expect(ok.signature).toBe("verified");

		const noKey = install(home(), root, { ...release, releaseKeys: [] });
		expect(noKey?.action).toBe("failed");
		expect(noKey?.detail).toMatch(/no release key is set up .*aidr setup --release-key/);
		const otherKey = install(home(), root, { ...release, releaseKeys: [releaseKeyPair().pem] });
		expect(otherKey?.detail).toMatch(/signature does not verify against the release key/);

		const dir = home();
		const installed = install(dir, root, release);
		expect(installed?.action, installed?.detail).toBe("installed");
		expect(
			JSON.parse(readFileSync(join(dir, ".singularity-aidr", "installation.json"), "utf8")),
		).toMatchObject({ package_integrity: "signature_verified" });

		// An unsigned bundle is refused as a release bundle.
		const unsigned = verifyStandaloneBundle(bundle(), {
			trustKeys: [signer.pem],
			requireSignature: true,
		});
		expect(unsigned.ok).toBe(false);
		expect(unsigned.problems.join("\n")).toMatch(
			/dist\/aidr-artifact\.manifest\.json is not signed/,
		);
	});

	it("a bundle signature must verify, and the runtime manifest must match the bundle", () => {
		const root = bundle();
		writeFileSync(
			join(root, "aidr-artifact.manifest.sig"),
			`${Buffer.alloc(64).toString("base64")}\n`,
		);
		const check = verifyStandaloneBundle(root, { trustKeys: [releaseKeyPair().pem] });
		expect(check.ok).toBe(false);
		expect(check.signature).toBe("invalid");

		const drifted = bundle();
		const runtime = join(drifted, "dist", "aidr-artifact.manifest.json");
		const parsed = JSON.parse(readFileSync(runtime, "utf8"));
		parsed.files[0].sha256 = "0".repeat(64);
		writeFileSync(runtime, JSON.stringify(parsed));
		writeManifestsOuterOnly(drifted);
		expect(verifyStandaloneBundle(drifted).problems.join("\n")).toMatch(
			/runtime manifest|does not match the bundle manifest/,
		);
	});
});

/** Re-write only the bundle manifest (a runtime manifest edited after the fact). */
function writeManifestsOuterOnly(root: string): void {
	const manifest = JSON.parse(readFileSync(join(root, "aidr-artifact.manifest.json"), "utf8"));
	manifest.files = files(root)
		.filter((path) => path !== "aidr-artifact.manifest.json")
		.sort()
		.map((path) => ({ path, sha256: digest(join(root, path)) }));
	writeFileSync(join(root, "aidr-artifact.manifest.json"), JSON.stringify(manifest));
}

// AIDR-SKIP: AIDR-063 qa-owner - the fake standalone bundle's multi-call hook is a /bin/sh script, which Windows cannot execute; the MSI path is covered by deploy/installers tests
describe.skipIf(!posix)("aidr setup from the standalone bundle (Codex and editors)", () => {
	it("registers the bundle's Codex hook after a passing canary, with no npm package on PATH", () => {
		const root = bundle();
		const dir = home();
		mkdirSync(join(dir, ".codex"));
		const results = installConnectors(
			{ home: dir, env: { PATH: process.env.PATH }, version: "0.6.0", standaloneRoot: root },
			{ hosts: ["codex"] },
		);
		const codex = results.find((entry) => entry.host === "codex");
		expect(codex?.action, codex?.detail).toBe("installed");
		const hooks = JSON.parse(readFileSync(join(dir, ".codex", "hooks.json"), "utf8")).hooks;
		const command = failClosedHookCommand(`"${join(root, "bin", "aidr")}" hook aidr-codex-hook`);
		for (const event of ["PreToolUse", "UserPromptSubmit", "PostToolUse"]) {
			expect(hooks[event].at(-1).hooks[0].command).toBe(command);
		}
		expect(detectConnectorStatuses(dir, {}).find((entry) => entry.id === "codex")?.state).toBe(
			"installed",
		);
		const verified = verifyHosts({ home: dir, env: { PATH: process.env.PATH } }).find(
			(entry) => entry.host === "codex",
		);
		expect(verified?.outcome, verified?.detail).toBe("pass");

		const permissive = installConnectors(
			{ home: home(), env: {}, version: "0.6.0", standaloneRoot: bundle(ALLOW_ALL) },
			{ hosts: ["codex"] },
		).find((entry) => entry.host === "codex");
		expect(permissive?.action).toBe("failed");
	});

	it("installs the VSIX the verified bundle ships for a detected editor, without an extra confirmation", () => {
		const root = bundle(MULTI_CALL, { extensions: ["aidr-cursor.vsix"] });
		const dir = home();
		mkdirSync(join(dir, ".cursor"));
		const bin = temp("bin");
		writeFileSync(join(bin, "cursor"), "#!/bin/sh\nexit 0\n", { mode: 0o755 });
		const calls: string[][] = [];
		const run = (_command: string, args: readonly string[]) => {
			calls.push([...args]);
			const ext = join(dir, ".cursor", "extensions", "singularityrd.aidr-cursor-0.6.0");
			mkdirSync(ext, { recursive: true });
			writeFileSync(
				join(ext, "package.json"),
				JSON.stringify({ publisher: "singularityrd", name: "aidr-cursor", version: "0.6.0" }),
			);
			return { status: 0 };
		};
		const cursor = installConnectors(
			{ home: dir, env: { PATH: bin }, version: "0.6.0", standaloneRoot: root, run },
			{ hosts: ["cursor"] },
		).find((entry) => entry.host === "cursor");
		expect(cursor?.action, cursor?.detail).toBe("installed");
		expect(calls).toEqual([
			["--install-extension", join(root, "extensions", "aidr-cursor.vsix"), "--force"],
		]);

		// A bundle that fails verification never hands its VSIX to the editor.
		writeFileSync(join(root, "extensions", "aidr-cursor.vsix"), "tampered");
		calls.length = 0;
		const refused = installConnectors(
			{ home: home(), env: { PATH: bin }, version: "0.6.0", standaloneRoot: root, run },
			{ hosts: ["cursor"] },
		).find((entry) => entry.host === "cursor");
		expect(refused?.action).toBe("failed");
		expect(calls).toEqual([]);
	});
});

describe("release key provisioning", () => {
	const memoryStore = (
		keys: string[] = [],
	): ReleaseKeyStore & { keys: string[]; writes: number } => {
		const store = {
			keys,
			writes: 0,
			read: () => [...store.keys],
			write: (next: string[]) => {
				store.keys = next;
				store.writes += 1;
			},
		};
		return store;
	};

	it("accepts only an Ed25519 SPKI public key PEM and reports its fingerprint", () => {
		const { pem } = releaseKeyPair();
		expect(parseReleaseKey(pem).fingerprint).toMatch(/^[0-9a-f]{64}$/);
		const { privateKey } = generateKeyPairSync("ed25519");
		expect(() =>
			parseReleaseKey(privateKey.export({ type: "pkcs8", format: "pem" }).toString()),
		).toThrow(/PRIVATE key/);
		const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey;
		expect(() => parseReleaseKey(rsa.export({ type: "spki", format: "pem" }).toString())).toThrow(
			/rsa key, not Ed25519/,
		);
		expect(() => parseReleaseKey("not a key")).toThrow(/not a PEM public key/);
		const file = join(temp("key"), "release.pem");
		writeFileSync(file, "garbage");
		expect(() => readReleaseKeyFile(file)).toThrow(
			/release\.pem is not an Ed25519 release public key/,
		);
	});

	it("adds the key to an empty list, never replaces a different operator key without --force", () => {
		const key = parseReleaseKey(releaseKeyPair().pem);
		const operator = releaseKeyPair().pem;
		expect(planReleaseKey([], key, false)).toMatchObject({ outcome: "added", keys: [key.pem] });
		expect(planReleaseKey([key.pem], key, true).outcome).toBe("present");
		const kept = memoryStore([operator]);
		expect(provisionReleaseKey(key, kept).outcome).toBe("kept_existing");
		expect(kept.keys).toEqual([operator]);
		expect(kept.writes).toBe(0);
		const forced = memoryStore([operator]);
		expect(provisionReleaseKey(key, forced, { force: true }).outcome).toBe("replaced");
		expect(forced.keys).toEqual([key.pem]);
		const dry = memoryStore();
		expect(provisionReleaseKey(key, dry, { dryRun: true }).outcome).toBe("added");
		expect(dry.writes).toBe(0);
	});

	it("aidr setup --release-key refuses a file that is not an Ed25519 public key, changing nothing", async () => {
		const file = join(temp("key"), "release.pem");
		writeFileSync(
			file,
			generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "pem" }),
		);
		const store = memoryStore();
		const log: string[] = [];
		const original = console.error;
		console.error = (...args: unknown[]) => log.push(args.join(" "));
		try {
			await setupCommand(
				{ releaseKey: file },
				{ home: home(), standaloneRoot: null, releaseKeyStore: store },
			);
		} finally {
			console.error = original;
		}
		expect(process.exitCode).toBe(1);
		expect(log.join("\n")).toMatch(/release key was refused: .*PRIVATE key/);
		expect(store.writes).toBe(0);
	});
});

// AIDR-SKIP: AIDR-063 qa-owner - the fake standalone bundle's multi-call hook is a /bin/sh script, which Windows cannot execute; the MSI path is covered by deploy/installers tests
describe.skipIf(!posix)("aidr uninstall of a standalone install", () => {
	it("removes exactly the managed hooks named by a standalone receipt", async () => {
		const root = bundle();
		const dir = home({ hooks: { PreToolUse: [{ matcher: "Bash", hooks: [CUSTOMER_HOOK] }] } });
		expect(install(dir, root)?.action).toBe("installed");
		const report = await uninstallAidr({ home: dir });
		expect(report.outcome, report.reason?.detail).toBe("removed");
		expect(report.removed).toHaveLength(3);
		expect(settingsOf(dir).hooks).toEqual({
			PreToolUse: [{ matcher: "Bash", hooks: [CUSTOMER_HOOK] }],
		});
	});

	it("refuses, changing nothing, when the receipt's bundle is gone", async () => {
		const root = bundle();
		const dir = home();
		expect(install(dir, root)?.action).toBe("installed");
		rmSync(root, { recursive: true, force: true });
		const raw = readFileSync(join(dir, ".claude", "settings.json"));
		const report = await uninstallAidr({ home: dir });
		expect(report.outcome).toBe("refused");
		expect(report.reason?.code).toBe("receipt_connector_missing");
		expect(readFileSync(join(dir, ".claude", "settings.json"))).toEqual(raw);
	});
});

describe("aidr status verdict", () => {
	const status = (id: string, state: string, extra: Record<string, unknown> = {}) =>
		({ id, label: id, state, detail: `${id} detail`, evidence: [], ...extra }) as never;

	it("splits protected, restart-needed and manual hosts, with the exact command", () => {
		const verdict = buildStatusVerdict(
			[
				status("claude-code", "installed"),
				status("opencode", "installed"),
				status("codex", "runtime_present_not_installed", { remedy: "install aidr-codex-hook" }),
				status("openclaw", "runtime_present_not_installed"),
				status("cursor", "not_detected"),
			],
			{ schema_version: 1, completed_at: "2026-10-13T10:00:00.000Z", registered: ["opencode"] },
		);
		expect(verdict.protected).toEqual(["claude-code"]);
		expect(verdict.restart).toEqual([{ label: "opencode", since: "2026-10-13T10:00:00.000Z" }]);
		expect(verdict.manual).toEqual([
			{ label: "codex", command: "install aidr-codex-hook" },
			{ label: "openclaw", command: "aidr setup --host openclaw" },
		]);
		expect(verdict.ok).toBe(false);
	});

	it("is not ok with nothing registered, and reads the ledger setup wrote", () => {
		expect(buildStatusVerdict([status("cursor", "not_detected")], null).ok).toBe(false);
		const dir = home({
			hooks: {
				PreToolUse: [
					{ hooks: [{ type: "command", command: '"/opt/x/bin/aidr" hook pre-tool-use' }] },
				],
			},
		});
		writeSetupLedger(dir, ["claude-code"], new Date("2026-10-13T09:00:00.000Z"));
		const verdict = statusVerdictFor(detectConnectorStatuses(dir, {}), dir);
		expect(verdict.restart).toEqual([{ label: "Claude Code", since: "2026-10-13T09:00:00.000Z" }]);
	});
});

describe("aidr verify", () => {
	it("reads every AIDR hook response shape", () => {
		expect(decisionOf('{"hookSpecificOutput":{"permissionDecision":"deny"}}').decision).toBe(
			"deny",
		);
		expect(decisionOf('{"permission":"deny","reason":"x"}').decision).toBe("deny");
		expect(decisionOf('{"decision":"block"}').decision).toBe("deny");
		expect(decisionOf("").decision).toBe("allow");
		expect(decisionOf("not json").decision).toBe("unknown");
	});

	// AIDR-SKIP: AIDR-063 qa-owner - the fake standalone bundle's multi-call hook is a /bin/sh script, which Windows cannot execute; the MSI path is covered by deploy/installers tests
	it.skipIf(!posix)("PASSes a hook that denies the canary and allows the benign twin", () => {
		const root = bundle();
		const dir = home();
		expect(install(dir, root)?.action).toBe("installed");
		const results = verifyHosts({ home: dir, env: { PATH: process.env.PATH } });
		const claude = results.find((entry) => entry.host === "claude-code");
		expect(claude?.outcome, claude?.detail).toBe("pass");
		expect(
			results.filter((entry) => entry.host !== "claude-code").map((entry) => entry.outcome),
		).toEqual(Array(5).fill("not_registered"));
	});

	it("FAILs a hook that denies everything and SKIPs in-process plugins", () => {
		const dir = home({
			hooks: { PreToolUse: [{ hooks: [{ type: "command", command: "aidr-hook" }] }] },
		});
		mkdirSync(join(dir, ".config", "opencode", "plugins"), { recursive: true });
		writeFileSync(
			join(dir, ".config", "opencode", "plugins", "aidr.js"),
			"// Singularity AIDR OpenCode plugin\n",
		);
		const seen: string[] = [];
		const results = verifyHosts({
			home: dir,
			env: {},
			run: (_command, payload) => {
				const input = (payload.tool_input as { command: string }).command;
				seen.push(input);
				return { decision: "deny", detail: "internal error" };
			},
		});
		expect(results.find((entry) => entry.host === "claude-code")?.outcome).toBe("fail");
		expect(results.find((entry) => entry.host === "opencode")?.outcome).toBe("skip");
		// The canary went to the hook as data, then the benign twin.
		expect(seen).toEqual([expect.stringMatching(/\| bash$/), "ls"]);
	});
});
