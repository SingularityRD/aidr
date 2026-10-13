/**
 * `aidr update` end to end against a desktop-installer layout in a temp
 * directory: a signed portal mirror, a real tarball (extracted with the
 * system tar), and a stand-in for the platform installer, `aidr verify` and
 * `aidr setup`. Privileged steps run directly (no sudo) on the temp prefix.
 */
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync, type KeyObject, sign } from "node:crypto";
import {
	existsSync,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	rmSync,
	symlinkSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { PassThrough } from "node:stream";
import { ConfigSchema, LINUX_MDM_MARKER } from "@singularityrd/aidr-core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import updateCommand, { type UpdateDeps, type UpdateOptions } from "../commands/update.js";
import { UPDATE_EN, UPDATE_TR } from "../i18n/index.js";
import {
	applyUpdate,
	type CommandRunner,
	privilegedOps,
	type RunResult,
	stagingDirFor,
	UpdateApplyError,
} from "../utils/update-installer.js";

const BINARIES = ["aidr", "aidr-pre-tool-use", "aidr-post-tool-use", "aidr-session-start"];
const sha = (bytes: string | Uint8Array) => createHash("sha256").update(bytes).digest("hex");
const catalogKey = generateKeyPairSync("ed25519");
const otherKey = generateKeyPairSync("ed25519");
const TAR_NAME = "singularity-aidr-1.5.0-linux-x64.tar.gz";

let root: string;
let prefix: string;
let savedExitCode: typeof process.exitCode;

/** A SEA-bundle look-alike that passes verifyStandaloneBundle. */
function writeBundle(dir: string, version: string, exe = ""): void {
	mkdirSync(join(dir, "bin"), { recursive: true });
	const files = BINARIES.map((name) => {
		const content = `#!/bin/sh\n# ${name} ${version}\n`;
		writeFileSync(join(dir, "bin", `${name}${exe}`), content, { mode: 0o755 });
		return { path: `bin/${name}${exe}`, sha256: sha(content) };
	});
	writeFileSync(
		join(dir, "aidr-artifact.manifest.json"),
		JSON.stringify({ artifact_id: "claude-code/sea", artifact_version: version, files }, null, 2),
	);
}

function bundleVersion(dir: string): string | null {
	try {
		return JSON.parse(readFileSync(join(dir, "aidr-artifact.manifest.json"), "utf8"))
			.artifact_version;
	} catch {
		return null;
	}
}

function signDoc(value: unknown, key: KeyObject) {
	const document = Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
	const signature = Buffer.from(
		JSON.stringify({
			schema_version: 1,
			algorithm: "Ed25519",
			key_id: "installer-catalog-1",
			signature_b64: sign(null, document, key).toString("base64"),
		}),
	);
	return { document, signature };
}

/** Stage the portal tree for `version` with one installer (linux-x64 unless given). */
function writeMirror(
	mirror: string,
	options: {
		platform?: "linux-x64" | "windows-x64";
		version?: string;
		installer: Buffer;
		file?: string;
		format?: string;
		key?: KeyObject;
		publishedBytes?: Buffer;
	},
): string {
	const version = options.version ?? "1.5.0";
	const file = options.file ?? TAR_NAME;
	const key = options.key ?? catalogKey.privateKey;
	const platform = options.platform ?? "linux-x64";
	const [os, arch] = platform.split("-");
	mkdirSync(join(mirror, version, platform), { recursive: true });
	writeFileSync(join(mirror, version, platform, file), options.publishedBytes ?? options.installer);
	const catalog = signDoc(
		{
			schema_version: 1,
			type: "aidr-installer-catalog",
			product_id: "singularity-aidr",
			version,
			published_at: "2026-10-12T09:00:00.000Z",
			release_notes_url: null,
			release: { tag: `v${version}`, git_sha: "a".repeat(40), release_sequence: 8 },
			files: [
				{
					platform,
					os,
					arch,
					file,
					path: `${version}/${platform}/${file}`,
					size: options.installer.length,
					sha256: sha(options.installer),
					minimum_os: "glibc 2.28",
					format: options.format ?? "tar.gz",
				},
			],
		},
		key,
	);
	const pointer = signDoc(
		{
			schema_version: 1,
			type: "aidr-installer-latest",
			product_id: "singularity-aidr",
			version,
			release_sequence: 8,
			manifest_path: `${version}/manifest.json`,
			manifest_sha256: sha(catalog.document),
			published_at: "2026-10-12T09:00:00.000Z",
		},
		key,
	);
	writeFileSync(join(mirror, "latest.json"), pointer.document);
	writeFileSync(join(mirror, "latest.json.sig"), pointer.signature);
	writeFileSync(join(mirror, version, "manifest.json"), catalog.document);
	writeFileSync(join(mirror, version, "manifest.json.sig"), catalog.signature);
	return mirror;
}

/** A real tarball laid out like deploy/installers/linux/build-linux-packages.mjs builds it. */
function buildTarball(version: string, options: { link?: boolean } = {}): Buffer {
	const stage = join(root, `tar-stage-${version}`);
	const top = join(stage, `singularity-aidr-${version}-linux-x64`);
	writeBundle(join(top, "bundle"), version);
	if (options.link) symlinkSync("/etc", join(top, "etc-link"));
	mkdirSync(join(top, "config"), { recursive: true });
	mkdirSync(join(top, "libexec"), { recursive: true });
	writeFileSync(
		join(top, "config", "release-public.pem"),
		"a different key the update must not install",
	);
	writeFileSync(join(top, "libexec", "package-hook.sh"), `#!/bin/sh\n# hook ${version}\n`);
	const out = join(root, `${version}.tar.gz`);
	const result = spawnSync("tar", [
		"-czf",
		out,
		"-C",
		stage,
		`singularity-aidr-${version}-linux-x64`,
	]);
	expect(result.status).toBe(0);
	return readFileSync(out);
}

interface Scenario {
	/** Outcome `aidr verify` reports for Claude Code, by bundle version. */
	verify?: (version: string | null) => "pass" | "fail";
	/** Stand-in for dpkg/rpm/msiexec: what it does to the prefix. */
	install?: () => void;
	installStatus?: number;
}

const PACKAGE_TOOLS = new Set(["dpkg", "rpm", "msiexec"]);
/** msiexec runs by absolute path (C:\Windows\System32\msiexec.exe). */
const toolName = (command: string) =>
	(command.split(/[\\/]/u).pop() ?? command).replace(/\.exe$/u, "");

/** The system tool itself (tar, cp): the tarball path is exercised for real. */
function realTool(command: string, args: readonly string[]): RunResult {
	const result = spawnSync(command, [...args], { encoding: "utf8" });
	return { status: result.status, stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
}

/** `<bundle>/bin/aidr verify --json` as the bundle at that path would answer. */
function verifyAnswer(aidr: string, scenario: Scenario): RunResult {
	const outcome = (scenario.verify ?? (() => "pass"))(bundleVersion(dirname(dirname(aidr))));
	const hosts = [{ host: "claude-code", outcome }];
	return { status: 0, stdout: JSON.stringify({ schema_version: 1, hosts }), stderr: "" };
}

function packageTool(scenario: Scenario): RunResult {
	scenario.install?.();
	const status = scenario.installStatus ?? 0;
	return { status, stdout: "", stderr: status ? "dpkg: error" : "" };
}

function runner(scenario: Scenario = {}) {
	const calls: string[][] = [];
	const run: CommandRunner = (command, args) => {
		calls.push([command, ...args]);
		if (command === "tar" || command === "cp") return realTool(command, args);
		if (args[0] === "verify") return verifyAnswer(command, scenario);
		if (args[0] === "setup") return { status: 0, stdout: "", stderr: "" };
		if (PACKAGE_TOOLS.has(toolName(command))) return packageTool(scenario);
		return {
			status: 127,
			stdout: "",
			stderr: `unexpected ${command}`,
			error: `unexpected ${command}`,
		};
	};
	return { run, calls };
}

function streams(tty = false) {
	const input = Object.assign(new PassThrough(), { isTTY: tty });
	const output = Object.assign(new PassThrough(), { isTTY: tty });
	return { input, output };
}

async function update(
	options: UpdateOptions,
	overrides: Partial<UpdateDeps> & { scenario?: Scenario } = {},
) {
	const lines: string[] = [];
	const errors: string[] = [];
	const { run, calls } = runner(overrides.scenario);
	await updateCommand(options, {
		config: ConfigSchema.parse({}),
		executable: join(prefix, "bundle", "bin", "aidr"),
		currentVersion: "1.4.0",
		platform: "linux",
		arch: "x64",
		environment: { exists: (path) => path !== LINUX_MDM_MARKER && existsSync(path) },
		apiKey: null,
		run,
		workRoot: join(root, "updates"),
		statePath: join(root, "update-check.json"),
		isRoot: false,
		privileged: "direct",
		installKind: "tar",
		env: { AIDR_OPERATOR_NONINTERACTIVE: "1" },
		streams: streams(),
		out: (line) => lines.push(line),
		err: (line) => errors.push(line),
		...overrides,
	});
	return { lines, errors, calls, output: [...lines, ...errors].join("\n") };
}

const installCalls = (calls: string[][]) =>
	calls.filter(
		([command, arg]) =>
			PACKAGE_TOOLS.has(toolName(command as string)) || (command === "tar" && arg === "-xzf"),
	);

beforeEach(() => {
	savedExitCode = process.exitCode;
	process.exitCode = undefined;
	root = mkdtempSync(join(tmpdir(), "aidr-update-cli-"));
	prefix = join(root, "opt", "singularity-aidr");
	writeBundle(join(prefix, "bundle"), "1.4.0");
	mkdirSync(join(prefix, "config"), { recursive: true });
	mkdirSync(join(prefix, "libexec"), { recursive: true });
	writeFileSync(join(prefix, "config", "release-public.pem"), "installed release key");
	writeFileSync(join(prefix, "libexec", "package-hook.sh"), "#!/bin/sh\n# hook 1.4.0\n");
	writeFileSync(
		join(prefix, "config", "installer-catalog-public.pem"),
		catalogKey.publicKey.export({ type: "spki", format: "pem" }).toString(),
	);
});

afterEach(() => {
	process.exitCode = savedExitCode;
	rmSync(root, { recursive: true, force: true });
});

describe("aidr update --check", () => {
	it("reports an available update and changes nothing", async () => {
		const mirror = writeMirror(join(root, "mirror"), { installer: buildTarball("1.5.0") });
		const result = await update({ check: true, from: mirror });
		expect(result.output).toContain(
			"Singularity AIDR v1.5.0 is available (you have v1.4.0). To install it, run: aidr update",
		);
		expect(result.calls).toEqual([]);
		expect(bundleVersion(join(prefix, "bundle"))).toBe("1.4.0");
		expect(existsSync(join(root, "updates"))).toBe(false);
		expect(process.exitCode).toBeUndefined();
	});

	it("emits JSON and says when the machine is up to date", async () => {
		const mirror = writeMirror(join(root, "mirror"), { installer: buildTarball("1.5.0") });
		const json = await update({ check: true, json: true, from: mirror });
		expect(JSON.parse(json.lines.join("\n"))).toMatchObject({
			status: "available",
			current: "1.4.0",
			latest: "1.5.0",
			platform: "linux-x64",
			mdm_managed: false,
			auto: "notify",
		});
		const same = await update({ check: true, from: mirror }, { currentVersion: "1.5.0" });
		expect(same.output).toContain("Singularity AIDR is up to date (v1.5.0).");
	});
});

describe("aidr update verification", () => {
	it("refuses a catalog signed with another key before downloading anything", async () => {
		const mirror = writeMirror(join(root, "mirror"), {
			installer: buildTarball("1.5.0"),
			key: otherKey.privateKey,
		});
		const result = await update({ from: mirror, yes: true });
		expect(result.output).toContain("signature does not match the installer-catalog key");
		expect(process.exitCode).toBe(1);
		expect(result.calls).toEqual([]);
		expect(bundleVersion(join(prefix, "bundle"))).toBe("1.4.0");
	});

	it("deletes an installer whose bytes do not match the signed SHA-256 and installs nothing", async () => {
		const tarball = buildTarball("1.5.0");
		const tampered = Buffer.from(tarball);
		tampered[tampered.length - 1] ^= 0xff;
		const mirror = writeMirror(join(root, "mirror"), {
			installer: tarball,
			publishedBytes: tampered,
		});
		const result = await update({ from: mirror, yes: true });
		expect(result.output).toContain("does not match the SHA-256 in the signed catalog");
		expect(process.exitCode).toBe(1);
		expect(installCalls(result.calls)).toEqual([]);
		expect(readdirSync(join(root, "updates")).filter((name) => name !== "update.lock")).toEqual([]);
		expect(bundleVersion(join(prefix, "bundle"))).toBe("1.4.0");
	});

	it("fails closed without a pinned catalog key", async () => {
		rmSync(join(prefix, "config", "installer-catalog-public.pem"));
		const mirror = writeMirror(join(root, "mirror"), { installer: buildTarball("1.5.0") });
		const result = await update({ from: mirror, yes: true });
		expect(result.output).toContain("no installer-catalog public key is set");
		expect(result.output).toContain(join(prefix, "config", "installer-catalog-public.pem"));
		expect(process.exitCode).toBe(1);
	});

	it("needs the operator's confirmation to install", async () => {
		const mirror = writeMirror(join(root, "mirror"), { installer: buildTarball("1.5.0") });
		const result = await update({ from: mirror }, { env: {} });
		expect(result.output).toContain("Nothing was installed.");
		expect(installCalls(result.calls)).toEqual([]);
		expect(process.exitCode).toBe(1);
	});
});

describe("aidr update install and rollback", () => {
	it("installs a tarball update, keeps the installed release key and re-registers", async () => {
		const mirror = writeMirror(join(root, "mirror"), { installer: buildTarball("1.5.0") });
		const result = await update({ from: mirror, yes: true });
		expect(result.errors).toEqual([]);
		expect(result.output).toContain(
			"Singularity AIDR v1.5.0 is installed and passed 'aidr verify'.",
		);
		expect(bundleVersion(join(prefix, "bundle"))).toBe("1.5.0");
		expect(readFileSync(join(prefix, "config", "release-public.pem"), "utf8")).toBe(
			"installed release key",
		);
		expect(readFileSync(join(prefix, "libexec", "package-hook.sh"), "utf8")).toContain(
			"hook 1.5.0",
		);
		expect(existsSync(join(prefix, "bundle.aidr-update-previous"))).toBe(false);
		expect(result.calls).toContainEqual([join(prefix, "bundle", "bin", "aidr"), "setup"]);
		expect(readdirSync(join(root, "updates"))).toEqual([]);
		expect(JSON.parse(readFileSync(join(root, "update-check.json"), "utf8"))).toMatchObject({
			current: "1.5.0",
			status: "up_to_date",
		});
		expect(process.exitCode).toBeUndefined();
	});

	it("puts the previous version back when the new one fails 'aidr verify'", async () => {
		const mirror = writeMirror(join(root, "mirror"), { installer: buildTarball("1.5.0") });
		const result = await update(
			{ from: mirror, yes: true },
			{ scenario: { verify: (version) => (version === "1.5.0" ? "fail" : "pass") } },
		);
		expect(result.output).toContain(
			"The new version did not pass the checks ('aidr verify' FAIL for claude-code). v1.4.0 was put back",
		);
		expect(bundleVersion(join(prefix, "bundle"))).toBe("1.4.0");
		expect(existsSync(join(prefix, "bundle.aidr-update-previous"))).toBe(false);
		expect(existsSync(join(prefix, "bundle.aidr-update-failed"))).toBe(false);
		expect(process.exitCode).toBe(1);
	});

	it("rolls a package install back from the fallback copy and says the package record is stale", async () => {
		const mirror = writeMirror(join(root, "mirror"), {
			installer: Buffer.from("deb bytes 1.5.0"),
			file: "singularity-aidr_1.5.0_amd64.deb",
			format: "deb",
		});
		const result = await update(
			{ from: mirror, yes: true },
			{
				installKind: "deb",
				scenario: {
					install: () => {
						rmSync(join(prefix, "bundle"), { recursive: true });
						writeBundle(join(prefix, "bundle"), "1.5.0");
					},
					verify: (version) => (version === "1.5.0" ? "fail" : "pass"),
				},
			},
		);
		expect(result.calls.some(([command, arg]) => command === "dpkg" && arg === "-i")).toBe(true);
		expect(bundleVersion(join(prefix, "bundle"))).toBe("1.4.0");
		expect(result.output).toContain("v1.4.0 was put back");
		expect(result.output).toContain("The package manager still lists v1.5.0.");
		expect(process.exitCode).toBe(1);
	});

	it("keeps a failed package transaction's untouched install without a rollback", async () => {
		const mirror = writeMirror(join(root, "mirror"), {
			installer: Buffer.from("deb bytes 1.5.0"),
			file: "singularity-aidr_1.5.0_amd64.deb",
			format: "deb",
		});
		const result = await update(
			{ from: mirror, yes: true },
			{ installKind: "deb", scenario: { installStatus: 2 } },
		);
		expect(result.output).toContain("The installer stopped with an error");
		expect(result.output).toContain("Nothing was changed.");
		expect(bundleVersion(join(prefix, "bundle"))).toBe("1.4.0");
	});

	it("refuses a tarball that holds a link, before anything is extracted", async () => {
		const mirror = writeMirror(join(root, "mirror"), {
			installer: buildTarball("1.5.0", { link: true }),
		});
		const result = await update({ from: mirror, yes: true });
		expect(result.output).toContain("may hold only regular files and folders");
		expect(result.calls.some(([command, arg]) => command === "tar" && arg === "-xzf")).toBe(false);
		expect(bundleVersion(join(prefix, "bundle"))).toBe("1.4.0");
	});

	it("refuses an installer of another package format", async () => {
		const mirror = writeMirror(join(root, "mirror"), { installer: buildTarball("1.5.0") });
		const result = await update({ from: mirror, yes: true }, { installKind: "rpm" });
		expect(result.output).toContain(
			"The available installer is a .tar.gz file, but Singularity AIDR on this machine was installed as .rpm.",
		);
		expect(installCalls(result.calls)).toEqual([]);
	});
});

describe("aidr update on Windows", () => {
	it("runs msiexec silently by absolute path, with the per-user properties of a per-user install", async () => {
		rmSync(join(prefix, "bundle"), { recursive: true });
		writeBundle(join(prefix, "bundle"), "1.4.0", ".exe");
		const msi = "singularity-aidr-1.5.0-windows-x64.msi";
		const mirror = writeMirror(join(root, "mirror"), {
			platform: "windows-x64",
			installer: Buffer.from("msi bytes 1.5.0"),
			file: msi,
			format: "msi",
		});
		const result = await update(
			{ from: mirror, yes: true },
			{
				platform: "win32",
				executable: join(prefix, "bundle", "bin", "aidr.exe"),
				installKind: undefined,
				env: { AIDR_OPERATOR_NONINTERACTIVE: "1", LOCALAPPDATA: root, SystemRoot: "C:\\Windows" },
				environment: { exists: existsSync, regQuery: () => null },
				scenario: {
					install: () => {
						rmSync(join(prefix, "bundle"), { recursive: true });
						writeBundle(join(prefix, "bundle"), "1.5.0", ".exe");
					},
				},
			},
		);
		expect(result.errors).toEqual([]);
		expect(result.output).toContain("Singularity AIDR v1.5.0 is installed");
		const msiexec = result.calls.find(([command]) => toolName(command as string) === "msiexec");
		expect(msiexec?.[0]).toMatch(/^C:\\Windows[\\/]System32[\\/]msiexec\.exe$/u);
		expect(msiexec?.slice(1, 5)).toEqual(["/i", expect.stringContaining(msi), "/qn", "/norestart"]);
		expect(msiexec?.slice(-2)).toEqual(["MSIINSTALLPERUSER=1", "ALLUSERS=2"]);
		expect(bundleVersion(join(prefix, "bundle"))).toBe("1.5.0");
	});

	it("refuses to install when the Windows device-management policy is set", async () => {
		const mirror = writeMirror(join(root, "mirror"), {
			platform: "windows-x64",
			installer: Buffer.from("msi"),
			file: "a.msi",
			format: "msi",
		});
		const policy = "    MdmManaged    REG_DWORD    0x1\r\n";
		const result = await update(
			{ from: mirror, yes: true },
			{ platform: "win32", env: {}, environment: { exists: existsSync, regQuery: () => policy } },
		);
		expect(result.output).toContain("HKLM\\SOFTWARE\\Policies\\Singularity AIDR\\MdmManaged");
		expect(result.calls).toEqual([]);
	});
});

describe("protected staging", () => {
	it("stages in a root-owned or administrator-only directory whenever a privilege boundary is crossed", () => {
		const layout = {
			prefix: "/opt/singularity-aidr",
			bundle: "/opt/singularity-aidr/bundle",
			perUser: false,
		};
		const base = {
			isRoot: false,
			layout,
			workDir: "/home/u/.singularity-aidr/updates/1.5.0-1",
			now: 1,
		};
		expect(stagingDirFor({ ...base, mode: "sudo", platform: "linux" })).toMatch(
			/^\/var\/cache\/singularity-aidr\/update-/u,
		);
		expect(stagingDirFor({ ...base, mode: "direct", platform: "linux", isRoot: true })).toMatch(
			/^\/var\/cache\/singularity-aidr\//u,
		);
		const machine = { prefix: "C:\\Program Files\\Singularity AIDR", bundle: "x", perUser: false };
		expect(
			stagingDirFor({ ...base, layout: machine, mode: "direct", platform: "win32" }),
		).toContain("update-staging");
		expect(
			stagingDirFor({
				...base,
				layout: { ...machine, perUser: true },
				mode: "direct",
				platform: "win32",
			}),
		).toBe(join(base.workDir, "staging"));
	});

	it("refuses an installer that changes between verification and the privileged copy", () => {
		const { run, calls } = runner();
		const direct = privilegedOps("direct", run);
		const tampering = {
			...direct,
			copyFile: (source: string, destination: string) => {
				const result = direct.copyFile(source, destination);
				writeFileSync(destination, "swapped by another process");
				return result;
			},
		};
		const installer = join(root, "singularity-aidr_1.5.0_amd64.deb");
		writeFileSync(installer, "deb bytes 1.5.0");
		const workDir = join(root, "work");
		mkdirSync(workDir);
		const apply = () =>
			applyUpdate({
				kind: "deb",
				layout: { prefix, bundle: join(prefix, "bundle"), perUser: false },
				installer,
				file: {
					platform: "linux-x64",
					os: "linux",
					arch: "x64",
					file: "singularity-aidr_1.5.0_amd64.deb",
					path: "1.5.0/linux-x64/singularity-aidr_1.5.0_amd64.deb",
					size: 15,
					sha256: sha("deb bytes 1.5.0"),
					minimum_os: "glibc 2.28",
					format: "deb",
				},
				targetVersion: "1.5.0",
				allowDowngrade: false,
				workDir,
				stagingDir: join(workDir, "staging"),
				platform: "linux",
				ops: tampering,
				run,
			});
		expect(apply).toThrow(UpdateApplyError);
		expect(apply).toThrow(/changed after it was verified/u);
		expect(calls.some(([command]) => command === "dpkg")).toBe(false);
		expect(existsSync(join(workDir, "staging"))).toBe(false);
		expect(bundleVersion(join(prefix, "bundle"))).toBe("1.4.0");
	});
});

describe("aidr update downgrades", () => {
	it("refuses an older version unless --allow-downgrade is given", async () => {
		const mirror = writeMirror(join(root, "mirror"), { installer: buildTarball("1.5.0") });
		const refused = await update({ from: mirror, yes: true }, { currentVersion: "1.6.0" });
		expect(refused.output).toContain("Refusing to go back from v1.6.0 to v1.5.0.");
		expect(installCalls(refused.calls)).toEqual([]);
		expect(process.exitCode).toBe(1);

		process.exitCode = undefined;
		const allowed = await update(
			{ from: mirror, yes: true, allowDowngrade: true },
			{ currentVersion: "1.6.0" },
		);
		expect(allowed.output).toContain("Singularity AIDR v1.5.0 is installed");
		expect(bundleVersion(join(prefix, "bundle"))).toBe("1.5.0");
	});

	it("never downgrades from the background path", async () => {
		const mirror = writeMirror(join(root, "mirror"), { installer: buildTarball("1.5.0") });
		const result = await update(
			{ auto: true },
			{
				currentVersion: "1.6.0",
				config: ConfigSchema.parse({ update: { auto: "install", source: mirror } }),
			},
		);
		expect(installCalls(result.calls)).toEqual([]);
		expect(bundleVersion(join(prefix, "bundle"))).toBe("1.4.0");
	});
});

describe("aidr update under device management", () => {
	const mdm = { exists: (path: string) => path === LINUX_MDM_MARKER || existsSync(path) };

	it("refuses to install, still checks, and the background path does nothing", async () => {
		const mirror = writeMirror(join(root, "mirror"), { installer: buildTarball("1.5.0") });
		const refused = await update({ from: mirror, yes: true }, { environment: mdm });
		expect(refused.output).toContain(
			"managed by your IT department's device management (/etc/singularity-aidr/mdm-managed)",
		);
		expect(refused.calls).toEqual([]);
		expect(process.exitCode).toBe(1);

		process.exitCode = undefined;
		const checked = await update({ check: true, from: mirror }, { environment: mdm });
		expect(checked.output).toContain("v1.5.0 is available");
		expect(checked.output).toContain("Automatic updates are off: device management");

		const background = await update(
			{ auto: true },
			{
				environment: mdm,
				config: ConfigSchema.parse({ update: { auto: "install", source: mirror } }),
			},
		);
		expect(background.calls).toEqual([]);
		expect(background.output).toBe("");
		expect(bundleVersion(join(prefix, "bundle"))).toBe("1.4.0");
	});

	it("installs from the background path only with update.auto=install", async () => {
		const mirror = writeMirror(join(root, "mirror"), { installer: buildTarball("1.5.0") });
		const notify = await update(
			{ auto: true },
			{ config: ConfigSchema.parse({ update: { source: mirror } }) },
		);
		expect(notify.calls).toEqual([]);
		const install = await update(
			{ auto: true },
			{ env: {}, config: ConfigSchema.parse({ update: { auto: "install", source: mirror } }) },
		);
		expect(install.output).toBe("");
		expect(bundleVersion(join(prefix, "bundle"))).toBe("1.5.0");
	});
});

describe("aidr update outside an installer layout", () => {
	it("explains how to update other installs and that Linux updates run as the user", async () => {
		const other = await update({ check: true }, { executable: null });
		expect(other.output).toContain("was not installed with the Windows or Linux installer");
		const asRoot = await update({ from: join(root, "mirror"), yes: true }, { isRoot: true });
		expect(asRoot.output).toContain("not as root or with sudo");
		const mac = await update({ check: true }, { platform: "darwin", arch: "arm64" });
		expect(mac.output).toContain("Windows and Linux (x64 and arm64); this machine is darwin/arm64");
		const noSource = await update({ check: true });
		expect(noSource.output).toContain("There is no update source.");
	});

	it("does not replace an installation that cannot be kept as the fallback copy", async () => {
		writeFileSync(join(prefix, "bundle", "bin", "aidr-pre-tool-use"), "tampered");
		const mirror = writeMirror(join(root, "mirror"), { installer: buildTarball("1.5.0") });
		const result = await update({ from: mirror, yes: true });
		expect(result.output).toContain("failed its own integrity check");
		expect(installCalls(result.calls)).toEqual([]);
		expect(bundleVersion(join(prefix, "bundle"))).toBe("1.4.0");
	});
});

describe("aidr update messages", () => {
	it("has the same keys and parameters in English and Turkish, and uses every key", () => {
		expect(Object.keys(UPDATE_TR).sort()).toEqual(Object.keys(UPDATE_EN).sort());
		const params = (text: string) =>
			[...text.matchAll(/\{(\w+)\}/g)].map((match) => match[1]).sort();
		for (const [key, english] of Object.entries(UPDATE_EN)) {
			expect(params(UPDATE_TR[key as keyof typeof UPDATE_EN]), key).toEqual(params(english));
		}
		const source = readFileSync(join(__dirname, "..", "commands", "update.ts"), "utf8");
		const unused = Object.keys(UPDATE_EN).filter(
			(key) => !key.startsWith("update.error.") && !source.includes(`"${key}"`),
		);
		expect(unused).toEqual([]);
	});

	it("speaks Turkish with AIDR_LOCALE=tr", async () => {
		const previous = process.env.AIDR_LOCALE;
		process.env.AIDR_LOCALE = "tr";
		try {
			const mirror = writeMirror(join(root, "mirror"), {
				installer: buildTarball("1.5.0"),
				key: otherKey.privateKey,
			});
			const result = await update({ check: true, from: mirror });
			expect(result.output).toContain(
				"imzası, bu makinenin güvendiği kurulum kataloğu anahtarıyla eşleşmiyor",
			);
		} finally {
			if (previous === undefined) delete process.env.AIDR_LOCALE;
			else process.env.AIDR_LOCALE = previous;
		}
	});
});
