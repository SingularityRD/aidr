import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
	closeSync,
	copyFileSync,
	cpSync,
	existsSync,
	mkdirSync,
	openSync,
	readSync,
	renameSync,
	rmdirSync,
	rmSync,
	statSync,
} from "node:fs";
import { basename, dirname, isAbsolute, join, normalize } from "node:path";
import type { InstallerCatalogFile, InstallerLayout } from "@singularityrd/aidr-core";
import { verifyStandaloneBundle } from "./standalone.js";

/**
 * Applying a verified installer for `aidr update`, with rollback.
 *
 * Everything the privileged steps read is first copied into a staging
 * directory the user cannot modify (root-owned under /var/cache with sudo, the
 * install folder on a per-machine Windows install) and checked there: the
 * installer against its SHA-256 again, so a process of the same user cannot
 * swap the verified file before root or an elevated msiexec reads it.
 *
 * Before anything changes, the installed bundle is copied there too and that
 * copy must pass its own manifest check: it is the rollback. The platform installer
 * then runs silently (msiexec /qn, dpkg -i, rpm -U, or the tarball's bundle
 * swap). The new version must pass the bundle manifest check against the
 * release key that is ALREADY installed, and `aidr verify` must not report a
 * host failing that passed before. Anything else restores the previous bundle,
 * re-registers it with `aidr setup`, and checks it again.
 */

export type InstallKind = "msi" | "deb" | "rpm" | "tar";

export interface RunResult {
	status: number | null;
	stdout: string;
	stderr: string;
	/** Spawn error (for example ENOENT). */
	error?: string;
}

export type CommandRunner = (
	command: string,
	args: readonly string[],
	options?: { env?: NodeJS.ProcessEnv; timeoutMs?: number; cwd?: string },
) => RunResult;

export const runCommand: CommandRunner = (command, args, options = {}) => {
	const result = spawnSync(command, [...args], {
		encoding: "utf8",
		env: options.env ?? process.env,
		cwd: options.cwd,
		timeout: options.timeoutMs ?? 30 * 60_000,
		windowsHide: true,
		maxBuffer: 16 * 1024 * 1024,
		stdio: ["inherit", "pipe", "pipe"],
	});
	return {
		status: result.status,
		stdout: result.stdout ?? "",
		stderr: result.stderr ?? "",
		...(result.error ? { error: result.error.message } : {}),
	};
};

/** Package name the .deb and .rpm register (deploy/installers/lib/common.mjs). */
const PACKAGE_NAME = "singularity-aidr";
const LINUX_PREFIX = "/opt/singularity-aidr";
const NEW_SUFFIX = ".aidr-update-new";
const PREVIOUS_SUFFIX = ".aidr-update-previous";
const FAILED_SUFFIX = ".aidr-update-failed";

/** How AIDR was installed on this machine. */
export function detectInstallKind(
	layout: InstallerLayout,
	platform: NodeJS.Platform,
	run: CommandRunner,
): InstallKind {
	if (platform === "win32") return "msi";
	if (normalize(layout.prefix) === LINUX_PREFIX) {
		const deb = run("dpkg-query", ["-W", "-f=${Status}", PACKAGE_NAME], { timeoutMs: 30_000 });
		if (deb.status === 0 && /install ok installed/u.test(deb.stdout)) return "deb";
		const rpm = run("rpm", ["-q", PACKAGE_NAME], { timeoutMs: 30_000 });
		if (rpm.status === 0) return "rpm";
	}
	return "tar";
}

/**
 * The catalog formats that update this kind of installation, in order of
 * preference. A new installer format becomes installable by adding it here (and
 * an apply step for it below).
 */
const KIND_FORMATS: Record<InstallKind, readonly string[]> = {
	msi: ["msi"],
	deb: ["deb"],
	rpm: ["rpm"],
	tar: ["tar.gz", "tgz"],
};

export function installerFormats(kind: InstallKind): readonly string[] {
	return KIND_FORMATS[kind];
}

/** Does the catalog's installer format update this kind of installation? */
export function formatMatches(kind: InstallKind, format: string): boolean {
	return KIND_FORMATS[kind].includes(format);
}

/**
 * Privileged file and command operations. On Windows (an elevated or per-user
 * install) and as root they run directly; otherwise through sudo, which asks
 * for the password in the terminal (`sudo -n` without a terminal).
 */
export interface PrivilegedOps {
	mode: "direct" | "sudo";
	run(command: string, args: readonly string[]): RunResult;
	copyDir(source: string, destination: string): RunResult;
	copyFile(source: string, destination: string): RunResult;
	makeDir(path: string): RunResult;
	move(source: string, destination: string): RunResult;
	remove(path: string): RunResult;
}

const OK: RunResult = { status: 0, stdout: "", stderr: "" };

function attempt(action: () => void): RunResult {
	try {
		action();
		return OK;
	} catch (error) {
		return {
			status: 1,
			stdout: "",
			stderr: error instanceof Error ? error.message : String(error),
		};
	}
}

export function privilegedOps(
	mode: "direct" | "sudo",
	run: CommandRunner,
	options: { nonInteractive?: boolean } = {},
): PrivilegedOps {
	if (mode === "direct") {
		return {
			mode,
			run: (command, args) => run(command, args),
			copyDir: (source, destination) =>
				attempt(() =>
					cpSync(source, destination, {
						recursive: true,
						verbatimSymlinks: true,
						errorOnExist: true,
						force: false,
					}),
				),
			copyFile: (source, destination) => attempt(() => copyFileSync(source, destination)),
			makeDir: (path) => attempt(() => mkdirSync(path, { recursive: true, mode: 0o755 })),
			move: (source, destination) => attempt(() => renameSync(source, destination)),
			remove: (path) => attempt(() => rmSync(path, { recursive: true, force: true })),
		};
	}
	const sudo = (args: readonly string[]) =>
		run("sudo", [...(options.nonInteractive ? ["-n"] : []), "--", ...args]);
	return {
		mode,
		run: (command, args) => sudo([command, ...args]),
		copyDir: (source, destination) => sudo(["cp", "-a", "--", source, destination]),
		copyFile: (source, destination) => sudo(["install", "-m", "0644", "--", source, destination]),
		makeDir: (path) => sudo(["install", "-d", "-m", "0755", "--", path]),
		move: (source, destination) => sudo(["mv", "-T", "--", source, destination]),
		remove: (path) => sudo(["rm", "-rf", "--", path]),
	};
}

interface VerifyReport {
	ok: boolean;
	/** host -> pass | fail | skip | not_registered */
	hosts: Record<string, string>;
	detail: string;
}

/** Run `<aidr> verify --json` and read the per-host outcome. */
function runVerify(aidr: string, run: CommandRunner, env?: NodeJS.ProcessEnv): VerifyReport {
	const result = run(aidr, ["verify", "--json"], { env, timeoutMs: 5 * 60_000 });
	try {
		const parsed = JSON.parse(result.stdout) as {
			hosts?: Array<{ host?: unknown; outcome?: unknown }>;
		};
		if (!Array.isArray(parsed.hosts)) throw new Error("no hosts");
		const hosts: Record<string, string> = {};
		for (const entry of parsed.hosts) {
			if (typeof entry.host === "string" && typeof entry.outcome === "string")
				hosts[entry.host] = entry.outcome;
		}
		return { ok: true, hosts, detail: "" };
	} catch {
		const reason =
			result.error ?? (`${result.stderr}`.trim().slice(0, 300) || `exit ${result.status}`);
		return { ok: false, hosts: {}, detail: reason };
	}
}

/** Hosts that fail now but did not fail before the update. */
function newlyFailingHosts(before: VerifyReport, after: VerifyReport): string[] {
	return Object.entries(after.hosts)
		.filter(([host, outcome]) => outcome === "fail" && before.hosts[host] !== "fail")
		.map(([host]) => host);
}

/** The installer command line for a package installer (not the tarball). */
function installerCommand(
	kind: Exclude<InstallKind, "tar">,
	file: string,
	options: { perUser: boolean; allowDowngrade: boolean; logFile: string; systemRoot?: string },
): { command: string; args: string[] } {
	if (kind === "msi") {
		return {
			// By absolute path, so a directory earlier on PATH cannot stand in for it.
			command: join(options.systemRoot?.trim() || "C:\\Windows", "System32", "msiexec.exe"),
			args: [
				"/i",
				file,
				"/qn",
				"/norestart",
				"/l*v",
				options.logFile,
				...(options.perUser ? ["MSIINSTALLPERUSER=1", "ALLUSERS=2"] : []),
			],
		};
	}
	if (kind === "deb") return { command: "dpkg", args: ["-i", file] };
	return {
		command: "rpm",
		args: ["-U", ...(options.allowDowngrade ? ["--oldpackage"] : []), file],
	};
}

/** msiexec success codes: 0, and 3010 / 1641 when Windows wants a restart. */
function installerSucceeded(kind: InstallKind, status: number | null): boolean {
	if (kind === "msi") return status === 0 || status === 3010 || status === 1641;
	return status === 0;
}

/** msiexec: elevation was needed (1925 needs admin, 1603 fatal, 1730 must be admin to remove). */
function needsElevation(kind: InstallKind, status: number | null): boolean {
	return kind === "msi" && (status === 1925 || status === 1730 || status === 1603);
}

export class UpdateApplyError extends Error {
	constructor(
		readonly code:
			| "snapshot_invalid"
			| "tar_invalid"
			| "staged_bundle_invalid"
			| "installer_failed"
			| "needs_elevation"
			| "privilege_denied",
		message: string,
	) {
		super(message);
		this.name = "UpdateApplyError";
	}
}

/**
 * Where the privileged steps read from: a directory the user cannot modify.
 * With sudo (or as root) a fresh root-owned directory under /var/cache; on a
 * per-machine Windows install a folder inside the install folder (writable by
 * administrators only). A per-user install crosses no privilege boundary.
 */
export function stagingDirFor(input: {
	mode: PrivilegedOps["mode"];
	platform: NodeJS.Platform;
	isRoot: boolean;
	layout: InstallerLayout;
	workDir: string;
	now: number;
}): string {
	const run = `update-${process.pid}-${input.now}`;
	if (input.platform === "linux" && (input.mode === "sudo" || input.isRoot)) {
		return `/var/cache/singularity-aidr/${run}`;
	}
	if (input.platform === "win32" && !input.layout.perUser) {
		return join(input.layout.prefix, "update-staging", run);
	}
	return join(input.workDir, "staging");
}

function privilegeError(
	ops: PrivilegedOps,
	result: RunResult,
	fallback: UpdateApplyError["code"],
): UpdateApplyError {
	return new UpdateApplyError(
		ops.mode === "sudo" ? "privilege_denied" : fallback,
		failed(result) ?? "",
	);
}

/** Copy the installed bundle aside; the copy must pass its own manifest check. */
function snapshotBundle(options: ApplyOptions): { path: string; manifestSha256: string | null } {
	const { layout, platform, ops } = options;
	const snapshot = join(options.stagingDir, "rollback-bundle");
	const copied = ops.copyDir(layout.bundle, snapshot);
	if (failed(copied)) throw privilegeError(ops, copied, "snapshot_invalid");
	const check = verifyStandaloneBundle(snapshot, {
		trustKeyPath: join(layout.prefix, "config", "release-public.pem"),
		platform,
	});
	if (!check.ok)
		throw new UpdateApplyError("snapshot_invalid", check.problems.slice(0, 5).join("; "));
	return { path: snapshot, manifestSha256: check.manifestSha256 };
}

function sha256File(path: string): string {
	const hash = createHash("sha256");
	const buffer = Buffer.alloc(1024 * 1024);
	const fd = openSync(path, "r");
	try {
		for (let read = readSync(fd, buffer); read > 0; read = readSync(fd, buffer)) {
			hash.update(buffer.subarray(0, read));
		}
	} finally {
		closeSync(fd);
	}
	return hash.digest("hex");
}

/**
 * Copy the verified installer into the staging directory and check its
 * SHA-256 there again: what root or an elevated msiexec reads is exactly what
 * was verified.
 */
function stageInstaller(options: ApplyOptions): string {
	const staged = join(options.stagingDir, basename(options.installer));
	const copied = options.ops.copyFile(options.installer, staged);
	if (failed(copied)) throw privilegeError(options.ops, copied, "installer_failed");
	if (sha256File(staged) !== options.file.sha256) {
		throw new UpdateApplyError("installer_failed", "the installer changed after it was verified");
	}
	return staged;
}

function safeTarEntry(entry: string): boolean {
	const path = entry.replace(/\/+$/u, "");
	return (
		path.length > 0 &&
		!isAbsolute(path) &&
		!path.includes("\\") &&
		!path.split("/").some((part) => part === ".." || part === "")
	);
}

/** Extract the staged tarball into `stage` (with the privileged tar) and return its top directory. */
function extractTarball(
	file: string,
	stage: string,
	run: CommandRunner,
	ops: PrivilegedOps,
): string {
	const listing = run("tar", ["-tzf", file], { timeoutMs: 10 * 60_000 });
	if (listing.status !== 0)
		throw new UpdateApplyError("tar_invalid", listing.stderr.trim() || "tar -t failed");
	const entries = listing.stdout.split(/\r?\n/u).filter(Boolean);
	if (entries.length === 0 || !entries.every(safeTarEntry)) {
		throw new UpdateApplyError("tar_invalid", "the archive has an unsafe or empty entry");
	}
	// Only regular files and directories: a link could make the privileged
	// extraction write outside the staging folder.
	const types = run("tar", ["-tvzf", file], { timeoutMs: 10 * 60_000 });
	const kinds = types.stdout
		.split(/\r?\n/u)
		.filter(Boolean)
		.map((line) => line[0]);
	if (
		types.status !== 0 ||
		kinds.length !== entries.length ||
		kinds.some((kind) => kind !== "-" && kind !== "d")
	) {
		throw new UpdateApplyError(
			"tar_invalid",
			"the archive may hold only regular files and folders",
		);
	}
	const tops = new Set(entries.map((entry) => entry.split("/")[0]));
	if (tops.size !== 1)
		throw new UpdateApplyError("tar_invalid", "the archive must have one top directory");
	const made = ops.makeDir(stage);
	if (failed(made)) throw privilegeError(ops, made, "tar_invalid");
	const extracted = ops.run("tar", [
		"-xzf",
		file,
		"-C",
		stage,
		"--no-same-owner",
		"--no-same-permissions",
	]);
	if (extracted.status !== 0)
		throw new UpdateApplyError("tar_invalid", extracted.stderr.trim() || "tar -x failed");
	const top = join(stage, [...tops][0] as string);
	if (!existsSync(join(top, "bundle")) || !statSync(join(top, "bundle")).isDirectory()) {
		throw new UpdateApplyError("tar_invalid", "the archive has no bundle directory");
	}
	return top;
}

export interface ApplyOptions {
	kind: InstallKind;
	layout: InstallerLayout;
	installer: string;
	file: InstallerCatalogFile;
	targetVersion: string;
	allowDowngrade: boolean;
	workDir: string;
	/** Directory the user cannot modify (stagingDirFor); removed when done. */
	stagingDir: string;
	platform: NodeJS.Platform;
	ops: PrivilegedOps;
	run: CommandRunner;
	env?: NodeJS.ProcessEnv;
	log?: (line: string) => void;
}

export type ApplyResult =
	| { outcome: "installed"; verify: VerifyReport }
	| {
			outcome: "rolled_back";
			reason: string;
			/** The package database still lists the new version (msi/deb/rpm). */
			packageRecordStale: boolean;
	  }
	| { outcome: "rollback_failed"; reason: string; rollbackError: string };

function aidrBinary(bundle: string, platform: NodeJS.Platform): string {
	return join(bundle, "bin", platform === "win32" ? "aidr.exe" : "aidr");
}

function failed(result: RunResult): string | null {
	if (result.status === 0) return null;
	return result.error ?? (`${result.stderr}`.trim().slice(0, 300) || `exit ${result.status}`);
}

/** Install the tarball by swapping the bundle directory (install.sh refuses an existing install). */
function swapTarball(options: ApplyOptions, snapshot: string, installer: string): void {
	const { layout, ops, run } = options;
	const top = extractTarball(installer, join(options.stagingDir, "stage"), run, ops);
	// The staged bundle must be intact and signed for the release key that is
	// already installed; the update never brings its own trust key.
	const staged = verifyStandaloneBundle(join(top, "bundle"), {
		trustKeyPath: join(layout.prefix, "config", "release-public.pem"),
		platform: options.platform,
	});
	if (!staged.ok)
		throw new UpdateApplyError("staged_bundle_invalid", staged.problems.slice(0, 5).join("; "));
	const next = `${layout.bundle}${NEW_SUFFIX}`;
	const previous = `${layout.bundle}${PREVIOUS_SUFFIX}`;
	ops.remove(next);
	ops.remove(previous);
	const copied = ops.copyDir(join(top, "bundle"), next);
	if (failed(copied)) {
		ops.remove(next);
		throw privilegeError(ops, copied, "installer_failed");
	}
	const aside = ops.move(layout.bundle, previous);
	if (failed(aside)) {
		ops.remove(next);
		throw new UpdateApplyError("installer_failed", failed(aside) ?? "");
	}
	const placed = ops.move(next, layout.bundle);
	if (failed(placed)) {
		// Put the previous bundle back where it was; the snapshot covers a failure here.
		if (failed(ops.move(previous, layout.bundle))) ops.copyDir(snapshot, layout.bundle);
		throw new UpdateApplyError("installer_failed", failed(placed) ?? "");
	}
	const hook = join(top, "libexec", "package-hook.sh");
	if (existsSync(hook))
		ops.run("cp", ["--", hook, join(layout.prefix, "libexec", "package-hook.sh")]);
}

/** Restore the snapshot over the installed bundle and check it. */
function restoreSnapshot(options: ApplyOptions, snapshot: string): string | null {
	const { layout, ops } = options;
	const previous = `${layout.bundle}${PREVIOUS_SUFFIX}`;
	const broken = `${layout.bundle}${FAILED_SUFFIX}`;
	ops.remove(broken);
	if (existsSync(layout.bundle)) {
		const aside = failed(ops.move(layout.bundle, broken));
		if (aside) return `could not move the new bundle aside: ${aside}`;
	}
	// The tarball swap kept the previous directory in place; use it, else the copy.
	let restored = existsSync(previous)
		? ops.move(previous, layout.bundle)
		: ops.copyDir(snapshot, layout.bundle);
	if (failed(restored) && existsSync(previous)) restored = ops.copyDir(snapshot, layout.bundle);
	if (failed(restored)) return `could not restore the previous bundle: ${failed(restored)}`;
	ops.remove(broken);
	const check = verifyStandaloneBundle(layout.bundle, {
		trustKeyPath: join(layout.prefix, "config", "release-public.pem"),
		platform: options.platform,
	});
	return check.ok
		? null
		: `the restored bundle failed its check: ${check.problems.slice(0, 3).join("; ")}`;
}

function postInstallProblem(
	options: ApplyOptions,
	before: VerifyReport,
): { problem: string | null; verify: VerifyReport } {
	const { layout, platform } = options;
	const check = verifyStandaloneBundle(layout.bundle, {
		trustKeyPath: join(layout.prefix, "config", "release-public.pem"),
		platform,
	});
	const empty: VerifyReport = { ok: false, hosts: {}, detail: "" };
	if (!check.ok)
		return { problem: `bundle check: ${check.problems.slice(0, 3).join("; ")}`, verify: empty };
	const target = options.targetVersion;
	if (check.version !== target && check.version !== target.replace(/-.*$/u, "")) {
		return { problem: `the installed bundle is v${check.version}, not v${target}`, verify: empty };
	}
	const after = runVerify(aidrBinary(layout.bundle, platform), options.run, options.env);
	if (!after.ok) return { problem: `'aidr verify' did not run: ${after.detail}`, verify: after };
	const failing = newlyFailingHosts(before, after);
	if (failing.length > 0)
		return { problem: `'aidr verify' FAIL for ${failing.join(", ")}`, verify: after };
	return { problem: null, verify: after };
}

/** Why a package transaction that left the installation untouched failed. */
function transactionError(options: ApplyOptions, result: RunResult): UpdateApplyError {
	if (needsElevation(options.kind, result.status)) {
		return new UpdateApplyError("needs_elevation", `msiexec exit ${result.status}`);
	}
	if (options.ops.mode === "sudo" && result.status === 1 && /password|sudo/iu.test(result.stderr)) {
		return new UpdateApplyError("privilege_denied", result.stderr.trim().slice(0, 300));
	}
	return new UpdateApplyError("installer_failed", failed(result) ?? `exit ${result.status}`);
}

/** Put the snapshot back, re-register it and say how that went. */
function rollBack(
	options: ApplyOptions,
	snapshot: string,
	reason: string,
	packageRecordStale: boolean,
): ApplyResult {
	const rollbackError = restoreSnapshot(options, snapshot);
	reregister(options);
	return rollbackError
		? { outcome: "rollback_failed", reason, rollbackError }
		: { outcome: "rolled_back", reason, packageRecordStale };
}

/**
 * Run msiexec / dpkg / rpm. Null when it succeeded; a result when it failed
 * after changing the installation (rolled back). Throws when it failed and the
 * installation is still the snapshot (nothing to roll back).
 */
function runPackageInstaller(
	options: ApplyOptions & { kind: Exclude<InstallKind, "tar"> },
	snapshot: { path: string; manifestSha256: string | null },
	installer: string,
): ApplyResult | null {
	const { layout, platform } = options;
	const { command, args } = installerCommand(options.kind, installer, {
		perUser: layout.perUser,
		allowDowngrade: options.allowDowngrade,
		logFile: join(options.workDir, "msiexec.log"),
		systemRoot: (options.env ?? process.env).SystemRoot,
	});
	options.log?.(`${command} ${args.join(" ")}`);
	const result = options.ops.run(command, args);
	if (installerSucceeded(options.kind, result.status)) return null;
	// A refused or failed package transaction normally leaves the previous
	// version in place; check, and restore the snapshot when it did not.
	const intact = verifyStandaloneBundle(layout.bundle, {
		trustKeyPath: join(layout.prefix, "config", "release-public.pem"),
		platform,
	});
	if (intact.ok && intact.manifestSha256 === snapshot.manifestSha256)
		throw transactionError(options, result);
	return rollBack(
		options,
		snapshot.path,
		`installer: ${failed(result) ?? `exit ${result.status}`}`,
		true,
	);
}

/**
 * Apply a downloaded, digest-verified installer. Throws UpdateApplyError only
 * before anything changed; once the installed bundle may have changed, every
 * failure is answered with a rollback and reported in the result.
 */
export function applyUpdate(options: ApplyOptions): ApplyResult {
	const made = options.ops.makeDir(options.stagingDir);
	if (failed(made)) throw privilegeError(options.ops, made, "installer_failed");
	try {
		return applyStaged(options);
	} finally {
		options.ops.remove(options.stagingDir);
		// The Windows parent folder is not part of the MSI; leave nothing behind.
		const parent = dirname(options.stagingDir);
		if (basename(parent) === "update-staging") attempt(() => rmdirSync(parent));
	}
}

function applyStaged(options: ApplyOptions): ApplyResult {
	const { layout, platform, run, ops } = options;
	const snapshot = snapshotBundle(options);
	const installer = stageInstaller(options);
	const before = runVerify(aidrBinary(layout.bundle, platform), run, options.env);

	if (options.kind === "tar") {
		swapTarball(options, snapshot.path, installer);
	} else {
		const failure = runPackageInstaller({ ...options, kind: options.kind }, snapshot, installer);
		if (failure) return failure;
	}

	const { problem, verify } = postInstallProblem(options, before);
	if (problem) {
		options.log?.(problem);
		return rollBack(options, snapshot.path, problem, options.kind !== "tar");
	}
	if (options.kind === "tar") {
		reregister(options);
		ops.remove(`${layout.bundle}${PREVIOUS_SUFFIX}`);
	}
	return { outcome: "installed", verify };
}

/** Re-run `aidr setup` with the bundle now installed, so registrations point at its manifest. */
function reregister(options: ApplyOptions): void {
	options.run(aidrBinary(options.layout.bundle, options.platform), ["setup"], {
		env: options.env,
		timeoutMs: 10 * 60_000,
	});
}

/** A unique work directory for one update run. */
export function updateWorkDir(root: string, version: string, now = Date.now()): string {
	const dir = join(root, `${basename(version)}-${now}`);
	mkdirSync(dir, { recursive: true, mode: 0o700 });
	return dir;
}
