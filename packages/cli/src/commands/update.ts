import { closeSync, mkdirSync, openSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
	CATALOG_KEY_FILE,
	type Config,
	checkInstallerUpdate,
	detectMdmManaged,
	downloadVerified,
	effectiveAutoMode,
	escapeTerminalText,
	type InstallerCatalogFile,
	type InstallerLayout,
	type InstallerPlatform,
	installerLayoutFor,
	installerLocation,
	installerPlatform,
	loadConfig,
	type MdmStatus,
	readUpdateState,
	resolveManagedApiKey,
	resolvePath,
	resolveUpdateSource,
	type TrustedCatalogKeys,
	trustedCatalogKeys,
	type UpdateCheck,
	type UpdateEnvironmentDeps,
	type UpdateSource,
	VERSION,
	writeUpdateState,
} from "@singularityrd/aidr-core";
import { type UpdateMessageKey, ut } from "../i18n/index.js";
import {
	confirmOperatorAction,
	type OperatorCommandDeps,
	OperatorConfirmationError,
} from "../utils/operator-confirm.js";
import { standaloneBundleRoot } from "../utils/standalone.js";
import {
	type ApplyResult,
	applyUpdate,
	type CommandRunner,
	detectInstallKind,
	formatMatches,
	type InstallKind,
	installerFormats,
	privilegedOps,
	runCommand,
	stagingDirFor,
	UpdateApplyError,
	updateWorkDir,
} from "../utils/update-installer.js";

/**
 * `aidr update`: update an endpoint installed with the Windows or Linux
 * desktop installers (docs/installation/desktop-installers.md#updating).
 *
 * 1. Source: `--from <file|dir|https-url>`; else the tenant's portal through
 *    the managed API key (installer-update Edge Function); else update.source.
 * 2. The signed catalog must verify with the pinned installer-catalog key and
 *    the installer bytes must match its SHA-256 and size, before anything runs.
 *    The installer is the one in the format this machine was installed with
 *    (.msi, .deb, .rpm or the .tar.gz bundle); a catalog without that format is
 *    refused with what it does offer.
 * 3. A lower version is refused unless --allow-downgrade.
 * 4. The platform installer runs silently; the new version must pass the
 *    bundle check and `aidr verify`, or the previous bundle is put back.
 *
 * Installing changes the protection binaries, so a manual install needs the
 * operator's confirmation (a terminal, or --yes with
 * AIDR_OPERATOR_NONINTERACTIVE=1). `--auto` is the background path started by
 * the session-start notice when update.auto is `install`: it only ever
 * installs a newer, verified version from the configured source.
 */

export interface UpdateOptions {
	check?: boolean;
	from?: string;
	catalog?: string;
	allowDowngrade?: boolean;
	yes?: boolean;
	auto?: boolean;
	json?: boolean;
}

export interface UpdateDeps extends OperatorCommandDeps {
	config?: Config;
	configPath?: string;
	/** The running `aidr` executable; default: process.execPath inside a standalone bundle. */
	executable?: string | null;
	currentVersion?: string;
	platform?: NodeJS.Platform;
	arch?: string;
	environment?: Omit<UpdateEnvironmentDeps, "platform" | "arch" | "env">;
	fetch?: typeof fetch;
	/** The managed API key; default: resolved from the configuration and managed state. */
	apiKey?: string | null;
	run?: CommandRunner;
	/** How AIDR was installed (default: detected from the package databases). */
	installKind?: InstallKind;
	/** Where downloads, the fallback copy and the lock go (default ~/.singularity-aidr/updates). */
	workRoot?: string;
	statePath?: string;
	isRoot?: boolean;
	/** How privileged steps run (default: direct on Windows or as root, sudo otherwise). */
	privileged?: "direct" | "sudo";
	out?: (line: string) => void;
	err?: (line: string) => void;
	now?: () => number;
}

const LOCK_STALE_MS = 2 * 60 * 60_000;

function sourceLabel(source: UpdateSource): string {
	if (source.kind === "portal") return ut("update.sourcePortal", { endpoint: source.endpoint });
	return source.kind === "mirror" ? source.location : source.installer;
}

function withDetail(detail: string | undefined, status?: number): string {
	const parts = [status ? `HTTP ${status}` : "", detail ?? ""].filter(Boolean).join(", ");
	return parts ? ` (${escapeTerminalText(parts).slice(0, 300)})` : "";
}

function checkError(check: Extract<UpdateCheck, { ok: false }>): string {
	const key = `update.error.${check.error}` as UpdateMessageKey;
	const detail =
		check.error === "installer_not_in_catalog"
			? escapeTerminalText(check.detail ?? "")
			: withDetail(check.detail, check.status);
	const message = ut(key, { detail });
	return message === key
		? ut("update.error.server_error", { detail: withDetail(check.error) })
		: message;
}

function takeLock(path: string, now: number): boolean {
	try {
		closeSync(openSync(path, "wx", 0o600));
		return true;
	} catch {
		try {
			if (now - statSync(path).mtimeMs < LOCK_STALE_MS) return false;
			writeFileSync(path, "", { mode: 0o600 });
			return true;
		} catch {
			return false;
		}
	}
}

/** Everything one run needs, resolved once. */
interface UpdateRun {
	options: UpdateOptions;
	deps: UpdateDeps;
	auto: boolean;
	out: (line: string) => void;
	err: (line: string) => void;
	fail: (message: string) => void;
	config: Config;
	platformName: NodeJS.Platform;
	platform: InstallerPlatform;
	layout: InstallerLayout;
	mdm: MdmStatus;
	isRoot: boolean;
	run: CommandRunner;
	/** How AIDR was installed here; picks the installer format. */
	kind: InstallKind;
	now: () => number;
	currentVersion: string;
	source: UpdateSource;
	keys: TrustedCatalogKeys;
}

type AvailableCheck = Extract<UpdateCheck, { ok: true }> & { file: InstallerCatalogFile };

const APPLY_ERROR_MESSAGE: Record<UpdateApplyError["code"], UpdateMessageKey> = {
	snapshot_invalid: "update.snapshotInvalid",
	staged_bundle_invalid: "update.stagedInvalid",
	tar_invalid: "update.tarInvalid",
	needs_elevation: "update.needsElevation",
	privilege_denied: "update.privilegeDenied",
	installer_failed: "update.installerFailed",
};

function runningExecutable(deps: UpdateDeps): string | null {
	if (deps.executable !== undefined) return deps.executable;
	return standaloneBundleRoot() ? process.execPath : null;
}

/** `error` is the machine-readable reason `aidr update --check --json` reports. */
type Resolved<T> = { ok: true; value: T } | { ok: false; error: string; message: string };

/** This machine's installer platform and installation layout. */
function resolveTarget(
	deps: UpdateDeps,
	environment: UpdateEnvironmentDeps,
): Resolved<{ platform: InstallerPlatform; layout: InstallerLayout }> {
	const platformName = environment.platform ?? process.platform;
	const arch = environment.arch ?? process.arch;
	const platform = installerPlatform(platformName, arch);
	if (!platform) {
		return {
			ok: false,
			error: "unsupported_platform",
			message: ut("update.unsupportedPlatform", { platform: platformName, arch }),
		};
	}
	const executable = runningExecutable(deps);
	const layout = executable ? installerLayoutFor(executable, environment) : null;
	return layout
		? { ok: true, value: { platform, layout } }
		: { ok: false, error: "not_installer_install", message: ut("update.notInstaller") };
}

/** Why this machine must not install, or null. */
function installBlocker(
	mdm: MdmStatus,
	platformName: NodeJS.Platform,
	isRoot: boolean,
): string | null {
	if (mdm.managed) return ut("update.mdm", { source: mdm.source ?? "" });
	return platformName === "linux" && isRoot ? ut("update.linuxRoot") : null;
}

function resolveKeys(
	layout: InstallerLayout,
	config: Config,
	environment: UpdateEnvironmentDeps,
): Resolved<TrustedCatalogKeys> {
	const keys = trustedCatalogKeys(layout, config.update.catalog_public_keys, environment);
	if (keys.invalid.length > 0) {
		return {
			ok: false,
			error: "catalog_key_invalid",
			message: ut("update.keyInvalid", { source: keys.invalid.join(", ") }),
		};
	}
	if (keys.keys.length === 0) {
		const path = join(layout.prefix, "config", CATALOG_KEY_FILE);
		return { ok: false, error: "catalog_key_missing", message: ut("update.noKey", { path }) };
	}
	return { ok: true, value: keys };
}

async function resolveSource(
	options: UpdateOptions,
	deps: UpdateDeps,
	config: Config,
): Promise<UpdateSource | null> {
	const apiKey =
		deps.apiKey !== undefined ? (deps.apiKey ?? undefined) : await resolveManagedApiKey(config);
	const source = resolveUpdateSource(config, apiKey, options.from);
	return source?.kind === "file" && options.catalog
		? { ...source, catalog: options.catalog }
		: source;
}

/** The background path installs only a newer verified version from the configured source. */
function autoDeclines(options: UpdateOptions, config: Config, mdm: MdmStatus): boolean {
	if (effectiveAutoMode(config.update.auto, mdm).mode !== "install") return true;
	return Boolean(options.from || options.allowDowngrade || options.check);
}

/** Output channels; the background path prints nothing but still sets the exit code. */
function outputs(deps: UpdateDeps, auto: boolean) {
	const out = deps.out ?? ((line: string) => console.log(line));
	const err = deps.err ?? ((line: string) => console.error(line));
	const fail = (message: string): null => {
		if (!auto) err(message);
		process.exitCode = 1;
		return null;
	};
	return { out, err, fail };
}

function environmentFor(deps: UpdateDeps): UpdateEnvironmentDeps & { platform: NodeJS.Platform } {
	return {
		...deps.environment,
		platform: deps.platform ?? process.platform,
		arch: deps.arch ?? process.arch,
		env: deps.env ?? process.env,
	};
}

/** Resolve the run, or report why there is nothing to do (null). */
async function prepare(options: UpdateOptions, deps: UpdateDeps): Promise<UpdateRun | null> {
	const auto = options.auto === true;
	const { out, err, fail } = outputs(deps, auto);
	// `--check --json` stays machine-readable when the check cannot even start.
	const refuse = (error: string, message: string): null => {
		if (!(options.check && options.json) || auto) return fail(message);
		out(
			JSON.stringify(
				{
					schema_version: 1,
					status: "error",
					error,
					message,
					current: deps.currentVersion ?? VERSION,
				},
				null,
				2,
			),
		);
		process.exitCode = 1;
		return null;
	};
	const environment = environmentFor(deps);
	const platformName = environment.platform;
	const config = deps.config ?? (await loadConfig(deps.configPath));
	const target = resolveTarget(deps, environment);
	if (!target.ok) return refuse(target.error, target.message);
	const { platform, layout } = target.value;
	const mdm = detectMdmManaged(environment);
	if (auto && autoDeclines(options, config, mdm)) return null;
	const isRoot = deps.isRoot ?? process.getuid?.() === 0;
	const blocker = options.check ? null : installBlocker(mdm, platformName, isRoot);
	if (blocker) return fail(blocker);
	const keys = resolveKeys(layout, config, environment);
	if (!keys.ok) return refuse(keys.error, keys.message);
	const source = await resolveSource(options, deps, config);
	if (!source) return refuse("no_source", ut("update.noSource"));
	const run = deps.run ?? runCommand;
	return {
		options,
		deps,
		auto,
		out,
		err,
		fail,
		config,
		platformName,
		platform,
		layout,
		mdm,
		isRoot,
		run,
		kind: deps.installKind ?? detectInstallKind(layout, platformName, run),
		now: deps.now ?? Date.now,
		currentVersion: deps.currentVersion ?? VERSION,
		source,
		keys: keys.value,
	};
}

function recordCheck(ctx: UpdateRun, check: UpdateCheck): void {
	const previous = readUpdateState(ctx.deps.statePath);
	writeUpdateState(
		{
			checked_at: new Date(ctx.now()).toISOString(),
			current: ctx.currentVersion,
			latest: check.ok ? check.latest : null,
			status: check.ok ? (check.file ? check.status : "up_to_date") : "error",
			...(previous?.install_attempted_at
				? { install_attempted_at: previous.install_attempted_at }
				: {}),
		},
		ctx.deps.statePath,
	);
}

/** `.msi`, `.deb`, `.rpm` or `.tar.gz`: how a kind of installation is named to the user. */
function kindLabel(kind: InstallKind): string {
	return kind === "tar" ? ".tar.gz" : `.${kind}`;
}

function checkJson(ctx: UpdateRun, check: UpdateCheck): Record<string, unknown> {
	if (!check.ok) {
		return { schema_version: 1, status: "error", error: check.error, current: ctx.currentVersion };
	}
	const { file } = check;
	const missing =
		check.platformFiles.length > 0 ? "no_installer_for_format" : "no_installer_for_platform";
	return {
		schema_version: 1,
		status: file ? check.status : missing,
		current: check.current,
		latest: check.latest,
		platform: ctx.platform,
		install_kind: ctx.kind,
		available_formats: check.platformFiles.map((entry) => entry.format),
		installer: file
			? { file: file.file, size: file.size, sha256: file.sha256, format: file.format }
			: null,
		release_notes_url: check.catalog.release_notes_url,
		mdm_managed: ctx.mdm.managed,
		auto: effectiveAutoMode(ctx.config.update.auto, ctx.mdm).mode,
	};
}

function releaseNotes(check: AvailableCheck): string | null {
	const url = check.catalog.release_notes_url;
	return url ? ut("update.releaseNotes", { url: escapeTerminalText(url) }) : null;
}

/** `aidr update --check` in words. */
function reportCheck(ctx: UpdateRun, check: AvailableCheck): void {
	const versions = { current: check.current, latest: check.latest };
	if (check.status === "available") {
		ctx.out(ut("update.available", versions));
		const notes = releaseNotes(check);
		if (notes) ctx.out(notes);
	} else {
		ctx.out(
			check.status === "older"
				? ut("update.older", versions)
				: ut("update.upToDate", { current: check.current }),
		);
	}
	if (ctx.mdm.managed) ctx.out(ut("update.mdmAuto", { source: ctx.mdm.source ?? "" }));
	else if (ctx.config.update.auto === "off") ctx.out(ut("update.autoOff"));
}

async function confirmed(ctx: UpdateRun, check: AvailableCheck): Promise<boolean> {
	if (ctx.auto) return true;
	const notes = releaseNotes(check);
	if (notes) ctx.out(notes);
	try {
		await confirmOperatorAction({
			prompt: ut("update.confirmPrompt", { current: check.current, latest: check.latest }),
			word: "update",
			yes: ctx.options.yes,
			env: ctx.deps.env,
			streams: ctx.deps.streams,
		});
		return true;
	} catch (error) {
		const reason = error instanceof OperatorConfirmationError ? error.message : String(error);
		ctx.fail(ut("update.notConfirmed", { reason }));
		return false;
	}
}

/** Say what happened; true when the msiexec log is worth keeping. */
function reportApply(
	ctx: UpdateRun,
	check: AvailableCheck,
	result: ApplyResult,
	kind: InstallKind,
): boolean {
	if (result.outcome === "installed") {
		if (!ctx.auto) ctx.out(ut("update.done", { latest: check.latest }));
		writeUpdateState(
			{
				checked_at: new Date(ctx.now()).toISOString(),
				current: check.latest,
				latest: check.latest,
				status: "up_to_date",
			},
			ctx.deps.statePath,
		);
		return false;
	}
	const reason = escapeTerminalText(result.reason).slice(0, 300);
	if (result.outcome === "rolled_back") {
		ctx.fail(ut("update.rolledBack", { reason, current: check.current }));
		if (result.packageRecordStale && !ctx.auto) {
			ctx.err(ut("update.rolledBackPackage", { latest: check.latest, current: check.current }));
		}
		return kind === "msi";
	}
	// A failed restore must reach the user even from the background path.
	ctx.err(
		ut("update.rollbackFailed", {
			reason,
			current: check.current,
			detail: escapeTerminalText(result.rollbackError).slice(0, 300),
		}),
	);
	process.exitCode = 1;
	return kind === "msi";
}

/** Download, verify and apply; true when the msiexec log is worth keeping. */
async function downloadAndApply(
	ctx: UpdateRun,
	check: AvailableCheck,
	kind: InstallKind,
	workDir: string,
): Promise<boolean> {
	const { file } = check;
	const location = await installerLocation(ctx.source, check.catalog, file, {
		fetch: ctx.deps.fetch,
	});
	if (!location.ok) {
		ctx.fail(checkError(location));
		return false;
	}
	if (!ctx.auto) {
		ctx.out(
			ut("update.downloading", { file: file.file, size: (file.size / 1_048_576).toFixed(1) }),
		);
	}
	const downloaded = await downloadVerified(location.location, file, join(workDir, file.file), {
		fetch: ctx.deps.fetch,
		allowInsecureLoopback: ctx.source.allowInsecureLoopback,
	});
	if (!downloaded.ok) {
		ctx.fail(checkError(downloaded));
		return false;
	}
	if (!ctx.auto) {
		ctx.out(ut("update.verified", { sha256: file.sha256 }));
		ctx.out(ut("update.installing", { latest: check.latest, kind }));
	}
	const direct = ctx.platformName === "win32" || ctx.isRoot;
	const ops = privilegedOps(ctx.deps.privileged ?? (direct ? "direct" : "sudo"), ctx.run, {
		nonInteractive: ctx.auto,
	});
	try {
		const result = applyUpdate({
			kind,
			layout: ctx.layout,
			installer: downloaded.path,
			file,
			targetVersion: check.latest,
			allowDowngrade: ctx.options.allowDowngrade === true,
			workDir,
			stagingDir: stagingDirFor({
				mode: ops.mode,
				platform: ctx.platformName,
				isRoot: ctx.isRoot,
				layout: ctx.layout,
				workDir,
				now: ctx.now(),
			}),
			platform: ctx.platformName,
			ops,
			run: ctx.run,
			env: ctx.deps.env,
		});
		return reportApply(ctx, check, result, kind);
	} catch (error) {
		if (!(error instanceof UpdateApplyError)) throw error;
		ctx.fail(
			ut(APPLY_ERROR_MESSAGE[error.code], {
				detail: escapeTerminalText(error.message).slice(0, 300),
			}),
		);
		return error.code === "installer_failed" && kind === "msi";
	}
}

/**
 * How this machine was installed, when the chosen installer can update it. The
 * catalog file already matches it, except for an installer the administrator
 * provides with --from.
 */
function installKindFor(ctx: UpdateRun, file: InstallerCatalogFile): InstallKind | null {
	if (formatMatches(ctx.kind, file.format)) return ctx.kind;
	ctx.fail(ut("update.formatMismatch", { format: `.${file.format}`, kind: kindLabel(ctx.kind) }));
	return null;
}

/** Why the catalog has nothing to install here: no installer for the platform, or not in this format. */
function missingInstaller(ctx: UpdateRun, check: Extract<UpdateCheck, { ok: true }>): string {
	if (check.platformFiles.length === 0) {
		return ut("update.noInstallerForPlatform", { latest: check.latest, platform: ctx.platform });
	}
	return ut("update.formatUnavailable", {
		latest: check.latest,
		platform: ctx.platform,
		kind: kindLabel(ctx.kind),
		offered: check.platformFiles.map((entry) => `.${entry.format} (${entry.file})`).join(", "),
	});
}

async function install(ctx: UpdateRun, check: AvailableCheck): Promise<void> {
	if (check.status === "up_to_date") {
		if (!ctx.auto) ctx.out(ut("update.upToDate", { current: check.current }));
		return;
	}
	if (check.status === "older" && (ctx.auto || !ctx.options.allowDowngrade)) {
		ctx.fail(ut("update.downgradeRefused", { current: check.current, latest: check.latest }));
		return;
	}
	const kind = installKindFor(ctx, check.file);
	if (!kind) return;
	if (!(await confirmed(ctx, check))) return;

	const workRoot = ctx.deps.workRoot ?? resolvePath("~/.singularity-aidr/updates");
	mkdirSync(workRoot, { recursive: true, mode: 0o700 });
	const lock = join(workRoot, "update.lock");
	if (!takeLock(lock, ctx.now())) {
		ctx.fail(ut("update.lockBusy"));
		return;
	}
	const workDir = updateWorkDir(workRoot, check.latest, ctx.now());
	let keepLog = false;
	try {
		keepLog = await downloadAndApply(ctx, check, kind, workDir);
	} finally {
		// The installer and the fallback copy are large; the msiexec log of a failed
		// Windows install is kept for the administrator.
		if (keepLog) {
			rmSync(join(workDir, "rollback"), { recursive: true, force: true });
			rmSync(join(workDir, check.file.file), { force: true });
		} else {
			rmSync(workDir, { recursive: true, force: true });
		}
		rmSync(lock, { force: true });
	}
}

export default async function updateCommand(
	options: UpdateOptions = {},
	deps: UpdateDeps = {},
): Promise<void> {
	const ctx = await prepare(options, deps);
	if (!ctx) return;
	if (!options.json && !ctx.auto) {
		ctx.out(ut("update.checking", { source: escapeTerminalText(sourceLabel(ctx.source)) }));
	}
	const check = await checkInstallerUpdate({
		currentVersion: ctx.currentVersion,
		platform: ctx.platform,
		source: ctx.source,
		keys: ctx.keys.keys,
		formats: installerFormats(ctx.kind),
		deps: { fetch: deps.fetch },
	});
	recordCheck(ctx, check);
	if (options.json && options.check) {
		ctx.out(JSON.stringify(checkJson(ctx, check), null, 2));
		if (!check.ok) process.exitCode = 1;
		return;
	}
	if (!check.ok) return ctx.fail(checkError(check));
	if (!check.file) return ctx.fail(escapeTerminalText(missingInstaller(ctx, check)));
	const available: AvailableCheck = { ...check, file: check.file };
	if (options.check) return reportCheck(ctx, available);
	await install(ctx, available);
}
