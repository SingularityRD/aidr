import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
	closeSync,
	constants,
	fchmodSync,
	fstatSync,
	fsyncSync,
	lstatSync,
	mkdirSync,
	openSync,
	readFileSync,
	renameSync,
	type Stats,
	unlinkSync,
	writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { VERSION } from "@singularityrd/aidr-core";
import { generateApiKey } from "./crypto.js";

const CONFIG_DIR = join(homedir(), ".singularity-aidr");
const CONFIG_FILE = join(CONFIG_DIR, "config.json");
const IS_POSIX = process.platform !== "win32";
const NO_FOLLOW = IS_POSIX ? constants.O_NOFOLLOW : 0;
const WINDOWS_PRIVATE_ACL = `
$ErrorActionPreference = 'Stop'
$path = [Environment]::GetEnvironmentVariable('AIDR_PRIVATE_ACL_PATH')
$directory = [Environment]::GetEnvironmentVariable('AIDR_PRIVATE_ACL_DIRECTORY') -eq '1'
$item = if ($directory) { [System.IO.DirectoryInfo]::new($path) } else { [System.IO.FileInfo]::new($path) }
$acl = $item.GetAccessControl()
$owner = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$system = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$administrators = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$acl.SetAccessRuleProtection($true, $false)
foreach ($entry in @($acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))) {
  $acl.PurgeAccessRules($entry.IdentityReference)
}
$inheritance = if ($directory) {
  [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
} else {
  [System.Security.AccessControl.InheritanceFlags]::None
}
foreach ($sid in @($owner, $system, $administrators)) {
  $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
    $sid,
    [System.Security.AccessControl.FileSystemRights]::FullControl,
    $inheritance,
    [System.Security.AccessControl.PropagationFlags]::None,
    [System.Security.AccessControl.AccessControlType]::Allow
  )
  $acl.AddAccessRule($rule)
}
$item.SetAccessControl($acl)
$updated = $item.GetAccessControl()
if (-not $updated.AreAccessRulesProtected) { throw 'ACL inheritance remains enabled' }
foreach ($entry in $updated.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
  if ($entry.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
      $entry.IdentityReference.Value -notin @($owner.Value, $system.Value, $administrators.Value)) {
    throw 'ACL grants another identity access'
  }
}
`;

export interface Environment {
	agent: "claude" | "cursor" | "vscode" | "openclaw" | "unknown";
	hasNode: boolean;
	nodeVersion: string;
	projectRoot: string;
}

export interface Config {
	apiKey: string;
	environment: Environment;
	version: string;
	createdAt: string;
	hooksInstalled: boolean;
	agentConfigured: boolean;
}

export interface ConfigCreationResult {
	path: string;
	/** "created" wrote a new config; "reused" kept the existing one. */
	outcome: "created" | "reused";
}

function lstatIfPresent(path: string): Stats | null {
	try {
		return lstatSync(path);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
		throw error;
	}
}

function sameFile(a: Stats, b: Stats): boolean {
	return a.dev === b.dev && a.ino === b.ino;
}

function assertOwner(stats: Stats): void {
	if (IS_POSIX && process.getuid && stats.uid !== process.getuid()) {
		throw new Error("Local config is not owned by the current user.");
	}
}

function hardenWindowsAcl(path: string, before: Stats, directory: boolean): Stats {
	const result = spawnSync(
		"powershell.exe",
		["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(WINDOWS_PRIVATE_ACL, "utf16le").toString("base64")],
		{
			env: {
				...process.env,
				AIDR_PRIVATE_ACL_PATH: path,
				AIDR_PRIVATE_ACL_DIRECTORY: directory ? "1" : "0",
			},
			encoding: "utf8",
			timeout: 30_000,
			windowsHide: true,
		},
	);
	if (result.error || result.status !== 0) {
		throw new Error("Local config Windows ACL could not be made private.");
	}
	const after = lstatIfPresent(path);
	if (!after || after.isSymbolicLink() || !sameFile(before, after) || directory !== after.isDirectory()) {
		throw new Error("Local config changed during Windows ACL update.");
	}
	return after;
}

function ensureConfigDirectory(create: boolean): Stats | null {
	let before = lstatIfPresent(CONFIG_DIR);
	if (!before && create) {
		createConfigDirectory();
		before = lstatIfPresent(CONFIG_DIR);
	}
	if (!before) return null;
	if (before.isSymbolicLink() || !before.isDirectory()) {
		throw new Error("Local config directory is not a regular directory.");
	}
	assertOwner(before);
	if (IS_POSIX) return hardenPosixDirectory(before);
	return create ? hardenWindowsAcl(CONFIG_DIR, before, true) : before;
}

function createConfigDirectory(): void {
	try {
		mkdirSync(CONFIG_DIR, { mode: 0o700 });
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
	}
}

function hardenPosixDirectory(before: Stats): Stats {
	// Use a descriptor for permission repair so chmod cannot follow a swapped link.
	const fd = openSync(CONFIG_DIR, constants.O_RDONLY | constants.O_DIRECTORY | NO_FOLLOW);
	try {
		let opened = fstatSync(fd);
		if (!opened.isDirectory() || !sameFile(before, opened)) {
			throw new Error("Local config directory changed during access.");
		}
		assertOwner(opened);
		if ((opened.mode & 0o077) !== 0) fchmodSync(fd, 0o700);
		opened = fstatSync(fd);
		if ((opened.mode & 0o077) !== 0) {
			throw new Error("Local config directory permissions are unsafe.");
		}
		const after = lstatIfPresent(CONFIG_DIR);
		if (!after || after.isSymbolicLink() || !sameFile(after, opened)) {
			throw new Error("Local config directory changed during access.");
		}
		return opened;
	} finally {
		closeSync(fd);
	}
}

function serializeConfig(config: Config): string {
	try {
		return JSON.stringify(config, null, 2);
	} catch {
		throw new Error("Local config cannot be serialized.");
	}
}

function mayReplaceConfig(directory: Stats, expected: Stats | null): boolean {
	const currentDirectory = ensureConfigDirectory(false);
	if (!currentDirectory || !sameFile(directory, currentDirectory)) {
		throw new Error("Local config directory changed during update.");
	}
	const current = openConfigFile();
	const currentStats = current?.stats ?? null;
	if (current) closeSync(current.fd);
	if (!expected && currentStats) return false;
	if (expected && (!currentStats || !sameFile(expected, currentStats))) {
		throw new Error("Local config changed during update.");
	}
	return true;
}

function discardTemporary(path: string): void {
	try {
		unlinkSync(path);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
	}
}

function openConfigFile(): { fd: number; stats: Stats } | null {
	const before = lstatIfPresent(CONFIG_FILE);
	if (!before) return null;
	if (before.isSymbolicLink() || !before.isFile() || before.nlink !== 1) {
		throw new Error("Local config is not a regular private file.");
	}
	assertOwner(before);
	const fd = openSync(CONFIG_FILE, constants.O_RDONLY | constants.O_NONBLOCK | NO_FOLLOW);
	try {
		let opened = fstatSync(fd);
		if (!opened.isFile() || opened.nlink !== 1 || !sameFile(before, opened)) {
			throw new Error("Local config changed during access.");
		}
		assertOwner(opened);
		if (IS_POSIX && (opened.mode & 0o077) !== 0) fchmodSync(fd, 0o600);
		opened = fstatSync(fd);
		if (IS_POSIX && (opened.mode & 0o077) !== 0) {
			throw new Error("Local config permissions are unsafe.");
		}
		const after = lstatIfPresent(CONFIG_FILE);
		if (!after || after.isSymbolicLink() || !sameFile(after, opened)) {
			throw new Error("Local config changed during access.");
		}
		return { fd, stats: opened };
	} catch (error) {
		closeSync(fd);
		throw error;
	}
}

function readConfig(): { config: Config; stats: Stats } | null {
	if (!ensureConfigDirectory(false)) return null;
	const opened = openConfigFile();
	if (!opened) return null;
	try {
		let parsed: unknown;
		try {
			parsed = JSON.parse(readFileSync(opened.fd, "utf8"));
		} catch {
			// JSON.parse errors can include source snippets containing credentials.
			throw new Error("Local config is invalid.");
		}
		if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
			throw new Error("Local config is invalid.");
		}
		return { config: parsed as Config, stats: opened.stats };
	} finally {
		closeSync(opened.fd);
	}
}

function writeConfigAtomically(config: Config, expected: Stats | null, securedDirectory?: Stats): boolean {
	const directory = securedDirectory ?? ensureConfigDirectory(true);
	if (!directory) throw new Error("Local config directory is unavailable.");
	const serialized = serializeConfig(config);
	const temporary = join(CONFIG_DIR, `.config-${randomBytes(16).toString("hex")}.tmp`);
	let fd: number | null = null;
	try {
		fd = openSync(
			temporary,
			constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | NO_FOLLOW,
			0o600,
		);
		const created = fstatSync(fd);
		assertOwner(created);
		if (!created.isFile() || created.nlink !== 1 || (IS_POSIX && (created.mode & 0o077) !== 0)) {
			throw new Error("Local config temporary file is unsafe.");
		}
		writeFileSync(fd, serialized, "utf8");
		fsyncSync(fd);
		closeSync(fd);
		fd = null;

		if (!mayReplaceConfig(directory, expected)) return false;
		renameSync(temporary, CONFIG_FILE);
		return true;
	} finally {
		if (fd !== null) closeSync(fd);
		discardTemporary(temporary);
	}
}

export async function createConfig(
	env: Environment,
	force: boolean,
): Promise<ConfigCreationResult> {
	const directory = ensureConfigDirectory(true);
	const existing = openConfigFile();
	const expected = existing?.stats ?? null;
	if (existing) closeSync(existing.fd);
	if (existing && !force) {
		if (!IS_POSIX) hardenWindowsAcl(CONFIG_FILE, existing.stats, false);
		return { path: CONFIG_FILE, outcome: "reused" };
	}

	const config: Config = {
		apiKey: generateApiKey(),
		environment: env,
		version: VERSION,
		createdAt: new Date().toISOString(),
		hooksInstalled: false,
		agentConfigured: false,
	};
	const written = writeConfigAtomically(config, expected, directory ?? undefined);
	return { path: CONFIG_FILE, outcome: written ? "created" : "reused" };
}

export function getConfig(): Config | null {
	return readConfig()?.config ?? null;
}

export function updateConfig(updates: Partial<Config>): void {
	const existing = readConfig();
	if (!existing) throw new Error("Config not found. Run 'aidr setup' first.");
	writeConfigAtomically({ ...existing.config, ...updates }, existing.stats);
}
