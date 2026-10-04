import { spawnSync } from "node:child_process";
import {
	closeSync,
	constants,
	fchmodSync,
	fstatSync,
	lstatSync,
	mkdirSync,
	openSync,
	type Stats,
} from "node:fs";
import { dirname } from "node:path";
import { windowsTargetsAreAlreadyPrivate } from "./windows-private-acl-probe.js";

const PRIVATE_DIRECTORY_MODE = 0o700;
const PRIVATE_FILE_MODE = 0o600;

// Node's mode/chmod do not protect NTFS files from inherited read ACLs.
//
// Starting powershell.exe costs hundreds of milliseconds (more under load) and a
// hook is a new process per tool call, so every call that blocks a tool pays it
// for its audit log. All paths prepared by one call are therefore hardened in a
// single PowerShell process instead of one process per path.
const WINDOWS_PRIVATE_ACL = `
$ErrorActionPreference = 'Stop'
$targets = ([Environment]::GetEnvironmentVariable('AIDR_PRIVATE_ACL_TARGETS') -split "\\n") | Where-Object { $_ -ne '' }
$owner = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$system = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$administrators = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
foreach ($target in $targets) {
$directory = $target.StartsWith('D|')
$path = $target.Substring(2)
$item = if ($directory) { [System.IO.DirectoryInfo]::new($path) } else { [System.IO.FileInfo]::new($path) }
$acl = $item.GetAccessControl()
$actualOwner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier])
if ($actualOwner.Value -ne $owner.Value) { throw 'Path is not owned by the current user' }
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
if ($updated.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne $owner.Value) { throw 'Path owner changed during ACL update' }
foreach ($entry in $updated.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
  if ($entry.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
      $entry.IdentityReference.Value -notin @($owner.Value, $system.Value, $administrators.Value)) {
    throw 'ACL grants another identity access'
  }
}
}
`;

interface AclTarget {
	path: string;
	directory: boolean;
}

function assertRegularTarget(target: AclTarget): Stats {
	const before = lstatSync(target.path);
	if (before.isSymbolicLink() || (target.directory ? !before.isDirectory() : !before.isFile())) {
		throw new Error("Local metrics/log path is not a regular file or directory.");
	}
	return before;
}

/** Make every target private to the current user, SYSTEM and Administrators. */
function hardenWindowsAcls(targets: AclTarget[]): void {
	const identities = targets.map((target) => assertRegularTarget(target));
	// Already private (verified read-only, fail-closed): skip the slow PowerShell run.
	if (windowsTargetsAreAlreadyPrivate(targets)) return;
	const result = spawnSync(
		"powershell.exe",
		[
			"-NoProfile",
			"-NonInteractive",
			"-EncodedCommand",
			Buffer.from(WINDOWS_PRIVATE_ACL, "utf16le").toString("base64"),
		],
		{
			env: {
				...process.env,
				// One "D|<path>" (directory) or "F|<path>" (file) per line.
				AIDR_PRIVATE_ACL_TARGETS: targets
					.map((target) => `${target.directory ? "D" : "F"}|${target.path}`)
					.join("\n"),
			},
			encoding: "utf8",
			timeout: 30_000,
			windowsHide: true,
		},
	);
	if (result.error || result.status !== 0) {
		throw new Error("Local metrics/log Windows ACL could not be made private.");
	}
	targets.forEach((target, index) => {
		const before = identities[index] as Stats;
		const after = lstatSync(target.path);
		if (after.isSymbolicLink() || after.dev !== before.dev || after.ino !== before.ino) {
			throw new Error("Local metrics/log path changed during ACL update.");
		}
	});
}

function sameFile(a: Stats, b: Stats): boolean {
	return a.dev === b.dev && a.ino === b.ino;
}

/** Create or repair a private directory without changing a different owner's path. */
export function preparePrivateLocalDirectory(path: string): void {
	prepareDirectory(path, false);
}

/**
 * `deferWindowsAcl` lets the caller harden this directory together with other
 * paths in one PowerShell process (see `hardenWindowsAcls`).
 */
function prepareDirectory(path: string, deferWindowsAcl: boolean): void {
	mkdirSync(path, { recursive: true, mode: PRIVATE_DIRECTORY_MODE });
	const before = lstatSync(path);
	if (before.isSymbolicLink() || !before.isDirectory()) {
		throw new Error("Local private path is not a regular directory.");
	}

	if (process.platform === "win32") {
		if (!deferWindowsAcl) hardenWindowsAcls([{ path, directory: true }]);
		return;
	}
	if (typeof process.getuid !== "function" || before.uid !== process.getuid()) {
		throw new Error("Local private directory is not owned by the current user.");
	}

	const noFollow = constants.O_NOFOLLOW ?? 0;
	const directoryOnly = constants.O_DIRECTORY ?? 0;
	const handle = openSync(path, constants.O_RDONLY | directoryOnly | noFollow);
	try {
		let opened = fstatSync(handle);
		if (!opened.isDirectory() || !sameFile(before, opened) || opened.uid !== process.getuid()) {
			throw new Error("Local private directory changed during permission repair.");
		}
		if ((opened.mode & 0o077) !== 0) fchmodSync(handle, PRIVATE_DIRECTORY_MODE);
		opened = fstatSync(handle);
		const after = lstatSync(path);
		if (
			(opened.mode & 0o077) !== 0 ||
			!sameFile(opened, after) ||
			after.isSymbolicLink() ||
			!after.isDirectory()
		) {
			throw new Error("Local private directory permissions are unsafe.");
		}
	} finally {
		closeSync(handle);
	}
}

/** Prepare an append-only local output before any metrics or logs are written. */
export function preparePrivateLocalFile(path: string): void {
	const directory = dirname(path);
	prepareDirectory(directory, true);

	try {
		const existing = lstatSync(path);
		if (existing.isSymbolicLink() || !existing.isFile()) {
			throw new Error("Local metrics/log path is not a regular file.");
		}
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
	}
	const handle = openSync(path, "a", PRIVATE_FILE_MODE);
	try {
		if (!fstatSync(handle).isFile())
			throw new Error("Local metrics/log path is not a regular file.");
		if (process.platform !== "win32") fchmodSync(handle, PRIVATE_FILE_MODE);
	} finally {
		closeSync(handle);
	}
	// Directory first, then file: the same order as hardening them separately.
	if (process.platform === "win32") {
		hardenWindowsAcls([
			{ path: directory, directory: true },
			{ path, directory: false },
		]);
	}
}
