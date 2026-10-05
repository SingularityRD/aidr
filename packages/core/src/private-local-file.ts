import { spawnSync } from "node:child_process";
import {
	closeSync,
	constants,
	existsSync,
	fchmodSync,
	fstatSync,
	lstatSync,
	mkdirSync,
	mkdtempSync,
	openSync,
	readFileSync,
	rmSync,
	type Stats,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";

const PRIVATE_DIRECTORY_MODE = 0o700;
const PRIVATE_FILE_MODE = 0o600;

// Node's mode/chmod do not protect NTFS files from inherited read ACLs.
const WINDOWS_PRIVATE_ACL = `
$ErrorActionPreference = 'Stop'
$path = [Environment]::GetEnvironmentVariable('AIDR_PRIVATE_ACL_PATH')
$directory = [Environment]::GetEnvironmentVariable('AIDR_PRIVATE_ACL_DIRECTORY') -eq '1'
$item = if ($directory) { [System.IO.DirectoryInfo]::new($path) } else { [System.IO.FileInfo]::new($path) }
$acl = $item.GetAccessControl()
$owner = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$actualOwner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier])
if ($actualOwner.Value -ne $owner.Value) { throw 'Path is not owned by the current user' }
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
if ($updated.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne $owner.Value) { throw 'Path owner changed during ACL update' }
foreach ($entry in $updated.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
  if ($entry.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
      $entry.IdentityReference.Value -notin @($owner.Value, $system.Value, $administrators.Value)) {
    throw 'ACL grants another identity access'
  }
}
`;

const SYSTEM_SID = "S-1-5-18";
const ADMINISTRATORS_SID = "S-1-5-32-544";
const SDDL_SID_ALIASES: Record<string, string> = { SY: SYSTEM_SID, BA: ADMINISTRATORS_SID };
const FAST_PROBE_TIMEOUT_MS = 5_000;
// Only plain drive-letter paths without cmd.exe metacharacters or icacls wildcards
// are probed natively; anything else takes the authoritative PowerShell path.
const PROBE_SAFE_PATH = /^[A-Za-z]:\\[\w .,@+~()\\-]+$/;

export interface WindowsIdentity {
	name: string;
	sid: string;
}

/** Parse `whoami /user /fo csv /nh` output, or null when it is not exactly that shape. */
export function parseWhoamiIdentity(output: string): WindowsIdentity | null {
	const match = /^"([^"\r\n]+)","(S-1-\d+(?:-\d+)+)"\s*$/.exec(output);
	return match ? { name: match[1] as string, sid: match[2] as string } : null;
}

/**
 * True only when an `icacls /save` SDDL is exactly the DACL the PowerShell
 * hardening produces: protected, no deny entries, and full control for the
 * current user, SYSTEM and Administrators only (inheritable on directories).
 * Any other shape returns false, which sends the caller to the full hardening.
 */
export function sddlIsPrivate(sddl: string, userSid: string, directory: boolean): boolean {
	const match = /^D:P(?:AI)?((?:\([^()]*\))+)$/.exec(sddl.trim());
	if (!match) return false;
	const aces = (match[1] as string).slice(1, -1).split(")(");
	const granted = new Set<string>();
	for (const ace of aces) {
		const [type, flags, rights, objectGuid, inheritedGuid, trustee, ...extra] = ace.split(";");
		if (
			extra.length > 0 ||
			type !== "A" ||
			flags !== (directory ? "OICI" : "") ||
			rights !== "FA" ||
			objectGuid !== "" ||
			inheritedGuid !== "" ||
			trustee === undefined
		) {
			return false;
		}
		granted.add(SDDL_SID_ALIASES[trustee] ?? trustee);
	}
	const expected = [userSid, SYSTEM_SID, ADMINISTRATORS_SID];
	return (
		granted.size === aces.length && granted.size === 3 && expected.every((sid) => granted.has(sid))
	);
}

/** True when a `dir /q` listing shows `entryName` owned by `ownerName` (the whoami account). */
export function listingShowsOwner(listing: string, entryName: string, ownerName: string): boolean {
	const owner = ownerName.toLowerCase();
	const suffix = ` ${entryName}`.toLowerCase();
	return listing.split(/\r?\n/).some((raw) => {
		const line = raw.trimEnd().toLowerCase();
		if (!line.endsWith(suffix)) return false;
		const beforeName = line.slice(0, line.length - suffix.length).trimEnd();
		if (!beforeName.endsWith(owner)) return false;
		// The owner column follows the size or <DIR> column, so a longer account name
		// that merely ends with ours (for example "DOMAIN\\First Last" vs "Last") cannot match.
		const beforeOwner = beforeName.slice(0, beforeName.length - owner.length);
		return /(?:<[^<>\s]+>|\d)\s+$/.test(beforeOwner);
	});
}

function systemTool(name: string): string {
	return join(process.env.SystemRoot || process.env.windir || "C:\\Windows", "System32", name);
}

interface AclTarget {
	path: string;
	directory: boolean;
}

/**
 * Native, read-only proof that every target already has the private ACL and the
 * current user as owner. One cmd.exe runs `whoami`, `icacls /save` (SDDL) and
 * `dir /q` (owner), about 40 ms for the whole set, instead of a PowerShell
 * start (about 150 ms) per path. It reads live state on every call (nothing is
 * cached between runs) and is strictly one-directional: any doubt, error or
 * unexpected output returns false and the caller applies the full PowerShell
 * hardening, which remains the only code that changes an ACL.
 */
function windowsAclsAlreadyPrivate(targets: AclTarget[]): boolean {
	if (targets.length === 0 || targets.some((target) => !PROBE_SAFE_PATH.test(target.path)))
		return false;
	let scratch: string | undefined;
	try {
		scratch = mkdtempSync(join(tmpdir(), "aidr-acl-"));
		const saved = targets.map((_, index) => join(scratch as string, `acl${index}.txt`));
		if (saved.some((file) => !PROBE_SAFE_PATH.test(file))) return false;
		const steps = [`"${systemTool("whoami.exe")}" /user /fo csv /nh`];
		targets.forEach((target, index) => {
			steps.push(`"${systemTool("icacls.exe")}" "${target.path}" /save "${saved[index]}" /c >nul`);
		});
		for (const target of targets) {
			steps.push(`dir /q /a${target.directory ? ":d" : ""} "${target.path}"`);
		}
		const result = spawnSync(systemTool("cmd.exe"), ["/d", "/s", "/c", `"${steps.join(" && ")}"`], {
			encoding: "utf8",
			timeout: FAST_PROBE_TIMEOUT_MS,
			windowsHide: true,
			windowsVerbatimArguments: true,
		});
		if (result.status !== 0) return false;
		const newline = result.stdout.indexOf("\n");
		const identity = newline > 0 ? parseWhoamiIdentity(result.stdout.slice(0, newline)) : null;
		if (!identity) return false;
		const listings = result.stdout.slice(newline + 1);
		return targets.every((target, index) => {
			const raw = readFileSync(saved[index] as string);
			const text = raw.subarray(0, 2).equals(Buffer.from([0xff, 0xfe]))
				? raw.subarray(2).toString("utf16le")
				: raw.toString("utf16le");
			const lines = text.split(/\r?\n/).filter((line) => line.trim() !== "");
			return (
				lines.length === 2 &&
				sddlIsPrivate(lines[1] as string, identity.sid, target.directory) &&
				listingShowsOwner(listings, target.directory ? "." : basename(target.path), identity.name)
			);
		});
	} catch {
		return false;
	} finally {
		if (scratch) rmSync(scratch, { recursive: true, force: true });
	}
}

/** verified: a native probe already proved it; probe: try one; new: just created, so harden directly. */
type AclState = "verified" | "probe" | "new";

function hardenWindowsAcl(path: string, directory: boolean, state: AclState = "probe"): void {
	const before = lstatSync(path);
	if (before.isSymbolicLink() || (directory ? !before.isDirectory() : !before.isFile())) {
		throw new Error("Local metrics/log path is not a regular file or directory.");
	}
	if (
		state === "verified" ||
		(state === "probe" && windowsAclsAlreadyPrivate([{ path, directory }]))
	) {
		const unchanged = lstatSync(path);
		if (
			unchanged.isSymbolicLink() ||
			unchanged.dev !== before.dev ||
			unchanged.ino !== before.ino
		) {
			throw new Error("Local metrics/log path changed during ACL update.");
		}
		return;
	}
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
				AIDR_PRIVATE_ACL_PATH: path,
				AIDR_PRIVATE_ACL_DIRECTORY: directory ? "1" : "0",
			},
			encoding: "utf8",
			timeout: 30_000,
			windowsHide: true,
		},
	);
	if (result.error || result.status !== 0) {
		throw new Error("Local metrics/log Windows ACL could not be made private.");
	}
	const after = lstatSync(path);
	if (after.isSymbolicLink() || after.dev !== before.dev || after.ino !== before.ino) {
		throw new Error("Local metrics/log path changed during ACL update.");
	}
}

function sameFile(a: Stats, b: Stats): boolean {
	return a.dev === b.dev && a.ino === b.ino;
}

/** Create or repair a private directory without changing a different owner's path. */
export function preparePrivateLocalDirectory(path: string): void {
	prepareDirectory(path, "probe");
}

function prepareDirectory(path: string, state: AclState): void {
	const created = mkdirSync(path, { recursive: true, mode: PRIVATE_DIRECTORY_MODE }) !== undefined;
	const before = lstatSync(path);
	if (before.isSymbolicLink() || !before.isDirectory()) {
		throw new Error("Local private path is not a regular directory.");
	}

	if (process.platform === "win32") {
		hardenWindowsAcl(path, true, created ? "new" : state);
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
	// Steady state on Windows: one native probe proves both the directory and the
	// existing file are already private, so no PowerShell start is needed at all.
	// Anything else (first run, loosened ACL, odd path) takes the full hardening.
	const fileExisted = existsSync(path);
	const state: AclState =
		process.platform === "win32" &&
		fileExisted &&
		windowsAclsAlreadyPrivate([
			{ path: directory, directory: true },
			{ path, directory: false },
		])
			? "verified"
			: "probe";
	prepareDirectory(directory, state);

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
	if (process.platform === "win32") hardenWindowsAcl(path, false, fileExisted ? state : "new");
}
