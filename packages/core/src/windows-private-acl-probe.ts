/**
 * Read-only check that a Windows path is ALREADY in the private state that
 * `private-local-file.ts` produces, so the ~0.5-2.5 s PowerShell hardening can be
 * skipped on every later call (a hook is a new process per tool call, so its
 * in-process memoisation never helps across calls).
 *
 * Safety model: this recognises only the exact state hardening creates, and it
 * fails closed. Any doubt (a spawn error, an unexpected ACE, an inherited or
 * unprotected DACL, a different owner, an unparsable or localised line, a path
 * with shell metacharacters) returns `false` and the caller falls back to the
 * full PowerShell hardening, whose post-conditions are the same:
 *
 *   - the DACL is protected (no inheritance),
 *   - every ACE is an explicit Allow/FullControl for the current user, SYSTEM or
 *     Administrators, and all three are present,
 *   - directory ACEs carry ContainerInherit+ObjectInherit, file ACEs none,
 *   - the owner is the current user (an owner can always rewrite the DACL, so a
 *     private DACL owned by someone else is not private).
 *
 * Only native System32 tools are used (no PowerShell, no PATH lookup).
 */

import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";

const NATIVE_TIMEOUT_MS = 10_000;
const SYSTEM_SID = "S-1-5-18";
const ADMINISTRATORS_SID = "S-1-5-32-544";
const SDDL_ALIASES: Readonly<Record<string, string>> = {
	SY: SYSTEM_SID,
	BA: ADMINISTRATORS_SID,
};
// Characters that cmd.exe or icacls would interpret rather than treat as a name.
const UNSAFE_PATH_CHARS = /[&|<>^%!"*?\r\n]/;

export interface ProbeTarget {
	path: string;
	directory: boolean;
}

interface CurrentUser {
	name: string;
	sid: string;
}

let currentUserCache: CurrentUser | null | undefined;

function system32(exe: string): string {
	return join(process.env.SystemRoot ?? "C:\\Windows", "System32", exe);
}

function runNative(exe: string, args: string[]): string | null {
	const result = spawnSync(system32(exe), args, {
		encoding: "utf8",
		timeout: NATIVE_TIMEOUT_MS,
		windowsHide: true,
	});
	return result.error || result.status !== 0 ? null : result.stdout;
}

function currentUser(): CurrentUser | null {
	if (currentUserCache !== undefined) return currentUserCache;
	currentUserCache = null;
	const output = runNative("whoami.exe", ["/user", "/fo", "csv", "/nh"]);
	const match = output ? /^"([^"]+)","(S-1-[0-9-]+)"\s*$/.exec(output.trim()) : null;
	if (match?.[1] && match[2]) currentUserCache = { name: match[1], sid: match[2] };
	return currentUserCache;
}

/** `icacls /save` writes UTF-16LE (observed without a BOM); tolerate a BOM or plain text. */
function decodeIcaclsSave(buffer: Buffer): string {
	if (buffer[0] === 0xff && buffer[1] === 0xfe) return buffer.subarray(2).toString("utf16le");
	return buffer[1] === 0 ? buffer.toString("utf16le") : buffer.toString("utf8");
}

/** The DACL part of a path's security descriptor, as written by `icacls /save`. */
function readDacl(path: string): string | null {
	const savePath = join(tmpdir(), `aidr-acl-probe-${randomUUID()}.txt`);
	try {
		if (runNative("icacls.exe", [path, "/save", savePath, "/c"]) === null) return null;
		const match = /(?:^|\n)(D:[^\r\n]*)/.exec(decodeIcaclsSave(readFileSync(savePath)));
		return match?.[1] ?? null;
	} catch {
		return null;
	} finally {
		rmSync(savePath, { force: true });
	}
}

function aclIsExactlyPrivate(sddl: string, directory: boolean, user: CurrentUser): boolean {
	const dacl = /^D:([A-Z]*)((?:\([^)]*\))+)$/.exec(sddl);
	if (!dacl?.[1] || !dacl[2]) return false;
	const isProtected = dacl[1].includes("P");
	// A file freshly created inside a hardened directory carries exactly the
	// directory's ACEs as inherited ("ID"). That is as private as the directory,
	// which `windowsTargetsAreAlreadyPrivate` verifies in the same call.
	const inheritedFromPrivateParent = !directory && !isProtected && dacl[1].includes("AI");
	if (!isProtected && !inheritedFromPrivateParent) return false;
	const aceFlags = directory ? "OICI" : inheritedFromPrivateParent ? "ID" : "";
	const required = new Set([user.sid, SYSTEM_SID, ADMINISTRATORS_SID]);
	const seen = new Set<string>();
	for (const ace of dacl[2].matchAll(/\(([^)]*)\)/g)) {
		const [type, flags, rights, objectGuid, inheritedGuid, trustee, ...rest] = (ace[1] ?? "").split(
			";",
		);
		const sid = trustee ? (SDDL_ALIASES[trustee] ?? trustee) : "";
		if (
			rest.length > 0 ||
			type !== "A" ||
			flags !== aceFlags ||
			(rights !== "FA" && rights !== "0x1f01ff") ||
			objectGuid !== "" ||
			inheritedGuid !== "" ||
			!required.has(sid)
		) {
			return false;
		}
		seen.add(sid);
	}
	return seen.size === required.size;
}

/** `dir /q` lists the owner immediately before the entry name ("." is the directory itself). */
function ownedByUser(directoryPath: string, entries: string[], user: CurrentUser): boolean {
	const listing = runNative("cmd.exe", ["/d", "/c", "dir", "/q", "/a", directoryPath]);
	if (listing === null) return false;
	const lines = listing.split(/\r?\n/);
	const escaped = user.name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
	return entries.every((entry) => {
		const owner = new RegExp(
			`\\s${escaped}\\s+${entry.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`,
			"i",
		);
		return lines.some((line) => owner.test(line));
	});
}

/**
 * True only when every target is verifiably in the exact private state. Never
 * throws; `false` means "unknown or not private", never "insecure".
 */
export function windowsTargetsAreAlreadyPrivate(targets: readonly ProbeTarget[]): boolean {
	try {
		if (process.platform !== "win32" || targets.length === 0) return false;
		if (targets.some((target) => UNSAFE_PATH_CHARS.test(target.path))) return false;
		const user = currentUser();
		if (!user) return false;

		for (const target of targets) {
			const sddl = readDacl(target.path);
			if (!sddl || !aclIsExactlyPrivate(sddl, target.directory, user)) return false;
		}

		// Ownership: one listing of the directory covers its "." entry and its files.
		const [directory, ...files] = targets;
		if (
			!directory?.directory ||
			files.some((file) => file.directory || dirname(file.path) !== directory.path)
		) {
			return false;
		}
		return ownedByUser(directory.path, [".", ...files.map((file) => basename(file.path))], user);
	} catch {
		return false;
	}
}
