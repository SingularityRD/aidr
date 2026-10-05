import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
	listingShowsOwner,
	parseWhoamiIdentity,
	preparePrivateLocalFile,
	sddlIsPrivate,
} from "../private-local-file.js";

const VERIFY_WINDOWS_ACL = `
$ErrorActionPreference = 'Stop'
$path = [Environment]::GetEnvironmentVariable('AIDR_TEST_ACL_PATH')
$item = if ([System.IO.Directory]::Exists($path)) { [System.IO.DirectoryInfo]::new($path) } else { [System.IO.FileInfo]::new($path) }
$acl = $item.GetAccessControl()
if (-not $acl.AreAccessRulesProtected) { throw 'Inherited ACL remains' }
$allowed = @(
  [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value,
  'S-1-5-18',
  'S-1-5-32-544'
)
foreach ($entry in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
  if ($entry.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
      $entry.IdentityReference.Value -notin $allowed) {
    throw "Unexpected ACL grant: $($entry.IdentityReference.Value)"
  }
}
`;

describe("private local output", () => {
	// AIDR-SKIP: AIDR-063 qa-owner - NTFS DACL inspection requires Windows security semantics
	it.skipIf(process.platform !== "win32")(
		"hardens NTFS DACLs for existing metrics/log files",
		() => {
			const root = mkdtempSync(join(tmpdir(), "aidr-private-output-"));
			const directory = join(root, "logs");
			const file = join(directory, "aidr.log");
			try {
				mkdirSync(directory);
				writeFileSync(file, "existing log\n");
				preparePrivateLocalFile(file);
				for (const path of [directory, file]) {
					const result = spawnSync(
						"powershell.exe",
						[
							"-NoProfile",
							"-NonInteractive",
							"-EncodedCommand",
							Buffer.from(VERIFY_WINDOWS_ACL, "utf16le").toString("base64"),
						],
						{
							env: { ...process.env, AIDR_TEST_ACL_PATH: path },
							encoding: "utf8",
							timeout: 30_000,
							windowsHide: true,
						},
					);
					expect(result.error).toBeUndefined();
					expect(result.status, result.stderr).toBe(0);
				}
			} finally {
				rmSync(root, { recursive: true, force: true });
			}
		},
	);

	it("refuses a non-file output target", () => {
		const root = mkdtempSync(join(tmpdir(), "aidr-private-invalid-"));
		const directory = join(root, "not-a-file");
		try {
			mkdirSync(directory);
			expect(() => preparePrivateLocalFile(directory)).toThrow("not a regular file");
		} finally {
			rmSync(root, { recursive: true, force: true });
		}
	});
});

const USER_SID = "S-1-5-21-1-2-3-1001";
const OTHER_SID = "S-1-5-21-1-2-3-1002";
const dirSddl = (...sids: string[]) => `D:PAI${sids.map((sid) => `(A;OICI;FA;;;${sid})`).join("")}`;

describe("native ACL fast-path decision (cross-platform parsing)", () => {
	it("accepts exactly the DACL the hardening produces, with SDDL aliases and any order", () => {
		expect(sddlIsPrivate(dirSddl(USER_SID, "BA", "SY"), USER_SID, true)).toBe(true);
		expect(sddlIsPrivate(dirSddl("SY", "S-1-5-32-544", USER_SID), USER_SID, true)).toBe(true);
		expect(sddlIsPrivate(`D:P(A;;FA;;;${USER_SID})(A;;FA;;;SY)(A;;FA;;;BA)`, USER_SID, false)).toBe(
			true,
		);
	});

	it("rejects every deviation so the PowerShell hardening runs instead", () => {
		// another identity, a missing required identity, or an extra grant
		expect(sddlIsPrivate(dirSddl(OTHER_SID, "BA", "SY"), USER_SID, true)).toBe(false);
		expect(sddlIsPrivate(dirSddl(USER_SID, "SY"), USER_SID, true)).toBe(false);
		expect(sddlIsPrivate(dirSddl(USER_SID, "BA", "SY", "WD"), USER_SID, true)).toBe(false);
		expect(sddlIsPrivate(dirSddl(USER_SID, "BA", "SY", USER_SID), USER_SID, true)).toBe(false);
		// inheritance not blocked, deny ACE, partial rights, wrong inheritance flags, SACL/owner parts
		expect(
			sddlIsPrivate(dirSddl(USER_SID, "BA", "SY").replace("D:PAI", "D:AI"), USER_SID, true),
		).toBe(false);
		expect(
			sddlIsPrivate(
				dirSddl(USER_SID, "BA", "SY").replace("(A;OICI;FA;;;BA)", "(D;OICI;FA;;;BA)"),
				USER_SID,
				true,
			),
		).toBe(false);
		expect(
			sddlIsPrivate(dirSddl(USER_SID, "BA", "SY").replace(/FA/g, "0x1200a9"), USER_SID, true),
		).toBe(false);
		expect(sddlIsPrivate(dirSddl(USER_SID, "BA", "SY"), USER_SID, false)).toBe(false);
		expect(
			sddlIsPrivate(`D:P(A;ID;FA;;;${USER_SID})(A;ID;FA;;;SY)(A;ID;FA;;;BA)`, USER_SID, false),
		).toBe(false);
		expect(sddlIsPrivate(`O:BAG:BA${dirSddl(USER_SID, "BA", "SY")}`, USER_SID, true)).toBe(false);
		expect(sddlIsPrivate(`${dirSddl(USER_SID, "BA", "SY")}S:(AU;SA;FA;;;WD)`, USER_SID, true)).toBe(
			false,
		);
		expect(sddlIsPrivate("", USER_SID, true)).toBe(false);
	});

	it("matches the owner only as an exact whole account name", () => {
		const listing = [
			" Directory of C:\\Users\\a\\.aidr",
			"",
			"05.10.2026  10:56    <DIR>          ANIL\\Anil Yagiz       .",
			"05.10.2026  10:57    <DIR>          NT AUTHORITY\\SYSTEM   ..",
			"05.10.2026  10:57                 3 BUILTIN\\Administrators audit.jsonl",
		].join("\r\n");
		expect(listingShowsOwner(listing, ".", "ANIL\\Anil Yagiz")).toBe(true);
		expect(listingShowsOwner(listing, ".", "anil\\anil yagiz")).toBe(true);
		expect(listingShowsOwner(listing, ".", "Yagiz")).toBe(false);
		expect(listingShowsOwner(listing, ".", "NT AUTHORITY\\SYSTEM")).toBe(false);
		expect(listingShowsOwner(listing, "audit.jsonl", "ANIL\\Anil Yagiz")).toBe(false);
		expect(listingShowsOwner(listing, "audit.jsonl", "BUILTIN\\Administrators")).toBe(true);
		expect(listingShowsOwner("", ".", "ANIL\\Anil Yagiz")).toBe(false);
	});

	it("parses only the exact whoami /user /fo csv /nh shape", () => {
		expect(
			parseWhoamiIdentity(`"anil\\anill","S-1-5-21-4043862446-965468061-1166222855-1001"\r\n`),
		).toEqual({
			name: "anil\\anill",
			sid: "S-1-5-21-4043862446-965468061-1166222855-1001",
		});
		expect(parseWhoamiIdentity("ERROR: nope")).toBeNull();
		expect(parseWhoamiIdentity(`"a","not-a-sid"`)).toBeNull();
	});
});

describe("private local output re-hardens loosened ACLs on Windows", () => {
	// AIDR-SKIP: AIDR-063 qa-owner - NTFS DACL inspection requires Windows security semantics
	it.skipIf(process.platform !== "win32")(
		"a second call keeps the ACL private, and an added grant is removed again",
		() => {
			const root = mkdtempSync(join(tmpdir(), "aidr-private-reharden-"));
			const directory = join(root, "logs");
			const file = join(directory, "aidr.log");
			const icacls = join(process.env.SystemRoot ?? "C:\\Windows", "System32", "icacls.exe");
			const sddl = (path: string): string => {
				const out = join(root, "acl.txt");
				spawnSync(icacls, [path, "/save", out, "/c"], { windowsHide: true });
				return readFileSync(out).toString("utf16le");
			};
			try {
				mkdirSync(directory);
				preparePrivateLocalFile(file);
				const hardened = sddl(directory);
				preparePrivateLocalFile(file); // fast path: nothing to change
				expect(sddl(directory)).toBe(hardened);

				// Everyone: read on the file. The fast path must notice and the full hardening must remove it.
				spawnSync(icacls, [file, "/grant", "*S-1-1-0:R"], { windowsHide: true });
				expect(sddl(file)).toContain(";;;WD)");
				preparePrivateLocalFile(file);
				expect(sddl(file)).not.toContain(";;;WD)");
			} finally {
				rmSync(root, { recursive: true, force: true });
			}
		},
	);
});
