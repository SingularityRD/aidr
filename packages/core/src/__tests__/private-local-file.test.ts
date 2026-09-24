import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { preparePrivateLocalFile } from "../private-local-file.js";

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
