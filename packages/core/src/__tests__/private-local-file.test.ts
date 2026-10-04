import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { preparePrivateLocalFile } from "../private-local-file.js";

// Passthrough spy so the test can count how many processes hardening starts.
vi.mock("node:child_process", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:child_process")>();
	return { ...actual, spawnSync: vi.fn(actual.spawnSync) };
});

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

	// AIDR-SKIP: AIDR-063 qa-owner - NTFS hardening only exists on Windows
	it.skipIf(process.platform !== "win32")(
		"hardens a directory and its file in ONE PowerShell process (hook latency)",
		() => {
			const spy = vi.mocked(spawnSync);
			const root = mkdtempSync(join(tmpdir(), "aidr-private-one-spawn-"));
			try {
				spy.mockClear();
				preparePrivateLocalFile(join(root, "logs", "audit.jsonl"));
				const powershell = spy.mock.calls.filter(([command]) => command === "powershell.exe");
				expect(powershell).toHaveLength(1);
			} finally {
				rmSync(root, { recursive: true, force: true });
			}
		},
	);

	// AIDR-SKIP: AIDR-063 qa-owner - NTFS hardening only exists on Windows
	it.skipIf(process.platform !== "win32")(
		"skips PowerShell when the paths are verifiably private, and re-hardens when they are not",
		() => {
			const spy = vi.mocked(spawnSync);
			const powershellRuns = () => spy.mock.calls.filter(([c]) => c === "powershell.exe").length;
			const root = mkdtempSync(join(tmpdir(), "aidr-private-warm-"));
			const file = join(root, "logs", "audit.jsonl");
			const verify = (path: string) =>
				spawnSync(
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
						windowsHide: true,
					},
				);
			try {
				preparePrivateLocalFile(file); // cold: hardens
				spy.mockClear();
				preparePrivateLocalFile(file); // warm: read-only verification only
				expect(powershellRuns()).toBe(0);

				// Someone widens the file's ACL: it must NOT be treated as private.
				const system32 = join(process.env.SystemRoot ?? "C:\\Windows", "System32", "icacls.exe");
				const grant = spawnSync(system32, [file, "/grant", "*S-1-1-0:(R)"], { encoding: "utf8" });
				expect(grant.status, grant.stderr).toBe(0);
				expect(verify(file).status).not.toBe(0);
				spy.mockClear();
				preparePrivateLocalFile(file);
				expect(powershellRuns()).toBe(1);
				expect(verify(file).status).toBe(0);
			} finally {
				rmSync(root, { recursive: true, force: true });
			}
		},
		60_000,
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
