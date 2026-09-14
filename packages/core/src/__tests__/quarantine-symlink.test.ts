/**
 * Quarantine must not lie about what it did — or about what it refused to do.
 *
 * Three defects are pinned here:
 *
 *  1. `quarantine()` used a following `stat`, so a symlink was resolved and the
 *     LINK TARGET was moved into the vault and deleted from where it lived. The
 *     module now uses `lstat` and refuses a link outright.
 *  2. A failed `unlink` in `delete()` was swallowed and the item was dropped from
 *     tracking anyway, so a hostile file still in the vault was reported as
 *     permanently deleted. A real failure now throws and keeps the item tracked.
 *  3. The date directory was created without a mode, unlike the 0o700 snapshot
 *     root. It is now 0o700 (asserted where the platform reports modes usefully).
 *
 * ISOLATION: every path is inside a temp directory; nothing touches the real
 * quarantine vault.
 */

import { existsSync } from "node:fs";
import { lstat, mkdir, readdir, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	AutoQuarantine,
	type QuarantineConfig,
	QuarantineDeleteError,
	QuarantineRefusedError,
} from "../quarantine.js";
import { ResponseAuditor } from "../response-audit.js";
import type { Verdict } from "../types.js";
import { makeTmpDir } from "./test-utils.js";

const VICTIM_CONTENT = "#!/bin/sh\necho hostile\n";

let tmpDir: string;
let vaultDir: string;
let victim: string;

function configFor(quarantineDir: string): QuarantineConfig {
	return { quarantineDir, retentionDays: 30, notifyChannels: [] };
}

async function readJsonl(path: string): Promise<Array<Record<string, unknown>>> {
	return (await readFile(path, "utf8"))
		.trim()
		.split("\n")
		.filter(Boolean)
		.map((line) => JSON.parse(line) as Record<string, unknown>);
}

function testVerdict(): Verdict {
	return {
		decision: "deny",
		category: "malware",
		confidence: 0.99,
		severity: "critical",
		source: "test",
		artifacts: [victim],
		matchedThreatId: "TEST-QUARANTINE-SYMLINK",
		reasons: ["test quarantine"],
	};
}

/**
 * Create a link at `linkPath` and return the path it points at.
 *
 * A FILE symlink is the interesting case, but on Windows it needs Developer Mode
 * or elevation (`EPERM`, verified on this host). The fallback is a directory
 * junction, which `lstat().isSymbolicLink()` also reports as a link — the property
 * quarantine has to refuse — so the refusal is exercised either way and the link
 * target is never touched.
 */
async function createLink(victimPath: string, linkPath: string): Promise<string> {
	try {
		await symlink(victimPath, linkPath, "file");
		return victimPath;
	} catch (error) {
		const code = (error as NodeJS.ErrnoException)?.code;
		if (code !== "EPERM" && code !== "EACCES" && code !== "ENOSYS") throw error;
		const targetDir = `${victimPath}-target`;
		await mkdir(targetDir, { recursive: true });
		await writeFile(join(targetDir, "payload.sh"), VICTIM_CONTENT, "utf8");
		await symlink(targetDir, linkPath, "junction");
		return targetDir;
	}
}

beforeEach(async () => {
	tmpDir = await makeTmpDir();
	vaultDir = join(tmpDir, "vault");
	victim = join(tmpDir, "payload.sh");
	await writeFile(victim, VICTIM_CONTENT, "utf8");
});

afterEach(async () => {
	await rm(tmpDir, { recursive: true, force: true });
});

describe("a quarantine refuses a link instead of following it", () => {
	it("refuses to quarantine a symlink instead of following it", async () => {
		const linkPath = join(tmpDir, "innocent-name.sh");
		const linkTarget = await createLink(victim, linkPath);
		expect((await lstat(linkPath)).isSymbolicLink()).toBe(true);

		const auditPath = join(tmpDir, "response-audit.jsonl");
		const manager = new AutoQuarantine(
			configFor(vaultDir),
			undefined,
			undefined,
			new ResponseAuditor(auditPath),
		);

		const error = await manager
			.quarantine(linkPath, "TEST-QUARANTINE-SYMLINK", undefined, {
				tool: "Bash",
				input: "quarantine innocent-name.sh",
				verdict: testVerdict(),
				authorizedBy: "operator:on-call",
			})
			.catch((err: unknown) => err);

		// A typed, machine-readable refusal — not the generic "not found" that a
		// following `stat` would have produced, and not a successful quarantine.
		expect(error).toBeInstanceOf(QuarantineRefusedError);
		expect(error).toMatchObject({ code: "symlink_refused" });

		// Nothing was moved or deleted: the link is still there, its target is
		// untouched, and nothing was tracked as quarantined.
		expect(existsSync(linkPath)).toBe(true);
		expect(existsSync(linkTarget)).toBe(true);
		expect(manager.list()).toEqual([]);

		// The refusal is on the record, attributed, and reported as a failure.
		const raw = await readdir(vaultDir, { recursive: true });
		expect(raw).toEqual([]);
		const entries = await readJsonl(auditPath);
		expect(entries).toHaveLength(1);
		expect(entries[0]).toMatchObject({
			action: "quarantine",
			outcome: "failure",
			authorized_by: "operator:on-call",
			metadata: { reason: "symlink_refused" },
		});
	});
});

describe("a quarantine vault is not world-traversable", () => {
	it("creates the date directory with owner-only permissions", async () => {
		const manager = new AutoQuarantine(configFor(vaultDir));
		const item = await manager.quarantine(victim, "TEST-QUARANTINE-SYMLINK");

		const dateDir = dirname(item.quarantinePath);
		expect((await stat(dateDir)).isDirectory()).toBe(true);

		// Windows does not implement POSIX directory modes, so the mode is asserted
		// where the platform actually reports it; the directory itself is asserted
		// everywhere.
		if (process.platform !== "win32") {
			expect((await stat(dateDir)).mode & 0o777).toBe(0o700);
		}
	});
});

describe("the operator that authorized a quarantine is recorded", () => {
	it("persists the identity with the item and in the audit entry", async () => {
		const auditPath = join(tmpDir, "operator-audit.jsonl");
		const manager = new AutoQuarantine(
			configFor(vaultDir),
			undefined,
			undefined,
			new ResponseAuditor(auditPath),
		);

		const item = await manager.quarantine(victim, "TEST-QUARANTINE-SYMLINK", undefined, {
			tool: "Bash",
			input: "quarantine payload.sh",
			verdict: testVerdict(),
			authorizedBy: "operator:on-call",
		});

		expect(item.authorizedBy).toBe("operator:on-call");
		// Persisted with the item, so a rebuilt manager still knows who authorized it.
		const reopened = new AutoQuarantine(configFor(vaultDir));
		expect(reopened.get(item.id)?.authorizedBy).toBe("operator:on-call");

		const entries = await readJsonl(auditPath);
		expect(entries[0]).toMatchObject({
			action: "quarantine",
			outcome: "success",
			authorized_by: "operator:on-call",
		});
	});
});

describe("a quarantine delete reports a failure it did not complete", () => {
	it("reports a failed delete instead of forgetting the item", async () => {
		const manager = new AutoQuarantine(configFor(vaultDir));
		const item = await manager.quarantine(victim, "TEST-QUARANTINE-SYMLINK");
		expect(manager.get(item.id)).toBeDefined();

		// Make `unlink` fail: a directory in the quarantined file's place cannot be
		// removed by `unlink` on any platform (EPERM on Windows, EISDIR elsewhere),
		// and ENOENT is deliberately NOT what this simulates.
		await rm(item.quarantinePath, { force: true });
		await mkdir(item.quarantinePath, { recursive: true });

		const error = await manager.delete(item.id).catch((err: unknown) => err);
		expect(error).toBeInstanceOf(QuarantineDeleteError);
		expect(error).toMatchObject({
			code: "delete_failed",
			itemId: item.id,
			quarantinePath: item.quarantinePath,
		});

		// The item is STILL tracked, and the path is still there: the old code
		// reported a permanent deletion it had not performed.
		expect(manager.get(item.id)).toBeDefined();
		expect(manager.list()).toHaveLength(1);
		expect(existsSync(item.quarantinePath)).toBe(true);

		// The persisted manifest agrees with the in-memory view, so the item survives
		// a restart rather than being forgotten on the next save.
		const reopened = new AutoQuarantine(configFor(vaultDir));
		expect(reopened.get(item.id)).toBeDefined();
	});
});
