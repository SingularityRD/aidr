import { mkdir, mkdtemp, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import { describe, expect, it } from "vitest";
import { evaluatePolicy } from "../policy.js";
import { compilePolicyDocumentYaml } from "../policy-document.js";
import { applyRemoteRuntimePolicy } from "../remote-policy.js";
import { ConfigSchema } from "../types.js";

describe("filesystem policy enforcement", () => {
	it("denies a path that escapes an allowed root through ..", async () => {
		const dir = await mkdtemp(join(tmpdir(), "aidr-policy-root-traversal-"));
		try {
			const root = join(dir, "allowed");
			await mkdir(root);
			const target = `${root}${sep}..${sep}outside.txt`;
			const config = ConfigSchema.parse({
				policy: {
					enabled: true,
					filesystem: {
						enabled: true,
						allowed_write_roots: [root],
						outside_root_action: "block",
					},
				},
			});

			const verdict = await evaluatePolicy(
				"Write",
				[{ type: "file_path", value: target }],
				config,
				{ file_path: target },
			);

			expect(verdict).toMatchObject({ decision: "deny", matchedThreatId: "POL-FS-001" });
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});

	it("denies a path that escapes an allowed root through a directory symlink", async () => {
		const dir = await mkdtemp(join(tmpdir(), "aidr-policy-root-symlink-"));
		try {
			const root = join(dir, "allowed");
			const outside = join(dir, "outside");
			await Promise.all([mkdir(root), mkdir(outside)]);
			const link = join(root, "link");
			await symlink(outside, link, process.platform === "win32" ? "junction" : "dir");
			const target = join(link, "outside.txt");
			const config = ConfigSchema.parse({
				policy: {
					enabled: true,
					filesystem: {
						enabled: true,
						allowed_write_roots: [root],
						outside_root_action: "block",
					},
				},
			});

			const verdict = await evaluatePolicy(
				"Write",
				[{ type: "file_path", value: target }],
				config,
				{ file_path: target },
			);

			expect(verdict).toMatchObject({ decision: "deny", matchedThreatId: "POL-FS-001" });
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});

	it("enforces Delete with a file default compiled from team policy YAML", async () => {
		const authored = compilePolicyDocumentYaml(
			"version: '1.0'\ndefault_action: allow\ncategory_defaults:\n  file: deny\nrules: []\n",
		);
		const config = applyRemoteRuntimePolicy(ConfigSchema.parse({}), {
			runtime_policy: authored.runtime_policy,
		});
		const target = join(tmpdir(), "aidr-policy-delete-target.txt");

		const verdict = await evaluatePolicy("Delete", [{ type: "file_path", value: target }], config, {
			file_path: target,
		});

		expect(verdict).toMatchObject({ decision: "deny", matchedThreatId: "POL-DEFAULT-FILE-001" });
	});
});
