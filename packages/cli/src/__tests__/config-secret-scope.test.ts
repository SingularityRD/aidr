import { afterEach, expect, it, vi } from "vitest";

vi.mock("../utils/config-manager.js", () => ({
	rotateSecret: () => ({
		path: "config.json",
		store: "windows-dpapi",
		rotated: true,
		ref: null,
		previousRef: null,
		rotatedAt: "2026-01-01T00:00:00Z",
	}),
	revokeSecret: () => ({
		path: "config.json",
		store: "windows-dpapi",
		revokedRef: null,
		revokedAt: "2026-01-01T00:00:00Z",
	}),
}));
vi.mock("../utils/secret-store.js", () => ({
	SECRET_STORE_KINDS: ["windows-dpapi", "file-acl"],
	SECRET_STORE_ENV: "AIDR_SECRET_STORE",
}));

import { revokeKeyCommand, rotateKeyCommand } from "../commands/config-secret.js";

afterEach(() => vi.restoreAllMocks());

it("labels CLI-only rotation and revocation without claiming a managed API-key change", async () => {
	const lines: string[] = [];
	vi.spyOn(console, "log").mockImplementation((line: string) => {
		lines.push(line);
	});

	await rotateKeyCommand({ json: true });
	await revokeKeyCommand({ json: true });
	expect(lines.map((line) => JSON.parse(line).scope)).toEqual(["cli-setup-only", "cli-setup-only"]);

	lines.length = 0;
	await rotateKeyCommand();
	await revokeKeyCommand();
	expect(lines.join("\n")).toContain("Managed endpoint API keys are unchanged");
	expect(lines.join("\n")).toContain("Managed endpoint API keys remain active");
});
