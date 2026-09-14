/**
 * The connector tool-name contract, asserted against the connector sources.
 *
 * These assertions read the real connector files and derive the tool names they
 * dispatch on. That is the point: a hard-coded list in this test could drift,
 * and drift is exactly how `apply_patch` — the file-edit tool of the Codex and
 * OpenClaw connectors — reached the package leg as an unknown operation.
 */

import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
	CONNECTOR_TOOL_SURFACES,
	type ConnectorToolSurface,
	extractDeclaredToolNames,
	findConnectorToolSurfaceViolations,
} from "../connector-alias-contract.js";
import { canonicalToolName } from "../tool-normalization.js";

/** Walk up from this file to the workspace root (the pnpm workspace marker). */
function findWorkspaceRoot(): string {
	let dir = dirname(fileURLToPath(import.meta.url));
	for (let depth = 0; depth < 10; depth++) {
		if (existsSync(join(dir, "pnpm-workspace.yaml"))) return dir;
		const parent = dirname(dir);
		if (parent === dir) break;
		dir = parent;
	}
	throw new Error("workspace root not found from the core test directory");
}

/** Derive each declared connector's real tool names from its dispatch source. */
async function deriveConnectorToolNames(): Promise<Map<string, string[]>> {
	const root = findWorkspaceRoot();
	const derived = new Map<string, string[]>();
	for (const surface of CONNECTOR_TOOL_SURFACES) {
		const source = await readFile(join(root, surface.dispatchSource), "utf8");
		const names = extractDeclaredToolNames(source);
		// If a source is moved or rewritten the derivation must fail loudly
		// rather than pass vacuously with an empty vocabulary.
		expect(names.length, `${surface.dispatchSource} yielded no tool names`).toBeGreaterThan(0);
		derived.set(surface.connector, names);
	}
	return derived;
}

describe("connector tool-name contract", () => {
	it("derives every connector's tool names from its source with no undeclared names", async () => {
		const derived = await deriveConnectorToolNames();

		expect(findConnectorToolSurfaceViolations(derived)).toEqual([]);

		// Anchors: if a source is exchanged for something unrelated, the derived
		// vocabulary still has to contain the operation each connector is known
		// to emit.
		expect(derived.get("codex")).toContain("apply_patch");
		expect(derived.get("openclaw")).toContain("apply_patch");
		expect(derived.get("opencode")).toContain("edit");
		expect(derived.get("cursor")).toContain("Write");
		expect(derived.get("vscode")).toContain("Bash");
		expect(derived.get("claude-code")).toContain("Bash");
	});

	it("maps the Codex and OpenClaw edit tool onto the canonical Edit shape", async () => {
		const derived = await deriveConnectorToolNames();

		// The regression this contract exists for: `apply_patch` is a file edit,
		// so it must canonicalise rather than fall through to the unknown path.
		expect(canonicalToolName("apply_patch")).toBe("Edit");
		for (const connector of ["codex", "openclaw"]) {
			expect(derived.get(connector)).toContain("apply_patch");
		}
	});

	it("flags a connector tool name that is neither aliased nor declared pass-through", async () => {
		const derived = await deriveConnectorToolNames();
		// A future Codex tool name nobody has classified — the exact shape of the
		// defect: an edit-capable name core would treat as a stranger.
		derived.set("codex", [...(derived.get("codex") ?? []), "patch_file"]);

		const violations = findConnectorToolSurfaceViolations(derived);

		expect(violations).toContainEqual(
			expect.objectContaining({ connector: "codex", toolName: "patch_file", kind: "unmapped" }),
		);
	});

	it("flags a pass-through declaration that the connector no longer emits", async () => {
		const derived = await deriveConnectorToolNames();
		derived.set(
			"opencode",
			(derived.get("opencode") ?? []).filter((name) => name !== "ls"),
		);

		const violations = findConnectorToolSurfaceViolations(derived);

		expect(violations).toContainEqual(
			expect.objectContaining({
				connector: "opencode",
				toolName: "ls",
				kind: "stale-pass-through",
			}),
		);
	});

	it("flags a pass-through name that has become a canonical alias", () => {
		const surfaces: ConnectorToolSurface[] = [
			{
				connector: "fixture",
				dispatchSource: "packages/fixture/src/extractors.ts",
				passThrough: ["apply_patch"],
			},
		];
		const derived = new Map<string, string[]>([["fixture", ["apply_patch"]]]);

		const violations = findConnectorToolSurfaceViolations(derived, surfaces);

		expect(violations).toContainEqual(
			expect.objectContaining({
				connector: "fixture",
				toolName: "apply_patch",
				kind: "stale-pass-through",
			}),
		);
	});

	it("requires a reason whenever a connector declares pass-through tools", () => {
		const surfaces: ConnectorToolSurface[] = [
			{
				connector: "fixture",
				dispatchSource: "packages/fixture/src/extractors.ts",
				passThrough: ["mystery_tool"],
			},
		];
		const derived = new Map<string, string[]>([["fixture", ["mystery_tool"]]]);

		const violations = findConnectorToolSurfaceViolations(derived, surfaces);

		expect(violations).toContainEqual(
			expect.objectContaining({ connector: "fixture", kind: "undeclared-pass-through" }),
		);
	});
});
