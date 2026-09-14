// @vitest-environment jsdom

// B1 — the YAML policy document editor must dry-run against the compiler that
// actually enforces the document, not only against its own parser.
//
// `packages/dashboard/src/enterprise/policy-editor.tsx` persists raw YAML with a
// local validator, and its local rules are weaker than
// `compileRuntimePolicyDocument` in
// `supabase/functions/_shared/policy-document.ts`: the server also bounds a rule
// name (160), a description (2000) and the rule count (200). A document the
// editor accepts could therefore be compiled differently — or refused outright —
// by the function that turns the stored document into runtime policy.
//
// The suite below never restates a compiler rule. It reads the fixtures, asks the
// editor's local validator, and asks the *real* shared compiler for the same
// document through the invocation seam the dashboard already uses
// (`supabase.functions.invoke("policy-management", { action: "compile_document" })`),
// which the double in this file forwards to the compiler module itself.

import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { createElement } from "react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/supabase", () => ({
	supabase: {
		auth: {
			getSession: vi.fn(),
			getUser: vi.fn(),
			signOut: vi.fn(),
			signInWithOAuth: vi.fn(),
			signInWithOtp: vi.fn(),
			exchangeCodeForSession: vi.fn(),
			onAuthStateChange: vi.fn(),
		},
		functions: { invoke: vi.fn() },
		from: vi.fn(),
	},
	supabaseEnvError: null,
}));

import { dryRunStoredDocument, validateDocument } from "../enterprise/policy-editor";
import { AppLayout } from "../ui/AppLayout";
import { PolicyPage } from "../ui/pages/PolicyPage";
import { installDashboardMocks, POLICY_ROW_ID, TEAM_ID } from "./helpers/dashboard-mocks";

const FIXTURE_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "fixtures", "policy-parity");
const STORED_AT = "2026-01-02T00:00:00.000Z";

function fixture(name: string): string {
	// Textarea values are LF-normalised by the DOM, so a fixture's own line
	// endings must not decide whether it round-trips through the editor.
	return readFileSync(join(FIXTURE_DIR, name), "utf8").replace(/\r\n/g, "\n");
}

interface LocalVerdict {
	ok: boolean;
	message: string;
}

/** The editor's own validator, reduced to the verdict this suite compares. */
function localVerdict(yaml: string): LocalVerdict {
	const validation = validateDocument(yaml);
	return validation.ok ? { ok: true, message: "" } : { ok: false, message: validation.message };
}

interface ServerCompiler {
	compileRuntimePolicyDocument: (document: unknown) => {
		runtime_policy: Record<string, unknown>;
		diagnostics: unknown[];
		semantics: { precedence: string[] };
	};
	simulateCompiledRuntimePolicy: (
		policy: Record<string, unknown>,
		simulation: unknown,
	) => { action: string; source: string; matched: string | null };
}

/**
 * The real compiler, loaded from the Edge Function's own source.
 *
 * The specifier is built at runtime so the dashboard's `tsc --noEmit` project
 * does not adopt the Deno-targeted function tree (which imports `npm:`
 * specifiers this package cannot resolve) as its own sources.
 */
async function loadServerCompiler(): Promise<ServerCompiler> {
	const specifier = "../../../../supabase/functions/_shared/policy-document.ts";
	return (await import(specifier)) as unknown as ServerCompiler;
}

/** The Deno `yaml` parser the handler parses a stored document with. */
async function loadStoredDocumentParser(): Promise<{
	parseDocument: (source: string, options: Record<string, unknown>) => {
		errors: Array<{ message?: string }>;
		toJS: (options: Record<string, unknown>) => unknown;
	};
}> {
	const specifier = "../../../core/node_modules/yaml/dist/index.js";
	const loaded = (await import(specifier)) as unknown as {
		parseDocument?: unknown;
		default?: { parseDocument?: unknown };
	};
	const parseDocument = loaded.parseDocument ?? loaded.default?.parseDocument;
	if (typeof parseDocument !== "function") throw new Error("the server's yaml parser is unavailable");
	return { parseDocument } as Awaited<ReturnType<typeof loadStoredDocumentParser>>;
}

/** The document the server currently has stored for the team. */
const serverStore: { content: string | null } = { content: null };

function refusedResponse(code: string, status = 400): { data: null; error: unknown } {
	return {
		data: null,
		error: Object.assign(new Error(code), {
			context: new Response(JSON.stringify({ error: code }), {
				status,
				headers: { "Content-Type": "application/json" },
			}),
		}),
	};
}

/**
 * The handler's `compile_document` branch, with the compiler left alone.
 *
 * It performs exactly the steps `policy-management` performs around the shared
 * compiler — read the stored document, parse it with the Deno `yaml` parser,
 * compile it, simulate — and answers with the same bodies, so the editor's own
 * response handling is exercised without a second copy of any compiler rule.
 */
async function compileStoredDocument(simulation: unknown): Promise<{ data: unknown; error: unknown }> {
	const content = serverStore.content;
	if (content === null) return refusedResponse("policy_document_not_found", 404);
	const [{ parseDocument }, compiler] = await Promise.all([
		loadStoredDocumentParser(),
		loadServerCompiler(),
	]);
	try {
		const parsed = parseDocument(content, { schema: "core", uniqueKeys: true, prettyErrors: false });
		if (parsed.errors.length > 0) {
			throw new Error(`invalid_policy_yaml:${parsed.errors[0]?.message ?? "parse_error"}`);
		}
		const document = parsed.toJS({ maxAliasCount: 0 });
		const compilation = compiler.compileRuntimePolicyDocument(document);
		const result =
			simulation === undefined
				? null
				: compiler.simulateCompiledRuntimePolicy(compilation.runtime_policy, simulation);
		return {
			data: {
				ok: true,
				dry_run: true,
				source: { id: POLICY_ROW_ID, updated_at: STORED_AT },
				...compilation,
				...(result ? { simulation: result } : {}),
			},
			error: null,
		};
	} catch (error) {
		return refusedResponse(error instanceof Error ? error.message : "invalid_policy_document");
	}
}

/** Point the invocation seam at a team whose stored document is `storedYaml`. */
function installParityServer(storedYaml: string | null) {
	serverStore.content = storedYaml;
	const mocks = installDashboardMocks({
		role: "admin",
		policyRow:
			storedYaml === null
				? null
				: { id: POLICY_ROW_ID, content: storedYaml, updated_at: STORED_AT },
	});
	mocks.invoke.mockImplementation(
		async (name: string, request?: { body?: { action?: string; simulation?: unknown } }) => {
			if (name === "identity-security" && request?.body?.action === "status") {
				return {
					data: {
						ok: true,
						require_mfa: true,
						current_assurance: "aal2",
						next_assurance: "aal2",
						access_allowed: true,
					},
					error: null,
				};
			}
			if (name !== "policy-management") return { data: { ok: true }, error: null };
			const body = request?.body ?? {};
			if (body.action === "read") return { data: { ok: true, version: 0, policy: null }, error: null };
			if (body.action === "history") {
				return { data: { ok: true, revisions: [], truncated: false }, error: null };
			}
			if (body.action === "adoption") {
				return { data: { ok: true, agents: [], truncated: false }, error: null };
			}
			if (body.action === "compile_document") return compileStoredDocument(body.simulation);
			return { data: { ok: true }, error: null };
		},
	);
	return mocks;
}

/**
 * Mirror the editor's writes into `team_policies` onto the stored document the
 * compile branch reads, so the compile of a *written* draft is observable.
 */
function mirrorWritesIntoServerStore(mocks: ReturnType<typeof installParityServer>) {
	const writeChain = () => {
		const written = async () => ({ data: [{ id: POLICY_ROW_ID }], error: null });
		return { select: written, eq: () => ({ select: written }) };
	};
	mocks.teamPolicies.update.mockImplementation((row: { content?: string }) => {
		if (typeof row?.content === "string") serverStore.content = row.content;
		return writeChain();
	});
	mocks.teamPolicies.insert.mockImplementation((row: { content?: string }) => {
		if (typeof row?.content === "string") serverStore.content = row.content;
		return writeChain();
	});
	mocks.teamPolicies.delete.mockImplementation(() => ({
		eq: async (column: string, value: unknown) => {
			if (column === "id" && value === POLICY_ROW_ID) serverStore.content = null;
			return { data: null, error: null };
		},
	}));
}

function renderPolicyRoute() {
	// createElement, not JSX: this suite is a .ts file (the path the B1 gap
	// record names), so it cannot rely on the tsx transform.
	return render(
		createElement(
			MemoryRouter,
			{ initialEntries: ["/policies"] },
			createElement(
				Routes,
				null,
				createElement(
					Route,
					{ path: "/*", element: createElement(AppLayout) },
					createElement(Route, { path: "policies", element: createElement(PolicyPage) }),
				),
			),
		),
	);
}

function saveButton(): HTMLElement {
	return screen.getByRole("button", { name: /Save Policy|Saving/ });
}

/** Invocation order of every `compile_document` call the editor made. */
function compileCallOrders(mocks: ReturnType<typeof installParityServer>): number[] {
	return mocks.invoke.mock.calls
		.map((call, index) => ({ call, index }))
		.filter(
			({ call }) =>
				call[0] === "policy-management" &&
				(call[1] as { body?: { action?: string } } | undefined)?.body?.action === "compile_document",
		)
		.map(({ index }) => mocks.invoke.mock.invocationCallOrder[index] as number);
}

function yamlEditor(): HTMLTextAreaElement {
	return screen.getByRole("textbox", { name: /Policy \(YAML\)/ }) as HTMLTextAreaElement;
}

/** A document with `count` rules, written the way the editor's reader parses. */
function documentWithRules(count: number): string {
	const lines = ['version: "1.0"', "default_action: ask", "rules:"];
	for (let index = 0; index < count; index += 1) {
		lines.push(
			`  - name: Rule ${index}`,
			"    condition:",
			`      mcp_tool: server${index}.tool`,
			"    action: allow",
			"    priority: 1",
		);
	}
	return `${lines.join("\n")}\n`;
}

/** Fields the runtime compiler must reject, with the exact wording each side uses. */
const UNKNOWN_FIELD_CASES = [
	{
		file: "unknown-document-field.yaml",
		path: "document",
		field: "telemetry_upload",
		local: "Unsupported policy field: telemetry_upload.",
		server: "invalid_policy_document:document:unsupported_field:telemetry_upload",
	},
	{
		file: "unknown-rule-field.yaml",
		path: "rules.0",
		field: "when",
		local: "Rule 1 has unsupported field: when.",
		server: "invalid_policy_document:rules.0:unsupported_field:when",
	},
	{
		file: "unknown-condition-field.yaml",
		path: "rules.0.condition",
		field: "pattern",
		local: "Rule 1 condition has unsupported field: pattern.",
		server: "invalid_policy_document:rules.0.condition:unsupported_field:pattern",
	},
	{
		file: "unknown-category-default.yaml",
		path: "category_defaults",
		field: "network",
		local: "Unsupported category default: network.",
		server: "invalid_policy_document:category_defaults:unsupported_field:network",
	},
] as const;

/** Documents the local validator accepts and the compiler that enforces them does not. */
const COMPILER_ONLY_REJECTIONS = [
	{ file: "rule-name-too-long.yaml", code: "invalid_policy_document:rules.0.name:invalid_string" },
	{ file: "description-too-long.yaml", code: "invalid_policy_document:description:invalid_string" },
	{ generated: documentWithRules(201), code: "invalid_policy_document:rules:invalid_rules" },
] as const;

beforeEach(() => {
	serverStore.content = null;
});

afterEach(() => {
	cleanup();
	vi.resetAllMocks();
});

describe("Policy document parity (B1)", () => {
	it("rejects exactly the fields the runtime compiler rejects", async () => {
		for (const testCase of UNKNOWN_FIELD_CASES) {
			const yaml = fixture(testCase.file);

			// The editor's local validator...
			const local = localVerdict(yaml);
			expect(local.ok, testCase.file).toBe(false);
			expect(local.message, testCase.file).toBe(testCase.local);

			// ...and the server compiler, through the seam the editor invokes.
			installParityServer(yaml);
			const server = await dryRunStoredDocument(TEAM_ID);
			expect(server.status, testCase.file).toBe("refused");
			if (server.status !== "refused") continue;
			expect(server.code, testCase.file).toBe(testCase.server);
			expect(server.unsupported, testCase.file).toEqual([
				{ path: testCase.path, field: testCase.field },
			]);
		}

		// The same document is accepted by both, with no fields to report.
		const accepted = fixture("valid-policy.yaml");
		expect(localVerdict(accepted).ok).toBe(true);
		installParityServer(accepted);
		const compiled = await dryRunStoredDocument(TEAM_ID);
		expect(compiled.status).toBe("compiled");
		if (compiled.status !== "compiled") return;
		expect(compiled.unsupported).toEqual([]);
		expect(compiled.precedence).toEqual(["deny", "ask", "allow"]);
		// unknown_action: deny in the fixture is what the server simulates.
		expect(compiled.simulation).toEqual({ action: "deny", source: "mcp_unknown", matched: null });
	});

	it("reports the documents the local validator accepts and the compiler refuses", async () => {
		for (const testCase of COMPILER_ONLY_REJECTIONS) {
			const label = "file" in testCase ? testCase.file : "documentWithRules(201)";
			const yaml = "file" in testCase ? fixture(testCase.file) : testCase.generated;

			// The local validator lets these through: the residual gap the editor's
			// server dry run exists to close.
			expect(localVerdict(yaml).ok, label).toBe(true);

			installParityServer(yaml);
			const server = await dryRunStoredDocument(TEAM_ID);
			expect(server.status, label).toBe("refused");
			if (server.status !== "refused") continue;
			expect(server.code, label).toBe(testCase.code);
		}
	});

	it("surfaces the server dry run inside the document editor before save", async () => {
		const stored = fixture("valid-policy.yaml");
		const mocks = installParityServer(stored);

		renderPolicyRoute();
		await waitFor(() => expect(screen.getByText("✓ Valid policy")).toBeInTheDocument());

		fireEvent.click(saveButton());

		await waitFor(() =>
			expect(screen.getByText("Policy saved successfully")).toBeInTheDocument(),
		);

		// The dry run is the sibling runtime policy editor's call shape.
		expect(mocks.invoke).toHaveBeenCalledWith("policy-management", {
			body: {
				action: "compile_document",
				tenant_id: TEAM_ID,
				simulation: {
					kind: "mcp",
					server: "unregistered-preview",
					tool: "call",
					inventory: "unknown",
				},
			},
		});

		// ...and it happens before the write it is gating, with a second compile of
		// the document that was just written so the acceptance is the server's.
		const compileOrders = compileCallOrders(mocks);
		expect(compileOrders).toHaveLength(2);
		const writeOrder = mocks.teamPolicies.update.mock.invocationCallOrder[0];
		expect(writeOrder).toBeDefined();
		expect(compileOrders[0]).toBeLessThan(Number(writeOrder));
		expect(compileOrders[1]).toBeGreaterThan(Number(writeOrder));

		// The server's verdict is rendered in the document card.
		expect(screen.getByText("Unsupported fields: none.")).toBeInTheDocument();
		expect(screen.getByText(/Conflict precedence: deny > ask > allow/)).toBeInTheDocument();
		expect(screen.getByText(/Simulated unknown MCP call: deny \(mcp_unknown\)/)).toBeInTheDocument();

		expect(mocks.teamPolicies.update).toHaveBeenCalledWith(
			expect.objectContaining({ content: stored, tenant_id: TEAM_ID }),
		);
	});

	it("refuses the save when the dry run refuses the document", async () => {
		const tooLong = fixture("rule-name-too-long.yaml");
		// The local validator accepts this document; the runtime compiler does not.
		expect(localVerdict(tooLong).ok).toBe(true);
		const mocks = installParityServer(tooLong);

		renderPolicyRoute();
		await waitFor(() => expect(screen.getByText("✓ Valid policy")).toBeInTheDocument());

		fireEvent.click(saveButton());

		await waitFor(() =>
			expect(screen.getByRole("alert")).toHaveTextContent(/rules\.0\.name:invalid_string/),
		);
		expect(screen.queryByText("Policy saved successfully")).not.toBeInTheDocument();
		expect(mocks.teamPolicies.insert).not.toHaveBeenCalled();
		expect(mocks.teamPolicies.update).not.toHaveBeenCalled();

		// The card names what the server refused, next to the local verdict.
		expect(
			screen.getAllByText(/invalid_policy_document:rules\.0\.name:invalid_string/).length,
		).toBeGreaterThan(0);
	});

	it("refuses a first document the compiler refuses and removes the rejected write", async () => {
		const refused = fixture("description-too-long.yaml");
		expect(localVerdict(refused).ok).toBe(true);
		// No stored document yet: the pre-save dry run has nothing to compile, so
		// the draft's own compile after the write is what decides the save.
		const mocks = installParityServer(null);
		mirrorWritesIntoServerStore(mocks);

		renderPolicyRoute();
		await waitFor(() => expect(screen.getByText("✓ Valid policy")).toBeInTheDocument());

		fireEvent.change(yamlEditor(), { target: { value: refused } });
		fireEvent.click(saveButton());

		await waitFor(() =>
			expect(screen.getByRole("alert")).toHaveTextContent(/description:invalid_string/),
		);
		expect(screen.queryByText("Policy saved successfully")).not.toBeInTheDocument();
		expect(mocks.teamPolicies.insert).toHaveBeenCalledTimes(1);
		expect(mocks.teamPolicies.delete).toHaveBeenCalledTimes(1);
		expect(serverStore.content).toBeNull();
		expect(
			screen.getAllByText(/invalid_policy_document:description:invalid_string/).length,
		).toBeGreaterThan(0);
	});

	it("rolls back a draft the compiler refuses when it differs from the stored document", async () => {
		const stored = fixture("valid-policy.yaml");
		const edited = fixture("rule-name-too-long.yaml");
		expect(localVerdict(edited).ok).toBe(true);
		const mocks = installParityServer(stored);
		mirrorWritesIntoServerStore(mocks);

		renderPolicyRoute();
		await waitFor(() => expect(screen.getByText("✓ Valid policy")).toBeInTheDocument());

		fireEvent.change(yamlEditor(), { target: { value: edited } });
		expect(screen.getByText("✓ Valid policy")).toBeInTheDocument();
		fireEvent.click(saveButton());

		await waitFor(() =>
			expect(screen.getByRole("alert")).toHaveTextContent(/rules\.0\.name:invalid_string/),
		);
		expect(screen.queryByText("Policy saved successfully")).not.toBeInTheDocument();
		// The draft reached the compiler, was refused, and the previous document
		// is what remains stored.
		expect(serverStore.content).toBe(stored);
		expect(mocks.teamPolicies.update).toHaveBeenNthCalledWith(
			1,
			expect.objectContaining({ content: edited }),
		);
		expect(mocks.teamPolicies.update).toHaveBeenNthCalledWith(
			2,
			expect.objectContaining({ content: stored }),
		);
		expect(mocks.teamPolicies.insert).not.toHaveBeenCalled();
	});
});
