// @vitest-environment jsdom

// B1 — the YAML policy document editor must submit exact draft bytes to the
// compiler that enforces them, not store locally validated bytes first.
//
// The local validator is weaker than `compileRuntimePolicyDocument`: the server
// also bounds rule names, descriptions and rule counts. This suite compares the
// local verdict with the real shared compiler through `save_document_draft`.
// The invocation double compiles submitted bytes before changing serverStore;
// refused drafts never become stored policy and need no client-side rollback.

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
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

import { saveDocumentDraft, validateDocument } from "../enterprise/policy-editor";
import { AppLayout } from "../ui/AppLayout";
import { PolicyPage } from "../ui/pages/PolicyPage";
import {
	EMPTY_AGENT_PROFILE_REPLIES,
	installDashboardMocks,
	POLICY_ROW_ID,
	TEAM_ID,
} from "./helpers/dashboard-mocks";

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
	const specifier = pathToFileURL(
		resolve(
			dirname(fileURLToPath(import.meta.url)),
			"../../../../supabase/functions/_shared/policy-document.ts",
		),
	).href;
	return (await import(specifier)) as unknown as ServerCompiler;
}

/** The Deno `yaml` parser the handler uses for submitted document bytes. */
async function loadPolicyDocumentParser(): Promise<{
	parseDocument: (
		source: string,
		options: Record<string, unknown>,
	) => {
		errors: Array<{ message?: string }>;
		toJS: (options: Record<string, unknown>) => unknown;
	};
}> {
	const specifier = pathToFileURL(
		resolve(
			dirname(fileURLToPath(import.meta.url)),
			"../../../core/node_modules/yaml/dist/index.js",
		),
	).href;
	const loaded = (await import(specifier)) as unknown as {
		parseDocument?: unknown;
		default?: { parseDocument?: unknown };
	};
	const parseDocument = loaded.parseDocument ?? loaded.default?.parseDocument;
	if (typeof parseDocument !== "function")
		throw new Error("the server's yaml parser is unavailable");
	return { parseDocument } as Awaited<ReturnType<typeof loadPolicyDocumentParser>>;
}

interface ExpectedDocument {
	id: string;
	version: number;
	source_sha256: string;
}

function sourceHash(content: string): string {
	return createHash("sha256").update(content).digest("hex");
}

function expectedDocument(content: string, version = 1): ExpectedDocument {
	return { id: POLICY_ROW_ID, version, source_sha256: sourceHash(content) };
}

/** Only a successful server-side compile may change the stored document. */
const serverStore: { content: string | null; version: number; writes: number } = {
	content: null,
	version: 0,
	writes: 0,
};

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
 * Compile and simulate submitted bytes with the real compiler, then save them.
 * No compiler rules are duplicated here and refusals perform zero store writes.
 */
async function compileAndSaveDraft(
	content: string,
	simulation: unknown,
): Promise<{ data: unknown; error: unknown }> {
	const [{ parseDocument }, compiler] = await Promise.all([
		loadPolicyDocumentParser(),
		loadServerCompiler(),
	]);
	try {
		const parsed = parseDocument(content, {
			schema: "core",
			uniqueKeys: true,
			prettyErrors: false,
		});
		if (parsed.errors.length > 0) {
			throw new Error(`invalid_policy_yaml:${parsed.errors[0]?.message ?? "parse_error"}`);
		}
		const document = parsed.toJS({ maxAliasCount: 0 });
		const compilation = compiler.compileRuntimePolicyDocument(document);
		const result =
			simulation === undefined
				? null
				: compiler.simulateCompiledRuntimePolicy(compilation.runtime_policy, simulation);
		const source = {
			...expectedDocument(content, serverStore.version + 1),
			updated_at: STORED_AT,
		};
		serverStore.content = content;
		serverStore.version = source.version;
		serverStore.writes += 1;
		return {
			data: {
				ok: true,
				source,
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
function policyManagementResponse(request?: {
	body?: { action?: string; content?: string; simulation?: unknown };
}) {
	const body = request?.body ?? {};
	switch (body.action) {
		case "read":
			return { data: { ok: true, version: 0, policy: null }, error: null };
		case "history":
			return { data: { ok: true, revisions: [], truncated: false }, error: null };
		case "adoption":
			return { data: { ok: true, agents: [], truncated: false }, error: null };
		case "rollout_progress":
			return {
				data: {
					ok: true,
					status: "none",
					version: null,
					rollout_progress: { targeted: 0, current: 0, stale: 0, outdated: 0, unknown: 0 },
				},
				error: null,
			};
		case "save_document_draft":
			if (typeof body.content !== "string") return refusedResponse("invalid_policy_document");
			return compileAndSaveDraft(body.content, body.simulation);
		case "read_agent_profiles":
		case "agent_profile_history":
			return EMPTY_AGENT_PROFILE_REPLIES[body.action];
		default:
			return refusedResponse("unsupported_action");
	}
}

function installParityServer(storedYaml: string | null) {
	serverStore.content = storedYaml;
	serverStore.version = storedYaml === null ? 0 : 1;
	serverStore.writes = 0;
	const mocks = installDashboardMocks({
		role: "admin",
		policyRow:
			storedYaml === null
				? null
				: { id: POLICY_ROW_ID, content: storedYaml, updated_at: STORED_AT },
	});
	const authenticatedIdentity = mocks.invoke.getMockImplementation() as (
		name: string,
		request?: unknown,
	) => Promise<unknown>;
	mocks.invoke.mockImplementation(
		async (
			name: string,
			request?: {
				body?: { action?: string; content?: string; simulation?: unknown };
			},
		) => {
			if (name === "identity-security") return authenticatedIdentity(name, request);
			if (name === "policy-management") return policyManagementResponse(request);
			return { data: { ok: true }, error: null };
		},
	);
	return mocks;
}

function expectNoDirectWrites(mocks: ReturnType<typeof installParityServer>) {
	expect(mocks.teamPolicies.insert).not.toHaveBeenCalled();
	expect(mocks.teamPolicies.update).not.toHaveBeenCalled();
	expect(mocks.teamPolicies.delete).not.toHaveBeenCalled();
}

function expectDraftRequest(
	mocks: ReturnType<typeof installParityServer>,
	content: string,
	expected: ExpectedDocument | null,
) {
	const saveCalls = mocks.invoke.mock.calls.filter(
		(call) =>
			call[0] === "policy-management" &&
			(call[1] as { body?: { action?: string } } | undefined)?.body?.action ===
				"save_document_draft",
	);
	expect(saveCalls).toEqual([
		[
			"policy-management",
			{
				body: {
					action: "save_document_draft",
					tenant_id: TEAM_ID,
					content,
					expected_document: expected,
					simulation: {
						kind: "mcp",
						server: "unregistered-preview",
						tool: "call",
						inventory: "unknown",
					},
				},
			},
		],
	]);
	const actions = mocks.invoke.mock.calls
		.filter((call) => call[0] === "policy-management")
		.map((call) => (call[1] as { body?: { action?: string } } | undefined)?.body?.action);
	expect(actions).not.toContain("compile_document");
	expect(actions).not.toContain("compile_document_draft");
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
	serverStore.version = 0;
	serverStore.writes = 0;
});

afterEach(() => {
	cleanup();
	vi.resetAllMocks();
	vi.unstubAllGlobals();
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
			const mocks = installParityServer(null);
			const { verdict: server, source } = await saveDocumentDraft(TEAM_ID, yaml, null);
			expectDraftRequest(mocks, yaml, null);
			expectNoDirectWrites(mocks);
			expect(source).toBeNull();
			expect(serverStore).toEqual({ content: null, version: 0, writes: 0 });
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
		const mocks = installParityServer(null);
		const { verdict: compiled, source } = await saveDocumentDraft(TEAM_ID, accepted, null);
		expectDraftRequest(mocks, accepted, null);
		expectNoDirectWrites(mocks);
		expect(source).toEqual({ ...expectedDocument(accepted), updated_at: STORED_AT });
		expect(serverStore).toEqual({ content: accepted, version: 1, writes: 1 });
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

			// Local acceptance must not bypass the server compiler before persistence.
			expect(localVerdict(yaml).ok, label).toBe(true);

			const stored = fixture("valid-policy.yaml");
			const mocks = installParityServer(stored);
			const expected = expectedDocument(stored);
			const { verdict: server, source } = await saveDocumentDraft(TEAM_ID, yaml, expected);
			expectDraftRequest(mocks, yaml, expected);
			expectNoDirectWrites(mocks);
			expect(source).toBeNull();
			expect(serverStore).toEqual({ content: stored, version: 1, writes: 0 });
			expect(server.status, label).toBe("refused");
			if (server.status !== "refused") continue;
			expect(server.code, label).toBe(testCase.code);
		}
	});

	it("saves exact edited bytes atomically and surfaces the compiler verdict", async () => {
		const stored = fixture("valid-policy.yaml");
		const edited = `${stored}\n# Exact submitted draft bytes: café\n`;
		const mocks = installParityServer(stored);

		renderPolicyRoute();
		await waitFor(() => expect(screen.getByText("✓ Valid policy")).toBeInTheDocument());

		fireEvent.change(yamlEditor(), { target: { value: edited } });
		fireEvent.click(saveButton());

		await waitFor(() => expect(screen.getByText("Policy saved successfully")).toBeInTheDocument());

		expectDraftRequest(mocks, edited, expectedDocument(stored));
		expectNoDirectWrites(mocks);
		expect(serverStore).toEqual({ content: edited, version: 2, writes: 1 });

		// The server's verdict is rendered in the document card.
		expect(screen.getByText("Unsupported fields: none.")).toBeInTheDocument();
		expect(screen.getByText(/Conflict precedence: deny > ask > allow/)).toBeInTheDocument();
		expect(
			screen.getByText(/Simulated unknown MCP call: deny \(mcp_unknown\)/),
		).toBeInTheDocument();
	});

	it("refuses an invalid stored document without rewriting it", async () => {
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
		expectDraftRequest(mocks, tooLong, expectedDocument(tooLong));
		expectNoDirectWrites(mocks);
		expect(serverStore).toEqual({ content: tooLong, version: 1, writes: 0 });

		// The card names what the server refused, next to the local verdict.
		expect(
			screen.getAllByText(/invalid_policy_document:rules\.0\.name:invalid_string/).length,
		).toBeGreaterThan(0);
	});

	it("refuses a first document with zero store writes", async () => {
		const refused = fixture("description-too-long.yaml");
		expect(localVerdict(refused).ok).toBe(true);
		const mocks = installParityServer(null);

		renderPolicyRoute();
		await waitFor(() => expect(screen.getByText("✓ Valid policy")).toBeInTheDocument());

		fireEvent.change(yamlEditor(), { target: { value: refused } });
		fireEvent.click(saveButton());

		await waitFor(() =>
			expect(screen.getByRole("alert")).toHaveTextContent(/description:invalid_string/),
		);
		expect(screen.queryByText("Policy saved successfully")).not.toBeInTheDocument();
		expectDraftRequest(mocks, refused, null);
		expectNoDirectWrites(mocks);
		expect(serverStore).toEqual({ content: null, version: 0, writes: 0 });
		expect(
			screen.getAllByText(/invalid_policy_document:description:invalid_string/).length,
		).toBeGreaterThan(0);
	});

	it("refuses an edited document with zero store writes", async () => {
		const stored = fixture("valid-policy.yaml");
		const edited = fixture("rule-name-too-long.yaml");
		expect(localVerdict(edited).ok).toBe(true);
		const mocks = installParityServer(stored);

		renderPolicyRoute();
		await waitFor(() => expect(screen.getByText("✓ Valid policy")).toBeInTheDocument());

		fireEvent.change(yamlEditor(), { target: { value: edited } });
		expect(screen.getByText("✓ Valid policy")).toBeInTheDocument();
		fireEvent.click(saveButton());

		await waitFor(() =>
			expect(screen.getByRole("alert")).toHaveTextContent(/rules\.0\.name:invalid_string/),
		);
		expect(screen.queryByText("Policy saved successfully")).not.toBeInTheDocument();
		expectDraftRequest(mocks, edited, expectedDocument(stored));
		expectNoDirectWrites(mocks);
		expect(serverStore).toEqual({ content: stored, version: 1, writes: 0 });
	});
});
