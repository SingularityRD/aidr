// @vitest-environment jsdom

// The tenant DLP policy editor's contract.
//
// Three things are pinned here:
//
//   1. The approval boundary. A DLP `ask` action is a block pending approval by
//      a human operator OUT OF BAND (CLAUDE.md). The model receives the
//      `actionId` in the block reason, so any agent-callable approval would let
//      a prompt-injected agent approve its own block. This editor must expose no
//      approve/resolve/allow/dismiss control anywhere, must say that `ask` is
//      resolved out of band, and must reach the backend through the two DLP
//      invoke actions only.
//
//   2. The schema mirror. `validateDlpPolicyDocument` in dlp-editor.tsx mirrors
//      the engine's `DlpPolicySchema`. Rather than trusting that claim, the
//      table below drives both the mirror and the real
//      `packages/core/src/dlp/policy.ts` schema over the same documents and
//      requires the same verdict and the same normalised output.
//
//   3. Honest persistence. The dashboard ships no DLP store: the
//      `policy-management` seam rejects actions it does not implement. When that
//      happens the editor says the policy is not available and disables
//      publishing; it never reports a save the function did not confirm.

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

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

import {
	DLP_EXPIRED_EXCEPTION_DOMINANCE,
	DLP_PUBLISH_ACTION,
	DLP_READ_ACTION,
	DlpPolicyEditor,
	createStarterDlpPolicy,
	serializeDlpPolicy,
	validateDlpPolicyDocument,
} from "../enterprise/dlp-editor";
import { TeamProvider } from "../enterprise/team-provider";
import {
	ADMIN_USER_ID,
	installDashboardMocks,
	type InstalledMocks,
	TEAM_ID,
} from "./helpers/dashboard-mocks";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const EDITOR_SOURCE = readFileSync(
	resolve(REPO_ROOT, "packages/dashboard/src/enterprise/dlp-editor.tsx"),
	"utf8",
);

const VALID_FINGERPRINT = "b".repeat(64);
const INVALID_FINGERPRINT = "not-a-sha256";
const FUTURE_EXPIRY = "2999-01-01T00:00:00.000Z";
const PAST_EXPIRY = "2001-01-01T00:00:00.000Z";

/**
 * The engine's real `DlpPolicySchema`, loaded by path from this Node-side test.
 *
 * The dashboard package deliberately does not depend on `@singularityrd/aidr-core`,
 * and its `tsconfig` sets `rootDir` to the package, so a static cross-package
 * import would be a TS6059 build error. A computed specifier keeps the engine
 * schema out of the dashboard's TypeScript program while letting the test drive it.
 */
interface CorePolicySchema {
	safeParse(input: unknown): { success: boolean; data?: unknown };
}

interface CoreDlpModule {
	DlpPolicySchema: CorePolicySchema;
	DLP_EXPIRED_EXCEPTION_DOMINANCE: string;
}

async function loadCoreDlpModule(): Promise<CoreDlpModule> {
	const specifier = "../../../core/src/dlp/policy.js";
	return (await import(/* @vite-ignore */ specifier)) as CoreDlpModule;
}

function storedDlpPolicy(overrides: Record<string, unknown> = {}): Record<string, unknown> {
	return {
		version: 3,
		tenantId: TEAM_ID,
		maxContentBytes: 4096,
		supportedFormats: ["text/*", "application/json"],
		unavailableAction: "block",
		labels: [
			{
				id: "label-employee-id",
				tenantId: TEAM_ID,
				name: "Employee ID",
				description: "Payroll identifier",
				sensitivity: "confidential",
				redactionToken: "[EMPLOYEE-ID]",
			},
			{
				id: "label-project",
				tenantId: TEAM_ID,
				name: "Project codename",
				sensitivity: "restricted",
				redactionToken: "[REDACTED]",
			},
		],
		rules: [
			{
				id: "rule-employee-id",
				tenantId: TEAM_ID,
				labelId: "label-employee-id",
				name: "Employee identifier",
				enabled: true,
				priority: 100,
				directions: ["input", "output"],
				action: "redact",
				matchMode: "any",
				matchers: [{ type: "regex", pattern: "EMP-[0-9]{6}", flags: "i" }],
			},
			{
				id: "rule-project-codename",
				tenantId: TEAM_ID,
				labelId: "label-project",
				name: "Project codename",
				enabled: true,
				priority: 50,
				directions: ["output"],
				action: "block",
				matchMode: "all",
				matchers: [
					{ type: "keyword", values: ["Project Atlas"], caseSensitive: false, wholeWord: true },
					{ type: "keyword", values: ["atlas"], caseSensitive: true, wholeWord: false },
				],
			},
		],
		exceptions: [
			{
				id: "exception-false-positive",
				tenantId: TEAM_ID,
				ruleId: "rule-employee-id",
				ownerId: ADMIN_USER_ID,
				justification: "Documented false positive for the payroll feed",
				scope: "rule",
				expiresAt: FUTURE_EXPIRY,
			},
		],
		...overrides,
	};
}

function ruleWith(overrides: Record<string, unknown>): Record<string, unknown>[] {
	const policy = storedDlpPolicy();
	return [{ ...(policy.rules as Record<string, unknown>[])[0], ...overrides }];
}

interface InvokeResponse {
	data: unknown;
	error: { message: string } | null;
}

/** Install the shared dashboard mocks, then route the DLP seam explicitly. */
function installDlpMocks(
	options: { read?: InvokeResponse; publish?: InvokeResponse } = {},
): InstalledMocks {
	const mocks = installDashboardMocks({ role: "admin" });
	mocks.invoke.mockImplementation(
		async (name: string, request?: { body?: { action?: string } }) => {
			if (name !== "policy-management") return { data: { ok: true }, error: null };
			if (request?.body?.action === DLP_READ_ACTION) {
				return options.read ?? { data: { ok: true, policy: null, version: 0 }, error: null };
			}
			if (request?.body?.action === DLP_PUBLISH_ACTION) {
				return options.publish ?? { data: { ok: true, version: 4 }, error: null };
			}
			// The real function refuses any action outside its own set.
			return { data: null, error: { message: "invalid_action" } };
		},
	);
	return mocks;
}

function renderDlpEditor() {
	return render(
		<TeamProvider>
			<DlpPolicyEditor />
		</TeamProvider>,
	);
}

function readInvoke(): InvokeResponse {
	return { data: { ok: true, policy: storedDlpPolicy(), version: 3 }, error: null };
}

function publishCalls(mocks: InstalledMocks) {
	return mocks.invoke.mock.calls.filter(
		([, request]) => request?.body?.action === DLP_PUBLISH_ACTION,
	);
}

async function renderLoadedEditor(
	mocks: InstalledMocks = installDlpMocks({ read: readInvoke() }),
): Promise<InstalledMocks> {
	renderDlpEditor();
	await waitFor(() => expect(screen.getByText("✓ Valid DLP policy")).toBeInTheDocument());
	return mocks;
}

describe("DLP policy editor approval boundary", () => {
	afterEach(cleanup);

	it("exposes no approval action and states that ask is resolved out of band", async () => {
		await renderLoadedEditor();

		// The out-of-band statement is rendered, not implied.
		expect(screen.getByText(/ask is resolved out of band/i)).toBeInTheDocument();
		expect(
			screen.getByText(/no approve, resolve, allow or dismiss control/i),
		).toBeInTheDocument();

		// No control anywhere offers to approve or resolve a block.
		const approvalControl = /approve|approval|resolve|grant|authorize|dismiss|waive|unblock|permit/i;
		const controls = [
			...screen.queryAllByRole("button"),
			...screen.queryAllByRole("combobox"),
			...screen.queryAllByRole("textbox"),
			...screen.queryAllByRole("checkbox"),
		];
		expect(controls.length).toBeGreaterThan(0);
		for (const control of controls) {
			expect(control).not.toHaveAccessibleName(approvalControl);
		}

		// No selectable value is an approval either.
		const optionValues = [...document.querySelectorAll("option")].map((option) => option.value);
		expect(optionValues.length).toBeGreaterThan(0);
		for (const value of optionValues) {
			expect(value).not.toMatch(/approve|resolve|allow|grant|authorize|dismiss|waive|permit/i);
		}

		// `ask` is offered as an authoring action whose label states the boundary.
		expect(
			within(screen.getByLabelText("Rule 1 action")).getByText(
				"ask (block pending out-of-band operator approval)",
			),
		).toBeInTheDocument();

		// Source-level guard: the editor reaches the backend through exactly the
		// two DLP actions, and no action identifier is an approval.
		expect([...EDITOR_SOURCE.matchAll(/supabase\.functions\.invoke\(/g)]).toHaveLength(2);
		expect(EDITOR_SOURCE).toContain("action: DLP_READ_ACTION");
		expect(EDITOR_SOURCE).toContain("action: DLP_PUBLISH_ACTION");
		expect(EDITOR_SOURCE).not.toMatch(/["'](approve|resolve|allow|grant|authorize|dismiss|waive)["']/i);
	});
});

describe("DLP policy editor persistence", () => {
	afterEach(cleanup);

	it("reports DLP policy storage as not available instead of pretending to save", async () => {
		const mocks = installDlpMocks({
			read: { data: null, error: { message: "Edge Function returned a non-2xx status code" } },
		});

		renderDlpEditor();

		await waitFor(() =>
			expect(
				screen.getByText(/DLP policy storage is not available in this deployment/i),
			).toBeInTheDocument(),
		);
		expect(screen.getByText(/Nothing authored below is stored or published/i)).toBeInTheDocument();

		// Authoring and validation still work locally...
		expect(screen.getByRole("button", { name: "Add label" })).toBeInTheDocument();
		expect(screen.getByText("✓ Valid DLP policy")).toBeInTheDocument();
		expect(screen.getByText(/not stored/)).toBeInTheDocument();

		// ...and the only artifact is a document the engine's own schema accepts.
		const json = (
			screen.getByRole("textbox", { name: "DLP policy document (JSON)" }) as HTMLTextAreaElement
		).value;
		const { DlpPolicySchema } = await loadCoreDlpModule();
		expect(DlpPolicySchema.safeParse(JSON.parse(json)).success).toBe(true);

		// Publishing is disabled, and clicking it writes nothing.
		const publish = screen.getByRole("button", { name: "Publish DLP policy" });
		expect(publish).toBeDisabled();
		fireEvent.click(publish);
		expect(publishCalls(mocks)).toHaveLength(0);
		expect(screen.queryByText(/published for this tenant/)).not.toBeInTheDocument();

		// Exactly one read attempt; nothing was written.
		expect(mocks.invoke.mock.calls.map(([, request]) => request?.body?.action)).toEqual([
			DLP_READ_ACTION,
		]);
	});

	it("refuses to author over a stored policy the engine rejects", async () => {
		const mocks = installDlpMocks({
			read: {
				data: { ok: true, policy: storedDlpPolicy({ labels: [] }), version: 3 },
				error: null,
			},
		});

		renderDlpEditor();

		await waitFor(() =>
			expect(screen.getByText(/The stored DLP policy could not be read/i)).toBeInTheDocument(),
		);
		expect(screen.getByRole("alert")).toHaveTextContent(/labels/);
		expect(
			screen.getByText(/Publishing stays disabled so this cannot overwrite it/i),
		).toBeInTheDocument();
		expect(
			screen.queryByRole("textbox", { name: "DLP policy document (JSON)" }),
		).not.toBeInTheDocument();
		expect(screen.queryByRole("button", { name: "Publish DLP policy" })).not.toBeInTheDocument();
		expect(publishCalls(mocks)).toHaveLength(0);
	});

	it("round-trips a valid stored policy through the invoke seam into the engine schema", async () => {
		const stored = storedDlpPolicy();
		const mocks = installDlpMocks({
			read: { data: { ok: true, policy: stored, version: 3 }, error: null },
			publish: { data: { ok: true, version: 4 }, error: null },
		});

		await renderLoadedEditor(mocks);

		// What the editor renders is the stored document, key for key.
		const json = (
			screen.getByRole("textbox", { name: "DLP policy document (JSON)" }) as HTMLTextAreaElement
		).value;
		expect(JSON.parse(json)).toStrictEqual(stored);

		fireEvent.click(screen.getByRole("button", { name: "Publish DLP policy" }));

		await waitFor(() =>
			expect(
				screen.getByText("DLP policy version 4 published for this tenant."),
			).toBeInTheDocument(),
		);

		const calls = publishCalls(mocks);
		expect(calls).toHaveLength(1);
		expect(calls[0]?.[0]).toBe("policy-management");
		const body = calls[0]?.[1]?.body;
		expect(body).toMatchObject({
			action: DLP_PUBLISH_ACTION,
			tenant_id: TEAM_ID,
			expected_version: 3,
		});
		expect(body.policy).toStrictEqual(stored);

		// The engine's own schema accepts exactly what was published.
		const { DlpPolicySchema } = await loadCoreDlpModule();
		expect(
			DlpPolicySchema.safeParse(body.policy).success,
			"the published document is refused by the engine's DlpPolicySchema",
		).toBe(true);
	});

	it("refuses an invalid label and refuses to publish it", async () => {
		const mocks = await renderLoadedEditor();

		fireEvent.change(screen.getByLabelText("Label 1 id"), {
			target: { value: "-not-an-identifier" },
		});

		expect(screen.getByText("✗ Invalid DLP policy")).toBeInTheDocument();
		expect(screen.getByRole("alert")).toHaveTextContent(/labels\.0\.id/);
		const publish = screen.getByRole("button", { name: "Publish DLP policy" });
		expect(publish).toBeDisabled();
		fireEvent.click(publish);
		expect(publishCalls(mocks)).toHaveLength(0);
	});

	it("refuses an invalid rule and refuses to publish it", async () => {
		const mocks = await renderLoadedEditor();

		fireEvent.change(screen.getByLabelText("Rule 1 priority"), { target: { value: "10001" } });

		expect(screen.getByText("✗ Invalid DLP policy")).toBeInTheDocument();
		expect(screen.getByRole("alert")).toHaveTextContent(/rules\.0\.priority/);
		fireEvent.click(screen.getByRole("button", { name: "Publish DLP policy" }));
		expect(publishCalls(mocks)).toHaveLength(0);
	});

	it("refuses an invalid exception and refuses to publish it", async () => {
		const mocks = await renderLoadedEditor();

		// A rule-scope exception must carry no fingerprint; content scope requires
		// one. Switching scope therefore invalidates the record until the operator
		// supplies the SHA-256 digest the schema demands.
		fireEvent.change(screen.getByLabelText("Exception 1 scope"), { target: { value: "content" } });

		expect(screen.getByText("✗ Invalid DLP policy")).toBeInTheDocument();
		expect(screen.getByRole("alert")).toHaveTextContent(/exceptions\.0\.fingerprint/);
		fireEvent.click(screen.getByRole("button", { name: "Publish DLP policy" }));
		expect(publishCalls(mocks)).toHaveLength(0);

		fireEvent.change(screen.getByLabelText("Exception 1 fingerprint"), {
			target: { value: VALID_FINGERPRINT },
		});
		expect(screen.getByText("✓ Valid DLP policy")).toBeInTheDocument();
	});

	it("never reports a publish the function rejected", async () => {
		const mocks = installDlpMocks({
			read: readInvoke(),
			publish: { data: null, error: { message: "invalid_action" } },
		});
		await renderLoadedEditor(mocks);

		fireEvent.click(screen.getByRole("button", { name: "Publish DLP policy" }));

		await waitFor(() =>
			expect(screen.getByRole("alert")).toHaveTextContent(
				/DLP policy was not published: invalid_action/,
			),
		);
		expect(screen.queryByText(/published for this tenant/)).not.toBeInTheDocument();
	});

	it("never reports a publish the function did not confirm", async () => {
		const mocks = installDlpMocks({
			read: readInvoke(),
			publish: { data: { ok: true }, error: null },
		});
		await renderLoadedEditor(mocks);

		fireEvent.click(screen.getByRole("button", { name: "Publish DLP policy" }));

		await waitFor(() =>
			expect(screen.getByRole("alert")).toHaveTextContent(
				/did not confirm a stored DLP policy version/,
			),
		);
		expect(screen.queryByText(/published for this tenant/)).not.toBeInTheDocument();
	});
});

describe("DLP policy schema mirror", () => {
	afterEach(cleanup);

	/** Each case is checked against `DlpPolicySchema` as well as the mirror. */
	const DOCUMENTS: Array<[name: string, document: unknown]> = [
		["a tenant policy with explicit fields", storedDlpPolicy()],
		["a minimal policy that relies on schema defaults", {
			version: 1,
			tenantId: "tenant-acme",
			labels: [{ id: "label-a", tenantId: "tenant-acme", name: "A", sensitivity: "public" }],
			rules: [
				{
					id: "rule-a",
					tenantId: "tenant-acme",
					labelId: "label-a",
					name: "A rule",
					action: "block",
					matchers: [{ type: "keyword", values: ["x"] }],
				},
			],
		}],
		["transformed names, media types and empty regex flags", {
			version: 1,
			tenantId: "tenant-acme",
			supportedFormats: ["TEXT/PLAIN", "Application/*"],
			labels: [
				{
					id: "label-a",
					tenantId: "tenant-acme",
					name: "  Padded name  ",
					description: "  padded  ",
					sensitivity: "internal",
				},
			],
			rules: [
				{
					id: "rule-a",
					tenantId: "tenant-acme",
					labelId: "label-a",
					name: "  Rule  ",
					action: "ask",
					matchers: [{ type: "regex", pattern: "EMP-[0-9]{6}", flags: "" }],
				},
			],
		}],
		["exceptions in every scope", storedDlpPolicy({
			exceptions: [
				{
					id: "exception-rule",
					tenantId: TEAM_ID,
					ruleId: "rule-employee-id",
					ownerId: ADMIN_USER_ID,
					justification: "Whole-rule false positive",
					scope: "rule",
					expiresAt: FUTURE_EXPIRY,
					createdAt: "2026-01-01T00:00:00.000Z",
				},
				{
					id: "exception-content",
					tenantId: TEAM_ID,
					ruleId: "rule-employee-id",
					ownerId: ADMIN_USER_ID,
					justification: "One document is a fixture",
					scope: "content",
					fingerprint: VALID_FINGERPRINT,
					expiresAt: FUTURE_EXPIRY,
				},
				{
					id: "exception-match",
					tenantId: TEAM_ID,
					ruleId: "rule-employee-id",
					ownerId: ADMIN_USER_ID,
					justification: "One known value is a fixture",
					scope: "match",
					fingerprint: VALID_FINGERPRINT,
					expiresAt: FUTURE_EXPIRY,
				},
			],
		})],
		["a single expired exception that the scanner prunes", storedDlpPolicy({
			exceptions: [
				{
					id: "exception-expired",
					tenantId: TEAM_ID,
					ruleId: "rule-employee-id",
					ownerId: ADMIN_USER_ID,
					justification: "Kept for the audit trail",
					scope: "rule",
					expiresAt: PAST_EXPIRY,
				},
			],
		})],
		["a disabled rule limited to one direction", storedDlpPolicy({
			rules: ruleWith({ enabled: false, directions: ["output"], matchMode: "all" }),
		})],

		["an unknown policy field", storedDlpPolicy({ retention_days: 30 })],
		["a zero version", storedDlpPolicy({ version: 0 })],
		["a string version", storedDlpPolicy({ version: "3" })],
		["no labels", storedDlpPolicy({ labels: [] })],
		["an unsupported label sensitivity", storedDlpPolicy({
			labels: [{ ...(storedDlpPolicy().labels as Record<string, unknown>[])[0], sensitivity: "secret" }],
		})],
		["a label owned by another tenant", storedDlpPolicy({
			labels: [{ ...(storedDlpPolicy().labels as Record<string, unknown>[])[0], tenantId: "tenant-other" }],
		})],
		["duplicate label ids", storedDlpPolicy({
			labels: [
				(storedDlpPolicy().labels as Record<string, unknown>[])[0],
				{ ...(storedDlpPolicy().labels as Record<string, unknown>[])[1], id: "label-employee-id" },
			],
		})],
		["a label with an unknown field", storedDlpPolicy({
			labels: [{ ...(storedDlpPolicy().labels as Record<string, unknown>[])[0], retention: 7 }],
		})],
		["a rule above the priority ceiling", storedDlpPolicy({ rules: ruleWith({ priority: 10_001 }) })],
		["a rule with no matchers", storedDlpPolicy({ rules: ruleWith({ matchers: [] }) })],
		["a rule with no directions", storedDlpPolicy({ rules: ruleWith({ directions: [] }) })],
		["a rule direction outside input/output", storedDlpPolicy({
			rules: ruleWith({ directions: ["both"] }),
		})],
		["a regex matcher that matches an empty string", storedDlpPolicy({
			rules: ruleWith({ matchers: [{ type: "regex", pattern: "a*", flags: "i" }] }),
		})],
		["a high-risk regular expression", storedDlpPolicy({
			rules: ruleWith({ matchers: [{ type: "regex", pattern: "(a+)+", flags: "i" }] }),
		})],
		["regex flags outside i, m, s, u", storedDlpPolicy({
			rules: ruleWith({ matchers: [{ type: "regex", pattern: "EMP-[0-9]{6}", flags: "g" }] }),
		})],
		["duplicate regex flags", storedDlpPolicy({
			rules: ruleWith({ matchers: [{ type: "regex", pattern: "EMP-[0-9]{6}", flags: "ii" }] }),
		})],
		["a keyword matcher with no values", storedDlpPolicy({
			rules: ruleWith({ matchers: [{ type: "keyword", values: [], wholeWord: true }] }),
		})],
		["a keyword matcher with an empty keyword", storedDlpPolicy({
			rules: ruleWith({ matchers: [{ type: "keyword", values: [""] }] }),
		})],
		["an unknown matcher type", storedDlpPolicy({
			rules: ruleWith({ matchers: [{ type: "glob", values: ["x"] }] }),
		})],
		["a rule referencing a label outside the policy", storedDlpPolicy({
			rules: ruleWith({ labelId: "label-missing" }),
		})],
		["a rule owned by another tenant", storedDlpPolicy({
			rules: ruleWith({ tenantId: "tenant-other" }),
		})],
		["a rule with an unknown field", storedDlpPolicy({ rules: ruleWith({ severity: "high" }) })],
		["an unsupported unavailableAction", storedDlpPolicy({ unavailableAction: "allow" })],
		["a supported format that is not a media type", storedDlpPolicy({
			supportedFormats: ["text"],
		})],
		["maxContentBytes below the floor", storedDlpPolicy({ maxContentBytes: 0 })],
		["exceptions that are not a list", storedDlpPolicy({ exceptions: null })],
		["a rule-scope exception carrying a fingerprint", storedDlpPolicy({
			exceptions: [
				{
					id: "exception-rule",
					tenantId: TEAM_ID,
					ruleId: "rule-employee-id",
					ownerId: ADMIN_USER_ID,
					justification: "Wrong scope for a fingerprint",
					scope: "rule",
					fingerprint: VALID_FINGERPRINT,
					expiresAt: FUTURE_EXPIRY,
				},
			],
		})],
		["a content-scope exception without a fingerprint", storedDlpPolicy({
			exceptions: [
				{
					id: "exception-content",
					tenantId: TEAM_ID,
					ruleId: "rule-employee-id",
					ownerId: ADMIN_USER_ID,
					justification: "Missing the digest the scope requires",
					scope: "content",
					expiresAt: FUTURE_EXPIRY,
				},
			],
		})],
		["an exception fingerprint that is not a SHA-256 digest", storedDlpPolicy({
			exceptions: [
				{
					id: "exception-content",
					tenantId: TEAM_ID,
					ruleId: "rule-employee-id",
					ownerId: ADMIN_USER_ID,
					justification: "Malformed digest",
					scope: "content",
					fingerprint: INVALID_FINGERPRINT,
					expiresAt: FUTURE_EXPIRY,
				},
			],
		})],
		["an exception whose expiry is not an ISO timestamp", storedDlpPolicy({
			exceptions: [
				{
					id: "exception-rule",
					tenantId: TEAM_ID,
					ruleId: "rule-employee-id",
					ownerId: ADMIN_USER_ID,
					justification: "Date only",
					scope: "rule",
					expiresAt: "2999-01-01",
				},
			],
		})],
		["an exception created after it expires", storedDlpPolicy({
			exceptions: [
				{
					id: "exception-rule",
					tenantId: TEAM_ID,
					ruleId: "rule-employee-id",
					ownerId: ADMIN_USER_ID,
					justification: "Window inverted",
					scope: "rule",
					expiresAt: FUTURE_EXPIRY,
					createdAt: "3000-01-01T00:00:00.000Z",
				},
			],
		})],
		["an exception referencing a rule outside the policy", storedDlpPolicy({
			exceptions: [
				{
					id: "exception-rule",
					tenantId: TEAM_ID,
					ruleId: "rule-missing",
					ownerId: ADMIN_USER_ID,
					justification: "Unknown rule",
					scope: "rule",
					expiresAt: FUTURE_EXPIRY,
				},
			],
		})],
		["an exception list dominated by expired records", storedDlpPolicy({
			exceptions: [
				{
					id: "exception-expired-a",
					tenantId: TEAM_ID,
					ruleId: "rule-employee-id",
					ownerId: ADMIN_USER_ID,
					justification: "Rotting archive entry",
					scope: "rule",
					expiresAt: PAST_EXPIRY,
				},
				{
					id: "exception-expired-b",
					tenantId: TEAM_ID,
					ruleId: "rule-employee-id",
					ownerId: ADMIN_USER_ID,
					justification: "Rotting archive entry",
					scope: "rule",
					expiresAt: PAST_EXPIRY,
				},
			],
		})],
	];

	it("agrees with the engine's DlpPolicySchema on valid and invalid documents", async () => {
		const core = await loadCoreDlpModule();
		expect(core.DLP_EXPIRED_EXCEPTION_DOMINANCE).toBe(DLP_EXPIRED_EXCEPTION_DOMINANCE);

		for (const [name, document] of DOCUMENTS) {
			const mine = validateDlpPolicyDocument(document);
			const theirs = core.DlpPolicySchema.safeParse(document);
			expect(mine.ok, `${name}: the editor and DlpPolicySchema disagree`).toBe(theirs.success);
			if (mine.ok && theirs.success) {
				expect(
					mine.policy,
					`${name}: the normalised document differs from DlpPolicySchema.parse`,
				).toStrictEqual(theirs.data);
			}
		}
	});

	it("names the engine's expired-exception dominance refusal", () => {
		const result = validateDlpPolicyDocument(
			storedDlpPolicy({
				exceptions: [
					{
						id: "exception-expired-a",
						tenantId: TEAM_ID,
						ruleId: "rule-employee-id",
						ownerId: ADMIN_USER_ID,
						justification: "Expired",
						scope: "rule",
						expiresAt: PAST_EXPIRY,
					},
					{
						id: "exception-expired-b",
						tenantId: TEAM_ID,
						ruleId: "rule-employee-id",
						ownerId: ADMIN_USER_ID,
						justification: "Expired",
						scope: "rule",
						expiresAt: PAST_EXPIRY,
					},
				],
			}),
		);
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.issues.map((issue) => issue.message).join("\n")).toContain(
			DLP_EXPIRED_EXCEPTION_DOMINANCE,
		);
	});

	it("round-trips a validated document through serialization", () => {
		const starter = createStarterDlpPolicy(TEAM_ID);
		const first = validateDlpPolicyDocument(starter);
		expect(first.ok, "the starter policy is not valid").toBe(true);
		if (!first.ok) return;

		const second = validateDlpPolicyDocument(JSON.parse(serializeDlpPolicy(first.policy)));
		expect(second).toStrictEqual(first);
	});
});
