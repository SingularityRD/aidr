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
//   3. Honest persistence. The backend confirms a stored revision, never signed
//      delivery. The editor requires saved/not-delivered evidence and an exact
//      versioned policy echo. Failed/unsupported requests never become success;
//      only owners/admins can save, and expired documents need explicit repair.

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import "@testing-library/jest-dom/vitest";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";

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
import * as TeamProviderModule from "../enterprise/team-provider";
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
	const specifier = pathToFileURL(resolve(REPO_ROOT, "packages/core/src/dlp/policy.ts")).href;
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

function deferredResponse() {
	let resolve!: (response: InvokeResponse) => void;
	let reject!: (error: Error) => void;
	const promise = new Promise<InvokeResponse>((fulfill, fail) => { resolve = fulfill; reject = fail; });
	return { promise, resolve, reject };
}

function savedInvoke(policy: Record<string, unknown>): InvokeResponse {
	return {
		data: {
			ok: true, saved: true, delivered: false, delivery_status: "not_delivered",
			policy, version: policy.version, updated_at: "2026-09-16T00:00:00Z",
		},
		error: null,
	};
}

/** Install the shared dashboard mocks, then route the DLP seam explicitly. */
function installDlpMocks(
	options: { read?: InvokeResponse; publish?: InvokeResponse | Promise<InvokeResponse>; role?: string } = {},
): InstalledMocks {
	const mocks = installDashboardMocks({ role: options.role ?? "admin" });
	let persisted: InvokeResponse | undefined;
	const identityInvoke = mocks.invoke.getMockImplementation() as
		| ((name: string, request?: unknown) => Promise<InvokeResponse>)
		| undefined;
	// The observation spy excludes only identity bootstrap/status calls; every
	// policy/non-identity call remains observable by the unchanged assertions.
	// The real provider's gate receives the shared authenticated fixtures.
	const editorInvoke = vi.fn(
		async (name: string, request?: { body?: { action?: string; expected_version?: number; policy?: unknown } }) => {
			if (name !== "policy-management") return { data: { ok: true }, error: null };
			if (request?.body?.action === DLP_READ_ACTION) {
				return persisted ?? options.read ?? { data: { ok: true, policy: null, version: 0 }, error: null };
			}
			if (request?.body?.action === DLP_PUBLISH_ACTION) {
				if (options.publish) return options.publish;
				const validation = validateDlpPolicyDocument(request.body.policy);
				if (!validation.ok) throw new Error("mock backend refused invalid schema");
				persisted = savedInvoke({ ...validation.policy, version: Number(request.body.expected_version) + 1 });
				return persisted;
			}
			// The real function refuses any action outside its own set.
			return { data: null, error: { message: "invalid_action" } };
		},
	);
	mocks.invoke.mockImplementation((name: string, request?: { body?: { action?: string } }) => {
		if (name === "identity-security" && ["bootstrap", "status"].includes(request?.body?.action ?? "")) {
			if (!identityInvoke) throw new Error("Missing shared identity fixture");
			return identityInvoke(name, request);
		}
		return editorInvoke(name, request);
	});
	return { ...mocks, invoke: editorInvoke };
}

function renderDlpEditor() {
	return render(
		<MemoryRouter>
			<TeamProvider>
				<DlpPolicyEditor />
			</TeamProvider>
		</MemoryRouter>,
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
		expect(screen.getByText(/Current managed connector hooks inspect tool input before execution only/i)).toBeInTheDocument();
		expect(screen.getByText(/output-direction rules are not enforced there/i)).toBeInTheDocument();
		expect(screen.getByText(/a redact match is blocked rather than rewriting the original input/i)).toBeInTheDocument();

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
		expect(screen.getByText(/Nothing authored below is stored or delivered/i)).toBeInTheDocument();

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
		const publish = screen.getByRole("button", { name: "Save DLP policy" });
		expect(publish).toBeDisabled();
		fireEvent.click(publish);
		expect(publishCalls(mocks)).toHaveLength(0);
		expect(screen.queryByText(/saved for this tenant/)).not.toBeInTheDocument();

		// Exactly one read attempt; nothing was written.
		expect(mocks.invoke.mock.calls.map(([, request]) => request?.body?.action)).toEqual([
			DLP_READ_ACTION,
		]);
	});

	it("offers MFA step-up on mfa_required instead of misreporting missing storage", async () => {
		const mocks = installDlpMocks({
			read: {
				data: null,
				error: Object.assign(new Error("Edge Function returned a non-2xx status code"), {
					context: new Response(JSON.stringify({ error: "mfa_required" }), { status: 403 }),
				}),
			},
		});
		renderDlpEditor();
		await waitFor(() =>
			expect(screen.getByRole("alert")).toHaveTextContent("Multi-factor authentication is required"),
		);
		expect(screen.getByRole("link", { name: "Verify with authenticator" })).toHaveAttribute(
			"href",
			"/auth/dlp-step-up?tenant=11111111-1111-4111-8111-111111111111",
		);
		expect(screen.queryByText(/DLP policy storage is not available/)).not.toBeInTheDocument();
		expect(screen.queryByRole("button", { name: "Save DLP policy" })).not.toBeInTheDocument();
		expect(publishCalls(mocks)).toHaveLength(0);
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
			screen.getByText(/Saving stays disabled so this cannot overwrite it/i),
		).toBeInTheDocument();
		expect(
			screen.queryByRole("textbox", { name: "DLP policy document (JSON)" }),
		).not.toBeInTheDocument();
		expect(screen.queryByRole("button", { name: "Save DLP policy" })).not.toBeInTheDocument();
		expect(publishCalls(mocks)).toHaveLength(0);
	});

	it("round-trips a valid stored policy through the invoke seam into the engine schema", async () => {
		const stored = storedDlpPolicy();
		const mocks = installDlpMocks({
			read: { data: { ok: true, policy: stored, version: 3 }, error: null },
		});

		await renderLoadedEditor(mocks);

		// What the editor renders is the stored document, key for key.
		const json = (
			screen.getByRole("textbox", { name: "DLP policy document (JSON)" }) as HTMLTextAreaElement
		).value;
		expect(JSON.parse(json)).toStrictEqual(stored);

		fireEvent.click(screen.getByRole("button", { name: "Save DLP policy" }));

		await waitFor(() =>
			expect(
				screen.getByText("DLP policy version 4 saved for this tenant. Not delivered: signed provisioning must distribute it separately."),
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
		expect(screen.queryByText(/published for this tenant/)).not.toBeInTheDocument();
		expect(screen.getByLabelText("Policy version")).toHaveValue(4);
		expect(screen.getByLabelText("Policy version")).toHaveAttribute("readonly");
		expect(JSON.parse((screen.getByLabelText("DLP policy document (JSON)") as HTMLTextAreaElement).value))
			.toStrictEqual({ ...stored, version: 4 });

		// A reload observes the committed document, then the next save carries
		// its CAS version rather than the pre-save draft's old version.
		cleanup();
		await renderLoadedEditor(mocks);
		expect(screen.getByLabelText("Policy version")).toHaveValue(4);
		fireEvent.click(screen.getByRole("button", { name: "Save DLP policy" }));
		await waitFor(() => expect(screen.getByText(/DLP policy version 5 saved for this tenant\. Not delivered/)).toBeInTheDocument());
		expect(publishCalls(mocks)).toHaveLength(2);
		expect(publishCalls(mocks)[1]?.[1]?.body).toMatchObject({ expected_version: 4, policy: { version: 4 } });
	});

	it("refuses an invalid label and refuses to publish it", async () => {
		const mocks = await renderLoadedEditor();

		fireEvent.change(screen.getByLabelText("Label 1 id"), {
			target: { value: "-not-an-identifier" },
		});

		expect(screen.getByText("✗ Invalid DLP policy")).toBeInTheDocument();
		expect(screen.getByRole("alert")).toHaveTextContent(/labels\.0\.id/);
		const publish = screen.getByRole("button", { name: "Save DLP policy" });
		expect(publish).toBeDisabled();
		fireEvent.click(publish);
		expect(publishCalls(mocks)).toHaveLength(0);
	});

	it("refuses an invalid rule and refuses to publish it", async () => {
		const mocks = await renderLoadedEditor();

		fireEvent.change(screen.getByLabelText("Rule 1 priority"), { target: { value: "10001" } });

		expect(screen.getByText("✗ Invalid DLP policy")).toBeInTheDocument();
		expect(screen.getByRole("alert")).toHaveTextContent(/rules\.0\.priority/);
		fireEvent.click(screen.getByRole("button", { name: "Save DLP policy" }));
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
		fireEvent.click(screen.getByRole("button", { name: "Save DLP policy" }));
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

		fireEvent.click(screen.getByRole("button", { name: "Save DLP policy" }));

		await waitFor(() =>
			expect(screen.getByRole("alert")).toHaveTextContent(
				/DLP policy save was not confirmed: invalid_action/,
			),
		);
		expect(screen.queryByText(/saved for this tenant/)).not.toBeInTheDocument();
	});

	it("never reports a publish the function did not confirm", async () => {
		const mocks = installDlpMocks({
			read: readInvoke(),
			publish: { data: { ok: true }, error: null },
		});
		await renderLoadedEditor(mocks);

		fireEvent.click(screen.getByRole("button", { name: "Save DLP policy" }));

		await waitFor(() =>
			expect(screen.getByRole("alert")).toHaveTextContent(
				/did not confirm a stored DLP policy version/,
			),
		);
		expect(screen.queryByText(/saved for this tenant/)).not.toBeInTheDocument();
	});
});

describe("DLP policy save authority and confirmation", () => {
	afterEach(cleanup);

	it.each(["member", "viewer"])("keeps %s access read-only despite the general policy edit affordance", async role => {
		const mocks = installDlpMocks({ role, read: readInvoke() });
		renderDlpEditor();
		await waitFor(() => expect(screen.getByLabelText("DLP policy document (JSON)")).toBeInTheDocument());
		expect(screen.getByText(/members and viewers have read-only access/)).toBeInTheDocument();
		expect(screen.getByLabelText("DLP policy document (JSON)")).toHaveAttribute("readonly");
		expect(JSON.parse((screen.getByLabelText("DLP policy document (JSON)") as HTMLTextAreaElement).value)).toStrictEqual(storedDlpPolicy());
		expect(screen.queryByRole("button", { name: "Save DLP policy" })).not.toBeInTheDocument();
		expect(screen.queryByRole("button", { name: "Add label" })).not.toBeInTheDocument();
		expect(screen.queryByRole("button", { name: "Remove expired exceptions" })).not.toBeInTheDocument();
		expect(publishCalls(mocks)).toHaveLength(0);
	});

	it.each(["member", "viewer"])("shows no saved policy rather than starter rules to an empty-store %s", async role => {
		const mocks = installDlpMocks({ role });
		renderDlpEditor();
		await waitFor(() => expect(screen.getByText("No DLP policy has been saved for this tenant.")).toBeInTheDocument());
		expect(screen.queryByLabelText("DLP policy document (JSON)")).not.toBeInTheDocument();
		expect(screen.queryByRole("button", { name: "Save DLP policy" })).not.toBeInTheDocument();
		expect(publishCalls(mocks)).toHaveLength(0);
	});

	it.each(["owner", "admin"])("lets an %s save but never claims delivery or enforcement", async role => {
		const mocks = await renderLoadedEditor(installDlpMocks({ role, read: readInvoke() }));
		expect(screen.getByText(/Saving is not delivery or enforcement/)).toBeInTheDocument();
		fireEvent.click(screen.getByRole("button", { name: "Save DLP policy" }));
		await waitFor(() => expect(screen.getByText(/version 4 saved for this tenant\. Not delivered/)).toBeInTheDocument());
		expect(publishCalls(mocks)).toHaveLength(1);
	});

	it.each([
		["unconfirmed saved flag", { saved: undefined }],
		["failed saved flag", { saved: false }],
		["missing delivery flag", { delivered: undefined }],
		["fabricated delivery", { delivered: true }],
		["missing delivery status", { delivery_status: undefined }],
		["fabricated delivery status", { delivery_status: "delivered" }],
		["stale storage version", { version: 3 }],
		["version jump", { version: 99 }],
		["missing policy echo", { policy: undefined }],
		["old document version", { policy: storedDlpPolicy() }],
		["different document", { policy: storedDlpPolicy({ version: 4, maxContentBytes: 2048 }) }],
	] as Array<[string, Record<string, unknown>]>)("rejects %s without acknowledging a save", async (_name, patch) => {
		const confirmed = savedInvoke(storedDlpPolicy({ version: 4 }));
		const mocks = installDlpMocks({
			read: readInvoke(),
			publish: { data: { ...(confirmed.data as Record<string, unknown>), ...patch }, error: null },
		});
		await renderLoadedEditor(mocks);
		fireEvent.click(screen.getByRole("button", { name: "Save DLP policy" }));
		await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent(/did not confirm a stored DLP policy version/));
		expect(screen.queryByText(/saved for this tenant/)).not.toBeInTheDocument();
		expect(screen.getByLabelText("Policy version")).toHaveValue(3);
		expect(publishCalls(mocks)).toHaveLength(1);
	});

	it("surfaces a version conflict without advancing the local version", async () => {
		const mocks = await renderLoadedEditor(installDlpMocks({
			read: readInvoke(), publish: { data: null, error: { message: "policy_version_conflict (409)" } },
		}));
		fireEvent.click(screen.getByRole("button", { name: "Save DLP policy" }));
		await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent(/save was not confirmed: policy_version_conflict \(409\)/));
		expect(screen.getByLabelText("Policy version")).toHaveValue(3);
		expect(publishCalls(mocks)).toHaveLength(1);
	});
});

describe("DLP pending-save isolation", () => {
	afterEach(() => { cleanup(); vi.restoreAllMocks(); });

	it("freezes authoring while saving so the committed echo cannot discard newer edits", async () => {
		const pending = deferredResponse();
		const mocks = await renderLoadedEditor(installDlpMocks({ read: readInvoke(), publish: pending.promise }));
		fireEvent.click(screen.getByRole("button", { name: "Save DLP policy" }));
		expect(screen.getByLabelText("Max content bytes")).toBeDisabled();
		expect(screen.getByLabelText("Rule 1 action")).toBeDisabled();
		expect(screen.getByRole("button", { name: "Add label" })).toBeDisabled();
		fireEvent.change(screen.getByLabelText("Max content bytes"), { target: { value: "2048" } });
		expect(screen.getByLabelText("Max content bytes")).toHaveValue(4096);
		await act(async () => pending.resolve(savedInvoke(storedDlpPolicy({ version: 4 }))));
		expect(screen.getByLabelText("Max content bytes")).toHaveValue(4096);
		expect(screen.getByLabelText("Max content bytes")).not.toBeDisabled();
		expect(screen.getByLabelText("Policy version")).toHaveValue(4);
		expect(publishCalls(mocks)).toHaveLength(1);
	});

	it.each(["success", "error", "rejection"])("ignores a previous tenant's late %s, including its finally state", async outcome => {
		const pendingA = deferredResponse();
		const pendingB = deferredResponse();
		const otherTenant = "tenant-other";
		const policyB = JSON.parse(JSON.stringify(storedDlpPolicy()).replaceAll(TEAM_ID, otherTenant));
		const mocks = installDlpMocks();
		mocks.invoke.mockImplementation(async (_name: string, request: { body: { action: string; tenant_id: string } }) => {
			if (request.body.action === DLP_READ_ACTION) return {
				data: { ok: true, version: 3, policy: request.body.tenant_id === TEAM_ID ? storedDlpPolicy() : policyB }, error: null,
			};
			if (request.body.action === DLP_PUBLISH_ACTION) return request.body.tenant_id === TEAM_ID ? pendingA.promise : pendingB.promise;
			throw new Error("unexpected editor action");
		});
		let selectedTenant = TEAM_ID;
		vi.spyOn(TeamProviderModule, "useTeam").mockImplementation(() => ({
			currentTeam: { id: selectedTenant, name: selectedTenant }, canManageTeam: true, isLoading: false, error: null,
		}) as ReturnType<typeof TeamProviderModule.useTeam>);
		const view = render(<DlpPolicyEditor />);
		await waitFor(() => expect(screen.getByText("✓ Valid DLP policy")).toBeInTheDocument());
		fireEvent.click(screen.getByRole("button", { name: "Save DLP policy" }));
		selectedTenant = otherTenant;
		view.rerender(<DlpPolicyEditor />);
		await waitFor(() => expect(JSON.parse((screen.getByLabelText("DLP policy document (JSON)") as HTMLTextAreaElement).value).tenantId).toBe(otherTenant));
		fireEvent.click(screen.getByRole("button", { name: "Save DLP policy" }));
		await act(async () => {
			if (outcome === "success") pendingA.resolve(savedInvoke(storedDlpPolicy({ version: 4 })));
			else if (outcome === "error") pendingA.resolve({ data: null, error: { message: "old-tenant-error" } });
			else pendingA.reject(new Error("old-tenant-rejection"));
		});
		expect(screen.getByRole("button", { name: "Saving..." })).toBeDisabled();
		expect(screen.queryByRole("alert")).not.toBeInTheDocument();
		expect(screen.queryByText(/saved for this tenant/)).not.toBeInTheDocument();
		expect(JSON.parse((screen.getByLabelText("DLP policy document (JSON)") as HTMLTextAreaElement).value)).toStrictEqual(policyB);
		await act(async () => pendingB.resolve(savedInvoke({ ...policyB, version: 4 })));
		expect(screen.getByText(/version 4 saved for this tenant\. Not delivered/)).toBeInTheDocument();
		expect(JSON.parse((screen.getByLabelText("DLP policy document (JSON)") as HTMLTextAreaElement).value)).toStrictEqual({ ...policyB, version: 4 });
		expect(publishCalls(mocks).map(([, request]) => request.body.tenant_id)).toEqual([TEAM_ID, otherTenant]);
	});
});

describe("DLP expired stored-document repair", () => {
	afterEach(cleanup);
	function agedPolicy(): Record<string, unknown> {
		const active = (storedDlpPolicy().exceptions as Record<string, unknown>[])[0];
		return storedDlpPolicy({ exceptions: [
			{ ...active, id: "expired-a", expiresAt: PAST_EXPIRY },
			{ ...active, id: "expired-b", expiresAt: PAST_EXPIRY },
			active,
		] });
	}

	it("loads an expired-majority document only for explicit repair and saves only the valid result", async () => {
		const aged = agedPolicy();
		const core = await loadCoreDlpModule();
		expect(validateDlpPolicyDocument(aged).ok).toBe(false);
		expect(core.DlpPolicySchema.safeParse(aged).success).toBe(false);
		const mocks = installDlpMocks({ read: { data: { ok: true, version: 3, policy: aged }, error: null } });
		renderDlpEditor();
		await waitFor(() => expect(screen.getByRole("button", { name: "Remove expired exceptions" })).toBeInTheDocument());
		expect(screen.getByText("✗ Invalid DLP policy")).toBeInTheDocument();
		expect(screen.getByRole("alert")).toHaveTextContent(DLP_EXPIRED_EXCEPTION_DOMINANCE);
		expect(screen.getByText(/nothing is removed automatically/)).toBeInTheDocument();
		expect(JSON.parse((screen.getByLabelText("DLP policy document (JSON)") as HTMLTextAreaElement).value)).toStrictEqual(aged);
		const save = screen.getByRole("button", { name: "Save DLP policy" });
		expect(save).toBeDisabled();
		fireEvent.click(save);
		expect(publishCalls(mocks)).toHaveLength(0);

		fireEvent.click(screen.getByRole("button", { name: "Remove expired exceptions" }));
		expect(screen.getByText("✓ Valid DLP policy")).toBeInTheDocument();
		expect(screen.queryByRole("button", { name: "Remove expired exceptions" })).not.toBeInTheDocument();
		const repaired = JSON.parse((screen.getByLabelText("DLP policy document (JSON)") as HTMLTextAreaElement).value);
		expect(repaired.exceptions).toStrictEqual(storedDlpPolicy().exceptions);
		expect(repaired.rules).toStrictEqual(aged.rules);
		expect(repaired.labels).toStrictEqual(aged.labels);
		expect(core.DlpPolicySchema.safeParse(repaired).success).toBe(true);
		expect(publishCalls(mocks)).toHaveLength(0);
		fireEvent.click(save);
		await waitFor(() => expect(screen.getByText(/version 4 saved for this tenant\. Not delivered/)).toBeInTheDocument());
		expect(publishCalls(mocks)[0]?.[1]?.body).toMatchObject({ expected_version: 3, policy: repaired });
	});

	it("does not turn an expiry issue into permission to repair structurally invalid data", async () => {
		const invalid = { ...agedPolicy(), rules: ruleWith({ labelId: "missing-label" }) };
		const mocks = installDlpMocks({ read: { data: { ok: true, version: 3, policy: invalid }, error: null } });
		renderDlpEditor();
		await waitFor(() => expect(screen.getByText(/The stored DLP policy could not be read/)).toBeInTheDocument());
		expect(screen.queryByRole("button", { name: "Remove expired exceptions" })).not.toBeInTheDocument();
		expect(screen.queryByLabelText("DLP policy document (JSON)")).not.toBeInTheDocument();
		expect(publishCalls(mocks)).toHaveLength(0);
	});

	it("refuses an engine-valid foreign-tenant stored document rather than offering repair", async () => {
		const foreign = JSON.parse(JSON.stringify(storedDlpPolicy()).replaceAll(TEAM_ID, "tenant-other"));
		expect((await loadCoreDlpModule()).DlpPolicySchema.safeParse(foreign).success).toBe(true);
		const mocks = installDlpMocks({ read: { data: { ok: true, version: 3, policy: foreign }, error: null } });
		renderDlpEditor();
		await waitFor(() => expect(screen.getByText(/The stored DLP policy could not be read/)).toBeInTheDocument());
		expect(screen.queryByLabelText("DLP policy document (JSON)")).not.toBeInTheDocument();
		expect(publishCalls(mocks)).toHaveLength(0);
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
