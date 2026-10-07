// @vitest-environment jsdom

import { generateKeyPairSync, webcrypto } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const invoke = vi.hoisted(() => vi.fn());
const team = vi.hoisted(() => ({
	value: {
		currentTeam: { id: "22222222-2222-4222-8222-222222222222", name: "Acme Security" } as {
			id: string;
			name: string;
		} | null,
		currentRole: "owner" as string | null,
		isLoading: false,
		roleResolved: true,
	},
}));
vi.mock("../lib/supabase", () => ({ supabase: { functions: { invoke } }, supabaseEnvError: null }));
vi.mock("../enterprise/team-provider", () => ({ useTeam: () => team.value }));

import {
	type ComplianceReport,
	customPeriod,
	parseComplianceReport,
	reportHashMatches,
} from "../lib/compliance-report";
import { crc32, csvBundleFiles, csvField, sectionBlocks } from "../ui/compliance-export";
import { renderPrintableReport } from "../ui/compliance-print";
import { CompliancePage } from "../ui/pages/CompliancePage";

const TENANT = "22222222-2222-4222-8222-222222222222";
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");

interface ServerModules {
	buildComplianceReportBody: (input: {
		evidence: unknown;
		reportId: string;
		actorUserId: string;
		from: Date;
		to: Date;
	}) => Record<string, unknown>;
	sealComplianceReport: (
		body: Record<string, unknown>,
		signer: { keyId: string; privateKeyPkcs8B64: string } | null,
	) => Promise<Record<string, unknown>>;
	complianceEvidenceFixture: () => Record<string, unknown>;
	COMPLIANCE_OWNER: string;
	COMPLIANCE_REPORT_ID: string;
}

/**
 * The page is exercised with reports sealed by the real Edge Function module,
 * loaded by URL so this package does not adopt the Deno function tree.
 */
async function loadServer(): Promise<ServerModules> {
	const load = (path: string) => import(pathToFileURL(resolve(REPO_ROOT, path)).href);
	const [shared, fixtures] = await Promise.all([
		load("supabase/functions/_shared/compliance-report.ts"),
		load("supabase/functions/__tests__/compliance-fixtures.ts"),
	]);
	return { ...shared, ...fixtures } as ServerModules;
}

let server: ServerModules;
let hashOnly: ComplianceReport;
let signed: ComplianceReport;

beforeAll(async () => {
	vi.stubGlobal("crypto", webcrypto);
	server = await loadServer();
	const body = server.buildComplianceReportBody({
		evidence: server.complianceEvidenceFixture(),
		reportId: server.COMPLIANCE_REPORT_ID,
		actorUserId: server.COMPLIANCE_OWNER,
		from: new Date("2026-06-27T00:00:00.000Z"),
		to: new Date("2026-09-25T00:00:00.000Z"),
	});
	hashOnly = (await server.sealComplianceReport(body, null)) as unknown as ComplianceReport;
	const { privateKey } = generateKeyPairSync("ed25519");
	signed = (await server.sealComplianceReport(body, {
		keyId: "compliance-2026-09",
		privateKeyPkcs8B64: privateKey.export({ format: "der", type: "pkcs8" }).toString("base64"),
	})) as unknown as ComplianceReport;
});

beforeEach(() => {
	vi.stubGlobal("crypto", webcrypto);
	invoke.mockReset();
	team.value = {
		currentTeam: { id: TENANT, name: "Acme Security" },
		currentRole: "owner",
		isLoading: false,
		roleResolved: true,
	};
});

afterEach(() => {
	cleanup();
	vi.restoreAllMocks();
	vi.unstubAllGlobals();
});

function renderPage() {
	return render(
		<MemoryRouter>
			<CompliancePage />
		</MemoryRouter>,
	);
}

function httpError(status: number, error: string) {
	return {
		data: null,
		error: Object.assign(new Error("Edge Function returned a non-2xx status code"), {
			context: new Response(JSON.stringify({ error }), { status }),
		}),
	};
}

async function generate() {
	fireEvent.click(screen.getByRole("button", { name: "Generate report" }));
}

/** jsdom's Blob is read through its own FileReader. */
function blobBytes(blob: Blob): Promise<Uint8Array> {
	return new Promise((done, fail) => {
		const reader = new FileReader();
		reader.onload = () => done(new Uint8Array(reader.result as ArrayBuffer));
		reader.onerror = () => fail(reader.error);
		reader.readAsArrayBuffer(blob);
	});
}

/** Read a stored-entry ZIP: names, contents and CRC check. */
function readZip(bytes: Uint8Array): Map<string, string> {
	const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
	const end = bytes.length - 22;
	expect(view.getUint32(end, true)).toBe(0x06054b50);
	const entries = view.getUint16(end + 10, true);
	let offset = view.getUint32(end + 16, true);
	const files = new Map<string, string>();
	for (let index = 0; index < entries; index += 1) {
		expect(view.getUint32(offset, true)).toBe(0x02014b50);
		const crc = view.getUint32(offset + 16, true);
		const size = view.getUint32(offset + 20, true);
		const nameLength = view.getUint16(offset + 28, true);
		const local = view.getUint32(offset + 42, true);
		const name = new TextDecoder().decode(bytes.subarray(offset + 46, offset + 46 + nameLength));
		const localNameLength = view.getUint16(local + 26, true);
		const data = bytes.subarray(local + 30 + localNameLength, local + 30 + localNameLength + size);
		expect(crc32(data), name).toBe(crc);
		files.set(name, new TextDecoder().decode(data));
		offset += 46 + nameLength;
	}
	return files;
}

describe("compliance page access", () => {
	it("is limited to owners and admins", () => {
		for (const role of ["member", "viewer", null]) {
			team.value = { ...team.value, currentRole: role };
			renderPage();
			expect(screen.getByRole("alert")).toHaveTextContent(
				"Only workspace owners and admins can generate compliance reports.",
			);
			expect(screen.queryByRole("button", { name: "Generate report" })).not.toBeInTheDocument();
			cleanup();
		}
		expect(invoke).not.toHaveBeenCalled();
	});

	it("waits for the tenant and role before rendering", () => {
		team.value = { ...team.value, isLoading: true };
		renderPage();
		expect(screen.getByRole("status")).toHaveTextContent("Resolving the managed tenant");
		cleanup();
		team.value = { ...team.value, isLoading: false, currentTeam: null };
		renderPage();
		expect(screen.getByRole("alert")).toHaveTextContent("Select a team");
	});
});

describe("compliance page generation", () => {
	it("requests the selected period for the current tenant and previews every section", async () => {
		let resolveInvoke: (value: unknown) => void = () => undefined;
		invoke.mockReturnValue(new Promise((resolve) => (resolveInvoke = resolve)));
		renderPage();
		await generate();
		expect(
			await screen.findByText("Collecting evidence and sealing the report…"),
		).toBeInTheDocument();
		expect(screen.getByRole("button", { name: "Generating…" })).toBeDisabled();
		const [name, options] = invoke.mock.calls[0] as [
			string,
			{ body: { from: string; to: string; tenant_id: string } },
		];
		expect(name).toBe("compliance-report");
		expect(options.body.tenant_id).toBe(TENANT);
		const days = (Date.parse(options.body.to) - Date.parse(options.body.from)) / 86_400_000;
		expect(days).toBe(90);
		resolveInvoke({ data: { ok: true, report: hashOnly }, error: null });

		const summary = await screen.findByRole("region", { name: "Report summary" });
		expect(within(summary).getByText(hashOnly.report_id)).toBeInTheDocument();
		expect(within(summary).getByText("Hash only")).toBeInTheDocument();
		expect(within(summary).getByText(/Not signed/)).toBeInTheDocument();
		for (const title of [
			"Tenant profile",
			"Protection coverage",
			"Data-protection activity",
			"Policy inventory",
			"Access and identity",
			"Incidents",
			"AI security posture",
			"Data flows and subprocessors",
			"Retention and deletion",
			"What this report does not prove",
		]) {
			expect(screen.getByRole("heading", { name: title })).toBeInTheDocument();
		}
		const access = screen.getByRole("region", { name: "Access and identity" });
		expect(within(access).getByText("1 of 2")).toBeInTheDocument();
		const policies = screen.getByRole("region", { name: "Policy inventory" });
		expect(within(policies).getByText("v4")).toBeInTheDocument();
	});

	it("shows a signed report's key", async () => {
		invoke.mockResolvedValue({ data: { ok: true, report: signed }, error: null });
		renderPage();
		await generate();
		const summary = await screen.findByRole("region", { name: "Report summary" });
		expect(within(summary).getByText("Signed")).toBeInTheDocument();
		expect(within(summary).getByText("Ed25519, key compliance-2026-09")).toBeInTheDocument();
	});

	it.each([
		["mfa_required", "multi-factor (AAL2) session"],
		["compliance_role_insufficient", "Only workspace owners and admins"],
		["rate_limited", "Wait a minute"],
		["period_too_long", "at most 366 days"],
		["compliance_evidence_invalid", "No partial report was produced"],
	])("explains the %s refusal without showing a report", async (code, text) => {
		invoke.mockResolvedValue(httpError(403, code));
		renderPage();
		await generate();
		expect(await screen.findByRole("alert")).toHaveTextContent(text);
		expect(screen.queryByRole("region", { name: "Report summary" })).not.toBeInTheDocument();
		expect(screen.queryByRole("button", { name: "Download JSON" })).not.toBeInTheDocument();
	});

	it("rejects an altered report and one issued for another tenant", async () => {
		const altered = structuredClone(hashOnly);
		(altered.sections.incidents.incidents as { total: number }).total = 0;
		invoke.mockResolvedValueOnce({ data: { ok: true, report: altered }, error: null });
		renderPage();
		await generate();
		expect(await screen.findByRole("alert")).toHaveTextContent("does not match its own SHA-256");

		const foreign = structuredClone(hashOnly);
		foreign.sections.tenant_profile.tenant_id = "44444444-4444-4444-8444-444444444444";
		invoke.mockResolvedValueOnce({ data: { ok: true, report: foreign }, error: null });
		await generate();
		await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("incomplete"));
		expect(screen.queryByRole("region", { name: "Report summary" })).not.toBeInTheDocument();
	});

	it("validates a custom range before calling the server", async () => {
		invoke.mockResolvedValue({ data: { ok: true, report: hashOnly }, error: null });
		renderPage();
		fireEvent.change(screen.getByLabelText("Period"), { target: { value: "custom" } });
		fireEvent.change(screen.getByLabelText("From (UTC)"), { target: { value: "2024-01-01" } });
		fireEvent.change(screen.getByLabelText("To (UTC, inclusive)"), {
			target: { value: "2025-06-30" },
		});
		await generate();
		expect(await screen.findByRole("alert")).toHaveTextContent("at most 366 days");
		expect(invoke).not.toHaveBeenCalled();

		fireEvent.change(screen.getByLabelText("From (UTC)"), { target: { value: "2025-06-01" } });
		await generate();
		await screen.findByRole("region", { name: "Report summary" });
		expect((invoke.mock.calls[0] as [string, { body: unknown }])[1].body).toEqual({
			tenant_id: TENANT,
			from: "2025-06-01T00:00:00.000Z",
			to: "2025-07-01T00:00:00.000Z",
		});
	});
});

describe("compliance page downloads", () => {
	async function readyPage() {
		invoke.mockResolvedValue({ data: { ok: true, report: signed }, error: null });
		const saved: Array<{ blob: Blob; name: string }> = [];
		let lastBlob: Blob | null = null;
		vi.spyOn(URL, "createObjectURL").mockImplementation((blob) => {
			lastBlob = blob as Blob;
			return "blob:compliance";
		});
		vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => undefined);
		vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (
			this: HTMLAnchorElement,
		) {
			if (lastBlob) saved.push({ blob: lastBlob, name: this.download });
		});
		renderPage();
		await generate();
		await screen.findByRole("region", { name: "Report summary" });
		return saved;
	}

	it("downloads the exact report as JSON", async () => {
		const saved = await readyPage();
		fireEvent.click(screen.getByRole("button", { name: "Download JSON" }));
		const json = saved[0];
		if (!json) throw new Error("no JSON download");
		expect(json.name).toBe("aidr-compliance-2026-06-27_2026-09-25-99999999.json");
		const parsed = JSON.parse(new TextDecoder().decode(await blobBytes(json.blob)));
		expect(parsed).toEqual(signed);
		expect(await reportHashMatches(parsed)).toBe(true);
	});

	it("builds a ZIP with one CSV per section table and a README", async () => {
		const saved = await readyPage();
		fireEvent.click(screen.getByRole("button", { name: "Download CSV bundle (.zip)" }));
		const zip = saved[0];
		if (!zip) throw new Error("no ZIP download");
		expect(zip.name).toMatch(/-csv\.zip$/);
		const files = readZip(await blobBytes(zip.blob));
		expect([...files.keys()]).toEqual(csvBundleFiles(signed).map((file) => file.name));
		expect(files.get("README.txt")).toContain(signed.integrity.sha256);
		expect(files.get("README.txt")).toContain("aidr compliance verify");
		expect(files.get("01_tenant_profile.csv")).toContain("region,eu-central-1");
		const bySite = files.get("03_data_protection_activity__browser_guard_by_site.csv") ?? "";
		expect(bySite.split("\r\n")[0]).toBe("site,scans,masked,warned,blocked");
		expect(bySite).toContain("chatgpt,30,25,2,3");
		expect(files.get("05_access_identity__admins.csv")).toContain("owner@acme.example");
		for (const index of ["01", "02", "03", "04", "05", "06", "07", "08", "09"]) {
			expect(
				[...files.keys()].some((name) => name.startsWith(`${index}_`)),
				index,
			).toBe(true);
		}
	});

	it("prints a Turkish or English edition through the browser print dialog", async () => {
		await readyPage();
		const written: string[] = [];
		const print = vi.fn();
		const fakeWindow = {
			opener: {} as unknown,
			document: { open: vi.fn(), write: (html: string) => written.push(html), close: vi.fn() },
			focus: vi.fn(),
			print,
		};
		vi.spyOn(window, "open").mockReturnValue(fakeWindow as unknown as Window);
		fireEvent.change(screen.getByLabelText("Printable report language"), {
			target: { value: "tr" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Print / save as PDF" }));
		expect(print).toHaveBeenCalledOnce();
		expect(fakeWindow.opener).toBeNull();
		expect(written[0]).toContain('<html lang="tr">');
		expect(written[0]).toContain("Uyum kanıt raporu");
		expect(written[0]).toContain("Veri akışları ve alt işleyenler");
		expect(written[0]).toContain("sertifika");
		fireEvent.change(screen.getByLabelText("Printable report language"), {
			target: { value: "en" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Print / save as PDF" }));
		expect(written[1]).toContain('<html lang="en">');
		expect(written[1]).toContain("Compliance evidence report");
		expect(written[1]).toContain("@media print");
	});
});

describe("compliance export helpers", () => {
	it("neutralises spreadsheet formulas and quotes CSV fields", () => {
		expect(csvField('=HYPERLINK("x")')).toBe('"\'=HYPERLINK(""x"")"');
		expect(csvField("+1")).toBe("'+1");
		expect(csvField(-3)).toBe("-3");
		expect(csvField("a,b")).toBe('"a,b"');
		expect(csvField(null)).toBe("");
	});

	it("escapes every report string in the printable edition", () => {
		const hostile = structuredClone(hashOnly);
		hostile.sections.tenant_profile.name = "<script>alert(1)</script>";
		const html = renderPrintableReport(hostile, "en");
		expect(html).not.toContain("<script>");
		expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
	});

	it("flattens nested sections into fields and record tables", () => {
		const [fields, ...tables] = sectionBlocks(hashOnly.sections.retention_deletion);
		expect(fields?.kind).toBe("fields");
		expect(fields?.rows).toContainEqual(["telemetry.within_policy", true]);
		expect(fields?.rows).toContainEqual(["offboarding_runs", "none"]);
		const blocks = tables;
		expect(blocks.find((block) => block.path === "policies")?.headers).toEqual([
			"data_class",
			"retention_days",
			"covers_backups",
			"updated_at",
		]);
	});

	it("bounds custom periods like the server", () => {
		const now = Date.parse("2026-09-25T10:00:00.000Z");
		expect(customPeriod("2026-09-01", "2026-09-30", now)).toEqual({
			ok: true,
			value: { from: "2026-09-01T00:00:00.000Z", to: "2026-09-25T10:00:00.000Z" },
		});
		expect(customPeriod("2025-09-24", "2026-09-24", now)).toMatchObject({ ok: true });
		expect(customPeriod("2025-09-23", "2026-09-24", now)).toEqual({
			ok: false,
			error: "period_too_long",
		});
		expect(customPeriod("2026-09-10", "2026-09-01", now)).toEqual({
			ok: false,
			error: "invalid_period",
		});
		expect(customPeriod("", "2026-09-01", now)).toEqual({ ok: false, error: "invalid_period" });
	});

	it("accepts only complete, sealed report documents", async () => {
		expect(parseComplianceReport(signed)).not.toBeNull();
		expect(await reportHashMatches(signed)).toBe(true);
		const { integrity: _drop, ...unsealed } = signed;
		expect(parseComplianceReport(unsealed)).toBeNull();
		const missingSection = structuredClone(signed) as unknown as {
			sections: Record<string, unknown>;
		};
		delete missingSection.sections.data_flows;
		expect(parseComplianceReport(missingSection)).toBeNull();
	});
});
