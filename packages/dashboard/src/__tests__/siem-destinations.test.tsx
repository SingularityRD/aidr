// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { I18nProvider } from "../i18n/I18nProvider";
import { buildSyslogAdapter, DEFAULT_SYSLOG_FORM } from "../lib/siem-syslog-config";
import { SiemDestinations } from "../ui/SiemDestinations";

const TENANT = "11111111-1111-4111-8111-111111111111";
const DESTINATION = "55555555-5555-4555-8555-555555555555";

const invoke = vi.hoisted(() => vi.fn());
vi.mock("../lib/supabase", () => ({ supabase: { functions: { invoke } }, supabaseEnvError: null }));

interface InvokeOptions {
	method?: string;
	headers?: Record<string, string>;
	body?: Record<string, unknown>;
}

function destination(overrides: Record<string, unknown> = {}) {
	return {
		id: DESTINATION,
		provider: "syslog",
		format: "leef",
		name: "QRadar",
		target_hint: "tls://qradar.corp.example:6514",
		enabled: true,
		filters: { incidents: true, decisions: ["deny", "ask"], browser: false, min_severity: "info" },
		last_delivery_at: null,
		last_delivery_status: "retrying",
		last_error: "tls_verification_failed",
		consecutive_failures: 3,
		dropped_events: 0,
		pending: 12,
		dead: 2,
		...overrides,
	};
}

function settings(overrides: Record<string, unknown> = {}) {
	return {
		ok: true,
		configured: true,
		private_networks_allowed: true,
		permissions: { can_manage: true, requires_aal2: true },
		limits: { max_destinations: 10 },
		destinations: [destination()],
		dead_letters: [
			{
				id: "9",
				destination_id: DESTINATION,
				kind: "decision",
				type: "runtime_verdict",
				decision: "deny",
				severity: "critical",
				attempts: 12,
				last_error: "receiver_unavailable",
				last_status_code: 503,
				created_at: "2026-10-14T08:00:00.000Z",
				dead_at: "2026-10-14T09:00:00.000Z",
			},
		],
		...overrides,
	};
}

beforeEach(() => {
	invoke.mockImplementation(async (_name: string, options: InvokeOptions) => {
		if (options.method === "GET") return { data: settings(), error: null };
		const body = options.body ?? {};
		if (body.action === "create")
			return { data: { ok: true, destination: destination({ name: body.name }) }, error: null };
		if (body.action === "test")
			return {
				data: {
					ok: true,
					delivery: { id: "77", status: "dead", error: "tls_verification_failed" },
				},
				error: null,
			};
		if (body.action === "requeue") return { data: { ok: true, requeued: 2 }, error: null };
		return { data: { ok: true }, error: null };
	});
});
afterEach(() => {
	cleanup();
	invoke.mockReset();
});

describe("central SIEM forwarding", () => {
	it("shows destination health, queue and dead letters without secrets", async () => {
		render(<SiemDestinations tenantId={TENANT} />);
		expect(await screen.findByText("tls://qradar.corp.example:6514")).toBeInTheDocument();
		expect(screen.getByText("12 waiting · 2 failed · 0 dropped")).toBeInTheDocument();
		expect(screen.getByText("receiver_unavailable (HTTP 503)")).toBeInTheDocument();
		expect(invoke).toHaveBeenCalledWith("siem-destinations", {
			method: "GET",
			headers: { "X-AIDR-Tenant-ID": TENANT },
		});
	});

	it("creates a LEEF syslog destination with a private CA and reports the test result", async () => {
		render(<SiemDestinations tenantId={TENANT} />);
		await screen.findByText("tls://qradar.corp.example:6514");
		fireEvent.change(screen.getByLabelText("Name"), { target: { value: "QRadar DC2" } });
		fireEvent.change(screen.getByLabelText("Collector host"), {
			target: { value: "qradar.corp.example" },
		});
		fireEvent.change(screen.getByLabelText("Private CA certificate (PEM, optional)"), {
			target: { value: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----" },
		});
		fireEvent.click(screen.getByLabelText(/private/i, { selector: "input[type=checkbox]" }));
		fireEvent.click(screen.getByRole("button", { name: "Save destination" }));
		await screen.findByText("Destination QRadar DC2 saved.");
		const create = invoke.mock.calls.find(
			([, options]) => (options as InvokeOptions).body?.action === "create",
		)?.[1] as InvokeOptions;
		expect(create.body).toMatchObject({
			tenant_id: TENANT,
			provider: "syslog",
			format: "leef",
			config: {
				transport: "tls",
				host: "qradar.corp.example",
				port: 6514,
				allow_private_network: true,
			},
			filters: {
				incidents: true,
				decisions: ["deny", "ask"],
				browser: false,
				min_severity: "info",
			},
		});
		fireEvent.click(screen.getByRole("button", { name: "Send test" }));
		expect(await screen.findByRole("alert")).toHaveTextContent(
			"Test event not delivered: tls_verification_failed",
		);
		fireEvent.click(screen.getByRole("button", { name: "Resend dead letters" }));
		await screen.findByText("2 dead letters queued for another attempt.");
	});

	it("explains the server-side errors in Turkish", async () => {
		invoke.mockImplementation(async () => ({
			data: null,
			error: {
				context: new Response(JSON.stringify({ error: "plan_feature_required" }), { status: 402 }),
			},
		}));
		render(
			<I18nProvider initialLocale="tr">
				<SiemDestinations tenantId={TENANT} />
			</I18nProvider>,
		);
		await waitFor(() =>
			expect(screen.getByRole("alert")).toHaveTextContent(
				"Merkezi SIEM iletimi için Business ya da daha üst bir plan gerekir.",
			),
		);
	});
});

describe("host syslog payload format", () => {
	it("adds payloadFormat only for CEF and LEEF so JSON configurations stay unchanged", () => {
		const base = { ...DEFAULT_SYSLOG_FORM, host: "siem.example.com" };
		const json = buildSyslogAdapter(base);
		expect(json.ok && "payloadFormat" in json.adapter).toBe(false);
		const leef = buildSyslogAdapter({ ...base, payloadFormat: "leef" });
		expect(leef).toMatchObject({ ok: true, adapter: { payloadFormat: "leef" } });
	});
});
