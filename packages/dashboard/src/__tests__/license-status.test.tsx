// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { act, cleanup, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../enterprise/team-provider", () => ({ useTeam: vi.fn() }));
vi.mock("../lib/supabase", () => ({ supabase: { rpc: vi.fn(), functions: { invoke: vi.fn() } } }));

// @ts-expect-error JavaScript module without type declarations
import { reportDigest } from "../../../../scripts/onprem-usage-report.mjs";
import { useTeam } from "../enterprise/team-provider";
import {
	type LicenseStatus,
	licenseBanner,
	licenseSubmitErrorKey,
	parseLicenseFile,
	readLicenseStatus,
	sealUsageReport,
	submitLicense,
	usageReportFields,
} from "../lib/license";
import { supabase } from "../lib/supabase";
import { LicenseBanner } from "../ui/LicenseBanner";
import { LicenseSection } from "../ui/LicenseSection";

const tenantId = "11111111-1111-4111-8111-111111111111";
const DAY = 86_400_000;
const EXPIRES = Date.parse("2027-09-01T00:00:00Z");
const rawStatus = {
	mode: "onprem",
	can_manage: true,
	admission: { kind: "licensed", seats: 250, expires_at: "2027-09-15T00:00:00Z", revoked: false },
	license: {
		license_id: "LIC-2026-0042",
		plan_id: "enterprise",
		seats: 250,
		not_before: "2026-09-01T00:00:00Z",
		expires_at: "2027-09-01T00:00:00Z",
		grace_ends_at: "2027-09-15T00:00:00Z",
		applied_at: "2026-09-02T00:00:00Z",
	},
	pending: null,
};
const status = readLicenseStatus(rawStatus) as LicenseStatus;

describe("license banner thresholds", () => {
	it("warns at 30 and 7 days, during grace and after it", () => {
		expect(licenseBanner(status, EXPIRES - 31 * DAY).level).toBe("none");
		expect(licenseBanner(status, EXPIRES - 30 * DAY)).toMatchObject({
			level: "expires_30",
			days: 30,
		});
		expect(licenseBanner(status, EXPIRES - 8 * DAY).level).toBe("expires_30");
		expect(licenseBanner(status, EXPIRES - 7 * DAY)).toMatchObject({ level: "expires_7", days: 7 });
		expect(licenseBanner(status, EXPIRES - 1).level).toBe("expires_7");
		expect(licenseBanner(status, EXPIRES)).toMatchObject({ level: "grace", days: 14 });
		expect(licenseBanner(status, EXPIRES + 14 * DAY).level).toBe("expired");
	});

	it("falls back to the admission end without a signed license and ignores trials and revocations", () => {
		const admissionOnly = readLicenseStatus({ ...rawStatus, license: null }) as LicenseStatus;
		const end = Date.parse("2027-09-15T00:00:00Z");
		expect(licenseBanner(admissionOnly, end - 5 * DAY).level).toBe("expires_7");
		expect(licenseBanner(admissionOnly, end).level).toBe("expired");
		const trial = readLicenseStatus({
			...rawStatus,
			license: null,
			admission: { ...rawStatus.admission, kind: "trial" },
		});
		expect(licenseBanner(trial, end).level).toBe("none");
		const revoked = readLicenseStatus({
			...rawStatus,
			license: null,
			admission: { ...rawStatus.admission, revoked: true },
		});
		expect(licenseBanner(revoked, end).level).toBe("none");
		expect(licenseBanner(null, end).level).toBe("none");
	});

	it("rejects a malformed status instead of rendering it", () => {
		expect(
			readLicenseStatus({ ...rawStatus, license: { ...rawStatus.license, seats: -1 } }),
		).toBeNull();
		expect(readLicenseStatus({ ...rawStatus, can_manage: "yes" })).toBeNull();
		expect(readLicenseStatus(null)).toBeNull();
	});
});

describe("usage report", () => {
	it("produces the same digest as scripts/onprem-usage-report.mjs", async () => {
		const now = Date.parse("2027-03-01T12:00:00Z");
		const fields = usageReportFields(
			{
				seats_licensed: 250,
				devices_enrolled: 180,
				devices_active_30d: 150,
				license: {
					license_id: "LIC-2026-0042",
					customer_id: "example-ag",
					not_before: "2026-09-01T00:00:00+00:00",
					expires_at: "2027-09-01T00:00:00+00:00",
					grace_ends_at: "2027-09-15T00:00:00+00:00",
				},
			},
			now,
			"0.6.0",
		);
		expect(fields).toMatchObject({
			license_state: "valid",
			updates_until: "2027-09-15T00:00:00.000Z",
		});
		const report = await sealUsageReport(fields as never);
		const { report_sha256, ...rest } = report;
		expect(report_sha256).toBe(reportDigest(rest));
		expect(usageReportFields({ seats_licensed: -1 }, now, "0.6.0")).toBeNull();
		expect(
			usageReportFields({ seats_licensed: 0, devices_enrolled: 0, devices_active_30d: 0 }, now, "x")
				?.license_state,
		).toBe("unlicensed");
	});
});

describe("license UI", () => {
	beforeEach(() => {
		vi.mocked(useTeam).mockReturnValue({
			currentTeam: { id: tenantId, name: "Customer" },
		} as never);
		vi.mocked(supabase.rpc).mockReset();
		vi.mocked(supabase.functions.invoke).mockReset();
	});
	afterEach(() => cleanup());

	it("renders the grace banner with the local-detection notice", async () => {
		vi.mocked(supabase.rpc).mockResolvedValue({ data: rawStatus, error: null } as never);
		await act(async () => {
			render(
				<MemoryRouter>
					<LicenseBanner now={() => EXPIRES + 2 * DAY} />
				</MemoryRouter>,
			);
		});
		const banner = document.querySelector("[data-license-banner]");
		expect(banner).toHaveAttribute("data-license-banner", "grace");
		expect(banner).toHaveTextContent("Local detection on every device keeps enforcing");
		expect(supabase.rpc).toHaveBeenCalledWith("tenant_license_status", { p_tenant_id: tenantId });
	});

	it("names the signed license id in the expiry banner", async () => {
		vi.mocked(supabase.rpc).mockResolvedValue({ data: rawStatus, error: null } as never);
		await act(async () => {
			render(
				<MemoryRouter>
					<LicenseBanner now={() => EXPIRES - 10 * DAY} />
				</MemoryRouter>,
			);
		});
		const banner = document.querySelector("[data-license-banner]");
		expect(banner).toHaveAttribute("data-license-banner", "expires_30");
		expect(banner).toHaveTextContent("Your AIDR license LIC-2026-0042 ends in 10 days");
	});

	it("leaves the id out for admission terms without a signed license (unsigned pilot bootstrap)", async () => {
		vi.mocked(supabase.rpc).mockResolvedValue({
			data: { ...rawStatus, license: null },
			error: null,
		} as never);
		const admissionEnd = Date.parse(rawStatus.admission.expires_at);
		await act(async () => {
			render(
				<MemoryRouter>
					<LicenseBanner now={() => admissionEnd - 20 * DAY} />
				</MemoryRouter>,
			);
		});
		const banner = document.querySelector("[data-license-banner]");
		expect(banner).toHaveAttribute("data-license-banner", "expires_30");
		expect(banner).toHaveTextContent("Your AIDR license ends in 20 days");
		expect(banner?.textContent).not.toMatch(/license\s{2}|\(\)/);
	});

	it("shows nothing when the status cannot be read", async () => {
		vi.mocked(supabase.rpc).mockResolvedValue({
			data: null,
			error: { message: "denied" },
		} as never);
		await act(async () => {
			render(
				<MemoryRouter>
					<LicenseBanner now={() => EXPIRES} />
				</MemoryRouter>,
			);
		});
		expect(document.querySelector("[data-license-banner]")).toBeNull();
	});

	it("shows the signed license, the pending import and the admin import form", async () => {
		vi.mocked(supabase.rpc).mockResolvedValue({
			data: {
				...rawStatus,
				pending: {
					id: "p-1",
					license_id: "LIC-2027-0001",
					seats: 300,
					expires_at: "2028-09-01T00:00:00Z",
					grace_ends_at: "2028-09-15T00:00:00Z",
					submitted_at: "2027-08-01T00:00:00Z",
				},
			},
			error: null,
		} as never);
		await act(async () => {
			render(<LicenseSection tenantId={tenantId} />);
		});
		expect(document.querySelector("[data-license-source='signed']")).toHaveTextContent(
			"LIC-2026-0042",
		);
		expect(screen.getByText("Waiting for operator approval")).toBeInTheDocument();
		expect(screen.getByLabelText("License file")).toBeInTheDocument();
		expect(screen.getByRole("button", { name: "Download usage report" })).toBeInTheDocument();
	});

	it("keeps members read-only", async () => {
		vi.mocked(supabase.rpc).mockResolvedValue({
			data: { ...rawStatus, can_manage: false },
			error: null,
		} as never);
		await act(async () => {
			render(<LicenseSection tenantId={tenantId} />);
		});
		expect(screen.queryByLabelText("License file")).not.toBeInTheDocument();
		expect(
			screen.getByText("Only workspace owners and admins can import a license."),
		).toBeInTheDocument();
	});
});

describe("license submission", () => {
	it("only accepts an aidr-license-v1 JSON object and sends it to license-admin", async () => {
		expect(parseLicenseFile("not json")).toBeNull();
		expect(parseLicenseFile(JSON.stringify({ format: "other" }))).toBeNull();
		expect(parseLicenseFile("x".repeat(70_000))).toBeNull();
		const document = { format: "aidr-license-v1", key_id: "k", payload: {}, sig: "AA==" };
		expect(parseLicenseFile(JSON.stringify(document))).toEqual(document);
		vi.mocked(supabase.functions.invoke).mockResolvedValue({
			data: {
				ok: true,
				status: "pending",
				license: {
					license_id: "LIC-1",
					seats: 5,
					expires_at: "2028-01-01T00:00:00Z",
					grace_ends_at: "2028-01-15T00:00:00Z",
					status: "valid",
				},
			},
			error: null,
		} as never);
		await expect(submitLicense(tenantId, document)).resolves.toMatchObject({
			ok: true,
			licenseId: "LIC-1",
			seats: 5,
		});
		expect(supabase.functions.invoke).toHaveBeenCalledWith("license-admin", {
			body: { action: "submit", tenant_id: tenantId, license: document },
		});
		expect(licenseSubmitErrorKey("license_rejected")).toBe("license.err.rejected");
		expect(licenseSubmitErrorKey(null)).toBe("license.err.unavailable");
	});
});
