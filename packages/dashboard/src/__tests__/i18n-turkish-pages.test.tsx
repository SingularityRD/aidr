// @vitest-environment jsdom
/**
 * The Turkish console really is Turkish: helpers that build messages outside
 * React take the viewer's translator, and pages render their copy from the
 * Turkish catalog. English defaults stay unchanged (the other suites pin them).
 */
import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen } from "@testing-library/react";
import type { ReactElement } from "react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it } from "vitest";
import { I18nProvider, type Translate, translate } from "../i18n/I18nProvider";
import { complianceErrorText } from "../lib/compliance-report";
import { exceptionErrorMessage } from "../lib/detection-exceptions";
import { governanceErrorText, settingsProblem } from "../lib/governance";
import { operatorErrorMessage } from "../lib/operator-admin";
import { policyManagementMessage } from "../lib/policy-management";
import { buildSyslogAdapter, DEFAULT_SYSLOG_FORM } from "../lib/siem-syslog-config";
import { DirectoryAuthorityPanel } from "../ui/pages/DirectoryAuthorityPanel";
import { PublicInfoPage } from "../ui/pages/public/PublicInfoPage";
import { SiemPage } from "../ui/pages/SiemPage";

const tr: Translate = (key, params) => translate("tr", key, params);

afterEach(cleanup);

describe("Turkish messages from helpers", () => {
	it("translates service errors when given the Turkish translator", () => {
		expect(governanceErrorText("mfa_required", tr)).toMatch(/çok adımlı/i);
		expect(complianceErrorText("period_too_long", tr)).toBe(
			"Bir rapor en fazla 366 günü kapsayabilir.",
		);
		expect(exceptionErrorMessage("detection_exception_quota", tr)).toMatch(/en fazla 500/);
		expect(operatorErrorMessage("tenant_not_found", "", tr)).toBe(
			"Bu kimliğe sahip çalışma alanı yok.",
		);
		expect(policyManagementMessage("revision_not_found", tr)).toBe("Bu revizyon artık yok.");
		// Unknown codes still fall back to a translated, fixed message.
		expect(governanceErrorText("something_new", tr)).toMatch(/alınamıyor/);
	});

	it("keeps English as the default for callers without a translator", () => {
		expect(complianceErrorText("period_too_long")).toBe("A report can cover at most 366 days.");
		expect(
			settingsProblem({
				digestEnabled: false,
				digestCadence: "weekly",
				digestRecipients: "owners",
				oversightFastSeconds: 0,
				oversightMinDecisions: 5,
				oversightFastShare: 0.8,
			}),
		).toMatch(/^Fast-approval time/);
	});

	it("validates the SIEM form in Turkish", () => {
		const result = buildSyslogAdapter({ ...DEFAULT_SYSLOG_FORM, host: "" }, tr);
		expect(result.ok).toBe(false);
		if (!result.ok)
			expect(result.errors).toContain("Toplayıcı sunucusunun adını ya da adresini girin.");
	});
});

describe("Turkish pages", () => {
	function renderTr(element: ReactElement) {
		return render(
			<I18nProvider initialLocale="tr">
				<MemoryRouter>{element}</MemoryRouter>
			</I18nProvider>,
		);
	}

	it("renders the SIEM page in Turkish", () => {
		renderTr(<SiemPage />);
		expect(screen.getByRole("heading", { level: 1, name: "SIEM syslog hedefi" })).toBeVisible();
		expect(screen.getByText("Aktarım")).toBeInTheDocument();
	});

	it("renders a public page in Turkish without hiding the fail-closed notice", () => {
		renderTr(<PublicInfoPage kind="status" />);
		expect(screen.getByRole("heading", { level: 1, name: "Hizmet durumu" })).toBeVisible();
		expect(screen.getByRole("alert")).toHaveTextContent(/canlı bir durum akışı yapılandırılmamış/);
	});

	it("renders the directory-authoritative panel in Turkish", () => {
		renderTr(
			<DirectoryAuthorityPanel
				authority={{ enabled: false, directory_id: null, break_glass_user_ids: [] }}
				directories={[]}
				owners={[]}
				currentUserId="00000000-0000-4000-8000-000000000001"
				busy={false}
				onChange={async () => true}
			/>,
		);
		expect(screen.getByRole("heading", { name: "Dizinin belirlediği üyelik" })).toBeVisible();
		expect(screen.getByText(/elle eklenen üyelikler/)).toBeInTheDocument();
	});
});
