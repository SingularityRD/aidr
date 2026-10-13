// @vitest-environment jsdom

/**
 * PRD-15: dashboard English / Turkish catalogs and the language switcher.
 * English stays the default text; Turkish must cover exactly the same keys
 * and parameters, and every key must be used by a component.
 */
import "@testing-library/jest-dom/vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { getSession } = vi.hoisted(() => ({ getSession: vi.fn() }));
vi.mock("../lib/supabase", () => ({ supabase: { auth: {} }, supabaseEnvError: null }));
vi.mock("../ui/session", () => ({ getSession, signOut: vi.fn() }));
vi.mock("../enterprise/team-provider", () => ({
	TeamProvider: ({ children }: { children: React.ReactNode }) => children,
	useTeam: () => ({
		canEditPolicy: true,
		roleResolved: true,
		currentRole: "owner",
		isLoading: false,
		currentTeam: null,
		error: null,
	}),
}));

import { en } from "../i18n/en";
import {
	DASHBOARD_CATALOGS,
	detectDashboardLocale,
	I18nProvider,
	LOCALE_STORAGE_KEY,
	translate,
} from "../i18n/I18nProvider";
import { tr } from "../i18n/tr";
import { AppLayout } from "../ui/AppLayout";
import { NotFoundPage } from "../ui/NotFoundPage";
import { LoginPage } from "../ui/pages/LoginPage";

const SRC = resolve(__dirname, "..");

/** Product, plan and protocol names that stay the same in Turkish. */
const UNTRANSLATED_NAMES = new Set(["Browser Guard", "Singularity AIDR", "Claude Code"]);

function placeholders(text: string): string[] {
	return [...text.matchAll(/\{(\w+)\}/g)].map((m) => m[1] as string).sort();
}

function sources(dir: string, out: string[] = []): string[] {
	for (const entry of readdirSync(dir)) {
		// The catalogs themselves (en.ts, tr.ts and the page message modules)
		// define the keys, so they cannot count as a use.
		if (entry === "__tests__" || entry === "en.ts" || entry === "tr.ts" || entry === "messages")
			continue;
		const path = join(dir, entry);
		if (statSync(path).isDirectory()) sources(path, out);
		else if (/\.tsx?$/.test(entry)) out.push(path);
	}
	return out;
}

beforeEach(() => {
	localStorage.clear();
	getSession.mockResolvedValue(null);
	window.__AIDR_CONFIG__ = { authMethods: ["password", "magic-link"] };
});

afterEach(() => {
	cleanup();
	vi.restoreAllMocks();
	delete window.__AIDR_CONFIG__;
});

describe("dashboard catalog parity", () => {
	it("has the same keys and parameters in en and tr", () => {
		expect(Object.keys(tr).sort()).toEqual(Object.keys(en).sort());
		for (const [key, english] of Object.entries(en)) {
			const turkish = tr[key as keyof typeof en];
			expect(turkish.trim(), key).not.toBe("");
			expect(placeholders(turkish), key).toEqual(placeholders(english));
		}
	});

	it("has no unused keys", () => {
		const corpus = sources(SRC)
			.map((file) => readFileSync(file, "utf8"))
			.join("\n");
		const unused = Object.keys(en).filter((key) => !corpus.includes(`"${key}"`));
		expect(unused).toEqual([]);
	});

	it("translates (no Turkish value is a copied English sentence)", () => {
		const copied = Object.entries(en).filter(
			([key, english]) =>
				tr[key as keyof typeof en] === english &&
				!UNTRANSLATED_NAMES.has(english) &&
				/[a-z]{3,} [a-z]{3,}/i.test(english),
		);
		expect(copied).toEqual([]);
		expect(Object.keys(DASHBOARD_CATALOGS).sort()).toEqual(["en", "tr"]);
		expect(translate("tr", "login.continueWith", { provider: "GitHub" })).toBe(
			"GitHub ile devam et",
		);
	});
});

describe("locale detection", () => {
	it("prefers the saved choice, then a Turkish browser, then English", () => {
		const languages = vi.spyOn(window.navigator, "languages", "get");
		languages.mockReturnValue(["en-US"]);
		expect(detectDashboardLocale()).toBe("en");
		languages.mockReturnValue(["tr-TR", "en-US"]);
		expect(detectDashboardLocale()).toBe("tr");
		localStorage.setItem(LOCALE_STORAGE_KEY, "en");
		expect(detectDashboardLocale()).toBe("en");
	});
});

describe("rendered pages", () => {
	it("keeps English text when rendered without a provider", () => {
		render(
			<MemoryRouter>
				<NotFoundPage />
			</MemoryRouter>,
		);
		expect(screen.getByRole("heading", { name: "Page not found" })).toBeInTheDocument();
	});

	it("renders the sign-in page in Turkish", () => {
		render(
			<I18nProvider initialLocale="tr">
				<MemoryRouter initialEntries={["/login"]}>
					<LoginPage />
				</MemoryRouter>
			</I18nProvider>,
		);
		expect(screen.getByRole("heading", { name: "AIDR'ye hoş geldiniz" })).toBeInTheDocument();
		expect(screen.getByLabelText("E-posta adresi")).toBeInTheDocument();
		expect(screen.getByLabelText("Parola")).toBeInTheDocument();
		expect(screen.getByRole("button", { name: "Oturum aç" })).toBeInTheDocument();
		expect(document.documentElement).toHaveAttribute("lang", "tr");
	});

	it("switches the dashboard shell language and remembers the choice", () => {
		render(
			<I18nProvider initialLocale="en">
				<MemoryRouter initialEntries={["/dashboard"]}>
					<Routes>
						<Route path="/" element={<AppLayout />}>
							<Route path="dashboard" element={<p>content</p>} />
						</Route>
					</Routes>
				</MemoryRouter>
			</I18nProvider>,
		);
		expect(screen.getByRole("link", { name: "Approvals" })).toBeInTheDocument();
		expect(screen.getByRole("button", { name: "Sign out" })).toBeInTheDocument();

		fireEvent.click(screen.getByRole("button", { name: "Switch the dashboard to Turkish" }));

		expect(screen.getByRole("link", { name: "Onaylar" })).toBeInTheDocument();
		expect(screen.getByRole("navigation", { name: "Panel" })).toBeInTheDocument();
		expect(screen.getByRole("button", { name: "Oturumu kapat" })).toBeInTheDocument();
		expect(localStorage.getItem(LOCALE_STORAGE_KEY)).toBe("tr");
		expect(document.documentElement).toHaveAttribute("lang", "tr");

		fireEvent.click(screen.getByRole("button", { name: "Paneli İngilizceye geçir" }));
		expect(screen.getByRole("link", { name: "Approvals" })).toBeInTheDocument();
		expect(localStorage.getItem(LOCALE_STORAGE_KEY)).toBe("en");
	});
});
