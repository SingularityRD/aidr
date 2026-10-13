// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { from, invoke, useTeam } = vi.hoisted(() => ({
	from: vi.fn(),
	invoke: vi.fn(),
	useTeam: vi.fn(),
}));

vi.mock("../lib/supabase", () => ({ supabase: { from, functions: { invoke } } }));
vi.mock("../enterprise/team-provider", () => ({ useTeam }));

import { I18nProvider } from "../i18n/I18nProvider";
import {
	checksumCommand,
	detectVisitorPlatform,
	readInstallerCatalog,
	recommendedInstaller,
	requestInstallerDownload,
} from "../lib/installers";
import { BROWSER_GUARD_FIREFOX_ID, browserGuardLinks } from "../onboarding/BrowserGuardDownloads";
import { DownloadsPage } from "../ui/pages/DownloadsPage";
import { OnboardingPage } from "../ui/pages/OnboardingPage";

const TEAM = { id: "22222222-2222-4222-8222-222222222222", name: "Acme" };
const WIN_SHA = "a".repeat(64);
const LINUX_SHA = "b".repeat(64);

function catalogResponse(overrides: Record<string, unknown> = {}) {
	return {
		ok: true,
		catalog: {
			version: "1.4.0",
			published_at: "2026-10-12T09:00:00.000Z",
			release_notes_url: "https://docs.example.com/releases/1.4.0",
			release_tag: "v1.4.0",
			files: [
				{
					platform: "windows-x64",
					os: "windows",
					arch: "x64",
					file: "AIDR-Setup-1.4.0-x64.msi",
					size: 50 * 1024 * 1024,
					sha256: WIN_SHA,
					minimum_os: "Windows 10",
					format: "msi",
				},
				{
					platform: "linux-x64",
					os: "linux",
					arch: "x64",
					file: "aidr-install-1.4.0-linux-x64.sh",
					size: 40 * 1024 * 1024,
					sha256: LINUX_SHA,
					minimum_os: "glibc 2.28",
					format: "sh",
				},
			],
		},
		managed_enrollment: { available: true, control_plane_url: "https://api.customer.example" },
		...overrides,
	};
}

const LINKS = {
	chromeUrl: "https://chromewebstore.google.com/detail/abc",
	edgeUrl: "https://microsoftedge.microsoft.com/addons/detail/abc",
	firefoxUrl: "https://addons.mozilla.org/firefox/addon/aidr",
	chromeId: "a".repeat(32),
	edgeId: "b".repeat(32),
	adminGuideUrl: "https://docs.example.com/aidr/admin",
};
const NO_LINKS = {
	chromeUrl: null,
	edgeUrl: null,
	firefoxUrl: null,
	chromeId: null,
	edgeId: null,
	adminGuideUrl: null,
};

function httpError(status: number, error: string) {
	return {
		data: null,
		error: {
			message: "Edge Function returned a non-2xx status code",
			context: new Response(JSON.stringify({ error }), { status }),
		},
	};
}

function renderPage(props: Parameters<typeof DownloadsPage>[0] = {}, locale: "en" | "tr" = "en") {
	return render(
		<I18nProvider initialLocale={locale}>
			<MemoryRouter>
				<DownloadsPage links={LINKS} {...props} />
			</MemoryRouter>
		</I18nProvider>,
	);
}

beforeEach(() => {
	vi.clearAllMocks();
	useTeam.mockReturnValue({
		currentTeam: TEAM,
		currentRole: "member",
		isLoading: false,
		roleResolved: true,
		error: null,
	});
	const chain = {
		select: () => chain,
		eq: () => chain,
		order: () => chain,
		limit: async () => ({ data: [], error: null }),
	};
	from.mockImplementation(() => chain);
	invoke.mockImplementation(async (name: string) =>
		name === "installer-download"
			? { data: catalogResponse(), error: null }
			: { data: null, error: null },
	);
});
afterEach(() => {
	cleanup();
	vi.unstubAllEnvs();
});

describe("download page", () => {
	it("highlights the Windows installer for a Windows visitor and lists the others", async () => {
		renderPage({ visitorOs: { os: "windows", arch: "x64" } });
		const recommended = await screen.findByRole("region", { name: "Windows (x64)" });
		expect(within(recommended).getByText("Recommended for this computer")).toBeInTheDocument();
		expect(
			within(recommended).getByRole("button", { name: "Download AIDR-Setup-1.4.0-x64.msi" }),
		).toBeInTheDocument();
		expect(within(recommended).getByText(WIN_SHA)).toBeInTheDocument();
		expect(within(recommended).getByText(/50 MiB · requires Windows 10/)).toBeInTheDocument();
		expect(
			within(recommended).getByText(
				`(Get-FileHash -Algorithm SHA256 ".\\AIDR-Setup-1.4.0-x64.msi").Hash.ToLower() -eq "${WIN_SHA}"`,
			),
		).toBeInTheDocument();
		const other = screen.getByRole("region", { name: "Linux (x64)" });
		expect(within(other).queryByText("Recommended for this computer")).toBeNull();
		expect(screen.getByRole("heading", { name: "Other platforms" })).toBeInTheDocument();
		expect(screen.getByRole("link", { name: "Release notes" })).toHaveAttribute(
			"href",
			"https://docs.example.com/releases/1.4.0",
		);
		expect(screen.queryByText(/macOS installer is not available/)).toBeNull();
		expect(invoke).toHaveBeenCalledWith("installer-download", {
			method: "GET",
			headers: { "X-AIDR-Tenant-ID": TEAM.id },
		});
	});

	it("tells a macOS visitor honestly that there is no installer and points to Browser Guard", async () => {
		renderPage({ visitorOs: { os: "macos", arch: "arm64" } });
		expect(
			await screen.findByText(
				/A macOS installer is not available yet\. Browser Guard, below, works in Chrome, Edge and Firefox on macOS\./,
			),
		).toBeInTheDocument();
		expect(screen.queryByText("Recommended for this computer")).toBeNull();
		expect(screen.getByRole("region", { name: "Windows (x64)" })).toBeInTheDocument();
		expect(screen.getByRole("link", { name: "Add to Chrome" })).toBeInTheDocument();
	});

	it("mints a link only on click, then starts the download", async () => {
		invoke.mockImplementation(async (name: string, options: { method: string }) =>
			options.method === "POST"
				? {
						data: {
							ok: true,
							url: "https://api.customer.example/storage/v1/object/sign/aidr-installers/1.4.0/linux-x64/x.sh?token=t",
							expires_at: "2026-10-13T10:05:00.000Z",
							file: "aidr-install-1.4.0-linux-x64.sh",
							sha256: LINUX_SHA,
						},
						error: null,
					}
				: { data: catalogResponse(), error: null },
		);
		renderPage({ visitorOs: { os: "linux", arch: "x64" } });
		const button = await screen.findByRole("button", {
			name: "Download aidr-install-1.4.0-linux-x64.sh",
		});
		expect(invoke).toHaveBeenCalledTimes(1);
		fireEvent.click(button);
		await waitFor(() =>
			expect(invoke).toHaveBeenCalledWith("installer-download", {
				method: "POST",
				body: { tenant_id: TEAM.id, version: "1.4.0", platform: "linux-x64" },
			}),
		);
		expect(await screen.findByRole("link", { name: "use this direct link" })).toHaveAttribute(
			"href",
			"https://api.customer.example/storage/v1/object/sign/aidr-installers/1.4.0/linux-x64/x.sh?token=t",
		);
	});

	it("refuses a link whose checksum disagrees with the listed installer", async () => {
		invoke.mockImplementation(async (_name: string, options: { method: string }) =>
			options.method === "POST"
				? {
						data: {
							ok: true,
							url: "https://api.customer.example/x?token=t",
							expires_at: "2026-10-13T10:05:00.000Z",
							file: "x",
							sha256: "c".repeat(64),
						},
						error: null,
					}
				: { data: catalogResponse(), error: null },
		);
		renderPage({ visitorOs: { os: "windows", arch: "x64" } });
		fireEvent.click(
			await screen.findByRole("button", { name: "Download AIDR-Setup-1.4.0-x64.msi" }),
		);
		expect(await screen.findByRole("alert")).toHaveTextContent(
			"The download link could not be created",
		);
		expect(screen.queryByRole("link", { name: "use this direct link" })).toBeNull();
	});

	it("shows managed enrollment only when the control plane offers it", async () => {
		renderPage({ visitorOs: { os: "windows", arch: "x64" } });
		expect(await screen.findByText("https://api.customer.example")).toBeInTheDocument();
		const managed = screen.getByRole("region", {
			name: "Connect this computer to your workspace (managed mode)",
		});
		expect(within(managed).getByRole("link", { name: "Verify a device code" })).toHaveAttribute(
			"href",
			`/verify?team=${TEAM.id}`,
		);
		cleanup();
		invoke.mockResolvedValue({
			data: catalogResponse({ managed_enrollment: { available: false } }),
			error: null,
		});
		renderPage({ visitorOs: { os: "windows", arch: "x64" } });
		await screen.findByRole("region", { name: "Windows (x64)" });
		expect(
			screen.queryByRole("region", {
				name: "Connect this computer to your workspace (managed mode)",
			}),
		).toBeNull();
	});

	it("explains an unentitled workspace and lists no installer", async () => {
		invoke.mockResolvedValue(httpError(403, "entitlement_required"));
		renderPage({ visitorOs: { os: "windows", arch: "x64" } });
		expect(
			await screen.findByText(/Downloads need an active licence or trial/),
		).toBeInTheDocument();
		expect(screen.queryByRole("button", { name: /^Download / })).toBeNull();
		expect(screen.queryByRole("button", { name: "Try again" })).toBeNull();
	});

	it("withholds downloads when the catalog fails its signature check", async () => {
		invoke.mockResolvedValue(httpError(503, "catalog_integrity_failed"));
		renderPage({ visitorOs: { os: "windows", arch: "x64" } });
		expect(await screen.findByText(/failed its signature check/)).toBeInTheDocument();
		expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument();
	});

	it("hides store links and IDs that are not configured", async () => {
		renderPage({ links: NO_LINKS, visitorOs: { os: "windows", arch: "x64" } });
		await screen.findByRole("region", { name: "Windows (x64)" });
		expect(screen.queryByRole("link", { name: /Add to/ })).toBeNull();
		expect(screen.getByText(/Store links are not configured/)).toBeInTheDocument();
		// The Firefox ID is fixed by the build; Chromium IDs come from configuration only.
		expect(screen.getByText(BROWSER_GUARD_FIREFOX_ID)).toBeInTheDocument();
		expect(screen.queryByText("a".repeat(32))).toBeNull();
		expect(screen.queryByRole("link", { name: "Open the administrator guide" })).toBeNull();
		expect(screen.getByText(/ships with your release bundle/)).toBeInTheDocument();
	});

	it("shows every configured store link, the extension IDs and the admin guide", async () => {
		renderPage({ visitorOs: { os: "windows", arch: "x64" } });
		await screen.findByRole("region", { name: "Windows (x64)" });
		expect(screen.getByRole("link", { name: "Add to Edge" })).toHaveAttribute(
			"href",
			LINKS.edgeUrl,
		);
		expect(screen.getByRole("link", { name: "Add to Firefox" })).toHaveAttribute(
			"rel",
			"noreferrer",
		);
		expect(screen.getByText("b".repeat(32))).toBeInTheDocument();
		expect(screen.getByRole("heading", { name: "IT / MDM deployment" })).toBeInTheDocument();
		expect(screen.getByRole("link", { name: "Open the administrator guide" })).toHaveAttribute(
			"href",
			LINKS.adminGuideUrl,
		);
	});

	it("renders in Turkish", async () => {
		renderPage({ visitorOs: { os: "macos", arch: "x64" } }, "tr");
		expect(screen.getByRole("heading", { level: 1, name: "İndir" })).toBeInTheDocument();
		expect(await screen.findByText(/macOS yükleyicisi henüz sunulmuyor/)).toBeInTheDocument();
		expect(
			screen.getByRole("button", { name: "AIDR-Setup-1.4.0-x64.msi dosyasını indir" }),
		).toBeInTheDocument();
		expect(screen.getByRole("heading", { name: "BT / MDM dağıtımı" })).toBeInTheDocument();
		expect(screen.getByRole("link", { name: "Chrome'a ekle" })).toBeInTheDocument();
	});
});

describe("onboarding", () => {
	it("starts with the installer and keeps manual steps behind a disclosure", async () => {
		useTeam.mockReturnValue({
			currentTeam: TEAM,
			currentRole: "owner",
			isLoading: false,
			roleResolved: true,
			error: null,
		});
		render(
			<MemoryRouter>
				<OnboardingPage />
			</MemoryRouter>,
		);
		const headings = screen
			.getAllByRole("heading", { level: 2 })
			.map((heading) => heading.textContent);
		expect(headings[0]).toBe("1) Download and run the installer");
		const install = screen.getByRole("region", { name: "1) Download and run the installer" });
		expect(await within(install).findAllByRole("button", { name: /^Download / })).toHaveLength(2);
		const manual = screen.getByRole("heading", { name: "1) Choose runtime" }).closest("details");
		expect(manual).not.toBeNull();
		expect(manual).not.toHaveAttribute("open");
		expect(
			within(manual as HTMLElement).getByText("Advanced: manual setup and device authorization"),
		).toBeInTheDocument();
		expect(screen.getByRole("link", { name: "Open the Download page" })).toHaveAttribute(
			"href",
			"/downloads",
		);
	});
});

describe("installer client", () => {
	it("reads only well-formed catalogs and skips platforms it does not know", () => {
		const catalog = readInstallerCatalog(catalogResponse());
		expect(catalog?.files.map((file) => file.platform)).toEqual(["windows-x64", "linux-x64"]);
		expect(catalog?.controlPlaneUrl).toBe("https://api.customer.example");
		const future = catalogResponse();
		future.catalog.files.push({
			platform: "macos-arm64",
			os: "macos",
			arch: "arm64",
			file: "AIDR.pkg",
			size: 1,
			sha256: "c".repeat(64),
			minimum_os: "macOS 12",
			format: "pkg",
		});
		expect(readInstallerCatalog(future)?.files).toHaveLength(2);
		const bad = catalogResponse();
		bad.catalog.files = bad.catalog.files.map((file, index) =>
			index === 0 ? { ...file, sha256: "not-a-digest" } : file,
		);
		expect(readInstallerCatalog(bad)).toBeNull();
		const unsafe = catalogResponse({
			managed_enrollment: { available: true, control_plane_url: "javascript:alert(1)" },
		});
		expect(readInstallerCatalog(unsafe)?.controlPlaneUrl).toBeNull();
		const notes = catalogResponse();
		notes.catalog.release_notes_url = "http://plain.example";
		expect(readInstallerCatalog(notes)?.releaseNotesUrl).toBeNull();
		expect(readInstallerCatalog({ ok: false })).toBeNull();
	});

	it("rejects a download answer without an https URL", async () => {
		invoke.mockResolvedValue({
			data: { ok: true, url: "http://evil.example/x", expires_at: "x", file: "f", sha256: WIN_SHA },
			error: null,
		});
		expect(await requestInstallerDownload(TEAM.id, "1.4.0", "windows-x64")).toEqual({
			ok: false,
			error: "download_unavailable",
		});
		invoke.mockResolvedValue(httpError(429, "rate_limited"));
		expect(await requestInstallerDownload(TEAM.id, "1.4.0", "windows-x64")).toEqual({
			ok: false,
			error: "rate_limited",
		});
	});

	it("detects the visitor OS and picks the matching installer", () => {
		const ua = (userAgent: string, platform?: string) =>
			detectVisitorPlatform({ userAgent, userAgentData: platform ? { platform } : undefined });
		expect(ua("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")).toEqual({ os: "windows", arch: "x64" });
		expect(ua("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0)")).toEqual({
			os: "macos",
			arch: "x64",
		});
		expect(ua("Mozilla/5.0 (X11; Linux aarch64)")).toEqual({ os: "linux", arch: "arm64" });
		expect(ua("Mozilla/5.0 (Linux; Android 14)")).toEqual({ os: "unknown", arch: "x64" });
		expect(ua("", "Windows").os).toBe("windows");
		const files = readInstallerCatalog(catalogResponse())?.files ?? [];
		expect(recommendedInstaller(files, { os: "linux", arch: "arm64" })?.platform).toBe("linux-x64");
		expect(recommendedInstaller(files, { os: "macos", arch: "arm64" })).toBeNull();
		expect(checksumCommand(files[1] as (typeof files)[number])).toBe(
			`echo "${LINUX_SHA}  aidr-install-1.4.0-linux-x64.sh" | sha256sum --check -`,
		);
	});

	it("takes Browser Guard links only from https configuration", () => {
		expect(
			browserGuardLinks({
				VITE_BROWSER_GUARD_CHROME_URL: "https://chromewebstore.google.com/detail/x",
				VITE_BROWSER_GUARD_EDGE_URL: "http://insecure.example",
				VITE_BROWSER_GUARD_CHROME_EXTENSION_ID: "a".repeat(32),
				VITE_BROWSER_GUARD_EDGE_EXTENSION_ID: "not-an-id",
			}),
		).toEqual({
			chromeUrl: "https://chromewebstore.google.com/detail/x",
			edgeUrl: null,
			firefoxUrl: null,
			chromeId: "a".repeat(32),
			edgeId: null,
			adminGuideUrl: null,
		});
	});
});
