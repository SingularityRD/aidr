// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { from, invoke, useTeam, agentsResult } = vi.hoisted(() => ({
	from: vi.fn(),
	invoke: vi.fn(),
	useTeam: vi.fn(),
	agentsResult: { current: { data: [] as unknown, error: null as unknown } },
}));

vi.mock("../lib/supabase", () => ({ supabase: { from, functions: { invoke } } }));
vi.mock("../enterprise/team-provider", () => ({ useTeam }));

import { DownloadsPage } from "../ui/pages/DownloadsPage";
import { OnboardingPage } from "../ui/pages/OnboardingPage";

const TEAM = { id: "team-downloads", name: "Download team" };
const SHA = "d".repeat(64);

function releaseManifest(
	url = "https://downloads.customer.example/aidr/2.0.0/aidr-claude-plugin-2.0.0.tar.gz",
) {
	return {
		version: "2.0.0",
		publishedAt: "2026-09-20T10:00:00Z",
		artifacts: [
			{
				id: "claude-code",
				version: "2.0.0",
				url,
				sha256: SHA,
				signature:
					"https://downloads.customer.example/aidr/2.0.0/aidr-claude-plugin-2.0.0.tar.gz.sig",
				size: 5 * 1024 * 1024,
				platforms: ["any"],
			},
			{
				id: "cursor",
				version: "2.0.0",
				url: "https://downloads.customer.example/aidr/2.0.0/aidr-cursor.vsix",
				sha256: "e".repeat(64),
				size: 900,
				platforms: ["any"],
			},
		],
	};
}

function queryChain() {
	const chain = {
		select: vi.fn(() => chain),
		eq: vi.fn(() => chain),
		order: vi.fn(() => chain),
		limit: vi.fn(async () => agentsResult.current),
	};
	return chain;
}

function renderAt(element: React.ReactElement) {
	return render(<MemoryRouter>{element}</MemoryRouter>);
}

function card(label: string) {
	return screen.getByRole("region", { name: label });
}

describe("download center", () => {
	beforeEach(() => {
		vi.clearAllMocks();
		useTeam.mockReturnValue({
			currentTeam: TEAM,
			currentRole: "owner",
			isLoading: false,
			roleResolved: true,
			error: null,
		});
		agentsResult.current = { data: [], error: null };
		from.mockImplementation(() => queryChain());
		invoke.mockResolvedValue({ data: { ok: true, status: "approved" }, error: null });
		vi.stubGlobal("fetch", vi.fn());
	});
	afterEach(() => {
		cleanup();
		vi.unstubAllGlobals();
		delete window.__AIDR_CONFIG__;
	});

	it("shows a not-configured state with install guidance and no download links", async () => {
		renderAt(<DownloadsPage />);
		expect(screen.getByRole("heading", { level: 1, name: "Downloads" })).toBeInTheDocument();
		expect(
			screen.getByText(/No release manifest is published for this deployment/),
		).toBeInTheDocument();
		expect(screen.queryAllByRole("link", { name: /^Download / })).toHaveLength(0);
		expect(fetch).not.toHaveBeenCalled();
		for (const label of [
			"Claude Code",
			"Cursor",
			"VS Code",
			"OpenClaw",
			"OpenCode",
			"Codex CLI",
			"AIDR CLI",
			"Browser Guard for Chrome and Edge",
			"Browser Guard for Firefox",
			"MCP gateway",
		]) {
			expect(card(label)).toBeInTheDocument();
		}
		expect(
			within(card("Claude Code")).getByText(
				"/plugin marketplace add /absolute/path/to/aidr-claude-plugin\n/plugin install aidr@aidr",
				{ normalizer: (text) => text },
			),
		).toBeInTheDocument();
		expect(
			within(card("OpenClaw")).getByText(
				/openclaw plugins install npm:@singularityrd\/aidr-openclaw@VERSION/,
			),
		).toBeInTheDocument();
		expect(
			within(card("Claude Code")).getByRole("link", { name: "Verify a device code" }),
		).toHaveAttribute("href", "/verify?team=team-downloads");
		expect(
			within(card("Browser Guard for Firefox")).getByRole("link", {
				name: "Create a Browser Guard key",
			}),
		).toHaveAttribute("href", "/api-keys?type=browser_guard");
		await waitFor(() =>
			expect(within(card("Claude Code")).getByText("Not detected yet")).toBeInTheDocument(),
		);
		expect(within(card("MCP gateway")).getByText("No control-plane check-in")).toBeInTheDocument();
		expect(from).toHaveBeenCalledWith("agents");
	});

	it("renders verified downloads, digests and verify commands from a same-origin manifest", async () => {
		window.__AIDR_CONFIG__ = { releaseManifestUrl: "/release-manifest.json" };
		vi.mocked(fetch).mockResolvedValue(
			new Response(JSON.stringify(releaseManifest()), { status: 200 }),
		);
		agentsResult.current = {
			data: [
				{
					agent_runtime: "cursor",
					agent_runtime_version: "1.0.0",
					last_seen: "2026-09-23T09:00:00Z",
				},
				{
					agent_runtime: "browser_guard",
					agent_runtime_version: "edge-126",
					last_seen: "2026-09-22T09:00:00Z",
				},
			],
			error: null,
		};
		renderAt(<DownloadsPage />);
		const claude = card("Claude Code");
		const download = await within(claude).findByRole("link", {
			name: "Download aidr-claude-plugin-2.0.0.tar.gz",
		});
		expect(fetch).toHaveBeenCalledWith(
			`${window.location.origin}/release-manifest.json`,
			expect.objectContaining({ credentials: "omit", redirect: "error" }),
		);
		expect(download).toHaveAttribute("href", releaseManifest().artifacts[0]?.url);
		expect(download).toHaveAttribute("download", "aidr-claude-plugin-2.0.0.tar.gz");
		expect(
			within(claude).getByLabelText("SHA-256 for Claude Code aidr-claude-plugin-2.0.0.tar.gz"),
		).toHaveTextContent(SHA);
		expect(
			within(claude).getByText(
				`echo "${SHA}  aidr-claude-plugin-2.0.0.tar.gz" | sha256sum --check`,
				{
					normalizer: (text) => text,
				},
			),
		).toBeInTheDocument();
		expect(within(claude).getByText(/5\.0 MiB/)).toBeInTheDocument();
		expect(
			within(claude).getByRole("link", {
				name: "Detached signature for aidr-claude-plugin-2.0.0.tar.gz",
			}),
		).toHaveAttribute("href", releaseManifest().artifacts[0]?.signature);
		expect(
			within(claude).getByText(
				/tar -xzf aidr-claude-plugin-2\.0\.0\.tar\.gz -C aidr-claude-plugin/,
			),
		).toBeInTheDocument();
		expect(
			within(card("Cursor")).getByText("cursor --install-extension ./aidr-cursor.vsix"),
		).toBeInTheDocument();
		expect(
			within(card("OpenClaw")).getByText("Release 2.0.0 does not include a OpenClaw artifact."),
		).toBeInTheDocument();
		expect(screen.getByText(/Release 2\.0\.0 · published/)).toBeInTheDocument();

		await waitFor(() =>
			expect(within(card("Cursor")).getByText(/^Detected · last check-in/)).toBeInTheDocument(),
		);
		expect(
			within(card("Browser Guard for Chrome and Edge")).getByText(/^Detected · last check-in/),
		).toBeInTheDocument();
		expect(
			within(card("Browser Guard for Firefox")).getByText("Not detected yet"),
		).toBeInTheDocument();
		expect(within(claude).getByText("Not detected yet")).toBeInTheDocument();
		for (const link of screen.getAllByRole("link", { name: /^Download / })) {
			expect(link.getAttribute("href")).toMatch(/^https:\/\//);
		}

		const writeText = vi.fn(async () => undefined);
		Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
		fireEvent.click(
			within(claude).getByRole("button", {
				name: "Copy SHA-256 for aidr-claude-plugin-2.0.0.tar.gz",
			}),
		);
		await waitFor(() => expect(writeText).toHaveBeenCalledWith(SHA));
	});

	it("withholds every download when the manifest contains an http: link", async () => {
		window.__AIDR_CONFIG__ = {
			releaseManifestUrl: "https://downloads.customer.example/release-manifest.json",
		};
		vi.mocked(fetch).mockResolvedValue(
			new Response(
				JSON.stringify(releaseManifest("http://downloads.customer.example/plugin.tar.gz")),
				{ status: 200 },
			),
		);
		renderAt(<DownloadsPage />);
		expect(await screen.findByRole("alert")).toHaveTextContent(
			/Downloads are withheld.*must use https/,
		);
		expect(screen.queryAllByRole("link", { name: /^Download / })).toHaveLength(0);
	});

	it("refuses an http: manifest URL without fetching it", async () => {
		window.__AIDR_CONFIG__ = {
			releaseManifestUrl: "http://downloads.customer.example/release-manifest.json",
		};
		renderAt(<DownloadsPage />);
		expect(screen.getByRole("alert")).toHaveTextContent(/not an HTTPS or same-origin address/);
		expect(fetch).not.toHaveBeenCalled();
	});

	it("reports unavailable check-ins instead of claiming a runtime is not installed", async () => {
		agentsResult.current = { data: null, error: { message: "permission denied" } };
		renderAt(<DownloadsPage />);
		await waitFor(() =>
			expect(
				within(card("Codex CLI")).getByText("Check-in status unavailable"),
			).toBeInTheDocument(),
		);
		expect(screen.queryByText("Not detected yet")).not.toBeInTheDocument();
	});

	it("adds a Download & connect step to onboarding for the selected runtime", async () => {
		window.__AIDR_CONFIG__ = { releaseManifestUrl: "/release-manifest.json" };
		vi.mocked(fetch).mockResolvedValue(
			new Response(JSON.stringify(releaseManifest()), { status: 200 }),
		);
		renderAt(<OnboardingPage />);
		expect(screen.getByRole("heading", { name: "2) Download & connect" })).toBeInTheDocument();
		expect(screen.getByRole("heading", { name: "3) Authorize" })).toBeInTheDocument();
		expect(screen.getByRole("link", { name: "All downloads" })).toHaveAttribute(
			"href",
			"/downloads",
		);
		expect(
			await screen.findByRole("link", { name: "Download aidr-claude-plugin-2.0.0.tar.gz" }),
		).toBeInTheDocument();
		expect(screen.queryByRole("region", { name: "Cursor" })).not.toBeInTheDocument();
		fireEvent.click(screen.getByRole("button", { name: "Cursor" }));
		expect(
			await screen.findByRole("link", { name: "Download aidr-cursor.vsix" }),
		).toBeInTheDocument();
		expect(screen.queryByRole("region", { name: "Claude Code" })).not.toBeInTheDocument();
	});
});
