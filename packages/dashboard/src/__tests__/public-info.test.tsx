// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { PublicInfoPage } from "../ui/pages/public/PublicInfoPage";

afterEach(() => {
	cleanup();
	vi.unstubAllEnvs();
});

describe("public deployment information", () => {
	it("does not present the public issue tracker as customer support by default", () => {
		vi.stubEnv("VITE_SUPPORT_URL", "");
		vi.stubEnv("VITE_SUPPORT_EMAIL", "");
		render(
			<MemoryRouter>
				<PublicInfoPage kind="support" />
			</MemoryRouter>,
		);

		expect(screen.queryByRole("link", { name: "Open support channel" })).not.toBeInTheDocument();
		expect(screen.getByRole("alert")).toHaveTextContent(
			"No safe HTTPS support URL or approved support mailbox is configured",
		);
	});

	it("uses only an explicitly configured safe HTTPS support route", () => {
		vi.stubEnv("VITE_SUPPORT_URL", "https://support.example.test/tickets");
		render(
			<MemoryRouter>
				<PublicInfoPage kind="support" />
			</MemoryRouter>,
		);

		expect(screen.getByRole("link", { name: "Open support channel" })).toHaveAttribute(
			"href",
			"https://support.example.test/tickets",
		);
	});

	it("accepts an approved support mailbox without falsely reporting that support is unavailable", () => {
		vi.stubEnv("VITE_SUPPORT_URL", "");
		vi.stubEnv("VITE_SUPPORT_EMAIL", "support@example.test");
		render(
			<MemoryRouter>
				<PublicInfoPage kind="support" />
			</MemoryRouter>,
		);

		expect(screen.getByRole("link", { name: "Email support" })).toHaveAttribute(
			"href",
			"mailto:support@example.test",
		);
		expect(screen.queryByRole("alert")).not.toBeInTheDocument();
	});

	it("labels a configured status link without claiming live availability", () => {
		vi.stubEnv("VITE_STATUS_URL", "https://status.example.test/aidr");
		render(
			<MemoryRouter>
				<PublicInfoPage kind="status" />
			</MemoryRouter>,
		);

		expect(screen.getByRole("link", { name: "Open status updates" })).toHaveAttribute(
			"href",
			"https://status.example.test/aidr",
		);
		expect(screen.getByText(/does not monitor availability or verify/)).toBeInTheDocument();
		expect(screen.queryByText(/all systems operational/i)).not.toBeInTheDocument();
	});

	it.each([
		{
			kind: "status" as const,
			env: "VITE_STATUS_URL",
			action: "Open status updates",
			message: "No live status feed is configured",
		},
		{
			kind: "privacy" as const,
			env: "VITE_PRIVACY_URL",
			action: "Read privacy notice",
			message: "Privacy notice URL is not configured",
		},
		{
			kind: "security" as const,
			env: "VITE_SECURITY_URL",
			action: "Read security",
			message: "Security URL is not configured",
		},
		{
			kind: "terms" as const,
			env: "VITE_TERMS_URL",
			action: "Read terms",
			message: "Terms URL is not configured",
		},
	])(
		"fails closed when the $kind page has no approved destination",
		({ kind, env, action, message }) => {
			vi.stubEnv(env, "");
			render(
				<MemoryRouter>
					<PublicInfoPage kind={kind} />
				</MemoryRouter>,
			);

			expect(screen.getByRole("alert")).toHaveTextContent(message);
			expect(screen.queryByRole("link", { name: action })).not.toBeInTheDocument();
		},
	);

	it.each([
		{ kind: "support" as const, env: "VITE_SUPPORT_URL", action: "Open support channel" },
		{ kind: "status" as const, env: "VITE_STATUS_URL", action: "Open status updates" },
		{ kind: "privacy" as const, env: "VITE_PRIVACY_URL", action: "Read privacy notice" },
		{ kind: "security" as const, env: "VITE_SECURITY_URL", action: "Read security" },
		{ kind: "terms" as const, env: "VITE_TERMS_URL", action: "Read terms" },
	])("rejects non-HTTPS destinations for $kind", ({ kind, env, action }) => {
		vi.stubEnv(env, "http://untrusted.example.test/path");
		if (kind === "support") vi.stubEnv("VITE_SUPPORT_EMAIL", "");
		render(
			<MemoryRouter>
				<PublicInfoPage kind={kind} />
			</MemoryRouter>,
		);

		expect(screen.getByRole("alert")).toBeInTheDocument();
		expect(screen.queryByRole("link", { name: action })).not.toBeInTheDocument();
	});
});
