// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { invoke, getSession, unsubscribe } = vi.hoisted(() => ({
	invoke: vi.fn(),
	getSession: vi.fn(),
	unsubscribe: vi.fn(),
}));

vi.mock("../lib/supabase", () => ({
	supabase: {
		auth: {
			getSession,
			onAuthStateChange: vi.fn(() => ({ data: { subscription: { unsubscribe } } })),
		},
		functions: { invoke },
	},
}));

import { RecoveryPage } from "../ui/pages/RecoveryPage";

describe("account recovery UI", () => {
	beforeEach(() => {
		vi.clearAllMocks();
		getSession.mockResolvedValue({ data: { session: null }, error: null });
		invoke.mockResolvedValue({ data: { ok: true }, error: null });
	});
	afterEach(cleanup);

	it("requests provider recovery without disclosing whether the account exists", async () => {
		render(
			<MemoryRouter>
				<RecoveryPage />
			</MemoryRouter>,
		);
		fireEvent.change(screen.getByLabelText("Email address"), {
			target: { value: "user@example.test" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Request recovery" }));
		await waitFor(() =>
			expect(invoke).toHaveBeenCalledWith("identity-security", {
				body: { action: "request_password_reset", email: "user@example.test" },
			}),
		);
		expect(screen.getByRole("alert")).toHaveTextContent("If this account is enabled");
	});

	it("clears the one-time code and exposes only the returned manual recovery link", async () => {
		invoke.mockResolvedValue({
			data: { ok: true, recovery_link: "https://auth.example.test/verify?token=opaque" },
			error: null,
		});
		render(
			<MemoryRouter>
				<RecoveryPage />
			</MemoryRouter>,
		);
		fireEvent.click(screen.getByRole("button", { name: "Break-glass code" }));
		fireEvent.change(screen.getByLabelText("Email address"), {
			target: { value: "user@example.test" },
		});
		fireEvent.change(screen.getByLabelText("One-time recovery code"), {
			target: { value: "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE-FFFFF-00000-11111" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Use one-time code" }));
		await waitFor(() =>
			expect(screen.getByRole("link", { name: "Continue password recovery" })).toHaveAttribute(
				"href",
				"https://auth.example.test/verify?token=opaque",
			),
		);
		expect(screen.getByLabelText("One-time recovery code")).toHaveValue("");
	});

	it("does not claim recovery success for an empty 200 response", async () => {
		invoke.mockResolvedValue({ data: {}, error: null });
		render(
			<MemoryRouter>
				<RecoveryPage />
			</MemoryRouter>,
		);
		fireEvent.change(screen.getByLabelText("Email address"), {
			target: { value: "user@example.test" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Request recovery" }));
		await waitFor(() =>
			expect(screen.getByRole("alert")).toHaveTextContent("Password recovery is temporarily unavailable"),
		);
	});
});
