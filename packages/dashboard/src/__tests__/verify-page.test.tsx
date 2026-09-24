// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { invoke, getUser, from, getSession } = vi.hoisted(() => ({
	invoke: vi.fn(),
	getUser: vi.fn(),
	from: vi.fn(),
	getSession: vi.fn(),
}));

vi.mock("../lib/supabase", () => ({
	supabase: { functions: { invoke }, auth: { getUser }, from },
}));
vi.mock("../ui/session", () => ({ getSession }));

import { VerifyPage } from "../ui/pages/public/VerifyPage";

/** PostgREST-shaped builder for the team lookup in the page's load effect. */
function teamQuery() {
	const rows = [{ role: "owner", teams: { id: "team-one", name: "First team" } }];
	const builder: Record<string, unknown> = {};
	builder.select = () => builder;
	builder.eq = () => builder;
	builder.then = (onFulfilled?: (value: unknown) => unknown) =>
		Promise.resolve({ data: rows, error: null }).then(onFulfilled);
	return builder;
}

function renderPage() {
	return render(
		<MemoryRouter initialEntries={["/verify?code=ABCD2345"]}>
			<VerifyPage />
		</MemoryRouter>,
	);
}

async function authorize() {
	const button = await screen.findByRole("button", { name: "Authorize" });
	await waitFor(() => expect(button).toBeEnabled());
	fireEvent.click(button);
}

describe("device verification page", () => {
	beforeEach(() => {
		vi.clearAllMocks();
		getSession.mockResolvedValue({ user: { id: "user-1" } });
		getUser.mockResolvedValue({ data: { user: { id: "user-1" } }, error: null });
		from.mockImplementation(() => teamQuery());
		invoke.mockImplementation(async (name: string) =>
			name === "device-verify"
				? {
						data: { ok: true, expires_at: new Date(Date.now() + 1_200).toISOString() },
						error: null,
					}
				: { data: null, error: new Error(`unexpected call: ${name}`) },
		);
	});
	afterEach(cleanup);

	it("shows the code expiry and refuses to claim success after it lapses", async () => {
		renderPage();
		await authorize();

		await screen.findByText(/Authorized\./);
		await screen.findByText(/Code expires in \d+:\d{2}/);

		await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("expired"), {
			timeout: 3_000,
		});
		expect(screen.queryByText(/Authorized\./)).not.toBeInTheDocument();
		expect(screen.queryByText(/Code expires in/)).not.toBeInTheDocument();
	});

	it("requires a fresh code from the same agent after expiry", async () => {
		renderPage();
		await authorize();
		await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("expired"), {
			timeout: 3_000,
		});
		expect(screen.getByRole("alert")).toHaveTextContent("Start authorization again in your agent");
		expect(screen.getByRole("link", { name: "Return to onboarding" })).toHaveAttribute(
			"href",
			"/onboarding",
		);
		expect(screen.getByRole("link", { name: "Contact support" })).toHaveAttribute("href", "/support");
		expect(screen.getByRole("alert")).not.toHaveTextContent("pilot");
		expect(screen.getByLabelText("Code")).toHaveValue("");
		expect(screen.queryByDisplayValue("ABCD2345")).not.toBeInTheDocument();
		expect(invoke.mock.calls.filter(([name]) => name === "device-verify")).toHaveLength(1);
		expect(invoke.mock.calls.filter(([name]) => name === "device-start")).toHaveLength(0);
	});

	it("keeps a signed-in operator from authorizing when team lookup fails", async () => {
		getUser.mockResolvedValue({ data: { user: null }, error: new Error("lookup failed") });
		renderPage();
		await screen.findByText("Your session could not be verified.");
		expect(screen.getByRole("button", { name: "Authorize" })).toBeDisabled();
		expect(screen.queryByRole("link", { name: "Sign in" })).not.toBeInTheDocument();
		expect(invoke).not.toHaveBeenCalled();
	});
});
