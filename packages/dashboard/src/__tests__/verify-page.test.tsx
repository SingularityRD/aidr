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
				? { data: { ok: true, expires_at: new Date(Date.now() + 1_200).toISOString() }, error: null }
				: {
						data: {
							ok: true,
							user_code: "WXYZ2345",
							expires_at: new Date(Date.now() + 600_000).toISOString(),
						},
						error: null,
					},
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

	it("issues a replacement code without keeping the previous one usable", async () => {
		renderPage();
		await authorize();
		await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("expired"), {
			timeout: 3_000,
		});

		fireEvent.click(screen.getByRole("button", { name: "Issue a replacement code" }));
		await waitFor(() => expect(invoke).toHaveBeenCalledWith("device-start", { method: "POST" }));

		// The expired code is gone from the page, and the replacement is the only
		// code that a later authorization attempt can present.
		await waitFor(() =>
			expect(screen.getByLabelText("Code")).toHaveValue("WXYZ2345"),
		);
		expect(screen.queryByDisplayValue("ABCD2345")).not.toBeInTheDocument();

		const before = invoke.mock.calls.filter(([name]) => name === "device-verify").length;
		fireEvent.click(screen.getByRole("button", { name: "Authorize" }));
		await waitFor(() =>
			expect(invoke.mock.calls.filter(([name]) => name === "device-verify")).toHaveLength(
				before + 1,
			),
		);

		// Every authorization attempt after the replacement presents the new
		// code; the retired code is never presented again.
		const replacements = invoke.mock.calls
			.filter(([name]) => name === "device-verify")
			.slice(before);
		expect(replacements).toHaveLength(1);
		expect(replacements[0]?.[1]).toMatchObject({ body: { user_code: "WXYZ2345" } });
		expect(JSON.stringify(replacements)).not.toContain("ABCD2345");
	});
});
