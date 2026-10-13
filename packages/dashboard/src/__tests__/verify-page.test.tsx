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

const SESSION_ID = "d0000000-0000-4000-8000-000000000001";

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

function renderPage(path = "/verify?code=ABCD2345") {
	return render(
		<MemoryRouter initialEntries={[path]}>
			<VerifyPage />
		</MemoryRouter>,
	);
}

function deviceAnswer(userCode: string) {
	return {
		ok: true,
		device: {
			device_session_id: SESSION_ID,
			user_code: userCode,
			requested_at: new Date(Date.now() - 2 * 60_000).toISOString(),
			expires_at: new Date(Date.now() + 8 * 60_000).toISOString(),
			requester_ip: "203.0.113.9",
			runtime: "claude-code",
			runtime_version: "2.1.0",
			os: "darwin",
			hostname: "build-mac",
			requested_scope: "tenant",
		},
	};
}

const verifyBodies = () =>
	invoke.mock.calls
		.filter(([name]) => name === "device-verify")
		.map(([, options]) => (options as { body: Record<string, unknown> }).body);

async function typeAndContinue(code: string) {
	fireEvent.change(await screen.findByLabelText("Code"), { target: { value: code } });
	const button = screen.getByRole("button", { name: "Continue" });
	await waitFor(() => expect(button).toBeEnabled());
	fireEvent.click(button);
	await screen.findByTestId("device-request");
}

async function confirmAndAuthorize() {
	fireEvent.click(screen.getByRole("checkbox"));
	fireEvent.click(screen.getByRole("button", { name: "Authorize device" }));
}

describe("device verification page", () => {
	beforeEach(() => {
		vi.clearAllMocks();
		getSession.mockResolvedValue({ user: { id: "user-1" } });
		getUser.mockResolvedValue({ data: { user: { id: "user-1" } }, error: null });
		from.mockImplementation(() => teamQuery());
		invoke.mockImplementation(
			async (name: string, options?: { body?: Record<string, unknown> }) => {
				if (name !== "device-verify")
					return { data: null, error: new Error(`unexpected call: ${name}`) };
				if (options?.body?.action === "lookup") {
					return { data: deviceAnswer(String(options.body.user_code)), error: null };
				}
				return {
					data: { ok: true, expires_at: new Date(Date.now() + 1_200).toISOString() },
					error: null,
				};
			},
		);
	});
	afterEach(cleanup);

	it("never prefills or binds the code from the link (CP-1)", async () => {
		renderPage();
		expect(await screen.findByTestId("link-code-notice")).toHaveTextContent(
			"type the code shown on the device you are setting up",
		);
		expect(screen.getByLabelText("Code")).toHaveValue("");
		expect(screen.queryByDisplayValue("ABCD2345")).not.toBeInTheDocument();
		expect(screen.getByRole("button", { name: "Continue" })).toBeDisabled();
		expect(screen.queryByRole("button", { name: /Authorize/ })).not.toBeInTheDocument();
		expect(invoke).not.toHaveBeenCalled();
	});

	it("shows who requested the code with a phishing warning before anything is bound", async () => {
		renderPage();
		await typeAndContinue("abcd-2345");
		expect(verifyBodies()).toEqual([{ action: "lookup", user_code: "ABCD2345" }]);
		const details = screen.getByTestId("device-request");
		expect(details).toHaveTextContent("Only approve a code you started on your own device.");
		expect(details).toHaveTextContent("203.0.113.9");
		expect(details).toHaveTextContent("host build-mac · OS darwin · claude-code 2.1.0");
		expect(details).toHaveTextContent("tenant API key (tenant scope)");
		expect(details).toHaveTextContent("First team");
		expect(details).toHaveTextContent("2 minutes ago");
		expect(screen.getByRole("button", { name: "Authorize device" })).toBeDisabled();

		await confirmAndAuthorize();
		await screen.findByText(/Authorized\./);
		expect(verifyBodies()).toEqual([
			{ action: "lookup", user_code: "ABCD2345" },
			{
				action: "authorize",
				user_code: "ABCD2345",
				device_session_id: SESSION_ID,
				confirmed: true,
			},
		]);
		expect(invoke).toHaveBeenLastCalledWith("device-verify", {
			method: "POST",
			headers: { "X-AIDR-Tenant-ID": "team-one" },
			body: {
				action: "authorize",
				user_code: "ABCD2345",
				device_session_id: SESSION_ID,
				confirmed: true,
			},
		});
	});

	it("authorizes only the typed code and says so when the link carried another one", async () => {
		renderPage();
		await typeAndContinue("WXYZ6789");
		expect(screen.getByText(/differs from the code in the link/)).toBeInTheDocument();
		await confirmAndAuthorize();
		await screen.findByText(/Authorized\./);
		expect(verifyBodies().map((body) => body.user_code)).toEqual(["WXYZ6789", "WXYZ6789"]);
	});

	it("refuses to authorize when the service does not describe the device", async () => {
		invoke.mockImplementation(async () => ({ data: { ok: true }, error: null }));
		renderPage();
		fireEvent.change(await screen.findByLabelText("Code"), { target: { value: "ABCD2345" } });
		const button = screen.getByRole("button", { name: "Continue" });
		await waitFor(() => expect(button).toBeEnabled());
		fireEvent.click(button);
		expect(await screen.findByRole("alert")).toHaveTextContent("did not describe this device");
		expect(verifyBodies()).toEqual([{ action: "lookup", user_code: "ABCD2345" }]);
	});

	it("shows the code expiry and refuses to claim success after it lapses", async () => {
		renderPage();
		await typeAndContinue("ABCD2345");
		await confirmAndAuthorize();

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
		await typeAndContinue("ABCD2345");
		await confirmAndAuthorize();
		await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("expired"), {
			timeout: 3_000,
		});
		expect(screen.getByRole("alert")).toHaveTextContent("Start authorization again in your agent");
		expect(screen.getByRole("link", { name: "Return to onboarding" })).toHaveAttribute(
			"href",
			"/onboarding",
		);
		expect(screen.getByRole("link", { name: "Contact support" })).toHaveAttribute(
			"href",
			"/support",
		);
		expect(screen.getByRole("alert")).not.toHaveTextContent("pilot");
		expect(screen.getByLabelText("Code")).toHaveValue("");
		expect(screen.queryByDisplayValue("ABCD2345")).not.toBeInTheDocument();
		expect(verifyBodies().filter((body) => body.action === "authorize")).toHaveLength(1);
		expect(invoke.mock.calls.filter(([name]) => name === "device-start")).toHaveLength(0);
	});

	it("keeps a signed-in operator from authorizing when team lookup fails", async () => {
		getUser.mockResolvedValue({ data: { user: null }, error: new Error("lookup failed") });
		renderPage();
		await screen.findByText("Your session could not be verified.");
		fireEvent.change(screen.getByLabelText("Code"), { target: { value: "ABCD2345" } });
		expect(screen.getByRole("button", { name: "Continue" })).toBeDisabled();
		expect(screen.queryByRole("link", { name: "Sign in" })).not.toBeInTheDocument();
		expect(invoke).not.toHaveBeenCalled();
	});
});
