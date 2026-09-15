// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { useLayoutEffect } from "react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
	from: vi.fn(),
	invoke: vi.fn(),
	getSession: vi.fn(),
	getUser: vi.fn(),
	onAuthStateChange: vi.fn(),
	signOut: vi.fn(),
	listFactors: vi.fn(),
	challenge: vi.fn(),
	verify: vi.fn(),
}));
vi.mock("../lib/supabase", () => ({
	supabase: {
		from: mocks.from,
		functions: { invoke: mocks.invoke },
		auth: {
			...mocks,
			mfa: { listFactors: mocks.listFactors, challenge: mocks.challenge, verify: mocks.verify },
		},
	},
	supabaseEnvError: null,
}));
import { AppLayout } from "../ui/AppLayout";
import { useTeam } from "../enterprise/team-provider";

const USER = "22222222-2222-4222-8222-222222222222";
// Deliberately NOT equal to team IDs: tenant policy must use canonical identity.
const A = {
	tenant_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
	team_id: "11111111-1111-4111-8111-111111111111",
};
const B = {
	tenant_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
	team_id: "33333333-3333-4333-8333-333333333333",
};
let token: string;
let memberships: (typeof A)[];
let requireMfa: Set<string>;
let revoked: boolean;
let authCallbacks: Set<() => void>;
let delayed: Map<string, (value: unknown) => void>;
let delayTenants: Set<string>;
let mounts = vi.fn<(teamId: string | undefined) => void>();
const reads: Array<{ table: string; token: string }> = [];
function report(tenantId: string) {
	const required = requireMfa.has(tenantId);
	return {
		ok: true,
		tenant_id: tenantId,
		require_mfa: required,
		current_assurance: token === "aal2-token" ? "aal2" : "aal1",
		next_assurance: "aal2",
		access_allowed: !required || token === "aal2-token",
	};
}
function emit(nextToken: string) {
	token = nextToken;
	for (const callback of [...authCallbacks]) callback();
}
function ProtectedPage() {
	const { currentTeam } = useTeam();
	useLayoutEffect(() => {
		mounts(currentTeam?.id);
	}, [currentTeam?.id]);
	return <div>Protected team {currentTeam?.id}</div>;
}
function renderRoute() {
	return render(
		<MemoryRouter initialEntries={["/team"]}>
			<Routes>
				<Route element={<AppLayout />}>
					<Route path="team" element={<ProtectedPage />} />
				</Route>
			</Routes>
		</MemoryRouter>,
	);
}

beforeEach(() => {
	vi.resetAllMocks();
	localStorage.clear();
	reads.length = 0;
	token = "aal1-token";
	memberships = [A];
	requireMfa = new Set([A.tenant_id]);
	revoked = false;
	authCallbacks = new Set();
	delayed = new Map();
	delayTenants = new Set();
	mounts = vi.fn();
	mocks.getSession.mockImplementation(async () => ({
		data: { session: { access_token: token, user: { id: USER } } },
		error: null,
	}));
	mocks.getUser.mockResolvedValue({ data: { user: { id: USER } }, error: null });
	mocks.onAuthStateChange.mockImplementation((callback) => {
		authCallbacks.add(callback);
		return { data: { subscription: { unsubscribe: () => authCallbacks.delete(callback) } } };
	});
	mocks.signOut.mockResolvedValue({ error: null });
	mocks.listFactors.mockResolvedValue({
		data: { totp: [{ id: "factor", status: "verified" }] },
		error: null,
	});
	mocks.challenge.mockResolvedValue({ data: { id: "challenge" }, error: null });
	mocks.verify.mockImplementation(async () => {
		emit("aal2-token");
		return { data: { access_token: token }, error: null };
	});
	mocks.invoke.mockImplementation(async (_name, request) => {
		if (revoked) return { data: null, error: new Error("session_revoked") };
		if (request.body.action === "bootstrap")
			return {
				data: {
					ok: true,
					memberships: memberships.map((identity) => ({
						...report(identity.tenant_id),
						...identity,
					})),
				},
				error: null,
			};
		if (delayTenants.has(request.body.tenant_id))
			return new Promise((resolve) => delayed.set(request.body.tenant_id, resolve));
		return { data: report(request.body.tenant_id), error: null };
	});
	mocks.from.mockImplementation((table: string) => {
		reads.push({ table, token });
		let columns = "";
		const filters = new Map<string, string>();
		const result = () => ({
			data:
				table === "team_members" && columns.includes("teams!")
					? memberships
							.filter((identity) => report(identity.tenant_id).access_allowed && !revoked)
							.map((identity) => ({
								team_id: identity.team_id,
								role: "owner",
								teams: {
									id: identity.team_id,
									name: `Team ${identity.team_id}`,
									plan: "pro",
									github_org: null,
									gitlab_group: null,
									created_at: "2026-01-01",
									updated_at: "2026-01-01",
								},
							}))
					: [],
			error: null,
		});
		const chain = {
			select: (value: string) => {
				columns = value;
				return chain;
			},
			eq: (key: string, value: string) => {
				filters.set(key, value);
				return chain;
			},
			order: () => chain,
			limit: () => chain,
			then: (resolve: (value: unknown) => void) => Promise.resolve(result()).then(resolve),
		};
		return chain;
	});
});
afterEach(cleanup);

describe("managed route identity bootstrap before protected providers", () => {
	it("discovers an AAL2-RLS-hidden team, challenges with zero table reads, then reloads after verification", async () => {
		renderRoute();
		await screen.findByLabelText("Authenticator code");
		expect(reads).toEqual([]);
		expect(mocks.getUser).not.toHaveBeenCalled();
		expect(mounts).not.toHaveBeenCalled();
		expect(mocks.invoke).toHaveBeenCalledWith("identity-security", {
			body: { action: "status", tenant_id: A.tenant_id },
			headers: { Authorization: "Bearer aal1-token" },
		});
		fireEvent.change(screen.getByLabelText("Authenticator code"), { target: { value: "123456" } });
		fireEvent.click(screen.getByText("Verify and continue"));
		await screen.findByText(`Protected team ${A.team_id}`);
		expect(mounts).toHaveBeenCalledExactlyOnceWith(A.team_id);
		expect(reads.length).toBeGreaterThan(0);
		expect(reads.every((read) => read.token === "aal2-token")).toBe(true);
		expect(
			mocks.invoke.mock.calls.filter((call) => call[1].body.action === "bootstrap"),
		).toHaveLength(2);
	});

	it("does not start protected reads from an old provider after token downgrade", async () => {
		token = "aal2-token";
		let finishUser!: (value: unknown) => void;
		mocks.getUser.mockImplementationOnce(
			() =>
				new Promise((resolve) => {
					finishUser = resolve;
				}),
		);
		renderRoute();
		await waitFor(() => expect(mocks.getUser).toHaveBeenCalledOnce());
		await act(async () => {
			emit("aal1-token");
			finishUser({ data: { user: { id: USER } }, error: null });
			await Promise.resolve();
		});
		await screen.findByLabelText("Authenticator code");
		expect(reads).toEqual([]);
		expect(mounts).not.toHaveBeenCalled();
	});

	it("cancels without protected queries even when sign-out fails", async () => {
		mocks.signOut.mockResolvedValue({ error: new Error("signout unavailable") });
		renderRoute();
		fireEvent.click(await screen.findByText("Cancel and sign out"));
		await screen.findByText("signout unavailable");
		expect(reads).toEqual([]);
		expect(mounts).not.toHaveBeenCalled();
	});

	it.each([
		"revoked",
		"no membership",
		"malformed",
	])("fails closed during %s bootstrap", async (mode) => {
		if (mode === "revoked") revoked = true;
		if (mode === "no membership") memberships = [];
		if (mode === "malformed") mocks.invoke.mockResolvedValue({ data: { ok: true }, error: null });
		renderRoute();
		await screen.findByRole("alert");
		expect(reads).toEqual([]);
		expect(mounts).not.toHaveBeenCalled();
	});

	it("mounts zero B children and performs zero new table queries while B assurance is delayed", async () => {
		memberships = [A, B];
		requireMfa.clear();
		renderRoute();
		await screen.findByText(`Protected team ${A.team_id}`);
		const previousReads = reads.length;
		delayTenants.add(B.tenant_id);
		fireEvent.change(screen.getByLabelText("Managed tenant"), { target: { value: B.tenant_id } });
		expect(mounts).toHaveBeenCalledExactlyOnceWith(A.team_id);
		expect(screen.queryByText(`Protected team ${B.team_id}`)).not.toBeInTheDocument();
		await waitFor(() => expect(delayed.has(B.tenant_id)).toBe(true));
		expect(reads).toHaveLength(previousReads);
		await act(async () => delayed.get(B.tenant_id)!({ data: report(B.tenant_id), error: null }));
		await screen.findByText(`Protected team ${B.team_id}`);
		expect(mounts).toHaveBeenCalledTimes(2);
		expect(mounts).toHaveBeenLastCalledWith(B.team_id);
	});

	it("keeps non-first B selected through MFA token rotation and closes it again on downgrade", async () => {
		memberships = [A, B];
		requireMfa = new Set([B.tenant_id]);
		renderRoute();
		await screen.findByText(`Protected team ${A.team_id}`);
		fireEvent.change(screen.getByLabelText("Managed tenant"), { target: { value: B.tenant_id } });
		await screen.findByLabelText("Authenticator code");
		const beforeMfa = reads.length;
		expect(mounts).toHaveBeenCalledExactlyOnceWith(A.team_id);
		fireEvent.change(screen.getByLabelText("Authenticator code"), { target: { value: "123456" } });
		fireEvent.click(screen.getByText("Verify and continue"));
		await screen.findByText(`Protected team ${B.team_id}`);
		expect(screen.getByLabelText("Managed tenant")).toHaveValue(B.tenant_id);
		expect(reads.slice(beforeMfa).every((read) => read.token === "aal2-token")).toBe(true);
		const afterMfa = reads.length;
		act(() => emit("aal1-token"));
		expect(screen.queryByText(`Protected team ${B.team_id}`)).not.toBeInTheDocument();
		await screen.findByLabelText("Authenticator code");
		expect(reads).toHaveLength(afterMfa);
		expect(mounts).toHaveBeenCalledTimes(2);
	});
});
