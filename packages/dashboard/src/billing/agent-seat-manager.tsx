import { createContext, type ReactNode, useCallback, useContext, useEffect, useState } from "react";
import type { Database } from "../lib/database.types";
import { supabase } from "../lib/supabase";
import { getInvoiceContactHref, selfServiceCheckoutEnabled } from "./commercial";

// Types
export interface AgentSeat {
	id: string;
	userId: string;
	agentName: string;
	agentType: "claude" | "cursor" | "vscode" | "openclaw" | "opencode";
	status: "active" | "paused" | "deleted";
	tier: "free" | "pro";
	createdAt: string;
	expiresAt?: string;
}

export interface SeatEntitlements {
	includedAgents: number;
	extraAgents: number;
	allowedAgents: number;
	currentAgents: number;
	isPro: boolean;
}

export interface BillingInfo {
	provider: string;
	status: string;
	extraAgents: number;
	currentPeriodEnd?: string;
	cancelAtPeriodEnd: boolean;
}

interface AgentSeatContextType {
	seats: AgentSeat[];
	entitlements: SeatEntitlements | null;
	billing: BillingInfo | null;
	isLoading: boolean;
	checkoutUrl: string | null;
	// Actions
	createSeat: (name: string, type: AgentSeat["agentType"]) => Promise<AgentSeat>;
	updateSeat: (id: string, updates: Partial<AgentSeat>) => Promise<void>;
	deleteSeat: (id: string) => Promise<void>;
	pauseSeat: (id: string) => Promise<void>;
	resumeSeat: (id: string) => Promise<void>;
	// Stripe
	initiateCheckout: () => Promise<void>;
	openCustomerPortal: () => Promise<void>;
	// Usage
	refreshData: () => Promise<void>;
	canAddAgent: boolean;
	remainingFreeSeats: number;
}

const AgentSeatContext = createContext<AgentSeatContextType | null>(null);

export function useAgentSeats() {
	const ctx = useContext(AgentSeatContext);
	if (!ctx) throw new Error("useAgentSeats must be used within AgentSeatProvider");
	return ctx;
}

interface AgentSeatProviderProps {
	children: ReactNode;
	userId: string;
}

const USD_PER_EXTRA_AGENT_PER_MONTH = 2;
const FREE_TIER_AGENT_LIMIT = 1;

export function AgentSeatProvider({ children, userId }: AgentSeatProviderProps) {
	const [seats, setSeats] = useState<AgentSeat[]>([]);
	const [entitlements, setEntitlements] = useState<SeatEntitlements | null>(null);
	const [billing, setBilling] = useState<BillingInfo | null>(null);
	const [checkoutUrl, setCheckoutUrl] = useState<string | null>(null);
	const [isLoading, setIsLoading] = useState(true);

	// Load data on mount
	useEffect(() => {
		let cancelled = false;

		async function loadData() {
			setIsLoading(true);

			const [seatsRes, usageRes, billingRes] = await Promise.all([
				supabase
					.from("agent_seats")
					.select("*")
					.eq("user_id", userId)
					.order("created_at", { ascending: false }),
				supabase.from("seat_usage").select("*").maybeSingle(),
				supabase
					.from("subscriptions")
					.select("*")
					.order("updated_at", { ascending: false })
					.limit(1)
					.maybeSingle(),
			]);
			const checkoutRes = selfServiceCheckoutEnabled
				? await supabase.functions.invoke("billing-checkout", { method: "GET" })
				: null;

			if (cancelled) return;

			// Process seats
			if (!seatsRes.error && seatsRes.data) {
				const formattedSeats: AgentSeat[] = (
					seatsRes.data as Database["public"]["Tables"]["agent_seats"]["Row"][]
				).map((row) => ({
					id: row.id,
					userId: row.user_id,
					agentName: row.agent_name,
					agentType: row.agent_type,
					status: row.status,
					tier: row.tier,
					createdAt: row.created_at,
					expiresAt: row.expires_at ?? undefined,
				}));
				setSeats(formattedSeats);
			}

			// Process entitlements
			if (!usageRes.error && usageRes.data) {
				const row = usageRes.data as Database["public"]["Tables"]["seat_usage"]["Row"];
				setEntitlements({
					includedAgents: Number(row.included_agents ?? FREE_TIER_AGENT_LIMIT),
					extraAgents: Number(row.extra_agents ?? 0),
					allowedAgents: Number(row.allowed_agents ?? FREE_TIER_AGENT_LIMIT),
					currentAgents: Number(row.current_agents ?? 0),
					isPro: (row.extra_agents ?? 0) > 0,
				});
			} else {
				// Fallback: calculate from the fresh query result. Reading the
				// previous React state here would make the first load stale and
				// previously forced this effect to depend on seats.length.
				const activeSeats = Array.isArray(seatsRes.data) ? seatsRes.data.length : 0;
				setEntitlements({
					includedAgents: FREE_TIER_AGENT_LIMIT,
					extraAgents: 0,
					allowedAgents: FREE_TIER_AGENT_LIMIT,
					currentAgents: activeSeats,
					isPro: false,
				});
			}

			// Process billing
			if (!billingRes.error && billingRes.data) {
				const row = billingRes.data as Database["public"]["Tables"]["subscriptions"]["Row"];
				setBilling({
					provider: row.provider,
					status: row.status,
					extraAgents: row.extra_agents ?? 0,
					currentPeriodEnd: row.current_period_end ?? undefined,
					cancelAtPeriodEnd: row.cancel_at_period_end,
				});
			}

			// Process checkout URL
			if (checkoutRes && !checkoutRes.error && checkoutRes.data) {
				const data = checkoutRes.data as { checkout_url?: string };
				setCheckoutUrl(data.checkout_url || null);
			} else if (!selfServiceCheckoutEnabled) {
				setCheckoutUrl(null);
			}

			setIsLoading(false);
		}

		loadData();

		// Subscribe to realtime changes
		const channel = supabase
			.channel("agent_seats_changes")
			.on(
				"postgres_changes",
				{
					event: "*",
					schema: "public",
					table: "agent_seats",
					filter: `user_id=eq.${userId}`,
				},
				() => loadData(),
			)
			.subscribe();

		return () => {
			cancelled = true;
			supabase.removeChannel(channel);
		};
	}, [userId]);

	// Computed values
	const canAddAgent = useCallback((): boolean => {
		if (!entitlements) return false;
		return entitlements.currentAgents < entitlements.allowedAgents;
	}, [entitlements]);

	const remainingFreeSeats = useCallback((): number => {
		if (!entitlements) return FREE_TIER_AGENT_LIMIT;
		return Math.max(0, entitlements.includedAgents - entitlements.currentAgents);
	}, [entitlements]);

	// Create a new agent seat
	const createSeat = useCallback(
		async (name: string, type: AgentSeat["agentType"]): Promise<AgentSeat> => {
			// Check if user can add more agents
			if (!canAddAgent()) {
				throw new Error("Agent limit reached. Upgrade to add more agents.");
			}

			// Determine tier based on available free seats
			const isFreeSeat = remainingFreeSeats() > 0;

			const { data, error } = await supabase
				.from("agent_seats")
				.insert({
					user_id: userId,
					agent_name: name,
					agent_type: type,
					status: "active",
					tier: isFreeSeat ? "free" : "pro",
				} as never)
				.select()
				.single();

			if (error) throw error;

			const dataTyped = data as Database["public"]["Tables"]["agent_seats"]["Row"];
			const newSeat: AgentSeat = {
				id: dataTyped.id,
				userId: dataTyped.user_id,
				agentName: dataTyped.agent_name,
				agentType: dataTyped.agent_type,
				status: dataTyped.status,
				tier: dataTyped.tier,
				createdAt: dataTyped.created_at,
				expiresAt: dataTyped.expires_at ?? undefined,
			};

			setSeats((prev) => [newSeat, ...prev]);
			return newSeat;
		},
		[userId, canAddAgent, remainingFreeSeats],
	);

	// Update seat
	const updateSeat = useCallback(async (id: string, updates: Partial<AgentSeat>) => {
		const dbUpdates: Partial<Database["public"]["Tables"]["agent_seats"]["Update"]> = {};
		if (updates.agentName) dbUpdates.agent_name = updates.agentName;
		if (updates.status) dbUpdates.status = updates.status;
		if (updates.tier) dbUpdates.tier = updates.tier;

		const { error } = await supabase
			.from("agent_seats")
			.update(dbUpdates as never)
			.eq("id", id);

		if (error) throw error;

		setSeats((prev) => prev.map((seat) => (seat.id === id ? { ...seat, ...updates } : seat)));
	}, []);

	// Delete seat
	const deleteSeat = useCallback(async (id: string) => {
		const { error } = await supabase
			.from("agent_seats")
			.update({ status: "deleted" } as never)
			.eq("id", id);

		if (error) throw error;

		setSeats((prev) => prev.filter((seat) => seat.id !== id));
	}, []);

	// Pause seat
	const pauseSeat = useCallback(
		async (id: string) => {
			await updateSeat(id, { status: "paused" });
		},
		[updateSeat],
	);

	// Resume seat
	const resumeSeat = useCallback(
		async (id: string) => {
			await updateSeat(id, { status: "active" });
		},
		[updateSeat],
	);

	// Initiate Stripe checkout
	const initiateCheckout = useCallback(async () => {
		if (!selfServiceCheckoutEnabled) {
			throw new Error(
				"Self-service checkout is disabled for the direct-GA release. Request an enterprise invoice.",
			);
		}
		const { data, error } = await supabase.functions.invoke("billing-checkout", {
			method: "POST",
			body: {
				userId,
				mode: "subscription",
				lineItems: [
					{
						price_data: {
							currency: "usd",
							product_data: {
								name: "Additional Agent Seat",
								description: `Extra agent seat for AIDR protection`,
							},
							unit_amount: USD_PER_EXTRA_AGENT_PER_MONTH * 100, // cents
							recurring: {
								interval: "month",
							},
						},
						quantity: 1,
					},
				],
			},
		});

		if (error) throw error;

		const checkoutData = data as { checkout_url?: string };
		if (checkoutData.checkout_url) {
			window.location.href = checkoutData.checkout_url;
		}
	}, [userId]);

	// Open Stripe customer portal
	const openCustomerPortal = useCallback(async () => {
		if (!selfServiceCheckoutEnabled) {
			throw new Error(
				"Self-service billing portal is disabled for the direct-GA release. Request an enterprise invoice.",
			);
		}
		const { data, error } = await supabase.functions.invoke("billing-portal", {
			method: "POST",
			body: { userId },
		});

		if (error) throw error;

		const portalData = data as { portal_url?: string };
		if (portalData.portal_url) {
			window.location.href = portalData.portal_url;
		}
	}, [userId]);

	// Refresh all data
	const refreshData = useCallback(async () => {
		const [seatsRes, usageRes] = await Promise.all([
			supabase
				.from("agent_seats")
				.select("*")
				.eq("user_id", userId)
				.order("created_at", { ascending: false }),
			supabase.from("seat_usage").select("*").maybeSingle(),
		]);

		if (!seatsRes.error && seatsRes.data) {
			const formattedSeats: AgentSeat[] = (
				seatsRes.data as Database["public"]["Tables"]["agent_seats"]["Row"][]
			).map((row) => ({
				id: row.id,
				userId: row.user_id,
				agentName: row.agent_name,
				agentType: row.agent_type,
				status: row.status,
				tier: row.tier,
				createdAt: row.created_at,
				expiresAt: row.expires_at ?? undefined,
			}));
			setSeats(formattedSeats);
		}

		if (!usageRes.error && usageRes.data) {
			const row = usageRes.data as Database["public"]["Tables"]["seat_usage"]["Row"];
			setEntitlements({
				includedAgents: Number(row.included_agents ?? FREE_TIER_AGENT_LIMIT),
				extraAgents: Number(row.extra_agents ?? 0),
				allowedAgents: Number(row.allowed_agents ?? FREE_TIER_AGENT_LIMIT),
				currentAgents: Number(row.current_agents ?? 0),
				isPro: (row.extra_agents ?? 0) > 0,
			});
		}
	}, [userId]);

	const value: AgentSeatContextType = {
		seats,
		entitlements,
		billing,
		isLoading,
		checkoutUrl,
		createSeat,
		updateSeat,
		deleteSeat,
		pauseSeat,
		resumeSeat,
		initiateCheckout,
		openCustomerPortal,
		refreshData,
		canAddAgent: canAddAgent(),
		remainingFreeSeats: remainingFreeSeats(),
	};

	return <AgentSeatContext.Provider value={value}>{children}</AgentSeatContext.Provider>;
}

// UI Components
export function SeatUsageCard() {
	const { entitlements, isLoading, canAddAgent, remainingFreeSeats, initiateCheckout } =
		useAgentSeats();
	const [showUpgradeModal, setShowUpgradeModal] = useState(false);

	if (isLoading || !entitlements) {
		return <div className="card">Loading seat usage...</div>;
	}

	const usagePercent = Math.min(
		100,
		(entitlements.currentAgents / entitlements.allowedAgents) * 100,
	);

	return (
		<div className="card">
			<h3>Agent Seats</h3>

			<div className="usage-bar" style={{ marginTop: 16 }}>
				<div
					className="usage-fill"
					style={{
						width: `${usagePercent}%`,
						backgroundColor:
							usagePercent > 90 ? "#ef4444" : usagePercent > 70 ? "#f59e0b" : "#22c55e",
					}}
				/>
			</div>

			<div className="grid" style={{ marginTop: 12 }}>
				<div>
					<div className="muted small">Kullanılan</div>
					<div className="mono" style={{ fontSize: 20, fontWeight: 600 }}>
						{entitlements.currentAgents}
					</div>
				</div>
				<div>
					<div className="muted small">Limit</div>
					<div className="mono" style={{ fontSize: 20, fontWeight: 600 }}>
						{entitlements.allowedAgents}
					</div>
				</div>
				<div>
					<div className="muted small">Ücretsiz Kalan</div>
					<div
						className="mono"
						style={{
							fontSize: 20,
							fontWeight: 600,
							color: remainingFreeSeats > 0 ? "#22c55e" : "#ef4444",
						}}
					>
						{remainingFreeSeats}
					</div>
				</div>
				<div>
					<div className="muted small">Plan</div>
					<div className="mono" style={{ fontSize: 20, fontWeight: 600 }}>
						{entitlements.isPro ? "Pro" : "Free"}
					</div>
				</div>
			</div>

			{!canAddAgent && (
				<div className="notice notice-danger" style={{ marginTop: 16 }}>
					⚠️ Agent limitine ulaştınız. Yeni agent eklemek için upgrade yapın.
				</div>
			)}

			<div className="row" style={{ marginTop: 16 }}>
				{selfServiceCheckoutEnabled && entitlements.isPro ? (
					<button className="button button-secondary" onClick={() => setShowUpgradeModal(true)}>
						Manage Subscription
					</button>
				) : selfServiceCheckoutEnabled ? (
					<button className="button" onClick={initiateCheckout}>
						Request approved order
					</button>
				) : (
					<div className="notice">
						Self-service checkout is disabled. Request an approved enterprise invoice to increase
						the protected-agent allowance.
						{getInvoiceContactHref() ? (
							<a
								className="button button-secondary"
								href={getInvoiceContactHref() ?? undefined}
								target={getInvoiceContactHref()?.startsWith("mailto:") ? undefined : "_blank"}
								rel={getInvoiceContactHref()?.startsWith("mailto:") ? undefined : "noreferrer"}
								style={{ marginLeft: 8 }}
							>
								Request invoice
							</a>
						) : null}
					</div>
				)}
			</div>

			{showUpgradeModal && <UpgradeModal onClose={() => setShowUpgradeModal(false)} />}
		</div>
	);
}

function UpgradeModal({ onClose }: { onClose: () => void }) {
	const { initiateCheckout, openCustomerPortal } = useAgentSeats();
	const [quantity, setQuantity] = useState(1);

	return (
		<div className="modal-overlay" onClick={onClose}>
			<div className="modal" onClick={(e) => e.stopPropagation()}>
				<h3>Add More Agents</h3>
				<p className="muted">Additional agent quantity and price come from the approved order.</p>

				<div style={{ marginTop: 16 }}>
					<label className="label">
						Agent Sayısı
						<input
							type="number"
							min={1}
							max={10}
							value={quantity}
							onChange={(e) => setQuantity(Number(e.target.value))}
							className="input"
						/>
					</label>
				</div>

				<div style={{ marginTop: 20 }}>
					<div className="muted small">Commercial amount:</div>
					<div style={{ fontSize: 24, fontWeight: 600 }}>
						Quoted in approved order ({quantity} agent{quantity === 1 ? "" : "s"})
					</div>
				</div>

				<div className="row" style={{ marginTop: 20 }}>
					{selfServiceCheckoutEnabled ? (
						<>
							<button className="button" onClick={initiateCheckout}>
								Checkout
							</button>
							<button className="button button-secondary" onClick={openCustomerPortal}>
								Customer Portal
							</button>
						</>
					) : (
						<div className="muted small">
							Self-service billing is disabled; use the enterprise invoice channel.
						</div>
					)}
					<button className="button button-secondary" onClick={onClose}>
						İptal
					</button>
				</div>
			</div>
		</div>
	);
}

export function SeatsList() {
	const { seats, isLoading, deleteSeat, pauseSeat, resumeSeat } = useAgentSeats();

	if (isLoading) return <div className="card">Yükleniyor...</div>;
	if (seats.length === 0) return <div className="card">Henüz agent eklenmemiş</div>;

	const getAgentIcon = (type: string) => {
		switch (type) {
			case "claude":
				return "🤖";
			case "cursor":
				return "💻";
			case "vscode":
				return "📝";
			case "openclaw":
				return "🦀";
			case "opencode":
				return "🚀";
			default:
				return "🤖";
		}
	};

	return (
		<div className="card">
			<h4>Your Agents</h4>
			<table className="table">
				<thead>
					<tr>
						<th>Agent</th>
						<th>Type</th>
						<th>Tier</th>
						<th>Status</th>
						<th>Created</th>
						<th>Actions</th>
					</tr>
				</thead>
				<tbody>
					{seats.map((seat) => (
						<tr key={seat.id}>
							<td>
								<span>{getAgentIcon(seat.agentType)}</span> {seat.agentName}
							</td>
							<td className="mono">{seat.agentType}</td>
							<td>
								<span className={`badge badge-${seat.tier}`}>
									{seat.tier === "free" ? "🆓 Free" : "⭐ Pro"}
								</span>
							</td>
							<td>
								<span className={`badge badge-${seat.status}`}>
									{seat.status === "active"
										? "🟢 Active"
										: seat.status === "paused"
											? "⏸️ Paused"
											: "❌ Deleted"}
								</span>
							</td>
							<td>{new Date(seat.createdAt).toLocaleDateString()}</td>
							<td>
								<div className="row">
									{seat.status === "active" ? (
										<button
											className="button button-sm button-secondary"
											onClick={() => pauseSeat(seat.id)}
										>
											Pause
										</button>
									) : seat.status === "paused" ? (
										<button className="button button-sm" onClick={() => resumeSeat(seat.id)}>
											Resume
										</button>
									) : null}
									<button
										className="button button-sm button-danger"
										onClick={() => deleteSeat(seat.id)}
									>
										Delete
									</button>
								</div>
							</td>
						</tr>
					))}
				</tbody>
			</table>
		</div>
	);
}

export function UsageBasedBillingCard() {
	const { entitlements, isLoading, billing } = useAgentSeats();

	if (isLoading || !entitlements) {
		return <div className="card">Loading billing info...</div>;
	}

	const billableAgents = Math.max(0, entitlements.currentAgents - entitlements.includedAgents);
	const additionalAgentCount = billableAgents;

	return (
		<div className="card">
			<h3>Usage-Based Billing</h3>
			<p className="muted">Current usage; commercial amount is quoted in the approved order.</p>

			<div className="grid" style={{ marginTop: 16 }}>
				<div>
					<div className="muted small">Ücretsiz Agent</div>
					<div className="mono">{entitlements.includedAgents}</div>
				</div>
				<div>
					<div className="muted small">Ekstra Agent</div>
					<div className="mono">{billableAgents}</div>
				</div>
				<div>
					<div className="muted small">Commercial unit price</div>
					<div className="mono">Quoted in approved order</div>
				</div>
				<div>
					<div className="muted small">Commercial amount</div>
					<div className="mono" style={{ fontSize: 20, fontWeight: 600, color: "#3b82f6" }}>
						Quoted in approved order ({additionalAgentCount} additional agent{additionalAgentCount === 1 ? "" : "s"})
					</div>
				</div>
			</div>

			{billing && (
				<div className="notice" style={{ marginTop: 16 }}>
					<div className="muted small">Subscription Status</div>
					<div className="mono">{billing.status}</div>
					{billing.currentPeriodEnd && (
						<div className="muted small" style={{ marginTop: 4 }}>
							Period ends: {new Date(billing.currentPeriodEnd).toLocaleDateString()}
						</div>
					)}
				</div>
			)}
		</div>
	);
}
