import { useEffect, useState } from "react";
import type { Database } from "../lib/database.types";
import { supabase } from "../lib/supabase";
import { createCheckout } from "./lemon-client";

interface Seat {
	id: string;
	agentName: string;
	agentType: "claude" | "cursor" | "vscode" | "openclaw" | "opencode";
	status: "active" | "paused" | "deleted";
	lastSeenAt?: string;
	createdAt: string;
}

interface Subscription {
	id: string;
	lemonSubscriptionId: string;
	status: string;
	planType: string;
	seats: number;
	currentPeriodEnd?: string;
	provider: string;
}

export function SeatManager({ userId }: { userId: string }) {
	const [seats, setSeats] = useState<Seat[]>([]);
	const [subscription, setSubscription] = useState<Subscription | null>(null);
	const [credits, setCredits] = useState(0);
	const [userEmail, setUserEmail] = useState("");
	const [isLoading, setIsLoading] = useState(true);
	const [isAddingSeat, setIsAddingSeat] = useState(false);
	const [error, setError] = useState<string | null>(null);

	useEffect(() => {
		loadUserData();
	}, [loadUserData]);

	async function loadUserData() {
		setIsLoading(true);
		setError(null);

		try {
			// Get user email
			const { data: user, error: userError } = await supabase
				.from("users")
				.select("email")
				.eq("id", userId)
				.single();

			if (userError) throw userError;
			setUserEmail((user as Database["public"]["Tables"]["users"]["Row"] | null)?.email || "");

			// Get active subscription
			const { data: subData } = await supabase
				.from("subscriptions")
				.select("*")
				.eq("user_id", userId)
				.in("status", ["active", "paused"])
				.order("created_at", { ascending: false })
				.limit(1)
				.single();

			if (subData) {
				const typedSub = subData as Database["public"]["Tables"]["subscriptions"]["Row"];
				setSubscription({
					id: typedSub.id,
					lemonSubscriptionId: typedSub.lemon_subscription_id || "",
					status: typedSub.status,
					planType: typedSub.plan_type || "monthly",
					seats: typedSub.seats || 1,
					currentPeriodEnd: typedSub.current_period_end || undefined,
					provider: typedSub.provider || "lemon_squeezy",
				});
			}

			// Get used seats
			const { data: seatsData, error: seatsError } = await supabase
				.from("agent_seats")
				.select("*")
				.eq("user_id", userId)
				.neq("status", "deleted");

			if (seatsError) throw seatsError;

			setSeats(
				((seatsData as Database["public"]["Tables"]["agent_seats"]["Row"][]) || []).map((s) => ({
					id: s.id,
					agentName: s.agent_name,
					agentType: s.agent_type,
					status: s.status,
					lastSeenAt: undefined,
					createdAt: s.created_at,
				})),
			);

			// Get referral credits
			const { data: creditsData, error: creditsError } = await supabase
				.from("referral_credits")
				.select("credit_months")
				.eq("referrer_id", userId)
				.eq("status", "active");

			if (creditsError) throw creditsError;

			const totalCredits =
				(creditsData as Database["public"]["Tables"]["referral_credits"]["Row"][] | null)?.reduce(
					(sum, c) => sum + (c.credit_months || 0),
					0,
				) || 0;
			setCredits(totalCredits);
		} catch (err) {
			setError(err instanceof Error ? err.message : "Failed to load data");
		} finally {
			setIsLoading(false);
		}
	}

	async function addSeat() {
		if (!userEmail || !subscription) {
			setError("Please complete onboarding first");
			return;
		}

		setIsAddingSeat(true);
		setError(null);

		try {
			const newSeatCount = (subscription?.seats || 0) + 1;

			// Lemon Squeezy checkout oluştur (prorated upgrade)
			const { checkoutUrl } = await createCheckout(
				userId,
				userEmail,
				newSeatCount,
				(subscription?.planType as "monthly" | "yearly") || "monthly",
			);

			window.location.href = checkoutUrl;
		} catch (err) {
			setError(err instanceof Error ? err.message : "Failed to create checkout");
			setIsAddingSeat(false);
		}
	}

	async function pauseSeat(seatId: string) {
		const { error } = await supabase
			.from("agent_seats")
			.update({ status: "paused" } as never)
			.eq("id", seatId);

		if (error) {
			setError(error.message);
		} else {
			setSeats((prev) => prev.map((s) => (s.id === seatId ? { ...s, status: "paused" } : s)));
		}
	}

	async function resumeSeat(seatId: string) {
		const { error } = await supabase
			.from("agent_seats")
			.update({ status: "active" } as never)
			.eq("id", seatId);

		if (error) {
			setError(error.message);
		} else {
			setSeats((prev) => prev.map((s) => (s.id === seatId ? { ...s, status: "active" } : s)));
		}
	}

	async function deleteSeat(seatId: string) {
		if (!confirm("Are you sure you want to delete this seat?")) return;

		const { error } = await supabase
			.from("agent_seats")
			.update({ status: "deleted" } as never)
			.eq("id", seatId);

		if (error) {
			setError(error.message);
		} else {
			setSeats((prev) => prev.filter((s) => s.id !== seatId));
		}
	}

	const activeSeats = seats.filter((s) => s.status === "active").length;
	const maxSeats = subscription?.seats || 1;
	const canAddMore = activeSeats < maxSeats;

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

	if (isLoading) {
		return <div className="card">Loading seat data...</div>;
	}

	return (
		<div className="card">
			<h2>Agent Seats</h2>

			{error && (
				<div className="notice notice-danger" style={{ marginBottom: 16 }}>
					⚠️ {error}
				</div>
			)}

			<div className="grid" style={{ marginTop: 16, marginBottom: 16 }}>
				<div>
					<div className="muted small">Active Seats</div>
					<div className="mono" style={{ fontSize: 24, fontWeight: 600 }}>
						{activeSeats}
					</div>
				</div>
				<div>
					<div className="muted small">Total Seats</div>
					<div className="mono" style={{ fontSize: 24, fontWeight: 600 }}>
						{maxSeats}
					</div>
				</div>
				<div>
					<div className="muted small">Plan</div>
					<div className="mono" style={{ fontSize: 20, fontWeight: 600 }}>
						{subscription?.planType === "yearly"
							? "Yearly"
							: subscription?.planType === "monthly"
								? "Monthly"
								: "Free"}
					</div>
				</div>
				<div>
					<div className="muted small">Provider</div>
					<div className="mono" style={{ fontSize: 16 }}>
						{subscription?.provider === "lemon_squeezy"
							? "🍋 Lemon Squeezy"
							: subscription?.provider || "Free"}
					</div>
				</div>
			</div>

			{credits > 0 && (
				<div
					className="notice"
					style={{
						background: "linear-gradient(135deg, #667eea 0%, #764ba2 100%)",
						color: "white",
						marginBottom: 16,
					}}
				>
					🎉 You have <strong>{credits}</strong> free month(s) from referrals!
				</div>
			)}

			{subscription?.currentPeriodEnd && (
				<div className="muted small" style={{ marginBottom: 16 }}>
					Next billing: {new Date(subscription.currentPeriodEnd).toLocaleDateString()}
				</div>
			)}

			{/* Seats Table */}
			<div style={{ marginTop: 20 }}>
				<h4>Your Agent Seats</h4>
				{seats.length === 0 ? (
					<p className="muted">No agents registered yet</p>
				) : (
					<table className="table">
						<thead>
							<tr>
								<th>Agent</th>
								<th>Type</th>
								<th>Status</th>
								<th>Last Seen</th>
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
										<span
											className={`badge badge-${
												seat.status === "active"
													? "success"
													: seat.status === "paused"
														? "warning"
														: "danger"
											}`}
										>
											{seat.status === "active"
												? "🟢 Active"
												: seat.status === "paused"
													? "⏸️ Paused"
													: "❌ Deleted"}
										</span>
									</td>
									<td className="muted small">
										{seat.lastSeenAt ? new Date(seat.lastSeenAt).toLocaleDateString() : "Never"}
									</td>
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
				)}
			</div>

			<div className="row" style={{ marginTop: 20 }}>
				<button className="button" onClick={addSeat} disabled={!canAddMore || isAddingSeat}>
					{isAddingSeat ? "Loading..." : canAddMore ? "+ Add Seat" : "Seat Limit Reached"}
				</button>
				<button className="button button-secondary" onClick={loadUserData} disabled={isLoading}>
					Refresh
				</button>
			</div>

			{!canAddMore && subscription && (
				<p className="muted small" style={{ marginTop: 12 }}>
					You&apos;ve reached your seat limit. Upgrade your plan to add more agents.
				</p>
			)}
		</div>
	);
}
