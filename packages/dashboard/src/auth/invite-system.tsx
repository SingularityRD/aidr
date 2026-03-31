import { createContext, type ReactNode, useCallback, useContext, useEffect, useState } from "react";
import type { Database } from "../lib/database.types";
import { supabase } from "../lib/supabase";

// Types
export interface Invite {
	id: string;
	referrerId: string;
	invitedEmail: string;
	status: "pending" | "converted" | "expired";
	creditsEarned: number;
	createdAt: string;
	convertedAt?: string;
}

export interface ReferralStats {
	totalInvites: number;
	converted: number;
	pending: number;
	totalCreditsEarned: number;
	referralLink: string;
}

interface InviteSystemContextType {
	invites: Invite[];
	stats: ReferralStats | null;
	isLoading: boolean;
	generateInviteLink: () => string;
	sendInvite: (email: string) => Promise<void>;
	trackReferralConversion: (referralCode: string, newUserEmail: string) => Promise<void>;
	claimCredits: () => Promise<number>;
	refreshInvites: () => Promise<void>;
}

const InviteSystemContext = createContext<InviteSystemContextType | null>(null);

export function useInviteSystem() {
	const ctx = useContext(InviteSystemContext);
	if (!ctx) throw new Error("useInviteSystem must be used within InviteSystemProvider");
	return ctx;
}

interface InviteSystemProviderProps {
	children: ReactNode;
	userId: string;
	userEmail: string;
}

const CREDITS_PER_INVITE = 1; // 1 month free Pro per invite

export function InviteSystemProvider({ children, userId, userEmail }: InviteSystemProviderProps) {
	const [invites, setInvites] = useState<Invite[]>([]);
	const [stats, setStats] = useState<ReferralStats | null>(null);
	const [isLoading, setIsLoading] = useState(true);

	// Generate referral code from user ID
	const generateReferralCode = useCallback((id: string): string => {
		return btoa(id)
			.replace(/[^a-zA-Z0-9]/g, "")
			.slice(0, 12)
			.toLowerCase();
	}, []);

	const referralCode = generateReferralCode(userId);
	const referralLink = `${window.location.origin}/signup?ref=${referralCode}`;

	// Load invites on mount
	useEffect(() => {
		let cancelled = false;

		async function loadInvites() {
			setIsLoading(true);

			// Load sent invites
			const { data: sentData, error: sentError } = await supabase
				.from("referrals")
				.select("*")
				.eq("referrer_id", userId)
				.order("created_at", { ascending: false })
				.returns<Database["public"]["Tables"]["referrals"]["Row"][]>();

			if (sentError) {
				console.error("Error loading invites:", sentError);
				setIsLoading(false);
				return;
			}

			if (!cancelled) {
				const formattedInvites: Invite[] = (sentData || []).map((row) => ({
					id: row.id,
					referrerId: row.referrer_id,
					invitedEmail: row.invited_email,
					status: row.status,
					creditsEarned: row.credits_earned || 0,
					createdAt: row.created_at,
					convertedAt: row.converted_at ?? undefined,
				}));

				setInvites(formattedInvites);

				// Calculate stats
				const totalInvites = formattedInvites.length;
				const converted = formattedInvites.filter((i) => i.status === "converted").length;
				const pending = formattedInvites.filter((i) => i.status === "pending").length;
				const totalCreditsEarned = formattedInvites.reduce((sum, i) => sum + i.creditsEarned, 0);

				setStats({
					totalInvites,
					converted,
					pending,
					totalCreditsEarned,
					referralLink,
				});
			}

			setIsLoading(false);
		}

		loadInvites();

		// Subscribe to realtime changes
		const channel = supabase
			.channel("referrals_changes")
			.on(
				"postgres_changes",
				{
					event: "*",
					schema: "public",
					table: "referrals",
					filter: `referrer_id=eq.${userId}`,
				},
				() => {
					// Reload on any change
					loadInvites();
				},
			)
			.subscribe();

		return () => {
			cancelled = true;
			supabase.removeChannel(channel);
		};
	}, [userId, referralLink]);

	// Generate invite link
	const generateInviteLink = useCallback((): string => {
		return referralLink;
	}, [referralLink]);

	// Send invite to email
	const sendInvite = useCallback(
		async (email: string) => {
			// Check if already invited
			const { data: existing } = await supabase
				.from("referrals")
				.select("id")
				.eq("referrer_id", userId)
				.eq("invited_email", email)
				.maybeSingle();

			if (existing) {
				throw new Error("This email has already been invited");
			}

			// Create invite record
			const { error } = await supabase.from("referrals").insert({
				referrer_id: userId,
				invited_email: email,
				status: "pending",
				credits_earned: 0,
			} as never);

			if (error) throw error;

			// Send invite email via Supabase function
			await supabase.functions.invoke("send-invite-email", {
				body: {
					to: email,
					fromEmail: userEmail,
					referralLink,
					referralCode,
				},
			});
		},
		[userId, userEmail, referralLink, referralCode],
	);

	// Track referral conversion (called when new user signs up with referral code)
	const trackReferralConversion = useCallback(
		async (referralCode: string, newUserEmail: string) => {
			// Find referrer by code
			const { data: referrer } = await supabase
				.from("users")
				.select("id")
				.eq("referral_code", referralCode)
				.maybeSingle()
				.returns<Database["public"]["Tables"]["users"]["Row"]>();

			if (!referrer) {
				console.warn("Referrer not found for code:", referralCode);
				return;
			}

			// Update referral status
			const { error } = await supabase
				.from("referrals")
				.update({
					status: "converted",
					credits_earned: CREDITS_PER_INVITE,
					converted_at: new Date().toISOString(),
				} as never)
				.eq("referrer_id", referrer.id)
				.eq("invited_email", newUserEmail);

			if (error) {
				console.error("Error tracking conversion:", error);
				throw error;
			}

			// Grant free Pro month to referrer
			await supabase.functions.invoke("grant-referral-credits", {
				body: {
					userId: referrer.id,
					months: CREDITS_PER_INVITE,
				},
			});
		},
		[],
	);

	// Claim accumulated credits (convert to Pro subscription)
	const claimCredits = useCallback(async (): Promise<number> => {
		const pendingCredits = invites
			.filter((i) => i.status === "converted" && i.creditsEarned > 0)
			.reduce((sum, i) => sum + i.creditsEarned, 0);

		if (pendingCredits === 0) return 0;

		// Call function to apply credits
		const { error } = await supabase.functions.invoke("claim-referral-credits", {
			body: {
				userId,
				credits: pendingCredits,
			},
		});

		if (error) throw error;

		// Reset credits earned in invites
		await supabase
			.from("referrals")
			.update({ credits_earned: 0 } as never)
			.eq("referrer_id", userId)
			.gt("credits_earned", 0);

		// Refresh data
		await refreshInvites();

		return pendingCredits;
	}, [invites, userId]);

	// Refresh invites data
	const refreshInvites = useCallback(async () => {
		const { data, error } = await supabase
			.from("referrals")
			.select("*")
			.eq("referrer_id", userId)
			.order("created_at", { ascending: false })
			.returns<Database["public"]["Tables"]["referrals"]["Row"][]>();

		if (error) {
			console.error("Error refreshing invites:", error);
			return;
		}

		const formattedInvites: Invite[] = (data || []).map((row) => ({
			id: row.id,
			referrerId: row.referrer_id,
			invitedEmail: row.invited_email,
			status: row.status,
			creditsEarned: row.credits_earned || 0,
			createdAt: row.created_at,
			convertedAt: row.converted_at ?? undefined,
		}));

		setInvites(formattedInvites);

		// Recalculate stats
		const totalInvites = formattedInvites.length;
		const converted = formattedInvites.filter((i) => i.status === "converted").length;
		const pending = formattedInvites.filter((i) => i.status === "pending").length;
		const totalCreditsEarned = formattedInvites.reduce((sum, i) => sum + i.creditsEarned, 0);

		setStats({
			totalInvites,
			converted,
			pending,
			totalCreditsEarned,
			referralLink,
		});
	}, [userId, referralLink]);

	const value: InviteSystemContextType = {
		invites,
		stats,
		isLoading,
		generateInviteLink,
		sendInvite,
		trackReferralConversion,
		claimCredits,
		refreshInvites,
	};

	return <InviteSystemContext.Provider value={value}>{children}</InviteSystemContext.Provider>;
}

// Hook to track referral from URL on signup
export function useReferralTracker() {
	const [referralCode, setReferralCode] = useState<string | null>(null);

	useEffect(() => {
		const params = new URLSearchParams(window.location.search);
		const ref = params.get("ref");
		if (ref) {
			setReferralCode(ref);
			// Store in session for later use during signup
			sessionStorage.setItem("pending_referral_code", ref);
		}
	}, []);

	const getStoredReferralCode = useCallback((): string | null => {
		return sessionStorage.getItem("pending_referral_code");
	}, []);

	const clearStoredReferralCode = useCallback((): void => {
		sessionStorage.removeItem("pending_referral_code");
	}, []);

	return {
		referralCode,
		getStoredReferralCode,
		clearStoredReferralCode,
	};
}

// Invite UI Components
export function ReferralStatsCard() {
	const { stats, isLoading, generateInviteLink, claimCredits } = useInviteSystem();
	const [copied, setCopied] = useState(false);

	const copyLink = useCallback(async () => {
		const link = generateInviteLink();
		await navigator.clipboard.writeText(link);
		setCopied(true);
		setTimeout(() => setCopied(false), 2000);
	}, [generateInviteLink]);

	if (isLoading) {
		return <div className="card">Loading referral stats...</div>;
	}

	if (!stats) {
		return <div className="card">No referral data available</div>;
	}

	return (
		<div className="card">
			<h3>🎁 Invite Friends, Get Free Pro</h3>
			<p className="muted">1 arkadaş davet et = 1 ay ücretsiz Pro</p>

			<div className="grid" style={{ marginTop: 16 }}>
				<div>
					<div className="muted small">Toplam Davet</div>
					<div className="mono" style={{ fontSize: 24, fontWeight: 600 }}>
						{stats.totalInvites}
					</div>
				</div>
				<div>
					<div className="muted small">Dönüşen</div>
					<div className="mono" style={{ fontSize: 24, fontWeight: 600, color: "#22c55e" }}>
						{stats.converted}
					</div>
				</div>
				<div>
					<div className="muted small">Bekleyen</div>
					<div className="mono" style={{ fontSize: 24, fontWeight: 600, color: "#f59e0b" }}>
						{stats.pending}
					</div>
				</div>
				<div>
					<div className="muted small">Kazanılan Kredi (Ay)</div>
					<div className="mono" style={{ fontSize: 24, fontWeight: 600, color: "#3b82f6" }}>
						{stats.totalCreditsEarned}
					</div>
				</div>
			</div>

			<div style={{ marginTop: 20 }}>
				<div className="muted small" style={{ marginBottom: 8 }}>
					Senin davet linkin:
				</div>
				<div className="row">
					<input
						type="text"
						value={stats.referralLink}
						readOnly
						className="input"
						style={{ flex: 1 }}
					/>
					<button className="button" onClick={copyLink}>
						{copied ? "Kopyalandı!" : "Kopyala"}
					</button>
				</div>
			</div>

			{stats.totalCreditsEarned > 0 && (
				<div style={{ marginTop: 16 }}>
					<button className="button" onClick={claimCredits}>
						Kredileri Kullan ({stats.totalCreditsEarned} ay Pro)
					</button>
				</div>
			)}
		</div>
	);
}

export function InviteForm() {
	const { sendInvite, refreshInvites } = useInviteSystem();
	const [email, setEmail] = useState("");
	const [status, setStatus] = useState<{ type: "success" | "error"; message: string } | null>(null);
	const [sending, setSending] = useState(false);

	const handleSubmit = useCallback(
		async (e: React.FormEvent) => {
			e.preventDefault();
			if (!email.trim()) return;

			setSending(true);
			setStatus(null);

			try {
				await sendInvite(email.trim());
				setStatus({ type: "success", message: "Davet gönderildi!" });
				setEmail("");
				await refreshInvites();
			} catch (err) {
				setStatus({
					type: "error",
					message: err instanceof Error ? err.message : "Davet gönderilemedi",
				});
			} finally {
				setSending(false);
			}
		},
		[email, sendInvite, refreshInvites],
	);

	return (
		<div className="card">
			<h4>E-posta ile Davet Gönder</h4>
			<form onSubmit={handleSubmit}>
				<div className="row">
					<input
						type="email"
						value={email}
						onChange={(e) => setEmail(e.target.value)}
						placeholder="arkadas@email.com"
						className="input"
						required
					/>
					<button type="submit" className="button" disabled={sending || !email.trim()}>
						{sending ? "Gönderiliyor..." : "Davet Gönder"}
					</button>
				</div>
				{status && (
					<div className={`notice ${status.type === "error" ? "notice-danger" : ""}`}>
						{status.message}
					</div>
				)}
			</form>
		</div>
	);
}

export function InvitesList() {
	const { invites, isLoading } = useInviteSystem();

	if (isLoading) return <div className="card">Yükleniyor...</div>;
	if (invites.length === 0) return <div className="card">Henüz davet gönderilmemiş</div>;

	return (
		<div className="card">
			<h4>Davet Geçmişi</h4>
			<table className="table">
				<thead>
					<tr>
						<th>E-posta</th>
						<th>Durum</th>
						<th>Tarih</th>
						<th>Kredi</th>
					</tr>
				</thead>
				<tbody>
					{invites.map((invite) => (
						<tr key={invite.id}>
							<td>{invite.invitedEmail}</td>
							<td>
								<span className={`badge badge-${invite.status}`}>
									{invite.status === "converted"
										? "✅ Dönüştü"
										: invite.status === "pending"
											? "⏳ Bekliyor"
											: "❌ Süresi Doldu"}
								</span>
							</td>
							<td>{new Date(invite.createdAt).toLocaleDateString("tr-TR")}</td>
							<td>{invite.creditsEarned > 0 ? `+${invite.creditsEarned} ay` : "-"}</td>
						</tr>
					))}
				</tbody>
			</table>
		</div>
	);
}
