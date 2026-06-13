import { useEffect, useState } from "react";
import type { Database } from "../lib/database.types";
import { supabase } from "../lib/supabase";

interface ReferralStats {
	referralCount: number;
	creditsEarned: number;
}

export function ReferralSection({ userId }: { userId: string }) {
	const [referralCode, setReferralCode] = useState("");
	const [stats, setStats] = useState<ReferralStats>({
		referralCount: 0,
		creditsEarned: 0,
	});
	const [isLoading, setIsLoading] = useState(true);
	const [copied, setCopied] = useState(false);
	const [error, setError] = useState<string | null>(null);

	useEffect(() => {
		loadReferralData();
	}, [loadReferralData]);

	async function loadReferralData() {
		setIsLoading(true);
		setError(null);

		try {
			// Get user's referral code
			const { data: user, error: userError } = await supabase
				.from("users")
				.select("referral_code")
				.eq("id", userId)
				.single();

			if (userError) throw userError;
			setReferralCode(
				(user as Database["public"]["Tables"]["users"]["Row"] | null)?.referral_code || "",
			);

			// Get referral statistics
			const { data: credits, error: creditsError } = await supabase
				.from("referral_credits")
				.select("credit_months, status")
				.eq("referrer_id", userId);

			if (creditsError) throw creditsError;

			const referralCount =
				(credits as Database["public"]["Tables"]["referral_credits"]["Row"][] | null)?.length || 0;
			const creditsEarned =
				(credits as Database["public"]["Tables"]["referral_credits"]["Row"][] | null)?.reduce(
					(sum, r) => sum + (r.credit_months || 0),
					0,
				) || 0;

			setStats({
				referralCount,
				creditsEarned,
			});
		} catch (err) {
			setError(err instanceof Error ? err.message : "Failed to load referral data");
		} finally {
			setIsLoading(false);
		}
	}

	const referralLink = referralCode ? `https://aidr.singularityrd.com/?ref=${referralCode}` : "";

	function copyToClipboard() {
		if (!referralLink) return;

		navigator.clipboard.writeText(referralLink).then(() => {
			setCopied(true);
			setTimeout(() => setCopied(false), 2000);
		});
	}

	function shareOnTwitter() {
		const text = encodeURIComponent(
			"I'm using AIDR to protect my AI agents from security threats. Get 1 month free when you sign up! 🛡️🤖",
		);
		const url = encodeURIComponent(referralLink);
		window.open(`https://twitter.com/intent/tweet?text=${text}&url=${url}`, "_blank");
	}

	function shareOnLinkedIn() {
		const url = encodeURIComponent(referralLink);
		const text = encodeURIComponent(
			"Protect your AI agents with AIDR - AI Agent Detection & Response",
		);
		window.open(
			`https://www.linkedin.com/sharing/share-offsite/?url=${url}&summary=${text}`,
			"_blank",
		);
	}

	function shareByEmail() {
		const subject = encodeURIComponent("Get AIDR - AI Agent Security");
		const body = encodeURIComponent(
			`Hey!\n\nI've been using AIDR to protect my AI agents from security threats. It's amazing!\n\nSign up using my referral link and get 1 month free:\n\n${referralLink}\n\nCheers!`,
		);
		window.location.href = `mailto:?subject=${subject}&body=${body}`;
	}

	if (isLoading) {
		return (
			<div className="card referral-card">
				<h3>🎁 Earn Free Months</h3>
				<p className="muted">Loading referral data...</p>
			</div>
		);
	}

	return (
		<div
			className="card referral-card"
			style={{
				background: "linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%)",
				border: "none",
			}}
		>
			<h3>🎁 Earn Free Months</h3>
			<p className="muted">
				Invite friends, get <strong>1 month free Pro</strong> for each signup!
			</p>

			{error && (
				<div className="notice notice-danger" style={{ marginBottom: 12 }}>
					⚠️ {error}
				</div>
			)}

			{/* Referral Link */}
			<div style={{ marginTop: 16, marginBottom: 16 }}>
				<label className="label muted small">Your Referral Link</label>
				<div
					className="row"
					style={{
						background: "white",
						borderRadius: 8,
						padding: "8px 12px",
						border: "1px solid #e5e7eb",
					}}
				>
					<input
						value={referralLink}
						readOnly
						className="input"
						style={{
							border: "none",
							background: "transparent",
							flex: 1,
							fontFamily: "monospace",
							fontSize: 14,
						}}
					/>
					<button className="button button-sm" onClick={copyToClipboard} disabled={!referralLink}>
						{copied ? "✓ Copied!" : "Copy Link"}
					</button>
				</div>
			</div>

			{/* Stats */}
			<div
				className="grid"
				style={{
					marginTop: 16,
					marginBottom: 16,
					background: "rgba(255,255,255,0.5)",
					padding: 16,
					borderRadius: 8,
				}}
			>
				<div style={{ textAlign: "center" }}>
					<div style={{ fontSize: 28, fontWeight: 700, color: "#4f46e5" }}>
						{stats.referralCount}
					</div>
					<div className="muted small">Friends Invited</div>
				</div>
				<div style={{ textAlign: "center" }}>
					<div style={{ fontSize: 28, fontWeight: 700, color: "#22c55e" }}>
						{stats.creditsEarned}
					</div>
					<div className="muted small">Free Months Earned</div>
				</div>
			</div>

			{/* Social Share Buttons */}
			<div style={{ marginTop: 12 }}>
				<p className="muted small" style={{ marginBottom: 8 }}>
					Share via:
				</p>
				<div className="row">
					<button
						className="button button-sm button-secondary"
						onClick={shareOnTwitter}
						disabled={!referralLink}
						style={{ background: "#1da1f2", color: "white", border: "none" }}
					>
						🐦 Twitter
					</button>
					<button
						className="button button-sm button-secondary"
						onClick={shareOnLinkedIn}
						disabled={!referralLink}
						style={{ background: "#0077b5", color: "white", border: "none" }}
					>
						💼 LinkedIn
					</button>
					<button
						className="button button-sm button-secondary"
						onClick={shareByEmail}
						disabled={!referralLink}
					>
						📧 Email
					</button>
				</div>
			</div>

			{/* How it works */}
			<div
				style={{
					marginTop: 20,
					padding: 12,
					background: "rgba(255,255,255,0.7)",
					borderRadius: 8,
				}}
			>
				<p className="muted small" style={{ margin: 0 }}>
					<strong>How it works:</strong>
					<br />
					1. Share your unique referral link
					<br />
					2. Friend signs up and subscribes
					<br />
					3. You both get 1 month free!
				</p>
			</div>
		</div>
	);
}

// Simple social share buttons component for reuse
export function SocialShareButtons({ link }: { link: string }) {
	if (!link) return null;

	return (
		<div className="row" style={{ gap: 8 }}>
			<a
				href={`https://twitter.com/intent/tweet?text=${encodeURIComponent(
					"Check out AIDR for AI agent security!",
				)}&url=${encodeURIComponent(link)}`}
				target="_blank"
				rel="noopener noreferrer"
				className="button button-sm"
				style={{ background: "#1da1f2", color: "white", textDecoration: "none" }}
			>
				Twitter
			</a>
			<a
				href={`https://www.linkedin.com/sharing/share-offsite/?url=${encodeURIComponent(link)}`}
				target="_blank"
				rel="noopener noreferrer"
				className="button button-sm"
				style={{ background: "#0077b5", color: "white", textDecoration: "none" }}
			>
				LinkedIn
			</a>
			<a
				href={`https://www.facebook.com/sharer/sharer.php?u=${encodeURIComponent(link)}`}
				target="_blank"
				rel="noopener noreferrer"
				className="button button-sm"
				style={{ background: "#4267B2", color: "white", textDecoration: "none" }}
			>
				Facebook
			</a>
		</div>
	);
}
