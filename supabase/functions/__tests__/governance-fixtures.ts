// Shared fixtures shaped exactly like the output of
// public.governance_scorecard / public.governance_digest_summary
// (supabase/migrations/20260927000060_governance_scorecard.sql). The real-SQL
// shape is pinned by scripts/governance-scorecard-postgres.test.mjs; the Edge
// contract suite and the dashboard page tests reuse this object.

export const GOVERNANCE_TENANT = "22222222-2222-4222-8222-222222222222";
export const GOVERNANCE_OWNER = "11111111-1111-4111-8111-111111111111";
export const GOVERNANCE_APPROVER = "33333333-3333-4333-8333-333333333333";

function trend(days: number) {
	return Array.from({ length: days }, (_, index) => {
		const day = new Date(Date.UTC(2026, 7, 27 + index)).toISOString().slice(0, 10);
		const busy = index === days - 2;
		return { day, allow: busy ? 40 : 2, ask: busy ? 3 : 0, deny: busy ? 5 : 0, masked: busy ? 7 : 1, blocked: busy ? 1 : 0 };
	});
}

/** The digest summary (no identities, no settings). */
export function governanceSummaryFixture(days = 30): Record<string, unknown> {
	return {
		generated_at: "2026-09-25T10:00:00.000Z",
		period: { from: "2026-08-27T00:00:00.000Z", to: "2026-09-25T10:00:00.000Z", days },
		usage: {
			agents: { enrolled: 12, active: 9 },
			browser_installs: { enrolled: 40, active: 31 },
			by_runtime: [
				{ runtime: "browser_guard", enrolled: 40, active: 31 },
				{ runtime: "claude-code", enrolled: 8, active: 7 },
				{ runtime: "cursor", enrolled: 4, active: 2 },
			],
			ai_sites: {
				distinct: 3,
				by_site: [
					{ site: "chatgpt", scans: 120, blocked: 2 },
					{ site: "gemini", scans: 30, blocked: 0 },
					{ site: "other", scans: 4, blocked: 1 },
				],
			},
			mcp_servers: { distinct: 6, not_approved: 2 },
		},
		decisions: { allow: 1200, ask: 40, deny: 25, released_by_operator: 3, released_by_dashboard: 18, released_other: 0 },
		trend: trend(days),
		approvals: {
			requested: 40,
			approved: 30,
			denied: 6,
			expired_without_decision: 3,
			pending: 1,
			median_decision_seconds: 42.5,
			p90_decision_seconds: 600,
		},
		oversight: {
			thresholds: { fast_seconds: 30, min_decisions: 10, fast_share: 0.9 },
			approvers: 3,
			review_prompts: 1,
			by_approver: [],
		},
		incidents: {
			reported: 5,
			open: 2,
			status_unknown: 0,
			open_by_severity: { critical: 1, high: 1, warning: 0, info: 0, unknown: 0 },
		},
		browser_guard: { scans: 154, masked: 60, warned: 4, blocked: 3, allowed: 87, items_masked: 142 },
		policies: {
			runtime: { version: 7, updated_at: "2026-05-01T09:00:00.000Z", age_days: 147 },
			dlp: { version: 3, updated_at: "2026-09-20T09:00:00.000Z", age_days: 5 },
			team: null,
			runtime_revisions_in_period: 0,
			dlp_revisions_in_period: 1,
		},
		identity: {
			require_mfa: false,
			sso_required: false,
			scim_active_tokens: 0,
			owners_admins: 3,
			owners_admins_without_mfa: 1,
			retention_policies: 10,
			telemetry_retention_days: 90,
			legal_hold_active: false,
		},
		posture: { findings: 9, critical: 1, high: 2, cve_confirmed: 1 },
		acceptable_use: {
			versions: [
				{ notice_id: "acme-aup", notice_version: 3, installs: 25, last_acknowledged_at: "2026-09-24T08:00:00.000Z" },
				{ notice_id: "acme-aup", notice_version: 2, installs: 38, last_acknowledged_at: "2026-07-01T08:00:00.000Z" },
			],
		},
		signals: {
			agents_reporting: true,
			browser_guard_reporting: true,
			dlp_policy_configured: true,
			runtime_policy_configured: true,
			human_approval_in_use: true,
			acceptable_use_acknowledged: true,
			mcp_inventory_reported: true,
			posture_reported: true,
			mfa_required: false,
			retention_configured: true,
			compliance_report_generated: false,
			governance_digest_enabled: false,
		},
	};
}

/** The dashboard scorecard (owner/admin view with approver identities). */
export function governanceScorecardFixture(days: 7 | 30 | 90 = 30): Record<string, unknown> {
	const summary = governanceSummaryFixture(days);
	return {
		...summary,
		window_days: days,
		oversight: {
			...(summary.oversight as Record<string, unknown>),
			by_approver: [
				{
					user_id: GOVERNANCE_APPROVER,
					email: "fast.approver@acme.example",
					decisions: 20,
					approved: 20,
					denied: 0,
					fast_approvals: 19,
					median_seconds: 4,
					review: true,
				},
				{
					user_id: GOVERNANCE_OWNER,
					email: "owner@acme.example",
					decisions: 14,
					approved: 8,
					denied: 6,
					fast_approvals: 1,
					median_seconds: 180,
					review: false,
				},
			],
		},
		settings: {
			digest_enabled: false,
			digest_cadence: "weekly",
			digest_recipients: "owners_admins",
			digest_next_at: null,
			digest_last_at: null,
			digest_last_status: null,
			oversight_fast_seconds: 30,
			oversight_min_decisions: 10,
			oversight_fast_share: 0.9,
			updated_at: null,
		},
		recent_deliveries: [],
	};
}

/** A scorecard for a workspace that has reported nothing yet. */
export function emptyGovernanceScorecardFixture(): Record<string, unknown> {
	const days = 30;
	return {
		generated_at: "2026-09-25T10:00:00.000Z",
		period: { from: "2026-08-27T00:00:00.000Z", to: "2026-09-25T10:00:00.000Z", days },
		window_days: days,
		usage: {
			agents: { enrolled: 0, active: 0 },
			browser_installs: { enrolled: 0, active: 0 },
			by_runtime: [],
			ai_sites: { distinct: 0, by_site: [] },
			mcp_servers: { distinct: 0, not_approved: 0 },
		},
		decisions: { allow: 0, ask: 0, deny: 0, released_by_operator: 0, released_by_dashboard: 0, released_other: 0 },
		trend: trend(days).map((row) => ({ ...row, allow: 0, ask: 0, deny: 0, masked: 0, blocked: 0 })),
		approvals: {
			requested: 0, approved: 0, denied: 0, expired_without_decision: 0, pending: 0,
			median_decision_seconds: null, p90_decision_seconds: null,
		},
		oversight: { thresholds: { fast_seconds: 30, min_decisions: 10, fast_share: 0.9 }, approvers: 0, review_prompts: 0, by_approver: [] },
		incidents: { reported: 0, open: 0, status_unknown: 0, open_by_severity: { critical: 0, high: 0, warning: 0, info: 0, unknown: 0 } },
		browser_guard: { scans: 0, masked: 0, warned: 0, blocked: 0, allowed: 0, items_masked: 0 },
		policies: { runtime: null, dlp: null, team: null, runtime_revisions_in_period: 0, dlp_revisions_in_period: 0 },
		identity: {
			require_mfa: false, sso_required: false, scim_active_tokens: 0, owners_admins: 1,
			owners_admins_without_mfa: 0, retention_policies: 0, telemetry_retention_days: null, legal_hold_active: false,
		},
		posture: { findings: 0, critical: 0, high: 0, cve_confirmed: 0 },
		acceptable_use: { versions: [] },
		signals: {
			agents_reporting: false, browser_guard_reporting: false, dlp_policy_configured: false,
			runtime_policy_configured: false, human_approval_in_use: false, acceptable_use_acknowledged: false,
			mcp_inventory_reported: false, posture_reported: false, mfa_required: false, retention_configured: false,
			compliance_report_generated: false, governance_digest_enabled: false,
		},
		settings: {
			digest_enabled: false, digest_cadence: "weekly", digest_recipients: "owners_admins", digest_next_at: null,
			digest_last_at: null, digest_last_status: null, oversight_fast_seconds: 30, oversight_min_decisions: 10,
			oversight_fast_share: 0.9, updated_at: null,
		},
		recent_deliveries: [],
	};
}
