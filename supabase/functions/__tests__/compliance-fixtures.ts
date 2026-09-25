// Shared fixtures for the compliance-report suites (Edge contract, CLI verify
// round trip, dashboard page). The evidence mirrors what
// public.compliance_report_evidence returns for a small tenant; the Postgres
// suite (scripts/compliance-report-postgres.test.mjs) proves the real SQL
// produces this shape.

export const COMPLIANCE_TENANT = "22222222-2222-4222-8222-222222222222";
export const COMPLIANCE_OWNER = "11111111-1111-4111-8111-111111111111";
export const COMPLIANCE_REPORT_ID = "99999999-9999-4999-8999-999999999999";
const SHA = (char: string) => char.repeat(64);

export function complianceEvidenceFixture(): Record<string, unknown> {
	return {
		generated_at: "2026-09-25T10:00:00.123456+00:00",
		actor_role: "owner",
		tenant_profile: {
			tenant_id: COMPLIANCE_TENANT,
			name: "Acme Security",
			kind: "team",
			status: "active",
			region: "eu-central-1",
			retention_days: 90,
			created_at: "2026-01-01T00:00:00+00:00",
		},
		protection_coverage: {
			by_runtime: [
				{
					runtime: "browser_guard",
					enrolled: 12,
					active_in_period: 9,
					first_enrolled_at: "2026-02-01T00:00:00+00:00",
					last_seen_at: "2026-09-25T09:00:00+00:00",
				},
				{
					runtime: "claude-code",
					enrolled: 20,
					active_in_period: 18,
					first_enrolled_at: "2026-01-05T00:00:00+00:00",
					last_seen_at: "2026-09-25T09:30:00+00:00",
				},
			],
			totals: {
				enrolled: 32,
				active_in_period: 27,
				browser_installs: 12,
				browser_installs_active_in_period: 9,
				last_seen_at: "2026-09-25T09:30:00+00:00",
			},
		},
		browser_guard: {
			totals: { scans: 48, masked: 38, warned: 3, blocked: 7, allowed: 0 },
			by_entity_type: [
				{ entity_type: "EMAIL", items: 900, masked_items: 880, warned_items: 5, blocked_items: 15 },
				{ entity_type: "TC_KIMLIK", items: 300, masked_items: 290, warned_items: 0, blocked_items: 10 },
			],
			by_site: [
				{ site: "chatgpt", scans: 30, masked: 25, warned: 2, blocked: 3 },
				{ site: "gemini", scans: 18, masked: 13, warned: 1, blocked: 4 },
			],
			by_channel: [
				{ channel: "paste", scans: 8 },
				{ channel: "prompt", scans: 40 },
			],
			by_day: [
				{ day: "2026-09-24", scans: 40, masked: 32, warned: 2, blocked: 6 },
				{ day: "2026-09-25", scans: 8, masked: 6, warned: 1, blocked: 1 },
			],
			managed_policy_ids: [
				{
					policy_id: "acme-browser-policy-v3",
					scans: 44,
					first_seen_at: "2026-09-24T08:00:00+00:00",
					last_seen_at: "2026-09-25T08:00:00+00:00",
				},
			],
		},
		agent_decisions: {
			totals: { decisions: 500, allow: 470, ask: 10, deny: 20 },
			data_protection: { decisions: 25, allow: 15, ask: 2, deny: 8 },
			by_source: [
				{ source: "heuristic", decisions: 475, allow: 455, ask: 8, deny: 12 },
				{ source: "dlp", decisions: 25, allow: 15, ask: 2, deny: 8 },
			],
		},
		policy_inventory: {
			dlp: {
				current: {
					version: 4,
					updated_at: "2026-09-01T00:00:00+00:00",
					sha256: SHA("a"),
					labels: 3,
					rules: 5,
					exceptions: 1,
				},
				revisions_total: 4,
				revisions_in_period: [{ version: 4, created_at: "2026-09-01T00:00:00+00:00", sha256: SHA("a") }],
			},
			runtime: {
				current: {
					version: 7,
					updated_at: "2026-09-10T00:00:00+00:00",
					sha256: SHA("b"),
					actions: { command_default: "ask", mcp_unknown: "deny", url_default: "allow" },
					list_sizes: { mcp_require_approval_servers: 2, mcp_require_approval_tools: 1, mcp_deny_servers: 3 },
				},
				revisions_total: 7,
				revisions_in_period: [
					{ version: 6, created_at: "2026-09-05T00:00:00+00:00", sha256: SHA("c") },
					{ version: 7, created_at: "2026-09-10T00:00:00+00:00", sha256: SHA("b") },
				],
			},
			team_policy: { updated_at: "2026-08-01T00:00:00+00:00", sha256: SHA("d") },
		},
		access_identity: {
			identity_policy: {
				require_mfa: true,
				sso_required: false,
				break_glass_enabled: true,
				updated_at: "2026-03-01T00:00:00+00:00",
			},
			scim: {
				active_tokens: 1,
				last_token_use_at: "2026-09-25T06:00:00+00:00",
				provisioned_users_active: 40,
				group_role_mappings: 3,
			},
			members_by_role: [
				{ role: "admin", members: 2 },
				{ role: "member", members: 37 },
				{ role: "owner", members: 1 },
			],
			admins: [
				{
					user_id: COMPLIANCE_OWNER,
					email: "owner@acme.example",
					role: "owner",
					joined_at: "2026-01-01T00:00:00+00:00",
					expires_at: null,
					mfa_verified: true,
				},
				{
					user_id: "33333333-3333-4333-8333-333333333333",
					email: "admin@acme.example",
					role: "admin",
					joined_at: "2026-02-01T00:00:00+00:00",
					expires_at: null,
					mfa_verified: false,
				},
			],
			admin_activity: [
				{ action: "dlp_policy.save", events: 1 },
				{ action: "tenant.settings_updated", events: 2 },
			],
		},
		incidents: {
			incidents: {
				total: 5,
				by_severity: { high: 2, critical: 1, warning: 2 },
				by_status: { open: 1, resolved: 4 },
			},
			plugin_scans_with_findings: 2,
		},
		ai_security_posture: {
			by_source_severity: [
				{ source: "infra_scan", severity: "critical", findings: 1 },
				{ source: "mcp_inventory", severity: "high", findings: 2 },
			],
			cve: {
				findings: 1,
				distinct_vulnerabilities: 1,
				confirmed_applicable: 1,
				max_cvss: 9.8,
				by_severity: { critical: 1 },
			},
			mcp: {
				findings: 2,
				distinct_servers: 2,
				by_attestation: { unverifiable: 1, approved: 1 },
				by_transport: { stdio: 1, remote: 1 },
				by_risk_category: { shell_wrapper_command: 1, remote_mcp_url: 1 },
			},
			skills: { findings: 0, by_risk_type: {} },
		},
		retention_deletion: {
			policies: [
				{
					data_class: "security_audit",
					retention_days: 365,
					covers_backups: false,
					updated_at: "2026-01-01T00:00:00+00:00",
				},
				{ data_class: "telemetry", retention_days: 90, covers_backups: false, updated_at: "2026-01-01T00:00:00+00:00" },
			],
			telemetry: {
				retention_days: 90,
				oldest_event_at: "2026-06-28T00:00:00+00:00",
				oldest_event_age_days: 89,
				grace_days: 1,
				within_policy: true,
			},
			legal_holds: { active: false, active_since: null, placed_in_period: 0, released_in_period: 0 },
			offboarding_runs: [],
			audit_exports: { created_in_period: 3, stored_now: 1, expired_pending_cleanup: 0 },
		},
	};
}
