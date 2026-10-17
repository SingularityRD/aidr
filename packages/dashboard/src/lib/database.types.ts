// Database type definitions for Supabase
// Generated schema types for AIDR Dashboard

type AddRelationships<T extends Record<string, object>> = {
	[K in keyof T]: T[K] extends { Relationships: unknown } ? T[K] : T[K] & { Relationships: [] };
};

export interface Database {
	public: {
		Tables: AddRelationships<{
			tenants: {
				Row: {
					id: string;
					name: string;
					kind: "personal" | "team" | "enterprise";
					status: "active" | "suspended" | "closing" | "closed";
					created_by: string | null;
					region: string | null;
					retention_days: number;
					created_at: string;
					closed_at: string | null;
				};
				Insert: {
					id?: string;
					name: string;
					kind?: "personal" | "team" | "enterprise";
					status?: "active" | "suspended" | "closing" | "closed";
					created_by?: string | null;
					region?: string | null;
					retention_days?: number;
					created_at?: string;
					closed_at?: string | null;
				};
				Update: {
					id?: string;
					name?: string;
					kind?: "personal" | "team" | "enterprise";
					status?: "active" | "suspended" | "closing" | "closed";
					created_by?: string | null;
					region?: string | null;
					retention_days?: number;
					created_at?: string;
					closed_at?: string | null;
				};
			};
			tenant_members: {
				Row: {
					tenant_id: string;
					user_id: string;
					role: "owner" | "admin" | "member" | "viewer" | "auditor" | "support_jit";
					joined_at: string;
					expires_at: string | null;
					created_at: string;
				};
				Insert: {
					tenant_id: string;
					user_id: string;
					role?: "owner" | "admin" | "member" | "viewer" | "auditor" | "support_jit";
					joined_at?: string;
					expires_at?: string | null;
					created_at?: string;
				};
				Update: {
					tenant_id?: string;
					user_id?: string;
					role?: "owner" | "admin" | "member" | "viewer" | "auditor" | "support_jit";
					joined_at?: string;
					expires_at?: string | null;
					created_at?: string;
				};
			};
			agent_seats: {
				Row: {
					id: string;
					user_id: string;
					agent_name: string;
					agent_type: "claude" | "cursor" | "vscode" | "openclaw" | "opencode";
					status: "active" | "paused" | "deleted";
					tier: "free" | "pro";
					created_at: string;
					expires_at: string | null;
				};
				Insert: {
					id?: string;
					user_id: string;
					agent_name: string;
					agent_type: "claude" | "cursor" | "vscode" | "openclaw" | "opencode";
					status?: "active" | "paused" | "deleted";
					tier?: "free" | "pro";
					created_at?: string;
					expires_at?: string | null;
				};
				Update: {
					id?: string;
					user_id?: string;
					agent_name?: string;
					agent_type?: "claude" | "cursor" | "vscode" | "openclaw" | "opencode";
					status?: "active" | "paused" | "deleted";
					tier?: "free" | "pro";
					created_at?: string;
					expires_at?: string | null;
				};
			};
			subscriptions: {
				Row: {
					id: string;
					user_id: string;
					tenant_id: string;
					provider: string;
					provider_subscription_id: string;
					status: string;
					extra_agents: number;
					current_period_start: string | null;
					current_period_end: string | null;
					cancel_at_period_end: boolean;
					created_at: string;
					updated_at: string;
					lemon_subscription_id?: string | null;
					lemon_customer_id?: string | null;
					lemon_order_id?: string | null;
					lemon_product_id?: string | null;
					lemon_variant_id?: string | null;
					plan_type?: "monthly" | "yearly" | null;
					seats?: number;
					total_seats?: number;
					trial_ends_at?: string | null;
					referral_code_used?: string | null;
					cancelled_at?: string | null;
				};
				Insert: {
					id?: string;
					user_id: string;
					tenant_id: string;
					provider: string;
					provider_subscription_id: string;
					status: string;
					extra_agents?: number;
					current_period_start?: string | null;
					current_period_end?: string | null;
					cancel_at_period_end?: boolean;
					created_at?: string;
					updated_at?: string;
				};
				Update: {
					id?: string;
					user_id?: string;
					tenant_id?: string;
					provider?: string;
					provider_subscription_id?: string;
					status?: string;
					extra_agents?: number;
					current_period_start?: string | null;
					current_period_end?: string | null;
					cancel_at_period_end?: boolean;
					created_at?: string;
					updated_at?: string;
					lemon_subscription_id?: string | null;
					lemon_customer_id?: string | null;
					lemon_order_id?: string | null;
					lemon_product_id?: string | null;
					lemon_variant_id?: string | null;
					plan_type?: "monthly" | "yearly" | null;
					seats?: number;
					total_seats?: number;
					trial_ends_at?: string | null;
					referral_code_used?: string | null;
					cancelled_at?: string | null;
				};
			};
			seat_usage: {
				Row: {
					included_agents: number;
					extra_agents: number;
					allowed_agents: number;
					current_agents: number;
					tenant_id: string;
					/** Retired agents (20261014120100); they hold no seat. */
					retired_agents: number;
				};
				Insert: {
					included_agents?: number;
					extra_agents?: number;
					allowed_agents?: number;
					current_agents?: number;
					subscription_status?: string;
				};
				Update: {
					included_agents?: number;
					extra_agents?: number;
					allowed_agents?: number;
					current_agents?: number;
					subscription_status?: string;
				};
			};
			referral_credits: {
				Row: {
					id: string;
					referrer_id: string;
					referred_user_id: string | null;
					lemon_subscription_id: string | null;
					credit_months: number;
					status: "active" | "used" | "expired";
					applied_to_subscription_id: string | null;
					created_at: string;
					expires_at: string | null;
				};
				Insert: {
					id?: string;
					referrer_id: string;
					referred_user_id?: string | null;
					lemon_subscription_id?: string | null;
					credit_months?: number;
					status?: "active" | "used" | "expired";
					applied_to_subscription_id?: string | null;
					created_at?: string;
					expires_at?: string | null;
				};
				Update: {
					id?: string;
					referrer_id?: string;
					referred_user_id?: string | null;
					lemon_subscription_id?: string | null;
					credit_months?: number;
					status?: "active" | "used" | "expired";
					applied_to_subscription_id?: string | null;
					created_at?: string;
					expires_at?: string | null;
				};
			};
			invoices: {
				Row: {
					id: string;
					user_id: string;
					subscription_id: string | null;
					lemon_order_id: string | null;
					lemon_invoice_id: string | null;
					amount: number;
					currency: string;
					status: "paid" | "pending" | "refunded";
					invoice_url: string | null;
					created_at: string;
				};
				Insert: {
					id?: string;
					user_id: string;
					subscription_id?: string | null;
					lemon_order_id?: string | null;
					lemon_invoice_id?: string | null;
					amount: number;
					currency?: string;
					status?: "paid" | "pending" | "refunded";
					invoice_url?: string | null;
					created_at?: string;
				};
				Update: {
					id?: string;
					user_id?: string;
					subscription_id?: string | null;
					lemon_order_id?: string | null;
					lemon_invoice_id?: string | null;
					amount?: number;
					currency?: string;
					status?: "paid" | "pending" | "refunded";
					invoice_url?: string | null;
					created_at?: string;
				};
			};
			users: {
				Row: {
					id: string;
					email: string;
					referral_code: string;
					created_at: string;
				};
				Insert: {
					id?: string;
					email: string;
					referral_code?: string;
					created_at?: string;
				};
				Update: {
					id?: string;
					email?: string;
					referral_code?: string;
					created_at?: string;
				};
			};
			referrals: {
				Row: {
					id: string;
					referrer_id: string;
					invited_email: string;
					status: "pending" | "converted" | "expired";
					credits_earned: number;
					created_at: string;
					converted_at: string | null;
				};
				Insert: {
					id?: string;
					referrer_id: string;
					invited_email: string;
					status?: "pending" | "converted" | "expired";
					credits_earned?: number;
					created_at?: string;
					converted_at?: string | null;
				};
				Update: {
					id?: string;
					referrer_id?: string;
					invited_email?: string;
					status?: "pending" | "converted" | "expired";
					credits_earned?: number;
					created_at?: string;
					converted_at?: string | null;
				};
			};
			entitlements: {
				Row: {
					user_id: string;
					tenant_id: string;
					included_agents: number;
					extra_agents: number;
					plan: "free" | "pro";
					updated_at: string;
				};
				Insert: {
					user_id: string;
					tenant_id: string;
					included_agents?: number;
					extra_agents?: number;
					plan?: "free" | "pro";
					updated_at?: string;
				};
				Update: {
					user_id?: string;
					tenant_id?: string;
					included_agents?: number;
					extra_agents?: number;
					plan?: "free" | "pro";
					updated_at?: string;
				};
			};
			agent_retirement_settings: {
				Row: {
					tenant_id: string;
					auto_retire_offline_days: number | null;
					updated_at: string;
				};
				Insert: never;
				Update: never;
			};
			agents: {
				Row: {
					id: string;
					user_id: string;
					tenant_id: string;
					iid: string;
					agent_runtime: string | null;
					agent_runtime_version: string | null;
					display_name: string | null;
					first_seen: string;
					last_seen: string;
					/** Set only by retire_agent / retire_offline_agents (20261014120100). */
					retired_at: string | null;
					retired_reason: "manual" | "offline" | null;
				};
				Insert: {
					id?: string;
					user_id: string;
					tenant_id: string;
					iid: string;
					agent_runtime?: string | null;
					agent_runtime_version?: string | null;
					display_name?: string | null;
					first_seen?: string;
					last_seen?: string;
				};
				Update: {
					id?: string;
					user_id?: string;
					tenant_id?: string;
					iid?: string;
					agent_runtime?: string | null;
					agent_runtime_version?: string | null;
					display_name?: string | null;
					first_seen?: string;
					last_seen?: string;
				};
			};
			/** Latest protection state per agent and connector (20261014000205); read-only for members. */
			connector_heartbeats: {
				Row: {
					tenant_id: string;
					agent_id: string;
					connector: string;
					state: "protected" | "hook_missing" | "hook_disabled" | "hook_untrusted" | "hook_broken";
					enforcement: "machine_policy" | "user_config" | "none";
					protection_locked: boolean;
					disable_attempts: number;
					host_version: string | null;
					reported_at: string;
					state_since: string;
				};
				Insert: never;
				Update: never;
			};
			events: {
				Row: {
					id: number;
					user_id: string;
					tenant_id: string;
					agent_id: string;
					event_id: string;
					type: string;
					created_at: string;
					payload: Record<string, unknown>;
				};
				Insert: {
					id?: number;
					user_id: string;
					tenant_id: string;
					agent_id: string;
					event_id: string;
					type: string;
					created_at?: string;
					payload: Record<string, unknown>;
				};
				Update: {
					id?: number;
					user_id?: string;
					tenant_id?: string;
					agent_id?: string;
					event_id?: string;
					type?: string;
					created_at?: string;
					payload?: Record<string, unknown>;
				};
			};
			entitlement_snapshots: {
				Row: {
					user_id: string;
					tenant_id: string;
					iid: string;
					agent_id: string | null;
					entitlement: Record<string, unknown>;
					sig_alg: string | null;
					sig_key_id: string | null;
					sig_b64: string | null;
					issued_at: string | null;
					expires_at: string | null;
					grace_until: string | null;
					created_at: string;
					updated_at: string;
				};
				Insert: {
					user_id: string;
					tenant_id: string;
					iid: string;
					agent_id?: string | null;
					entitlement: Record<string, unknown>;
					sig_alg?: string | null;
					sig_key_id?: string | null;
					sig_b64?: string | null;
					issued_at?: string | null;
					expires_at?: string | null;
					grace_until?: string | null;
					created_at?: string;
					updated_at?: string;
				};
				Update: {
					user_id?: string;
					tenant_id?: string;
					iid?: string;
					agent_id?: string | null;
					entitlement?: Record<string, unknown>;
					sig_alg?: string | null;
					sig_key_id?: string | null;
					sig_b64?: string | null;
					issued_at?: string | null;
					expires_at?: string | null;
					grace_until?: string | null;
					created_at?: string;
					updated_at?: string;
				};
			};
			audit_logs: {
				Row: {
					id: string;
					team_id: string;
					tenant_id: string;
					user_id: string | null;
					user_email: string | null;
					action: string;
					verdict: Record<string, unknown> | null;
					timestamp: number;
					created_at: string;
				};
				Insert: {
					id?: string;
					team_id: string;
					tenant_id: string;
					user_id?: string | null;
					user_email?: string | null;
					action: string;
					verdict?: Record<string, unknown> | null;
					timestamp?: number;
					created_at?: string;
				};
				Update: {
					id?: string;
					team_id?: string;
					tenant_id?: string;
					user_id?: string | null;
					user_email?: string | null;
					action?: string;
					verdict?: Record<string, unknown> | null;
					timestamp?: number;
					created_at?: string;
				};
			};
			credential_shares: {
				Row: {
					id: string;
					owner_id: string;
					shared_with_email: string;
					status: "pending" | "accepted" | "revoked";
					created_at: string;
				};
				Insert: {
					id?: string;
					owner_id: string;
					shared_with_email: string;
					status?: "pending" | "accepted" | "revoked";
					created_at?: string;
				};
				Update: {
					id?: string;
					owner_id?: string;
					shared_with_email?: string;
					status?: "pending" | "accepted" | "revoked";
					created_at?: string;
				};
			};
			agent_sync: {
				Row: {
					id: string;
					agent_id: string;
					user_id: string;
					config: Record<string, unknown>;
					last_synced_at: string;
				};
				Insert: {
					id?: string;
					agent_id: string;
					user_id: string;
					config?: Record<string, unknown>;
					last_synced_at?: string;
				};
				Update: {
					id?: string;
					agent_id?: string;
					user_id?: string;
					config?: Record<string, unknown>;
					last_synced_at?: string;
				};
			};
			teams: {
				Row: {
					id: string;
					tenant_id: string;
					name: string;
					github_org: string | null;
					gitlab_group: string | null;
					plan: "free" | "pro" | "team" | "business" | "enterprise";
					created_at: string;
					updated_at: string;
				};
				Insert: {
					id?: string;
					tenant_id: string;
					name: string;
					github_org?: string | null;
					gitlab_group?: string | null;
					plan?: "free" | "pro" | "team" | "business" | "enterprise";
					created_at?: string;
					updated_at?: string;
				};
				Update: {
					id?: string;
					tenant_id?: string;
					name?: string;
					github_org?: string | null;
					gitlab_group?: string | null;
					plan?: "free" | "pro" | "team" | "business" | "enterprise";
					created_at?: string;
					updated_at?: string;
				};
			};
			team_members: {
				Row: {
					id: string;
					team_id: string;
					tenant_id: string;
					user_id: string;
					role: "owner" | "admin" | "member" | "viewer" | "auditor";
					invited_by: string | null;
					joined_at: string;
					created_at: string;
				};
				Insert: {
					id?: string;
					team_id: string;
					tenant_id: string;
					user_id: string;
					role?: "owner" | "admin" | "member" | "viewer" | "auditor";
					invited_by?: string | null;
					joined_at?: string;
					created_at?: string;
				};
				Update: {
					id?: string;
					team_id?: string;
					tenant_id?: string;
					user_id?: string;
					role?: "owner" | "admin" | "member" | "viewer" | "auditor";
					invited_by?: string | null;
					joined_at?: string;
					created_at?: string;
				};
				Relationships: [
					{
						foreignKeyName: "team_members_team_id_fkey";
						columns: ["team_id"];
						isOneToOne: false;
						referencedRelation: "teams";
						referencedColumns: ["id"];
					},
					{
						foreignKeyName: "team_members_user_id_fkey";
						columns: ["user_id"];
						isOneToOne: false;
						referencedRelation: "users";
						referencedColumns: ["id"];
					},
					{
						foreignKeyName: "team_members_invited_by_fkey";
						columns: ["invited_by"];
						isOneToOne: false;
						referencedRelation: "users";
						referencedColumns: ["id"];
					},
				];
			};
			team_policies: {
				Row: {
					id: string;
					team_id: string;
					tenant_id: string;
					content: string;
					updated_at: string;
					updated_by: string | null;
				};
				Insert: {
					id?: string;
					team_id: string;
					tenant_id: string;
					content: string;
					updated_at?: string;
					updated_by?: string | null;
				};
				Update: {
					id?: string;
					team_id?: string;
					tenant_id?: string;
					content?: string;
					updated_at?: string;
					updated_by?: string | null;
				};
			};
			// Read-only for the browser: rows are written only by the ingest projection.
			posture_findings: {
				Row: {
					id: number;
					tenant_id: string;
					event_row_id: number;
					agent_id: string;
					source: "infra_scan" | "mcp_inventory" | "skill_scan" | "agent_environment";
					finding_kind:
						| "cve"
						| "advisory"
						| "exposed_component"
						| "mcp_server"
						| "skill_rule"
						| "agent_config";
					severity: "critical" | "high" | "medium" | "low" | "info" | "unknown";
					cvss: number | string | null;
					vuln_id: string | null;
					component: string | null;
					component_version: string | null;
					applicability: "confirmed" | "unconfirmed" | null;
					target_digest: string | null;
					mcp_server_name: string | null;
					mcp_transport: "remote" | "stdio" | null;
					risk_categories: string[];
					attestation_status: string | null;
					subject_digest: string | null;
					plugin_key: string | null;
					rule_id: string | null;
					skill_risk_type: string | null;
					scan_id: string | null;
					agent_host: string | null;
					check_id: string | null;
					finding_count: number | null;
					observed_at: string;
					created_at: string;
				};
				Insert: Record<string, never>;
				Update: Record<string, never>;
			};
			// Read-only for the browser (column grants exclude token material);
			// written only by the approval-requests Edge Function RPCs.
			approval_requests: {
				Row: {
					id: string;
					tenant_id: string;
					iid: string;
					agent_id: string | null;
					agent_runtime: string | null;
					action_id: string;
					artifact_digest: string;
					tool: string;
					threat_ids: string[];
					summary: string;
					status: "pending" | "approved" | "denied" | "expired";
					decided_by: string | null;
					decided_at: string | null;
					reason: string | null;
					key_id: string | null;
					token_expires_at: string | null;
					token_delivered_at: string | null;
					expires_at: string;
					created_at: string;
				};
				Insert: Record<string, never>;
				Update: Record<string, never>;
			};
			// AI governance (docs/ai-governance.md). Read-only for the browser; every
			// write is an ai-governance Edge Function RPC.
			tenant_ai_governance_settings: {
				Row: {
					tenant_id: string;
					policy_four_eyes: boolean;
					default_review_days: number;
					/** Browser Guard: native NER required (signed browser-guard-policy document). */
					browser_guard_require_native_ner: boolean;
					updated_by: string | null;
					updated_at: string;
				};
				Insert: Record<string, never>;
				Update: Record<string, never>;
			};
			ai_governance_reviewers: {
				Row: { tenant_id: string; user_id: string; designated_by: string; designated_at: string };
				Insert: Record<string, never>;
				Update: Record<string, never>;
			};
			ai_assets: {
				Row: {
					id: string;
					tenant_id: string;
					asset_type: "coding_agent" | "mcp_server" | "ai_site" | "model_service";
					identifier: string;
					name: string;
					vendor: string | null;
					owner_user_id: string | null;
					business_purpose: string | null;
					data_categories: string[];
					risk_tier: "unassessed" | "minimal" | "limited" | "high" | "prohibited";
					risk_score: number | null;
					status: "proposed" | "approved" | "restricted" | "banned" | "retired";
					review_due_at: string | null;
					last_reviewed_at: string | null;
					last_reviewed_by: string | null;
					source: string;
					first_observed_at: string | null;
					last_observed_at: string | null;
					version: number;
					created_by: string | null;
					created_at: string;
					updated_by: string | null;
					updated_at: string;
				};
				Insert: Record<string, never>;
				Update: Record<string, never>;
			};
			ai_asset_evidence: {
				Row: {
					id: string;
					tenant_id: string;
					asset_id: string;
					evidence_kind: "posture_finding" | "incident" | "approval_request";
					evidence_ref: string;
					label: string;
					observed_at: string | null;
					linked_by: string;
					linked_at: string;
				};
				Insert: Record<string, never>;
				Update: Record<string, never>;
			};
			ai_intake_requests: {
				Row: {
					id: string;
					tenant_id: string;
					asset_id: string | null;
					asset_type: "coding_agent" | "mcp_server" | "ai_site" | "model_service";
					identifier: string;
					name: string;
					vendor: string | null;
					business_purpose: string;
					data_categories: string[];
					requested_status: "approved" | "restricted";
					status: "pending" | "approved" | "rejected" | "cancelled" | "expired";
					requested_by: string;
					created_at: string;
					expires_at: string;
					decided_by: string | null;
					decided_at: string | null;
					decision_reason: string | null;
					closed_at: string | null;
					resulting_asset_id: string | null;
				};
				Insert: Record<string, never>;
				Update: Record<string, never>;
			};
			ai_governance_exceptions: {
				Row: {
					id: string;
					tenant_id: string;
					asset_id: string;
					scope_kind: "tenant" | "members" | "agents";
					scope_user_ids: string[];
					scope_agent_ids: string[];
					justification: string;
					status: "pending" | "approved" | "rejected" | "cancelled" | "revoked" | "expired";
					requested_by: string;
					created_at: string;
					expires_at: string;
					starts_at: string | null;
					decided_by: string | null;
					decided_at: string | null;
					decision_reason: string | null;
					revoked_by: string | null;
					revoked_at: string | null;
					revoke_reason: string | null;
					closed_at: string | null;
				};
				Insert: Record<string, never>;
				Update: Record<string, never>;
			};
			// Column grants exclude `payload` (DLP payloads carry sensitive matchers).
			policy_change_requests: {
				Row: {
					id: string;
					tenant_id: string;
					change_kind: string;
					base_version: number;
					expected_revision_version: number | null;
					target_version: number | null;
					payload_sha256: string;
					summary: Record<string, number>;
					status:
						| "pending"
						| "approved"
						| "rejected"
						| "cancelled"
						| "superseded"
						| "failed"
						| "expired";
					requested_by: string;
					created_at: string;
					expires_at: string;
					decided_by: string | null;
					decided_at: string | null;
					decision_reason: string | null;
					closed_at: string | null;
					applied_version: number | null;
					outcome_code: string | null;
				};
				Insert: Record<string, never>;
				Update: Record<string, never>;
			};
		}>;
		Views: AddRelationships<{
			user_subscription_summary: {
				Row: {
					user_id: string;
					email: string;
					active_subscriptions: number;
					total_paid_seats: number;
					referral_credits_earned: number;
					next_billing_date: string | null;
				};
			};
			referral_stats: {
				Row: {
					user_id: string;
					referral_code: string;
					active_referrals: number;
					total_referrals: number;
					free_months_earned: number;
				};
			};
			incident_events: {
				Row: {
					id: number;
					user_id: string;
					tenant_id: string;
					agent_id: string;
					type: string;
					created_at: string;
					payload: Record<string, unknown>;
				};
			};
		}>;
		Functions: {
			/** License banner and pending import (20261014120200). */
			tenant_license_status: {
				Args: { p_tenant_id: string };
				Returns: Record<string, unknown>;
			};
			/** Usage report facts for owners/admins (20261014120200). */
			tenant_usage_report: {
				Args: { p_tenant_id: string };
				Returns: Record<string, unknown>;
			};
			list_team_members_with_email: {
				Args: { p_team_id: string };
				Returns: Array<{
					id: string;
					user_id: string;
					role: string;
					email: string | null;
					avatar_url: string | null;
					invited_by: string | null;
					joined_at: string;
				}>;
			};
			create_team_tenant: {
				Args: {
					p_name: string;
					p_request_id: string;
					p_plan?: string;
				};
				Returns: Database["public"]["Tables"]["teams"]["Row"];
			};
			billing_checkout: {
				Args: Record<string, never>;
				Returns: { url: string };
			};
			/** Browser Guard privacy telemetry aggregates (migration 20260925000001). */
			privacy_guard_summary: {
				Args: { p_tenant_id: string; p_days: number };
				Returns: Record<string, unknown>;
			};
			/** Browser Guard Shadow AI aggregates (20260926000010). */
			shadow_ai_summary: {
				Args: { p_tenant_id: string; p_days: number };
				Returns: Record<string, unknown>;
			};
			/** Owner/admin AI governance scorecard, counts only (20260927000060). */
			governance_scorecard: {
				Args: { p_tenant_id: string; p_days: number };
				Returns: unknown;
			};
			/** Owner/admin governance summary schedule and oversight thresholds (20260927000060). */
			set_governance_settings: {
				Args: {
					p_tenant_id: string;
					p_digest_enabled: boolean;
					p_digest_cadence: string;
					p_digest_recipients: string;
					p_oversight_fast_seconds: number;
					p_oversight_min_decisions: number;
					p_oversight_fast_share: number;
				};
				Returns: unknown;
			};
			/** Member-only plan/admission/usage projection (20260925000012). */
			get_tenant_plan: {
				Args: { p_tenant_id: string };
				Returns: unknown;
			};
			get_tenant_plan_entitlements: {
				Args: { p_tenant_id: string };
				Returns: unknown;
			};
			get_approval_settings: {
				Args: { p_tenant_id: string };
				Returns: unknown;
			};
			list_tenant_admin_audit_logs: {
				Args: {
					p_tenant_id: string;
					p_limit?: number;
					p_before_created_at?: string;
					p_before_id?: number;
				};
				Returns: unknown;
			};
		};
	};
}
