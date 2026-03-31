// Database type definitions for Supabase
// Generated schema types for AIDR Dashboard

export interface Database {
	public: {
		Tables: {
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
					lemon_subscription_id: string | null;
					lemon_customer_id: string | null;
					lemon_order_id: string | null;
					lemon_product_id: string | null;
					lemon_variant_id: string | null;
					status: "active" | "cancelled" | "expired" | "paused" | "past_due";
					plan_type: "monthly" | "yearly" | null;
					seats: number;
					total_seats: number;
					current_period_start: string | null;
					current_period_end: string | null;
					trial_ends_at: string | null;
					referral_code_used: string | null;
					provider: "lemon_squeezy" | "stripe" | "iyzico" | "crypto";
					cancel_at_period_end: boolean;
					created_at: string;
					updated_at: string;
					cancelled_at: string | null;
				};
				Insert: {
					id?: string;
					user_id: string;
					lemon_subscription_id?: string | null;
					lemon_customer_id?: string | null;
					lemon_order_id?: string | null;
					lemon_product_id?: string | null;
					lemon_variant_id?: string | null;
					status?: "active" | "cancelled" | "expired" | "paused" | "past_due";
					plan_type?: "monthly" | "yearly" | null;
					seats?: number;
					total_seats?: number;
					current_period_start?: string | null;
					current_period_end?: string | null;
					trial_ends_at?: string | null;
					referral_code_used?: string | null;
					provider?: "lemon_squeezy" | "stripe" | "iyzico" | "crypto";
					cancel_at_period_end?: boolean;
					created_at?: string;
					updated_at?: string;
					cancelled_at?: string | null;
				};
				Update: {
					id?: string;
					user_id?: string;
					lemon_subscription_id?: string | null;
					lemon_customer_id?: string | null;
					lemon_order_id?: string | null;
					lemon_product_id?: string | null;
					lemon_variant_id?: string | null;
					status?: "active" | "cancelled" | "expired" | "paused" | "past_due";
					plan_type?: "monthly" | "yearly" | null;
					seats?: number;
					total_seats?: number;
					current_period_start?: string | null;
					current_period_end?: string | null;
					trial_ends_at?: string | null;
					referral_code_used?: string | null;
					provider?: "lemon_squeezy" | "stripe" | "iyzico" | "crypto";
					cancel_at_period_end?: boolean;
					created_at?: string;
					updated_at?: string;
					cancelled_at?: string | null;
				};
			};
			seat_usage: {
				Row: {
					included_agents: number;
					extra_agents: number;
					allowed_agents: number;
					current_agents: number;
					subscription_status: string;
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
					included_agents: number;
					extra_agents: number;
					plan: "free" | "pro";
					updated_at: string;
				};
				Insert: {
					user_id: string;
					included_agents?: number;
					extra_agents?: number;
					plan?: "free" | "pro";
					updated_at?: string;
				};
				Update: {
					user_id?: string;
					included_agents?: number;
					extra_agents?: number;
					plan?: "free" | "pro";
					updated_at?: string;
				};
			};
			agents: {
				Row: {
					id: string;
					user_id: string;
					name: string;
					last_seen_at: string;
					created_at: string;
				};
				Insert: {
					id?: string;
					user_id: string;
					name: string;
					last_seen_at?: string;
					created_at?: string;
				};
				Update: {
					id?: string;
					user_id?: string;
					name?: string;
					last_seen_at?: string;
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
					name: string;
					github_org: string | null;
					gitlab_group: string | null;
					plan: "free" | "pro" | "enterprise";
					created_at: string;
					updated_at: string;
				};
				Insert: {
					id?: string;
					name: string;
					github_org?: string | null;
					gitlab_group?: string | null;
					plan?: "free" | "pro" | "enterprise";
					created_at?: string;
					updated_at?: string;
				};
				Update: {
					id?: string;
					name?: string;
					github_org?: string | null;
					gitlab_group?: string | null;
					plan?: "free" | "pro" | "enterprise";
					created_at?: string;
					updated_at?: string;
				};
			};
			team_members: {
				Row: {
					id: string;
					team_id: string;
					user_id: string;
					role: "owner" | "admin" | "member";
					created_at: string;
				};
				Insert: {
					id?: string;
					team_id: string;
					user_id: string;
					role?: "owner" | "admin" | "member";
					created_at?: string;
				};
				Update: {
					id?: string;
					team_id?: string;
					user_id?: string;
					role?: "owner" | "admin" | "member";
					created_at?: string;
				};
			};
			team_policies: {
				Row: {
					id: string;
					team_id: string;
					content: string;
					updated_at: string;
					updated_by: string | null;
				};
				Insert: {
					id?: string;
					team_id: string;
					content: string;
					updated_at?: string;
					updated_by?: string | null;
				};
				Update: {
					id?: string;
					team_id?: string;
					content?: string;
					updated_at?: string;
					updated_by?: string | null;
				};
			};
		};
		Views: {
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
		};
		Functions: {
			billing_checkout: {
				Args: Record<string, never>;
				Returns: { url: string };
			};
		};
	};
}

// Helper type for typed Supabase client
export type TypedSupabaseClient = import("@supabase/supabase-js").SupabaseClient<Database>;
