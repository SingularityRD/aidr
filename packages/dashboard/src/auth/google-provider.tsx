import { createContext, type ReactNode, useCallback, useContext, useEffect, useState } from "react";
import { supabase } from "../lib/supabase";

// Types
interface User {
	id: string;
	email: string;
	googleId?: string;
	githubId?: string;
	referralCode: string;
	createdAt: string;
}

interface GoogleCredential {
	id: string;
	email: string;
	name?: string;
	picture?: string;
	familyName?: string;
	givenName?: string;
}

interface CredentialShare {
	id: string;
	ownerId: string;
	sharedWithEmail: string;
	status: "pending" | "accepted" | "revoked";
	createdAt: string;
}

interface AgentSync {
	agentId: string;
	userId: string;
	config: Record<string, unknown>;
	lastSyncedAt: string;
}

interface GoogleAuthContextType {
	user: User | null;
	isLoading: boolean;
	signInWithGoogle: () => Promise<void>;
	signInWithOneTap: () => Promise<void>;
	signOut: () => Promise<void>;
	shareCredential: (email: string) => Promise<void>;
	sharedCredentials: CredentialShare[];
	syncAgentConfig: (agentId: string, config: Record<string, unknown>) => Promise<void>;
	getSyncedAgents: () => Promise<AgentSync[]>;
	generateReferralLink: () => string;
}

const GoogleAuthContext = createContext<GoogleAuthContextType | null>(null);

export function useGoogleAuth() {
	const ctx = useContext(GoogleAuthContext);
	if (!ctx) throw new Error("useGoogleAuth must be used within GoogleAuthProvider");
	return ctx;
}

interface GoogleAuthProviderProps {
	children: ReactNode;
	clientId?: string;
}

export function GoogleAuthProvider({ children, clientId }: GoogleAuthProviderProps) {
	const [user, setUser] = useState<User | null>(null);
	const [isLoading, setIsLoading] = useState(true);
	const [sharedCredentials, setSharedCredentials] = useState<CredentialShare[]>([]);

	// Load user on mount
	useEffect(() => {
		let cancelled = false;

		async function loadUser() {
			const {
				data: { session },
			} = await supabase.auth.getSession();

			if (session?.user && !cancelled) {
				const userData: User = {
					id: session.user.id,
					email: session.user.email!,
					googleId: session.user.user_metadata?.provider_id,
					githubId: session.user.user_metadata?.github_id,
					referralCode: generateReferralCode(session.user.id),
					createdAt: session.user.created_at,
				};
				setUser(userData);
				await loadSharedCredentials(session.user.id);
			}

			if (!cancelled) setIsLoading(false);
		}

		loadUser();

		// Subscribe to auth changes
		const {
			data: { subscription },
		} = supabase.auth.onAuthStateChange(async (event, session) => {
			if (event === "SIGNED_IN" && session?.user) {
				const userData: User = {
					id: session.user.id,
					email: session.user.email!,
					googleId: session.user.user_metadata?.provider_id,
					githubId: session.user.user_metadata?.github_id,
					referralCode: generateReferralCode(session.user.id),
					createdAt: session.user.created_at,
				};
				setUser(userData);
				await loadSharedCredentials(session.user.id);
			} else if (event === "SIGNED_OUT") {
				setUser(null);
				setSharedCredentials([]);
			}
		});

		return () => {
			cancelled = true;
			subscription.unsubscribe();
		};
	}, []);

	// Load credential shares
	async function loadSharedCredentials(userId: string) {
		const { data } = await supabase.from("credential_shares").select("*").eq("owner_id", userId);

		if (data) {
			setSharedCredentials(data as CredentialShare[]);
		}
	}

	// Generate referral code from user ID
	function generateReferralCode(userId: string): string {
		return btoa(userId)
			.replace(/[^a-zA-Z0-9]/g, "")
			.slice(0, 12)
			.toLowerCase();
	}

	// Generate referral link
	const generateReferralLink = useCallback((): string => {
		if (!user) return "";
		const baseUrl = window.location.origin;
		return `${baseUrl}/signup?ref=${user.referralCode}`;
	}, [user]);

	// Standard Google OAuth 2.0 flow
	const signInWithGoogle = useCallback(async () => {
		setIsLoading(true);

		const redirectTo = `${window.location.origin}/auth/callback`;

		const { error } = await supabase.auth.signInWithOAuth({
			provider: "google",
			options: {
				redirectTo,
				queryParams: {
					access_type: "offline",
					prompt: "consent",
				},
			},
		});

		if (error) {
			console.error("Google sign-in error:", error);
			setIsLoading(false);
			throw error;
		}
	}, []);

	// Google One-tap sign-in for new users
	const signInWithOneTap = useCallback(async () => {
		if (!clientId) {
			throw new Error("Google Client ID required for One-tap sign-in");
		}

		// Load Google Identity Services script
		await loadGoogleScript();

		return new Promise<void>((resolve, reject) => {
			// @ts-expect-error - Google Identity Services types
			google.accounts.id.initialize({
				client_id: clientId,
				callback: async (response: { credential: string }) => {
					try {
						// Send ID token to Supabase
						const { error } = await supabase.auth.signInWithIdToken({
							provider: "google",
							token: response.credential,
						});

						if (error) throw error;
						resolve();
					} catch (err) {
						reject(err);
					}
				},
				auto_select: true,
				cancel_on_tap_outside: false,
			});

			// @ts-expect-error - Google Identity Services types
			google.accounts.id.prompt((notification: unknown) => {
				// Handle notification
				console.log("One-tap notification:", notification);
			});
		});
	}, [clientId]);

	// Share credentials with family/team member
	const shareCredential = useCallback(
		async (email: string) => {
			if (!user) throw new Error("Must be signed in to share credentials");

			const { error } = await supabase.from("credential_shares").insert({
				owner_id: user.id,
				shared_with_email: email,
				status: "pending",
			});

			if (error) throw error;

			// Reload shared credentials
			await loadSharedCredentials(user.id);
		},
		[user],
	);

	// Sync agent configuration across devices
	const syncAgentConfig = useCallback(
		async (agentId: string, config: Record<string, unknown>) => {
			if (!user) throw new Error("Must be signed in to sync");

			const { error } = await supabase.from("agent_sync").upsert(
				{
					agent_id: agentId,
					user_id: user.id,
					config,
					last_synced_at: new Date().toISOString(),
				},
				{
					onConflict: "agent_id,user_id",
				},
			);

			if (error) throw error;
		},
		[user],
	);

	// Get synced agents
	const getSyncedAgents = useCallback(async (): Promise<AgentSync[]> => {
		if (!user) return [];

		const { data, error } = await supabase.from("agent_sync").select("*").eq("user_id", user.id);

		if (error) throw error;

		return (data || []).map((row) => ({
			agentId: row.agent_id,
			userId: row.user_id,
			config: row.config,
			lastSyncedAt: row.last_synced_at,
		}));
	}, [user]);

	// Sign out
	const signOut = useCallback(async () => {
		setIsLoading(true);
		await supabase.auth.signOut();
		setUser(null);
		setSharedCredentials([]);
		setIsLoading(false);
	}, []);

	const value: GoogleAuthContextType = {
		user,
		isLoading,
		signInWithGoogle,
		signInWithOneTap,
		signOut,
		shareCredential,
		sharedCredentials,
		syncAgentConfig,
		getSyncedAgents,
		generateReferralLink,
	};

	return <GoogleAuthContext.Provider value={value}>{children}</GoogleAuthContext.Provider>;
}

// Load Google Identity Services script
function loadGoogleScript(): Promise<void> {
	return new Promise((resolve, reject) => {
		if (document.getElementById("google-identity-script")) {
			resolve();
			return;
		}

		const script = document.createElement("script");
		script.id = "google-identity-script";
		script.src = "https://accounts.google.com/gsi/client";
		script.async = true;
		script.defer = true;
		script.onload = () => resolve();
		script.onerror = () => reject(new Error("Failed to load Google Identity Services"));
		document.head.appendChild(script);
	});
}
