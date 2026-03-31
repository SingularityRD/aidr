import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

interface GoogleUserInfo {
  id: string;
  email: string;
  verified_email: boolean;
  name?: string;
  picture?: string;
  given_name?: string;
  family_name?: string;
}

serve(async (req) => {
  // Handle CORS preflight
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { code, state } = await req.json();
    
    if (!code) {
      return new Response(
        JSON.stringify({ error: "Authorization code required" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // Create Supabase admin client
    const supabaseAdmin = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
      { auth: { autoRefreshToken: false, persistSession: false } }
    );

    // Exchange code for tokens with Google
    const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code,
        client_id: Deno.env.get("GOOGLE_CLIENT_ID") ?? "",
        client_secret: Deno.env.get("GOOGLE_CLIENT_SECRET") ?? "",
        redirect_uri: `${Deno.env.get("SUPABASE_URL")}/auth/v1/callback`,
        grant_type: "authorization_code",
      }),
    });

    if (!tokenResponse.ok) {
      const error = await tokenResponse.text();
      console.error("Google token exchange failed:", error);
      return new Response(
        JSON.stringify({ error: "Failed to exchange authorization code" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const tokens = await tokenResponse.json();

    // Fetch user info from Google
    const userInfoResponse = await fetch(
      "https://www.googleapis.com/oauth2/v2/userinfo",
      { headers: { Authorization: `Bearer ${tokens.access_token}` } }
    );

    if (!userInfoResponse.ok) {
      const error = await userInfoResponse.text();
      console.error("Failed to fetch user info:", error);
      return new Response(
        JSON.stringify({ error: "Failed to fetch user information" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const googleUser: GoogleUserInfo = await userInfoResponse.json();

    // Check for existing user by Google ID
    const { data: existingUser } = await supabaseAdmin
      .from("users")
      .select("*")
      .eq("google_id", googleUser.id)
      .maybeSingle();

    let userId: string;
    let isNewUser = false;

    if (existingUser) {
      // Update existing user
      userId = existingUser.id;
      const { error: updateError } = await supabaseAdmin
        .from("users")
        .update({
          email: googleUser.email,
          updated_at: new Date().toISOString(),
        })
        .eq("id", userId);

      if (updateError) {
        console.error("Error updating user:", updateError);
        throw updateError;
      }
    } else {
      // Create new user
      isNewUser = true;
      const referralCode = generateReferralCode();
      
      // Check if there's a pending referral
      const pendingReferralCode = state ? JSON.parse(atob(state)).referralCode : null;

      const { data: newUser, error: insertError } = await supabaseAdmin
        .from("users")
        .insert({
          email: googleUser.email,
          google_id: googleUser.id,
          referral_code: referralCode,
          referred_by: pendingReferralCode || null,
        })
        .select()
        .single();

      if (insertError) {
        console.error("Error creating user:", insertError);
        throw insertError;
      }

      userId = newUser.id;

      // Process referral if exists
      if (pendingReferralCode) {
        await processReferral(supabaseAdmin, pendingReferralCode, googleUser.email);
      }

      // Create first free agent seat automatically
      await supabaseAdmin.from("agent_seats").insert({
        user_id: userId,
        agent_name: "My First Agent",
        agent_type: "claude",
        status: "active",
        tier: "free",
      });

      // Initialize free tier entitlements
      await supabaseAdmin.from("entitlements").insert({
        user_id: userId,
        included_agents: 1,
        extra_agents: 0,
        plan: "free",
      });
    }

    // Create Supabase auth session
    const { data: authData, error: authError } = await supabaseAdmin.auth.admin.createUser({
      email: googleUser.email,
      email_confirm: true,
      user_metadata: {
        provider_id: googleUser.id,
        full_name: googleUser.name,
        avatar_url: googleUser.picture,
        referral_code: isNewUser ? generateReferralCode() : existingUser?.referral_code,
      },
    });

    if (authError) {
      // User might already exist in auth, try to get session
      console.log("Auth user may exist, proceeding...");
    }

    // Generate session
    const { data: sessionData, error: sessionError } = await supabaseAdmin.auth.admin.signInUser({
      userId: userId,
    });

    if (sessionError) {
      console.error("Error creating session:", sessionError);
    }

    return new Response(
      JSON.stringify({
        success: true,
        userId,
        isNewUser,
        session: sessionData,
        message: isNewUser 
          ? "Welcome! Your free agent has been created." 
          : "Welcome back!",
      }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );

  } catch (error) {
    console.error("Auth callback error:", error);
    return new Response(
      JSON.stringify({ error: "Internal server error" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});

// Generate unique referral code
function generateReferralCode(): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let code = "";
  for (let i = 0; i < 12; i++) {
    code += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return code;
}

// Process referral conversion
async function processReferral(
  supabase: ReturnType<typeof createClient>,
  referralCode: string,
  newUserEmail: string
) {
  try {
    // Find referrer
    const { data: referrer } = await supabase
      .from("users")
      .select("id")
      .eq("referral_code", referralCode)
      .maybeSingle();

    if (!referrer) {
      console.warn("Referrer not found for code:", referralCode);
      return;
    }

    // Update referral record
    const { error: referralError } = await supabase
      .from("referrals")
      .update({
        status: "converted",
        credits_earned: 1,
        converted_at: new Date().toISOString(),
      })
      .eq("referrer_id", referrer.id)
      .eq("invited_email", newUserEmail);

    if (referralError) {
      console.error("Error updating referral:", referralError);
    }

    // Grant 1 month free Pro to referrer
    const { error: creditError } = await supabase
      .from("referral_credits")
      .insert({
        user_id: referrer.id,
        months_granted: 1,
        reason: `Referral: ${newUserEmail}`,
        expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
      });

    if (creditError) {
      console.error("Error granting referral credit:", creditError);
    }

    // Update referrer's entitlements temporarily
    const { data: entitlements } = await supabase
      .from("entitlements")
      .select("*")
      .eq("user_id", referrer.id)
      .maybeSingle();

    if (entitlements) {
      await supabase
        .from("entitlements")
        .update({
          plan: "pro",
          pro_expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
        })
        .eq("user_id", referrer.id);
    }

  } catch (error) {
    console.error("Error processing referral:", error);
  }
}
