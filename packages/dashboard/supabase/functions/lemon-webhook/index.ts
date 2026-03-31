// Lemon Squeezy webhook handler
// Supabase Edge Function

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.39.7';

const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
const supabaseServiceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;

// CORS headers
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Signature',
};

Deno.serve(async (req) => {
  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  // Only accept POST requests
  if (req.method !== 'POST') {
    return new Response('Method not allowed', { status: 405, headers: corsHeaders });
  }

  const supabase = createClient(supabaseUrl, supabaseServiceKey);

  try {
    const payload = await req.json();
    const event = payload.meta?.event_name;
    const signature = req.headers.get('X-Signature');
    
    // Optional: Verify webhook signature
    const webhookSecret = Deno.env.get('LEMON_SQUEEZY_WEBHOOK_SECRET');
    if (webhookSecret && signature) {
      // Implement signature verification if needed
      // Lemon Squeezy uses HMAC-SHA256 for webhook signing
    }
    
    console.log(`[Lemon Webhook] Event: ${event}`);
    
    switch (event) {
      case 'subscription_created':
        await handleSubscriptionCreated(supabase, payload.data);
        break;
        
      case 'subscription_updated':
        await handleSubscriptionUpdated(supabase, payload.data);
        break;
        
      case 'subscription_cancelled':
        await handleSubscriptionCancelled(supabase, payload.data);
        break;
        
      case 'order_created':
        // One-time purchase (initial seat or upgrade)
        await handleOrderCreated(supabase, payload.data);
        break;
        
      case 'subscription_resumed':
        await handleSubscriptionResumed(supabase, payload.data);
        break;
        
      case 'subscription_expired':
        await handleSubscriptionExpired(supabase, payload.data);
        break;
    }
    
    return new Response('OK', { headers: corsHeaders });
  } catch (error) {
    console.error('[Lemon Webhook] Error:', error);
    return new Response(
      JSON.stringify({ error: 'Webhook processing failed', details: error.message }), 
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  }
});

async function handleSubscriptionCreated(supabase: any, data: any) {
  const customData = data.attributes?.checkout_data?.custom || {};
  const userId = customData.user_id;
  const seats = parseInt(customData.seats) || 1;
  const referralCode = customData.referral_code;
  
  if (!userId) {
    console.error('[Lemon Webhook] Missing user_id in subscription_created');
    return;
  }
  
  const variantId = data.attributes?.variant_id;
  const planType = variantId === Deno.env.get('LEMON_SQUEEZY_VARIANT_MONTHLY') ? 'monthly' : 'yearly';
  
  // Database'de subscription oluştur
  const { error: subError } = await supabase
    .from('subscriptions')
    .insert({
      user_id: userId,
      lemon_subscription_id: data.id,
      lemon_customer_id: data.attributes.customer_id,
      lemon_order_id: data.attributes.order_id,
      lemon_product_id: data.attributes.product_id,
      lemon_variant_id: data.attributes.variant_id,
      seats: seats,
      total_seats: seats,
      status: 'active',
      plan_type: planType,
      current_period_start: data.attributes.created_at,
      current_period_end: data.attributes.renews_at,
      referral_code_used: referralCode || null
    });
    
  if (subError) {
    console.error('[Lemon Webhook] Subscription insert error:', subError);
  } else {
    console.log(`[Lemon Webhook] Subscription created for user ${userId}`);
  }
  
  // Eğer referral code varsa, referrer'a credit ekle
  if (referralCode) {
    await addReferralCredit(supabase, referralCode, userId);
  }
  
  // Entitlements tablosunu güncelle
  await updateEntitlements(supabase, userId, seats);
}

async function handleSubscriptionUpdated(supabase: any, data: any) {
  const variantId = data.attributes?.variant_id;
  const planType = variantId === Deno.env.get('LEMON_SQUEEZY_VARIANT_MONTHLY') ? 'monthly' : 'yearly';
  
  // Seat upgrade/downgrade handling
  const { error } = await supabase
    .from('subscriptions')
    .update({
      status: data.attributes.status,
      seats: data.attributes.quantity || 1,
      current_period_end: data.attributes.renews_at,
      plan_type: planType,
      updated_at: new Date().toISOString()
    })
    .eq('lemon_subscription_id', data.id);
    
  if (error) {
    console.error('[Lemon Webhook] Subscription update error:', error);
  } else {
    // Entitlements'i güncelle
    const { data: sub } = await supabase
      .from('subscriptions')
      .select('user_id, seats')
      .eq('lemon_subscription_id', data.id)
      .single();
      
    if (sub) {
      await updateEntitlements(supabase, sub.user_id, sub.seats);
    }
    
    console.log(`[Lemon Webhook] Subscription updated: ${data.id}`);
  }
}

async function handleSubscriptionCancelled(supabase: any, data: any) {
  const { error } = await supabase
    .from('subscriptions')
    .update({
      status: 'cancelled',
      cancelled_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    })
    .eq('lemon_subscription_id', data.id);
    
  if (error) {
    console.error('[Lemon Webhook] Subscription cancellation error:', error);
  } else {
    console.log(`[Lemon Webhook] Subscription cancelled: ${data.id}`);
  }
}

async function handleSubscriptionResumed(supabase: any, data: any) {
  const { error } = await supabase
    .from('subscriptions')
    .update({
      status: 'active',
      cancelled_at: null,
      updated_at: new Date().toISOString()
    })
    .eq('lemon_subscription_id', data.id);
    
  if (error) {
    console.error('[Lemon Webhook] Subscription resume error:', error);
  } else {
    console.log(`[Lemon Webhook] Subscription resumed: ${data.id}`);
  }
}

async function handleSubscriptionExpired(supabase: any, data: any) {
  const { error } = await supabase
    .from('subscriptions')
    .update({
      status: 'expired',
      updated_at: new Date().toISOString()
    })
    .eq('lemon_subscription_id', data.id);
    
  if (error) {
    console.error('[Lemon Webhook] Subscription expiration error:', error);
  } else {
    console.log(`[Lemon Webhook] Subscription expired: ${data.id}`);
  }
}

async function handleOrderCreated(supabase: any, data: any) {
  const customData = data.attributes?.checkout_data?.custom || {};
  const userId = customData.user_id;
  
  if (!userId) {
    console.error('[Lemon Webhook] Missing user_id in order_created');
    return;
  }
  
  // Invoice kaydı oluştur
  const { error } = await supabase
    .from('invoices')
    .insert({
      user_id: userId,
      lemon_order_id: data.id,
      lemon_invoice_id: data.attributes?.first_order_item?.id,
      amount: data.attributes.total / 100, // cents to dollars
      currency: data.attributes.currency,
      status: 'paid',
      created_at: data.attributes.created_at
    });
    
  if (error) {
    console.error('[Lemon Webhook] Invoice insert error:', error);
  } else {
    console.log(`[Lemon Webhook] Invoice created for order: ${data.id}`);
  }
}

async function addReferralCredit(supabase: any, referralCode: string, newUserId: string) {
  // Referrer'ı bul
  const { data: referrer } = await supabase
    .from('users')
    .select('id')
    .eq('referral_code', referralCode)
    .single();
    
  if (!referrer) {
    console.log(`[Lemon Webhook] No referrer found for code: ${referralCode}`);
    return;
  }
  
  // Aynı kullanıcı kendi kendine refer etmemeli
  if (referrer.id === newUserId) {
    console.log('[Lemon Webhook] Self-referral blocked');
    return;
  }
  
  // Referrer'a 1 ay free credit ekle
  const { error: creditError } = await supabase
    .from('referral_credits')
    .insert({
      referrer_id: referrer.id,
      referred_user_id: newUserId,
      credit_months: 1,
      status: 'active',
      expires_at: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString() // 1 year expiry
    });
    
  if (creditError) {
    console.error('[Lemon Webhook] Referral credit insert error:', creditError);
  } else {
    console.log(`[Lemon Webhook] Referral credit added for referrer: ${referrer.id}`);
  }
  
  // Referrals tablosunu güncelle
  await supabase
    .from('referrals')
    .update({
      status: 'converted',
      converted_at: new Date().toISOString(),
      credits_earned: 1
    })
    .eq('referrer_id', referrer.id)
    .eq('invited_email', newUserId); // Note: This assumes user_id maps to email somehow
}

async function updateEntitlements(supabase: any, userId: string, seats: number) {
  const { error } = await supabase
    .from('entitlements')
    .upsert({
      user_id: userId,
      included_agents: 1, // Free tier
      extra_agents: Math.max(0, seats - 1),
      plan: seats > 1 ? 'pro' : 'free',
      updated_at: new Date().toISOString()
    }, {
      onConflict: 'user_id'
    });
    
  if (error) {
    console.error('[Lemon Webhook] Entitlements update error:', error);
  }
}
