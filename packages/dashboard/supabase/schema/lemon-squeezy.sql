-- Lemon Squeezy billing integration schema
-- Extends the existing agent-seats.sql schema

-- ============================================
-- Lemon Squeezy Subscriptions Table
-- ============================================
CREATE TABLE IF NOT EXISTS subscriptions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  
  -- Lemon Squeezy IDs
  lemon_subscription_id TEXT UNIQUE,
  lemon_customer_id TEXT,
  lemon_order_id TEXT,
  lemon_product_id TEXT,
  lemon_variant_id TEXT,
  
  -- Subscription details
  status TEXT DEFAULT 'active', -- 'active', 'cancelled', 'expired', 'paused', 'past_due'
  plan_type TEXT, -- 'monthly', 'yearly'
  seats INTEGER DEFAULT 1,
  total_seats INTEGER DEFAULT 1, -- User's total purchased seats
  
  -- Billing periods
  current_period_start TIMESTAMPTZ,
  current_period_end TIMESTAMPTZ,
  trial_ends_at TIMESTAMPTZ,
  
  -- Referral tracking
  referral_code_used TEXT,
  
  -- Metadata
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  cancelled_at TIMESTAMPTZ
);

-- ============================================
-- Referral Credits (earned by inviting others)
-- ============================================
CREATE TABLE IF NOT EXISTS referral_credits (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  referrer_id UUID REFERENCES users(id) ON DELETE CASCADE,
  referred_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  lemon_subscription_id TEXT REFERENCES subscriptions(lemon_subscription_id) ON DELETE SET NULL,
  credit_months INTEGER DEFAULT 1,
  status TEXT DEFAULT 'active', -- 'active', 'used', 'expired'
  applied_to_subscription_id UUID REFERENCES subscriptions(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  expires_at TIMESTAMPTZ
);

-- ============================================
-- Seat Usage Tracking
-- ============================================
CREATE TABLE IF NOT EXISTS seat_usage (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  subscription_id UUID REFERENCES subscriptions(id) ON DELETE CASCADE,
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  agent_name TEXT,
  agent_type TEXT, -- 'claude', 'cursor', 'vscode', 'openclaw', 'cli'
  last_seen_at TIMESTAMPTZ,
  is_active BOOLEAN DEFAULT true,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================
-- Invoices (sync from Lemon Squeezy)
-- ============================================
CREATE TABLE IF NOT EXISTS invoices (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  subscription_id UUID REFERENCES subscriptions(id) ON DELETE SET NULL,
  lemon_order_id TEXT,
  lemon_invoice_id TEXT,
  amount DECIMAL(10,2),
  currency TEXT DEFAULT 'USD',
  status TEXT, -- 'paid', 'pending', 'refunded'
  invoice_url TEXT, -- Lemon Squeezy invoice PDF URL
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================
-- Payment Providers Configuration
-- Multi-provider support: stripe, iyzico, lemon_squeezy, crypto
-- ============================================
ALTER TABLE subscriptions 
ADD COLUMN IF NOT EXISTS provider TEXT DEFAULT 'lemon_squeezy'; -- 'stripe', 'iyzico', 'lemon_squeezy', 'crypto'

-- ============================================
-- Indexes for Performance
-- ============================================
CREATE INDEX IF NOT EXISTS idx_subscriptions_user ON subscriptions(user_id);
CREATE INDEX IF NOT EXISTS idx_subscriptions_lemon ON subscriptions(lemon_subscription_id);
CREATE INDEX IF NOT EXISTS idx_subscriptions_status ON subscriptions(status);
CREATE INDEX IF NOT EXISTS idx_referral_credits_referrer ON referral_credits(referrer_id);
CREATE INDEX IF NOT EXISTS idx_referral_credits_status ON referral_credits(status);
CREATE INDEX IF NOT EXISTS idx_seat_usage_subscription ON seat_usage(subscription_id);
CREATE INDEX IF NOT EXISTS idx_seat_usage_user ON seat_usage(user_id);
CREATE INDEX IF NOT EXISTS idx_invoices_user ON invoices(user_id);
CREATE INDEX IF NOT EXISTS idx_invoices_lemon ON invoices(lemon_order_id);

-- ============================================
-- Row Level Security Policies
-- ============================================
ALTER TABLE subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE referral_credits ENABLE ROW LEVEL SECURITY;
ALTER TABLE seat_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;

-- Users can only see their own subscriptions
CREATE POLICY subscriptions_own_data ON subscriptions
  FOR ALL USING (user_id = auth.uid());

-- Users can view referral credits they earned
CREATE POLICY referral_credits_referrer_view ON referral_credits
  FOR SELECT USING (referrer_id = auth.uid());

-- Users can manage their seat usage
CREATE POLICY seat_usage_own_data ON seat_usage
  FOR ALL USING (user_id = auth.uid());

-- Users can view their invoices
CREATE POLICY invoices_own_data ON invoices
  FOR SELECT USING (user_id = auth.uid());

-- ============================================
-- Triggers
-- ============================================

-- Update updated_at timestamp for subscriptions
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_subscriptions_updated_at ON subscriptions;
CREATE TRIGGER trigger_subscriptions_updated_at
  BEFORE UPDATE ON subscriptions
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

-- Auto-update entitlements when subscription changes
CREATE OR REPLACE FUNCTION sync_entitlements_from_subscription()
RETURNS TRIGGER AS $$
DECLARE
  total_seats INTEGER;
BEGIN
  -- Calculate total seats from active subscriptions
  SELECT COALESCE(SUM(seats), 0) INTO total_seats
  FROM subscriptions
  WHERE user_id = NEW.user_id 
    AND status = 'active' 
    AND (current_period_end IS NULL OR current_period_end > NOW());
  
  -- Update entitlements
  INSERT INTO entitlements (user_id, included_agents, extra_agents, plan, updated_at)
  VALUES (
    NEW.user_id, 
    1, 
    GREATEST(0, total_seats - 1), 
    CASE WHEN total_seats > 1 THEN 'pro' ELSE 'free' END,
    NOW()
  )
  ON CONFLICT (user_id) 
  DO UPDATE SET
    extra_agents = GREATEST(0, total_seats - 1),
    plan = CASE WHEN total_seats > 1 THEN 'pro' ELSE 'free' END,
    updated_at = NOW();
    
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_sync_entitlements ON subscriptions;
CREATE TRIGGER trigger_sync_entitlements
  AFTER INSERT OR UPDATE ON subscriptions
  FOR EACH ROW
  EXECUTE FUNCTION sync_entitlements_from_subscription();

-- ============================================
-- Views
-- ============================================

-- Active subscription summary per user
CREATE OR REPLACE VIEW user_subscription_summary AS
SELECT 
  u.id as user_id,
  u.email,
  COUNT(DISTINCT s.id) FILTER (WHERE s.status = 'active') as active_subscriptions,
  COALESCE(SUM(s.seats) FILTER (WHERE s.status = 'active'), 0) as total_paid_seats,
  COALESCE(SUM(rc.credit_months) FILTER (WHERE rc.status = 'active'), 0) as referral_credits_earned,
  MAX(s.current_period_end) FILTER (WHERE s.status = 'active') as next_billing_date
FROM users u
LEFT JOIN subscriptions s ON u.id = s.user_id
LEFT JOIN referral_credits rc ON u.id = rc.referrer_id
GROUP BY u.id, u.email;

-- Referral stats per user
CREATE OR REPLACE VIEW referral_stats AS
SELECT 
  u.id as user_id,
  u.referral_code,
  COUNT(DISTINCT rc.id) FILTER (WHERE rc.status = 'active') as active_referrals,
  COUNT(DISTINCT rc.id) as total_referrals,
  COALESCE(SUM(rc.credit_months) FILTER (WHERE rc.status = 'active'), 0) as free_months_earned
FROM users u
LEFT JOIN referral_credits rc ON u.id = rc.referrer_id
GROUP BY u.id, u.referral_code;
