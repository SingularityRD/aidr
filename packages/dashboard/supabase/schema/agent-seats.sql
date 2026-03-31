-- Users table with OAuth support and referral tracking
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE NOT NULL,
  google_id TEXT UNIQUE,
  github_id TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  referral_code TEXT UNIQUE,
  referred_by TEXT, -- referral_code of the referrer
  last_login_at TIMESTAMPTZ
);

-- Agent seats table for tracking agent allocations
CREATE TABLE IF NOT EXISTS agent_seats (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  agent_name TEXT NOT NULL,
  agent_type TEXT NOT NULL CHECK (agent_type IN ('claude', 'cursor', 'vscode', 'openclaw', 'opencode')),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'paused', 'deleted')),
  tier TEXT NOT NULL DEFAULT 'free' CHECK (tier IN ('free', 'pro')),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  expires_at TIMESTAMPTZ, -- for trial/free periods
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Referrals table for viral growth tracking
CREATE TABLE IF NOT EXISTS referrals (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  referrer_id UUID REFERENCES users(id) ON DELETE CASCADE,
  invited_email TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'converted', 'expired')),
  credits_earned INTEGER DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  converted_at TIMESTAMPTZ,
  UNIQUE(referrer_id, invited_email)
);

-- Entitlements table for seat limits
CREATE TABLE IF NOT EXISTS entitlements (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE UNIQUE,
  included_agents INTEGER NOT NULL DEFAULT 1,
  extra_agents INTEGER NOT NULL DEFAULT 0,
  plan TEXT NOT NULL DEFAULT 'free' CHECK (plan IN ('free', 'pro', 'enterprise')),
  pro_expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Referral credits tracking
CREATE TABLE IF NOT EXISTS referral_credits (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  months_granted INTEGER NOT NULL DEFAULT 1,
  reason TEXT,
  expires_at TIMESTAMPTZ,
  used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Credential sharing for family/team
CREATE TABLE IF NOT EXISTS credential_shares (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id UUID REFERENCES users(id) ON DELETE CASCADE,
  shared_with_email TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'revoked')),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  accepted_at TIMESTAMPTZ
);

-- Agent sync for cross-device configuration
CREATE TABLE IF NOT EXISTS agent_sync (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id TEXT NOT NULL,
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  config JSONB NOT NULL DEFAULT '{}',
  last_synced_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(agent_id, user_id)
);

-- Seat usage view for easy querying
CREATE OR REPLACE VIEW seat_usage AS
SELECT 
  u.id as user_id,
  COALESCE(e.included_agents, 1) as included_agents,
  COALESCE(e.extra_agents, 0) as extra_agents,
  COALESCE(e.included_agents, 1) + COALESCE(e.extra_agents, 0) as allowed_agents,
  COUNT(s.id) FILTER (WHERE s.status = 'active') as current_agents,
  e.plan,
  e.pro_expires_at,
  e.subscription_status
FROM users u
LEFT JOIN entitlements e ON u.id = e.user_id
LEFT JOIN agent_seats s ON u.id = s.user_id
GROUP BY u.id, e.included_agents, e.extra_agents, e.plan, e.pro_expires_at, e.subscription_status;

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_google_id ON users(google_id);
CREATE INDEX IF NOT EXISTS idx_users_github_id ON users(github_id);
CREATE INDEX IF NOT EXISTS idx_users_referral_code ON users(referral_code);
CREATE INDEX IF NOT EXISTS idx_agent_seats_user_id ON agent_seats(user_id);
CREATE INDEX IF NOT EXISTS idx_agent_seats_status ON agent_seats(status);
CREATE INDEX IF NOT EXISTS idx_referrals_referrer_id ON referrals(referrer_id);
CREATE INDEX IF NOT EXISTS idx_referrals_status ON referrals(status);
CREATE INDEX IF NOT EXISTS idx_referral_credits_user_id ON referral_credits(user_id);

-- Row Level Security policies
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_seats ENABLE ROW LEVEL SECURITY;
ALTER TABLE referrals ENABLE ROW LEVEL SECURITY;
ALTER TABLE entitlements ENABLE ROW LEVEL SECURITY;
ALTER TABLE referral_credits ENABLE ROW LEVEL SECURITY;
ALTER TABLE credential_shares ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_sync ENABLE ROW LEVEL SECURITY;

-- Users can only see their own data
CREATE POLICY users_own_data ON users
  FOR ALL USING (auth.uid() = id);

-- Agent seats: users can manage their own seats
CREATE POLICY agent_seats_own_data ON agent_seats
  FOR ALL USING (user_id = auth.uid());

-- Referrals: referrers can see their referrals
CREATE POLICY referrals_referrer_view ON referrals
  FOR SELECT USING (referrer_id = auth.uid());

-- Entitlements: users can view their own
CREATE POLICY entitlements_own_data ON entitlements
  FOR SELECT USING (user_id = auth.uid());

-- Referral credits: users can view their own
CREATE POLICY referral_credits_own_data ON referral_credits
  FOR SELECT USING (user_id = auth.uid());

-- Credential shares: owners can manage
CREATE POLICY credential_shares_owner ON credential_shares
  FOR ALL USING (owner_id = auth.uid());

-- Agent sync: users can manage their own
CREATE POLICY agent_sync_own_data ON agent_sync
  FOR ALL USING (user_id = auth.uid());

-- Function to auto-generate referral code on user creation
CREATE OR REPLACE FUNCTION generate_referral_code()
RETURNS TRIGGER AS $$
BEGIN
  IF NEW.referral_code IS NULL THEN
    NEW.referral_code = LOWER(SUBSTRING(MD5(NEW.id::TEXT || NOW()::TEXT) FROM 1 FOR 12));
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_generate_referral_code
  BEFORE INSERT ON users
  FOR EACH ROW
  EXECUTE FUNCTION generate_referral_code();

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_users_updated_at
  BEFORE UPDATE ON users
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trigger_agent_seats_updated_at
  BEFORE UPDATE ON agent_seats
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trigger_entitlements_updated_at
  BEFORE UPDATE ON entitlements
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();
