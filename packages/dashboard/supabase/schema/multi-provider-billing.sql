-- Multi-provider billing schema for AIDR Dashboard

-- Payment providers table
CREATE TABLE IF NOT EXISTS payment_providers (
  id TEXT PRIMARY KEY, -- 'stripe', 'iyzico', 'crypto', 'paypal'
  name TEXT NOT NULL,
  display_name TEXT,
  supported_countries TEXT[], -- ['US', 'GB', 'DE']
  supported_currencies TEXT[], -- ['USD', 'EUR', 'TRY']
  features TEXT[], -- ['3D Secure', 'Taksit', 'Subscription']
  is_active BOOLEAN DEFAULT true,
  is_sandbox BOOLEAN DEFAULT false,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Insert default providers
INSERT INTO payment_providers (id, name, display_name, supported_countries, supported_currencies, features, is_active)
VALUES
  ('stripe', 'Stripe', 'Credit Card', ARRAY['US', 'GB', 'DE', 'FR', 'CA', 'AU', 'JP', 'NL', 'ES', 'IT'], 
   ARRAY['USD', 'EUR', 'GBP', 'JPY', 'CAD', 'AUD'], 
   ARRAY['Subscription', 'Invoice', 'Stripe Tax', 'SEPA'], true),
  
  ('iyzico', 'iyzico', 'Kredi/Banka Kartı', ARRAY['TR'], 
   ARRAY['TRY'], 
   ARRAY['3D Secure', 'Taksit', 'TL Fatura', 'KDV'], true),
  
  ('crypto', 'coinbase_commerce', 'Cryptocurrency', ARRAY['*'], 
   ARRAY['BTC', 'ETH', 'USDC', 'USD'], 
   ARRAY['Anonymous', 'No KYC', 'Privacy'], true),
  
  ('paypal', 'PayPal', 'PayPal', ARRAY['US', 'GB', 'DE', 'FR', 'CA', 'AU'], 
   ARRAY['USD', 'EUR', 'GBP'], 
   ARRAY['One-click', 'Buyer Protection'], true)
ON CONFLICT (id) DO NOTHING;

-- User subscriptions table (multi-provider)
CREATE TABLE IF NOT EXISTS user_subscriptions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  provider TEXT NOT NULL REFERENCES payment_providers(id),
  
  -- Provider-specific subscription/payment reference
  provider_subscription_id TEXT, -- Stripe subscription ID
  provider_payment_id TEXT, -- iyzico payment transaction ID, Coinbase charge ID
  provider_customer_id TEXT, -- Stripe customer ID
  
  -- Subscription details
  seats INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'active', -- 'active', 'canceled', 'past_due', 'unpaid', 'trialing'
  plan_type TEXT NOT NULL, -- 'monthly', 'yearly'
  
  -- Pricing
  currency TEXT NOT NULL DEFAULT 'USD',
  amount DECIMAL(10,2) NOT NULL,
  amount_local DECIMAL(10,2), -- Converted local amount (e.g., TRY)
  
  -- Billing periods
  current_period_start TIMESTAMPTZ,
  current_period_end TIMESTAMPTZ,
  next_billing_date TIMESTAMPTZ,
  
  -- Trial
  trial_start TIMESTAMPTZ,
  trial_end TIMESTAMPTZ,
  
  -- Cancellation
  canceled_at TIMESTAMPTZ,
  cancel_at_period_end BOOLEAN DEFAULT false,
  
  -- Metadata
  metadata JSONB DEFAULT '{}',
  
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Payments/invoices table
CREATE TABLE IF NOT EXISTS payments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  subscription_id UUID REFERENCES user_subscriptions(id) ON DELETE SET NULL,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  provider TEXT NOT NULL REFERENCES payment_providers(id),
  
  -- Provider transaction details
  provider_payment_id TEXT NOT NULL, -- Unique payment ID from provider
  provider_invoice_id TEXT, -- Invoice ID if available
  
  -- Payment details
  amount DECIMAL(10,2) NOT NULL,
  currency TEXT NOT NULL,
  amount_local DECIMAL(10,2),
  currency_local TEXT,
  
  -- Status
  status TEXT NOT NULL DEFAULT 'pending', -- 'succeeded', 'failed', 'pending', 'refunded', 'disputed'
  
  -- 3D Secure / authentication
  auth_code TEXT,
  
  -- Provider response (for debugging)
  provider_response JSONB,
  
  -- Metadata
  metadata JSONB DEFAULT '{}',
  
  -- Receipt/invoice
  receipt_url TEXT,
  invoice_pdf_url TEXT,
  
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Payment events/webhooks log
CREATE TABLE IF NOT EXISTS payment_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  provider TEXT NOT NULL,
  event_type TEXT NOT NULL, -- 'charge.succeeded', 'invoice.paid', etc.
  provider_event_id TEXT, -- Event ID from provider
  
  -- Event data
  payload JSONB NOT NULL,
  
  -- Processing status
  processed BOOLEAN DEFAULT false,
  processed_at TIMESTAMPTZ,
  error_message TEXT,
  
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- User billing profiles
CREATE TABLE IF NOT EXISTS user_billing_profiles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL UNIQUE REFERENCES auth.users(id) ON DELETE CASCADE,
  
  -- Default preferences
  preferred_provider TEXT REFERENCES payment_providers(id),
  preferred_currency TEXT DEFAULT 'USD',
  
  -- Billing address
  company_name TEXT,
  tax_id TEXT, -- VAT number, Tax ID
  address_line1 TEXT,
  address_line2 TEXT,
  city TEXT,
  state TEXT,
  postal_code TEXT,
  country TEXT,
  
  -- Turkey-specific (KDV fatura)
  tc_kimlik_no TEXT, -- Turkish ID for e-fatura
  vergi_dairesi TEXT, -- Tax office
  
  -- Stripe customer ID (if using Stripe)
  stripe_customer_id TEXT,
  
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Exchange rates cache
CREATE TABLE IF NOT EXISTS exchange_rates (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  base_currency TEXT NOT NULL,
  target_currency TEXT NOT NULL,
  rate DECIMAL(15,8) NOT NULL,
  source TEXT DEFAULT 'exchangerate-api',
  fetched_at TIMESTAMPTZ DEFAULT NOW(),
  
  UNIQUE(base_currency, target_currency)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_user_subscriptions_user_id ON user_subscriptions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_subscriptions_status ON user_subscriptions(status);
CREATE INDEX IF NOT EXISTS idx_user_subscriptions_provider ON user_subscriptions(provider);
CREATE INDEX IF NOT EXISTS idx_payments_user_id ON payments(user_id);
CREATE INDEX IF NOT EXISTS idx_payments_subscription_id ON payments(subscription_id);
CREATE INDEX IF NOT EXISTS idx_payments_provider_payment_id ON payments(provider_payment_id);
CREATE INDEX IF NOT EXISTS idx_payments_created_at ON payments(created_at);
CREATE INDEX IF NOT EXISTS idx_payment_events_provider ON payment_events(provider);
CREATE INDEX IF NOT EXISTS idx_payment_events_processed ON payment_events(processed);

-- Row Level Security (RLS)
ALTER TABLE user_subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE payments ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_billing_profiles ENABLE ROW LEVEL SECURITY;

-- RLS Policies
CREATE POLICY "Users can view own subscriptions"
  ON user_subscriptions FOR SELECT
  USING (user_id = auth.uid());

CREATE POLICY "Users can view own payments"
  ON payments FOR SELECT
  USING (user_id = auth.uid());

CREATE POLICY "Users can manage own billing profile"
  ON user_billing_profiles FOR ALL
  USING (user_id = auth.uid());

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ language 'plpgsql';

-- Triggers for updated_at
CREATE TRIGGER update_user_subscriptions_updated_at
  BEFORE UPDATE ON user_subscriptions
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_payments_updated_at
  BEFORE UPDATE ON payments
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_user_billing_profiles_updated_at
  BEFORE UPDATE ON user_billing_profiles
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Function to calculate next billing date
CREATE OR REPLACE FUNCTION calculate_next_billing_date(
  p_start_date TIMESTAMPTZ,
  p_plan_type TEXT
) RETURNS TIMESTAMPTZ AS $$
BEGIN
  IF p_plan_type = 'monthly' THEN
    RETURN p_start_date + INTERVAL '1 month';
  ELSIF p_plan_type = 'yearly' THEN
    RETURN p_start_date + INTERVAL '1 year';
  ELSE
    RETURN p_start_date + INTERVAL '1 month';
  END IF;
END;
$$ LANGUAGE plpgsql;

-- View: Active subscriptions summary
CREATE OR REPLACE VIEW user_subscription_summary AS
SELECT 
  s.id,
  s.user_id,
  s.provider,
  p.name as provider_name,
  s.seats,
  s.status,
  s.plan_type,
  s.currency,
  s.amount,
  s.next_billing_date,
  s.created_at,
  COUNT(py.id) as total_payments,
  COALESCE(SUM(CASE WHEN py.status = 'succeeded' THEN py.amount ELSE 0 END), 0) as total_paid
FROM user_subscriptions s
JOIN payment_providers p ON s.provider = p.id
LEFT JOIN payments py ON s.id = py.subscription_id
WHERE s.status = 'active'
GROUP BY s.id, s.user_id, s.provider, p.name, s.seats, s.status, s.plan_type, s.currency, s.amount, s.next_billing_date, s.created_at;

-- Turkey-specific view for e-fatura
CREATE OR REPLACE VIEW turkey_billing_view AS
SELECT 
  s.id as subscription_id,
  s.user_id,
  s.seats,
  s.amount_local as tutar,
  s.currency_local as para_birimi,
  s.amount_local * 0.20 as kdv_tutari, -- %20 KDV
  s.amount_local * 1.20 as toplam_tutar, -- KDV dahil
  s.created_at as fatura_tarihi,
  bp.company_name as sirket_adi,
  bp.tc_kimlik_no,
  bp.vergi_dairesi,
  bp.tax_id as vergi_no,
  bp.address_line1 as adres,
  bp.city as sehir,
  bp.postal_code as posta_kodu
FROM user_subscriptions s
JOIN user_billing_profiles bp ON s.user_id = bp.user_id
WHERE s.currency_local = 'TRY' OR bp.country = 'TR';
